use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SealError {
    #[error("invalid sealing key: expected 32 bytes")]
    InvalidKey,
    /// The envelope cannot be opened: malformed, tampered with, bound to other associated data,
    /// or sealed under a key that is no longer configured. Retrying cannot help.
    #[error("invalid sealed envelope")]
    InvalidEnvelope,
    /// The sealer could not be reached (a remote key service is down or timed out). The envelope
    /// is not known to be bad, so callers fail the request with a server error and must not treat
    /// the value as tampered with.
    #[error("sealer unavailable")]
    Unavailable,
}

/// Authenticated encryption of the values the relay hands to clients or parks in the transient
/// store. Both operations are asynchronous so that an embedder can back them with a remote key
/// service; [`XChaChaSealer`] is pure CPU.
///
/// `associated_data` binds a ciphertext to its context: `unseal` succeeds only with the same
/// bytes `seal` was given. Report a failure to reach the key service as
/// [`SealError::Unavailable`] and everything wrong with the envelope itself as
/// [`SealError::InvalidEnvelope`].
#[async_trait]
pub trait Sealer: Send + Sync + 'static {
    async fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<String, SealError>;
    async fn unseal(&self, envelope: &str, associated_data: &[u8]) -> Result<Vec<u8>, SealError>;
}

pub struct XChaChaSealer {
    current: [u8; 32],
    previous: Option<[u8; 32]>,
}

impl XChaChaSealer {
    pub fn new(current: &[u8], previous: Option<&[u8]>) -> Result<Self, SealError> {
        let current: [u8; 32] = current.try_into().map_err(|_| SealError::InvalidKey)?;
        let previous = previous
            .map(|key| key.try_into().map_err(|_| SealError::InvalidKey))
            .transpose()?;
        Ok(Self { current, previous })
    }

    fn try_unseal(
        key: &[u8; 32],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SealError::InvalidEnvelope)
    }
}

#[async_trait]
impl Sealer for XChaChaSealer {
    async fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<String, SealError> {
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new((&self.current).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SealError::InvalidEnvelope)?;
        let mut bytes = Vec::with_capacity(nonce.len() + ciphertext.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        Ok(format!("v1.{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    async fn unseal(&self, envelope: &str, associated_data: &[u8]) -> Result<Vec<u8>, SealError> {
        let encoded = envelope
            .strip_prefix("v1.")
            .ok_or(SealError::InvalidEnvelope)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| SealError::InvalidEnvelope)?;
        if bytes.len() <= 24 {
            return Err(SealError::InvalidEnvelope);
        }
        let (nonce, ciphertext) = bytes.split_at(24);
        Self::try_unseal(&self.current, nonce, ciphertext, associated_data).or_else(|_| {
            self.previous
                .as_ref()
                .ok_or(SealError::InvalidEnvelope)
                .and_then(|key| Self::try_unseal(key, nonce, ciphertext, associated_data))
        })
    }
}

/// A sealer whose operations can be switched off individually, standing in for a remote key
/// service that goes down.
#[cfg(test)]
pub(crate) struct FlakySealer {
    inner: XChaChaSealer,
    seal_down: std::sync::atomic::AtomicBool,
    unseal_down: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl FlakySealer {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self {
            inner: XChaChaSealer::new(key, None).unwrap(),
            seal_down: false.into(),
            unseal_down: false.into(),
        }
    }

    pub(crate) fn set_seal_down(&self, down: bool) {
        self.seal_down
            .store(down, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn set_unseal_down(&self, down: bool) {
        self.unseal_down
            .store(down, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn set_down(&self, down: bool) {
        self.set_seal_down(down);
        self.set_unseal_down(down);
    }
}

#[cfg(test)]
#[async_trait]
impl Sealer for FlakySealer {
    async fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<String, SealError> {
        if self.seal_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SealError::Unavailable);
        }
        self.inner.seal(plaintext, associated_data).await
    }

    async fn unseal(&self, envelope: &str, associated_data: &[u8]) -> Result<Vec<u8>, SealError> {
        if self.unseal_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(SealError::Unavailable);
        }
        self.inner.unseal(envelope, associated_data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_rotation_and_tamper_rejection() {
        let old = [1_u8; 32];
        let new = [2_u8; 32];
        let old_sealer = XChaChaSealer::new(&old, None).unwrap();
        let token = old_sealer.seal(b"secret", b"resource").await.unwrap();
        let rotated = XChaChaSealer::new(&new, Some(&old)).unwrap();
        assert_eq!(
            rotated.unseal(&token, b"resource").await.unwrap(),
            b"secret"
        );
        assert!(matches!(
            rotated.unseal(&token, b"other").await,
            Err(SealError::InvalidEnvelope)
        ));
        let mut tampered = token.into_bytes();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            rotated
                .unseal(&String::from_utf8(tampered).unwrap(), b"resource")
                .await,
            Err(SealError::InvalidEnvelope)
        ));
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(XChaChaSealer::new(&[0; 31], None).is_err());
        assert!(XChaChaSealer::new(&[0; 32], Some(&[0; 31])).is_err());
    }
}
