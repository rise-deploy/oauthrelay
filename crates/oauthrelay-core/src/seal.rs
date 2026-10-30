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
    #[error("invalid sealed envelope")]
    InvalidEnvelope,
}

pub trait Sealer: Send + Sync + 'static {
    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<String, SealError>;
    fn unseal(&self, envelope: &str, associated_data: &[u8]) -> Result<Vec<u8>, SealError>;
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

impl Sealer for XChaChaSealer {
    fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<String, SealError> {
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

    fn unseal(&self, envelope: &str, associated_data: &[u8]) -> Result<Vec<u8>, SealError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_rotation_and_tamper_rejection() {
        let old = [1_u8; 32];
        let new = [2_u8; 32];
        let old_sealer = XChaChaSealer::new(&old, None).unwrap();
        let token = old_sealer.seal(b"secret", b"resource").unwrap();
        let rotated = XChaChaSealer::new(&new, Some(&old)).unwrap();
        assert_eq!(rotated.unseal(&token, b"resource").unwrap(), b"secret");
        assert!(rotated.unseal(&token, b"other").is_err());
        let mut tampered = token.into_bytes();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(rotated
            .unseal(&String::from_utf8(tampered).unwrap(), b"resource")
            .is_err());
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(XChaChaSealer::new(&[0; 31], None).is_err());
        assert!(XChaChaSealer::new(&[0; 32], Some(&[0; 31])).is_err());
    }
}
