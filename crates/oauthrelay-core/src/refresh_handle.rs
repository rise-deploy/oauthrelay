//! Sealed refresh-token handles.
//!
//! In `sealed` mode a relay never shows its client the upstream refresh token. Token responses
//! carry a handle instead: the upstream token sealed with the relay's sealer, bound through the
//! associated data to this purpose and to a [`HandleBinding`]: the relay key, the relay's
//! generation, and the identity of its upstream. Only the relay that issued a handle, still
//! pointing at the same upstream, can open it, and seal-key rotation applies through the sealer's
//! previous-key mechanism.

use crate::{router::issuer_identifier, Relay, ResourceKey, SealError, Sealer, Upstream};
use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::fmt;

/// Recognizable, versioned prefix of every sealed handle. The remainder is a sealer envelope.
pub(crate) const HANDLE_PREFIX: &str = "rrt1.";
const REFRESH_TOKEN_MEMBER: &str = "refresh_token";

#[derive(Debug, Serialize, Deserialize)]
struct RefreshHandle {
    upstream_token: String,
    issued_at: u64,
}

/// An upstream refresh token recovered from a handle.
#[derive(Debug)]
pub(crate) struct OpenedHandle {
    pub upstream_token: String,
    pub issued_at: u64,
}

/// Domain separation of the upstream-identity fingerprint. A new binding scheme gets a new tag.
const FINGERPRINT_DOMAIN: &[u8] = b"oauthrelay refresh-token binding v1";

/// What a refresh-token handle, and every rotating-mode record that holds or leads to an upstream
/// token, is bound to: the relay key and a fingerprint of the relay's generation and of the
/// upstream identity a refresh token belongs to.
///
/// The upstream identity is the configured issuer URL (normalized as for ID-token issuer
/// comparison), the configured token endpoint override if there is one, and the upstream
/// `client_id`. A change to any of them, or to the relay's generation, changes the fingerprint,
/// so handles issued before no longer open: the relay answers `invalid_grant` without sending
/// the stored upstream token anywhere. Discovered endpoints are not part of the identity, so a
/// change in the provider's discovery document does not sign anyone out; neither does any other
/// relay or upstream setting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HandleBinding {
    relay: ResourceKey,
    fingerprint: [u8; 32],
}

impl HandleBinding {
    /// The binding of `relay` as it is configured now, with `upstream` the upstream it references.
    pub(crate) fn new(relay: &Relay, upstream: &Upstream) -> Self {
        Self::with_fingerprint(relay.key.clone(), fingerprint(relay, upstream))
    }

    /// A binding whose fingerprint was computed earlier, for example when the upstream answered
    /// the code exchange whose tokens are being handed out now.
    pub(crate) fn with_fingerprint(relay: ResourceKey, fingerprint: [u8; 32]) -> Self {
        Self { relay, fingerprint }
    }

    pub(crate) fn relay(&self) -> &ResourceKey {
        &self.relay
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// Domain-separated SHA-256 over the relay generation and the upstream identity. Every field is
/// length-prefixed and absent values are distinct from empty ones, so no two configurations
/// share an encoding.
pub(crate) fn fingerprint(relay: &Relay, upstream: &Upstream) -> [u8; 32] {
    fn field(hasher: &mut Sha256, value: Option<&str>) {
        match value {
            None => hasher.update([0]),
            Some(value) => {
                hasher.update([1]);
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value.as_bytes());
            }
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    field(&mut hasher, relay.generation.as_deref());
    field(&mut hasher, Some(&issuer_identifier(&upstream.issuer_url)));
    field(
        &mut hasher,
        upstream.token_endpoint.as_ref().map(url::Url::as_str),
    );
    field(&mut hasher, Some(&upstream.client_id));
    hasher.finalize().into()
}

fn associated_data(binding: &HandleBinding) -> Vec<u8> {
    let mut data = format!("refresh:{}\0", binding.relay).into_bytes();
    data.extend_from_slice(&binding.fingerprint);
    data
}

/// Why a handle could not be sealed or opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandleError {
    /// Not a handle this relay issued: wrong shape, tampered with, issued for another relay or
    /// under another binding, or sealed under a key that is no longer configured. (When sealing: the value could not be
    /// encoded or sealed.)
    Invalid,
    /// The sealer could not be reached; the handle may be fine.
    SealerUnavailable,
}

impl From<SealError> for HandleError {
    fn from(error: SealError) -> Self {
        match error {
            SealError::Unavailable => Self::SealerUnavailable,
            SealError::InvalidKey | SealError::InvalidEnvelope => Self::Invalid,
        }
    }
}

/// Seals an upstream refresh token into a handle bound to `binding`.
pub(crate) async fn seal_handle(
    sealer: &dyn Sealer,
    binding: &HandleBinding,
    upstream_token: &str,
    issued_at: u64,
) -> Result<String, HandleError> {
    let plaintext = postcard::to_stdvec(&RefreshHandle {
        upstream_token: upstream_token.to_owned(),
        issued_at,
    })
    .map_err(|_| HandleError::Invalid)?;
    let envelope = sealer.seal(&plaintext, &associated_data(binding)).await?;
    Ok(format!("{HANDLE_PREFIX}{envelope}"))
}

/// Opens a handle issued under `binding`. Anything else, including a raw upstream token, a handle
/// issued for another relay, another relay generation or another upstream identity, or a
/// tampered handle, is rejected.
pub(crate) async fn open_handle(
    sealer: &dyn Sealer,
    binding: &HandleBinding,
    handle: &str,
) -> Result<OpenedHandle, HandleError> {
    let envelope = handle
        .strip_prefix(HANDLE_PREFIX)
        .ok_or(HandleError::Invalid)?;
    let plaintext = sealer.unseal(envelope, &associated_data(binding)).await?;
    let handle: RefreshHandle =
        postcard::from_bytes(&plaintext).map_err(|_| HandleError::Invalid)?;
    Ok(OpenedHandle {
        upstream_token: handle.upstream_token,
        issued_at: handle.issued_at,
    })
}

/// Whether `token` has the shape of a handle of any version (`rrt<N>.`). Such a value is never
/// an upstream refresh token, so it is never forwarded upstream, whatever the relay's mode.
pub(crate) fn has_handle_prefix(token: &str) -> bool {
    token.strip_prefix("rrt").is_some_and(|rest| {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        digits > 0 && rest[digits..].starts_with('.')
    })
}

/// Why a token response could not be substituted. No case may return the upstream body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubstitutionError {
    /// Sealing or encoding the handle failed.
    Sealing,
    /// The sealer could not be reached.
    SealerUnavailable,
    /// A successful response is not a JSON object yet appears to carry a refresh token (for
    /// example a form-encoded `refresh_token=` pair), so it cannot be rewritten safely.
    UnrecognizedBody,
}

/// Whether `body` names a `refresh_token` as a member or field (`refresh_token=`,
/// `"refresh_token":`), which a body that is not a JSON object must not be allowed to carry.
pub(crate) fn names_refresh_token(body: &[u8]) -> bool {
    let text = String::from_utf8_lossy(body);
    text.match_indices(REFRESH_TOKEN_MEMBER).any(|(at, name)| {
        text[at + name.len()..]
            .trim_start_matches(['"', '\''])
            .trim_start()
            .starts_with(['=', ':'])
    })
}

/// Replaces the `refresh_token` member of a successful token response with a handle.
///
/// Any 2xx body is read as a JSON object whatever its content type. Returns `Ok(None)` when the
/// response must be passed on unchanged: it is not a 2xx response, or carries no non-empty
/// string `refresh_token` and does not look like it hides one. Member order and the bytes of
/// every other member are preserved; only inter-member whitespace is normalized. `Err` means the
/// response must not be returned, as it would expose the upstream token.
pub(crate) async fn seal_token_response(
    sealer: &dyn Sealer,
    binding: &HandleBinding,
    status: u16,
    body: &[u8],
    issued_at: u64,
) -> Result<Option<Vec<u8>>, SubstitutionError> {
    if !(200..300).contains(&status) {
        return Ok(None);
    }
    let Ok(mut members) = serde_json::from_slice::<Members>(body) else {
        return if names_refresh_token(body) {
            Err(SubstitutionError::UnrecognizedBody)
        } else {
            Ok(None)
        };
    };
    let mut replaced = false;
    for (name, value) in &mut members.0 {
        if name != REFRESH_TOKEN_MEMBER {
            continue;
        }
        let Ok(token) = serde_json::from_str::<String>(value.get()) else {
            continue;
        };
        if token.is_empty() {
            continue;
        }
        let handle = seal_handle(sealer, binding, &token, issued_at)
            .await
            .map_err(|error| match error {
                HandleError::SealerUnavailable => SubstitutionError::SealerUnavailable,
                HandleError::Invalid => SubstitutionError::Sealing,
            })?;
        *value = serde_json::to_string(&handle)
            .ok()
            .and_then(|json| RawValue::from_string(json).ok())
            .ok_or(SubstitutionError::Sealing)?;
        replaced = true;
    }
    if !replaced {
        return Ok(None);
    }
    serde_json::to_vec(&members)
        .map(Some)
        .map_err(|_| SubstitutionError::Sealing)
}

/// The first non-empty string `refresh_token` member of a 2xx JSON object body.
pub(crate) fn upstream_refresh_token(status: u16, body: &[u8]) -> Option<String> {
    if !(200..300).contains(&status) {
        return None;
    }
    let members = serde_json::from_slice::<Members>(body).ok()?;
    members
        .0
        .iter()
        .filter(|(name, _)| name == REFRESH_TOKEN_MEMBER)
        .filter_map(|(_, value)| serde_json::from_str::<String>(value.get()).ok())
        .find(|token| !token.is_empty())
}

/// Sets the `refresh_token` member of a 2xx JSON object body to `token`: every
/// existing member is replaced in place, and one is appended when there is none. Other members
/// keep their order and bytes. `None` means the body is not a 2xx JSON object.
pub(crate) fn with_refresh_token(status: u16, body: &[u8], token: &str) -> Option<Vec<u8>> {
    if !(200..300).contains(&status) {
        return None;
    }
    let mut members = serde_json::from_slice::<Members>(body).ok()?;
    let value = RawValue::from_string(serde_json::to_string(token).ok()?).ok()?;
    let mut replaced = false;
    for (name, existing) in &mut members.0 {
        if name == REFRESH_TOKEN_MEMBER {
            *existing = value.clone();
            replaced = true;
        }
    }
    if !replaced {
        members.0.push((REFRESH_TOKEN_MEMBER.to_owned(), value));
    }
    serde_json::to_vec(&members).ok()
}

/// The members of a JSON object in document order, with values kept verbatim.
struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MembersVisitor;
        impl<'de> Visitor<'de> for MembersVisitor {
            type Value = Members;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut members = Vec::new();
                while let Some(entry) = map.next_entry::<String, Box<RawValue>>()? {
                    members.push(entry);
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_map(MembersVisitor)
    }
}

impl Serialize for Members {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in &self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::XChaChaSealer;

    fn binding(name: &str) -> HandleBinding {
        HandleBinding::with_fingerprint(ResourceKey::new(name).unwrap(), [3; 32])
    }

    async fn seal(sealer: &XChaChaSealer, body: &str) -> Option<String> {
        seal_token_response(sealer, &binding("app"), 200, body.as_bytes(), 42)
            .await
            .unwrap()
            .map(|bytes| String::from_utf8(bytes).unwrap())
    }

    #[tokio::test]
    async fn handle_round_trips_and_is_bound_to_the_relay() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let handle = seal_handle(&sealer, &binding("app"), "upstream-token", 7)
            .await
            .unwrap();
        assert!(handle.starts_with("rrt1."));
        assert!(!handle.contains("upstream-token"));
        let opened = open_handle(&sealer, &binding("app"), &handle)
            .await
            .unwrap();
        assert_eq!(opened.upstream_token, "upstream-token");
        assert_eq!(opened.issued_at, 7);
        assert!(open_handle(&sealer, &binding("other"), &handle)
            .await
            .is_err());
        let rebound = HandleBinding::with_fingerprint(ResourceKey::new("app").unwrap(), [4; 32]);
        assert_eq!(
            open_handle(&sealer, &rebound, &handle).await.unwrap_err(),
            HandleError::Invalid
        );
        assert!(open_handle(&sealer, &binding("app"), "upstream-token")
            .await
            .is_err());
        assert!(
            open_handle(&sealer, &binding("app"), &handle["rrt1.".len()..])
                .await
                .is_err()
        );
        assert!(open_handle(&sealer, &binding("app"), "rrt1.")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn handles_survive_seal_key_rotation() {
        let old = XChaChaSealer::new(&[1; 32], None).unwrap();
        let handle = seal_handle(&old, &binding("app"), "upstream-token", 7)
            .await
            .unwrap();
        let rotated = XChaChaSealer::new(&[2; 32], Some(&[1; 32])).unwrap();
        assert_eq!(
            open_handle(&rotated, &binding("app"), &handle)
                .await
                .unwrap()
                .upstream_token,
            "upstream-token"
        );
        let retired = XChaChaSealer::new(&[2; 32], None).unwrap();
        assert!(open_handle(&retired, &binding("app"), &handle)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn substitution_preserves_member_order_and_other_members() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let body = r#"{"z":1.50,"refresh_token":"secret","a":{"y":[1, 2],"b":null},"big":123456789012345678901234567890}"#;
        let sealed = seal(&sealer, body).await.unwrap();
        assert!(!sealed.contains("secret"));
        let (head, tail) = sealed.split_once(r#""refresh_token":""#).unwrap();
        assert_eq!(head, r#"{"z":1.50,"#);
        let (handle, tail) = tail.split_once('"').unwrap();
        assert_eq!(
            tail,
            r#","a":{"y":[1, 2],"b":null},"big":123456789012345678901234567890}"#
        );
        assert_eq!(
            open_handle(&sealer, &binding("app"), handle)
                .await
                .unwrap()
                .upstream_token,
            "secret"
        );
    }

    #[tokio::test]
    async fn unchanged_when_there_is_no_refresh_token_to_substitute() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        for body in [
            r#"{"access_token":"a"}"#,
            r#"{"refresh_token":null}"#,
            r#"{"refresh_token":""}"#,
            r#"{"refresh_token":7}"#,
            r#"["refresh_token"]"#,
            "access_token=a&token_type=Bearer",
            "",
        ] {
            assert_eq!(seal(&sealer, body).await, None, "{body}");
        }
        for status in [400, 302, 500] {
            assert_eq!(
                seal_token_response(
                    &sealer,
                    &binding("app"),
                    status,
                    br#"{"refresh_token":"secret"}"#,
                    0
                )
                .await,
                Ok(None),
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn json_is_recognised_whatever_the_content_type() {
        // The content type is not an input: a 2xx body is a JSON object or it is not.
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let sealed = seal(&sealer, r#"{"refresh_token":"secret","x":1}"#)
            .await
            .unwrap();
        assert!(!sealed.contains("secret") && sealed.contains(r#""x":1"#));
    }

    #[tokio::test]
    async fn a_non_json_success_body_that_carries_a_refresh_token_fails_closed() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        for body in [
            "access_token=a&refresh_token=secret&token_type=Bearer",
            "refresh_token=secret",
            "refresh_token = secret",
            r#"[{"refresh_token":"secret"}]"#,
            r#"not json "refresh_token" : "secret""#,
            "{\"refresh_token\": \"secret\"",
        ] {
            assert_eq!(
                seal_token_response(&sealer, &binding("app"), 200, body.as_bytes(), 0).await,
                Err(SubstitutionError::UnrecognizedBody),
                "{body}"
            );
        }
    }

    #[test]
    fn refresh_token_is_read_and_set_in_place_or_appended() {
        let body = br#"{"a":1,"refresh_token":"old","b":[1, 2]}"#;
        assert_eq!(upstream_refresh_token(200, body).as_deref(), Some("old"));
        assert_eq!(
            with_refresh_token(200, body, "new").unwrap(),
            br#"{"a":1,"refresh_token":"new","b":[1, 2]}"#
        );
        let without = br#"{"a":1}"#;
        assert_eq!(upstream_refresh_token(200, without), None);
        assert_eq!(
            with_refresh_token(200, without, "new").unwrap(),
            br#"{"a":1,"refresh_token":"new"}"#
        );
        for empty in [
            &br#"{"refresh_token":""}"#[..],
            br#"{"refresh_token":null}"#,
        ] {
            assert_eq!(upstream_refresh_token(200, empty), None);
            assert_eq!(
                with_refresh_token(200, empty, "new").unwrap(),
                br#"{"refresh_token":"new"}"#
            );
        }
        for (status, body) in [
            (400, &br#"{"refresh_token":"x"}"#[..]),
            (200, br#"["refresh_token"]"#),
            (200, b"not json"),
        ] {
            assert_eq!(upstream_refresh_token(status, body), None);
            assert_eq!(with_refresh_token(status, body, "n"), None);
        }
    }

    #[test]
    fn handle_prefixes_of_any_version_are_recognised() {
        for token in ["rrt1.abc", "rrt2.abc", "rrt10.x", "rrt3."] {
            assert!(has_handle_prefix(token), "{token}");
        }
        for token in [
            "rrt.abc",
            "rrt1abc",
            "rrtx.abc",
            "xrrt1.abc",
            "rrt",
            "",
            "1//abc",
        ] {
            assert!(!has_handle_prefix(token), "{token}");
        }
    }

    fn upstream() -> Upstream {
        Upstream {
            key: ResourceKey::new("idp").unwrap(),
            issuer_url: url::Url::parse("https://issuer.example").unwrap(),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            client_id: "client".into(),
            client_secret: crate::SecretString::new("secret"),
            token_endpoint_auth_method: crate::TokenEndpointAuthMethod::ClientSecretPost,
        }
    }

    fn relay() -> Relay {
        Relay {
            key: ResourceKey::new("app").unwrap(),
            upstream: ResourceKey::new("idp").unwrap(),
            generation: None,
            client_auth: crate::ClientAuth::Public,
            scopes: vec!["openid".into()],
            allowed_scopes: None,
            required_id_token_claims: Default::default(),
            id_token_policy: None,
            refresh_tokens: Default::default(),
            redirect_policy: vec![
                crate::RedirectMatcher::uri("https://app.example/callback").unwrap()
            ],
        }
    }

    #[test]
    fn the_fingerprint_covers_generation_and_upstream_identity_only() {
        let base = fingerprint(&relay(), &upstream());
        let url = |value: &str| url::Url::parse(value).unwrap();
        let changed_upstream: [fn(&mut Upstream); 5] = [
            |u| u.issuer_url = url::Url::parse("https://other.example").unwrap(),
            |u| u.issuer_url = url::Url::parse("https://issuer.example/tenant").unwrap(),
            |u| u.token_endpoint = Some(url::Url::parse("https://issuer.example/token").unwrap()),
            |u| u.client_id = "other-client".into(),
            |u| u.client_id = String::new(),
        ];
        for change in changed_upstream {
            let mut upstream = upstream();
            change(&mut upstream);
            assert_ne!(fingerprint(&relay(), &upstream), base);
        }
        let mut overridden = upstream();
        overridden.token_endpoint = Some(url("https://issuer.example/token"));
        let mut other_override = overridden.clone();
        other_override.token_endpoint = Some(url("https://issuer.example/oauth/token"));
        assert_ne!(
            fingerprint(&relay(), &overridden),
            fingerprint(&relay(), &other_override)
        );
        for generation in ["", "1", "2"] {
            let mut relay = relay();
            relay.generation = Some(generation.into());
            assert_ne!(fingerprint(&relay, &upstream()), base, "{generation:?}");
        }
        let mut first = relay();
        first.generation = Some("1".into());
        let mut second = relay();
        second.generation = Some("2".into());
        assert_ne!(
            fingerprint(&first, &upstream()),
            fingerprint(&second, &upstream())
        );

        // The issuer is compared as the ID-token issuer is: a bare origin with or without its
        // trailing slash is the same issuer.
        let mut slash = upstream();
        slash.issuer_url = url("https://issuer.example/");
        assert_eq!(fingerprint(&relay(), &slash), base);

        // Nothing else about the upstream or the relay is part of the identity.
        let mut unrelated = upstream();
        unrelated.key = ResourceKey::new("renamed").unwrap();
        unrelated.authorization_endpoint = Some(url("https://issuer.example/authorize"));
        unrelated.jwks_uri = Some(url("https://issuer.example/jwks"));
        unrelated.client_secret = crate::SecretString::new("rotated");
        unrelated.token_endpoint_auth_method = crate::TokenEndpointAuthMethod::ClientSecretBasic;
        let mut edited = relay();
        edited.key = ResourceKey::new("renamed").unwrap();
        edited.upstream = ResourceKey::new("renamed").unwrap();
        edited.client_auth = crate::ClientAuth::UpstreamClient;
        edited.scopes = vec!["openid".into(), "email".into()];
        edited.allowed_scopes = Some(vec!["openid".into(), "email".into()]);
        edited
            .required_id_token_claims
            .insert("hd".into(), "example.com".into());
        edited.refresh_tokens.mode = crate::RefreshTokenMode::Rotating;
        edited.refresh_tokens.grace_period_seconds = 5;
        edited.redirect_policy = vec![crate::RedirectMatcher::uri("https://b.example/cb").unwrap()];
        assert_eq!(fingerprint(&edited, &unrelated), base);
    }
}
