//! Sealed refresh-token handles.
//!
//! In `sealed` mode a relay never shows its client the upstream refresh token. Token responses
//! carry a handle instead: the upstream token sealed with the relay's sealer, bound to the relay
//! key and to this purpose through the associated data. Only the relay that issued a handle can
//! open it, and seal-key rotation applies through the sealer's previous-key mechanism.

use crate::{ResourceKey, Sealer};
use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json::value::RawValue;
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
    #[allow(dead_code)]
    pub issued_at: u64,
}

fn associated_data(relay: &ResourceKey) -> Vec<u8> {
    format!("refresh:{relay}").into_bytes()
}

/// Seals an upstream refresh token into a handle for `relay`.
pub(crate) fn seal_handle(
    sealer: &dyn Sealer,
    relay: &ResourceKey,
    upstream_token: &str,
    issued_at: u64,
) -> Result<String, ()> {
    let plaintext = postcard::to_stdvec(&RefreshHandle {
        upstream_token: upstream_token.to_owned(),
        issued_at,
    })
    .map_err(|_| ())?;
    let envelope = sealer
        .seal(&plaintext, &associated_data(relay))
        .map_err(|_| ())?;
    Ok(format!("{HANDLE_PREFIX}{envelope}"))
}

/// Opens a handle issued by `relay`. Anything else, including a raw upstream token, a handle
/// issued for another relay, or a tampered handle, is rejected.
pub(crate) fn open_handle(
    sealer: &dyn Sealer,
    relay: &ResourceKey,
    handle: &str,
) -> Result<OpenedHandle, ()> {
    let envelope = handle.strip_prefix(HANDLE_PREFIX).ok_or(())?;
    let plaintext = sealer
        .unseal(envelope, &associated_data(relay))
        .map_err(|_| ())?;
    let handle: RefreshHandle = postcard::from_bytes(&plaintext).map_err(|_| ())?;
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

/// Why a token response could not be substituted. Neither case may return the upstream body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubstitutionError {
    /// Sealing or encoding the handle failed.
    Sealing,
    /// A successful response is not a JSON object yet appears to carry a refresh token (for
    /// example a form-encoded `refresh_token=` pair), so it cannot be rewritten safely.
    UnrecognizedBody,
}

/// Whether `body` names a `refresh_token` as a member or field (`refresh_token=`,
/// `"refresh_token":`), which a body that is not a JSON object must not be allowed to carry.
fn names_refresh_token(body: &[u8]) -> bool {
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
pub(crate) fn seal_token_response(
    sealer: &dyn Sealer,
    relay: &ResourceKey,
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
        let handle = seal_handle(sealer, relay, &token, issued_at)
            .map_err(|()| SubstitutionError::Sealing)?;
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

    fn key(name: &str) -> ResourceKey {
        ResourceKey::new(name).unwrap()
    }

    fn seal(sealer: &XChaChaSealer, body: &str) -> Option<String> {
        seal_token_response(sealer, &key("app"), 200, body.as_bytes(), 42)
            .unwrap()
            .map(|bytes| String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn handle_round_trips_and_is_bound_to_the_relay() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let handle = seal_handle(&sealer, &key("app"), "upstream-token", 7).unwrap();
        assert!(handle.starts_with("rrt1."));
        assert!(!handle.contains("upstream-token"));
        let opened = open_handle(&sealer, &key("app"), &handle).unwrap();
        assert_eq!(opened.upstream_token, "upstream-token");
        assert_eq!(opened.issued_at, 7);
        assert!(open_handle(&sealer, &key("other"), &handle).is_err());
        assert!(open_handle(&sealer, &key("app"), "upstream-token").is_err());
        assert!(open_handle(&sealer, &key("app"), &handle["rrt1.".len()..]).is_err());
        assert!(open_handle(&sealer, &key("app"), "rrt1.").is_err());
    }

    #[test]
    fn handles_survive_seal_key_rotation() {
        let old = XChaChaSealer::new(&[1; 32], None).unwrap();
        let handle = seal_handle(&old, &key("app"), "upstream-token", 7).unwrap();
        let rotated = XChaChaSealer::new(&[2; 32], Some(&[1; 32])).unwrap();
        assert_eq!(
            open_handle(&rotated, &key("app"), &handle)
                .unwrap()
                .upstream_token,
            "upstream-token"
        );
        let retired = XChaChaSealer::new(&[2; 32], None).unwrap();
        assert!(open_handle(&retired, &key("app"), &handle).is_err());
    }

    #[test]
    fn substitution_preserves_member_order_and_other_members() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let body = r#"{"z":1.50,"refresh_token":"secret","a":{"y":[1, 2],"b":null},"big":123456789012345678901234567890}"#;
        let sealed = seal(&sealer, body).unwrap();
        assert!(!sealed.contains("secret"));
        let (head, tail) = sealed.split_once(r#""refresh_token":""#).unwrap();
        assert_eq!(head, r#"{"z":1.50,"#);
        let (handle, tail) = tail.split_once('"').unwrap();
        assert_eq!(
            tail,
            r#","a":{"y":[1, 2],"b":null},"big":123456789012345678901234567890}"#
        );
        assert_eq!(
            open_handle(&sealer, &key("app"), handle)
                .unwrap()
                .upstream_token,
            "secret"
        );
    }

    #[test]
    fn unchanged_when_there_is_no_refresh_token_to_substitute() {
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
            assert_eq!(seal(&sealer, body), None, "{body}");
        }
        for status in [400, 302, 500] {
            assert_eq!(
                seal_token_response(
                    &sealer,
                    &key("app"),
                    status,
                    br#"{"refresh_token":"secret"}"#,
                    0
                ),
                Ok(None),
                "{status}"
            );
        }
    }

    #[test]
    fn json_is_recognised_whatever_the_content_type() {
        // The content type is not an input: a 2xx body is a JSON object or it is not.
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let sealed = seal(&sealer, r#"{"refresh_token":"secret","x":1}"#).unwrap();
        assert!(!sealed.contains("secret") && sealed.contains(r#""x":1"#));
    }

    #[test]
    fn a_non_json_success_body_that_carries_a_refresh_token_fails_closed() {
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
                seal_token_response(&sealer, &key("app"), 200, body.as_bytes(), 0),
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
}
