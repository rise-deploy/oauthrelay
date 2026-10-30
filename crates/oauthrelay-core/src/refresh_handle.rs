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

/// Recognizable, versioned prefix of every handle. The remainder is a sealer envelope.
const HANDLE_PREFIX: &str = "rrt1.";
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

/// Whether a response `Content-Type` denotes a JSON document (`application/json` or any
/// `+json` structured syntax suffix, parameters ignored).
pub(crate) fn is_json_content_type(content_type: Option<&str>) -> bool {
    let Some(essence) = content_type.and_then(|value| value.split(';').next()) else {
        return false;
    };
    let essence = essence.trim().to_ascii_lowercase();
    essence == "application/json"
        || (essence.starts_with("application/") && essence.ends_with("+json"))
}

/// Replaces the `refresh_token` member of a successful JSON token response with a handle.
///
/// Returns `Ok(None)` when the response must be passed on unchanged: it is not a successful
/// JSON object response, or carries no non-empty string `refresh_token`. Member order and the
/// bytes of every other member are preserved; only inter-member whitespace is normalized.
/// `Err` means sealing failed and the response must not be returned, as it would expose the
/// upstream token.
pub(crate) fn seal_token_response(
    sealer: &dyn Sealer,
    relay: &ResourceKey,
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
    issued_at: u64,
) -> Result<Option<Vec<u8>>, ()> {
    if !(200..300).contains(&status) || !is_json_content_type(content_type) {
        return Ok(None);
    }
    let Ok(mut members) = serde_json::from_slice::<Members>(body) else {
        return Ok(None);
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
        let handle = seal_handle(sealer, relay, &token, issued_at)?;
        *value = RawValue::from_string(serde_json::to_string(&handle).map_err(|_| ())?)
            .map_err(|_| ())?;
        replaced = true;
    }
    if !replaced {
        return Ok(None);
    }
    serde_json::to_vec(&members).map(Some).map_err(|_| ())
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
        seal_token_response(
            sealer,
            &key("app"),
            200,
            Some("application/json"),
            body.as_bytes(),
            42,
        )
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
    fn unchanged_when_not_a_successful_json_object_with_a_refresh_token() {
        let sealer = XChaChaSealer::new(&[1; 32], None).unwrap();
        let with_token = r#"{"refresh_token":"secret"}"#;
        for body in [
            r#"{"access_token":"a"}"#,
            r#"{"refresh_token":null}"#,
            r#"{"refresh_token":""}"#,
            r#"{"refresh_token":7}"#,
            r#"["refresh_token"]"#,
            "refresh_token=secret",
            "",
        ] {
            assert_eq!(seal(&sealer, body), None, "{body}");
        }
        for (status, content_type) in [
            (400, Some("application/json")),
            (302, Some("application/json")),
            (200, Some("text/plain")),
            (200, Some("application/x-www-form-urlencoded")),
            (200, None),
        ] {
            assert_eq!(
                seal_token_response(
                    &sealer,
                    &key("app"),
                    status,
                    content_type,
                    with_token.as_bytes(),
                    0
                )
                .unwrap(),
                None,
                "{status} {content_type:?}"
            );
        }
    }

    #[test]
    fn json_content_types() {
        for value in [
            "application/json",
            "Application/JSON; charset=utf-8",
            "application/vnd.oauth-token+json",
        ] {
            assert!(is_json_content_type(Some(value)), "{value}");
        }
        for value in ["text/json", "application/jsonp", "text/html", ""] {
            assert!(!is_json_content_type(Some(value)), "{value}");
        }
        assert!(!is_json_content_type(None));
    }
}
