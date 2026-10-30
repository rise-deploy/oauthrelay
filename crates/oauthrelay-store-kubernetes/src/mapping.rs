//! How a store record is laid out as a Kubernetes object.

use crate::{
    crd::{TransientRecord, TransientRecordSpec},
    NewRecord, Stored,
};
use anyhow::{anyhow, Context};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use k8s_openapi::jiff::Timestamp;
use kube::{
    api::{ApiResource, DynamicObject},
    core::GroupVersionKind,
    CustomResourceExt,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Label carried by every object the store writes; every list selects on it.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGED_BY_VALUE: &str = "oauthrelay";
/// Label selector matching exactly the objects the store wrote.
pub const MANAGED_SELECTOR: &str = "app.kubernetes.io/managed-by=oauthrelay";
/// Label carrying the key's purpose prefix (`replay`, `refresh`), for `kubectl get -l`.
pub const PURPOSE_LABEL: &str = "oauthrelay.dev/purpose";
/// Label carrying the unix hour (integer hours since the epoch, decimal) in which the record
/// expires. It is rewritten on every write, since a write restarts the TTL, and lets the sweeper
/// list only the records that can have expired.
pub const EXPIRES_HOUR_LABEL: &str = "oauthrelay.dev/expires-hour";
/// Milliseconds in one expiry bucket.
pub const EXPIRY_BUCKET_MS: u64 = 3_600_000;
/// Prefix of every object name the store writes.
pub const NAME_PREFIX: &str = "oauthrelay-";

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The object name for a store key: [`NAME_PREFIX`] plus the lowercase, unpadded base32 of the
/// key's SHA-256, 63 characters in all (a DNS label, and so a valid name for any resource).
/// Keys are arbitrary UTF-8 up to 1024 bytes, which are not valid names, and hashing keeps the
/// name fixed-length.
pub fn object_name(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("{NAME_PREFIX}{}", base32_lower(&digest))
}

pub(crate) fn base32_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer = 0_u32;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(
                BASE32_ALPHABET[((buffer >> bits) & 31) as usize],
            ));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            BASE32_ALPHABET[((buffer << (5 - bits)) & 31) as usize],
        ));
    }
    out
}

/// The key's first `:`-separated segment, when it is a valid label value.
fn purpose(key: &str) -> Option<&str> {
    let segment = key.split(':').next().unwrap_or_default();
    let alphanumeric = |byte: &u8| byte.is_ascii_alphanumeric();
    let valid = !segment.is_empty()
        && segment.len() <= 63
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && segment.as_bytes().first().is_some_and(alphanumeric)
        && segment.as_bytes().last().is_some_and(alphanumeric);
    valid.then_some(segment)
}

/// The expiry bucket of an instant: its unix hour.
pub fn expiry_hour(expires_at_ms: u64) -> u64 {
    expires_at_ms / EXPIRY_BUCKET_MS
}

/// The label selector matching managed objects that expire in one of `hours`.
pub fn expiry_selector(hours: impl IntoIterator<Item = u64>) -> String {
    let hours: Vec<_> = hours.into_iter().map(|hour| hour.to_string()).collect();
    format!(
        "{MANAGED_SELECTOR},{EXPIRES_HOUR_LABEL} in ({})",
        hours.join(",")
    )
}

pub(crate) fn labels(key: &str, expires_at_ms: u64) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::from([
        (MANAGED_BY_LABEL.to_owned(), MANAGED_BY_VALUE.to_owned()),
        (
            EXPIRES_HOUR_LABEL.to_owned(),
            expiry_hour(expires_at_ms).to_string(),
        ),
    ]);
    if let Some(purpose) = purpose(key) {
        labels.insert(PURPOSE_LABEL.to_owned(), purpose.to_owned());
    }
    labels
}

/// Formats Unix epoch milliseconds as RFC 3339 UTC with millisecond precision.
pub(crate) fn format_time(millis: u64) -> anyhow::Result<String> {
    let millis = i64::try_from(millis).context("timestamp out of range")?;
    let timestamp = Timestamp::from_millisecond(millis).context("timestamp out of range")?;
    Ok(timestamp.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}

/// Parses an RFC 3339 timestamp (any offset) to Unix epoch milliseconds; instants before the
/// epoch read as the epoch.
pub(crate) fn parse_time(text: &str) -> anyhow::Result<u64> {
    let timestamp: Timestamp = text.parse().context("invalid RFC 3339 timestamp")?;
    Ok(u64::try_from(timestamp.as_millisecond()).unwrap_or(0))
}

/// The latest instant [`format_time`] can represent, in Unix epoch milliseconds.
pub(crate) fn max_expiry_millis() -> u64 {
    u64::try_from(Timestamp::MAX.as_second() * 1000).unwrap_or(0)
}

/// A Kubernetes resource the store can keep its records in, and how a record maps onto it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordMapping {
    /// oauthrelay's own `transientrecords.oauthrelay.dev`.
    TransientRecord,
    /// Dex's `authcodes.dex.coreos.com`. A record is an `AuthCode` that Dex can never exchange:
    /// its `clientID` is not a registered client and its PKCE challenge is random. Dex creates
    /// the CRD itself and its garbage collector also removes expired codes.
    DexAuthCode,
}

/// The `clientID` of every `AuthCode` the store writes. Dex rejects a code whose `clientID` is
/// not the authenticating client's, and no Dex client has this ID.
const DEX_CLIENT_ID: &str = "oauthrelay:transient-record";
const DEX_REDIRECT_URI: &str = "urn:oauthrelay:transient-record";
/// The `connectorID` of every `AuthCode` the store writes, for whoever reads the namespace.
const DEX_CONNECTOR_ID: &str = "oauthrelay";

impl RecordMapping {
    /// Every supported mapping.
    pub const ALL: [Self; 2] = [Self::TransientRecord, Self::DexAuthCode];

    pub fn resource_name(self) -> &'static str {
        match self {
            Self::TransientRecord => "transientrecords.oauthrelay.dev",
            Self::DexAuthCode => "authcodes.dex.coreos.com",
        }
    }

    /// The mapping for a `plural.group` resource name, if the store supports it.
    pub fn from_resource_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|mapping| mapping.resource_name() == name)
    }

    /// What must hold for the resource to be served, for startup messages.
    pub fn install_hint(self) -> &'static str {
        match self {
            Self::TransientRecord => "the CRD is installed (`oauthrelay crds`)",
            Self::DexAuthCode => {
                "Dex is installed and running in that namespace (it creates the CRD)"
            }
        }
    }

    pub fn api_resource(self) -> ApiResource {
        match self {
            Self::TransientRecord => TransientRecord::api_resource(),
            Self::DexAuthCode => ApiResource::from_gvk_with_plural(
                &GroupVersionKind::gvk("dex.coreos.com", "v1", "AuthCode"),
                "authcodes",
            ),
        }
    }

    /// The full object for `record`, without a `resourceVersion`.
    pub fn encode(self, namespace: &str, record: &NewRecord<'_>) -> anyhow::Result<DynamicObject> {
        let mut object = DynamicObject::new(record.name, &self.api_resource()).within(namespace);
        object.metadata.labels = Some(labels(record.key, record.expires_at_ms));
        let expires_at = format_time(record.expires_at_ms)?;
        object.data = match self {
            Self::TransientRecord => serde_json::json!({
                "spec": TransientRecordSpec {
                    key: record.key.to_owned(),
                    value: STANDARD.encode(record.value),
                    expires_at,
                }
            }),
            // Go decodes `connectorData` ([]byte) from padded standard base64 and `expiry`
            // (time.Time) from RFC 3339; a malformed field would make Dex's garbage collector
            // fail to list every AuthCode, so both use exactly those encodings. The unused
            // fields are omitted and decode as their zero values.
            Self::DexAuthCode => serde_json::json!({
                "clientID": DEX_CLIENT_ID,
                "redirectURI": DEX_REDIRECT_URI,
                "connectorID": DEX_CONNECTOR_ID,
                "connectorData": STANDARD.encode(record.value),
                "expiry": expires_at,
                // A random S256 challenge: no code verifier can match it.
                "code_challenge": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
                "code_challenge_method": "S256",
            }),
        };
        Ok(object)
    }

    pub fn decode(self, object: &DynamicObject) -> anyhow::Result<Stored> {
        let name = object
            .metadata
            .name
            .clone()
            .ok_or_else(|| anyhow!("object has no name"))?;
        let resource_version = object
            .metadata
            .resource_version
            .clone()
            .ok_or_else(|| anyhow!("object {name:?} has no resourceVersion"))?;
        let (value, expires_at_ms) = match self {
            Self::TransientRecord => {
                let spec = object
                    .data
                    .get("spec")
                    .cloned()
                    .ok_or_else(|| anyhow!("object {name:?} has no spec"))?;
                let spec: TransientRecordSpec = serde_json::from_value(spec)
                    .with_context(|| format!("object {name:?} has an invalid spec"))?;
                let value = STANDARD
                    .decode(&spec.value)
                    .with_context(|| format!("object {name:?} has an invalid value"))?;
                let expires_at_ms = parse_time(&spec.expires_at)
                    .with_context(|| format!("object {name:?} has an invalid expiresAt"))?;
                (value, expires_at_ms)
            }
            Self::DexAuthCode => {
                let field = |field: &str| {
                    object
                        .data
                        .get(field)
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow!("object {name:?} has no {field}"))
                };
                let value = STANDARD
                    .decode(field("connectorData")?)
                    .with_context(|| format!("object {name:?} has an invalid connectorData"))?;
                let expires_at_ms = parse_time(field("expiry")?)
                    .with_context(|| format!("object {name:?} has an invalid expiry"))?;
                (value, expires_at_ms)
            }
        };
        Ok(Stored {
            name,
            resource_version,
            value,
            expires_at_ms,
        })
    }
}
