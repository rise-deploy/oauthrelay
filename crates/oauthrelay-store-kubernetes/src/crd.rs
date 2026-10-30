//! The `TransientRecord` custom resource.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One record of oauthrelay's transient store. The object's name is a hash of the store key, so
/// the key itself is stored only for inspection.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "oauthrelay.dev",
    version = "v1alpha1",
    kind = "TransientRecord",
    namespaced,
    printcolumn = r#"{"name":"Expires","type":"date","jsonPath":".spec.expiresAt"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct TransientRecordSpec {
    /// The store key. It holds purpose prefixes, hashes and random IDs, never a secret.
    #[schemars(length(min = 1, max = 1024))]
    pub key: String,
    /// The opaque record value, base64-encoded. Values are sealed by the relay.
    pub value: String,
    /// When the record expires, RFC 3339 with millisecond precision. An expired record is absent
    /// for reads and may be overwritten; the sweeper deletes it.
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}
