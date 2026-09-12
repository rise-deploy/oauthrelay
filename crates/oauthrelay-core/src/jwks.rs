use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Public JSON Web Key Set used to verify client assertions.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicJwkSet {
    #[schemars(length(min = 1))]
    pub keys: Vec<PublicJwk>,
}

/// Public key material for the asymmetric algorithms accepted by oauthrelay.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kty")]
pub enum PublicJwk {
    RSA {
        n: String,
        e: String,
        #[serde(flatten)]
        common: JwkCommon,
    },
    EC {
        crv: EcCurve,
        x: String,
        y: String,
        #[serde(flatten)]
        common: JwkCommon,
    },
    OKP {
        crv: OkpCurve,
        x: String,
        #[serde(flatten)]
        common: JwkCommon,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum EcCurve {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum OkpCurve {
    Ed25519,
}

/// Standard optional JWK metadata. Key material is carried by the key type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct JwkCommon {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    pub public_key_use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(default, rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}
