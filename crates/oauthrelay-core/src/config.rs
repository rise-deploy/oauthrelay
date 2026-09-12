use crate::{
    ClientAuth, ClientJwks, ProviderSnapshot, PublicJwkSet, RedirectMatcher, Relay, ResourceKey,
    SecretString, Upstream,
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use url::Url;

/// API version accepted by oauthrelay resource documents.
pub const API_VERSION: &str = "oauthrelay.dev/v1alpha1";

/// Returns the JSON Schema for one oauthrelay resource document.
pub fn resource_schema() -> schemars::Schema {
    schemars::schema_for!(ResourceDocument)
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind")]
/// A versioned oauthrelay configuration resource.
pub enum ResourceDocument {
    /// An external OAuth/OIDC provider client and its stable callback.
    Upstream(UpstreamResource),
    /// A transparent-relay policy that references an upstream.
    Relay(RelayResource),
}

impl ResourceDocument {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Upstream(_) => "Upstream",
            Self::Relay(_) => "Relay",
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Upstream(resource) => &resource.metadata.name,
            Self::Relay(resource) => &resource.metadata.name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// An external OAuth/OIDC provider connection.
pub struct UpstreamResource {
    /// Configuration API version. Must be `oauthrelay.dev/v1alpha1`.
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    /// Resource identity.
    pub metadata: Metadata,
    /// Provider connection and OAuth client configuration.
    pub spec: UpstreamResourceSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// A transparent relay that applies downstream policy to one upstream.
pub struct RelayResource {
    /// Configuration API version. Must be `oauthrelay.dev/v1alpha1`.
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    /// Resource identity.
    pub metadata: Metadata,
    /// Upstream reference and transparent-relay policy.
    pub spec: RelayResourceSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
/// Supported configuration API versions.
pub enum ApiVersion {
    /// Initial upstream and relay resource API.
    #[serde(rename = "oauthrelay.dev/v1alpha1")]
    V1Alpha1,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Common resource identity fields.
pub struct Metadata {
    /// Kubernetes namespace; ignored by File and SSM resource discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// URL-safe resource name containing ASCII letters, numbers, `.`, `_`, or `-`.
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// External issuer, optional explicit endpoints, and provider OAuth client.
pub struct UpstreamResourceSpec {
    /// Absolute HTTP(S) issuer URL used for discovery and transparent token trust.
    pub issuer_url: String,
    /// Explicit provider endpoints. Omitted endpoints are resolved through issuer discovery.
    #[serde(default)]
    pub endpoints: UpstreamEndpoints,
    /// OAuth client registered with the external provider.
    pub oauth_client: OAuthClient,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Optional explicit provider endpoints.
pub struct UpstreamEndpoints {
    /// Absolute provider authorization endpoint.
    #[serde(default)]
    pub authorization: Option<String>,
    /// Absolute provider token endpoint.
    #[serde(default)]
    pub token: Option<String>,
    /// Absolute provider JSON Web Key Set endpoint.
    #[serde(default)]
    pub jwks: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// OAuth client registered with the external provider.
pub struct OAuthClient {
    /// Provider client identifier.
    pub client_id: String,
    /// Provider client secret, supplied inline or through a provider-supported reference.
    pub client_secret: SecretValue,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Transparent-relay policy and upstream reference.
pub struct RelayResourceSpec {
    /// Upstream used for authorization and token exchange.
    pub upstream_ref: ResourceReference,
    /// Default and allowed upstream scopes.
    #[serde(default)]
    pub scopes: ScopePolicy,
    /// Exact string values required in the verified upstream ID token.
    #[serde(default)]
    pub required_id_token_claims: HashMap<String, String>,
    /// Authentication required at the relay token endpoint.
    pub client_authentication: ClientAuthentication,
    /// Explicit application redirect matchers.
    #[schemars(length(min = 1))]
    pub redirect_policy: Vec<RedirectPolicyEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Reference to another resource of the expected kind.
pub struct ResourceReference {
    /// Referenced resource name.
    pub name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Scopes applied to upstream authorization and refresh requests.
pub struct ScopePolicy {
    /// Scopes used when an authorization request omits `scope`.
    #[serde(default)]
    pub default: Vec<String>,
    /// Complete allow-list for configured and requested scopes. Omission leaves scope policy to the upstream.
    #[serde(default)]
    pub allowed: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
/// One explicit application redirect matcher.
pub enum RedirectPolicyEntry {
    /// Match one complete redirect URI exactly.
    Uri(UriRedirectPolicy),
    /// Match every path and query at one HTTPS origin.
    Origin(OriginRedirectPolicy),
    /// Match one loopback path and query on any runtime port.
    Loopback(LoopbackRedirectPolicy),
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Exact redirect URI matcher.
pub struct UriRedirectPolicy {
    /// Complete HTTPS URI, or an exact HTTP URI on an IP-literal loopback host.
    uri: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// HTTPS origin matcher.
pub struct OriginRedirectPolicy {
    /// HTTPS scheme, host, and optional port; every path and query at the origin is allowed.
    origin: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Variable-port loopback matcher.
pub struct LoopbackRedirectPolicy {
    /// HTTP URI on 127.0.0.1 or ::1 without a port; path and query match exactly.
    loopback: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", deny_unknown_fields)]
#[schemars(transform = require_jwks_source)]
/// Authentication accepted from a relying party at the relay token endpoint.
pub enum ClientAuthentication {
    /// Require the referenced upstream's OAuth client ID and secret.
    UpstreamClient,
    /// Accept no client secret and require S256 PKCE for authorization-code flows.
    Public,
    /// Require a relay-specific client ID and shared secret.
    ClientSecret {
        /// Relay-specific downstream client identifier.
        #[serde(rename = "clientId")]
        client_id: String,
        /// Relay-specific downstream client secret.
        #[serde(rename = "clientSecret")]
        client_secret: SecretValue,
    },
    /// Require a signed client assertion, optionally from a federated workload issuer.
    PrivateKeyJwt {
        /// Client identifier required in the token request; default assertion issuer and subject.
        #[serde(rename = "clientId")]
        client_id: String,
        /// Exact assertion issuer. HTTPS URL (HTTP allowed on loopback); defaults to clientId.
        /// Supplies OIDC discovery when neither jwks nor jwksUrl is configured.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(with = "String", length(min = 1))]
        issuer: Option<String>,
        /// Exact assertion subject, such as system:serviceaccount:namespace:name; defaults to clientId.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(with = "String", length(min = 1))]
        subject: Option<String>,
        /// Inline public keys. Mutually exclusive with jwksUrl; omit both to discover from issuer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[schemars(with = "PublicJwkSet")]
        jwks: Option<PublicJwkSet>,
        /// Absolute HTTP(S) JWKS URL. Mutually exclusive with jwks; omit both to discover from issuer.
        #[serde(default, rename = "jwksUrl", skip_serializing_if = "Option::is_none")]
        #[schemars(with = "String")]
        jwks_url: Option<String>,
    },
}

/// Require one explicit key source, or issuer discovery when neither is supplied.
fn require_jwks_source(schema: &mut schemars::Schema) {
    if let Some(variants) = schema
        .get_mut("oneOf")
        .and_then(serde_json::Value::as_array_mut)
    {
        for variant in variants {
            if variant
                .get("properties")
                .and_then(|p| p.get("jwksUrl"))
                .is_some()
            {
                variant["oneOf"] = serde_json::json!([
                    {"required":["jwks"], "not":{"required":["jwksUrl"]}},
                    {"required":["jwksUrl"], "not":{"required":["jwks"]}},
                    {"required":["issuer"], "not":{"anyOf":[{"required":["jwks"]},{"required":["jwksUrl"]}]}}
                ]);
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
/// A secret supplied either inline or through exactly one external source.
pub enum SecretValue {
    /// Inline secret value.
    Value(InlineSecret),
    /// Provider-resolved secret reference.
    ValueFrom(ReferencedSecret),
}

#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Literal secret representation.
pub struct InlineSecret {
    /// Literal secret value.
    value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// External secret reference.
pub struct ReferencedSecret {
    /// Exactly one provider-specific secret source.
    value_from: SecretSource,
}

impl std::fmt::Debug for InlineSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InlineSecret([REDACTED])")
    }
}

impl SecretValue {
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Value(secret) => Some(&secret.value),
            Self::ValueFrom(_) => None,
        }
    }

    pub fn value_from(&self) -> Option<&SecretSource> {
        match self {
            Self::Value(_) => None,
            Self::ValueFrom(secret) => Some(&secret.value_from),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, Hash, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Secret sources resolved by configured provider backends.
pub enum SecretSource {
    /// Environment variable in the oauthrelay process.
    Env {
        /// Environment variable name.
        name: String,
    },
    /// Local file accessible to the oauthrelay process.
    File {
        /// Absolute path or path relative to the resource file.
        path: String,
    },
    /// Exact AWS SSM SecureString parameter.
    AwsSsmParameter {
        /// Absolute SSM parameter name.
        name: String,
    },
    /// Secret key resolved within the Kubernetes provider namespace.
    SecretKeyRef {
        /// Secret resource name.
        name: String,
        /// Key in the Secret data map.
        key: String,
    },
    /// AWS Secrets Manager SecretString.
    AwsSecretsManager {
        /// Secret name or ARN passed to Secrets Manager GetSecretValue.
        #[serde(rename = "secretId")]
        secret_id: String,
        /// Optional top-level JSON string field selected from SecretString.
        #[serde(default, rename = "jsonKey")]
        json_key: Option<String>,
    },
}

#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn resolve_value(&self, value: &str) -> anyhow::Result<SecretString>;
    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString>;
}

pub async fn compile_resources(
    documents: Vec<ResourceDocument>,
    secrets: &dyn SecretResolver,
) -> anyhow::Result<ProviderSnapshot> {
    let mut upstream_documents = Vec::new();
    let mut relay_documents = Vec::new();
    let mut identities = std::collections::HashSet::new();

    for document in documents {
        let identity = (document.kind(), document.name().to_owned());
        if !identities.insert(identity.clone()) {
            return Err(anyhow!("duplicate {}/{}", identity.0, identity.1));
        }
        match document {
            ResourceDocument::Upstream(resource) => upstream_documents.push(resource),
            ResourceDocument::Relay(resource) => relay_documents.push(resource),
        }
    }

    let mut snapshot = ProviderSnapshot::default();
    let mut secret_cache = HashMap::new();
    for resource in upstream_documents {
        let key = resource_key("Upstream", &resource.metadata.name)?;
        let secret = resolve_secret(
            &resource.spec.oauth_client.client_secret,
            secrets,
            &mut secret_cache,
        )
        .await
        .with_context(|| format!("Upstream/{key} spec.oauthClient.clientSecret"))?;
        let upstream = Upstream {
            key: key.clone(),
            issuer_url: parse_url("spec.issuerUrl", &resource.spec.issuer_url)?,
            authorization_endpoint: parse_optional_url(
                "spec.endpoints.authorization",
                resource.spec.endpoints.authorization,
            )?,
            token_endpoint: parse_optional_url(
                "spec.endpoints.token",
                resource.spec.endpoints.token,
            )?,
            jwks_uri: parse_optional_url("spec.endpoints.jwks", resource.spec.endpoints.jwks)?,
            client_id: resource.spec.oauth_client.client_id,
            client_secret: secret,
        };
        upstream
            .validate()
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("Upstream/{key}"))?;
        snapshot.upstreams.insert(key, Arc::new(upstream));
    }

    for resource in relay_documents {
        let key = resource_key("Relay", &resource.metadata.name)?;
        let upstream = resource_key("Upstream", &resource.spec.upstream_ref.name)?;
        let client_auth = match resource.spec.client_authentication {
            ClientAuthentication::UpstreamClient => ClientAuth::UpstreamClient,
            ClientAuthentication::Public => ClientAuth::Public,
            ClientAuthentication::ClientSecret {
                client_id,
                client_secret,
            } => ClientAuth::ClientSecret {
                client_id,
                client_secret: resolve_secret(&client_secret, secrets, &mut secret_cache)
                    .await
                    .with_context(|| {
                        format!("Relay/{key} spec.clientAuthentication.clientSecret")
                    })?,
            },
            ClientAuthentication::PrivateKeyJwt {
                client_id,
                issuer,
                subject,
                jwks,
                jwks_url,
            } => ClientAuth::PrivateKeyJwt {
                client_id,
                jwks: match (jwks, jwks_url) {
                    (None, Some(value)) => Some(ClientJwks::Url(
                        Url::parse(&value).context("spec.clientAuthentication.jwksUrl")?,
                    )),
                    (Some(jwks), None) => Some(ClientJwks::Inline(serde_json::to_value(jwks)?)),
                    (None, None) if issuer.is_some() => None,
                    _ => {
                        return Err(anyhow!(
                            "Relay/{key}: PrivateKeyJwt requires exactly one of jwks and jwksUrl, or issuer discovery with neither"
                        ))
                    }
                },
                issuer,
                subject,
            },
        };
        let redirect_policy = resource
            .spec
            .redirect_policy
            .into_iter()
            .enumerate()
            .map(|(index, policy)| {
                let matcher = match policy {
                    RedirectPolicyEntry::Uri(policy) => RedirectMatcher::uri(policy.uri),
                    RedirectPolicyEntry::Origin(policy) => RedirectMatcher::origin(&policy.origin),
                    RedirectPolicyEntry::Loopback(policy) => {
                        RedirectMatcher::loopback(&policy.loopback)
                    }
                };
                matcher
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("Relay/{key} spec.redirectPolicy[{index}]"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let relay = Relay {
            key: key.clone(),
            upstream,
            client_auth,
            scopes: resource.spec.scopes.default,
            allowed_scopes: resource.spec.scopes.allowed,
            required_id_token_claims: resource.spec.required_id_token_claims,
            redirect_policy,
        };
        relay
            .validate()
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("Relay/{key}"))?;
        snapshot.relays.insert(key, Arc::new(relay));
    }

    snapshot.validate().map_err(anyhow::Error::msg)?;
    Ok(snapshot)
}

async fn resolve_secret(
    secret: &SecretValue,
    resolver: &dyn SecretResolver,
    cache: &mut HashMap<SecretSource, SecretString>,
) -> anyhow::Result<SecretString> {
    if let Some(value) = secret.value() {
        return resolver.resolve_value(value).await;
    }
    let source = secret.value_from().expect("validated source");
    if let Some(value) = cache.get(source) {
        return Ok(value.clone());
    }
    let value = resolver.resolve_source(source).await?;
    cache.insert(source.clone(), value.clone());
    Ok(value)
}

fn resource_key(kind: &str, value: &str) -> anyhow::Result<ResourceKey> {
    if value.contains('/') {
        return Err(anyhow!(
            "{kind}/{value}: metadata.name must be one path segment"
        ));
    }
    ResourceKey::new(value).map_err(|error| anyhow!("{kind}/{value}: metadata.name {error}"))
}

fn parse_url(field: &str, value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).with_context(|| field.to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(anyhow!("{field}: must be an absolute http(s) URL"));
    }
    Ok(url)
}

fn parse_optional_url(field: &str, value: Option<String>) -> anyhow::Result<Option<Url>> {
    value.map(|value| parse_url(field, &value)).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockSecrets {
        calls: Mutex<Vec<SecretSource>>,
    }

    #[async_trait]
    impl SecretResolver for MockSecrets {
        async fn resolve_value(&self, value: &str) -> anyhow::Result<SecretString> {
            Ok(SecretString::new(value))
        }

        async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
            self.calls.lock().unwrap().push(source.clone());
            Ok(SecretString::new("resolved"))
        }
    }

    fn documents(secret: SecretValue) -> Vec<ResourceDocument> {
        vec![
            ResourceDocument::Upstream(UpstreamResource {
                api_version: ApiVersion::V1Alpha1,
                metadata: Metadata {
                    namespace: None,
                    name: "google".into(),
                },
                spec: UpstreamResourceSpec {
                    issuer_url: "https://issuer.example".into(),
                    endpoints: UpstreamEndpoints::default(),
                    oauth_client: OAuthClient {
                        client_id: "client".into(),
                        client_secret: secret,
                    },
                },
            }),
            ResourceDocument::Relay(RelayResource {
                api_version: ApiVersion::V1Alpha1,
                metadata: Metadata {
                    namespace: None,
                    name: "cognito".into(),
                },
                spec: RelayResourceSpec {
                    upstream_ref: ResourceReference {
                        name: "google".into(),
                    },
                    scopes: ScopePolicy::default(),
                    required_id_token_claims: HashMap::new(),
                    client_authentication: ClientAuthentication::UpstreamClient,
                    redirect_policy: vec![RedirectPolicyEntry::Uri(UriRedirectPolicy {
                        uri: "https://app.example/callback".into(),
                    })],
                },
            }),
        ]
    }

    #[tokio::test]
    async fn compiles_references_and_resolves_secret_source() {
        let source = SecretSource::Env {
            name: "GOOGLE_SECRET".into(),
        };
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        let mut resources = documents(SecretValue::ValueFrom(ReferencedSecret {
            value_from: source.clone(),
        }));
        let ResourceDocument::Relay(relay) = &mut resources[1] else {
            unreachable!();
        };
        relay.spec.required_id_token_claims = HashMap::from([("hd".into(), "example.com".into())]);
        let snapshot = compile_resources(resources, &secrets).await.unwrap();
        assert_eq!(snapshot.upstreams.len(), 1);
        assert_eq!(snapshot.relays.len(), 1);
        assert_eq!(
            snapshot
                .relays
                .values()
                .next()
                .unwrap()
                .required_id_token_claims,
            HashMap::from([("hd".into(), "example.com".into())])
        );
        assert_eq!(*secrets.calls.lock().unwrap(), vec![source]);
    }

    #[tokio::test]
    async fn resolves_and_deduplicates_relay_client_secret_references() {
        let source = SecretSource::AwsSsmParameter {
            name: "/oauthrelay/secrets/shared".into(),
        };
        let mut resources = documents(SecretValue::ValueFrom(ReferencedSecret {
            value_from: source.clone(),
        }));
        let ResourceDocument::Relay(relay) = &mut resources[1] else {
            unreachable!();
        };
        relay.spec.client_authentication = ClientAuthentication::ClientSecret {
            client_id: "downstream".into(),
            client_secret: SecretValue::ValueFrom(ReferencedSecret {
                value_from: source.clone(),
            }),
        };
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };

        let snapshot = compile_resources(resources, &secrets).await.unwrap();
        let relay = snapshot.relays.values().next().unwrap();
        let ClientAuth::ClientSecret { client_secret, .. } = &relay.client_auth else {
            panic!("expected relay client secret authentication");
        };
        assert_eq!(client_secret.expose(), "resolved");
        assert_eq!(*secrets.calls.lock().unwrap(), vec![source]);
    }

    #[tokio::test]
    async fn rejects_missing_reference_and_ambiguous_secret() {
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        let mut resources = documents(SecretValue::Value(InlineSecret {
            value: "inline".into(),
        }));
        resources.remove(0);
        assert!(compile_resources(resources, &secrets)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist"));

        let ambiguous = r#"{"value":"inline","valueFrom":{"env":{"name":"X"}}}"#;
        assert!(serde_json::from_str::<SecretValue>(ambiguous).is_err());
    }

    #[tokio::test]
    async fn redirect_policy_requires_strict_non_empty_entries() {
        let valid = r#"[
            {"uri":"https://app.example/callback?channel=stable"},
            {"origin":"https://preview.example"},
            {"loopback":"http://127.0.0.1/callback"}
        ]"#;
        let entries: Vec<RedirectPolicyEntry> = serde_json::from_str(valid).unwrap();
        assert_eq!(entries.len(), 3);
        for invalid in [
            r#"[{"uri":"https://app.example/callback","origin":"https://app.example"}]"#,
            r#"[{"prefix":"https://app.example"}]"#,
            r#"{"allowedOrigins":["https://app.example"]}"#,
        ] {
            assert!(serde_json::from_str::<Vec<RedirectPolicyEntry>>(invalid).is_err());
        }

        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        let mut resources = documents(SecretValue::Value(InlineSecret {
            value: "inline".into(),
        }));
        let ResourceDocument::Relay(relay) = &mut resources[1] else {
            unreachable!();
        };
        relay.spec.redirect_policy.clear();
        let error = compile_resources(resources, &secrets).await.unwrap_err();
        assert!(format!("{error:#}").contains("at least one matcher"));

        let mut resources = documents(SecretValue::Value(InlineSecret {
            value: "inline".into(),
        }));
        let ResourceDocument::Relay(relay) = &mut resources[1] else {
            unreachable!();
        };
        relay
            .spec
            .redirect_policy
            .push(RedirectPolicyEntry::Uri(UriRedirectPolicy {
                uri: "https://app.example/callback".into(),
            }));
        let error = compile_resources(resources, &secrets).await.unwrap_err();
        assert!(format!("{error:#}").contains("must not contain duplicates"));
    }

    #[test]
    fn generated_schema_contains_versioned_resources_and_json_key() {
        let schema = serde_json::to_string(&resource_schema()).unwrap();
        assert!(schema.contains(API_VERSION));
        assert!(schema.contains("Upstream"));
        assert!(schema.contains("Relay"));
        assert!(schema.contains("awsSsmParameter"));
        assert!(schema.contains("awsSecretsManager"));
        assert!(schema.contains("jsonKey"));
        assert!(schema.contains("requiredIdTokenClaims"));
        assert!(schema.contains("stable callback"));
        assert!(schema.contains("complete redirect URI exactly"));
    }

    #[test]
    fn aws_secret_sources_require_cloud_prefixed_keys() {
        assert!(serde_json::from_str::<SecretSource>(
            r#"{"awsSsmParameter":{"name":"/oauthrelay/secrets/google"}}"#
        )
        .is_ok());
        assert!(serde_json::from_str::<SecretSource>(
            r#"{"awsSecretsManager":{"secretId":"oauthrelay/google","jsonKey":"clientSecret"}}"#
        )
        .is_ok());
        assert!(serde_json::from_str::<SecretSource>(
            r#"{"ssmParameter":{"name":"/oauthrelay/secrets/google"}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SecretSource>(
            r#"{"secretsManager":{"secretId":"oauthrelay/google"}}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn compiles_workload_identity_and_rejects_invalid_trust_configuration() {
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        let issuer = "https://cluster.example";
        let subject = "system:serviceaccount:workloads:worker";
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"jwksUrl":"https://keys.example/jwks"}),
            serde_json::json!({"jwks":{"keys":[{"kty":"RSA","n":"a","e":"b"}]}}),
        ] {
            let mut auth = serde_json::json!({"type":"PrivateKeyJwt","clientId":"worker","issuer":issuer,"subject":subject});
            auth.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let mut resources = documents(SecretValue::Value(InlineSecret {
                value: "secret".into(),
            }));
            let ResourceDocument::Relay(relay) = &mut resources[1] else {
                unreachable!()
            };
            relay.spec.client_authentication = serde_json::from_value(auth).unwrap();
            let compiled = compile_resources(resources, &secrets).await.unwrap();
            let ClientAuth::PrivateKeyJwt {
                issuer: actual_issuer,
                subject: actual_subject,
                ..
            } = &compiled.relays.values().next().unwrap().client_auth
            else {
                unreachable!()
            };
            assert_eq!(actual_issuer.as_deref(), Some(issuer));
            assert_eq!(actual_subject.as_deref(), Some(subject));
        }
        for extra in [
            serde_json::json!({"issuer":""}),
            serde_json::json!({"issuer":"cluster.example"}),
            serde_json::json!({"issuer":"http://cluster.example"}),
            serde_json::json!({"issuer":"https://user@cluster.example"}),
            serde_json::json!({"issuer":"https://cluster.example?query"}),
            serde_json::json!({"issuer":"https://cluster.example#fragment"}),
            serde_json::json!({"subject":""}),
            serde_json::json!({"issuer":null}),
            serde_json::json!({"jwksUrl":"https://keys.example/jwks","jwks":{"keys":[{"kty":"RSA","n":"a","e":"b"}]}}),
        ] {
            let mut auth = serde_json::json!({"type":"PrivateKeyJwt","clientId":"worker","issuer":issuer,"subject":subject});
            auth.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let mut resources = documents(SecretValue::Value(InlineSecret {
                value: "secret".into(),
            }));
            let ResourceDocument::Relay(relay) = &mut resources[1] else {
                unreachable!()
            };
            relay.spec.client_authentication = serde_json::from_value(auth.clone()).unwrap();
            assert!(
                compile_resources(resources, &secrets).await.is_err(),
                "{auth}"
            );
        }
    }

    #[tokio::test]
    async fn compilation_requires_one_jwks_source_and_ignores_namespace_identity() {
        let secrets = MockSecrets {
            calls: Mutex::new(vec![]),
        };
        for auth in [
            serde_json::json!({"type":"PrivateKeyJwt","clientId":"app"}),
            serde_json::json!({"type":"PrivateKeyJwt","clientId":"app","jwksUrl":"https://app.example/jwks","jwks":{"keys":[{"kty":"RSA","n":"a","e":"b"}]}}),
        ] {
            let mut resources = documents(SecretValue::Value(InlineSecret {
                value: "secret".into(),
            }));
            let ResourceDocument::Relay(relay) = &mut resources[1] else {
                unreachable!()
            };
            relay.spec.client_authentication = serde_json::from_value(auth).unwrap();
            assert!(format!(
                "{:#}",
                compile_resources(resources, &secrets).await.unwrap_err()
            )
            .contains("exactly one"));
        }
        let mut resources = documents(SecretValue::Value(InlineSecret {
            value: "secret".into(),
        }));
        let ResourceDocument::Upstream(upstream) = &mut resources[0] else {
            unreachable!()
        };
        upstream.metadata.namespace = Some("first".into());
        let mut duplicate = upstream.clone();
        duplicate.metadata.namespace = Some("second".into());
        assert!(compile_resources(resources.clone(), &secrets).await.is_ok());
        resources.push(ResourceDocument::Upstream(duplicate));
        assert!(compile_resources(resources, &secrets)
            .await
            .unwrap_err()
            .to_string()
            .contains("duplicate Upstream"));
    }
}

#[cfg(test)]
mod kubernetes_configuration_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn namespaces_are_optional_and_do_not_change_file_identities() {
        for namespace in [None, Some("team")] {
            let metadata: Metadata =
                serde_json::from_value(json!({"name":"issuer", "namespace":namespace})).unwrap();
            assert_eq!(metadata.name, "issuer");
            assert_eq!(metadata.namespace.as_deref(), namespace);
        }
    }

    #[test]
    fn private_key_jwt_accepts_exactly_one_typed_key_source() {
        let base = json!({"type":"PrivateKeyJwt", "clientId":"app"});
        for source in [
            json!({"jwksUrl":"https://app.example/jwks"}),
            json!({"jwks":{"keys":[{"kty":"RSA", "n":"AQAB", "e":"AQAB", "kid":"rsa"}]}}),
            json!({"jwks":{"keys":[{"kty":"EC", "crv":"P-256", "x":"abc", "y":"def"}]}}),
            json!({"jwks":{"keys":[{"kty":"OKP", "crv":"Ed25519", "x":"abc"}]}}),
        ] {
            let mut value = base.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(source.as_object().unwrap().clone());
            let parsed: ClientAuthentication = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        }
        for source in [
            json!({"jwks":"https://app.example/jwks"}),
            json!({"jwks":{"keys":[{"kty":"RSA", "n":"a"}]}}),
            json!({"jwks":{"keys":[{"kty":"EC", "crv":"invalid", "x":"a", "y":"b"}]}}),
        ] {
            let mut value = base.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(source.as_object().unwrap().clone());
            assert!(
                serde_json::from_value::<ClientAuthentication>(value.clone()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let source: SecretValue = serde_json::from_value(json!({"value":"do-not-log"})).unwrap();
        assert!(!format!("{source:?}").contains("do-not-log"));
    }
}
