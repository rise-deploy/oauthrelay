use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oauthrelay_core::{
    compile_resources, ConfigProvider, ProviderSnapshot, ResourceDocument, SecretResolver,
    SecretSource, SecretString,
};
use oauthrelay_secret_resolver::{LocalSecrets, StandardSecretResolver, SystemLocalSecrets};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

pub const DEFAULT_PREFIX: &str = "/oauthrelay/";
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterType {
    String,
    SecureString,
    StringList,
}

#[derive(Clone, Debug)]
pub struct Parameter {
    pub name: String,
    pub value: String,
    pub parameter_type: ParameterType,
}

#[derive(Clone, Debug, Default)]
pub struct ParameterPage {
    pub parameters: Vec<Parameter>,
    pub next_token: Option<String>,
}

#[async_trait]
pub trait SsmClient: Send + Sync + 'static {
    async fn get_parameters_by_path(
        &self,
        path: &str,
        next_token: Option<String>,
    ) -> anyhow::Result<ParameterPage>;

    async fn get_parameter(&self, name: &str) -> anyhow::Result<Option<Parameter>>;
}

#[async_trait]
pub trait SecretsManagerClient: Send + Sync + 'static {
    async fn get_secret_string(&self, secret_id: &str) -> anyhow::Result<Option<String>>;
}

#[cfg(feature = "aws")]
pub struct AwsSsmClient(pub aws_sdk_ssm::Client);

#[cfg(feature = "aws")]
#[async_trait]
impl SsmClient for AwsSsmClient {
    async fn get_parameters_by_path(
        &self,
        path: &str,
        next_token: Option<String>,
    ) -> anyhow::Result<ParameterPage> {
        let output = self
            .0
            .get_parameters_by_path()
            .path(path)
            .recursive(true)
            .with_decryption(true)
            .set_next_token(next_token)
            .send()
            .await
            .context("GetParametersByPath")?;
        let parameters = output
            .parameters()
            .iter()
            .filter_map(convert_parameter)
            .collect();
        Ok(ParameterPage {
            parameters,
            next_token: output.next_token().map(str::to_owned),
        })
    }

    async fn get_parameter(&self, name: &str) -> anyhow::Result<Option<Parameter>> {
        let output = self
            .0
            .get_parameter()
            .name(name)
            .with_decryption(true)
            .send()
            .await;
        match output {
            Ok(output) => Ok(output.parameter().and_then(convert_parameter)),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_parameter_not_found()) =>
            {
                Ok(None)
            }
            Err(error) => Err(error).context("GetParameter"),
        }
    }
}

#[cfg(feature = "aws")]
fn convert_parameter(parameter: &aws_sdk_ssm::types::Parameter) -> Option<Parameter> {
    use aws_sdk_ssm::types::ParameterType as AwsParameterType;
    let parameter_type = match parameter.r#type()? {
        AwsParameterType::String => ParameterType::String,
        AwsParameterType::SecureString => ParameterType::SecureString,
        AwsParameterType::StringList => ParameterType::StringList,
        _ => return None,
    };
    Some(Parameter {
        name: parameter.name()?.to_owned(),
        value: parameter.value()?.to_owned(),
        parameter_type,
    })
}

#[cfg(feature = "aws")]
pub struct AwsSecretsManagerClient(pub aws_sdk_secretsmanager::Client);

#[cfg(feature = "aws")]
#[async_trait]
impl SecretsManagerClient for AwsSecretsManagerClient {
    async fn get_secret_string(&self, secret_id: &str) -> anyhow::Result<Option<String>> {
        let output = self
            .0
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .context("GetSecretValue")?;
        Ok(output.secret_string().map(str::to_owned))
    }
}

pub struct SsmProvider<C, S> {
    client: Arc<C>,
    secrets_manager: Arc<S>,
    prefix: String,
    poll_interval: Duration,
    local_secrets: Arc<dyn LocalSecrets>,
}

impl<C, S> SsmProvider<C, S> {
    pub fn new(
        client: Arc<C>,
        secrets_manager: Arc<S>,
        prefix: impl Into<String>,
        poll_interval: Duration,
    ) -> anyhow::Result<Self> {
        let prefix = prefix.into();
        if !prefix.starts_with('/') || !prefix.ends_with('/') {
            return Err(anyhow!("SSM prefix must start and end with '/'"));
        }
        if poll_interval.is_zero() {
            return Err(anyhow!("SSM poll interval must be greater than zero"));
        }
        Ok(Self {
            client,
            secrets_manager,
            prefix,
            poll_interval,
            local_secrets: Arc::new(SystemLocalSecrets),
        })
    }

    /// Supplies environment and filesystem access for local secret sources.
    pub fn with_local_secrets(mut self, local_secrets: Arc<dyn LocalSecrets>) -> Self {
        self.local_secrets = local_secrets;
        self
    }
}

impl<C: SsmClient, S: SecretsManagerClient> SsmProvider<C, S> {
    pub async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        let mut documents = Vec::new();
        for plural in ["upstreams", "relays"] {
            let path = format!("{}{plural}/", self.prefix);
            let mut token = None;
            loop {
                let page = self.client.get_parameters_by_path(&path, token).await?;
                for parameter in page.parameters {
                    if parameter.parameter_type != ParameterType::String {
                        return Err(anyhow!(
                            "{}: resource documents must use the SSM String type",
                            parameter.name
                        ));
                    }
                    let expected = expected_identity(&self.prefix, &parameter.name)?;
                    let document: ResourceDocument = serde_yaml::from_str(&parameter.value)
                        .with_context(|| format!("{}: parse resource document", parameter.name))?;
                    if document.kind() != expected.0 || document.name() != expected.1 {
                        return Err(anyhow!(
                            "{}: path identifies {}/{}, document identifies {}/{}",
                            parameter.name,
                            expected.0,
                            expected.1,
                            document.kind(),
                            document.name()
                        ));
                    }
                    documents.push(document);
                }
                token = page.next_token;
                if token.is_none() {
                    break;
                }
            }
        }
        let resolver = StandardSecretResolver::new(None)
            .with_local_secrets(self.local_secrets.clone())
            .with_aws_secrets(Arc::new(AwsSecretResolver::new(
                self.client.clone(),
                self.secrets_manager.clone(),
            )));
        compile_resources(documents, &resolver).await
    }
}

#[async_trait]
impl<C: SsmClient, S: SecretsManagerClient> ConfigProvider for SsmProvider<C, S> {
    fn name(&self) -> &str {
        "ssm"
    }

    async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        SsmProvider::load(self).await
    }

    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
        let mut has_sent = false;
        loop {
            match self.load().await {
                Ok(snapshot) => {
                    if tx.send(snapshot).is_err() {
                        return Ok(());
                    }
                    has_sent = true;
                }
                Err(error) if !has_sent => return Err(error),
                Err(error) => {
                    tracing::error!(%error, "SSM refresh failed; keeping last good snapshot")
                }
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

fn expected_identity<'a>(prefix: &str, name: &'a str) -> anyhow::Result<(&'static str, &'a str)> {
    let relative = name
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("{name}: parameter is outside the configured prefix"))?;
    let segments: Vec<_> = relative.split('/').collect();
    if segments.len() != 2 || segments[1].is_empty() {
        return Err(anyhow!(
            "{name}: expected {prefix}{{upstreams|relays}}/{{name}}"
        ));
    }
    let kind = match segments[0] {
        "upstreams" => "Upstream",
        "relays" => "Relay",
        _ => {
            return Err(anyhow!(
                "{name}: expected an upstreams or relays resource path"
            ))
        }
    };
    Ok((kind, segments[1]))
}

/// Resolves SSM Parameter Store and Secrets Manager secret references.
pub struct AwsSecretResolver<C, S> {
    ssm: Arc<C>,
    secrets_manager: Arc<S>,
}

impl<C, S> AwsSecretResolver<C, S> {
    /// Creates a resolver backed by the supplied client implementations.
    pub fn new(ssm: Arc<C>, secrets_manager: Arc<S>) -> Self {
        Self {
            ssm,
            secrets_manager,
        }
    }
}

#[async_trait]
impl<C: SsmClient, S: SecretsManagerClient> SecretResolver for AwsSecretResolver<C, S> {
    async fn resolve_value(&self, _: &str) -> anyhow::Result<SecretString> {
        Err(anyhow!("inline values are not AWS secret sources"))
    }

    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
        let value = match source {
            SecretSource::AwsSsmParameter { name } => {
                if !name.starts_with('/') {
                    return Err(anyhow!("SSM parameter name must be absolute"));
                }
                let parameter = self
                    .ssm
                    .get_parameter(name)
                    .await?
                    .ok_or_else(|| anyhow!("referenced SSM parameter does not exist"))?;
                if parameter.parameter_type != ParameterType::SecureString {
                    return Err(anyhow!(
                        "referenced SSM parameter must use the SecureString type"
                    ));
                }
                parameter.value
            }
            SecretSource::AwsSecretsManager {
                secret_id,
                json_key,
            } => {
                let secret = self
                    .secrets_manager
                    .get_secret_string(secret_id)
                    .await?
                    .ok_or_else(|| anyhow!("Secrets Manager secret must contain SecretString"))?;
                match json_key {
                    None => secret,
                    Some(key) => serde_json::from_str::<serde_json::Value>(&secret)
                        .context("Secrets Manager SecretString is not valid JSON")?
                        .as_object()
                        .and_then(|object| object.get(key))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            anyhow!(
                                "Secrets Manager jsonKey must identify a top-level string field"
                            )
                        })?,
                }
            }
            SecretSource::Env { .. }
            | SecretSource::File { .. }
            | SecretSource::SecretKeyRef { .. } => {
                return Err(anyhow!("source is not an AWS secret source"))
            }
        };
        Ok(SecretString::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, path::PathBuf, sync::Mutex};

    #[derive(Default)]
    struct MockLocalSecrets {
        environment: HashMap<String, String>,
        files: HashMap<PathBuf, String>,
        calls: Mutex<Vec<String>>,
    }

    impl LocalSecrets for MockLocalSecrets {
        fn environment(&self, name: &str) -> anyhow::Result<String> {
            self.calls.lock().unwrap().push(format!("env:{name}"));
            self.environment
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow!("missing environment variable"))
        }

        fn file(&self, path: &std::path::Path) -> anyhow::Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("file:{}", path.display()));
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| anyhow!("missing secret file"))
        }
    }

    #[derive(Default)]
    struct MockSsm {
        resources: Vec<Parameter>,
        secrets: HashMap<String, Parameter>,
        calls: Mutex<Vec<String>>,
        resource_paths: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl SsmClient for MockSsm {
        async fn get_parameters_by_path(
            &self,
            path: &str,
            _: Option<String>,
        ) -> anyhow::Result<ParameterPage> {
            self.resource_paths.lock().unwrap().push(path.to_owned());
            Ok(ParameterPage {
                parameters: self
                    .resources
                    .iter()
                    .filter(|parameter| parameter.name.starts_with(path))
                    .cloned()
                    .collect(),
                next_token: None,
            })
        }

        async fn get_parameter(&self, name: &str) -> anyhow::Result<Option<Parameter>> {
            self.calls.lock().unwrap().push(name.to_owned());
            Ok(self.secrets.get(name).cloned())
        }
    }

    #[derive(Default)]
    struct MockSecretsManager {
        secrets: HashMap<String, Option<String>>,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl SecretsManagerClient for MockSecretsManager {
        async fn get_secret_string(&self, secret_id: &str) -> anyhow::Result<Option<String>> {
            self.calls.lock().unwrap().push(secret_id.to_owned());
            Ok(self.secrets.get(secret_id).cloned().flatten())
        }
    }

    fn upstream(secret: &str) -> String {
        format!(
            r#"apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://issuer.example
  oauthClient:
    clientId: upstream
    clientSecret:
{secret}
"#
        )
    }

    fn relay() -> String {
        r#"apiVersion: oauthrelay.dev/v1alpha1
kind: Relay
metadata:
  name: cognito-google
spec:
  upstreamRef:
    name: google
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    - uri: https://app.example/callback
"#
        .into()
    }

    fn resource(name: &str, value: String) -> Parameter {
        Parameter {
            name: name.into(),
            value,
            parameter_type: ParameterType::String,
        }
    }

    async fn load(
        secret: &str,
        ssm_secrets: HashMap<String, Parameter>,
        manager_secrets: HashMap<String, Option<String>>,
    ) -> (ProviderSnapshot, Arc<MockSsm>, Arc<MockSecretsManager>) {
        let ssm = Arc::new(MockSsm {
            resources: vec![
                resource("/oauthrelay/upstreams/google", upstream(secret)),
                resource("/oauthrelay/relays/cognito-google", relay()),
            ],
            secrets: ssm_secrets,
            calls: Mutex::new(vec![]),
            resource_paths: Mutex::new(vec![]),
        });
        let manager = Arc::new(MockSecretsManager {
            secrets: manager_secrets,
            calls: Mutex::new(vec![]),
        });
        let provider = SsmProvider::new(
            ssm.clone(),
            manager.clone(),
            DEFAULT_PREFIX,
            Duration::from_secs(1),
        )
        .unwrap();
        let snapshot = provider.load().await.unwrap();
        (snapshot, ssm, manager)
    }

    #[tokio::test]
    async fn resolves_secure_ssm_parameter() {
        let secret_name = "/oauthrelay/secrets/google";
        let (snapshot, ssm, manager) = load(
            "      valueFrom:\n        awsSsmParameter:\n          name: /oauthrelay/secrets/google",
            HashMap::from([(
                secret_name.into(),
                Parameter {
                    name: secret_name.into(),
                    value: "from-ssm".into(),
                    parameter_type: ParameterType::SecureString,
                },
            )]),
            HashMap::new(),
        )
        .await;
        assert_eq!(
            snapshot
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "from-ssm"
        );
        assert_eq!(ssm.calls.lock().unwrap().as_slice(), [secret_name]);
        assert!(manager.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn enumerates_only_upstream_and_relay_resources() {
        let (_, ssm, _) = load("      value: inline", HashMap::new(), HashMap::new()).await;
        assert_eq!(
            ssm.resource_paths.lock().unwrap().as_slice(),
            ["/oauthrelay/upstreams/", "/oauthrelay/relays/"]
        );
    }

    #[tokio::test]
    async fn resolves_whole_secrets_manager_secret_string() {
        let (snapshot, _, manager) = load(
            "      valueFrom:\n        awsSecretsManager:\n          secretId: oauthrelay/google",
            HashMap::new(),
            HashMap::from([("oauthrelay/google".into(), Some("whole-secret".into()))]),
        )
        .await;
        assert_eq!(
            snapshot
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "whole-secret"
        );
        assert_eq!(
            manager.calls.lock().unwrap().as_slice(),
            ["oauthrelay/google"]
        );
    }

    #[tokio::test]
    async fn resolves_secrets_manager_json_key() {
        let (snapshot, _, _) = load(
            "      valueFrom:\n        awsSecretsManager:\n          secretId: oauthrelay/google\n          jsonKey: clientSecret",
            HashMap::new(),
            HashMap::from([(
                "oauthrelay/google".into(),
                Some(r#"{"clientId":"id","clientSecret":"selected"}"#.into()),
            )]),
        )
        .await;
        assert_eq!(
            snapshot
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "selected"
        );
    }

    #[tokio::test]
    async fn json_key_requires_top_level_string() {
        for secret in ["not-json", r#"{"clientSecret":42}"#, r#"{"other":"x"}"#] {
            let ssm = Arc::new(MockSsm {
                resources: vec![
                    resource(
                        "/oauthrelay/upstreams/google",
                        upstream("      valueFrom:\n        awsSecretsManager:\n          secretId: oauthrelay/google\n          jsonKey: clientSecret"),
                    ),
                    resource("/oauthrelay/relays/cognito-google", relay()),
                ],
                ..Default::default()
            });
            let manager = Arc::new(MockSecretsManager {
                secrets: HashMap::from([("oauthrelay/google".into(), Some(secret.into()))]),
                ..Default::default()
            });
            let provider =
                SsmProvider::new(ssm, manager, DEFAULT_PREFIX, Duration::from_secs(1)).unwrap();
            let error = provider.load().await.unwrap_err().to_string();
            assert!(error.contains("Upstream/google"));
            assert!(!error.contains(secret));
        }
    }

    #[tokio::test]
    async fn validates_resource_path_document_and_parameter_type() {
        let manager = Arc::new(MockSecretsManager::default());
        for parameter in [
            resource(
                "/oauthrelay/upstreams/team/google",
                upstream("      value: hidden"),
            ),
            resource(
                "/oauthrelay/upstreams/wrong",
                upstream("      value: hidden"),
            ),
            Parameter {
                name: "/oauthrelay/upstreams/google".into(),
                value: upstream("      value: hidden"),
                parameter_type: ParameterType::SecureString,
            },
        ] {
            let ssm = Arc::new(MockSsm {
                resources: vec![parameter],
                ..Default::default()
            });
            let provider =
                SsmProvider::new(ssm, manager.clone(), DEFAULT_PREFIX, Duration::from_secs(1))
                    .unwrap();
            assert!(provider.load().await.is_err());
        }
    }

    #[tokio::test]
    async fn resolves_inline_environment_and_absolute_file_sources() {
        for (secret, expected, local) in [
            (
                "      value: inline",
                "inline",
                Arc::new(MockLocalSecrets::default()),
            ),
            (
                "      valueFrom:\n        env:\n          name: GOOGLE_SECRET",
                "from-env",
                Arc::new(MockLocalSecrets {
                    environment: HashMap::from([("GOOGLE_SECRET".into(), "from-env\n".into())]),
                    ..Default::default()
                }),
            ),
            (
                "      valueFrom:\n        file:\n          path: /run/secrets/google",
                "from-file",
                Arc::new(MockLocalSecrets {
                    files: HashMap::from([(
                        PathBuf::from("/run/secrets/google"),
                        "from-file\n".into(),
                    )]),
                    ..Default::default()
                }),
            ),
        ] {
            let ssm = Arc::new(MockSsm {
                resources: vec![
                    resource("/oauthrelay/upstreams/google", upstream(secret)),
                    resource("/oauthrelay/relays/cognito-google", relay()),
                ],
                ..Default::default()
            });
            let provider = SsmProvider::new(
                ssm,
                Arc::new(MockSecretsManager::default()),
                DEFAULT_PREFIX,
                Duration::from_secs(1),
            )
            .unwrap()
            .with_local_secrets(local);
            let snapshot = provider.load().await.unwrap();
            assert_eq!(
                snapshot
                    .upstreams
                    .values()
                    .next()
                    .unwrap()
                    .client_secret
                    .expose(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn ssm_resources_require_absolute_secret_file_paths() {
        let ssm = Arc::new(MockSsm {
            resources: vec![
                resource(
                    "/oauthrelay/upstreams/google",
                    upstream("      valueFrom:\n        file:\n          path: relative-secret"),
                ),
                resource("/oauthrelay/relays/cognito-google", relay()),
            ],
            ..Default::default()
        });
        let provider = SsmProvider::new(
            ssm,
            Arc::new(MockSecretsManager::default()),
            DEFAULT_PREFIX,
            Duration::from_secs(1),
        )
        .unwrap();
        let error = provider.load().await.unwrap_err();
        assert!(format!("{error:#}").contains("resource base directory"));
    }

    #[tokio::test]
    async fn rejects_non_secure_referenced_ssm_parameter_and_binary_secret() {
        let secret_name = "/oauthrelay/secrets/google";
        let ssm = Arc::new(MockSsm {
            resources: vec![
                resource(
                    "/oauthrelay/upstreams/google",
                    upstream(
                        "      valueFrom:\n        awsSsmParameter:\n          name: /oauthrelay/secrets/google",
                    ),
                ),
                resource("/oauthrelay/relays/cognito-google", relay()),
            ],
            secrets: HashMap::from([(
                secret_name.into(),
                Parameter {
                    name: secret_name.into(),
                    value: "not-encrypted".into(),
                    parameter_type: ParameterType::String,
                },
            )]),
            ..Default::default()
        });
        let provider = SsmProvider::new(
            ssm,
            Arc::new(MockSecretsManager::default()),
            DEFAULT_PREFIX,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(provider.load().await.is_err());

        let ssm = Arc::new(MockSsm {
            resources: vec![
                resource(
                    "/oauthrelay/upstreams/google",
                    upstream(
                        "      valueFrom:\n        awsSecretsManager:\n          secretId: oauthrelay/google",
                    ),
                ),
                resource("/oauthrelay/relays/cognito-google", relay()),
            ],
            ..Default::default()
        });
        let manager = Arc::new(MockSecretsManager {
            secrets: HashMap::from([("oauthrelay/google".into(), None)]),
            ..Default::default()
        });
        let provider =
            SsmProvider::new(ssm, manager, DEFAULT_PREFIX, Duration::from_secs(1)).unwrap();
        assert!(provider.load().await.is_err());
    }

    #[test]
    fn rejects_invalid_provider_prefix_and_interval() {
        let ssm = Arc::new(MockSsm::default());
        let manager = Arc::new(MockSecretsManager::default());
        assert!(SsmProvider::new(
            ssm.clone(),
            manager.clone(),
            "missing-slashes",
            Duration::from_secs(1)
        )
        .is_err());
        assert!(SsmProvider::new(ssm, manager, DEFAULT_PREFIX, Duration::ZERO).is_err());
    }
}
