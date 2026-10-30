use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oauthrelay_core::{
    compile_resources, ConfigProvider, ProviderSnapshot, ResourceDocument, SecretResolver,
};
use oauthrelay_secret_resolver::{LocalSecrets, StandardSecretResolver, SystemLocalSecrets};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::watch;

pub const DEFAULT_PATH: &str = "/etc/oauthrelay/config.yaml";
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

pub struct FileProvider {
    path: PathBuf,
    poll_interval: Duration,
    local_secrets: Arc<dyn LocalSecrets>,
    aws_secrets: Option<Arc<dyn SecretResolver>>,
}

impl Default for FileProvider {
    fn default() -> Self {
        Self {
            path: DEFAULT_PATH.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            local_secrets: Arc::new(SystemLocalSecrets),
            aws_secrets: None,
        }
    }
}

impl FileProvider {
    pub fn new(path: impl Into<PathBuf>, poll_interval: Duration) -> anyhow::Result<Self> {
        if poll_interval.is_zero() {
            return Err(anyhow!(
                "file provider poll interval must be greater than zero"
            ));
        }
        Ok(Self {
            path: path.into(),
            poll_interval,
            local_secrets: Arc::new(SystemLocalSecrets),
            aws_secrets: None,
        })
    }

    /// Supplies environment and filesystem access to the standard secret resolver.
    pub fn with_local_secrets(mut self, local_secrets: Arc<dyn LocalSecrets>) -> Self {
        self.local_secrets = local_secrets;
        self
    }

    /// Supplies AWS-backed resolution for `awsSsmParameter` and `awsSecretsManager` references.
    pub fn with_aws_secrets(mut self, resolver: Arc<dyn SecretResolver>) -> Self {
        self.aws_secrets = Some(resolver);
        self
    }

    pub async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        let contents = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| format!("read {}", self.path.display()))?;
        let documents = parse_documents(&contents)?;
        let mut resolver = StandardSecretResolver::new(Some(
            self.path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .to_owned(),
        ))
        .with_local_secrets(self.local_secrets.clone());
        if let Some(aws) = &self.aws_secrets {
            resolver = resolver.with_aws_secrets(aws.clone());
        }
        compile_resources(documents, &resolver).await
    }
}

#[async_trait]
impl ConfigProvider for FileProvider {
    fn name(&self) -> &str {
        "file"
    }

    async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
        FileProvider::load(self).await
    }

    async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
        tx.send(self.load().await?)
            .map_err(|_| anyhow!("registry receiver closed"))?;
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match self.load().await {
                Ok(snapshot) => {
                    if tx.send(snapshot).is_err() {
                        return Ok(());
                    }
                }
                Err(error) => {
                    tracing::error!(path = %self.path.display(), %error, "invalid file provider configuration; keeping last good snapshot");
                }
            }
        }
    }
}

fn parse_documents(yaml: &str) -> anyhow::Result<Vec<ResourceDocument>> {
    serde_yaml::Deserializer::from_str(yaml)
        .map(|document| ResourceDocument::deserialize(document).context("parse resource document"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oauthrelay_core::{SecretSource, SecretString};
    use std::{collections::HashMap, sync::Mutex};
    use tempfile::NamedTempFile;

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
    struct MockAwsSecrets {
        calls: Mutex<Vec<SecretSource>>,
    }

    #[async_trait]
    impl SecretResolver for MockAwsSecrets {
        async fn resolve_value(&self, _: &str) -> anyhow::Result<SecretString> {
            unreachable!("StandardSecretResolver handles inline values")
        }

        async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
            self.calls.lock().unwrap().push(source.clone());
            let value = match source {
                SecretSource::AwsSsmParameter { .. } => "from-ssm",
                SecretSource::AwsSecretsManager { .. } => "from-secrets-manager",
                _ => unreachable!("only AWS sources are delegated"),
            };
            Ok(SecretString::new(value))
        }
    }

    fn yaml(secret: &str) -> String {
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
---
apiVersion: oauthrelay.dev/v1alpha1
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
        )
    }

    async fn load_with(secret: &str, secrets: Arc<dyn LocalSecrets>) -> ProviderSnapshot {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), yaml(secret)).unwrap();
        let provider = FileProvider::new(file.path(), Duration::from_secs(1))
            .unwrap()
            .with_local_secrets(secrets);
        provider.load().await.unwrap()
    }

    #[tokio::test]
    async fn resolves_inline_environment_and_relative_file_secrets() {
        let inline = load_with("      value: inline", Arc::new(MockLocalSecrets::default())).await;
        assert_eq!(
            inline
                .upstreams
                .values()
                .next()
                .unwrap()
                .client_secret
                .expose(),
            "inline"
        );

        let environment = Arc::new(MockLocalSecrets {
            environment: HashMap::from([("GOOGLE_SECRET".into(), "from-env".into())]),
            ..Default::default()
        });
        let snapshot = load_with(
            "      valueFrom:\n        env:\n          name: GOOGLE_SECRET",
            environment.clone(),
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
            "from-env"
        );
        assert_eq!(
            environment.calls.lock().unwrap().as_slice(),
            ["env:GOOGLE_SECRET"]
        );

        let file = NamedTempFile::new().unwrap();
        let base = file.path().parent().unwrap();
        let secret_path = base.join("relative-secret");
        let files = Arc::new(MockLocalSecrets {
            files: HashMap::from([(secret_path.clone(), "from-file\n".into())]),
            ..Default::default()
        });
        let snapshot = load_with(
            "      valueFrom:\n        file:\n          path: relative-secret",
            files.clone(),
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
            "from-file"
        );
        assert!(files.calls.lock().unwrap()[0].ends_with("relative-secret"));
    }

    #[tokio::test]
    async fn requires_aws_secret_resolution_for_aws_sources() {
        for secret in [
            "      valueFrom:\n        awsSsmParameter:\n          name: /secret",
            "      valueFrom:\n        awsSecretsManager:\n          secretId: oauthrelay/google\n          jsonKey: clientSecret",
        ] {
            let file = NamedTempFile::new().unwrap();
            std::fs::write(file.path(), yaml(secret)).unwrap();
            let provider = FileProvider::new(file.path(), Duration::from_secs(1)).unwrap();
            assert!(provider
                .load()
                .await
                .unwrap_err()
                .to_string()
                .contains("Upstream/google"));
        }
    }

    #[tokio::test]
    async fn delegates_aws_secret_sources() {
        let cases = [
            (
                "      valueFrom:\n        awsSsmParameter:\n          name: /secret",
                SecretSource::AwsSsmParameter {
                    name: "/secret".into(),
                },
                "from-ssm",
            ),
            (
                "      valueFrom:\n        awsSecretsManager:\n          secretId: oauthrelay/google\n          jsonKey: clientSecret",
                SecretSource::AwsSecretsManager {
                    secret_id: "oauthrelay/google".into(),
                    json_key: Some("clientSecret".into()),
                },
                "from-secrets-manager",
            ),
        ];

        for (secret, expected_source, expected_value) in cases {
            let file = NamedTempFile::new().unwrap();
            std::fs::write(file.path(), yaml(secret)).unwrap();
            let aws = Arc::new(MockAwsSecrets::default());
            let provider = FileProvider::new(file.path(), Duration::from_secs(1))
                .unwrap()
                .with_aws_secrets(aws.clone());
            let snapshot = provider.load().await.unwrap();
            assert_eq!(
                snapshot
                    .upstreams
                    .values()
                    .next()
                    .unwrap()
                    .client_secret
                    .expose(),
                expected_value
            );
            assert_eq!(aws.calls.lock().unwrap().as_slice(), [expected_source]);
        }
    }

    #[test]
    fn rejects_zero_poll_interval() {
        assert!(FileProvider::new("config.yaml", Duration::ZERO).is_err());
    }
}
