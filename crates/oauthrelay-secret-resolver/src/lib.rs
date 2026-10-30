use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oauthrelay_core::{SecretResolver, SecretSource, SecretString};
use std::{path::PathBuf, sync::Arc};

/// Reads environment and filesystem secret values.
pub trait LocalSecrets: Send + Sync + 'static {
    fn environment(&self, name: &str) -> anyhow::Result<String>;
    fn file(&self, path: &std::path::Path) -> anyhow::Result<String>;
}

/// Reads secrets from the process environment and local filesystem.
pub struct SystemLocalSecrets;

impl LocalSecrets for SystemLocalSecrets {
    fn environment(&self, name: &str) -> anyhow::Result<String> {
        std::env::var(name).with_context(|| format!("environment variable {name} is not set"))
    }

    fn file(&self, path: &std::path::Path) -> anyhow::Result<String> {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
    }
}

/// Resolves every secret-source variant independently of resource discovery.
pub struct StandardSecretResolver {
    base_directory: Option<PathBuf>,
    local: Arc<dyn LocalSecrets>,
    aws: Option<Arc<dyn SecretResolver>>,
    kubernetes: Option<Arc<dyn SecretResolver>>,
}

impl StandardSecretResolver {
    /// Creates a resolver. Relative file paths require a base directory.
    pub fn new(base_directory: Option<PathBuf>) -> Self {
        Self {
            base_directory,
            local: Arc::new(SystemLocalSecrets),
            aws: None,
            kubernetes: None,
        }
    }

    /// Supplies environment and filesystem access.
    pub fn with_local_secrets(mut self, local: Arc<dyn LocalSecrets>) -> Self {
        self.local = local;
        self
    }

    /// Supplies namespace-scoped Kubernetes Secret resolution.
    pub fn with_kubernetes_secrets(mut self, resolver: Arc<dyn SecretResolver>) -> Self {
        self.kubernetes = Some(resolver);
        self
    }

    /// Supplies resolution for AWS-prefixed secret sources.
    pub fn with_aws_secrets(mut self, aws: Arc<dyn SecretResolver>) -> Self {
        self.aws = Some(aws);
        self
    }
}

#[async_trait]
impl SecretResolver for StandardSecretResolver {
    async fn resolve_value(&self, value: &str) -> anyhow::Result<SecretString> {
        Ok(SecretString::new(value))
    }

    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
        let value = match source {
            SecretSource::SecretKeyRef { .. } => {
                return self
                    .kubernetes
                    .as_ref()
                    .ok_or_else(|| anyhow!("Kubernetes secret resolution is not configured"))?
                    .resolve_source(source)
                    .await;
            }
            SecretSource::Env { name } => self.local.environment(name)?,
            SecretSource::File { path } => {
                let path = PathBuf::from(path);
                let path = if path.is_absolute() {
                    path
                } else {
                    self.base_directory
                        .as_ref()
                        .ok_or_else(|| {
                            anyhow!("relative secret file requires a resource base directory")
                        })?
                        .join(path)
                };
                self.local.file(&path)?
            }
            SecretSource::AwsSsmParameter { .. } | SecretSource::AwsSecretsManager { .. } => {
                return self
                    .aws
                    .as_ref()
                    .ok_or_else(|| anyhow!("AWS secret resolution is not configured"))?
                    .resolve_source(source)
                    .await;
            }
        };
        Ok(SecretString::new(value.trim_end_matches(['\r', '\n'])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, sync::Mutex};

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
            unreachable!()
        }

        async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
            self.calls.lock().unwrap().push(source.clone());
            Ok(SecretString::new("from-aws"))
        }
    }

    #[tokio::test]
    async fn resolves_every_source_through_one_path() {
        let base = PathBuf::from("/configuration");
        let local = Arc::new(MockLocalSecrets {
            environment: HashMap::from([("SECRET".into(), "from-env\n".into())]),
            files: HashMap::from([
                (base.join("relative"), "from-relative\r\n".into()),
                (PathBuf::from("/absolute"), "from-absolute".into()),
            ]),
            ..Default::default()
        });
        let aws = Arc::new(MockAwsSecrets::default());
        let resolver = StandardSecretResolver::new(Some(base))
            .with_local_secrets(local.clone())
            .with_aws_secrets(aws.clone());

        assert_eq!(
            resolver.resolve_value("inline").await.unwrap().expose(),
            "inline"
        );
        assert_eq!(
            resolver
                .resolve_source(&SecretSource::Env {
                    name: "SECRET".into()
                })
                .await
                .unwrap()
                .expose(),
            "from-env"
        );
        for (path, expected) in [
            ("relative", "from-relative"),
            ("/absolute", "from-absolute"),
        ] {
            assert_eq!(
                resolver
                    .resolve_source(&SecretSource::File { path: path.into() })
                    .await
                    .unwrap()
                    .expose(),
                expected
            );
        }
        let source = SecretSource::AwsSecretsManager {
            secret_id: "oauthrelay/google".into(),
            json_key: Some("clientSecret".into()),
        };
        assert_eq!(
            resolver.resolve_source(&source).await.unwrap().expose(),
            "from-aws"
        );
        assert_eq!(aws.calls.lock().unwrap().as_slice(), [source]);
        assert_eq!(local.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn relative_files_require_a_resource_base_directory() {
        let resolver = StandardSecretResolver::new(None);
        let error = resolver
            .resolve_source(&SecretSource::File {
                path: "relative".into(),
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("resource base directory"));
    }
}
