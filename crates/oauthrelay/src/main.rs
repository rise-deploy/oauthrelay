use anyhow::{anyhow, Context};
#[cfg(feature = "aws")]
use async_trait::async_trait;
#[cfg(feature = "lambda")]
use axum::{
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
};
use axum::{http::StatusCode, routing::get, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use oauthrelay_core::{
    resource_schema, router, ConfigProvider, DefaultLayout, KeyStrategy, MemoryStore,
    ProviderSnapshot, RedirectOptions, Registry, RelayConfig, TransientStore, XChaChaSealer,
};
#[cfg(feature = "aws")]
use oauthrelay_core::{SecretResolver, SecretSource, SecretString};
use oauthrelay_provider_file::FileProvider;
#[cfg(feature = "aws")]
use oauthrelay_provider_ssm::{
    AwsSecretResolver, AwsSecretsManagerClient, AwsSsmClient, SsmProvider,
};
#[cfg(feature = "aws")]
use oauthrelay_store_dynamodb::{AwsDynamoDbClient, DynamoDbStore};
#[cfg(feature = "lambda")]
use std::time::SystemTime;
use std::{
    env,
    io::IsTerminal,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::watch;
#[cfg(feature = "lambda")]
use tokio::sync::Mutex;
use url::Url;

struct RunningProvider {
    name: String,
    #[cfg(feature = "lambda")]
    provider: Arc<dyn ConfigProvider>,
    rx: watch::Receiver<ProviderSnapshot>,
    #[cfg(feature = "lambda")]
    task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "lambda")]
struct LambdaProvider {
    name: String,
    provider: Arc<dyn ConfigProvider>,
    snapshot: ProviderSnapshot,
}

#[cfg(feature = "lambda")]
struct LambdaRefreshState {
    // Wall time includes intervals while Lambda has frozen the process.
    last_attempt: SystemTime,
    providers: Vec<LambdaProvider>,
}

#[cfg(feature = "lambda")]
struct LambdaConfigRefresher {
    registry: Arc<Registry>,
    ttl: Duration,
    state: Mutex<LambdaRefreshState>,
}

#[cfg(feature = "aws")]
#[derive(Default)]
struct LazyAwsSecretResolver {
    resolver: tokio::sync::OnceCell<AwsSecretResolver<AwsSsmClient, AwsSecretsManagerClient>>,
}

#[cfg(feature = "aws")]
#[async_trait]
impl SecretResolver for LazyAwsSecretResolver {
    async fn resolve_value(&self, _: &str) -> anyhow::Result<SecretString> {
        Err(anyhow!(
            "inline values are resolved by StandardSecretResolver"
        ))
    }

    async fn resolve_source(&self, source: &SecretSource) -> anyhow::Result<SecretString> {
        let resolver = self
            .resolver
            .get_or_try_init(|| async {
                let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                Ok::<_, anyhow::Error>(AwsSecretResolver::new(
                    Arc::new(AwsSsmClient(aws_sdk_ssm_client(&config))),
                    Arc::new(AwsSecretsManagerClient(
                        aws_sdk_secretsmanager::Client::new(&config),
                    )),
                ))
            })
            .await?;
        resolver.resolve_source(source).await
    }
}

#[cfg(feature = "lambda")]
const DEFAULT_LAMBDA_CONFIG_TTL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::args().nth(1).as_deref() == Some("schema") {
        println!("{}", serde_json::to_string_pretty(&resource_schema())?);
        return Ok(());
    }
    if env::args().nth(1).as_deref() == Some("crds") {
        #[cfg(feature = "kubernetes")]
        {
            print!(
                "{}---\n{}",
                oauthrelay_provider_kubernetes::crds_yaml()?,
                oauthrelay_store_kubernetes::crds_yaml()?
            );
            return Ok(());
        }
        #[cfg(not(feature = "kubernetes"))]
        return Err(anyhow!("crds requires the oauthrelay kubernetes feature"));
    }
    init_tracing();
    let public_url = required_url("OAUTHRELAY_PUBLIC_URL")?;
    let current = seal_key("OAUTHRELAY_SEAL_KEY", true)?.expect("required key");
    let previous = seal_key("OAUTHRELAY_SEAL_KEY_PREVIOUS", false)?;
    let sealer = Arc::new(XChaChaSealer::new(&current, previous.as_deref())?);
    let providers = configured_providers().await?;
    if providers.is_empty() {
        return Err(anyhow!(
            "at least one provider is required; set OAUTHRELAY_PROVIDER_FILE, OAUTHRELAY_PROVIDER_SSM_PREFIX, or OAUTHRELAY_PROVIDER_KUBERNETES=true"
        ));
    }
    let store = configured_store().await?;
    let redirect_options = RedirectOptions {
        allow_localhost_loopback: bool_env("OAUTHRELAY_ALLOW_LOCALHOST_LOOPBACK", false)?,
        allow_http_origins: bool_env("OAUTHRELAY_ALLOW_HTTP_ORIGINS", false)?,
    };
    let registry = Arc::new(Registry::default());
    let mut running = start_providers(providers);
    await_initial_snapshots(&mut running).await?;
    replace_registry(&registry, &running);
    check_redirect_options(&registry.snapshot(), redirect_options)?;

    let relay_router = router(
        registry.clone(),
        RelayConfig {
            public_url,
            sealer,
            store: Some(store),
            http: reqwest::Client::builder().build()?,
            client_assertion_http: oauthrelay_core::ClientAssertionHttpClient::new(
                reqwest::Client::builder(),
            )?,
            redirect: redirect_options,
        },
        Arc::new(DefaultLayout::new(KeyStrategy::SingleSegment)),
    );
    let ready = Arc::new(AtomicBool::new(true));
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(
            "/readyz",
            get({
                let ready = ready.clone();
                move || async move {
                    if ready.load(Ordering::Relaxed) {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        )
        .merge(relay_router);

    if is_lambda_runtime() {
        #[cfg(feature = "lambda")]
        {
            // Lambda refreshes providers at invocation boundaries because it freezes between requests.
            let refresh_ttl =
                duration_env("OAUTHRELAY_LAMBDA_CONFIG_TTL", DEFAULT_LAMBDA_CONFIG_TTL)?;
            let refresher = Arc::new(LambdaConfigRefresher::new(registry, running, refresh_ttl));
            let app = app.layer(middleware::from_fn_with_state(
                refresher,
                refresh_lambda_config,
            ));
            tracing::info!("starting AWS Lambda runtime");
            lambda_http::run(app)
                .await
                .map_err(|error| anyhow!("Lambda runtime failed: {error}"))?;
            return Ok(());
        }
        #[cfg(not(feature = "lambda"))]
        return Err(anyhow!("binary was built without the lambda feature"));
    }

    let updater = spawn_registry_updater(registry, running);
    let listen = env::var("OAUTHRELAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    tracing::info!(%listen, "oauthrelay ready");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    updater.abort();
    Ok(())
}

/// Which [`TransientStore`] backend `OAUTHRELAY_STORE` selects.
#[derive(Debug, Eq, PartialEq)]
enum StoreConfig {
    Memory,
    DynamoDb {
        table: String,
    },
    Kubernetes {
        /// The `plural.group` resource name, validated where the store crate is linked; `None`
        /// is the store's own `TransientRecord`.
        resource: Option<String>,
        /// `None` follows the provider namespace, then the pod or kubeconfig namespace, except
        /// for Dex's resource, which has no fallback and needs Dex's namespace named.
        namespace: Option<String>,
        /// `None` disables the sweeper.
        sweep: Option<Duration>,
    },
}

const DEFAULT_KUBERNETES_SWEEP: Duration = Duration::from_secs(60);

/// The raw values of the `OAUTHRELAY_STORE*` environment variables.
#[derive(Default)]
struct StoreEnv<'a> {
    kind: Option<&'a str>,
    dynamodb_table: Option<&'a str>,
    kubernetes_resource: Option<&'a str>,
    kubernetes_namespace: Option<&'a str>,
    kubernetes_sweep: Option<&'a str>,
}

fn parse_store_config(env: StoreEnv<'_>) -> anyhow::Result<StoreConfig> {
    // Settings of a backend that is not selected are rejected rather than silently ignored.
    if env.kind != Some("dynamodb") && env.dynamodb_table.is_some() {
        return Err(anyhow!(
            "OAUTHRELAY_STORE_DYNAMODB_TABLE requires OAUTHRELAY_STORE=dynamodb"
        ));
    }
    if env.kind != Some("kubernetes") {
        let kubernetes_settings = [
            (
                "OAUTHRELAY_STORE_KUBERNETES_RESOURCE",
                env.kubernetes_resource,
            ),
            (
                "OAUTHRELAY_STORE_KUBERNETES_NAMESPACE",
                env.kubernetes_namespace,
            ),
            ("OAUTHRELAY_STORE_KUBERNETES_SWEEP", env.kubernetes_sweep),
        ];
        if let Some((name, _)) = kubernetes_settings
            .iter()
            .find(|(_, value)| value.is_some())
        {
            return Err(anyhow!("{name} requires OAUTHRELAY_STORE=kubernetes"));
        }
    }
    match env.kind {
        None | Some("memory") => Ok(StoreConfig::Memory),
        Some("dynamodb") => {
            let table = env.dynamodb_table.ok_or_else(|| {
                anyhow!("OAUTHRELAY_STORE=dynamodb requires OAUTHRELAY_STORE_DYNAMODB_TABLE")
            })?;
            let valid = (3..=255).contains(&table.len())
                && table
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
            if !valid {
                return Err(anyhow!(
                    "OAUTHRELAY_STORE_DYNAMODB_TABLE must be a DynamoDB table name: 3-255 characters from A-Z, a-z, 0-9, '_', '-' and '.'"
                ));
            }
            Ok(StoreConfig::DynamoDb {
                table: table.to_owned(),
            })
        }
        Some("kubernetes") => {
            let sweep = match env.kubernetes_sweep {
                None => Some(DEFAULT_KUBERNETES_SWEEP),
                Some("off") => None,
                Some(value) => Some(parse_duration("OAUTHRELAY_STORE_KUBERNETES_SWEEP", value)?),
            };
            Ok(StoreConfig::Kubernetes {
                resource: env.kubernetes_resource.map(str::to_owned),
                namespace: env.kubernetes_namespace.map(str::to_owned),
                sweep,
            })
        }
        Some(other) => Err(anyhow!(
            "OAUTHRELAY_STORE must be memory, dynamodb or kubernetes, got {other:?}"
        )),
    }
}

async fn configured_store() -> anyhow::Result<Arc<dyn TransientStore>> {
    let read = |name: &str| env::var(name).ok();
    let (kind, table) = (
        read("OAUTHRELAY_STORE"),
        read("OAUTHRELAY_STORE_DYNAMODB_TABLE"),
    );
    let (resource, namespace, sweep) = (
        read("OAUTHRELAY_STORE_KUBERNETES_RESOURCE"),
        read("OAUTHRELAY_STORE_KUBERNETES_NAMESPACE"),
        read("OAUTHRELAY_STORE_KUBERNETES_SWEEP"),
    );
    let config = parse_store_config(StoreEnv {
        kind: kind.as_deref(),
        dynamodb_table: table.as_deref(),
        kubernetes_resource: resource.as_deref(),
        kubernetes_namespace: namespace.as_deref(),
        kubernetes_sweep: sweep.as_deref(),
    })?;
    reject_kubernetes_on_lambda(&config, is_lambda_runtime())?;
    match config {
        StoreConfig::Memory => {
            if is_lambda_runtime() {
                tracing::warn!(
                    "the memory store only protects against replay within one Lambda execution environment; set OAUTHRELAY_STORE=dynamodb for deployment-wide single use"
                );
            }
            Ok(Arc::new(MemoryStore::default()))
        }
        #[cfg(feature = "aws")]
        StoreConfig::DynamoDb { table } => {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            tracing::info!(%table, "using DynamoDB transient store");
            Ok(Arc::new(DynamoDbStore::new(Arc::new(
                AwsDynamoDbClient::new(aws_sdk_dynamodb::Client::new(&config), table),
            ))))
        }
        #[cfg(not(feature = "aws"))]
        StoreConfig::DynamoDb { .. } => Err(anyhow!(
            "OAUTHRELAY_STORE=dynamodb requires the oauthrelay aws feature"
        )),
        #[cfg(feature = "kubernetes")]
        StoreConfig::Kubernetes {
            resource,
            namespace,
            sweep,
        } => {
            use oauthrelay_store_kubernetes::{
                KubeClient, KubernetesStore, RecordMapping, DEX_MINIMUM_VERSION,
            };
            let mapping = kubernetes_mapping(resource.as_deref())?;
            let mut config = kube_config().await?;
            // The store bounds its own requests (`OPERATION_DEADLINE`). Kube's default retry
            // layer would instead retry 429, 503 and 504 for as long as the server keeps
            // answering them, honouring `Retry-After`: a stalled token request, and a claim
            // that outlives its lease.
            config.default_retry = false;
            // The provider's namespace is the natural home for records when it is enabled.
            let provider_namespace = if bool_env("OAUTHRELAY_PROVIDER_KUBERNETES", false)? {
                env::var("OAUTHRELAY_PROVIDER_KUBERNETES_NAMESPACE").ok()
            } else {
                None
            };
            let namespace = kubernetes_store_namespace(
                mapping,
                namespace.as_deref(),
                provider_namespace.as_deref(),
                &config.default_namespace,
            )?;
            if mapping == RecordMapping::DexAuthCode {
                tracing::warn!(
                    minimum_dex_version = DEX_MINIMUM_VERSION,
                    %namespace,
                    "the Dex AuthCode store requires Dex {DEX_MINIMUM_VERSION} or later in that namespace; oauthrelay cannot detect Dex's version, and older Dex releases let anyone who knows a record's name redeem it through the device callback"
                );
            }
            let client =
                KubeClient::new(kube::Client::try_from(config)?, namespace.clone(), mapping);
            let mut store = KubernetesStore::new(Arc::new(client));
            store.probe().await?;
            if let Some(interval) = sweep {
                store = store.with_sweeper(interval);
            }
            tracing::info!(resource = mapping.resource_name(), %namespace, sweep = ?sweep, "using Kubernetes transient store");
            Ok(Arc::new(store))
        }
        #[cfg(not(feature = "kubernetes"))]
        StoreConfig::Kubernetes { .. } => Err(anyhow!(
            "OAUTHRELAY_STORE=kubernetes requires the oauthrelay kubernetes feature"
        )),
    }
}

/// Lambda freezes the process between invocations, so no background sweeper would run, and the
/// Kubernetes store has no other way to delete expired records.
fn reject_kubernetes_on_lambda(config: &StoreConfig, lambda: bool) -> anyhow::Result<()> {
    if lambda && matches!(config, StoreConfig::Kubernetes { .. }) {
        return Err(anyhow!(
            "OAUTHRELAY_STORE=kubernetes is not supported on AWS Lambda: the process is frozen between invocations, so nothing would delete expired records. Use OAUTHRELAY_STORE=dynamodb, whose TTL deletes them"
        ));
    }
    Ok(())
}

/// The namespace for the Kubernetes store's records: `explicit` (`OAUTHRELAY_STORE_KUBERNETES_NAMESPACE`),
/// then the provider's, then the pod or kubeconfig `default`.
///
/// Dex's records live in Dex's namespace and nowhere else, because that is where Dex's garbage
/// collector runs, so that mapping accepts only an explicit namespace.
#[cfg(feature = "kubernetes")]
fn kubernetes_store_namespace(
    mapping: oauthrelay_store_kubernetes::RecordMapping,
    explicit: Option<&str>,
    provider: Option<&str>,
    default: &str,
) -> anyhow::Result<String> {
    if mapping.needs_explicit_namespace() && explicit.is_none() {
        return Err(anyhow!(
            "OAUTHRELAY_STORE_KUBERNETES_RESOURCE={} requires OAUTHRELAY_STORE_KUBERNETES_NAMESPACE to name Dex's namespace: Dex garbage-collects expired authcodes only there, so it is never inferred from the provider or pod namespace",
            mapping.resource_name()
        ));
    }
    oauthrelay_provider_kubernetes::select_namespace(explicit.or(provider), default)
}

/// The store's mapping for `OAUTHRELAY_STORE_KUBERNETES_RESOURCE`.
#[cfg(feature = "kubernetes")]
fn kubernetes_mapping(
    resource: Option<&str>,
) -> anyhow::Result<oauthrelay_store_kubernetes::RecordMapping> {
    use oauthrelay_store_kubernetes::RecordMapping;
    let Some(name) = resource else {
        return Ok(RecordMapping::TransientRecord);
    };
    RecordMapping::from_resource_name(name).ok_or_else(|| {
        let supported: Vec<_> = RecordMapping::ALL
            .iter()
            .map(|mapping| mapping.resource_name())
            .collect();
        anyhow!(
            "OAUTHRELAY_STORE_KUBERNETES_RESOURCE must be one of {}, got {name:?}",
            supported.join(", ")
        )
    })
}

/// Credentials for the cluster: the pod's service account in a pod, else the active kubeconfig.
#[cfg(feature = "kubernetes")]
async fn kube_config() -> anyhow::Result<kube::Config> {
    if env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        kube::Config::incluster().context("load in-cluster Kubernetes credentials")
    } else {
        kube::Config::from_kubeconfig(&Default::default())
            .await
            .context("load Kubernetes kubeconfig")
    }
}

async fn configured_providers() -> anyhow::Result<Vec<Arc<dyn ConfigProvider>>> {
    let mut providers: Vec<Arc<dyn ConfigProvider>> = Vec::new();
    let file_path = env::var("OAUTHRELAY_PROVIDER_FILE").ok();
    let ssm_prefix = env::var("OAUTHRELAY_PROVIDER_SSM_PREFIX").ok();

    #[cfg(feature = "aws")]
    let aws_clients = if ssm_prefix.is_some() {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Some((
            Arc::new(AwsSsmClient(aws_sdk_ssm_client(&config))),
            Arc::new(AwsSecretsManagerClient(
                aws_sdk_secretsmanager::Client::new(&config),
            )),
        ))
    } else {
        None
    };

    if let Some(path) = file_path {
        let provider = FileProvider::new(
            path,
            duration_env("OAUTHRELAY_PROVIDER_FILE_POLL", Duration::from_secs(30))?,
        )?;
        #[cfg(feature = "aws")]
        let provider = provider.with_aws_secrets(Arc::new(LazyAwsSecretResolver::default()));
        providers.push(Arc::new(provider));
    }
    #[cfg(feature = "aws")]
    if let Some(prefix) = ssm_prefix {
        let (ssm, secrets_manager) = aws_clients.as_ref().expect("AWS clients initialized");
        providers.push(Arc::new(SsmProvider::new(
            ssm.clone(),
            secrets_manager.clone(),
            prefix,
            duration_env("OAUTHRELAY_PROVIDER_SSM_POLL", Duration::from_secs(60))?,
        )?));
    }
    #[cfg(not(feature = "aws"))]
    if ssm_prefix.is_some() {
        return Err(anyhow!(
            "OAUTHRELAY_PROVIDER_SSM_PREFIX requires the oauthrelay aws feature"
        ));
    }
    if bool_env("OAUTHRELAY_PROVIDER_KUBERNETES", false)? {
        #[cfg(feature = "kubernetes")]
        {
            use oauthrelay_provider_kubernetes::{
                select_namespace, KubernetesProvider, DEFAULT_REFRESH_INTERVAL,
            };
            let config = kube_config().await?;
            let namespace = select_namespace(
                env::var("OAUTHRELAY_PROVIDER_KUBERNETES_NAMESPACE")
                    .ok()
                    .as_deref(),
                &config.default_namespace,
            )?;
            let provider = KubernetesProvider::new(
                kube::Client::try_from(config)?,
                namespace,
                duration_env(
                    "OAUTHRELAY_PROVIDER_KUBERNETES_REFRESH",
                    DEFAULT_REFRESH_INTERVAL,
                )?,
            )?;
            #[cfg(feature = "aws")]
            let provider = provider.with_aws_secrets(Arc::new(LazyAwsSecretResolver::default()));
            providers.push(Arc::new(provider));
        }
        #[cfg(not(feature = "kubernetes"))]
        return Err(anyhow!(
            "OAUTHRELAY_PROVIDER_KUBERNETES requires the oauthrelay kubernetes feature"
        ));
    }
    Ok(providers)
}

#[cfg(feature = "aws")]
fn aws_sdk_ssm_client(config: &aws_config::SdkConfig) -> aws_sdk_ssm::Client {
    aws_sdk_ssm::Client::new(config)
}

fn start_providers(providers: Vec<Arc<dyn ConfigProvider>>) -> Vec<RunningProvider> {
    providers
        .into_iter()
        .map(|provider| {
            let name = provider.name().to_owned();
            let (tx, rx) = watch::channel(ProviderSnapshot::default());
            let log_name = name.clone();
            let task_provider = provider.clone();
            let task = tokio::spawn(async move {
                if let Err(error) = task_provider.run(tx).await {
                    tracing::error!(provider = %log_name, %error, "config provider stopped");
                }
            });
            #[cfg(not(feature = "lambda"))]
            drop(task);
            RunningProvider {
                name,
                #[cfg(feature = "lambda")]
                provider,
                rx,
                #[cfg(feature = "lambda")]
                task,
            }
        })
        .collect()
}

#[cfg(feature = "lambda")]
impl LambdaConfigRefresher {
    fn new(registry: Arc<Registry>, providers: Vec<RunningProvider>, ttl: Duration) -> Self {
        let providers = providers
            .into_iter()
            .map(|running| {
                running.task.abort();
                LambdaProvider {
                    name: running.name,
                    provider: running.provider,
                    snapshot: running.rx.borrow().clone(),
                }
            })
            .collect();
        Self {
            registry,
            ttl,
            state: Mutex::new(LambdaRefreshState {
                last_attempt: SystemTime::now(),
                providers,
            }),
        }
    }

    async fn refresh_if_stale(&self) {
        let mut state = self.state.lock().await;
        let is_fresh = SystemTime::now()
            .duration_since(state.last_attempt)
            .is_ok_and(|age| age < self.ttl);
        if is_fresh {
            return;
        }
        state.last_attempt = SystemTime::now();

        for provider in &mut state.providers {
            match provider.provider.load().await {
                Ok(snapshot) => provider.snapshot = snapshot,
                Err(error) => {
                    tracing::error!(
                        provider = %provider.name,
                        %error,
                        "Lambda provider refresh failed; keeping last good snapshot"
                    );
                }
            }
        }

        let snapshots: Vec<_> = state
            .providers
            .iter()
            .map(|provider| (provider.name.as_str(), &provider.snapshot))
            .collect();
        self.registry.replace(Registry::merge_ordered(
            snapshots.iter().map(|(name, snapshot)| (*name, *snapshot)),
        ));
    }
}

#[cfg(feature = "lambda")]
async fn refresh_lambda_config(
    State(refresher): State<Arc<LambdaConfigRefresher>>,
    request: Request,
    next: Next,
) -> Response {
    refresher.refresh_if_stale().await;
    next.run(request).await
}

async fn await_initial_snapshots(providers: &mut [RunningProvider]) -> anyhow::Result<()> {
    for provider in providers {
        provider.rx.changed().await.with_context(|| {
            format!(
                "provider {} stopped before its first snapshot",
                provider.name
            )
        })?;
    }
    Ok(())
}

/// Fails startup when a configured relay needs a redirect option this service leaves off. A relay
/// that later gains such a matcher through a provider refresh fails each request instead.
fn check_redirect_options(
    snapshot: &ProviderSnapshot,
    options: RedirectOptions,
) -> anyhow::Result<()> {
    let mut keys: Vec<_> = snapshot.relays.keys().collect();
    keys.sort();
    for key in keys {
        snapshot.relays[key]
            .validate_for(options)
            .map_err(|error| anyhow!("Relay/{key}: {error}"))?;
    }
    Ok(())
}

fn replace_registry(registry: &Registry, providers: &[RunningProvider]) {
    let snapshots: Vec<_> = providers
        .iter()
        .map(|provider| (provider.name.as_str(), provider.rx.borrow().clone()))
        .collect();
    registry.replace(Registry::merge_ordered(
        snapshots.iter().map(|(name, snapshot)| (*name, snapshot)),
    ));
}

fn spawn_registry_updater(
    registry: Arc<Registry>,
    mut providers: Vec<RunningProvider>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let mut changed = false;
            for provider in &mut providers {
                match provider.rx.has_changed() {
                    Ok(true) => {
                        provider.rx.borrow_and_update();
                        changed = true;
                    }
                    Ok(false) => {}
                    Err(_) => {}
                }
            }
            if changed {
                replace_registry(&registry, &providers);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

fn required_url(name: &str) -> anyhow::Result<Url> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    let url = Url::parse(&value).with_context(|| format!("{name} must be a URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(anyhow!("{name} must be an absolute http(s) URL"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!("{name} must not contain a query or fragment"));
    }
    Ok(url)
}

fn seal_key(name: &str, required: bool) -> anyhow::Result<Option<Vec<u8>>> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(_) if required => return Err(anyhow!("{name} is required")),
        Err(_) => return Ok(None),
    };
    let encoded = value.strip_prefix("base64:").unwrap_or(&value);
    let bytes = STANDARD
        .decode(encoded)
        .with_context(|| format!("{name} must be base64"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{name} must decode to exactly 32 bytes"));
    }
    Ok(Some(bytes))
}

fn duration_env(name: &str, default: Duration) -> anyhow::Result<Duration> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    parse_duration(name, &value)
}

fn bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    let Ok(value) = env::var(name) else {
        return Ok(default);
    };
    parse_bool(name, &value)
}

fn parse_bool(name: &str, value: &str) -> anyhow::Result<bool> {
    value
        .parse()
        .with_context(|| format!("{name} must be true or false"))
}

fn parse_duration(name: &str, value: &str) -> anyhow::Result<Duration> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1_u64)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1_000)
    } else if let Some(value) = value.strip_suffix('m') {
        (value, 60_000)
    } else if let Some(value) = value.strip_suffix('h') {
        (value, 3_600_000)
    } else {
        return Err(anyhow!("{name} must use ms, s, m, or h units"));
    };
    let millis: u64 = number.parse().with_context(|| format!("invalid {name}"))?;
    let millis = millis
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("{name} is too large"))?;
    let duration = Duration::from_millis(millis);
    if duration.is_zero() {
        return Err(anyhow!("{name} must be greater than zero"));
    }
    Ok(duration)
}

fn is_lambda_runtime() -> bool {
    env::var_os("AWS_LAMBDA_RUNTIME_API").is_some()
}

fn init_tracing() {
    let filter = env::var("OAUTHRELAY_LOG").unwrap_or_else(|_| "info".into());
    let builder =
        tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::new(filter));
    if std::io::stdout().is_terminal() {
        builder.compact().init();
    } else {
        builder.json().init();
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "lambda")]
    use async_trait::async_trait;
    #[cfg(feature = "lambda")]
    use oauthrelay_core::{
        ClientAuth, RedirectMatcher, Relay, ResourceKey, SecretString, TokenEndpointAuthMethod,
        Upstream,
    };

    #[cfg(feature = "lambda")]
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn startup_rejects_http_origins_unless_allowed() {
        use oauthrelay_core::{
            ClientAuth, RedirectMatcher, Relay, ResourceKey, SecretString, TokenEndpointAuthMethod,
            Upstream,
        };
        let key = ResourceKey::new("dev").unwrap();
        let mut snapshot = ProviderSnapshot::default();
        snapshot.upstreams.insert(
            key.clone(),
            Arc::new(Upstream {
                key: key.clone(),
                issuer_url: Url::parse("https://issuer.example").unwrap(),
                authorization_endpoint: None,
                token_endpoint: None,
                jwks_uri: None,
                client_id: "upstream".into(),
                client_secret: SecretString::new("secret"),
                token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
            }),
        );
        snapshot.relays.insert(
            key.clone(),
            Arc::new(Relay {
                key: key.clone(),
                upstream: key,
                client_auth: ClientAuth::Public,
                scopes: vec![],
                allowed_scopes: None,
                required_id_token_claims: std::collections::HashMap::new(),
                id_token_policy: None,
                refresh_tokens: Default::default(),
                redirect_policy: vec![
                    RedirectMatcher::http_origin("http://dev.example:3000").unwrap()
                ],
            }),
        );
        let error = check_redirect_options(&snapshot, RedirectOptions::default()).unwrap_err();
        let error = error.to_string();
        assert!(error.starts_with("Relay/dev: "), "{error}");
        assert!(error.contains("OAUTHRELAY_ALLOW_HTTP_ORIGINS"), "{error}");
        assert!(check_redirect_options(
            &snapshot,
            RedirectOptions {
                allow_http_origins: true,
                ..Default::default()
            }
        )
        .is_ok());
    }

    #[cfg(feature = "lambda")]
    struct ReloadingProvider {
        loads: AtomicUsize,
    }

    #[cfg(feature = "lambda")]
    fn snapshot(key_text: &str) -> ProviderSnapshot {
        let key = ResourceKey::new(key_text).unwrap();
        let upstream = Arc::new(Upstream {
            key: key.clone(),
            issuer_url: Url::parse("https://issuer.example").unwrap(),
            authorization_endpoint: Some(Url::parse("https://issuer.example/authorize").unwrap()),
            token_endpoint: Some(Url::parse("https://issuer.example/token").unwrap()),
            jwks_uri: None,
            client_id: "upstream".into(),
            client_secret: SecretString::new("secret"),
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretPost,
        });
        let relay = Arc::new(Relay {
            key: key.clone(),
            upstream: key.clone(),
            client_auth: ClientAuth::Public,
            scopes: vec![],
            allowed_scopes: None,
            required_id_token_claims: std::collections::HashMap::new(),
            id_token_policy: None,
            refresh_tokens: Default::default(),
            redirect_policy: vec![RedirectMatcher::uri("https://app.example/callback").unwrap()],
        });
        let mut snapshot = ProviderSnapshot::default();
        snapshot.upstreams.insert(key.clone(), upstream);
        snapshot.relays.insert(key, relay);
        snapshot
    }

    #[cfg(feature = "lambda")]
    #[async_trait]
    impl ConfigProvider for ReloadingProvider {
        fn name(&self) -> &str {
            "reload-test"
        }

        async fn load(&self) -> anyhow::Result<ProviderSnapshot> {
            match self.loads.fetch_add(1, Ordering::SeqCst) {
                0 => Ok(snapshot("initial")),
                1 => Ok(snapshot("refreshed")),
                _ => Err(anyhow!("refresh failed")),
            }
        }

        async fn run(self: Arc<Self>, tx: watch::Sender<ProviderSnapshot>) -> anyhow::Result<()> {
            tx.send(self.load().await?)?;
            std::future::pending().await
        }
    }

    #[test]
    fn durations_support_documented_units() {
        assert_eq!(
            parse_duration("TEST", "1ms").unwrap(),
            Duration::from_millis(1)
        );
        assert_eq!(
            parse_duration("TEST", "2s").unwrap(),
            Duration::from_secs(2)
        );
        assert_eq!(
            parse_duration("TEST", "3m").unwrap(),
            Duration::from_secs(3 * 60)
        );
        assert_eq!(
            parse_duration("TEST", "1h").unwrap(),
            Duration::from_secs(60 * 60)
        );
    }

    #[test]
    fn durations_require_units_and_positive_integer_values() {
        assert!(parse_duration("TEST", "0s").is_err());
        assert!(parse_duration("TEST", "1").is_err());
        assert!(parse_duration("TEST", "1d").is_err());
        assert!(parse_duration("TEST", "1.5h").is_err());
    }

    #[test]
    fn durations_reject_millisecond_overflow() {
        let largest_hours = u64::MAX / 3_600_000;
        assert_eq!(
            parse_duration("TEST", &format!("{largest_hours}h")).unwrap(),
            Duration::from_millis(largest_hours * 3_600_000)
        );
        assert!(parse_duration("TEST", &format!("{}h", largest_hours + 1)).is_err());
    }

    fn store_env(kind: Option<&str>) -> StoreEnv<'_> {
        StoreEnv {
            kind,
            ..StoreEnv::default()
        }
    }

    #[test]
    fn store_defaults_to_memory_and_validates_selection() {
        assert_eq!(
            parse_store_config(store_env(None)).unwrap(),
            StoreConfig::Memory
        );
        assert_eq!(
            parse_store_config(store_env(Some("memory"))).unwrap(),
            StoreConfig::Memory
        );
        assert_eq!(
            parse_store_config(StoreEnv {
                dynamodb_table: Some("oauthrelay-store"),
                ..store_env(Some("dynamodb"))
            })
            .unwrap(),
            StoreConfig::DynamoDb {
                table: "oauthrelay-store".into()
            }
        );
        assert!(parse_store_config(store_env(Some("dynamodb"))).is_err());
        assert!(parse_store_config(store_env(Some("redis"))).is_err());
        for kind in [None, Some("memory"), Some("kubernetes")] {
            assert!(
                parse_store_config(StoreEnv {
                    dynamodb_table: Some("oauthrelay-store"),
                    ..store_env(kind)
                })
                .is_err(),
                "{kind:?}"
            );
        }
        for table in ["", "ab", "has space", "slash/name", &"t".repeat(256)] {
            assert!(
                parse_store_config(StoreEnv {
                    dynamodb_table: Some(table),
                    ..store_env(Some("dynamodb"))
                })
                .is_err(),
                "{table:?}"
            );
        }
    }

    #[test]
    fn kubernetes_store_has_defaults_and_validates_its_settings() {
        assert_eq!(
            parse_store_config(store_env(Some("kubernetes"))).unwrap(),
            StoreConfig::Kubernetes {
                resource: None,
                namespace: None,
                sweep: Some(Duration::from_secs(60)),
            }
        );
        assert_eq!(
            parse_store_config(StoreEnv {
                kubernetes_resource: Some("transientrecords.oauthrelay.dev"),
                kubernetes_namespace: Some("relay-state"),
                kubernetes_sweep: Some("5m"),
                ..store_env(Some("kubernetes"))
            })
            .unwrap(),
            StoreConfig::Kubernetes {
                resource: Some("transientrecords.oauthrelay.dev".into()),
                namespace: Some("relay-state".into()),
                sweep: Some(Duration::from_secs(300)),
            }
        );
        assert_eq!(
            parse_store_config(StoreEnv {
                kubernetes_sweep: Some("off"),
                ..store_env(Some("kubernetes"))
            })
            .unwrap(),
            StoreConfig::Kubernetes {
                resource: None,
                namespace: None,
                sweep: None,
            }
        );
        for sweep in ["", "0s", "60", "Off", "1d"] {
            assert!(
                parse_store_config(StoreEnv {
                    kubernetes_sweep: Some(sweep),
                    ..store_env(Some("kubernetes"))
                })
                .is_err(),
                "{sweep:?}"
            );
        }
        assert_eq!(
            parse_store_config(StoreEnv {
                kubernetes_resource: Some("authcodes.dex.coreos.com"),
                kubernetes_namespace: Some("dex"),
                ..store_env(Some("kubernetes"))
            })
            .unwrap(),
            StoreConfig::Kubernetes {
                resource: Some("authcodes.dex.coreos.com".into()),
                namespace: Some("dex".into()),
                sweep: Some(Duration::from_secs(60)),
            }
        );
    }

    #[cfg(feature = "kubernetes")]
    #[test]
    fn kubernetes_resource_names_select_a_store_mapping() {
        use oauthrelay_store_kubernetes::RecordMapping;
        assert_eq!(
            kubernetes_mapping(None).unwrap(),
            RecordMapping::TransientRecord
        );
        for mapping in RecordMapping::ALL {
            assert_eq!(
                kubernetes_mapping(Some(mapping.resource_name())).unwrap(),
                mapping
            );
        }
        for resource in [
            "",
            "relays.oauthrelay.dev",
            "transientrecords",
            "authcodes",
            "refreshtokens.dex.coreos.com",
            "AuthCodes.dex.coreos.com",
        ] {
            let error = kubernetes_mapping(Some(resource)).unwrap_err().to_string();
            assert!(
                error.contains("transientrecords.oauthrelay.dev, authcodes.dex.coreos.com"),
                "{error}"
            );
        }
    }

    #[cfg(feature = "kubernetes")]
    #[test]
    fn the_dex_mapping_requires_an_explicit_namespace() {
        use oauthrelay_store_kubernetes::RecordMapping;
        let dex = RecordMapping::DexAuthCode;
        for (provider, default) in [(None, "oauthrelay"), (Some("relay-state"), "oauthrelay")] {
            let error = kubernetes_store_namespace(dex, None, provider, default)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("OAUTHRELAY_STORE_KUBERNETES_NAMESPACE") && error.contains("Dex"),
                "{error}"
            );
        }
        // An explicit namespace wins over the provider's and the default.
        assert_eq!(
            kubernetes_store_namespace(dex, Some("dex"), Some("relay-state"), "oauthrelay")
                .unwrap(),
            "dex"
        );
        assert!(kubernetes_store_namespace(dex, Some("Not A Namespace"), None, "x").is_err());
        // The default mapping keeps falling back to the provider, then the pod namespace.
        let record = RecordMapping::TransientRecord;
        assert_eq!(
            kubernetes_store_namespace(record, None, Some("relay-state"), "oauthrelay").unwrap(),
            "relay-state"
        );
        assert_eq!(
            kubernetes_store_namespace(record, None, None, "oauthrelay").unwrap(),
            "oauthrelay"
        );
        assert_eq!(
            kubernetes_store_namespace(record, Some("explicit"), Some("relay-state"), "x").unwrap(),
            "explicit"
        );
    }

    #[test]
    fn the_kubernetes_store_is_rejected_on_lambda() {
        let kubernetes = parse_store_config(store_env(Some("kubernetes"))).unwrap();
        let error = reject_kubernetes_on_lambda(&kubernetes, true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not supported on AWS Lambda"), "{error}");
        assert!(error.contains("OAUTHRELAY_STORE=dynamodb"), "{error}");
        // An explicit sweep setting does not make it acceptable.
        let swept = parse_store_config(StoreEnv {
            kubernetes_sweep: Some("30s"),
            ..store_env(Some("kubernetes"))
        })
        .unwrap();
        assert!(reject_kubernetes_on_lambda(&swept, true).is_err());
        assert!(reject_kubernetes_on_lambda(&kubernetes, false).is_ok());
        for kind in [None, Some("memory")] {
            let config = parse_store_config(store_env(kind)).unwrap();
            assert!(reject_kubernetes_on_lambda(&config, true).is_ok());
        }
        let dynamodb = parse_store_config(StoreEnv {
            dynamodb_table: Some("oauthrelay-store"),
            ..store_env(Some("dynamodb"))
        })
        .unwrap();
        assert!(reject_kubernetes_on_lambda(&dynamodb, true).is_ok());
    }

    #[test]
    fn kubernetes_store_settings_require_the_kubernetes_store() {
        for kind in [None, Some("memory"), Some("dynamodb")] {
            let table = (kind == Some("dynamodb")).then_some("oauthrelay-store");
            for (variable, env) in [
                (
                    "OAUTHRELAY_STORE_KUBERNETES_RESOURCE",
                    StoreEnv {
                        kubernetes_resource: Some("transientrecords.oauthrelay.dev"),
                        dynamodb_table: table,
                        ..store_env(kind)
                    },
                ),
                (
                    "OAUTHRELAY_STORE_KUBERNETES_NAMESPACE",
                    StoreEnv {
                        kubernetes_namespace: Some("relay-state"),
                        dynamodb_table: table,
                        ..store_env(kind)
                    },
                ),
                (
                    "OAUTHRELAY_STORE_KUBERNETES_SWEEP",
                    StoreEnv {
                        kubernetes_sweep: Some("off"),
                        dynamodb_table: table,
                        ..store_env(kind)
                    },
                ),
            ] {
                let error = parse_store_config(env).unwrap_err().to_string();
                assert!(error.contains(variable), "{kind:?}: {error}");
                assert!(error.contains("OAUTHRELAY_STORE=kubernetes"), "{error}");
            }
        }
    }

    #[test]
    fn booleans_accept_only_rust_boolean_literals() {
        assert!(parse_bool("TEST", "true").unwrap());
        assert!(!parse_bool("TEST", "false").unwrap());
        assert!(parse_bool("TEST", "yes").is_err());
    }

    #[cfg(feature = "lambda")]
    #[tokio::test]
    async fn lambda_refreshes_stale_configuration_and_keeps_last_good_snapshot() {
        let registry = Arc::new(Registry::default());
        let provider = Arc::new(ReloadingProvider {
            loads: AtomicUsize::new(0),
        });
        let mut providers = start_providers(vec![provider]);
        await_initial_snapshots(&mut providers).await.unwrap();
        replace_registry(&registry, &providers);
        let refresher =
            LambdaConfigRefresher::new(registry.clone(), providers, DEFAULT_LAMBDA_CONFIG_TTL);
        refresher.refresh_if_stale().await;
        assert!(registry
            .snapshot()
            .relays
            .contains_key(&ResourceKey::new("initial").unwrap()));

        refresher.state.lock().await.last_attempt = SystemTime::now() - DEFAULT_LAMBDA_CONFIG_TTL;
        refresher.refresh_if_stale().await;
        assert!(registry
            .snapshot()
            .relays
            .contains_key(&ResourceKey::new("refreshed").unwrap()));

        refresher.state.lock().await.last_attempt = SystemTime::now() - DEFAULT_LAMBDA_CONFIG_TTL;
        refresher.refresh_if_stale().await;
        assert!(registry
            .snapshot()
            .relays
            .contains_key(&ResourceKey::new("refreshed").unwrap()));
        assert_eq!(DEFAULT_LAMBDA_CONFIG_TTL, Duration::from_secs(60));
    }
}
