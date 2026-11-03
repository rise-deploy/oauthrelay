#![cfg(feature = "kubernetes")]

use base64::{engine::general_purpose::STANDARD, Engine};
use std::{io::Write, time::Duration};
use tokio::{net::TcpListener, process::Command};

#[tokio::test]
async fn kubernetes_store_startup_reaches_the_api_without_a_crypto_provider_panic() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((connection, _)) = listener.accept().await {
            drop(connection);
        }
    });
    let mut kubeconfig = tempfile::NamedTempFile::new().unwrap();
    write!(
        kubeconfig,
        r#"apiVersion: v1
kind: Config
clusters:
  - name: test
    cluster:
      server: https://{address}
users:
  - name: test
    user:
      token: test-only
contexts:
  - name: test
    context:
      cluster: test
      user: test
current-context: test
"#
    )
    .unwrap();
    let resources = tempfile::NamedTempFile::new().unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new(env!("CARGO_BIN_EXE_oauthrelay"))
            .kill_on_drop(true)
            .env_clear()
            .env("KUBECONFIG", kubeconfig.path())
            .env("OAUTHRELAY_PUBLIC_URL", "https://relay.example.com")
            .env("OAUTHRELAY_SEAL_KEY", STANDARD.encode([0; 32]))
            .env("OAUTHRELAY_PROVIDER_FILE", resources.path())
            .env("OAUTHRELAY_STORE", "kubernetes")
            .env("OAUTHRELAY_STORE_KUBERNETES_NAMESPACE", "test")
            .env("OAUTHRELAY_STORE_KUBERNETES_SWEEP", "off")
            .output(),
    )
    .await;
    server.abort();
    let output = output.expect("startup must have a deadline").unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(
        stderr.contains("cannot list transientrecords.oauthrelay.dev"),
        "startup must report the unavailable API: {stderr}"
    );
}
