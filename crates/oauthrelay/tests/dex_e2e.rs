use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use reqwest::{redirect::Policy, StatusCode};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use url::Url;

const DEX_ISSUER: &str = "http://127.0.0.1:15556/dex";
const RELAY_BASE: &str = "http://127.0.0.1:18080";
const RELAY_PUBLIC_URL: &str = "http://127.0.0.1:18080/oidc";
const APP_CALLBACK: &str = "http://127.0.0.1:19090/callback";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_ready(client: &reqwest::Client, url: &str) {
    for _ in 0..120 {
        if client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {url}");
}

fn parameter(url: &Url, name: &str) -> String {
    url.query_pairs()
        .find(|(candidate, _)| candidate == name)
        .unwrap_or_else(|| panic!("missing {name} in {url}"))
        .1
        .into_owned()
}

async fn follow_authorization(client: &reqwest::Client, start: Url) -> Url {
    let mut current = start;
    for _ in 0..12 {
        let response = client.get(current.clone()).send().await.unwrap();
        assert!(
            response.status().is_redirection(),
            "expected redirect from {current}, got {}",
            response.status()
        );
        let next = current
            .join(
                response.headers()[reqwest::header::LOCATION]
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
        if next.host_str() == Some("127.0.0.1") && next.port() == Some(19090) {
            return next;
        }
        current = next;
    }
    panic!("authorization redirect chain did not reach the application");
}

#[tokio::test]
#[ignore = "requires Docker Compose; run with mise run e2e"]
async fn dex_authorization_code_and_refresh_flow() {
    let no_redirect = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap();
    wait_ready(
        &no_redirect,
        &format!("{DEX_ISSUER}/.well-known/openid-configuration"),
    )
    .await;

    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: dex
spec:
  issuerUrl: {DEX_ISSUER}
  oauthClient:
    clientId: oauthrelay-e2e
    clientSecret:
      value: oauthrelay-e2e-secret
---
apiVersion: oauthrelay.dev/v1alpha1
kind: Relay
metadata:
  name: dex
spec:
  upstreamRef:
    name: dex
  scopes:
    default: [openid, email, profile, offline_access]
    allowed: [openid, email, profile, offline_access]
  clientAuthentication:
    type: Public
  redirectPolicy:
    - uri: {APP_CALLBACK}
"#
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_oauthrelay"))
        .env("OAUTHRELAY_PUBLIC_URL", RELAY_PUBLIC_URL)
        .env("OAUTHRELAY_LISTEN", "127.0.0.1:18080")
        .env(
            "OAUTHRELAY_SEAL_KEY",
            "base64:ERERERERERERERERERERERERERERERERERERERERERE=",
        )
        .env("OAUTHRELAY_PROVIDER_FILE", &config_path)
        .env("OAUTHRELAY_PROVIDER_FILE_POLL", "10m")
        .env_remove("AWS_LAMBDA_RUNTIME_API")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _guard = ChildGuard(child);
    wait_ready(&no_redirect, &format!("{RELAY_BASE}/readyz")).await;

    let verifier = "dex-e2e-verifier-with-at-least-forty-three-characters";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let nonce = "dex-e2e-nonce";
    let mut authorize = Url::parse(&format!("{RELAY_PUBLIC_URL}/relay/dex/authorize")).unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", "oauthrelay-e2e")
        .append_pair("redirect_uri", APP_CALLBACK)
        .append_pair("state", "dex-e2e-state")
        .append_pair("scope", "openid email profile offline_access")
        .append_pair("nonce", nonce)
        .append_pair("connector_id", "mock")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let application = follow_authorization(&no_redirect, authorize).await;
    assert_eq!(parameter(&application, "state"), "dex-e2e-state");
    let code = parameter(&application, "code");

    let token = no_redirect
        .post(format!("{RELAY_PUBLIC_URL}/relay/dex/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", APP_CALLBACK),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    let token: Value = token.json().await.unwrap();
    let id_token = token["id_token"].as_str().unwrap();
    let discovery: Value = no_redirect
        .get(format!("{DEX_ISSUER}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let jwks: JwkSet = no_redirect
        .get(discovery["jwks_uri"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let header = decode_header(id_token).unwrap();
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.common.key_id.as_deref() == header.kid.as_deref())
        .unwrap();
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[DEX_ISSUER]);
    validation.set_audience(&["oauthrelay-e2e"]);
    let claims = decode::<Value>(id_token, &DecodingKey::from_jwk(jwk).unwrap(), &validation)
        .unwrap()
        .claims;
    assert_eq!(claims["nonce"], nonce);

    let refresh = no_redirect
        .post(format!("{RELAY_PUBLIC_URL}/relay/dex/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", token["refresh_token"].as_str().unwrap()),
            ("scope", "openid email profile offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::OK);
    assert!(refresh.json::<Value>().await.unwrap()["access_token"].is_string());

    let replay = no_redirect
        .post(format!("{RELAY_PUBLIC_URL}/relay/dex/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", APP_CALLBACK),
            ("code_verifier", verifier),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let invalid_redirect = no_redirect
        .get(format!(
            "{RELAY_PUBLIC_URL}/relay/dex/authorize?redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&code_challenge={challenge}&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_redirect.status(), StatusCode::BAD_REQUEST);
}
