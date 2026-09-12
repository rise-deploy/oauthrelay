//! Requires an isolated cluster with the generated CRDs installed.
use k8s_openapi::{
    api::{
        authentication::v1::{TokenRequest, TokenRequestSpec},
        core::v1::{Namespace, Secret, ServiceAccount},
    },
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams, PostParams},
    Api, Client, Config, CustomResourceExt,
};
use oauthrelay_core::{ConfigProvider, ProviderSnapshot};
use oauthrelay_provider_kubernetes::{KubernetesProvider, Relay, Upstream};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::watch;

async fn snapshot(
    rx: &mut watch::Receiver<ProviderSnapshot>,
    predicate: impl Fn(&ProviderSnapshot) -> bool,
) -> ProviderSnapshot {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            rx.changed().await.unwrap();
            let snapshot = rx.borrow_and_update().clone();
            if predicate(&snapshot) {
                return snapshot;
            }
        }
    })
    .await
    .expect("provider snapshot converges")
}
fn relay_spec(auth: Value) -> Value {
    json!({"upstreamRef":{"name":"issuer"},"clientAuthentication":auth,"redirectPolicy":[{"uri":"https://app.example/cb"}]})
}
fn relay(name: &str, auth: Value) -> Value {
    json!({"apiVersion":"oauthrelay.dev/v1alpha1","kind":"Relay","metadata":{"name":name,"namespace":"oauthrelay"},"spec":relay_spec(auth)})
}

#[tokio::test]
#[ignore = "requires the disposable Kind cluster created by mise run kubernetes:test"]
async fn api_validation_namespace_isolation_and_watch_updates() {
    let path = std::env::var("OAUTHRELAY_KUBERNETES_TEST_KUBECONFIG")
        .expect("explicit disposable test kubeconfig required");
    let kubeconfig = kube::config::Kubeconfig::read_from(path).unwrap();
    let admin_config = Config::from_custom_kubeconfig(kubeconfig, &Default::default())
        .await
        .unwrap();
    let admin = Client::try_from(admin_config.clone()).unwrap();
    // Exercise the exact read-only RBAC shipped with the deployment example.
    for document in
        serde_yaml::Deserializer::from_str(include_str!("../../../deploy/kubernetes.yaml"))
    {
        let value = Value::deserialize(document).unwrap();
        let kind = value["kind"].as_str().unwrap();
        if matches!(kind, "Deployment" | "Service") {
            continue;
        }
        let group = if kind.starts_with("Role") {
            "rbac.authorization.k8s.io"
        } else {
            ""
        };
        let gvk = kube::core::GroupVersionKind::gvk(group, "v1", kind);
        let resource = kube::core::ApiResource::from_gvk(&gvk);
        let api: Api<kube::core::DynamicObject> = if kind == "Namespace" {
            Api::all_with(admin.clone(), &resource)
        } else {
            Api::namespaced_with(admin.clone(), "oauthrelay", &resource)
        };
        api.patch(
            "oauthrelay",
            &PatchParams::apply("oauthrelay-tests"),
            &Patch::Apply(value),
        )
        .await
        .unwrap();
    }
    let namespaces: Api<Namespace> = Api::all(admin.clone());
    namespaces
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some("other".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let sas: Api<ServiceAccount> = Api::namespaced(admin.clone(), "oauthrelay");
    let token = sas
        .create_token_request(
            "oauthrelay",
            &PostParams::default(),
            &TokenRequest {
                spec: TokenRequestSpec {
                    audiences: vec![],
                    expiration_seconds: Some(600),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .status
        .unwrap()
        .token;
    let mut restricted_config = admin_config;
    restricted_config.auth_info = kube::config::AuthInfo {
        token: Some(token.into()),
        ..Default::default()
    };
    let restricted = Client::try_from(restricted_config).unwrap();
    let forbidden: Api<Upstream> = Api::namespaced(restricted.clone(), "other");
    assert!(
        matches!(forbidden.list(&ListParams::default()).await, Err(kube::Error::Api(status)) if status.code == 403)
    );

    let upstreams: Api<Upstream> = Api::namespaced(admin.clone(), "oauthrelay");
    let relays: Api<Relay> = Api::namespaced(admin.clone(), "oauthrelay");
    let secrets: Api<Secret> = Api::namespaced(admin.clone(), "oauthrelay");
    let up = json!({"apiVersion":"oauthrelay.dev/v1alpha1","kind":"Upstream","metadata":{"name":"issuer","namespace":"oauthrelay"},"spec":{"issuerUrl":"https://issuer.example","oauthClient":{"clientId":"client","clientSecret":{"valueFrom":{"secretKeyRef":{"name":"credentials","key":"password"}}}}}});
    upstreams
        .create(
            &PostParams::default(),
            &serde_json::from_value(up.clone()).unwrap(),
        )
        .await
        .unwrap();
    let mut other = up;
    other["metadata"]["namespace"] = json!("other");
    other["spec"]["oauthClient"]["clientId"] = json!("wrong-namespace");
    Api::<Upstream>::namespaced(admin.clone(), "other")
        .create(
            &PostParams::default(),
            &serde_json::from_value(other).unwrap(),
        )
        .await
        .unwrap();
    secrets
        .create(
            &PostParams::default(),
            &Secret {
                metadata: ObjectMeta {
                    name: Some("credentials".into()),
                    ..Default::default()
                },
                string_data: Some(BTreeMap::from([("password".into(), "initial".into())])),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    relays
        .create(
            &PostParams::default(),
            &serde_json::from_value(relay("app", json!({"type":"Public"}))).unwrap(),
        )
        .await
        .unwrap();

    let dry_run = PostParams {
        dry_run: true,
        ..Default::default()
    };
    let inline = json!({"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]});
    for auth in [
        json!({"type":"Public"}),
        json!({"type":"UpstreamClient"}),
        json!({"type":"ClientSecret","clientId":"app","clientSecret":{"value":"secret"}}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwksUrl":"https://app.example/jwks"}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":inline}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"},{"kty":"OKP","crv":"Ed25519","x":"x"}]}}),
    ] {
        let expected = relay("valid", auth);
        let result = relays
            .create(&dry_run, &serde_json::from_value(expected.clone()).unwrap())
            .await
            .unwrap();
        let actual = serde_json::to_value(result).unwrap();
        assert_eq!(
            actual["spec"]["clientAuthentication"], expected["spec"]["clientAuthentication"],
            "API must not prune configured key material"
        );
    }
    // Dynamic resources exercise API validation before typed deserialization rejects input.
    let dynamic_relays: Api<kube::core::DynamicObject> =
        Api::namespaced_with(admin.clone(), "oauthrelay", &Relay::api_resource());
    for auth in [
        json!({"type":"Unknown"}),
        json!({"type":"ClientSecret","clientId":"app"}),
        json!({"type":"Public","clientId":"unexpected"}),
        json!({"type":"PrivateKeyJwt","clientId":"app"}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":null}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwksUrl":null}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":"https://app.example/jwks"}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwksUrl":"https://app.example/jwks","jwks":inline}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":{"keys":[]}}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":{"keys":[{"kty":"RSA","n":"a"}]}}),
        json!({"type":"PrivateKeyJwt","clientId":"app","jwks":{"keys":[{"kty":"EC","crv":"Ed25519","x":"a","y":"b"}]}}),
        json!({"type":"ClientSecret","clientId":"app","clientSecret":{"value":"a","valueFrom":{"env":{"name":"SECRET"}}}}),
        json!({"type":"ClientSecret","clientId":"app","clientSecret":{"valueFrom":{"env":{"name":"SECRET"},"secretKeyRef":{"name":"credentials","key":"password"}}}}),
    ] {
        let result = dynamic_relays
            .create(
                &dry_run,
                &serde_json::from_value(relay("invalid", auth.clone())).unwrap(),
            )
            .await;
        assert!(
            matches!(&result, Err(kube::Error::Api(status)) if status.code == 422),
            "API must reject {auth}: {result:?}"
        );
    }

    let provider = Arc::new(
        KubernetesProvider::new(restricted, "oauthrelay", Duration::from_secs(60)).unwrap(),
    );
    let (tx, mut rx) = watch::channel(ProviderSnapshot::default());
    let task = tokio::spawn(provider.run(tx));
    let initial = snapshot(&mut rx, |s| s.relays.len() == 1).await;
    assert_eq!(
        initial.upstreams.values().next().unwrap().client_id,
        "client"
    );
    secrets
        .patch(
            "credentials",
            &PatchParams::default(),
            &Patch::Merge(json!({"stringData":{"password":"rotated\n"}})),
        )
        .await
        .unwrap();
    snapshot(&mut rx, |s| {
        s.upstreams
            .values()
            .next()
            .is_some_and(|u| u.client_secret.expose() == "rotated\n")
    })
    .await;
    relays
        .delete("app", &DeleteParams::default())
        .await
        .unwrap();
    snapshot(&mut rx, |s| s.relays.is_empty()).await;
    upstreams
        .delete("issuer", &DeleteParams::default())
        .await
        .unwrap();
    snapshot(&mut rx, |s| s.upstreams.is_empty()).await;
    drop(rx);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
