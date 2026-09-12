---
title: Kubernetes provider
description: Namespaced custom resources and live configuration updates.
---

The Kubernetes provider reads `Upstream` and `Relay` custom resources from exactly one namespace.
Enable it with `OAUTHRELAY_PROVIDER_KUBERNETES=true`. The default binary and container image include
the `kubernetes` feature; minimal builds must enable that feature explicitly.

## Namespace and credentials

In a pod, oauthrelay uses its service account credentials and namespace. Outside the cluster it
uses the active kubeconfig context, including its namespace (or `default` when omitted).
`OAUTHRELAY_PROVIDER_KUBERNETES_NAMESPACE` selects a different single namespace. Empty values,
namespace lists, and wildcards are invalid. The service account needs permission in the selected
namespace.

An `upstreamRef.name` always refers to an upstream in that namespace. A `secretKeyRef` always reads
a Secret in that namespace. Neither reference accepts a namespace field. Resource names remain
single-segment URL keys: namespaces do not appear in authorization, token, or callback URLs.

File and SSM resource documents accept optional `metadata.namespace` and ignore it. Their resource
identities remain `(kind, name)`, including when oauthrelay runs in a pod.

## Install the CRDs

Generate the definitions from the same binary build that will serve the resources:

```sh
oauthrelay crds > oauthrelay.crds.yaml
kubectl apply --server-side -f oauthrelay.crds.yaml
kubectl wait --for=condition=Established --timeout=60s \
  crd/upstreams.oauthrelay.dev crd/relays.oauthrelay.dev
```

The command requires no credentials or runtime environment variables. The
[generated CRD bundle](https://github.com/rise-deploy/oauthrelay/blob/develop/deploy/oauthrelay.crds.yaml)
is committed under `deploy/`. From a repository checkout, install it with
`kubectl apply --server-side -f deploy/oauthrelay.crds.yaml`. Regenerate it with `mise run crds`;
`mise run crds:check` checks that it matches the Rust definitions.
The definitions and their structural schemas come from Rust types and `schemars`. CI checks
regeneration for drift and validates them against a Kubernetes 1.35 API server.

CRD installation requires cluster-level privileges. The running provider is read-only and does
not install definitions, write resource status, or manage finalizers.

## Configure resources

```yaml oauthrelay-config
apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: issuer
  namespace: oauthrelay
spec:
  issuerUrl: https://issuer.example.com
  oauthClient:
    clientId: registered-client
    clientSecret:
      valueFrom:
        secretKeyRef:
          name: provider-credentials
          key: client-secret
---
apiVersion: oauthrelay.dev/v1alpha1
kind: Relay
metadata:
  name: app
  namespace: oauthrelay
spec:
  upstreamRef:
    name: issuer
  clientAuthentication:
    type: Public
  redirectPolicy:
    - uri: https://app.example.com/callback
```

Create `provider-credentials` in the same namespace with a `client-secret` data key. Secret values
must be non-empty UTF-8; oauthrelay preserves their bytes, including trailing newlines.

All [secret sources](/oauthrelay/configuration/#secret-values) are supported: inline values,
environment variables, absolute local files, AWS references when the `aws` feature is enabled,
and Kubernetes `secretKeyRef`. Kubernetes resources have no base directory for relative files.
AWS clients are initialized only when an AWS source is resolved. Anyone able to configure CRs
can select these sources using the running process's credentials and filesystem access.

## Workload authentication

A workload can use a projected Kubernetes service-account token to authenticate at a relay
without a static client secret. Configure `PrivateKeyJwt` with the cluster issuer and the exact
service-account subject, and project a token whose audience is the relay token URL. See
[Kubernetes service-account authentication](/oauthrelay/configuration/#kubernetes-service-account-authentication)
for issuer accessibility requirements and a complete token projection example.

## Updates and errors

The provider watches both resource kinds and Secret metadata. It fetches values only for
referenced Secrets, deduplicating identical references within each snapshot. Relevant events
trigger compilation of a complete resource graph. Initial lists and relists are staged until
complete, and watches reconnect with backoff.

`OAUTHRELAY_PROVIDER_KUBERNETES_REFRESH` defaults to `60s`. Each refresh resolves secret sources
again and retries failed compilation. This picks up local file and AWS secret changes without a
Kubernetes event. Environment values come from the running process environment.

Startup requires complete initial synchronization and valid configuration within 60 seconds.
An empty namespace is valid. After startup, invalid resources, missing Secret keys, dangling
upstream references, and API failures retain the complete last valid snapshot. For example,
deleting an upstream while a relay references it keeps that snapshot active; deleting the relay
as well permits the removal to take effect. Readiness follows the runtime's first-snapshot rule.

File, SSM, and Kubernetes providers can be enabled together, in that precedence order. Each
provider must supply a valid graph itself. On duplicate `(kind, name)` identities, the earlier
provider wins. Lambda uses complete reads at invocation refresh boundaries.

## Deployment and RBAC

The repository's [deployment example](https://github.com/rise-deploy/oauthrelay/blob/develop/deploy/kubernetes.yaml)
contains a Namespace, ServiceAccount, Role, RoleBinding, Deployment, and Service. Set the image to
your published build's immutable tag and set the public URL before applying it. Create the
`oauthrelay-runtime` Secret with a `seal-key` containing a base64-encoded 32-byte key. Configure
your ingress to route the public URL to the Service's port 8080.

The Role grants `list` and `watch` on upstreams and relays, and `get`, `list`, and `watch` on
Secrets within the namespace. Kubernetes authorizes Secret metadata watches using the Secret
resource permissions; these permissions also allow reading Secret contents in that namespace.
A namespace override requires a RoleBinding in the target namespace referencing the pod's
ServiceAccount.
