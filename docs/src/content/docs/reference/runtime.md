---
title: Runtime and deployment
description: Configure oauthrelay native, container, and AWS Lambda execution.
---

The `oauthrelay` executable uses the same Axum router in native server and AWS Lambda modes. It loads
every configured provider before serving traffic.

The default build includes the `kubernetes` feature. Set `OAUTHRELAY_PROVIDER_KUBERNETES=true`
to consume namespaced custom resources; see the [Kubernetes provider](/oauthrelay/reference/kubernetes-provider/)
for namespace selection, refresh settings, CRD installation, and deployment examples.

## Environment variables

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `OAUTHRELAY_PUBLIC_URL` | yes | — | Complete externally visible OAuth API base used both to serve routes and construct endpoint URLs. |
| `OAUTHRELAY_SEAL_KEY` | yes | — | Raw base64 or `base64:`-prefixed 32-byte key for state and authorization-code envelopes. |
| `OAUTHRELAY_SEAL_KEY_PREVIOUS` | no | unset | Previous 32-byte key accepted while rotating envelopes. |
| `OAUTHRELAY_LISTEN` | native only | `0.0.0.0:8080` | Native server socket. |
| `OAUTHRELAY_PROVIDER_FILE` | one provider required | disabled | File provider YAML path. |
| `OAUTHRELAY_PROVIDER_FILE_POLL` | no | `30s` | File and referenced-secret reload interval. |
| `OAUTHRELAY_PROVIDER_SSM_PREFIX` | one provider required | disabled | Absolute SSM root ending in `/`. |
| `OAUTHRELAY_PROVIDER_SSM_POLL` | no | `60s` | Native SSM reload interval. |
| `OAUTHRELAY_PROVIDER_KUBERNETES` | one provider required | `false` | Enable namespaced Kubernetes CR discovery. |
| `OAUTHRELAY_PROVIDER_KUBERNETES_NAMESPACE` | no | pod or kubeconfig namespace | Single namespace consumed by the Kubernetes provider. |
| `OAUTHRELAY_PROVIDER_KUBERNETES_REFRESH` | no | `60s` | Secret refresh and failed-compilation retry interval. |
| `OAUTHRELAY_LAMBDA_CONFIG_TTL` | no | `60s` | Maximum Lambda snapshot age before invocation-driven refresh. |
| `OAUTHRELAY_STORE` | no | `memory` | Transient store backend for single-use state: `memory`, `dynamodb`, or `kubernetes` (not on Lambda). |
| `OAUTHRELAY_STORE_DYNAMODB_TABLE` | with `dynamodb` | — | DynamoDB table holding transient records; see [Transient store](/oauthrelay/reference/transient-store/). |
| `OAUTHRELAY_STORE_KUBERNETES_RESOURCE` | no | `transientrecords.oauthrelay.dev` | Resource holding the records of the `kubernetes` store: that one, or Dex's `authcodes.dex.coreos.com` (requires Dex 2.46.0 or later). |
| `OAUTHRELAY_STORE_KUBERNETES_NAMESPACE` | no | provider, pod, or kubeconfig namespace | Namespace holding the records of the `kubernetes` store. Required, and never inferred, with `authcodes.dex.coreos.com`: Dex's namespace. |
| `OAUTHRELAY_STORE_KUBERNETES_SWEEP` | no | `60s` | Interval at which the `kubernetes` store deletes expired records, or `off`. |
| `OAUTHRELAY_ALLOW_LOCALHOST_LOOPBACK` | no | `false` | Treat `localhost` as an alias for configured IP-literal loopback redirect matchers. |
| `OAUTHRELAY_LOG` | no | `info` | `tracing` filter. |

Durations require an explicit unit such as `30s`, `5m`, or `1h` and must be greater than zero.
The localhost compatibility value must be `true` or `false`.
Provider collision precedence is File, SSM, then Kubernetes.

## Build features

The standalone crate enables `aws`, `lambda`, and `kubernetes` by default. `aws` supplies SSM resource
discovery, AWS secret resolution for all providers, and the DynamoDB transient store. `kubernetes` supplies the
Kubernetes provider and the Kubernetes transient store. A native File-only build without AWS
SDK dependencies uses `--no-default-features`; in that build, File resources can use inline,
environment, and file secrets, while AWS secret references fail configuration validation.

## Native server

Native mode binds `OAUTHRELAY_LISTEN`, runs provider watches and periodic refreshes, and shuts down
on SIGTERM or SIGINT. It exposes:

- `GET /healthz` for process liveness.
- `GET /readyz` after every provider has supplied its initial snapshot.

Logs use human-readable output on a terminal and JSON when stdout is not a terminal.

## Container image

Multi-architecture images are published at `ghcr.io/rise-deploy/oauthrelay` for AMD64 and ARM64.
Every published build has an immutable `sha-<short-commit>` tag; builds from a version tag also
publish that version tag.

The image is a non-root, scratch-based executable listening on port 8080. Mount a File provider
configuration or supply AWS credentials for the SSM provider. Terminate TLS at the ingress, load
balancer, API Gateway, or Function URL, and set `OAUTHRELAY_PUBLIC_URL` to the complete public HTTPS
base for the OAuth API.

The path is customizable. `https://login.example.com/oidc` serves routes below `/oidc`, while
`https://login.example.com/services/oauthrelay` serves the same routes below `/services/oauthrelay`.
Forward the public path unchanged to oauthrelay. Health and readiness remain at `/healthz` and
`/readyz`, outside the OAuth API base.

## AWS Lambda

The executable enters Lambda mode when `AWS_LAMBDA_RUNTIME_API` is present. Provider initialization
is part of cold start, so the Lambda event loop begins only after every provider has supplied a
valid initial snapshot.

Lambda can freeze the process between requests, so background polling cannot bound configuration
age. Before each invocation, oauthrelay compares wall-clock time with the last refresh attempt. Once
the snapshot reaches `OAUTHRELAY_LAMBDA_CONFIG_TTL`, it synchronously reloads each provider. A
successful provider replaces its snapshot; a failure retains that provider's last-good snapshot.

Configure an API Gateway HTTP API or Lambda Function URL to forward every oauthrelay route. The
function role needs the permissions documented by the selected provider. The default binary
includes the Lambda Runtime API client.

The default memory transient store lives inside one execution environment, and Lambda runs several
at once under load, so an authorization code could be redeemed once in each. Set
`OAUTHRELAY_STORE=dynamodb` and `OAUTHRELAY_STORE_DYNAMODB_TABLE`, and grant the function role the
table permissions in [Transient store](/oauthrelay/reference/transient-store/), to make codes
single-use across all environments. oauthrelay logs a warning at startup when it runs on Lambda
with the memory store.

## Sealing-key rotation

The ten-minute flow envelope is carried by the upstream OAuth `state` parameter. The five-minute
authorization-code envelope is returned to the application and then presented to the oauthrelay
token endpoint. Both are encrypted and authenticated client-held values; oauthrelay does not store
their contents in memory. Each envelope contains an authenticated issuance timestamp. oauthrelay
compares that timestamp with wall-clock time when opening the envelope, allowing up to 30 seconds
of forward clock skew.

To rotate keys, set the new key as `OAUTHRELAY_SEAL_KEY` and the prior key as
`OAUTHRELAY_SEAL_KEY_PREVIOUS`. Keep the prior key available for at least ten minutes, then remove it
after envelopes created with it have expired.

The standalone runtime records only used authorization-code envelope IDs, in the
[transient store](/oauthrelay/reference/transient-store/). With the default memory store, codes are
single-use within one native process or one warm Lambda execution environment. Set
`OAUTHRELAY_STORE=dynamodb` or `kubernetes` for single use across replicas and restarts; use
`dynamodb` on Lambda.
