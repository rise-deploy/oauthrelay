---
title: Getting started
description: Run oauthrelay with a File provider and connect the first transparent relay.
sidebar:
  order: 1
---

This guide runs oauthrelay as a native server with one upstream and one public relay. The resulting
relay keeps token trust with the upstream provider while giving that provider one stable oauthrelay
callback.

## Prerequisites

- [mise](https://mise.jdx.dev/) for the repository toolchain
- An OAuth/OIDC provider client ID and secret
- An application that supports separate issuer, JWKS, authorization, and token endpoints

Install the pinned tools and build oauthrelay:

```console
mise install
cargo build -p oauthrelay
```

## Create the configuration

Save this as `config.yaml`. Replace the issuer, endpoints, and client credentials with values from
the provider. The example makes every upstream endpoint explicit so the routing boundary is
visible.

```yaml oauthrelay-config
apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: example
spec:
  issuerUrl: https://issuer.example.com
  endpoints:
    authorization: https://issuer.example.com/oauth2/authorize
    token: https://issuer.example.com/oauth2/token
    jwks: https://issuer.example.com/.well-known/jwks.json
  oauthClient:
    clientId: example-client-id
    clientSecret:
      valueFrom:
        env:
          name: EXAMPLE_CLIENT_SECRET
---
apiVersion: oauthrelay.dev/v1alpha1
kind: Relay
metadata:
  name: example
spec:
  upstreamRef:
    name: example
  scopes:
    default: [openid, email, profile]
    allowed: [openid, email, profile]
  clientAuthentication:
    type: Public
  redirectPolicy:
    - uri: https://app.example.com/oauth/callback
```

If the issuer publishes standard OIDC discovery metadata, omit the complete `spec.endpoints`
block. oauthrelay then resolves the authorization, token, and JWKS endpoints from
`{issuerUrl}/.well-known/openid-configuration`.

`Public` relays require the application to use S256 PKCE. Server-side relying parties can instead
use `UpstreamClient`, a relay-specific `ClientSecret`, or `PrivateKeyJwt`; see
[Client authentication](/oauthrelay/configuration/#client-authentication).
Every authorization request must send the exact configured `redirect_uri`.

## Start oauthrelay

Generate a 32-byte sealing key and start the server:

```console
export EXAMPLE_CLIENT_SECRET='provider-client-secret'
export OAUTHRELAY_PUBLIC_URL='https://login.example.com/oidc'
export OAUTHRELAY_SEAL_KEY="base64:$(openssl rand -base64 32)"
export OAUTHRELAY_PROVIDER_FILE="$PWD/config.yaml"
cargo run -p oauthrelay
```

The native server listens on `0.0.0.0:8080` by default. `/healthz` reports process liveness and
`/readyz` becomes healthy after every configured provider has supplied its first valid snapshot.

## Register and consume the endpoints

Register this callback with the external provider:

```text
https://login.example.com/oidc/upstream/example/callback
```

Configure the relying party with the upstream issuer, JWKS, and UserInfo endpoints. Route only its
authorization and token requests through the relay:

```text
https://login.example.com/oidc/relay/example/authorize
https://login.example.com/oidc/relay/example/token
```

This separation is the defining constraint of the [relay trust model](/oauthrelay/relay-model/).
The relying party must support independently configured authorization and token endpoints while
continuing to trust the upstream issuer.

## Choose the production provider

- Use the [File provider](/oauthrelay/reference/file-provider/) for a mounted configuration file,
  container secrets, or environment-backed secrets.
- Use the [AWS SSM provider](/oauthrelay/reference/ssm-provider/) for Lambda and AWS deployments that
  need independently managed resource documents and secrets.

Continue with [Runtime and deployment](/oauthrelay/reference/runtime/) for container and Lambda
behavior, or follow the [Cognito relay to Google guide](/oauthrelay/guides/cognito-google-relay/) for
a concrete multi-pool topology.
