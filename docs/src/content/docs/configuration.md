---
title: Configuration
description: Reference for oauthrelay Upstream and Relay resources, policies, and secret values.
---

oauthrelay configuration is a stream of strict, versioned resources. Each resource has an API
version, kind, name, and kind-specific specification. Unknown fields, unsupported API versions,
duplicate identities, and invalid references reject the complete candidate snapshot.

```yaml oauthrelay-config
apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://accounts.google.com
  endpoints:
    authorization: https://accounts.google.com/o/oauth2/v2/auth
    token: https://oauth2.googleapis.com/token
    jwks: https://www.googleapis.com/oauth2/v3/certs
  oauthClient:
    clientId: 123456789.apps.googleusercontent.com
    clientSecret:
      valueFrom:
        env:
          name: GOOGLE_CLIENT_SECRET
---
apiVersion: oauthrelay.dev/v1alpha1
kind: Relay
metadata:
  name: cognito-google
spec:
  upstreamRef:
    name: google
  scopes:
    default: [openid, email, profile]
    allowed: [openid, email, profile]
  requiredIdTokenClaims:
    hd: example.com
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    - uri: https://pool-a.auth.eu-west-1.amazoncognito.com/oauth2/idpresponse
    - uri: https://pool-b.auth.us-east-1.amazoncognito.com/oauth2/idpresponse
```

`Upstream` owns the external issuer, provider endpoints, OAuth client registration, credentials,
and stable provider callback. `Relay` owns transparent-relay scopes, downstream authentication,
and redirect policy. Several relays can reference one upstream and use the same callback.

## Common fields

| Field | Required | Meaning |
| --- | --- | --- |
| `apiVersion` | yes | Exactly `oauthrelay.dev/v1alpha1`. |
| `kind` | yes | `Upstream` or `Relay`. |
| `metadata.name` | yes | URL-safe resource name containing ASCII letters, numbers, `.`, `_`, or `-`. File and SSM resource names occupy one path segment. |

An upstream and a relay may use the same name because identities include the resource kind.

## Upstream

| Field | Required | Meaning |
| --- | --- | --- |
| `spec.issuerUrl` | yes | Absolute HTTP(S) issuer URL used for discovery and preserved as the transparent trust authority. |
| `spec.endpoints.authorization` | no | Explicit upstream authorization endpoint. Discovery supplies it when omitted. |
| `spec.endpoints.token` | no | Explicit upstream token endpoint. Discovery supplies it when omitted. |
| `spec.endpoints.jwks` | no | Explicit upstream JWKS endpoint. Discovery supplies it when omitted. |
| `spec.oauthClient.clientId` | yes | Provider OAuth client ID. |
| `spec.oauthClient.clientSecret` | yes | Provider OAuth client secret as a [secret value](#secret-values). |

`OAUTHRELAY_PUBLIC_URL` is the complete externally visible OAuth API base. The callback registered
with the provider is derived from that base and the upstream name:

```text
https://login.example.com/oidc/upstream/google/callback
```

Here `OAUTHRELAY_PUBLIC_URL` is `https://login.example.com/oidc`. Set it to another path, such as
`https://login.example.com/services/oauthrelay`, to serve the same API under that path instead.

Explicit endpoints are useful for providers without standard discovery. Each omitted endpoint is
resolved from `{issuerUrl}/.well-known/openid-configuration`. The issuer and JWKS remain
upstream-owned by the relay contract.

## Relay

| Field | Required | Default | Meaning |
| --- | --- | --- | --- |
| `spec.upstreamRef.name` | yes | — | Existing upstream used for authorization and token exchange. |
| `spec.scopes.default` | no | `[]` | Scopes used when the authorization request omits `scope`. |
| `spec.scopes.allowed` | no | unrestricted | Complete allow-list for configured and requested scopes. Every default scope must be allowed. |
| `spec.requiredIdTokenClaims` | no | `{}` | Exact string values required in the verified upstream ID token. |
| `spec.clientAuthentication` | yes | — | Authentication policy for requests to the relay token endpoint. |
| `spec.redirectPolicy` | yes | — | Non-empty list of explicit application redirect matchers. |

Relay endpoints are derived from the relay name:

```text
https://login.example.com/oidc/relay/cognito-google/authorize
https://login.example.com/oidc/relay/cognito-google/token
```

Every authorization request supplies `redirect_uri`. Policy entries are ORed and each entry
contains exactly one matcher:

```yaml
redirectPolicy:
  - uri: https://app.example.com/oauth/callback?channel=stable
  - origin: https://preview.example.com
  - loopback: http://127.0.0.1/oauth/callback
```

`uri` compares the complete decoded value exactly, including path, query order, encoding, port,
and trailing slash. It requires HTTPS, except for an exact HTTP URI on `127.0.0.1` or `::1`.
Static query parameters participate in matching; oauthrelay appends generated authorization results
and application state only after the URI passes policy.

`origin` requires HTTPS and matches scheme, host, and effective port. Every path and query at that
origin is accepted, which suits preview environments whose callback paths vary.

`loopback` requires HTTP on `127.0.0.1` or `::1` without a configured port. Its path and query
match exactly while the application may select any runtime port. Use `uri` when a loopback port is
fixed. `localhost` is not a loopback IP literal; the off-by-default
`OAUTHRELAY_ALLOW_LOCALHOST_LOOPBACK` service option treats it as an alias for a matching IP-literal
loopback entry.

User information, fragments, wildcards, prefix matching, empty policies, duplicate entries,
backslashes, and entries containing more than one matcher are rejected.

The token endpoint derives CORS permission without broadening redirects. A `uri` entry permits its
origin, an `origin` entry permits that origin, and a `loopback` entry permits its IP host on any
port. The authorization-code token request must still repeat the exact redirect URI stored for the
flow.

`requiredIdTokenClaims` applies to successful authorization-code exchanges. oauthrelay verifies
the upstream ID-token signature, issuer, audience, lifetime, subject, issued-at time, nonce when
requested, authorized party, and access-token hash when present. Every configured claim must exist
as a string with the exact configured value. The policy reads only signed ID-token claims; it does
not read UserInfo. A failed policy returns `invalid_grant` without returning upstream tokens. Relay
codes remain single-use after a failed check. Refresh grants do not evaluate this policy because an
upstream refresh response does not always contain an ID token.

## Client authentication

`spec.clientAuthentication` selects how a relying party authenticates to the relay token endpoint.

### UpstreamClient

The relying party presents the referenced upstream's client ID and secret. This is useful when a
manually configured relying party, such as Cognito, already stores those credentials.

```yaml
clientAuthentication:
  type: UpstreamClient
```

### Public

Client authentication credentials are not accepted. `client_id`, when present, is a public
identifier rather than a credential. Every authorization-code flow must use S256 PKCE.

```yaml
clientAuthentication:
  type: Public
```

### ClientSecret

The relay has a distinct downstream client ID and secret. The secret supports the same provider-
specific sources as the upstream client secret.

```yaml
clientAuthentication:
  type: ClientSecret
  clientId: relying-party
  clientSecret:
    valueFrom:
      env:
        name: RELAY_CLIENT_SECRET
```

### PrivateKeyJwt

The relying party sends an RFC 7523 client assertion. Configure exactly one of `jwksUrl` (an
absolute HTTP(S) URL) or `jwks` (an inline public JWKS object with a non-empty `keys` array). The assertion issuer and subject must equal `clientId`,
and its audience must equal the relay token endpoint.

```yaml
clientAuthentication:
  type: PrivateKeyJwt
  clientId: relying-party
  jwks:
    keys:
      - kty: RSA
        kid: relying-party-2026-01
        use: sig
        alg: RS256
        n: base64url-modulus
        e: AQAB
```

For remote keys, use:

```yaml
clientAuthentication:
  type: PrivateKeyJwt
  clientId: relying-party
  jwksUrl: https://app.example.com/.well-known/jwks.json
```

Inline keys use typed RSA (`n`, `e`), EC (`crv`, `x`, `y`, with P-256 or P-384), or OKP
(`crv: Ed25519`, `x`) public key material and standard optional JWK metadata.

## Secret values

A secret-bearing field contains exactly one inline value or one reference:

```yaml
clientSecret:
  value: local-development-secret
```

```yaml
clientSecret:
  valueFrom:
    env:
      name: GOOGLE_CLIENT_SECRET
```

```yaml
clientSecret:
  valueFrom:
    file:
      path: ./secrets/google-client-secret
```

```yaml
clientSecret:
  valueFrom:
    awsSsmParameter:
      name: /oauthrelay/secrets/google-client-secret
```

```yaml
clientSecret:
  valueFrom:
    awsSecretsManager:
      secretId: oauthrelay/google
      jsonKey: clientSecret
```

Resource discovery and secret resolution are separate concerns:

| Provider | Accepted secret forms |
| --- | --- |
| [File](/oauthrelay/reference/file-provider/) | `value`, `valueFrom.env`, `valueFrom.file`, `valueFrom.awsSsmParameter`, `valueFrom.awsSecretsManager` |
| [AWS SSM](/oauthrelay/reference/ssm-provider/) | `value`, `valueFrom.env`, `valueFrom.file`, `valueFrom.awsSsmParameter`, `valueFrom.awsSecretsManager` |
| [Kubernetes](/oauthrelay/reference/kubernetes-provider/) | All sources above and `valueFrom.secretKeyRef: { name, key }` |

All providers use the same resolver implementation. Relative `file.path` values resolve from a
File provider resource document's directory. SSM and Kubernetes resource documents have no filesystem base, so
their `file.path` values must be absolute. AWS-prefixed sources require AWS resolution in the
embedding; the standalone binary includes it through the default `aws` feature.

Identical references are resolved once while compiling a candidate snapshot. Resolved values have
a redacted debug representation and are not included in configuration errors.

## JSON Schema

Generate the schema directly from the Rust configuration types:

```console
oauthrelay schema > oauthrelay.schema.json
```

The schema describes one resource document; a File provider configuration is a YAML stream of
those documents. The published [oauthrelay JSON Schema](/oauthrelay/oauthrelay.schema.json) includes
field descriptions, strict unions, and the exact API version. CI checks that it remains synchronized
with the Rust types.


## Kubernetes namespaces

Resources accept optional `metadata.namespace`. File and SSM ignore it. The Kubernetes provider
consumes one configured namespace and resolves upstream and Secret references within it. See the
[Kubernetes provider reference](/oauthrelay/reference/kubernetes-provider/) for installation,
CRD generation, watches, and RBAC.
