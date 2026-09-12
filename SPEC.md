# oauthrelay specification

## Mission

oauthrelay is a reusable OAuth/OIDC transparent relay in Rust. A named upstream owns one external
OAuth client registration and one stable callback. One or more named relays reference that
upstream and multiplex authorization results to an explicit set of relying-party redirects.

The protocol engine is an embeddable Axum router. The standalone binary supplies File and AWS SSM
configuration providers and runs as a native server or AWS Lambda container.

Transparent relay preserves the upstream token response, issuer, signature, JWKS, audience, and
UserInfo contract. A relying party sends authorization and token requests through oauthrelay while
continuing to trust the upstream issuer.

## Workspace

```text
crates/
  oauthrelay-core/          protocol engine, resources, resolver seams, router, sealing
  oauthrelay-secret-resolver/ shared inline, environment, file, and cloud secret dispatch
  oauthrelay-provider-file/ multi-document YAML provider and composable secret resolution
  oauthrelay-provider-ssm/  SSM resource discovery and AWS secret backend
  oauthrelay-provider-kubernetes/ Namespaced CR discovery and Kubernetes Secret backend
  oauthrelay/               provider wiring, native server, Lambda runtime, schema CLI
```

Provider crates depend on `oauthrelay-core`; the core has no provider-specific dependency.

## Resource model

Configuration uses `oauthrelay.dev/v1alpha1` resources. `ResourceKey` is a URL-safe opaque name.

```rust
pub struct Upstream {
    pub key: ResourceKey,
    pub issuer_url: Url,
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub client_id: String,
    pub client_secret: SecretString,
}

pub struct Relay {
    pub key: ResourceKey,
    pub upstream: ResourceKey,
    pub client_auth: ClientAuth,
    pub scopes: Vec<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub redirect_policy: Vec<RedirectMatcher>,
}
```

`Upstream` owns the external authorization-server connection, OAuth client credentials, and
provider callback. `Relay` owns transparent-relay scope policy, downstream authentication, and
redirect policy.

`ClientAuth` supports:

- `UpstreamClient`: the downstream request presents the referenced upstream's client ID and
  secret.
- `Public`: no client credential; S256 PKCE is mandatory.
- `ClientSecret`: a relay-specific client ID and secret are compared in constant time.
- `PrivateKeyJwt`: an RFC 7523 assertion is verified against inline JWKS or a JWKS URL.

`ResourceResolver` resolves relays and upstreams independently for every request. `Registry`
implements the resolver with an atomically swapped `ProviderSnapshot` containing both maps.
Provider collisions are keyed by `(kind, name)`; the earlier-configured provider remains active.

Every provider snapshot is a complete valid resource graph. A relay reference to an absent
upstream rejects the candidate snapshot.

## HTTP routes

For public base URL `B`, relay key `R`, and upstream key `U`:

| Route | Behavior |
| --- | --- |
| `GET {B}/relay/{R}/authorize` | Validates redirect and downstream PKCE, applies relay scope policy, creates independent upstream state and PKCE, and redirects to the referenced upstream. |
| `GET {B}/upstream/{U}/callback` | Unseals upstream-bound state, resolves the originating relay, exchanges the upstream code, and returns to the relay's validated application redirect. |
| `POST {B}/relay/{R}/token` | Authenticates the downstream client, validates the sealed code, redirect and PKCE, then returns the stored upstream response unchanged. |
| `POST {B}/relay/{R}/token` with `refresh_token` | Authenticates the downstream client and relays the refresh grant using the upstream client credentials. |
| `GET {B}/relay/{R}/.well-known/openid-configuration` | Preserves upstream issuer/JWKS metadata and rewrites authorization and token endpoints to the relay. |
| `GET {B}/relay/{R}/jwks` | Proxies the referenced upstream JWKS. |
| `GET /healthz` | Standalone runtime liveness. |
| `GET /readyz` | Ready after every configured provider supplies its first snapshot. |

Several relays referencing one upstream use the same provider callback. The flow-state envelope is
sealed with the upstream key as associated data and carries the originating relay key. The
authorization-code envelope is sealed with the relay key.

Unknown relay or upstream keys return 404. The token endpoint uses RFC 6749 error bodies. An
unvalidated redirect URI is never reflected into a response.

## Protocol invariants

- Authorization code flow only; query response mode only.
- S256 PKCE only.
- Flow-state TTL is 10 minutes.
- Authorization-code TTL is 5 minutes.
- Redirect policy uses explicit exact-URI, HTTPS-origin, or variable-port IP-loopback matchers.
- `localhost` aliases an IP-loopback matcher only when service compatibility is enabled.
- Client-secret comparisons are constant-time.
- Upstream-owned authorization parameters are replaced rather than forwarded.
- Other authorization and grant extensions are preserved.
- OIDC request objects are rejected because their routing fields conflict with proxy ownership.
- Upstream token response status, content type, and bytes are preserved.
- Discovery and JWKS responses are cached for bounded TTLs.

The standalone binary supplies an in-memory replay cache. An embedding without a replay cache
accepts a sealed authorization code for its five-minute cryptographic lifetime.

## Configuration resources

The File provider reads a YAML document stream:

```yaml
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
    clientId: 1234.apps.googleusercontent.com
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
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    - uri: https://app.example.com/oauth/callback
```

Unknown fields, kinds, API versions, duplicate identities, invalid URLs, invalid origins, invalid
scope tokens, and dangling references reject the candidate snapshot.

`oauthrelay schema` prints a JSON Schema generated from the Rust configuration types.

`oauthrelay crds` prints the namespaced Upstream and Relay CRDs generated from shared Rust
configuration types with structural schema validation. The generated bundle is committed at
`deploy/oauthrelay.crds.yaml`, and CI checks it with `mise run crds:check`.

`metadata.namespace` is optional in File/SSM documents and ignored by those providers. PrivateKeyJwt config requires exactly one of
`jwksUrl` or typed inline `jwks`.

## Kubernetes provider

`OAUTHRELAY_PROVIDER_KUBERNETES=true` enables discovery within one namespace. The namespace comes
from `OAUTHRELAY_PROVIDER_KUBERNETES_NAMESPACE`, the pod namespace, or the local kubeconfig context.
References remain local to that namespace and public URL keys remain name-only. Runtime RBAC is
read-only and namespaced; CRD installation is an explicit deployment operation.

CR and Secret metadata watches trigger complete validated snapshot publication. Initial lists
and relists are staged until complete; watches reconnect with backoff. Referenced Secret values
are fetched on compilation. All standard secret sources are available, plus
`valueFrom.secretKeyRef: { name, key }`. Periodic refresh defaults to 60 seconds through
`OAUTHRELAY_PROVIDER_KUBERNETES_REFRESH`. Initial synchronization has a 60-second deadline;
subsequent errors retain the last valid snapshot. Provider precedence is File, SSM, Kubernetes.

## Secret sources

A secret-bearing field contains exactly one `value` or `valueFrom` member.

The File provider supports:

```yaml
clientSecret: { value: local-secret }
clientSecret: { valueFrom: { env: { name: GOOGLE_CLIENT_SECRET } } }
clientSecret: { valueFrom: { file: { path: ./secrets/google } } }
clientSecret: { valueFrom: { awsSsmParameter: { name: /oauthrelay/secrets/google } } }
clientSecret: { valueFrom: { awsSecretsManager: { secretId: oauthrelay/google, jsonKey: clientSecret } } }
```

Every configuration provider uses the same standard resolver for inline, environment, file, and
AWS-backed values. Relative file paths resolve from a File resource document's directory; resource
documents without a filesystem location require absolute paths. Values are re-resolved on every
provider refresh. The standalone binary supplies AWS resolution when compiled with the default
`aws` feature.

The SSM provider supports:

```yaml
clientSecret:
  valueFrom:
    awsSsmParameter:
      name: /oauthrelay/secrets/google
```

The referenced parameter must exist, have an absolute name, and use the `SecureString` type.

```yaml
clientSecret:
  valueFrom:
    awsSecretsManager:
      secretId: oauthrelay/google
      jsonKey: clientSecret
```

Secrets Manager resolution uses `GetSecretValue` and the current `SecretString`. Without
`jsonKey`, the complete string is used. With `jsonKey`, the value must be valid JSON whose named
top-level field is a string. Binary secrets and nested JSON paths are rejected.

Secret references are deduplicated within a candidate snapshot. Resolved secret values use a
redacted debug representation and are never included in errors or logs.

## File provider

`OAUTHRELAY_PROVIDER_FILE` names a multi-document YAML file. The provider reloads the resource file
and referenced local secrets every `OAUTHRELAY_PROVIDER_FILE_POLL`, default `30s`. A failed reload
retains the complete last-good snapshot.

## AWS SSM provider

`OAUTHRELAY_PROVIDER_SSM_PREFIX` is one absolute root ending in `/`. The provider enumerates the
fixed resource paths independently:

```text
{root}upstreams/{name}
{root}relays/{name}
```

Resource parameters use the SSM `String` type and contain the complete resource document. Path
kind/name and document kind/name must agree. Names occupy exactly one path segment.

The provider handles `GetParametersByPath` pagination and resolves referenced SSM parameters with
`GetParameter`. Secrets Manager references use `GetSecretValue`. Region and credentials follow the
AWS SDK default provider chain.

A parse, reference, secret-resolution, or validation error rejects the complete candidate and
retains the provider's last-good snapshot. SSM reads are not transactional; a temporarily
inconsistent multi-parameter rollout becomes active after a later refresh observes a complete
valid graph.

## Runtime

```text
OAUTHRELAY_PUBLIC_URL=https://auth.example.com/oidc
OAUTHRELAY_SEAL_KEY=base64:…
OAUTHRELAY_SEAL_KEY_PREVIOUS=base64:…
OAUTHRELAY_LISTEN=0.0.0.0:8080
OAUTHRELAY_PROVIDER_FILE=/etc/oauthrelay/config.yaml
OAUTHRELAY_PROVIDER_FILE_POLL=30s
OAUTHRELAY_PROVIDER_SSM_PREFIX=/oauthrelay/
OAUTHRELAY_PROVIDER_SSM_POLL=60s
OAUTHRELAY_LAMBDA_CONFIG_TTL=60s
OAUTHRELAY_LOG=info
```

At least one provider is required. Native mode reloads providers on their polling intervals.
Lambda mode loads all first snapshots during cold start and refreshes stale provider snapshots
synchronously before an invocation. Wall-clock age includes intervals while Lambda freezes the
process. A failed provider refresh retains that provider's last-good snapshot.

## Sealing and rotation

Transient values are XChaCha20-Poly1305 envelopes serialized with postcard. The current 32-byte
key seals new values. `OAUTHRELAY_SEAL_KEY_PREVIOUS` remains accepted during rotation. Key material,
secret material, and envelope plaintext are never logged.
