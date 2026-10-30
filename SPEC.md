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
  oauthrelay-core/          protocol engine, resources, resolver and transient-store seams, router, sealing
  oauthrelay-secret-resolver/ shared inline, environment, file, and cloud secret dispatch
  oauthrelay-provider-file/ multi-document YAML provider and composable secret resolution
  oauthrelay-provider-ssm/  SSM resource discovery and AWS secret backend
  oauthrelay-provider-kubernetes/ Namespaced CR discovery and Kubernetes Secret backend
  oauthrelay-store-dynamodb/ Amazon DynamoDB transient store
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
    pub refresh_tokens: RefreshTokens,
    pub redirect_policy: Vec<RedirectMatcher>,
}

pub struct RefreshTokens {
    pub mode: RefreshTokenMode, // Passthrough (default) | Sealed | Rotating
    pub grace_period_seconds: u64, // Rotating only; 1..=300, default 30
    pub max_lifetime_seconds: u64, // Rotating only; default 30 days
}
```

`Upstream` owns the external authorization-server connection, OAuth client credentials, and
provider callback. `Relay` owns transparent-relay scope policy, downstream authentication,
refresh-token handling, and redirect policy.

`RefreshTokens` is a struct so that further refresh-token policy can be added per relay without
changing the resource shape. `Passthrough` returns upstream refresh tokens unchanged. `Sealed`
returns sealed handles instead and `Rotating` returns single-use handles whose state lives in the
transient store (see protocol invariants).

`ClientAuth` supports:

- `UpstreamClient`: the downstream request presents the referenced upstream's client ID and
  secret.
- `Public`: no client credential; S256 PKCE is mandatory.
- `ClientSecret`: a relay-specific client ID and secret are compared in constant time.
- `PrivateKeyJwt`: a signed client assertion is verified against inline JWKS, a JWKS URL, or configured issuer discovery. `issuer` and `subject` are exact claim constraints, each defaulting to `clientId`; `client_id` must still match `clientId`. `audience` is an optional non-empty exact audience constraint, defaulting to the relay token endpoint URL; the JWT must contain it as a string or array element. Expiration is required, and optional `iat`/`nbf` timestamps are checked with 60 seconds of skew. Configured workload subjects may differ from the OAuth client ID. Tokens are reusable until expiry; verification does not call Kubernetes TokenReview.

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
| `POST {B}/relay/{R}/token` | Authenticates the downstream client, validates the sealed code, redirect and PKCE, then returns the stored upstream response unchanged (a `sealed` or `rotating` relay replaces only `refresh_token`). |
| `POST {B}/relay/{R}/token` with `refresh_token` | Authenticates the downstream client and relays the refresh grant using the upstream client credentials. A `sealed` relay first opens the presented handle; a `rotating` relay claims it in the transient store and answers with a successor handle. |
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
- Upstream token response status, content type, and bytes are preserved, except for the
  `refresh_token` member of a `sealed` or `rotating` relay (below).
- A `sealed` relay never returns an upstream refresh token. In every successful (2xx) JSON token
  response, from the authorization-code grant and the refresh grant alike, the string
  `refresh_token` member is replaced by a handle: `rrt1.` followed by an XChaCha20-Poly1305
  envelope of the upstream token and an issued-at time, sealed with associated data
  `refresh:{relay key}`. The prefix versions the format; the associated data binds the handle to
  its relay and purpose, so handles are not interchangeable between relays or with flow and code
  envelopes. Member order, all other members, status, and content type are preserved; only
  whitespace between members is normalized. Requests to the upstream token endpoint send
  `Accept: application/json`, and any 2xx body is read as a JSON object whatever its content
  type. Non-2xx responses and 2xx responses without a non-empty string `refresh_token` pass through
  unchanged. A response whose handle cannot be sealed is a `server_error`, and so is a 2xx body
  that is not a JSON object but names a `refresh_token` (for example a form-encoded
  `refresh_token=` pair): the relay answers 502 `server_error` and never returns the raw token.
  Upstream transport failures are 502 `server_error`.
- A `sealed` relay accepts only its own handles at the refresh grant: it opens the handle and
  forwards the upstream token. A raw upstream token, a handle of another relay or installation, or
  a tampered handle is `invalid_grant` and is not forwarded. When the upstream refresh response
  omits `refresh_token`, so does the relay's, and the client keeps its handle. Handles follow
  seal-key rotation: they open under the current or previous key. Switching a relay to `sealed`
  invalidates the refresh tokens it issued earlier; clients must re-authenticate. Switching from
  `rotating` to `sealed` rejects every `rrt2.` handle with `invalid_grant`.
- A `rotating` relay returns single-use handles, `rrt2.` followed by the base64url encoding of 32
  random bytes. A handle is opaque and carries no data; everything it stands for is in the
  transient store. The settings are `gracePeriodSeconds` (1 to 300, default 30) and
  `maxLifetimeSeconds` (at least the grace period, default 30 days): the absolute lifetime of a
  token family from the code grant that created it. A relay in this mode requires
  `RelayConfig.store`; without one, authorize, the code grant, and the refresh grant fail with a
  logged `server_error`.
  - *Issuance.* A successful JSON code-grant response with a non-empty string `refresh_token`
    starts a family and substitutes an `rrt2.` handle with the same rules as `sealed`.
  - *Refresh.* An unknown, expired, or revoked handle, or one past its family's end, is
    `invalid_grant`. Otherwise the handle is claimed with a compare-and-swap so that one
    concurrent caller wins and refreshes upstream. On success the response always carries a
    successor `rrt2.` handle in the same family, wrapping the upstream's new refresh token or, if
    the upstream did not rotate, the same one. The response, byte for byte, is recorded for the
    grace period. An upstream failure or error response releases the claim and is returned as
    for other modes. An upstream `invalid_grant` revokes the family and is returned. A 2xx
    response that is not a JSON object cannot carry a handle: the claim is released and the
    client gets a 502 `server_error`.
  - *Replay.* A handle already rotated is answered with the recorded response for
    `gracePeriodSeconds` after its rotation, so concurrent tabs and retries receive the same
    successor. A handle whose rotation is still in flight is polled for up to five seconds, then
    answered with 503 `temporarily_unavailable` and `Retry-After`. A handle presented after the
    grace period is reuse: the family is revoked, no member refreshes again, and the client gets
    `invalid_grant`. The relay logs a structured `refresh_token_reuse` security event with the
    relay and a hash of the family id, never a token or handle.
  - *Abandoned claims.* A claim older than 60 seconds is presumed abandoned (its process was
    killed or suspended) and can be claimed again, so a crash cannot strand a handle. The
    upstream call itself is abandoned after 30 seconds and its claim released.
  - *Migration.* A `rrt1.` handle presented to a `rotating` relay is opened, refreshed, and
    replaced by an `rrt2.` successor in a new family, so switching `sealed` to `rotating` does
    not sign users out. Raw upstream tokens are `invalid_grant`.
  - *Storage.* Keys carry only a SHA-256 over the relay key and the handle (or family id). Record
    values are XChaCha20-Poly1305 envelopes whose associated data names the relay, the purpose,
    and the store key, so the store never holds a plaintext token and values cannot be moved
    between keys. Records expire with their family; see the transient store below. A store
    failure fails closed with 503 `server_error`; an upstream token is never returned in its
    place. A record this relay cannot open (seal key replaced, value tampered with) is
    `invalid_grant`, because retrying cannot help.
- In every mode, including `passthrough`, a refresh token with a handle prefix (`rrt` followed by
  digits and a dot) is never forwarded to the upstream: it is `invalid_grant`. A handle is not an
  upstream token, so forwarding one only leaks it.
- Discovery and JWKS responses are cached for bounded TTLs.

## Transient store

Sealed envelopes carry their own state, so the router remembers only the facts that must outlive a
request: redeemed codes and assertions, and the state of `rotating` refresh-token families. Those live behind one seam, `TransientStore`, selected through `RelayConfig.store`:

```rust
#[async_trait]
pub trait TransientStore: Send + Sync + 'static {
    async fn put_if_absent(&self, key: &str, value: &[u8], ttl: Duration) -> Result<bool, StoreError>;
    async fn get(&self, key: &str) -> Result<Option<Entry>, StoreError>;
    async fn compare_and_swap(&self, key: &str, expected: &[u8], new: &[u8], ttl: Duration)
        -> Result<bool, StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
}
```

Every write carries a TTL, values are opaque bytes, and operations on one key are linearizable
across all instances sharing the backend. Callers namespace keys by purpose (`replay:` and
`refresh:`); backends never interpret keys. An expired record
is absent for reads and conditional writes even when the backend has not yet deleted it. Callers write values unique
to the writer (sealed with a random nonce, or carrying a random claim id): DynamoDB asks for the
existing item when a condition fails and counts a failure against the value it just wrote as
success, since SDK retries can report a failure for a write that applied. A backend
error means the outcome is unknown and callers fail closed. The rustdoc on the trait states the
full contract and the rotation protocol built on it.

Replay protection uses `put_if_absent` on `replay:code:{envelope id}` for authorization codes and
`replay:client-assertion:{digest}` for `requireSingleUse` client assertions. An unavailable store
makes the token endpoint return HTTP 503 `server_error` without consuming the code, and fails
client-assertion authentication.

Rotation uses three keys under `refresh:`: `refresh:handle:{hash}` holds a handle's record
(`Active`, `Claimed`, or a token-free `Rotated` tombstone) until its family expires;
`refresh:grace:{hash}` holds the response of one rotation for the grace period plus ten seconds;
`refresh:revoked:{hash}` marks a revoked family until it expires. A rotation costs about two
strongly consistent reads and four writes, and leaves a tombstone of a few hundred bytes that
lives until the family ends.

The standalone binary selects the backend with `OAUTHRELAY_STORE`. `memory` (default) is
process-local and protects one process or one Lambda execution environment. `dynamodb`
(`oauthrelay-store-dynamodb`, behind the `aws` feature) shares state across replicas and Lambda
environments through conditional `PutItem` and strongly consistent `GetItem`, with `expires_at`
epoch seconds as the table's TTL attribute and an explicit expiry check on every read. An
embedding without a store accepts a sealed authorization code for its five-minute cryptographic
lifetime and rejects `requireSingleUse` client assertions.

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

`spec.refreshTokens.mode` is `passthrough` (default), `sealed`, or `rotating`. `gracePeriodSeconds`
(1 to 300, default 30) and `maxLifetimeSeconds` (default 2592000) apply only to `rotating`; setting
them in another mode, or out of range, rejects the candidate snapshot.

Unknown fields, kinds, API versions, duplicate identities, invalid URLs, invalid origins, invalid
scope tokens, and dangling references reject the candidate snapshot.

`oauthrelay schema` prints a JSON Schema generated from the Rust configuration types.

`oauthrelay crds` prints the namespaced Upstream and Relay CRDs generated from shared Rust
configuration types with structural schema validation. The generated bundle is committed at
`deploy/oauthrelay.crds.yaml`, and CI checks it with `mise run crds:check`.

`metadata.namespace` is optional in File/SSM documents and ignored by those providers. PrivateKeyJwt
accepts either `jwksUrl` or typed inline `jwks`, or discovers keys from an explicit `issuer` when
both are omitted. Discovery metadata must identify that exact issuer. Issuer and discovered JWKS
URLs use HTTPS (HTTP is allowed on IP loopback), without user information, queries, or fragments.
Discovery requests do not inherit Kubernetes API credentials or the cluster CA. Client assertion
discovery and JWKS fetches reject redirects, use a separate cache and HTTP client, and have a
ten-second deadline. Unknown signing key IDs trigger one serialized JWKS refresh per URL;
forced refreshes and failed fetch retries are limited to once per thirty seconds. A failed refresh
retains known keys until their normal cache expiry.

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
