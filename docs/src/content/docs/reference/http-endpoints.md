---
title: HTTP endpoints
description: Reference for oauthrelay relay, callback, metadata, and health routes.
---

`OAUTHRELAY_PUBLIC_URL` is the complete base `B` for the OAuth API. For relay name `R` referencing
upstream name `U`, oauthrelay serves:

| Method and route | Behavior |
| --- | --- |
| `GET {B}/relay/{R}/authorize` | Validates redirect and scope policy, creates independent upstream state and S256 PKCE, then redirects to the upstream. |
| `GET {B}/upstream/{U}/callback` | Validates upstream-bound state, exchanges the upstream code, and returns a sealed code to the originating relay redirect. |
| `POST {B}/relay/{R}/token` | Authenticates the relying party, validates the sealed code, redirect, PKCE, and configured ID-token claims, then returns the stored upstream response unchanged. A relay with `refreshTokens.mode: sealed` or `rotating` replaces only the `refresh_token` member. |
| `POST {B}/relay/{R}/token` with `refresh_token` | Authenticates the relying party and relays the refresh grant with upstream credentials. A `sealed` relay opens the presented handle first; a `rotating` relay claims it and returns a successor handle. |
| `OPTIONS {B}/relay/{R}/token` | Returns CORS headers only for an allowed origin. |
| `GET {B}/relay/{R}/.well-known/openid-configuration` | Preserves upstream issuer/JWKS metadata, rewrites authorization and token endpoints to the relay, and describes what the relay accepts (see [Transparent metadata](#transparent-metadata)). |
| `GET {B}/relay/{R}/jwks` | Proxies the referenced upstream JWKS. Answers 404 when the upstream has none (see [Upstream endpoints](/oauthrelay/configuration/#upstream)). |
| `GET /healthz` | Reports standalone process liveness. |
| `GET /readyz` | Reports readiness after initial provider snapshots are available. |

## Embedding: custom URL layout

The routes above are the built-in layout (`DefaultLayout`). A Rust host that embeds
`oauthrelay_core::router` can serve the same endpoints under its own paths by passing an
`Arc<dyn PathLayout>`:

```rust
pub trait PathLayout: Send + Sync + 'static {
    /// Maps a request path below `public_url` (no leading slash) to an endpoint and key.
    fn parse(&self, path: &str) -> Option<(Endpoint, ResourceKey)>;
    /// The path below `public_url` (no leading slash) serving `endpoint` for `key`.
    fn path(&self, endpoint: Endpoint, key: &ResourceKey) -> String;
}
```

`Endpoint` is `Authorize`, `Callback`, `Token`, `Discovery`, or `Jwks`. Every endpoint is keyed by
the relay key except `Callback`, which is keyed by the upstream key. A layout may place the callback
under the same key as the relay, for example `/oidc/{project}/{extension}/callback`; that only lines
up when the relay key equals its upstream key, otherwise the callback lands under the upstream's key.
`parse` receives the raw request path below `public_url` without its leading slash: percent-escapes
are not decoded, and repeated or empty segments are passed through as-is.

The router renders every URL it hands out through `path`: the upstream `redirect_uri`, the
`authorization_endpoint` and `token_endpoint` in the discovery document, and the default
`private_key_jwt` audience. `path` must therefore invert `parse`. `DefaultLayout::new(KeyStrategy)`
keeps the built-in routes; for `KeyStrategy::Custom` it renders keys verbatim, so the mapper must
accept the key parts it is given.

## Embedding: outbound requests

The relay sends HTTP requests to URLs it did not choose: an issuer's discovery document names its
own `jwks_uri`, which the relay fetches and serves at `/jwks`, and a `private_key_jwt` client's
issuer does the same. An embedder whose issuers are not all trusted should vet those URLs.
`RelayConfig.outbound` takes an `Arc<dyn OutboundPolicy>`; `None` allows everything, as the
standalone service does.

```rust
#[async_trait]
pub trait OutboundPolicy: Send + Sync + 'static {
    async fn check(&self, url: &Url, purpose: OutboundPurpose) -> Result<(), OutboundDenied>;
}

#[non_exhaustive]
pub enum OutboundPurpose {
    Discovery, Jwks, TokenExchange, Refresh, ClientAssertionMetadata, ClientAssertionJwks,
}
```

`check` runs before every request sent with `RelayConfig.http` or
`RelayConfig.client_assertion_http`, with the URL as the relay holds it, and not again for answers
served from the metadata and key caches. A denied request is never sent and is unavailable, not
absent: relay discovery and `/jwks` answer 502 and remember nothing, a code redemption that needs
the JWKS answers 502 `server_error` and leaves the code unconsumed, token and refresh requests
answer 502, and a client assertion is rejected as `invalid_client`. Denials are logged at `warn`
(target `oauthrelay::outbound`) with the purpose and host, never the path or query.

The policy sees only the initial URL, so the clients must not follow redirects, or must enforce
the policy on every hop. `oauthrelay_core::default_client_builder()` does not follow redirects;
build `RelayConfig.http` with `redirect::Policy::none()` when using another builder.
`ClientAssertionHttpClient` never follows them. Resolve host names and reject private, loopback,
and link-local addresses inside the policy, or in the client's connector, if the network behind
the relay must stay out of reach.

## Authorization endpoint

Only authorization-code flow and query response mode are accepted. oauthrelay owns and replaces
`client_id`, `redirect_uri`, `state`, upstream PKCE, and `response_type`. Other parameters,
including `nonce`, `prompt`, `login_hint`, `access_type`, `hd`, repeated `resource` values, and
provider extensions, are forwarded.

OIDC `request` and `request_uri` objects are rejected because their embedded routing fields cannot
be reconciled safely with proxy-owned values. A supplied scope must pass the relay allow-list. A
public relay also requires a valid S256 application code challenge.

`redirect_uri` is required and must match one configured redirect-policy entry. Static query
parameters are part of the match. oauthrelay appends authorization results and application state
only after the redirect has passed policy.

## Callback

The callback is owned by the upstream, not by an individual relay. Sealed state identifies the
originating relay and validated application redirect, so several relays can share the same
upstream callback. Upstream error parameters are returned only to that validated redirect.

oauthrelay exchanges a successful upstream code immediately. It stores the upstream status, content
type, and body inside the sealed application code and never exposes the upstream code to the
application.

## Token endpoint

Relying parties with a `UpstreamClient` or `ClientSecret` relay authenticate with either an
`Authorization: Basic` header (RFC 6749 section 2.3.1: form-urlencoded client ID and secret joined by
`:` and base64-encoded) or `client_id` and `client_secret` form fields, never both. Both at once
return HTTP 400 `invalid_request`. A malformed header or wrong credentials return HTTP 401
`invalid_client`, with `WWW-Authenticate: Basic realm="oauthrelay"` when the client used the header.
See [Client authentication](/oauthrelay/configuration/#client-authentication).

The authorization-code request must use the same redirect URI and, when the authorization request
carried a `code_challenge`, the matching PKCE verifier. A `code_verifier` for a code whose
authorization request had no `code_challenge` returns HTTP 400 `invalid_grant` for every client
authentication type, so a PKCE downgrade cannot go unnoticed (RFC 9700 section 4.8.2). Successful exchange returns the upstream status, content type, and body bytes unchanged
under `no-store`/`no-cache` response headers. The transient store rejects a second use: in the same
process with the default memory store, deployment-wide with DynamoDB. If the store is unavailable,
the endpoint returns HTTP 503 `server_error` and leaves the code unconsumed.

When `requiredIdTokenClaims` is non-empty, oauthrelay verifies the signed upstream ID token before
returning a successful stored response. A missing or different claim returns HTTP 400 with
`error=invalid_grant`, a generic description, and `no-store`/`no-cache` response headers. The
response does not include tokens or rejected claim values.

Refresh grants preserve extension fields and replace downstream authentication with the referenced
upstream client credentials. Unsupported grants and invalid requests use RFC 6749-style JSON error
bodies.

### Sealed refresh tokens

With `refreshTokens.mode: sealed` (see [Refresh tokens](/oauthrelay/configuration/#refresh-tokens)),
the relay never returns the upstream refresh token. In a successful JSON response from either grant,
`refresh_token` is a handle beginning with `rrt1.`; the status, content type, member order, and all
other members are unchanged.

```json
{"access_token":"ya29.…","refresh_token":"rrt1.v1.…","expires_in":3599,"token_type":"Bearer"}
```

The refresh grant takes that handle as `refresh_token`. Anything else, including a raw upstream
token, a handle from another relay, a handle issued before the relay's
[upstream identity or generation changed](/oauthrelay/configuration/#changing-a-relays-upstream),
or a modified handle, returns HTTP 400 with `error=invalid_grant`, and the request is not sent to
the upstream. If the upstream refresh response
has no `refresh_token`, neither does the relay's response, and the client keeps its handle.
Non-2xx upstream responses are returned unchanged. The relay sends `Accept: application/json` to
the upstream and reads any 2xx body as JSON whatever its content type; a 2xx body that is not a
JSON object but contains a `refresh_token` field (for example form-encoded) is answered with 502
`server_error` and is never returned. A refresh token with a handle prefix (`rrt<N>.`) is never sent
to the upstream as-is in any mode, including `passthrough`: a handle the mode can open is opened,
any other is `invalid_grant`.

### Rotating refresh tokens

With `refreshTokens.mode: rotating` (see
[Rotating refresh tokens](/oauthrelay/configuration/#rotating-refresh-tokens)) handles begin with
`rrt2.` and are single use. A successful refresh response always contains a successor handle,
even when the provider returned none; present that one next.

```json
{"access_token":"ya29.…","refresh_token":"rrt2.Zk3…","expires_in":3599,"token_type":"Bearer"}
```

| Situation | Response |
| --- | --- |
| Handle unknown, expired, revoked, past the family's maximum lifetime, not issued by this relay, issued before the relay's [upstream identity or generation changed](/oauthrelay/configuration/#changing-a-relays-upstream), or stored under a seal key that is no longer configured | 400 `invalid_grant`; the provider is not contacted. |
| Handle already used, within `gracePeriodSeconds` of its rotation | The response of that rotation again, with the same successor handle. |
| Handle already used, after the grace period | 400 `invalid_grant`, and the whole family is revoked. |
| Another request is rotating the same handle and does not finish within five seconds | 503 `temporarily_unavailable` with `Retry-After: 1`; retry. |
| Provider unreachable or answers an error | The provider's error, or 502 `server_error`; the handle stays usable. |
| Provider answers `invalid_grant` | The provider's error, and the family is revoked. |
| Provider answers success without a JSON object body | 502 `server_error`; the handle stays usable. |
| Transient store unreachable | 503 `server_error`. |
| `rrt1.` handle from this relay when it was `sealed`, younger than `maxLifetimeSeconds` | Accepted (and accepted again if presented again: sealed handles are stateless); the response carries an `rrt2.` handle in a new family. |
| `rrt1.` handle older than `maxLifetimeSeconds` | 400 `invalid_grant`. |
| Provider answers a 2xx body that is not a JSON object but contains `refresh_token` (code or refresh grant) | 502 `server_error`; the token is never returned. |
| The family is revoked while the request is in flight | 400 `invalid_grant`; no tokens are returned. |

A relay in this mode with no transient store configured returns 500 `server_error` from the
authorize endpoint and both grants and logs the cause.

### Sealer unavailable

A library embedder can supply a `Sealer` backed by a remote key service. When it reports
`SealError::Unavailable`, or does not answer within five seconds during a rotation, the request fails
without treating the value as invalid:

- The token endpoint (code and refresh grants) returns 503 `server_error` and never returns a token.
  The authorize and callback endpoints return a bare 503.
- A refresh handle is usable again once the claim lease (at most 60 seconds) has expired. If the
  provider rotated its refresh token during the failed attempt, the next refresh may be rejected by
  the provider.
- A `sealed`-mode authorization code stays redeemable. A `rotating`-mode code is consumed, because
  its family is written to the store first; a retry answers `invalid_grant`.
- Revoking a family still succeeds, so the client gets the usual `invalid_grant` or the provider's
  error. The revocation marker blocks the family; the stored token it could not erase expires with the
  family.

A value the sealer reports as invalid keeps its `invalid_grant` (or 400) answer.

## Transparent metadata

Relay metadata is useful to inspect the routed authorization and token endpoints, but is not a
portable OIDC Discovery contract. The metadata URL is hosted by oauthrelay while `issuer` remains the
upstream issuer. Configure transparent-relay relying parties with manual endpoints as described in
[Relay trust model](/oauthrelay/relay-model/).

The document starts from the upstream's discovery metadata (or an empty document when the
authorization, token, and JWKS endpoints are all configured explicitly, or when an upstream with
explicit authorization and token endpoints definitely has no discovery document) and keeps what
still holds for a client of the relay: the issuer, `jwks_uri` (omitted when the upstream has no
JWKS), `userinfo_endpoint` (it takes the upstream access token, which the relay never
replaces), `end_session_endpoint`, ID-token, claim, and subject-type members, and members
oauthrelay does not recognize, except endpoints. Members that describe the relay's own endpoints
are replaced:

| Member | Value |
| --- | --- |
| `authorization_endpoint`, `token_endpoint` | The relay's endpoints. |
| `response_types_supported` | `["code"]` |
| `response_modes_supported` | `["query"]` |
| `grant_types_supported` | `authorization_code`, and `refresh_token` unless the upstream lists its `grant_types_supported` without it. An upstream that omits the member keeps `refresh_token`, although [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html#section-2) reads that absence as `authorization_code` and `implicit` only: providers such as Microsoft Entra ID omit it yet issue refresh tokens. |
| `code_challenge_methods_supported` | `["S256"]` |
| `request_parameter_supported`, `request_uri_parameter_supported` | `false` |
| `scopes_supported` | The relay's `scopes.allowed` when configured; otherwise the upstream's value. |
| `token_endpoint_auth_methods_supported` | `UpstreamClient` and `ClientSecret`: `["client_secret_basic", "client_secret_post"]`. `Public`: `["none"]`. `PrivateKeyJwt`: `["private_key_jwt"]`. |
| `token_endpoint_auth_signing_alg_values_supported` | `PrivateKeyJwt` only: the accepted assertion algorithms, `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, and `EdDSA`. Removed otherwise. |

Members for endpoints and features a client of the relay cannot use are removed. Every
`*_endpoint` member other than `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
`end_session_endpoint`, `revocation_endpoint`, and `introspection_endpoint` is removed, whether
oauthrelay recognizes it (dynamic client registration, device authorization, pushed authorization
requests, CIBA) or not. So are mTLS endpoint aliases and certificate-bound tokens, DPoP, request
objects, JARM, session-management and front-, back-channel, and HTTP logout, and `signed_metadata`,
whose values would take precedence over the relay's. The upstream `revocation_endpoint` and
`introspection_endpoint`, with their authentication and response-signing members, remain only in
`passthrough` refresh-token mode, where the client holds the upstream tokens those endpoints
accept; in `sealed` and `rotating` mode it holds relay handles, and they are removed.
