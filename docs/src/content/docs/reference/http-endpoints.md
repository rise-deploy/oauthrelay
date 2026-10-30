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
| `POST {B}/relay/{R}/token` | Authenticates the relying party, validates the sealed code, redirect, PKCE, and configured ID-token claims, then returns the stored upstream response unchanged. A relay with `refreshTokens.mode: sealed` replaces only the `refresh_token` member. |
| `POST {B}/relay/{R}/token` with `refresh_token` | Authenticates the relying party and relays the refresh grant with upstream credentials. A `sealed` relay opens the presented handle first. |
| `OPTIONS {B}/relay/{R}/token` | Returns CORS headers only for an allowed origin. |
| `GET {B}/relay/{R}/.well-known/openid-configuration` | Preserves upstream issuer/JWKS metadata and rewrites authorization and token endpoints to the relay. |
| `GET {B}/relay/{R}/jwks` | Proxies the referenced upstream JWKS. |
| `GET /healthz` | Reports standalone process liveness. |
| `GET /readyz` | Reports readiness after initial provider snapshots are available. |

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

The authorization-code request must use the same redirect URI and, when present, the matching PKCE
verifier. Successful exchange returns the upstream status, content type, and body bytes unchanged
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
token, a handle from another relay, or a modified handle, returns HTTP 400 with
`error=invalid_grant`, and the request is not sent to the upstream. If the upstream refresh response
has no `refresh_token`, neither does the relay's response, and the client keeps its handle.
Non-2xx upstream responses are returned unchanged. The relay sends `Accept: application/json` to
the upstream and reads any 2xx body as JSON whatever its content type; a 2xx body that is not a
JSON object but contains a `refresh_token` field (for example form-encoded) is answered with 502
`server_error` and is never returned. A refresh token with a handle prefix (`rrt<N>.`) is never sent
to the upstream in any mode, including `passthrough`; it is `invalid_grant`.

## Transparent metadata

Relay metadata is useful to inspect the routed authorization and token endpoints, but is not a
portable OIDC Discovery contract. The metadata URL is hosted by oauthrelay while `issuer` remains the
upstream issuer. Configure transparent-relay relying parties with manual endpoints as described in
[Relay trust model](/oauthrelay/relay-model/).
