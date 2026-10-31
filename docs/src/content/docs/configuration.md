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
| `spec.oauthClient.tokenEndpointAuthMethod` | no | How oauthrelay authenticates at the upstream token endpoint: `client_secret_post` (default) or `client_secret_basic`. |

`client_secret_post` sends `client_id` and `client_secret` as form fields in the request body.
`client_secret_basic` sends them in an HTTP `Authorization: Basic` header instead, form-urlencoded
before the Basic encoding as RFC 6749 section 2.3.1 requires, and leaves them out of the body. Use it
for providers that accept only Basic client authentication, such as Notion. The method applies to
every upstream token request: the authorization-code exchange and all refresh grants. It does not
change how relying parties authenticate to the relay, which `clientAuthentication` controls.

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
| `spec.idTokenPolicy` | no | omitted | Typed claim rules for initial sign-in; all rules also compose with `requiredIdTokenClaims`. |
| `spec.refreshTokens.mode` | no | `passthrough` | `passthrough` returns upstream refresh tokens unchanged; `sealed` returns [sealed handles](#refresh-tokens) instead; `rotating` returns [single-use handles](#rotating-refresh-tokens) and needs a shared [transient store](/oauthrelay/reference/transient-store/). |
| `spec.refreshTokens.gracePeriodSeconds` | no | `30` | `rotating` only, 1 to 300. How long an already-used handle is still answered with the same successor. |
| `spec.refreshTokens.maxLifetimeSeconds` | no | `2592000` (30 days) | `rotating` only, at least `gracePeriodSeconds`. Absolute lifetime of a refresh-token family from the original sign-in. |
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
  - loopbackOrigin: http://[::1]
```

`uri` compares the complete decoded value exactly, including path, query order, encoding, port,
and trailing slash. It requires HTTPS, except for an exact HTTP URI on `127.0.0.1` or `::1`.
Static query parameters participate in matching; oauthrelay appends generated authorization results
and application state only after the URI passes policy.

`origin` requires HTTPS and matches scheme, host, and effective port. Every path and query at that
origin is accepted, which suits preview environments whose callback paths vary. An `http://` origin
is accepted only by a service started with the off-by-default `OAUTHRELAY_ALLOW_HTTP_ORIGINS`
development option, and must be spelled canonically (`http:dev.example` or a zero-padded port is a
configuration error). Without the option, a relay carrying an `http://` origin is invalid and never
silently ignores the entry:

- If such a relay is configured at startup, the service refuses to start and names the relay and
  the option.
- If a provider refresh introduces one later, every endpoint of that relay (authorize, token,
  discovery, JWKS) answers HTTP 500 (`server_error` at the token endpoint) and logs an error naming
  the option. Provider callbacks for that relay's flows already in progress answer 400 and redirect
  nowhere. Other relays are unaffected.

`loopback` requires HTTP on `127.0.0.1` or `::1` without a configured port. Its path and query
match exactly while the application may select any runtime port. Use `uri` when a loopback port is
fixed.

`loopbackOrigin` names a loopback host alone, `http://127.0.0.1` or `http://[::1]`, and accepts
every port, path, and query on it. It suits local development servers that choose their callback
path at runtime; prefer `loopback` when the path is known.

`localhost` is not a loopback IP literal. The off-by-default `OAUTHRELAY_ALLOW_LOCALHOST_LOOPBACK`
service option lets a `loopback` or `loopbackOrigin` entry also match `localhost` and its
subdomains such as `app.localhost` (RFC 6761), which most browsers, including Chrome and Firefox,
resolve to loopback. Names are
compared without regard to case; empty labels, trailing dots, and names that merely contain
`localhost`, such as `localhost.example.com`, never match. Other resolvers may send such names to
DNS, so enable the option only where every client is a browser or resolves them locally.

Redirects matched by `loopback`, `loopbackOrigin`, or an `http://` origin must spell their scheme,
host, and port unambiguously. Rejected forms are a missing or extra `/` after the scheme
(`http:127.0.0.1/cb`, `http:/127.0.0.1/cb`, `http:///127.0.0.1/cb`), empty user information
(`http://@127.0.0.1/cb`), shortened, octal, hexadecimal, or decimal IPv4 hosts (`127.1`, `0177.0.0.1`,
`0x7f.0.0.1`, `2130706433`), percent-encoded hosts, and empty or zero-padded ports (`:`, `:049152`,
`:080`). Any spelling of the IPv6 loopback address (`[0:0:0:0:0:0:0:1]`) and an explicit default
port (`:80`) are accepted. HTTPS `origin` and `uri` matching are unaffected.

User information, fragments, wildcards, prefix matching, empty policies, duplicate entries,
backslashes, and entries containing more than one matcher are rejected.

The token endpoint derives CORS permission without broadening redirects. A `uri` entry permits its
origin, an `origin` entry permits that origin, and a `loopback` or `loopbackOrigin` entry permits
its IP host on any port, plus `localhost` names when the localhost option is on. The
authorization-code token request must still repeat the exact redirect URI stored for the flow.

`requiredIdTokenClaims` applies to successful authorization-code exchanges. oauthrelay verifies
the upstream ID-token signature, issuer, audience, lifetime, subject, issued-at time, nonce when
requested, authorized party, and access-token hash when present. Every configured claim must exist
as a string with the exact configured value. The policy reads only signed ID-token claims; it does
not read UserInfo. A failed policy returns `invalid_grant` without returning upstream tokens. Relay
codes remain single-use after a failed check. Refresh grants do not evaluate this policy because an
upstream refresh response does not always contain an ID token.

### ID-token admission policy

`idTokenPolicy` evaluates top-level claims from the verified upstream ID token. It can require a
verified email and admit either a Google Workspace domain or an explicit set of Gmail accounts:

```yaml
idTokenPolicy:
  required:
    email_verified:
      booleanEquals: true
  anyOf:
    - hd:
        stringEquals: example.com
    - email:
        stringIn:
          - alice@gmail.com
          - bob@gmail.com
```

Every matcher in `required` must pass. At least one `anyOf` branch must pass, and every matcher
within that branch must pass. If both sections are configured, both must pass. A missing claim
or a value of the wrong JSON type fails only its matcher: a Gmail account without `hd` can still
match the email branch. When `requiredIdTokenClaims` is configured too, its exact-string checks
must also pass. Both policy fields are optional; omitting both leaves admission to the upstream.

Each claim has exactly one operator:

| Operator | Configuration value | Comparison |
| --- | --- | --- |
| `stringEquals` | string | Exact, case-sensitive equality. |
| `stringIn` | non-empty string list | Exact, case-sensitive membership. |
| `stringLike` | string | Full-string, case-sensitive glob matching. |
| `booleanEquals` | boolean | Exact JSON boolean equality; `true` does not match the string `"true"`. |
| `arrayContainsAny` | non-empty string list | The claim is an array of strings and at least one listed value is an element (exact, case-sensitive). |
| `arrayContainsAll` | non-empty string list | The claim is an array of strings and every listed value is an element (exact, case-sensitive). |
| `arrayLikeAny` | string | The claim is an array of strings and at least one element matches the `stringLike` glob. |

For `stringLike`, `*` matches zero or more Unicode characters and `?` matches exactly one. All
other characters, including brackets and backslashes, are literals; there is no regex or escape
syntax, path-separator handling, or implicit email normalization. For example,
`stringLike: "guest-?@example.net"` matches `guest-a@example.net`, but not `guest-ab@example.net`
or `guest-a@example.net.evil`. Use Google's signed `hd` claim when checking Workspace membership;
an email-address suffix alone does not establish it.

The array operators are for claims such as `groups`. An absent claim fails the matcher
(`missing_claim`); a claim that is `null`, is not an array, or is an array with any non-string
element fails it as `wrong_type`, and the string operators likewise reject an array claim. An empty
array never satisfies an array operator, including `arrayContainsAll`. Providers that leave the claim
out under some conditions (Microsoft Entra ID omits `groups` for users in more groups than fit in a
token) are therefore denied for those users. `arrayLikeAny` uses the `stringLike` glob semantics for each element. For
example, to admit verified users in the `admins` or `ops` group:

```yaml
idTokenPolicy:
  required:
    email_verified:
      booleanEquals: true
    groups:
      arrayContainsAny:
        - admins
        - ops
```

Only top-level claims are addressed. The IdP must be configured to emit the claim in the ID token
(for example, a `groups` claim or scope), and it must be an array of strings.

Absent or null optional policy fields are omitted. Empty policies or sections, empty branches or
membership lists, unknown operators, and multiple operators on one claim reject the candidate configuration. A denied
authorization-code exchange returns `invalid_grant` without upstream tokens and consumes the
single-use relay code. Failed signature, issuer, audience, nonce, or lifetime validation also
rejects the exchange before claim evaluation.

Admission rules apply only to authorization-code redemption. Refresh grants do not evaluate
either policy field, even when they return an ID token. Removing an identity from an allowlist
does not revoke an existing session or establish that a submitted refresh token passed admission.

Enable `OAUTHRELAY_LOG=info,oauthrelay::id_token_policy=debug` to log matcher, branch, and final
admission results, including missing-claim, wrong-type, and value-mismatch reasons. Events identify
the relay, upstream, section, claim name, operator, and branch index where applicable. They do
not include actual claim values, configured comparison values or patterns, or tokens. Invalid
tokens produce a final rejection result without evaluating their untrusted claims. Exchanges
without an admission policy or without a successful upstream response log a `skipped` outcome.

## Refresh tokens

By default a relay is transparent: the upstream refresh token reaches the relying party and comes
back at the refresh grant. A refresh token that leaks from the relying party can then be refreshed
through the relay for as long as the provider honours it.

A `Public` relay must use `refreshTokens.mode: rotating`. Its relying party, typically a browser or
native app, cannot keep a credential, and [RFC 9700 section
4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) requires a public client's refresh
tokens to be sender-constrained or rotated; the relay does not sender-constrain them. A `Public`
relay with `passthrough` (the default) or `sealed` fails validation, naming the relay: at startup the
configuration is rejected, and a provider refresh keeps its last good snapshot and logs the error.
The Kubernetes `Relay` CRD also rejects it at admission (see
[Kubernetes provider](/oauthrelay/reference/kubernetes-provider/)). `rotating` needs a transient
store shared by every serving instance; see [Rotating refresh tokens](#rotating-refresh-tokens).

In every mode, including `passthrough`, a refresh token that starts with `rrt` followed by digits
and a dot (such as `rrt1.`) is a relay handle, never an upstream token, and is never forwarded to
the provider as-is. A handle the relay's mode can open is opened (see the modes below); any other
handle is answered with `invalid_grant`.

### Security profile

| | `passthrough` | `sealed` | `rotating` |
|---|---|---|---|
| The client holds | the upstream token | an `rrt1.` handle | an `rrt2.` handle |
| The upstream token leaves the relay | yes | no | no |
| A leaked token works through the relay | until the provider expires it | until the provider expires it | until the legitimate client next refreshes; if the thief refreshed first, that refresh revokes the family |
| Theft detection | none | none | reuse after the grace period revokes the family |
| Lifetime bound set by the relay | none | none | `maxLifetimeSeconds` |
| Revoke every token at once | at the provider | replace the seal key | replace the seal key |
| Needs a store | no | no | yes |
| Allowed for `Public` relays | no | no | yes |

`sealed` hides the upstream token but does not shorten the life of a leaked handle; use `rotating`
when a stolen refresh token has to stop working. In both, the relay holds the upstream token only
encrypted with `OAUTHRELAY_SEAL_KEY`, so the store or a captured handle reveals nothing without
the key. Within `gracePeriodSeconds` of a rotation, anyone presenting the spent handle gets the
same successor, so the grace window is the one span in which a thief goes undetected.

Set `refreshTokens.mode: sealed` to keep upstream refresh tokens inside the relay, here for a
server-side relying party with its own client secret:

```yaml oauthrelay-config
apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://accounts.google.com
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
  name: web
spec:
  upstreamRef:
    name: google
  refreshTokens:
    mode: sealed
  clientAuthentication:
    type: ClientSecret
    clientId: web-backend
    clientSecret:
      valueFrom:
        env:
          name: WEB_BACKEND_CLIENT_SECRET
  redirectPolicy:
    - uri: https://app.example.com/oauth/callback
```

In `sealed` mode every successful JSON token response, from the authorization-code grant and from
the refresh grant, has its `refresh_token` replaced by an opaque handle that starts with `rrt1.`.
The handle contains the upstream token encrypted with `OAUTHRELAY_SEAL_KEY`, bound to the relay
name, so only this relay can open it. At the refresh grant the relay opens the handle and sends
the upstream token to the provider. Status, content type, member order, and every other member of
the response are preserved. Non-2xx responses, and successful responses that carry no
`refresh_token`, are returned unchanged. When a refresh response omits `refresh_token`, the
relying party keeps using its current handle.

- A refresh token that is not a handle of this relay, such as a raw upstream token or a handle
  issued by another relay, is rejected with `invalid_grant`. Switching an existing relay to
  `sealed` therefore requires its users to sign in again.
- Handles open under `OAUTHRELAY_SEAL_KEY` and `OAUTHRELAY_SEAL_KEY_PREVIOUS`, so seal-key rotation
  keeps them valid until the previous key is removed. Replacing the key without keeping the old
  one as the previous key invalidates every handle.
- A handle carries no expiry and is not single-use: it stays valid for as long as the upstream
  token does. Sealing prevents a leaked handle from being used at the provider directly; it does
  not make the handle unusable at the relay. Providers that rotate refresh tokens return a new
  upstream token, which the relay seals into a new handle.
- The relay asks the provider for JSON (`Accept: application/json`) and reads any successful
  response body as a JSON object, whatever its content type. A provider that still answers with a
  form-encoded or other non-JSON body that contains a `refresh_token` cannot be rewritten, so the
  relay fails closed with HTTP 502 `server_error` instead of returning the raw token. Provider
  errors (non-2xx) pass through unchanged; an unreachable provider is a 502 `server_error`.

### Rotating refresh tokens

`sealed` handles are stateless, so a leaked handle works for as long as the upstream token does.
Set `refreshTokens.mode: rotating` to make every handle single use and to detect theft:

```yaml oauthrelay-config
apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: google
spec:
  issuerUrl: https://accounts.google.com
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
  name: spa
spec:
  upstreamRef:
    name: google
  refreshTokens:
    mode: rotating
    gracePeriodSeconds: 30
    maxLifetimeSeconds: 2592000
  clientAuthentication:
    type: Public
  redirectPolicy:
    - origin: https://app.example.com
```

In `rotating` mode the code grant returns a handle that starts with `rrt2.`: 32 random bytes that
mean nothing outside the relay. The upstream token lives, encrypted with `OAUTHRELAY_SEAL_KEY` and
bound to the relay, in the [transient store](/oauthrelay/reference/transient-store/). Every
refresh grant presents a handle, refreshes upstream, and returns a **new** handle in the same
`refresh_token` member; the presented handle is spent. If the upstream does not rotate its own
token, the relay wraps the same upstream token in the new handle, so the response always carries a
refresh token and the client must always store the latest one.

- **Grace period.** Browsers with several tabs, and clients that retry after a lost response, can
  present the same handle twice. Within `gracePeriodSeconds` of the rotation the second request
  gets the same response, and the same successor handle, without reaching the provider. Requests
  that arrive while the first is still in flight wait up to five seconds for it; if it is slower
  they get HTTP 503 `temporarily_unavailable` with `Retry-After` and should retry.
- **Reuse detection.** A spent handle presented after the grace period means two parties hold the
  same token. The relay revokes the whole family, including the newest handle, and answers
  `invalid_grant`; the user signs in again. The relay logs a `refresh_token_reuse` security event
  (target `oauthrelay::security`) with the relay name and a hash of the family, never a token.
- **Revocation erases the token.** Revoking a family deletes the stored upstream token as well as
  blocking the handles, and a refresh that was in flight when the revocation happened answers
  `invalid_grant` instead of returning tokens.
- **Provider responses.** As in `sealed` mode, any successful body is read as JSON whatever its
  content type, a successful body that is not JSON but contains a `refresh_token` (such as a
  form-encoded one) is answered with HTTP 502 `server_error` and never returned, and the claim is
  released. Only a provider 4xx with the JSON error `invalid_grant` revokes the family; every other
  provider error is passed through and leaves the handle usable. Handles (`rrt<N>.`) are never
  forwarded to the provider.
- **Maximum lifetime.** A family ends `maxLifetimeSeconds` after the sign-in that created it,
  however actively it is used. After that a refresh fails with `invalid_grant`.
- **Upstream errors.** A network error or provider error response is returned to the client and
  leaves the handle usable for a retry. A provider `invalid_grant` revokes the family.
- **Switching modes.** A relay changed from `sealed` to `rotating` accepts the `rrt1.` handles it
  issued earlier and replaces them with `rrt2.` handles in a new family, so users stay signed in.
  A sealed handle is stateless and cannot be spent: presenting the same `rrt1.` handle again starts
  another family, until the provider stops honouring its upstream token (a known limitation). A
  sealed handle older than `maxLifetimeSeconds` is rejected with `invalid_grant`. Changed from
  `rotating` back to `sealed`, or to `passthrough`, every `rrt2.` handle is rejected with
  `invalid_grant` and users sign in again. Raw upstream tokens are rejected in both modes.
- **A store is required.** A `rotating` relay needs a transient store shared by every serving
  instance: use `OAUTHRELAY_STORE=dynamodb` (or `kubernetes`, for moderate refresh volumes inside a
  cluster) for more than one replica, and `dynamodb` for any Lambda deployment. With
  the default in-process `memory` store a handle only works on the instance that issued it and
  stops working when that process restarts. An embedding that supplies no store gets a logged
  HTTP 500 `server_error` from authorize and from both grants of a `rotating` relay.
- If the store is unreachable, refresh grants fail closed with HTTP 503 `server_error`.

Rotation settings are rejected on a relay that is not `rotating`.

## Client authentication

`spec.clientAuthentication` selects how a relying party authenticates to the relay token endpoint.

`UpstreamClient` and `ClientSecret` accept the client ID and secret in either of the two forms of
[RFC 6749 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1), and a request
must use exactly one:

- Form fields `client_id` and `client_secret` in the request body.
- An `Authorization: Basic` header carrying `base64(urlencode(client_id):urlencode(client_secret))`,
  where each credential is form-urlencoded (`application/x-www-form-urlencoded`) before the two are
  joined with `:`. Characters such as `:`, `+`, `%`, or non-ASCII must therefore be percent-encoded.
  This is the default of many OIDC clients, such as Dex's OIDC connector. A `client_id` form field
  that repeats the header's identifies the client and is allowed.

A request that carries the header and a `client_secret`, a client assertion, or a different
`client_id` in the body is rejected with `400 invalid_request`. A `Basic` header that is not valid
credentials, or several `Authorization` headers, are rejected with `401 invalid_client`; so are wrong
credentials. Both `401` answers to a header carry `WWW-Authenticate: Basic realm="oauthrelay"`, while
failures of body credentials do not. An `Authorization` header of another scheme, such as a gateway's
`Bearer` or SigV4 header, is not a client credential: the body credentials are used as usual.

`Public` takes no secret in either form, so a `client_secret` or a Basic header with a non-empty
secret is `401 invalid_client`. A Basic header with an empty secret (`base64(client_id:)`, which some
clients send for public clients) only identifies the client, like a body `client_id`; a body
`client_id` that differs from the header's is rejected. `PrivateKeyJwt` authenticates with its
assertion alone and ignores the `Authorization` header.

The token endpoint's CORS policy allows only the `Content-Type` request header, so browser relying
parties cannot send `Authorization: Basic`; they are `Public` clients.

The relay's metadata advertises the accepted methods in `token_endpoint_auth_methods_supported`:
`client_secret_basic` and `client_secret_post` for `UpstreamClient` and `ClientSecret`, `none` for
`Public`, and `private_key_jwt`, with the accepted assertion algorithms in
`token_endpoint_auth_signing_alg_values_supported`, for `PrivateKeyJwt` (see
[Transparent metadata](/oauthrelay/reference/http-endpoints/#transparent-metadata)).

### UpstreamClient

The relying party presents the referenced upstream's client ID and secret. This is useful when a
manually configured relying party, such as Cognito, already stores those credentials.

```yaml
clientAuthentication:
  type: UpstreamClient
```

### Public

Client authentication credentials are not accepted: a `client_secret`, a client assertion, or an
`Authorization: Basic` header is answered with `401 invalid_client`. `client_id`, when present, is a
public identifier rather than a credential. Every authorization-code flow must use S256 PKCE, and
the relay must use [rotating refresh tokens](#rotating-refresh-tokens):

```yaml
refreshTokens:
  mode: rotating
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

The relying party sends a signed JWT in `client_assertion`, with
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and
`client_id` equal to the configured `clientId`. The assertion's `iss` and `sub` must match
`issuer` and `subject`, each defaulting to `clientId`. Matching is exact, including trailing
slashes. The `aud` claim must equal `audience` as a string, or contain it as an array element.
`audience` is an optional non-empty string, defaulting to the relay token endpoint URL. An explicit
value replaces that default; it does not add an alternative accepted audience.
A valid signature and `exp` are required. When present, `iat` and `nbf` must be numeric timestamps
no later than the current time, allowing 60 seconds of clock skew for time checks.

`requireSingleUse` defaults to `false`, allowing projected Kubernetes service-account tokens
and other workload JWTs to be reused until expiry. Clients that sign a fresh assertion for each
request can set `requireSingleUse: true`. This requires an integer `iat`, a non-empty string `jti`,
and `exp` greater than `iat` by at most 300 seconds. Every request, including retries, needs a
fresh `jti`. Replay identity is scoped to the configured issuer, subject, and audience; key rotation
does not reset it. Assertions are recorded only after validation and retained through expiration
plus clock skew. A missing or failing [transient store](/oauthrelay/reference/transient-store/)
rejects authentication.

The standalone server's default transient store is in memory: protection covers one process
lifetime. Multiple replicas, Lambda instances, and restarts need `OAUTHRELAY_STORE=dynamodb` or
`kubernetes` (or an embedded deployment supplying a shared durable `TransientStore`) to enforce
single use across them.
`requireSingleUse` authenticates the request; it does not sender-constrain upstream access tokens.

Configure `jwksUrl` (an absolute HTTP(S) URL), `jwks` (an inline public JWKS object with a
non-empty `keys` array), or `issuer` for OIDC discovery. `jwks` and `jwksUrl` are mutually
exclusive. An explicit key source can accompany `issuer`; it takes precedence over discovery.
Without either key source, oauthrelay fetches `{issuer}/.well-known/openid-configuration`,
requires its `issuer` to match exactly, and uses its `jwks_uri`. Discovery uses only the configured
issuer. Issuer and discovered JWKS URLs require HTTPS, with HTTP permitted on IP loopback for
local development; user information, queries, and fragments are forbidden. Discovery and JWKS
requests reject redirects and have a ten-second deadline. They use a separate HTTP client and
cache from upstream requests. Metadata is cached for one hour and keys for ten minutes.
An unknown `kid` triggers a JWKS refresh; concurrent requests share one fetch. Forced refreshes
and failed fetch retries have a thirty-second cooldown per URL. A failed refresh preserves
previously fetched keys until their normal cache expiry.

Rust embedders configure trust-fetch TLS roots through
`ClientAssertionHttpClient::new(reqwest::ClientBuilder)` and supply the result as
`RelayConfig.client_assertion_http`. Its constructor enforces the redirect policy and deadline.
The `RelayConfig.http` client controls upstream traffic independently.

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

### Kubernetes service-account authentication

A workload can authenticate using a projected service-account token:

```yaml
clientAuthentication:
  type: PrivateKeyJwt
  clientId: worker
  issuer: https://cluster-issuer.example.com
  subject: system:serviceaccount:workloads:worker
```

Set `issuer` to the exact `iss` of your cluster's tokens. The subject selects both the namespace
and the service account. `clientId` remains the OAuth client ID sent by the application.
This is workload federation using the client-assertion transport; configuring a subject different
from `clientId` extends the [RFC 7523 client authentication profile](https://www.rfc-editor.org/rfc/rfc7523.html#section-3),
which requires the subject to be the client ID.

The issuer's discovery and JWKS endpoints must be reachable by oauthrelay without HTTP credentials,
with certificates trusted by its HTTP client. Enabling the Kubernetes configuration provider does
not attach its API credentials or cluster CA to these requests. For a private Kubernetes API,
you can configure `issuer` with explicit inline `jwks` obtained by an administrator using
`kubectl get --raw /openid/v1/jwks`; keep those public keys current when the cluster rotates them.
See [Kubernetes issuer discovery](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#service-account-issuer-discovery)
for publishing discovery and public keys to relying parties.

Project a token with the **configured audience**, defaulting to the relay token endpoint URL.
For a relay named `worker`
served at `https://relay.example.com`, the workload Pod spec includes:

```yaml
serviceAccountName: worker
containers:
  - name: worker
    image: your-worker-image
    volumeMounts:
      - name: oauthrelay-token
        mountPath: /var/run/secrets/oauthrelay
        readOnly: true
volumes:
  - name: oauthrelay-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: https://relay.example.com/relay/worker/token
            expirationSeconds: 3600
```

To use a custom audience, add it to the relay authentication configuration and set the projected
`serviceAccountToken.audience` to the same value:

```yaml
clientAuthentication:
  type: PrivateKeyJwt
  clientId: worker
  issuer: https://cluster-issuer.example.com
  subject: system:serviceaccount:workloads:worker
  audience: api://oauthrelay
```

Create the `worker` ServiceAccount and Pod in namespace `workloads`. Read the token file on each
request so the application picks up kubelet rotation. For example, a refresh request uses:

```sh
curl --fail-with-body https://relay.example.com/relay/worker/token \
  --data-urlencode grant_type=refresh_token \
  --data-urlencode client_id=worker \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode client_assertion@/var/run/secrets/oauthrelay/token \
  --data-urlencode refresh_token@/path/to/upstream-refresh-token
```

This authenticates the existing authorization-code and refresh-token flows; it does not create
a client-credentials grant. Tokens without the configured audience are rejected.
Matching projected tokens may be reused until expiry. Verification checks the JWT
offline and does not perform TokenReview or check whether a bound Pod or ServiceAccount still
exists. Deleting those objects does not immediately revoke a token at oauthrelay.

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
