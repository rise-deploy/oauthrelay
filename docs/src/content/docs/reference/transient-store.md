---
title: Transient store
description: Choose where oauthrelay records single-use state, and provision the DynamoDB table or Kubernetes resource.
---

oauthrelay keeps no database. Authorization codes, flow state, and other envelopes are sealed and
travel with the client. The few facts that must be remembered between requests live in a
**transient store**: a key-value store in which every record carries a TTL and disappears on its
own. Today it holds:

- the ID of each redeemed authorization code, so a code works once (`replay:code:` keys);
- the identity of each `requireSingleUse` client assertion (`replay:client-assertion:` keys);
- the state of every [rotating refresh-token](/oauthrelay/configuration/#rotating-refresh-tokens)
  family (`refresh:` keys), for relays with `refreshTokens.mode: rotating`.

Select a backend with `OAUTHRELAY_STORE`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OAUTHRELAY_STORE` | `memory` | `memory`, `dynamodb`, or `kubernetes`. `kubernetes` is rejected at startup on AWS Lambda. |
| `OAUTHRELAY_STORE_DYNAMODB_TABLE` | — | DynamoDB table name. Required with `dynamodb`, rejected otherwise. |
| `OAUTHRELAY_STORE_KUBERNETES_RESOURCE` | `transientrecords.oauthrelay.dev` | Resource that holds the records: oauthrelay's own, or `authcodes.dex.coreos.com` (see [Using Dex's AuthCode resource](#using-dexs-authcode-resource)). Only valid with `kubernetes`. |
| `OAUTHRELAY_STORE_KUBERNETES_NAMESPACE` | see [Kubernetes](#kubernetes) | Namespace that holds the records. Only valid with `kubernetes`. |
| `OAUTHRELAY_STORE_KUBERNETES_SWEEP` | `60s` | How often expired records are deleted, or `off`. Only valid with `kubernetes`. |

Settings for a backend that is not selected are rejected at startup rather than ignored.

Replay records are small and short-lived: an authorization code is retained for five minutes, a
client assertion until its expiry plus clock skew. Refresh-token records live as long as the
family, 30 days by default; see [Key namespaces](#key-namespaces).

## Key namespaces

Keys are namespaced by purpose. A backend never interprets them, and a table can be inspected by
prefix.

| Key | Written by | Value | Lives for |
| --- | --- | --- | --- |
| `replay:code:{id}` | code grant | `1` | five minutes |
| `replay:client-assertion:{digest}` | `requireSingleUse` assertions | `1` | assertion expiry plus skew |
| `refresh:handle:{hash}` | `rotating` relays | The handle's record, sealed: `Active`, `Claimed`, or a `Rotated` tombstone | until the family's maximum lifetime |
| `refresh:grace:{hash}` | `rotating` relays | The response of one rotation, sealed | grace period plus ten seconds |
| `refresh:revoked:{hash}` | `rotating` relays | `1`, present when the family is revoked | until the family's maximum lifetime |
| `refresh:head:{hash}` | `rotating` relays | The store key of the family's newest handle record (a hash, not secret) | until the family's maximum lifetime |

The `{hash}` in `refresh:` keys is a SHA-256 over the relay name and the handle or family ID, so the
store cannot be used to recover a handle. Values are sealed with `OAUTHRELAY_SEAL_KEY` and bound
to the relay, the purpose, and the key, so the store never holds a plaintext upstream token or
access token and a value cannot be copied to another key. Changing the seal key without keeping the
old one as `OAUTHRELAY_SEAL_KEY_PREVIOUS` makes the stored records unreadable: those refreshes fail with
`invalid_grant` and the users sign in again.

A rotating relay needs this store shared by every instance. With `memory`, a handle only works on
the instance that issued it and is lost when that process restarts.

## Memory

The default. Records live in the process, so protection covers one native server process or one
warm Lambda execution environment and is lost on restart. Two replicas, or two concurrent Lambda
environments, can each redeem the same code once. Use it for a single native instance or for local
development.

Lambda starts a new execution environment whenever it scales out, so **use DynamoDB for Lambda**
deployments that need a code to be single-use. oauthrelay logs a warning at startup when it runs
on Lambda with the memory store.

## DynamoDB

`OAUTHRELAY_STORE=dynamodb` requires the `aws` build feature, which the default build includes.
Region, credentials, and endpoint follow the standard AWS SDK provider chain.

```console
export OAUTHRELAY_STORE=dynamodb
export OAUTHRELAY_STORE_DYNAMODB_TABLE=oauthrelay-store
```

### Table

| Setting | Value |
| --- | --- |
| Partition key | `pk`, type String |
| Sort key | none |
| Capacity | on-demand is a good fit; see [Sizing for rotating refresh tokens](#sizing-for-rotating-refresh-tokens) |
| Time to Live attribute | `expires_at` |

oauthrelay writes three attributes: `pk` (the store key), `value` (Binary), and `expires_at`
(Number, Unix epoch seconds). For example:

```console
aws dynamodb create-table \
  --table-name oauthrelay-store \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

aws dynamodb update-time-to-live \
  --table-name oauthrelay-store \
  --time-to-live-specification Enabled=true,AttributeName=expires_at
```

Enabling TTL is for storage hygiene only. DynamoDB deletes expired items lazily, often many hours
after expiry, so oauthrelay checks `expires_at` itself: an expired item is treated as absent when
read and may be overwritten by a new claim. Correctness does not depend on TTL deletion.

### Sizing for rotating refresh tokens

Replay protection costs one conditional write per code grant or single-use assertion. Rotating
refresh tokens cost more, because each refresh is a small transaction in the store:

| Per refresh grant | Operations |
| --- | --- |
| Rotation | 2 strongly consistent reads (handle, revoked marker) and 5 writes: claim, response, successor, the final tombstone swap, and the head pointer |
| Duplicate within the grace period | 3 reads, no writes |

Write capacity depends on item size, charged in 1 KB units. Plan on 1 to 3 units for the record
writes (an upstream refresh token sealed is roughly 0.2 to 2 KB; the tombstone is about 0.3 KB) and
1 to 7 for the response write, whose size is that of your provider's token response, base64-encoded
(a response with an ID token is typically 1 to 4 KB). A typical refresh therefore costs about 6 to
13 write units and 2 read units. Active sessions refresh about once per access-token lifetime, so
multiply by sessions and by one refresh per hour for a provider with one-hour access tokens.

Storage is dominated by tombstones. Each rotation leaves one, about 0.3 KB, which has to stay until
the family ends so a replay can be recognised. A session that refreshes hourly leaves roughly 720
of them over the default 30-day family (about 220 KB). Shorten `maxLifetimeSeconds` to bound this,
and keep Time to Live enabled so expired items are eventually reclaimed. Response records last only
seconds and add no lasting storage.

Raising `gracePeriodSeconds` does not change the cost of a rotation, but it lengthens the window in
which a stolen, already-used handle can still fetch the recorded response.

The table can be shared by several oauthrelay deployments only if their keys cannot collide; give
each deployment its own table otherwise.

### IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:GetItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:REGION:ACCOUNT:table/oauthrelay-store"
    }
  ]
}
```

`kms:Decrypt` and `kms:GenerateDataKey` on the key are needed in addition when the table uses a
customer-managed KMS key.

### Behavior

- Claims use a conditional `PutItem` that succeeds only when no live item exists (or, for rotation,
  when the item still holds exactly the value that was read), so exactly one of any number of
  concurrent redemptions or refreshes wins, across every replica and Lambda environment.
- Reads are strongly consistent.
- A conditional write asks DynamoDB to return the existing item when its condition fails
  (`ReturnValuesOnConditionCheckFailure=ALL_OLD`). The AWS SDK retries a request whose response was
  lost, and such a retry can report `ConditionalCheckFailed` for a write that had already applied.
  When the returned item still holds exactly the value being written, the write is treated as
  successful. This relies on callers writing values that are unique to the writer, which
  oauthrelay does (every record value is sealed with a random nonce); a custom caller that writes
  the same bytes from several writers loses that exactness.
- DynamoDB stores whole seconds. A record is kept for its TTL rounded up to whole seconds plus one
  second: never shorter than requested, at most two seconds longer. Expiry is judged by the
  reading instance's clock, so keep instance clocks synchronized.
- If DynamoDB is unreachable, a token request that needs the store fails closed with HTTP 503
  `server_error` and the authorization code stays unconsumed, so the client can retry. A
  `requireSingleUse` client assertion that cannot be recorded is rejected as an authentication
  failure.

## Kubernetes

`OAUTHRELAY_STORE=kubernetes` keeps every record as a namespaced custom resource, so an oauthrelay
deployment inside a cluster can run several replicas without DynamoDB. It needs the `kubernetes`
build feature, which the default build includes, and works with any configuration provider. It is
never implied by `OAUTHRELAY_PROVIDER_KUBERNETES=true`: selecting it also means granting the RBAC
below, so you choose it explicitly.

It does not run on AWS Lambda. Lambda freezes the process between invocations, so no background
sweeper would ever delete an expired record, and oauthrelay refuses to start with
`OAUTHRELAY_STORE=kubernetes` there, even when `OAUTHRELAY_STORE_KUBERNETES_SWEEP` is set. Use
[DynamoDB](#dynamodb), whose TTL deletes expired items.

```console
export OAUTHRELAY_STORE=kubernetes
```

oauthrelay authenticates like the [Kubernetes provider](/oauthrelay/reference/kubernetes-provider/#namespace-and-credentials):
with its service account in a pod, otherwise with the active kubeconfig. Records live in one
namespace, chosen in this order: `OAUTHRELAY_STORE_KUBERNETES_NAMESPACE`, the provider namespace
(`OAUTHRELAY_PROVIDER_KUBERNETES_NAMESPACE`, when the Kubernetes provider is enabled), then the
pod or kubeconfig namespace. At startup oauthrelay lists the resource once, then asks the API
server (a `SelfSubjectAccessReview` per verb) whether the credentials may `get`, `list`, `create`,
`update`, and `delete` it in that namespace. It refuses to start, with the resource and namespace
in the message, if the resource is not served, if a verb is missing (the message names the missing
verbs), or if the access review itself fails. A Role without `create`, `update`, or `delete` is
therefore reported when the pod starts, not on the first token request.

### Install the CRD and grant access

`oauthrelay crds` prints the `TransientRecord` definition together with the provider's. The
[generated bundle](https://github.com/rise-deploy/oauthrelay/blob/develop/deploy/oauthrelay.crds.yaml)
installs both:

```sh
kubectl apply --server-side -f oauthrelay.crds.yaml
kubectl wait --for=condition=Established --timeout=60s crd/transientrecords.oauthrelay.dev
```

The service account needs these verbs in the records' namespace. The Role in the
[deployment example](https://github.com/rise-deploy/oauthrelay/blob/develop/deploy/kubernetes.yaml)
already includes the rule.

```yaml
rules:
  - apiGroups: [oauthrelay.dev]
    resources: [transientrecords]
    verbs: [get, list, create, update, delete]
```

Grant that only to oauthrelay. Anyone who can delete or edit `TransientRecord` objects can make a
used authorization code usable again or un-revoke a refresh-token family, so the namespace's write
access is as sensitive as the store itself. Reading is far less sensitive: values are sealed with
`OAUTHRELAY_SEAL_KEY` and bound to their key, and keys hold hashes and random identifiers.

### Records

Each record is one `TransientRecord` (`oauthrelay.dev/v1alpha1`):

| Field | Meaning |
| --- | --- |
| `metadata.name` | `oauthrelay-` plus the lowercase base32 of the key's SHA-256: 63 characters, a valid name for any key. |
| `metadata.labels` | `app.kubernetes.io/managed-by: oauthrelay`; `oauthrelay.dev/purpose` with the key's first segment (`replay`, `refresh`); and `oauthrelay.dev/expires-hour`, the unix hour of the expiry (integer hours since the epoch, for example `"498921"`), which every write sets again because a write restarts the TTL. The sweeper selects on it. |
| `spec.key` | The store key, for inspection. |
| `spec.value` | The value, base64. |
| `spec.expiresAt` | Expiry, RFC 3339 with millisecond precision. |

```console
$ kubectl -n oauthrelay get transientrecords -l oauthrelay.dev/purpose=refresh
NAME                                                              EXPIRES
oauthrelay-ic2idwnc3abyaqmxw55xhuecxwilgrg5uvwduxthintqsmw723da   2026-12-01T09:30:12.481Z
```

### Expiry and the sweeper

Kubernetes has no server-side TTL, and correctness never depends on deletion: reads compare
`spec.expiresAt` with the clock, and a write treats an expired record as absent and takes it over.
Deleting expired records only keeps etcd small. Every replica runs a sweeper for that, by default
every 60 seconds (`OAUTHRELAY_STORE_KUBERNETES_SWEEP`; `off` disables it, for example when
another job cleans up).

A sweeper that listed every record each time would not scale: records such as rotation tombstones
live for the whole refresh family, so there can be hundreds of thousands (see
[sizing](#rotating-refresh-tokens-and-sizing)). Instead each sweeper lists only records that can
have expired, using the `oauthrelay.dev/expires-hour` label:

- **At start**, a sweeper does one full pass over every record oauthrelay wrote (selector
  `app.kubernetes.io/managed-by=oauthrelay`, 500 per page). That also covers records written before
  the label existed.
- **Each later sweep** lists `app.kubernetes.io/managed-by=oauthrelay,oauthrelay.dev/expires-hour in (...)`
  for the hours from a watermark, which the sweeper keeps in memory, up to the hour of the current
  time minus the grace below (twenty hours per request, 500 records per page). Normally that is
  the current hour. It deletes each expired record with a `resourceVersion` precondition, so a
  record that another replica renewed between the list and the delete is kept, and then advances
  the watermark past every hour that is entirely in the past. A sweep that fails leaves the
  watermark where it was.
- **Every 24 hours** it repeats the full pass as a backstop, for records the hours missed: those
  written by a replica whose clock ran far behind, or without the label.

Replicas sweeping at once is harmless: deletes are idempotent. **Grace:** a sweeper deletes only
records that expired more than 30 seconds ago. Reads and writes judge expiry exactly, so a
replica whose clock runs fast cannot delete a record that its peers still treat as live; the
price is that expired records stay in etcd 30 seconds longer.

The remaining cost is one full pass per replica at every start and every 24 hours, and then, per
sweep, a list bounded by the records that expire in the current hour (the ones that have not
expired yet are listed again on every sweep of that hour; with the default interval, about sixty
times). Long-lived records are listed again only in the hour they expire, so the number of
objects in etcd no longer sets the cost of a sweep. API load still scales with the number of
replicas, since each runs a sweeper; to reduce it, raise `OAUTHRELAY_STORE_KUBERNETES_SWEEP`.
Start replicas gradually when the namespace holds many records, so their full passes do not
coincide.

### Using Dex's AuthCode resource

`OAUTHRELAY_STORE_KUBERNETES_RESOURCE=authcodes.dex.coreos.com` keeps the same records as Dex
`AuthCode` objects instead, for a deployment that runs Dex with its Kubernetes storage and does
not want another CRD. It is opt-in, and `TransientRecord` stays the recommended mapping:

```console
export OAUTHRELAY_STORE=kubernetes
export OAUTHRELAY_STORE_KUBERNETES_RESOURCE=authcodes.dex.coreos.com
export OAUTHRELAY_STORE_KUBERNETES_NAMESPACE=dex   # Dex's namespace
```

Dex installs `authcodes.dex.coreos.com` when it starts, so there is no CRD to apply; start
oauthrelay after Dex (the startup check fails, and the pod restarts, until the resource exists).
Everything except the object layout is identical to the default mapping: naming, expiry, the
`resourceVersion` compare-and-swap, and the sweeper.

| `AuthCode` field | Value |
| --- | --- |
| `metadata.name`, `metadata.labels` | As for `TransientRecord`. Dex names its own codes in lowercase base32 without hyphens, so the names never collide. |
| `connectorData` | The value, base64 (Dex's `[]byte` encoding). |
| `expiry` | Expiry, RFC 3339 with millisecond precision. |
| `connectorID` | `oauthrelay`. The store key is not stored: `AuthCode` has no field for it. |
| `clientID`, `redirectURI` | `oauthrelay:transient-record` and `urn:oauthrelay:transient-record`. |
| `code_challenge`, `code_challenge_method` | 43 random base64url characters and `S256`. |
| `claims`, `scopes` | Absent. |

**Trust.** The service account needs `get`, `list`, `create`, `update`, and `delete` on `authcodes`
in Dex's namespace, and Kubernetes RBAC cannot narrow that to the objects oauthrelay wrote. The
same grant lets oauthrelay read Dex's own live authorization codes, which carry the user's claims
and `connectorData` (for some connectors, upstream tokens), and delete or forge them. Oauthrelay
itself only lists objects labelled `app.kubernetes.io/managed-by=oauthrelay`, but the permission
is wider than the code. Use this mapping only when Dex and oauthrelay run as one trust domain;
otherwise use `TransientRecord`, whose Role is confined to oauthrelay's own records. The Role in
the [deployment example](https://github.com/rise-deploy/oauthrelay/blob/develop/deploy/kubernetes.yaml)
carries the rule commented out, and it belongs in Dex's namespace:

```yaml
rules:
  - apiGroups: [dex.coreos.com]
    resources: [authcodes]
    verbs: [get, list, create, update, delete]
```

**Why Dex cannot be tricked into using these objects.** Dex's token endpoint rejects an
authorization code whose `clientID` is not the authenticating client's, and `oauthrelay:transient-record`
is never a registered client. An object whose name was learned would also fail the PKCE check,
because its `code_challenge` is random and no code verifier hashes to it, and it has no claims to
issue tokens for. This is the reason the mapping is safe to use at all; it relies on no Dex client
being configured with that ID.

**Dex's garbage collector is not a TTL.** Dex deletes expired `AuthCode` objects every five
minutes by default, at most 500 objects per run, shared with its own codes. A relay with rotating
refresh tokens leaves one small object per refresh until its family ends, so at volume Dex's
collector falls behind and etcd fills. That is why the oauthrelay sweeper is on by default for
this mapping too, and why the savings of this mapping are limited to the CRD install and the extra
API group in RBAC. Dex's collector and oauthrelay's sweeper may delete the same object; either
way an expired record is already absent to oauthrelay.

### Rotating refresh tokens and sizing

The Kubernetes store suits moderate refresh traffic. Every operation is a request to the API
server and every record an object in etcd, which the cluster shares with everything else it runs.

| Per refresh grant | Operations |
| --- | --- |
| Rotation | 5 reads and 5 writes (see below) |
| Duplicate within the grace period | 3 reads, no writes |

A rotation reads the handle and the revoked marker (2 `GET`s), then makes five conditional writes.
Three of them are `compare_and_swap` calls (claim, tombstone swap, head pointer), each of which is
a `GET` followed by a `PUT`; the other two are creates (response, successor), each a `POST`. That
is 5 `GET`s and 5 writes, about ten sequential API requests at a few milliseconds each on a
healthy cluster, in addition to the upstream refresh. A duplicate reads the handle, the revoked
marker, and the recorded response.

Each rotation leaves a tombstone object until the family ends, so a session that refreshes hourly
leaves about 720 of them over the default 30-day family. An object weighs roughly 1 to 2 KB in
etcd including its metadata, so 1,000 such sessions hold about 720,000 objects, on the order of a
gigabyte. Set a shorter `maxLifetimeSeconds` on relays that use this backend (seven days cuts the
figure to about 170 per session), and use [DynamoDB](#dynamodb) when refresh volumes are high.

### Consistency and failures

- A record is created with `POST`, and exactly one concurrent creator succeeds. A replacement is
  a `PUT` that carries the `resourceVersion` that was read, and Kubernetes rejects it with 409 if
  the object changed in between, so `compare_and_swap` and the takeover of an expired record each
  succeed for exactly one of any set of concurrent callers across all replicas.
- Reads are quorum reads: a `GET` without a `resourceVersion` is served from etcd's current state.
- A 409 can also be what a write reports when its response was lost and the request was retried.
  When the record read back is live and holds exactly the value the call wrote, the write is
  treated as successful. This relies on callers writing values that are unique to the writer,
  which oauthrelay does (see [DynamoDB behavior](#behavior)).
- Records keep millisecond precision. Expiry is judged by the reading instance's clock, so keep
  instance clocks synchronized.
- Every store operation, with all the API requests it makes, has 10 seconds in total. When the
  API server is slower than that, the operation fails with an error whose outcome is unknown,
  like a lost response, instead of stalling the token request. The deadline is well inside the
  60-second claim lease of a refresh-token rotation, so a caller stuck on the store cannot hold
  a claim past its lease and be overtaken. oauthrelay turns off the Kubernetes client library's
  own retry of 429, 503, and 504 responses for this client, which would otherwise keep retrying
  for minutes and honour `Retry-After`; such a response fails the operation at once. The deadline
  is not configurable.
- A missing resource type (for example a CRD removed while oauthrelay runs) is an error, not an
  absent record: only the API server's "object not found" answer, which names the object, reads
  as absence.
- If the API server is unreachable, slow, or denies a request, a token request that needs the store
  fails closed with HTTP 503 `server_error` and the authorization code stays unconsumed, exactly
  as with DynamoDB.

## Embedding the core

`RelayConfig.store` accepts any `Arc<dyn TransientStore>`. Without one, authorization codes are not
tracked, `requireSingleUse` client assertions are rejected, and relays in `rotating` refresh-token
mode fail with a `server_error`. A host that already runs a
database can implement the trait over it:

| Operation | Contract |
| --- | --- |
| `put_if_absent(key, value, ttl)` | Store when no live record exists; return whether it was stored. |
| `get(key)` | The live record and its remaining TTL, strongly consistent. |
| `compare_and_swap(key, expected, new, ttl)` | Replace a live record whose value equals `expected` and restart its TTL; return whether it was replaced. |
| `delete(key)` | Remove a record; absent keys succeed. |

Keys are non-empty and at most 1024 bytes, namespaced by their callers, and TTLs are non-zero.
Every operation on a key must be linearizable across all instances. The `oauthrelay-core` rustdoc
for `TransientStore` has the complete contract, plus the rotation protocol built from these four
operations (claim a handle once, record its successor, answer a racing duplicate, release a failed
claim, and revoke a token family).
