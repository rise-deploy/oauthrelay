---
title: Transient store
description: Choose where oauthrelay records single-use state, and provision the DynamoDB table.
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
| `OAUTHRELAY_STORE` | `memory` | `memory` or `dynamodb`. |
| `OAUTHRELAY_STORE_DYNAMODB_TABLE` | — | DynamoDB table name. Required with `dynamodb`, rejected otherwise. |

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
| Rotation | 2 strongly consistent reads (handle, revoked marker) and 4 writes: claim, response, successor, and the final tombstone swap |
| Duplicate within the grace period | 3 reads, no writes |

Write capacity depends on item size, charged in 1 KB units. Plan on 1 to 3 units for the record
writes (an upstream refresh token sealed is roughly 0.2 to 2 KB; the tombstone is about 0.2 KB) and
1 to 7 for the response write, whose size is that of your provider's token response, base64-encoded
(a response with an ID token is typically 1 to 4 KB). A typical refresh therefore costs about 5 to
12 write units and 2 read units. Active sessions refresh about once per access-token lifetime, so
multiply by sessions and by one refresh per hour for a provider with one-hour access tokens.

Storage is dominated by tombstones. Each rotation leaves one, about 0.2 KB, which has to stay until
the family ends so a replay can be recognised. A session that refreshes hourly leaves roughly 720
of them over the default 30-day family (about 150 KB). Shorten `maxLifetimeSeconds` to bound this,
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
