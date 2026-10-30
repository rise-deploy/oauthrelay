---
title: Transient store
description: Choose where oauthrelay records single-use state, and provision the DynamoDB table.
---

oauthrelay keeps no database. Authorization codes, flow state, and other envelopes are sealed and
travel with the client. The few facts that must be remembered between requests live in a
**transient store**: a key-value store in which every record carries a TTL and disappears on its
own. Today it holds:

- the ID of each redeemed authorization code, so a code works once (`replay:code:` keys);
- the identity of each `requireSingleUse` client assertion (`replay:client-assertion:` keys).

Select a backend with `OAUTHRELAY_STORE`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OAUTHRELAY_STORE` | `memory` | `memory` or `dynamodb`. |
| `OAUTHRELAY_STORE_DYNAMODB_TABLE` | — | DynamoDB table name. Required with `dynamodb`, rejected otherwise. |

Records are small and short-lived: an authorization code is retained for five minutes, a client
assertion until its expiry plus clock skew.

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
| Capacity | on-demand is a good fit; each token request is one conditional write |
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

- Claims use a conditional `PutItem` that succeeds only when no live item exists, so exactly one
  of any number of concurrent redemptions wins, across every replica and Lambda environment.
- Reads are strongly consistent.
- DynamoDB stores whole seconds. A record is kept for its TTL rounded up to whole seconds plus one
  second: never shorter than requested, at most two seconds longer. Expiry is judged by the
  reading instance's clock, so keep instance clocks synchronized.
- If DynamoDB is unreachable, a token request that needs the store fails closed with HTTP 503
  `server_error` and the authorization code stays unconsumed, so the client can retry. A
  `requireSingleUse` client assertion that cannot be recorded is rejected as an authentication
  failure.

## Embedding the core

`RelayConfig.store` accepts any `Arc<dyn TransientStore>`. Without one, authorization codes are not
tracked and `requireSingleUse` client assertions are rejected. A host that already runs a
database can implement the trait over it:

| Operation | Contract |
| --- | --- |
| `put_if_absent(key, value, ttl)` | Store when no live record exists; return whether it was stored. |
| `get(key)` | The live record and its remaining TTL, strongly consistent. |
| `compare_and_swap(key, expected, new, ttl)` | Replace a live record whose value equals `expected` and restart its TTL; return whether it was replaced. |
| `delete(key)` | Remove a record; absent keys succeed. |

Keys are non-empty and at most 1024 bytes, namespaced by their callers, and TTLs are non-zero.
Every operation on a key must be linearizable across all instances. The `oauthrelay-core` rustdoc
for `TransientStore` has the complete contract, plus the intended record layout for stateful
refresh-token rotation (claim a handle once, record its successor, answer a racing duplicate, and
revoke a token family) built from these four operations.
