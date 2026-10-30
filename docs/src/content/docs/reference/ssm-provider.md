---
title: AWS SSM provider
description: Load oauthrelay resources from SSM Parameter Store and resolve AWS-managed secrets.
---

The AWS SSM provider discovers complete resource documents under fixed Parameter Store paths. It
uses the standard inline, environment, file, SSM `SecureString`, and Secrets Manager
`SecretString` resolution shared by every resource provider.

## Enable the provider

```console
export OAUTHRELAY_PROVIDER_SSM_PREFIX=/oauthrelay/
export OAUTHRELAY_PROVIDER_SSM_POLL=60s
```

The prefix must start and end with `/`. AWS region, credentials, and endpoint selection follow the
standard AWS SDK provider chain. The poll interval defaults to `60s`.

## Resource parameters

The provider enumerates these subpaths independently:

```text
/oauthrelay/upstreams/{name}
/oauthrelay/relays/{name}
```

Each parameter uses the SSM `String` type and contains one complete YAML or JSON resource document.
The path kind and name must match `kind` and `metadata.name` in the document. Names occupy exactly
one path segment.

For example, store the first document at `/oauthrelay/upstreams/google` and the second at
`/oauthrelay/relays/cognito-google`:

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
        awsSsmParameter:
          name: /oauthrelay/secrets/google-client-secret
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
  clientAuthentication:
    type: UpstreamClient
  redirectPolicy:
    - uri: https://pool.auth.eu-west-1.amazoncognito.com/oauth2/idpresponse
```

## SSM secret reference

An SSM reference names an absolute parameter. The referenced parameter must use `SecureString`:

```yaml
clientSecret:
  valueFrom:
    awsSsmParameter:
      name: /oauthrelay/secrets/google-client-secret
```

Resource discovery does not enumerate the secrets subtree; each secret is fetched by its exact
name with decryption enabled.

## Secrets Manager reference

`secretId` accepts either a secret name or a full Secrets Manager ARN and is passed unchanged to
`GetSecretValue`. A name resolves in the configured AWS account and region. Use a full ARN for a
cross-account secret or when the configuration should identify one exact secret; avoid partial
ARNs.

Without `jsonKey`, the complete `SecretString` is the client secret:

```yaml
clientSecret:
  valueFrom:
    awsSecretsManager:
      secretId: oauthrelay/google
```

With `jsonKey`, the `SecretString` must contain a JSON object and the selected top-level field must
be a string:

```yaml
clientSecret:
  valueFrom:
    awsSecretsManager:
      secretId: oauthrelay/google
      jsonKey: clientSecret
```

Nested JSON paths, missing fields, non-string selected values, and binary secrets are rejected.

## Local secret sources

SSM resource documents use the same inline, environment, and file resolution as File provider
documents:

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
      path: /run/secrets/google-client-secret
```

An SSM document has no filesystem base directory, so its file paths must be absolute. Environment
and file values have trailing CR/LF characters removed, matching File provider behavior.

## IAM permissions

The runtime role needs permissions equivalent to:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:GetParametersByPath",
      "Resource": [
        "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthrelay/upstreams/*",
        "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthrelay/relays/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:REGION:ACCOUNT:parameter/oauthrelay/secrets/*"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:oauthrelay/*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }
  ]
}
```

Limit each statement to the configured paths, secret IDs, and KMS keys. `kms:Decrypt` is needed
when a customer-managed KMS key protects the referenced SSM or Secrets Manager value.

## Refresh behavior

Native mode builds a complete candidate on each poll. The provider follows SSM pagination,
resolves every referenced secret, validates the complete graph, and publishes it atomically. A
failure retains the last-good snapshot.

SSM reads are not transactional. During a multi-parameter rollout, an inconsistent candidate is
rejected until a later refresh observes a complete valid graph. Lambda performs the same load at
invocation boundaries according to `OAUTHRELAY_LAMBDA_CONFIG_TTL`; see
[Runtime and deployment](/oauthrelay/reference/runtime/).
