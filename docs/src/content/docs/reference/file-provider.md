---
title: File provider
description: Load oauthrelay resources from a YAML document stream.
---

The File provider reads a multi-document YAML stream from one path. It is suitable for native
servers, mounted container configuration, and development environments. Secret values may remain
local or reference AWS Parameter Store and Secrets Manager independently of where the resource
document is stored.

## Enable the provider

```console
export OAUTHRELAY_PROVIDER_FILE=/etc/oauthrelay/config.yaml
export OAUTHRELAY_PROVIDER_FILE_POLL=30s
```

The poll interval must include a unit such as `s` or `m` and must be greater than zero. It defaults
to `30s`.

## Resource file

Put every upstream and relay in the same YAML stream, separated by `---`:

```yaml oauthrelay-config
apiVersion: oauthrelay.dev/v1alpha1
kind: Upstream
metadata:
  name: example
spec:
  issuerUrl: https://issuer.example.com
  oauthClient:
    clientId: example-client
    clientSecret:
      valueFrom:
        file:
          path: ./secrets/provider-client-secret
---
apiVersion: oauthrelay.dev/v1alpha1
kind: Relay
metadata:
  name: example
spec:
  upstreamRef:
    name: example
  scopes:
    default: [openid, email]
  clientAuthentication:
    type: Public
  redirectPolicy:
    - uri: https://app.example.com/oauth/callback
```

Relative secret paths resolve from the resource file's directory. Referenced environment and file
values have trailing CR/LF characters removed, which supports mounted secret files ending in a
newline.

## Secret sources

The File provider accepts these forms:

```yaml
clientSecret:
  value: local-development-secret
```

```yaml
clientSecret:
  valueFrom:
    env:
      name: PROVIDER_CLIENT_SECRET
```

```yaml
clientSecret:
  valueFrom:
    file:
      path: ./secrets/provider-client-secret
```

```yaml
clientSecret:
  valueFrom:
    awsSsmParameter:
      name: /oauthrelay/secrets/provider-client-secret
```

```yaml
clientSecret:
  valueFrom:
    awsSecretsManager:
      secretId: oauthrelay/provider
      jsonKey: clientSecret
```

The File and SSM providers use the same standard resolver. The standalone binary's default `aws`
feature supplies the AWS resolver and standard AWS SDK credential, region, and endpoint chain.
Embeddings inject the resolver with
`FileProvider::with_aws_secrets`. Without an AWS resolver, AWS references reject the candidate
snapshot. The [AWS SSM provider reference](/oauthrelay/reference/ssm-provider/) documents secret
validation and the relevant `GetParameter`, `GetSecretValue`, and KMS permissions; those
requirements also apply when the resource document comes from a file.

## Reload behavior

The complete resource stream and every referenced secret are re-read on each poll, including when
the resource file itself has not changed. A valid candidate replaces the provider snapshot as one
unit. A read, parse, reference, secret, or validation error retains the complete last-good
snapshot.

When both File and SSM providers are enabled, File has precedence for a resource with the same kind
and name. Collisions are logged and do not combine individual fields.

See [Configuration](/oauthrelay/configuration/) for every resource field and validation rule.
