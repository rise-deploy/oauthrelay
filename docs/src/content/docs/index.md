---
title: oauthrelay
description: One stable upstream OAuth callback, safely relayed to an explicit set of applications.
---

oauthrelay multiplexes a provider callback across production, preview, and local application
origins. It owns the authorization transport and callback state while keeping each redirect target
inside an explicit origin policy.

The available transparent relay returns upstream token responses unchanged. The relying party
therefore trusts the upstream issuer and keys even though authorization and token requests pass
through oauthrelay.

An **upstream** represents one provider OAuth client and its stable callback. A **relay** references
that upstream and defines the scopes, downstream authentication, and allowed application origins.
Several relays can share one upstream without creating additional provider callbacks.

## Start here

- [Getting started](/oauthrelay/getting-started/) runs the first File-backed transparent relay.
- [Relay trust model](/oauthrelay/relay-model/) explains the endpoint and token-trust boundaries.
- [Cognito relay to Google](/oauthrelay/guides/cognito-google-relay/) applies one stable Google
  callback to any number of Cognito user pools.
- [Dex in front of oauthrelay](/oauthrelay/guides/dex-in-front/) gives each Dex client its own
  ID-token claim policy through a dedicated relay.

## Reference

- [Configuration](/oauthrelay/configuration/) defines upstreams, relays, authentication, redirect
  policy, scopes, and secret values.
- [File provider](/oauthrelay/reference/file-provider/) and
  [AWS SSM provider](/oauthrelay/reference/ssm-provider/) describe the available configuration
  sources.
- [Runtime and deployment](/oauthrelay/reference/runtime/) covers native, container, and Lambda
  execution.
- [Transient store](/oauthrelay/reference/transient-store/) covers single-use state: the memory,
  DynamoDB, and Kubernetes backends.
- [HTTP endpoints](/oauthrelay/reference/http-endpoints/) describes relay, callback, metadata, and
  health routes.

## Trust model

The upstream provider remains the token issuer and signer. oauthrelay owns the stable callback,
redirect policy, authorization state, and relayed authorization and token endpoints.
