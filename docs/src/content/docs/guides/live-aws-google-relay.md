---
title: Verify a Google relay on AWS Lambda
description: Exercise a published oauthrelay image through a real Google authorization flow.
sidebar:
  order: 2
---

The live verification script deploys an isolated oauthrelay relay to AWS Lambda, completes a Google
authorization-code flow through it, and removes the AWS resources. It proves that the published
container, Lambda runtime, SSM provider, Secrets Manager resolution, public URL base path, relay
discovery, redirect policy, PKCE exchange, Google ID token, and UserInfo request work together.

This is an interactive release or integration check. The local test suite remains the fast,
repeatable quality gate and does not need cloud credentials.

## Prerequisites

You need:

- Docker with Buildx;
- AWS credentials allowed to manage run-scoped ECR, Lambda, IAM, SSM Parameter Store, Secrets
  Manager, and CloudWatch Logs resources;
- a Google OAuth 2.0 **Web application** client whose redirect URI you can edit; and
- a published multi-architecture oauthrelay image.

The repository's mise configuration supplies Node.js, the AWS CLI, and the Docker CLI. A running
Docker engine and authenticated AWS CLI credentials remain host responsibilities.

## Run the verification

From the repository root, run:

```console
mise run e2e:aws-google -- --google-client-id 123456789.apps.googleusercontent.com --region eu-west-1
```

The script reads the Google client secret from a hidden prompt. For automation, set
`GOOGLE_CLIENT_SECRET` or pass `--google-client-secret-file PATH`; a secret value is deliberately
not accepted as a command-line argument.

By default, the script derives
`ghcr.io/rise-deploy/oauthrelay:sha-<7-character-HEAD>` and verifies that its OCI index contains a
Linux ARM64 image before creating AWS resources. Use `--image` to test another published tag or
`--architecture amd64` for an x86-64 Lambda.

After deployment, the script prints a callback such as:

```text
https://abcde.lambda-url.eu-west-1.on.aws/oidc/upstream/google/callback
```

Add that exact URI to the Google web client and press Enter. The script opens an authorization URL
and listens on a random local loopback port for the result. `--no-open` prints the URL without
launching a browser.

The checks confirm that the relay rejects an unconfigured redirect, advertises Google's issuer and
JWKS while publishing oauthrelay authorization and token endpoints, completes S256 PKCE, validates
the Google-signed ID token, and obtains matching UserInfo. Remove the generated callback from the
Google client when the script tells you to do so.

## Resources and cleanup

Each run has a unique `oauthrelay-e2e-<run-id>` namespace. The script creates:

- a temporary private ECR repository containing the selected single-architecture image;
- a Secrets Manager secret for the Google client secret;
- one SSM `Upstream` and one public `Relay` resource;
- a least-privilege Lambda execution role;
- a Lambda function and unauthenticated Function URL; and
- the function's CloudWatch log group when Lambda emits logs.

The Function URL is intentionally public for the duration of this test. oauthrelay is served below
its `/oidc` public base, while `/readyz` remains at the Function URL root. The run-scoped SSM
configuration refresh TTL is `60s`.

The script attempts to remove AWS resources after success, failure, or interruption. Cleanup cannot
edit the Google client, so remove the printed redirect URI there yourself. `--keep` retains AWS
resources for inspection and prints an exact cleanup command. A retained or partially cleaned run
can be removed later with:

```console
mise run e2e:aws-google -- --cleanup RUN_ID --region eu-west-1
```

Use the same `--profile` and `--region` that created the run. Cleanup is deterministic and can also
finish removing resources from an interrupted or partially completed deployment.

## Image transfer

Lambda consumes a same-region ECR image. The script selects one architecture from the GHCR OCI
index, pulls that child manifest, and pushes it to a temporary ECR repository before creating the
function. This keeps the verification self-contained and does not require a GitHub token in AWS
Secrets Manager, which an ECR pull-through cache for GHCR would require.
