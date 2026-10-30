#!/usr/bin/env node

import { spawn } from 'node:child_process';
import {
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const DEFAULT_CALLBACK_TIMEOUT_MS = 5 * 60 * 1000;
const GOOGLE_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);
const OCI_INDEX = 'application/vnd.oci.image.index.v1+json';
const DOCKER_INDEX = 'application/vnd.docker.distribution.manifest.list.v2+json';

export function selectPlatformManifest(index, architecture) {
  if (!Array.isArray(index?.manifests)) {
    throw new Error('source image is not a multi-architecture image index');
  }
  const manifest = index.manifests.find(
    (candidate) =>
      candidate.platform?.os === 'linux' &&
      candidate.platform?.architecture === architecture,
  );
  if (!manifest?.digest) {
    throw new Error(`source image does not contain linux/${architecture}`);
  }
  return manifest;
}

export function namesForRun(runId) {
  if (!/^[a-z0-9][a-z0-9-]{2,31}$/.test(runId)) {
    throw new Error('run ID must contain 3-32 lowercase letters, numbers, or hyphens');
  }
  const base = `oauthrelay-e2e-${runId}`;
  return {
    runId,
    functionName: base,
    roleName: base,
    rolePolicyName: 'oauthrelay-e2e',
    repositoryName: `oauthrelay-e2e/${runId}`,
    secretName: `oauthrelay-e2e/${runId}/google-client`,
    ssmPrefix: `/oauthrelay-e2e/${runId}/`,
    upstreamParameter: `/oauthrelay-e2e/${runId}/upstreams/google`,
    relayParameter: `/oauthrelay-e2e/${runId}/relays/google`,
    logGroup: `/aws/lambda/${base}`,
  };
}

export function resourceDocuments(secretArn, clientId) {
  return {
    upstream: {
      apiVersion: 'oauthrelay.dev/v1alpha1',
      kind: 'Upstream',
      metadata: { name: 'google' },
      spec: {
        issuerUrl: 'https://accounts.google.com',
        oauthClient: {
          clientId,
          clientSecret: {
            valueFrom: {
              awsSecretsManager: { secretId: secretArn },
            },
          },
        },
      },
    },
    relay: {
      apiVersion: 'oauthrelay.dev/v1alpha1',
      kind: 'Relay',
      metadata: { name: 'google' },
      spec: {
        upstreamRef: { name: 'google' },
        scopes: {
          default: ['openid', 'email', 'profile'],
          allowed: ['openid', 'email', 'profile'],
        },
        clientAuthentication: { type: 'Public' },
        redirectPolicy: [{ loopback: 'http://127.0.0.1/oauth/callback' }],
      },
    },
  };
}

export function executionRolePolicy({ partition, region, accountId, ssmPrefix, secretArn }) {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'WriteFunctionLogs',
        Effect: 'Allow',
        Action: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
        Resource: `arn:${partition}:logs:${region}:${accountId}:*`,
      },
      {
        Sid: 'ReadRunConfiguration',
        Effect: 'Allow',
        Action: 'ssm:GetParametersByPath',
        Resource: `arn:${partition}:ssm:${region}:${accountId}:parameter${ssmPrefix}*`,
      },
      {
        Sid: 'ReadGoogleClientSecret',
        Effect: 'Allow',
        Action: 'secretsmanager:GetSecretValue',
        Resource: secretArn,
      },
    ],
  };
}

export function redact(value, secrets) {
  let output = String(value);
  for (const secret of secrets.filter(Boolean)) {
    output = output.split(secret).join('[REDACTED]');
  }
  return output;
}

export class CleanupStack {
  #entries = [];

  add(name, cleanup) {
    this.#entries.push({ name, cleanup });
  }

  async run(log = () => {}) {
    const failures = [];
    for (const entry of this.#entries.reverse()) {
      try {
        await entry.cleanup();
      } catch (error) {
        failures.push({ name: entry.name, error });
        log(`cleanup warning (${entry.name}): ${error.message}`);
      }
    }
    this.#entries = [];
    return failures;
  }
}

export async function retry(operation, {
  attempts = 8,
  delay = async (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  retryIf = () => true,
} = {}) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await operation(attempt);
    } catch (error) {
      lastError = error;
      if (attempt === attempts - 1 || !retryIf(error)) throw error;
      await delay(Math.min(1000 * 2 ** attempt, 8000));
    }
  }
  throw lastError;
}

export async function runProcess(command, args, {
  input,
  env,
  redactions = [],
  allowFailure = false,
} = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      const result = { code, stdout: stdout.trim(), stderr: stderr.trim() };
      if (code === 0 || allowFailure) return resolve(result);
      const detail = redact(stderr || stdout || `exit code ${code}`, redactions);
      reject(new Error(`${command} failed: ${detail}`));
    });
    if (input !== undefined) child.stdin.end(input);
    else child.stdin.end();
  });
}

export async function preflightImage(runner, image, architecture) {
  const result = await runner('docker', ['buildx', 'imagetools', 'inspect', '--raw', image]);
  let index;
  try {
    index = JSON.parse(result.stdout);
  } catch {
    throw new Error(`could not parse the image index for ${image}`);
  }
  const manifest = selectPlatformManifest(index, architecture);
  return { image, architecture, digest: manifest.digest, indexDigest: index.digest };
}

function usage() {
  return `Usage:
  mise run e2e:aws-google -- --google-client-id ID [options]
  mise run e2e:aws-google -- --cleanup RUN_ID [AWS options]

Secret input (first available wins):
  --google-client-secret-file PATH
  GOOGLE_CLIENT_SECRET
  hidden terminal prompt

Options:
  --region REGION          AWS region (defaults to AWS CLI configuration)
  --profile PROFILE        AWS CLI profile
  --image IMAGE            source image (defaults to sha-<7-char HEAD>)
  --architecture ARCH      arm64 (default) or amd64
  --no-open                print the authorization URL without opening a browser
  --keep                   retain AWS resources and print a cleanup command
  --cleanup RUN_ID         delete resources retained by a previous run
  --help                    show this help
`;
}

function parseOptions(argv) {
  const { values } = parseArgs({
    args: argv,
    allowPositionals: false,
    strict: true,
    options: {
      'google-client-id': { type: 'string' },
      'google-client-secret-file': { type: 'string' },
      region: { type: 'string' },
      profile: { type: 'string' },
      image: { type: 'string' },
      architecture: { type: 'string', default: 'arm64' },
      'no-open': { type: 'boolean', default: false },
      keep: { type: 'boolean', default: false },
      cleanup: { type: 'string' },
      help: { type: 'boolean', default: false },
    },
  });
  if (!['arm64', 'amd64'].includes(values.architecture)) {
    throw new Error('--architecture must be arm64 or amd64');
  }
  return values;
}

function runIdNow() {
  const timestamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').toLowerCase();
  return `${timestamp}-${randomBytes(2).toString('hex')}`;
}

function awsArguments(options, region, args) {
  return [
    ...(options.profile ? ['--profile', options.profile] : []),
    ...(region ? ['--region', region] : []),
    ...args,
    '--no-cli-pager',
    '--output',
    'json',
  ];
}

function awsRunner(options, region, runner, redactions) {
  return async (...args) => runner('aws', awsArguments(options, region, args), { redactions });
}

async function resolveRegion(options, runner) {
  if (options.region) return options.region;
  if (process.env.AWS_REGION) return process.env.AWS_REGION;
  if (process.env.AWS_DEFAULT_REGION) return process.env.AWS_DEFAULT_REGION;
  const args = [
    ...(options.profile ? ['--profile', options.profile] : []),
    'configure',
    'get',
    'region',
  ];
  const result = await runner('aws', args, { allowFailure: true });
  if (result.code === 0 && result.stdout) return result.stdout;
  throw new Error('AWS region is required; pass --region or configure an AWS CLI region');
}

async function writePrivate(path, value) {
  await writeFile(path, value, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

async function writeJson(path, value) {
  return writePrivate(path, `${JSON.stringify(value)}\n`);
}

async function readHidden(prompt) {
  if (!process.stdin.isTTY) throw new Error('GOOGLE_CLIENT_SECRET or a secret file is required without a TTY');
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  return await new Promise((resolve, reject) => {
    let value = '';
    const finish = () => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write('\n');
    };
    const onData = (chunk) => {
      for (const character of chunk) {
        if (character === '\r' || character === '\n') {
          finish();
          resolve(value);
          return;
        }
        if (character === '\u0003') {
          finish();
          reject(new Error('cancelled'));
          return;
        }
        if (character === '\u007f') value = value.slice(0, -1);
        else value += character;
      }
    };
    process.stdin.on('data', onData);
  });
}

async function googleSecret(options) {
  if (options['google-client-secret-file']) {
    return (await readFile(options['google-client-secret-file'], 'utf8')).replace(/[\r\n]+$/, '');
  }
  if (process.env.GOOGLE_CLIENT_SECRET) return process.env.GOOGLE_CLIENT_SECRET;
  return readHidden('Google OAuth client secret: ');
}

async function promptEnter(message) {
  if (!process.stdin.isTTY) throw new Error('interactive Google redirect registration requires a TTY');
  const interface_ = createInterface({ input: process.stdin, output: process.stdout });
  try {
    await interface_.question(`${message}\nPress Enter to continue... `);
  } finally {
    interface_.close();
  }
}

function parseJson(result, label) {
  try {
    return JSON.parse(result.stdout || '{}');
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
}

async function ignoreMissing(operation) {
  try {
    return await operation();
  } catch (error) {
    if (/not found|does not exist|ResourceNotFound|RepositoryNotFound/i.test(error.message)) return undefined;
    throw error;
  }
}

async function cleanupRun({ aws, names, status = console.log }) {
  const cleanup = new CleanupStack();
  cleanup.add('ECR repository', () => ignoreMissing(() => aws(
    'ecr', 'delete-repository', '--repository-name', names.repositoryName, '--force',
  )));
  cleanup.add('IAM role', async () => {
    await ignoreMissing(() => aws(
      'iam', 'delete-role-policy', '--role-name', names.roleName,
      '--policy-name', names.rolePolicyName,
    ));
    await retry(
      () => ignoreMissing(() => aws('iam', 'delete-role', '--role-name', names.roleName)),
      { retryIf: (error) => /DeleteConflict|cannot be deleted/i.test(error.message) },
    );
  });
  cleanup.add('Google client secret', () => ignoreMissing(() => aws(
    'secretsmanager', 'delete-secret', '--secret-id', names.secretName,
    '--force-delete-without-recovery',
  )));
  cleanup.add('SSM parameters', () => ignoreMissing(() => aws(
    'ssm', 'delete-parameters', '--names', names.upstreamParameter, names.relayParameter,
  )));
  cleanup.add('CloudWatch log group', () => ignoreMissing(() => aws(
    'logs', 'delete-log-group', '--log-group-name', names.logGroup,
  )));
  cleanup.add('Lambda function', async () => {
    await ignoreMissing(() => aws(
      'lambda', 'delete-function-url-config', '--function-name', names.functionName,
    ));
    await ignoreMissing(() => aws('lambda', 'delete-function', '--function-name', names.functionName));
  });
  status(`Cleaning AWS resources for ${names.runId}...`);
  return cleanup.run(status);
}

export async function deploy({ options, image, clientId, secret, aws, names, account, region, workdir, runner, status }) {
  status(`Creating temporary ECR repository ${names.repositoryName}...`);
  const repository = parseJson(await aws(
    'ecr', 'create-repository', '--repository-name', names.repositoryName,
    '--image-tag-mutability', 'IMMUTABLE',
    '--image-scanning-configuration', 'scanOnPush=true',
    '--tags', `Key=Purpose,Value=oauthrelay-e2e`, `Key=RunId,Value=${names.runId}`,
  ), 'create-repository').repository;
  const repositoryUri = repository.repositoryUri;

  const password = (await aws('ecr', 'get-login-password')).stdout;
  await runner('docker', [
    'login', '--username', 'AWS', '--password-stdin', `${account.account}.dkr.ecr.${region}.${account.dnsSuffix}`,
  ], { input: `${password}\n`, redactions: [password, secret] });
  const source = `${image.image}@${image.digest}`;
  const platform = `linux/${image.architecture}`;
  status(`Copying ${source} (${platform}) into ECR...`);
  await runner('docker', ['pull', '--platform', platform, source], { redactions: [secret] });
  const destinationTag = `sha-${image.sourceRevision}-${image.architecture}`;
  const destination = `${repositoryUri}:${destinationTag}`;
  await runner('docker', ['tag', source, destination], { redactions: [secret] });
  await runner('docker', ['push', destination], { redactions: [secret] });

  const images = parseJson(await aws(
    'ecr', 'describe-images', '--repository-name', names.repositoryName,
    '--image-ids', `imageTag=${destinationTag}`,
  ), 'describe-images').imageDetails ?? [];
  const mediaType = images[0]?.imageManifestMediaType;
  if (!mediaType || mediaType === OCI_INDEX || mediaType === DOCKER_INDEX) {
    throw new Error('the ECR image is not a single-architecture image manifest');
  }

  const repositoryPolicyPath = await writeJson(join(workdir, 'repository-policy.json'), {
    Version: '2012-10-17',
    Statement: [{
      Sid: 'LambdaRetrieveImage',
      Effect: 'Allow',
      Principal: { Service: 'lambda.amazonaws.com' },
      Action: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'],
    }],
  });
  await aws(
    'ecr', 'set-repository-policy', '--repository-name', names.repositoryName,
    '--policy-text', `file://${repositoryPolicyPath}`,
  );

  const secretPath = await writePrivate(join(workdir, 'google-client-secret'), secret);
  status('Creating the run-scoped Google client secret...');
  const secretArn = parseJson(await aws(
    'secretsmanager', 'create-secret', '--name', names.secretName,
    '--description', `oauthrelay Google relay test ${names.runId}`,
    '--secret-string', `file://${secretPath}`,
    '--tags', `Key=Purpose,Value=oauthrelay-e2e`, `Key=RunId,Value=${names.runId}`,
  ), 'create-secret').ARN;

  const documents = resourceDocuments(secretArn, clientId);
  const upstreamPath = await writePrivate(join(workdir, 'upstream.json'), JSON.stringify(documents.upstream));
  const relayPath = await writePrivate(join(workdir, 'relay.json'), JSON.stringify(documents.relay));
  status(`Creating SSM resources below ${names.ssmPrefix}...`);
  await aws(
    'ssm', 'put-parameter', '--name', names.upstreamParameter, '--type', 'String',
    '--value', `file://${upstreamPath}`, '--tags', `Key=Purpose,Value=oauthrelay-e2e`, `Key=RunId,Value=${names.runId}`,
  );
  await aws(
    'ssm', 'put-parameter', '--name', names.relayParameter, '--type', 'String',
    '--value', `file://${relayPath}`, '--tags', `Key=Purpose,Value=oauthrelay-e2e`, `Key=RunId,Value=${names.runId}`,
  );

  const trustPath = await writeJson(join(workdir, 'trust-policy.json'), {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { Service: 'lambda.amazonaws.com' },
      Action: 'sts:AssumeRole',
    }],
  });
  status(`Creating Lambda execution role ${names.roleName}...`);
  const role = parseJson(await aws(
    'iam', 'create-role', '--role-name', names.roleName,
    '--assume-role-policy-document', `file://${trustPath}`,
    '--description', `oauthrelay Google relay test ${names.runId}`,
    '--tags', `Key=Purpose,Value=oauthrelay-e2e`, `Key=RunId,Value=${names.runId}`,
  ), 'create-role').Role;
  const rolePolicyPath = await writeJson(join(workdir, 'role-policy.json'), executionRolePolicy({
    partition: account.partition,
    region,
    accountId: account.account,
    ssmPrefix: names.ssmPrefix,
    secretArn,
  }));
  await aws(
    'iam', 'put-role-policy', '--role-name', names.roleName,
    '--policy-name', names.rolePolicyName, '--policy-document', `file://${rolePolicyPath}`,
  );

  const sealKey = `base64:${randomBytes(32).toString('base64')}`;
  const environmentPath = join(workdir, 'lambda-environment.json');
  const environment = (publicUrl) => ({ Variables: {
    OAUTHRELAY_PUBLIC_URL: publicUrl,
    OAUTHRELAY_PROVIDER_SSM_PREFIX: names.ssmPrefix,
    OAUTHRELAY_LAMBDA_CONFIG_TTL: '60s',
    OAUTHRELAY_SEAL_KEY: sealKey,
    OAUTHRELAY_LOG: 'info',
  } });
  await writeJson(environmentPath, environment('https://example.invalid/oidc'));
  const lambdaArchitecture = image.architecture === 'amd64' ? 'x86_64' : 'arm64';
  status(`Creating ${lambdaArchitecture} Lambda ${names.functionName}...`);
  await retry(
    () => aws(
      'lambda', 'create-function', '--function-name', names.functionName,
      '--description', `oauthrelay Google relay test ${names.runId}`,
      '--package-type', 'Image', '--code', `ImageUri=${destination}`,
      '--role', role.Arn, '--architectures', lambdaArchitecture,
      '--timeout', '30', '--memory-size', '256',
      '--environment', `file://${environmentPath}`,
      '--tags', `Purpose=oauthrelay-e2e,RunId=${names.runId}`,
    ),
    { retryIf: (error) => /cannot be assumed|InvalidParameterValue/i.test(error.message) },
  );
  await aws('lambda', 'wait', 'function-active-v2', '--function-name', names.functionName);

  const functionUrl = parseJson(await aws(
    'lambda', 'create-function-url-config', '--function-name', names.functionName,
    '--auth-type', 'NONE',
  ), 'create-function-url-config').FunctionUrl.replace(/\/$/, '');
  await aws(
    'lambda', 'add-permission', '--function-name', names.functionName,
    '--statement-id', 'FunctionURLAllowPublicAccess', '--action', 'lambda:InvokeFunctionUrl',
    '--principal', '*', '--function-url-auth-type', 'NONE',
  );
  await aws(
    'lambda', 'add-permission', '--function-name', names.functionName,
    '--statement-id', 'FunctionURLInvokeAllowPublicAccess', '--action', 'lambda:InvokeFunction',
    '--principal', '*', '--invoked-via-function-url',
  );

  const publicUrl = `${functionUrl}/oidc`;
  await writeJson(environmentPath, environment(publicUrl));
  await aws(
    'lambda', 'update-function-configuration', '--function-name', names.functionName,
    '--environment', `file://${environmentPath}`,
  );
  await aws('lambda', 'wait', 'function-updated-v2', '--function-name', names.functionName);
  return { publicUrl, functionUrl, callbackUrl: `${publicUrl}/upstream/google/callback` };
}

async function fetchWithRetry(url, attempts = 20) {
  return retry(async () => {
    const response = await fetch(url, { redirect: 'manual' });
    if (!response.ok) throw new Error(`${url} returned ${response.status}`);
    return response;
  }, { attempts });
}

function base64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function sameText(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function startCallbackServer(timeoutMs = DEFAULT_CALLBACK_TIMEOUT_MS) {
  let settle;
  const callback = new Promise((resolve, reject) => { settle = { resolve, reject }; });
  const server = createServer((request, response) => {
    const url = new URL(request.url, 'http://127.0.0.1');
    if (url.pathname !== '/oauth/callback') {
      response.writeHead(404).end('Not found');
      return;
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    response.end('<!doctype html><title>oauthrelay verified</title><p>Authorization returned to the oauthrelay verification script. You may close this window.</p>');
    settle.resolve(url);
  });
  server.on('error', (error) => settle.reject(error));
  const timeout = setTimeout(() => settle.reject(new Error('timed out waiting for the browser callback')), timeoutMs);
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        redirectUri: `http://127.0.0.1:${port}/oauth/callback`,
        callback: callback.finally(() => {
          clearTimeout(timeout);
          server.close();
        }),
      });
    });
    server.on('error', reject);
  });
}

async function openBrowser(url) {
  const command = process.platform === 'darwin'
    ? ['open', [url]]
    : process.platform === 'win32'
      ? ['cmd', ['/c', 'start', '', url]]
      : ['xdg-open', [url]];
  return await new Promise((resolve) => {
    const child = spawn(command[0], command[1], { detached: true, stdio: 'ignore' });
    child.once('spawn', () => {
      child.unref();
      resolve(true);
    });
    child.once('error', () => resolve(false));
  });
}

function decodeJwtPart(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

async function verifyGoogleIdToken(idToken, { clientId, nonce, metadata }) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Google ID token is not a JWT');
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = decodeJwtPart(encodedHeader);
  const claims = decodeJwtPart(encodedClaims);
  if (header.alg !== 'RS256' || !header.kid) throw new Error('Google ID token has an unsupported header');
  const jwksResponse = await fetch(metadata.jwks_uri);
  if (!jwksResponse.ok) {
    throw new Error(`Google JWKS returned ${jwksResponse.status}`);
  }
  const jwks = await jwksResponse.json();
  const jwk = jwks.keys?.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new Error('Google signing key was not found');
  const valid = verifySignature(
    'RSA-SHA256',
    Buffer.from(`${encodedHeader}.${encodedClaims}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(encodedSignature, 'base64url'),
  );
  if (!valid) throw new Error('Google ID token signature is invalid');
  if (!GOOGLE_ISSUERS.has(claims.iss)) throw new Error(`unexpected Google issuer ${claims.iss}`);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(clientId)) throw new Error('Google ID token audience does not contain the client ID');
  if (!sameText(String(claims.nonce ?? ''), nonce)) throw new Error('Google ID token nonce does not match');
  if (!Number.isFinite(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('Google ID token is expired');
  }
  return claims;
}

async function verifyRelay({ publicUrl, clientId, noOpen, status }) {
  status('Waiting for oauthrelay readiness...');
  await fetchWithRetry(`${new URL(publicUrl).origin}/readyz`);

  const upstreamMetadataResponse = await fetchWithRetry(
    'https://accounts.google.com/.well-known/openid-configuration',
    5,
  );
  const upstreamMetadata = await upstreamMetadataResponse.json();
  const relayMetadataResponse = await fetchWithRetry(
    `${publicUrl}/relay/google/.well-known/openid-configuration`,
  );
  const relayMetadata = await relayMetadataResponse.json();
  if (relayMetadata.issuer !== upstreamMetadata.issuer || relayMetadata.jwks_uri !== upstreamMetadata.jwks_uri) {
    throw new Error('transparent discovery did not preserve the Google issuer and JWKS URI');
  }
  if (
    relayMetadata.authorization_endpoint !== `${publicUrl}/relay/google/authorize` ||
    relayMetadata.token_endpoint !== `${publicUrl}/relay/google/token`
  ) {
    throw new Error('transparent discovery did not publish the relay endpoints');
  }

  const invalid = new URL(`${publicUrl}/relay/google/authorize`);
  invalid.searchParams.set('redirect_uri', 'https://invalid.example/callback');
  invalid.searchParams.set('code_challenge', base64url(randomBytes(32)));
  invalid.searchParams.set('code_challenge_method', 'S256');
  const invalidResponse = await fetch(invalid, { redirect: 'manual' });
  if (invalidResponse.status !== 400) throw new Error(`invalid redirect returned ${invalidResponse.status}, expected 400`);

  const listener = await startCallbackServer();
  const verifier = base64url(randomBytes(48));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  const state = base64url(randomBytes(24));
  const nonce = base64url(randomBytes(24));
  const authorize = new URL(`${publicUrl}/relay/google/authorize`);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', clientId);
  authorize.searchParams.set('redirect_uri', listener.redirectUri);
  authorize.searchParams.set('scope', 'openid email profile');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('nonce', nonce);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  authorize.searchParams.set('prompt', 'select_account');

  status(`Open this URL to authenticate:\n${authorize}`);
  if (!noOpen && !(await openBrowser(authorize.toString()))) {
    status('The browser could not be opened automatically; open the URL above.');
  }
  const callback = await listener.callback;
  if (callback.searchParams.has('error')) {
    throw new Error(`authorization failed: ${callback.searchParams.get('error')}`);
  }
  if (!sameText(callback.searchParams.get('state') ?? '', state)) {
    throw new Error('application state did not round-trip through oauthrelay');
  }
  const code = callback.searchParams.get('code');
  if (!code) throw new Error('application callback did not contain an authorization code');

  const tokenResponse = await fetch(`${publicUrl}/relay/google/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: listener.redirectUri,
      code_verifier: verifier,
    }),
  });
  const tokenText = await tokenResponse.text();
  if (!tokenResponse.ok) throw new Error(`relay token exchange returned ${tokenResponse.status}: ${tokenText}`);
  const tokens = JSON.parse(tokenText);
  if (!tokens.access_token || !tokens.id_token) throw new Error('Google token response omitted access_token or id_token');
  const claims = await verifyGoogleIdToken(tokens.id_token, {
    clientId,
    nonce,
    metadata: upstreamMetadata,
  });
  const userInfoResponse = await fetch(upstreamMetadata.userinfo_endpoint, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  });
  if (!userInfoResponse.ok) throw new Error(`Google UserInfo returned ${userInfoResponse.status}`);
  const userInfo = await userInfoResponse.json();
  if (!claims.sub || userInfo.sub !== claims.sub) throw new Error('Google UserInfo subject does not match the ID token');
  status('Google authorization, token validation, and UserInfo verification succeeded.');
}

async function defaultImage(runner) {
  const revision = (await runner('git', ['rev-parse', '--short=7', 'HEAD'])).stdout;
  return { image: `ghcr.io/rise-deploy/oauthrelay:sha-${revision}`, revision };
}

async function accountContext(aws) {
  const identity = parseJson(await aws('sts', 'get-caller-identity'), 'get-caller-identity');
  const [partition] = identity.Arn.split(':').slice(1);
  const dnsSuffix = partition === 'aws-cn' ? 'amazonaws.com.cn' : 'amazonaws.com';
  return { account: identity.Account, partition, dnsSuffix };
}

function retainedCleanupCommand(options, region, runId) {
  return [
    'mise run e2e:aws-google --',
    `--cleanup ${runId}`,
    `--region ${region}`,
    ...(options.profile ? [`--profile ${options.profile}`] : []),
  ].join(' ');
}

async function main(argv = process.argv.slice(2), runner = runProcess) {
  const options = parseOptions(argv);
  if (options.help) {
    console.log(usage());
    return;
  }
  const region = await resolveRegion(options, runner);
  const redactions = [];
  const aws = awsRunner(options, region, runner, redactions);

  if (options.cleanup) {
    const names = namesForRun(options.cleanup);
    const failures = await cleanupRun({ aws, names });
    if (failures.length > 0) throw new Error(`cleanup completed with ${failures.length} failure(s)`);
    return;
  }
  const clientId = options['google-client-id'];
  if (!clientId) throw new Error('--google-client-id is required');

  const source = options.image
    ? { image: options.image, revision: 'custom' }
    : await defaultImage(runner);
  console.log(`Resolving ${source.image} before creating AWS resources...`);
  let image;
  try {
    image = await preflightImage(runner, source.image, options.architecture);
  } catch (error) {
    throw new Error(`${error.message}. Ensure CI published ${source.image} or pass --image.`);
  }
  image.sourceRevision = source.revision;

  const secret = await googleSecret(options);
  delete process.env.GOOGLE_CLIENT_SECRET;
  if (!secret) throw new Error('Google OAuth client secret must not be empty');
  redactions.push(secret);

  const account = await accountContext(aws);
  const names = namesForRun(runIdNow());
  const workdir = await mkdtemp(join(tmpdir(), 'oauthrelay-e2e-'));
  await chmod(workdir, 0o700);
  let deployed;
  let cleaning = false;
  const cleanup = async () => {
    if (cleaning) return [];
    cleaning = true;
    return cleanupRun({ aws, names });
  };
  const signal = async () => {
    if (!options.keep) {
      const failures = await cleanup();
      if (failures.length > 0) {
        console.error(`Cleanup is incomplete. Retry with:\n${retainedCleanupCommand(options, region, names.runId)}`);
      }
    }
    await rm(workdir, { recursive: true, force: true });
    process.exit(130);
  };
  process.once('SIGINT', signal);
  process.once('SIGTERM', signal);

  try {
    deployed = await deploy({
      options, image, clientId, secret, aws, names, account, region, workdir, runner,
      status: console.log,
    });
    console.log(`\nRegister this exact redirect URI on the Google web OAuth client:\n${deployed.callbackUrl}\n`);
    await promptEnter('The Lambda Function URL is public only for this test. Register the callback above in Google Cloud.');
    await verifyRelay({ publicUrl: deployed.publicUrl, clientId, noOpen: options['no-open'], status: console.log });
  } catch (error) {
    if (deployed || !options.keep) {
      try {
        const logs = await aws(
          'logs', 'tail', names.logGroup, '--since', '10m', '--format', 'short',
        );
        if (logs.stdout) console.error(`Recent Lambda logs:\n${redact(logs.stdout, redactions)}`);
      } catch {}
    }
    throw error;
  } finally {
    process.removeListener('SIGINT', signal);
    process.removeListener('SIGTERM', signal);
    await rm(workdir, { recursive: true, force: true });
    if (deployed) {
      console.log(`If registered, remove this redirect URI from Google Cloud:\n${deployed.callbackUrl}`);
    }
    if (options.keep) {
      console.log(`AWS resources retained for run ${names.runId}.`);
      console.log(`Clean them with:\n${retainedCleanupCommand(options, region, names.runId)}`);
    } else {
      const failures = await cleanup();
      if (failures.length > 0) process.exitCode = 1;
    }
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : '';
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    console.error(`error: ${error.message}`);
    process.exitCode = 1;
  });
}
