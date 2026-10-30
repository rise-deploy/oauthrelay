import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  CleanupStack,
  deploy,
  executionRolePolicy,
  namesForRun,
  preflightImage,
  redact,
  resourceDocuments,
  retry,
  selectPlatformManifest,
} from './aws-google-relay-e2e.mjs';

const index = {
  mediaType: 'application/vnd.oci.image.index.v1+json',
  manifests: [
    { digest: 'sha256:amd64', platform: { os: 'linux', architecture: 'amd64' } },
    { digest: 'sha256:attestation', platform: { os: 'unknown', architecture: 'unknown' } },
    { digest: 'sha256:arm64', platform: { os: 'linux', architecture: 'arm64' } },
  ],
};

test('selects one requested platform and ignores attestations', () => {
  assert.equal(selectPlatformManifest(index, 'arm64').digest, 'sha256:arm64');
  assert.throws(() => selectPlatformManifest(index, 's390x'), /linux\/s390x/);
});

test('image preflight fails without calling AWS', async () => {
  const calls = [];
  const runner = async (command, args) => {
    calls.push([command, args]);
    return { code: 0, stdout: JSON.stringify(index), stderr: '' };
  };
  const image = await preflightImage(runner, 'ghcr.io/rise-deploy/oauthrelay:sha-1234567', 'arm64');
  assert.equal(image.digest, 'sha256:arm64');
  assert.deepEqual(calls.map(([command]) => command), ['docker']);

  await assert.rejects(
    preflightImage(async () => ({ stdout: '{}' }), 'missing', 'arm64'),
    /not a multi-architecture image index/,
  );
});

test('builds run-scoped resources and a shared secret reference', () => {
  const names = namesForRun('20260826t210000-abcd');
  assert.equal(names.ssmPrefix, '/oauthrelay-e2e/20260826t210000-abcd/');
  const documents = resourceDocuments('arn:aws:secretsmanager:eu-west-1:123:secret:test', 'client');
  assert.equal(
    documents.upstream.spec.oauthClient.clientSecret.valueFrom.awsSecretsManager.secretId,
    'arn:aws:secretsmanager:eu-west-1:123:secret:test',
  );
  assert.deepEqual(documents.relay.spec.redirectPolicy, [
    { loopback: 'http://127.0.0.1/oauth/callback' },
  ]);
});

test('deploy wires the selected image, SSM resources, secret, role, and public URL', async () => {
  const awsCalls = [];
  const processCalls = [];
  const aws = async (...args) => {
    awsCalls.push(args);
    const operation = args.slice(0, 2).join(' ');
    if (operation === 'ecr create-repository') {
      return { stdout: JSON.stringify({ repository: { repositoryUri: '123.dkr.ecr.eu-west-1.amazonaws.com/test' } }) };
    }
    if (operation === 'ecr get-login-password') return { stdout: 'registry-password' };
    if (operation === 'ecr describe-images') {
      return { stdout: JSON.stringify({ imageDetails: [{ imageManifestMediaType: 'application/vnd.oci.image.manifest.v1+json' }] }) };
    }
    if (operation === 'secretsmanager create-secret') {
      return { stdout: JSON.stringify({ ARN: 'arn:aws:secretsmanager:eu-west-1:123:secret:google' }) };
    }
    if (operation === 'iam create-role') {
      return { stdout: JSON.stringify({ Role: { Arn: 'arn:aws:iam::123:role/test' } }) };
    }
    if (operation === 'lambda create-function-url-config') {
      return { stdout: JSON.stringify({ FunctionUrl: 'https://function.lambda-url.eu-west-1.on.aws/' }) };
    }
    return { stdout: '{}' };
  };
  const runner = async (command, args, options = {}) => {
    processCalls.push({ command, args, options });
    return { code: 0, stdout: '', stderr: '' };
  };
  const workdir = await mkdtemp(join(tmpdir(), 'oauthrelay-script-test-'));
  const names = namesForRun('20260826t210000-abcd');
  try {
    const result = await deploy({
      options: {},
      image: {
        image: 'ghcr.io/rise-deploy/oauthrelay:sha-1234567',
        digest: 'sha256:arm64',
        architecture: 'arm64',
        sourceRevision: '1234567',
      },
      clientId: 'google-client',
      secret: 'google-secret',
      aws,
      names,
      account: { account: '123', partition: 'aws', dnsSuffix: 'amazonaws.com' },
      region: 'eu-west-1',
      workdir,
      runner,
      status: () => {},
    });
    assert.deepEqual(result, {
      publicUrl: 'https://function.lambda-url.eu-west-1.on.aws/oidc',
      functionUrl: 'https://function.lambda-url.eu-west-1.on.aws',
      callbackUrl: 'https://function.lambda-url.eu-west-1.on.aws/oidc/upstream/google/callback',
    });

    assert.deepEqual(processCalls.map(({ args }) => args[0]), ['login', 'pull', 'tag', 'push']);
    assert.ok(processCalls[1].args.includes('linux/arm64'));
    assert.ok(processCalls[3].args.includes('123.dkr.ecr.eu-west-1.amazonaws.com/test:sha-1234567-arm64'));

    const upstreamCall = awsCalls.find((args) => args[0] === 'ssm' && args.includes(names.upstreamParameter));
    const upstreamPath = upstreamCall[upstreamCall.indexOf('--value') + 1].replace('file://', '');
    const upstream = JSON.parse(await readFile(upstreamPath, 'utf8'));
    assert.equal(
      upstream.spec.oauthClient.clientSecret.valueFrom.awsSecretsManager.secretId,
      'arn:aws:secretsmanager:eu-west-1:123:secret:google',
    );
    assert.equal(await readFile(join(workdir, 'google-client-secret'), 'utf8'), 'google-secret');

    const lambdaCreate = awsCalls.find((args) => args[0] === 'lambda' && args[1] === 'create-function');
    assert.ok(lambdaCreate.includes('ImageUri=123.dkr.ecr.eu-west-1.amazonaws.com/test:sha-1234567-arm64'));
    assert.ok(lambdaCreate.includes('arm64'));
    assert.equal(
      awsCalls.filter((args) => args[0] === 'lambda' && args[1] === 'add-permission').length,
      2,
    );

    const environment = JSON.parse(await readFile(join(workdir, 'lambda-environment.json'), 'utf8'));
    assert.equal(environment.Variables.OAUTHRELAY_PUBLIC_URL, result.publicUrl);
    assert.equal(environment.Variables.OAUTHRELAY_PROVIDER_SSM_PREFIX, names.ssmPrefix);
    assert.equal(environment.Variables.OAUTHRELAY_LAMBDA_CONFIG_TTL, '60s');
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
});

test('execution policy is limited to the run prefix and exact secret', () => {
  const policy = executionRolePolicy({
    partition: 'aws',
    region: 'eu-west-1',
    accountId: '123456789012',
    ssmPrefix: '/oauthrelay-e2e/run/',
    secretArn: 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:run',
  });
  assert.equal(
    policy.Statement[1].Resource,
    'arn:aws:ssm:eu-west-1:123456789012:parameter/oauthrelay-e2e/run/*',
  );
  assert.equal(policy.Statement[2].Resource, 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:run');
});

test('redacts every occurrence of sensitive values', () => {
  assert.equal(redact('secret then secret', ['secret']), '[REDACTED] then [REDACTED]');
});

test('cleanup runs in reverse order and continues after failures', async () => {
  const calls = [];
  const cleanup = new CleanupStack();
  cleanup.add('first', async () => { calls.push('first'); });
  cleanup.add('second', async () => { calls.push('second'); throw new Error('failed'); });
  cleanup.add('third', async () => { calls.push('third'); });
  const failures = await cleanup.run();
  assert.deepEqual(calls, ['third', 'second', 'first']);
  assert.equal(failures.length, 1);
  assert.equal(failures[0].name, 'second');
});

test('retry uses bounded retries and injected delays', async () => {
  let calls = 0;
  const delays = [];
  const result = await retry(async () => {
    calls += 1;
    if (calls < 3) throw new Error('eventually consistent');
    return 'ready';
  }, {
    attempts: 4,
    delay: async (milliseconds) => { delays.push(milliseconds); },
  });
  assert.equal(result, 'ready');
  assert.equal(calls, 3);
  assert.deepEqual(delays, [1000, 2000]);
});
