import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as esm from '../src/index.mjs';
import { CHALLENGE, ISSUER, REDIRECT_URI, STATE, VERIFIER, validCallbackQuery, validDiscovery } from './helpers.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'oauthcage.mjs');

const EXPORTED_FUNCTIONS = [
  'createOAuthPolicy',
  'getPolicy',
  'auditRedirectUri',
  'validateRedirectUri',
  'createPkcePair',
  'verifyPkce',
  'generateState',
  'generateNonce',
  'verifyState',
  'verifyNonce',
  'auditAuthRequest',
  'auditCallback',
  'auditTokenRequest',
  'auditEndpointUrl',
  'auditDiscoveryMetadata',
  'neutralizeTerminal',
  'redactSensitiveText'
];

for (const name of EXPORTED_FUNCTIONS) {
  test('ESM exports function ' + name, () => {
    assert.equal(typeof esm[name], 'function');
  });
  test('CJS exports function ' + name, () => {
    assert.equal(typeof cjs[name], 'function');
  });
}

test('version and error constants have ESM and CJS parity', () => {
  assert.equal(esm.OAUTHCAGE_VERSION, cjs.OAUTHCAGE_VERSION);
  assert.deepEqual(cjs.OAUTHCAGE_ERROR_CODES, esm.OAUTHCAGE_ERROR_CODES);
  assert.equal(cjs.default, cjs);
});

test('redirect audit has ESM and CJS parity', () => {
  const left = esm.auditRedirectUri('https://app.example/cb', ['https://app.example/cb']);
  const right = cjs.auditRedirectUri('https://app.example/cb', ['https://app.example/cb']);
  assert.deepEqual(JSON.parse(JSON.stringify(right)), JSON.parse(JSON.stringify(left)));
});

test('endpoint audit has ESM and CJS parity', () => {
  const left = esm.auditEndpointUrl('https://127.0.0.1/token');
  const right = cjs.auditEndpointUrl('https://127.0.0.1/token');
  assert.deepEqual(JSON.parse(JSON.stringify(right)), JSON.parse(JSON.stringify(left)));
});

test('discovery audit has ESM and CJS parity', () => {
  const input = validDiscovery();
  const options = { expectedIssuer: ISSUER };
  const left = esm.auditDiscoveryMetadata(input, options);
  const right = cjs.auditDiscoveryMetadata(input, options);
  assert.deepEqual(JSON.parse(JSON.stringify(right)), JSON.parse(JSON.stringify(left)));
});

test('PKCE verification has ESM and CJS parity', () => {
  assert.equal(esm.verifyPkce(VERIFIER, CHALLENGE, 'S256'), true);
  assert.equal(cjs.verifyPkce(VERIFIER, CHALLENGE, 'S256'), true);
});

for (const name of ['strict', 'spa', 'confidential', 'native']) {
  test('policy preset ' + name + ' is available and deeply frozen', () => {
    const policy = esm.getPolicy(name);
    assert.equal(policy.name, name);
    assert.equal(Object.isFrozen(policy), true);
    assert.equal(Object.isFrozen(policy.allowedPkceMethods), true);
    assert.equal(Object.isFrozen(policy.allowedRedirectSchemes), true);
    assert.throws(() => {
      policy.requirePkce = false;
    }, TypeError);
  });
}

test('spa preset forbids client secrets', () => {
  assert.equal(esm.getPolicy('spa').allowClientSecret, false);
});

test('confidential preset requires PAR', () => {
  assert.equal(esm.getPolicy('confidential').requirePar, true);
});

test('native preset permits loopback HTTP but not localhost by default', () => {
  const policy = esm.getPolicy('native');
  assert.equal(policy.allowLoopbackHttp, true);
  assert.equal(policy.allowLocalhostHttp, false);
});

test('every preset permits only S256 PKCE', () => {
  for (const name of ['strict', 'spa', 'confidential', 'native']) {
    assert.deepEqual(esm.getPolicy(name).allowedPkceMethods, ['S256']);
  }
});

test('custom policy preserves preset base and freezes overrides', () => {
  const policy = esm.createOAuthPolicy('native', { allowLocalhostHttp: true, allowedEndpointPorts: ['443', '8443'] });
  assert.equal(policy.name, 'native');
  assert.equal(policy.allowLoopbackHttp, true);
  assert.equal(policy.allowLocalhostHttp, true);
  assert.deepEqual(policy.allowedEndpointPorts, ['443', '8443']);
  assert.equal(Object.isFrozen(policy), true);
});

for (const [label, override] of [
  ['boolean as string', { requirePkce: 'yes' }],
  ['integer as string', { maxUriLength: '2048' }],
  ['integer too small', { maxUriLength: 1 }],
  ['integer too large', { maxUriLength: 999999 }],
  ['array as string', { allowedGrantTypes: 'code' }],
  ['array with nonstring', { allowedGrantTypes: [42] }],
  ['bad port string', { allowedEndpointPorts: ['abc'] }],
  ['port overflow', { allowedEndpointPorts: ['65536'] }],
  ['unknown field', { unexpected: true }],
  ['plain combined with S256', { allowedPkceMethods: ['plain', 'S256'] }]
]) {
  test('createOAuthPolicy rejects invalid override for ' + label, () => {
    assert.throws(() => esm.createOAuthPolicy('strict', override), { code: 'OAUTHCAGE_POLICY_INVALID' });
  });
}

test('getPolicy rejects an unknown preset', () => {
  assert.throws(() => esm.getPolicy('unknown'), { code: 'OAUTHCAGE_POLICY_UNKNOWN' });
});

for (const [label, invoke] of [
  ['auditRedirectUri', () => esm.auditRedirectUri('https://a.example/cb', ['https://a.example/cb'], { unknown: true })],
  ['auditAuthRequest', () => esm.auditAuthRequest('response_type=code', { unknown: true })],
  ['auditCallback', () => esm.auditCallback('code=x', { unknown: true })],
  ['auditTokenRequest', () => esm.auditTokenRequest('grant_type=password', { unknown: true })],
  ['auditEndpointUrl', () => esm.auditEndpointUrl('https://issuer.example/token', { unknown: true })],
  ['auditDiscoveryMetadata', () => esm.auditDiscoveryMetadata({}, { unknown: true })]
]) {
  test('unknown options are rejected for ' + label, () => {
    assert.throws(invoke, { code: 'OAUTHCAGE_INVALID_OPTIONS' });
  });
}

for (const [label, input, expected] of [
  ['ANSI escape', 'abc\x1b[31mdef', 'abc\\x1B[31mdef'],
  ['nul', 'a\0b', 'a\\x00b'],
  ['bell', 'a\x07b', 'a\\x07b'],
  ['delete', 'a\x7fb', 'a\\x7Fb'],
  ['C1 control', 'a\x85b', 'a\\x85b'],
  ['bidi override', 'a\u202eb', 'a\\u202Eb'],
  ['zero width', 'a\u200bb', 'a\\u200Bb'],
  ['line separator', 'a\u2028b', 'a\\u2028b'],
  ['paragraph separator', 'a\u2029b', 'a\\u2029b']
]) {
  test('terminal neutralization escapes ' + label, () => {
    assert.equal(esm.neutralizeTerminal(input), expected);
  });
}

test('terminal neutralization preserves ordinary newlines', () => {
  assert.equal(esm.neutralizeTerminal('a\nb'), 'a\nb');
});

for (const key of ['access_token', 'id_token', 'refresh_token', 'client_secret', 'code_verifier', 'password', 'code']) {
  test('redaction hides sensitive query value ' + key, () => {
    const output = esm.redactSensitiveText('https://x/cb?' + key + '=secret-value&x=1');
    assert.equal(output.includes('secret-value'), false);
    assert.equal(output.includes('[REDACTED]'), true);
  });
}

function runCli(args, input) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    input,
    encoding: 'utf8',
    timeout: 20000
  });
}

test('CLI help exits zero', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /audit-redirect/u);
});

test('CLI unknown command exits two', () => {
  const result = runCli(['missing-command']);
  assert.equal(result.status, 2);
});

test('CLI gen-pkce emits parseable JSON', () => {
  const result = runCli(['gen-pkce', '--json']);
  assert.equal(result.status, 0, result.stderr);
  const pair = JSON.parse(result.stdout);
  assert.match(pair.verifier, /^[A-Za-z0-9\-._~]{64}$/u);
  assert.match(pair.challenge, /^[A-Za-z0-9_-]{43}$/u);
});

test('CLI verify-pkce exits zero for RFC vector and never echoes verifier', () => {
  const result = runCli(['verify-pkce', '--verifier', VERIFIER, '--challenge', CHALLENGE, '--json']);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  assert.equal(result.stdout.includes(VERIFIER), false);
});

test('CLI verify-pkce exits one for plain downgrade', () => {
  const result = runCli(['verify-pkce', '--verifier', VERIFIER, '--challenge', VERIFIER, '--method', 'plain', '--json']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes(VERIFIER), false);
});

test('CLI audit-redirect exits zero for exact match', () => {
  const result = runCli(['audit-redirect', 'https://app.example/cb', '--registered', 'https://app.example/cb']);
  assert.equal(result.status, 0, result.stderr + result.stdout);
});

test('CLI audit-redirect exits one for mismatch', () => {
  const result = runCli(['audit-redirect', 'https://app.example/evil', '--registered', 'https://app.example/cb']);
  assert.equal(result.status, 1);
});

test('CLI audit-callback exits zero for valid callback', () => {
  const result = runCli([
    'audit-callback',
    validCallbackQuery(),
    '--expected-state', STATE,
    '--expected-issuer', ISSUER,
    '--json'
  ]);
  assert.equal(result.status, 0, result.stderr + result.stdout);
});

test('CLI audit-callback exits one for duplicate code', () => {
  const result = runCli([
    'audit-callback',
    validCallbackQuery() + '&code=secondsecretcode',
    '--expected-state', STATE,
    '--expected-issuer', ISSUER,
    '--json'
  ]);
  assert.equal(result.status, 1);
  assert.equal((result.stdout + result.stderr).includes('secondsecretcode'), false);
});

test('CLI audit-discovery reads bounded stdin without trimming', () => {
  const result = runCli(['audit-discovery', '-', '--expected-issuer', ISSUER, '--json'], JSON.stringify(validDiscovery()));
  assert.equal(result.status, 0, result.stderr + result.stdout);
});

test('CLI audit-discovery rejects whitespace-only stdin', () => {
  const result = runCli(['audit-discovery', '-', '--expected-issuer', ISSUER], ' \n\t ');
  assert.notEqual(result.status, 0);
});

test('CLI output contains no raw ANSI or control characters from hostile input', () => {
  const result = runCli(['audit-redirect', 'https://app.example/\x1b[31m', '--registered', 'https://app.example/cb', '--json']);
  assert.equal(result.status, 1);
  assert.equal((result.stdout + result.stderr).includes('\x1b'), false);
});

function listFiles(directory) {
  const output = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== '.git') output.push(...listFiles(full));
    } else {
      output.push(full);
    }
  }
  return output;
}

test('repository contains no em dash or en dash characters', () => {
  for (const file of listFiles(root)) {
    if (!/\.(?:mjs|cjs|ts|json|md|yml|txt)$/u.test(file) && !file.endsWith('LICENSE')) continue;
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes('\u2014'), false, file);
    assert.equal(text.includes('\u2013'), false, file);
  }
});

test('repository contains no local user filesystem paths', () => {
  const marker = '/' + 'Users' + '/';
  for (const file of listFiles(root)) {
    if (!/\.(?:mjs|cjs|ts|json|md|yml|txt)$/u.test(file) && !file.endsWith('LICENSE')) continue;
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes(marker), false, file);
  }
});

test('package has zero runtime and development dependencies', () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(packageJson.dependencies, {});
  assert.deepEqual(packageJson.devDependencies, {});
  assert.equal(packageJson.sideEffects, false);
});

test('package exports dual ESM and CJS entries with declarations', () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(packageJson.type, 'module');
  assert.equal(packageJson.exports['.'].import, './src/index.mjs');
  assert.equal(packageJson.exports['.'].require, './cjs/index.cjs');
  assert.equal(packageJson.exports['.'].types, './types/index.d.ts');
  assert.equal(packageJson.bin.oauthcage, 'bin/oauthcage.mjs');
});

test('required project documents and scripts exist', () => {
  for (const name of ['README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CHANGELOG.md', 'LICENSE', '.github/workflows/ci.yml', 'scripts/build-cjs.mjs', 'scripts/check-types.mjs', 'scripts/cli-smoke.mjs']) {
    assert.equal(fs.existsSync(path.join(root, name)), true, name);
  }
});

test('CI covers two operating systems and four Node versions', () => {
  const ci = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
  assert.match(ci, /ubuntu-24\.04/u);
  assert.match(ci, /windows-latest/u);
  assert.match(ci, /node: \[18, 20, 22, 24\]/u);
  assert.equal((ci.match(/shell: bash/gu) || []).length >= 5, true);
});

test('TypeScript declarations do not use the broad type forbidden by project checks', () => {
  const declaration = fs.readFileSync(path.join(root, 'types/index.d.ts'), 'utf8');
  assert.equal(/\bany\b/u.test(declaration), false);
});

test('generated CommonJS bundle uses timingSafeEqual for secret comparisons', () => {
  const bundle = fs.readFileSync(path.join(root, 'cjs/index.cjs'), 'utf8');
  assert.match(bundle, /timingSafeEqual/u);
});

test('examples directory contains three runnable examples', () => {
  const examples = fs.readdirSync(path.join(root, 'examples')).filter((name) => name.endsWith('.mjs')).sort();
  assert.equal(examples.length, 3);
});
