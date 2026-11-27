import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'oauthcage.mjs');

function run(args, input) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    input,
    encoding: 'utf8',
    timeout: 20000
  });
}

function assert(condition, message) {
  if (!condition) throw new Error('cli smoke failure: ' + message);
}

function cleanOutput(result) {
  return !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/u.test(result.stdout + result.stderr);
}

let result = run(['gen-pkce', '--json']);
assert(result.status === 0, 'gen-pkce exits zero');
assert(cleanOutput(result), 'gen-pkce output is terminal safe');
const pair = JSON.parse(result.stdout);
assert(typeof pair.verifier === 'string' && typeof pair.challenge === 'string', 'gen-pkce emits a pair');

result = run(['verify-pkce', '--verifier', pair.verifier, '--challenge', pair.challenge, '--json']);
assert(result.status === 0, 'verify-pkce accepts a valid pair');
assert(!result.stdout.includes(pair.verifier), 'verify-pkce does not echo the verifier');

result = run(['verify-pkce', '--verifier', pair.verifier, '--challenge', pair.challenge, '--method', 'plain', '--json']);
assert(result.status === 1, 'plain PKCE exits one');
assert(!result.stdout.includes(pair.verifier), 'failed verification does not echo the verifier');

result = run(['audit-redirect', 'https://app.example/callback', '--registered', 'https://app.example/callback', '--json']);
assert(result.status === 0, 'exact redirect audit passes');

result = run(['audit-redirect', 'https://app.example/callback/../evil', '--registered', 'https://app.example/callback/../evil', '--json']);
assert(result.status === 1, 'path traversal redirect fails');
assert(!result.stdout.includes('/../evil'), 'redirect failure does not echo the candidate path');

const secretCode = 'smoke-secret-code-value';
result = run(['audit-callback', 'https://app.example/cb?code=' + secretCode + '&code=second', '--json']);
assert(result.status === 1, 'duplicate callback parameter fails');
assert(!result.stdout.includes(secretCode) && !result.stderr.includes(secretCode), 'callback output redacts authorization code');

const discovery = JSON.stringify({
  issuer: 'https://issuer.example',
  authorization_endpoint: 'https://issuer.example/auth',
  token_endpoint: 'https://issuer.example/token',
  jwks_uri: 'https://issuer.example/jwks',
  id_token_signing_alg_values_supported: ['RS256'],
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256']
});
result = run(['audit-discovery', '-', '--expected-issuer', 'https://issuer.example', '--json'], discovery);
assert(result.status === 0, 'discovery audit passes from stdin');
assert(cleanOutput(result), 'discovery output is terminal safe');

result = run(['audit-discovery', '-', '--expected-issuer', 'https://issuer.example'], '   ');
assert(result.status !== 0, 'whitespace only stdin is not trimmed into a pass');

result = run(['audit-endpoint', 'https://issuer.example/jwks', '--json']);
assert(result.status === 0, 'public HTTPS endpoint audit passes');
assert(cleanOutput(result), 'endpoint output is terminal safe');

result = run(['audit-endpoint', '-', '--json'], 'https://169.254.169.254/smoke-endpoint-path?smoke-endpoint-query=1');
assert(result.status === 1, 'cloud metadata endpoint fails from stdin');
assert(!result.stdout.includes('smoke-endpoint-path') && !result.stdout.includes('smoke-endpoint-query'), 'endpoint failure does not echo the path or query');

result = run(['audit-endpoint', 'https://issuer.example/\u001b[31m\u202e\u2028token']);
assert(result.status === 1, 'hostile endpoint fails');
assert(cleanOutput(result) && !/[\u202E\u2028]/u.test(result.stdout + result.stderr), 'hostile endpoint output is terminal safe');

result = run(['audit-endpoint', 'https://issuer.example/a', 'https://issuer.example/b']);
assert(result.status === 2, 'audit-endpoint usage error exits two');

result = run(['not-a-command']);
assert(result.status === 2, 'unknown command exits two');

console.log('CLI smoke test passed');
