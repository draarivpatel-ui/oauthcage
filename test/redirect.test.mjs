import test from 'node:test';
import assert from 'node:assert/strict';
import { auditRedirectUri, validateRedirectUri } from '../src/index.mjs';
import { codes, hasCode } from './helpers.mjs';

const BASE = 'https://app.example/callback';

function expectOk(candidate, registered, options) {
  const result = auditRedirectUri(candidate, registered, options);
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.matched, true);
  return result;
}

function expectFail(candidate, registered, code, options) {
  const result = auditRedirectUri(candidate, registered, options);
  assert.equal(result.ok, false, 'expected failure for ' + String(candidate));
  if (code) assert.equal(hasCode(result, code), true, JSON.stringify(codes(result)));
  return result;
}


for (const [label, encoded] of [
  ['encoded slash', '%2F'],
  ['encoded backslash', '%5C'],
  ['encoded carriage return', '%0D'],
  ['encoded line feed', '%0A'],
  ['encoded nul', '%00'],
  ['encoded space', '%20'],
  ['encoded bidi override', '%E2%80%AE']
]) {
  test('redirect rejects hostile encoded path byte for ' + label, () => {
    const uri = 'https://app.example/a' + encoded + 'b';
    expectFail(uri, [uri], null);
  });
}

for (const [label, encoded] of [
  ['encoded carriage return', '%0D'],
  ['encoded line feed', '%0A'],
  ['encoded nul', '%00'],
  ['encoded space', '%20'],
  ['encoded bidi override', '%E2%80%AE']
]) {
  test('redirect rejects hostile encoded query byte for ' + label, () => {
    const uri = 'https://app.example/callback?x=a' + encoded + 'b';
    expectFail(uri, [uri], null);
  });
}

for (const [label, candidate, registered] of [
  ['simple path', BASE, [BASE]],
  ['root slash', 'https://app.example/', ['https://app.example/']],
  ['empty path', 'https://app.example', ['https://app.example']],
  ['query exact', 'https://app.example/cb?x=1&y=2', ['https://app.example/cb?x=1&y=2']],
  ['explicit port exact', 'https://app.example:8443/cb', ['https://app.example:8443/cb']],
  ['public ipv4 exact', 'https://192.0.1.10/cb', ['https://192.0.1.10/cb']],
  ['ipv6 loopback https exact', 'https://[::1]/cb', ['https://[::1]/cb']],
  ['uppercase scheme and host', 'HTTPS://APP.EXAMPLE/callback', [BASE]],
  ['unreserved percent canonicalization', 'https://app.example/%7Eabc', ['https://app.example/~abc']],
  ['uppercase percent hex canonicalization', 'https://app.example/%2dabc', ['https://app.example/%2Dabc']],
  ['multiple registered exact selection', 'https://app.example/two', ['https://app.example/one', 'https://app.example/two']],
  ['punycode unicode canonical match', 'https://bücher.example/cb', ['https://xn--bcher-kva.example/cb']]
]) {
  test('valid redirect exact match for ' + label, () => {
    const result = expectOk(candidate, registered);
    assert.equal(typeof result.uri, 'string');
  });
}

for (const [label, candidate] of [
  ['prefix extension', BASE + '/evil'],
  ['prefix truncation', 'https://app.example/call'],
  ['subdomain prefix', 'https://evil.app.example/callback'],
  ['suffix host confusion', 'https://app.example.evil/callback'],
  ['missing path slash', 'https://app.examplecallback'],
  ['extra path slash', BASE + '/'],
  ['root slash against empty path', 'https://app.example/'],
  ['explicit default port difference', 'https://app.example:443/callback'],
  ['query parameter order difference', 'https://app.example/callback?b=2&a=1'],
  ['case sensitive path difference', 'https://app.example/Callback'],
  ['trailing dot host difference', 'https://app.example./callback']
]) {
  test('redirect mismatch rejects ' + label, () => {
    const registered = label === 'query parameter order difference' ? ['https://app.example/callback?a=1&b=2'] : [label === 'root slash against empty path' ? 'https://app.example' : BASE];
    expectFail(candidate, registered, 'OAUTHCAGE_REDIRECT_MISMATCH');
  });
}

for (const scheme of ['javascript', 'data', 'vbscript', 'file', 'blob', 'filesystem']) {
  test('dangerous scheme rejected: ' + scheme, () => {
    const uri = scheme + ':alert(1)';
    const result = expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_DANGEROUS_SCHEME');
    assert.equal(result.matched, false);
  });
}

for (const scheme of ['JavaScript', 'DATA', 'VbScript', 'FILE']) {
  test('dangerous scheme rejected case independently: ' + scheme, () => {
    const uri = scheme + ':alert(1)';
    expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_DANGEROUS_SCHEME');
  });
}

for (const [label, candidate] of [
  ['empty string', ''],
  ['relative path', '/callback'],
  ['scheme relative', '//app.example/callback'],
  ['host without scheme', 'app.example/callback'],
  ['space before scheme', ' https://app.example/callback'],
  ['space after host', 'https://app.example /callback'],
  ['newline inside', 'https://app.example/call\nback'],
  ['tab inside', 'https://app.example/call\tback'],
  ['carriage return inside', 'https://app.example/call\rback'],
  ['nul inside', 'https://app.example/call\0back'],
  ['bidi override', 'https://app.example/call\u202eback'],
  ['zero width character', 'https://app.example/call\u200bback']
]) {
  test('malformed redirect rejected for ' + label, () => {
    const result = auditRedirectUri(candidate, [BASE]);
    assert.equal(result.ok, false);
  });
}

for (const [label, fragment] of [
  ['simple fragment', '#x'],
  ['empty fragment', '#'],
  ['fragment with token shape', '#access_token=value']
]) {
  test('redirect fragment rejected for ' + label, () => {
    expectFail(BASE + fragment, [BASE + fragment], 'OAUTHCAGE_REDIRECT_FRAGMENT');
  });
}

for (const [label, hostpart] of [
  ['user name', 'user@'],
  ['user and password', 'user:pass@'],
  ['empty userinfo delimiter', '@']
]) {
  test('redirect userinfo rejected for ' + label, () => {
    const uri = 'https://' + hostpart + 'app.example/callback';
    expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_USERINFO');
  });
}

for (const [label, path] of [
  ['raw backslash', '/call\\back'],
  ['leading backslash', '\\callback'],
  ['double backslash', '/call\\\\back'],
  ['encoded backslash lower', '/call%5cback'],
  ['encoded backslash upper', '/call%5Cback'],
  ['encoded slash lower', '/call%2fevil'],
  ['encoded slash upper', '/call%2Fevil']
]) {
  test('redirect separator confusion rejected for ' + label, () => {
    const uri = 'https://app.example' + path;
    const result = auditRedirectUri(uri, [uri]);
    assert.equal(result.ok, false);
    assert.equal(
      hasCode(result, 'OAUTHCAGE_REDIRECT_BACKSLASH') || hasCode(result, 'OAUTHCAGE_REDIRECT_PATH_TRAVERSAL'),
      true,
      JSON.stringify(codes(result))
    );
  });
}

for (const [label, path] of [
  ['parent segment', '/a/../b'],
  ['final parent segment', '/a/..'],
  ['dot segment', '/a/./b'],
  ['encoded dot one', '/a/%2e/b'],
  ['encoded dot upper', '/a/%2E/b'],
  ['encoded dotdot', '/a/%2e%2e/b'],
  ['mixed encoded dotdot', '/a/.%2e/b'],
  ['encoded first dotdot', '/a/%2e./b'],
  ['double encoded shape', '/a/%252e%252e/b'],
  ['three dot segment', '/a/.../b'],
  ['dot segment at root', '/../b'],
  ['encoded slash traversal', '/a/..%2fb'],
  ['encoded backslash traversal', '/a/..%5cb'],
  ['unicode escape style text', '/a/%u002e%u002e/b']
]) {
  test('redirect path traversal rejected for ' + label, () => {
    const uri = 'https://app.example' + path;
    const result = auditRedirectUri(uri, [uri]);
    assert.equal(result.ok, false, label);
  });
}

for (const [label, path] of [
  ['double slash after root', '//evil'],
  ['double slash in middle', '/a//b'],
  ['triple slash in middle', '/a///b'],
  ['many slashes', '////'],
  ['double slash before query', '/cb//']
]) {
  test('redirect repeated slash rejected for ' + label, () => {
    const uri = 'https://app.example' + path;
    expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_DOUBLE_SLASH');
  });
}

for (const [label, uri] of [
  ['public HTTP host', 'http://app.example/cb'],
  ['loopback IPv4 HTTP in strict', 'http://127.0.0.1/cb'],
  ['loopback IPv6 HTTP in strict', 'http://[::1]/cb'],
  ['localhost HTTP in strict', 'http://localhost/cb']
]) {
  test('strict policy rejects HTTP redirect for ' + label, () => {
    const result = auditRedirectUri(uri, [uri]);
    assert.equal(result.ok, false);
    assert.equal(hasCode(result, 'OAUTHCAGE_REDIRECT_SCHEME_DENIED') || hasCode(result, 'OAUTHCAGE_REDIRECT_HTTP_NOT_LOOPBACK'), true);
  });
}

for (const [label, uri] of [
  ['loopback IPv4 native', 'http://127.0.0.1:8080/cb'],
  ['loopback IPv6 native', 'http://[::1]:8080/cb']
]) {
  test('native policy permits exact RFC 8252 loopback HTTP for ' + label, () => {
    expectOk(uri, [uri], { policy: 'native' });
  });
}

for (const [label, uri] of [
  ['public HTTP host native', 'http://app.example/cb'],
  ['localhost native default', 'http://localhost:8080/cb'],
  ['other 127 address', 'http://127.0.0.2:8080/cb'],
  ['decimal loopback', 'http://2130706433:8080/cb'],
  ['shorthand loopback', 'http://127.1:8080/cb'],
  ['hex loopback', 'http://0x7f000001:8080/cb']
]) {
  test('native policy rejects unsafe loopback bypass for ' + label, () => {
    const result = auditRedirectUri(uri, [uri], { policy: 'native' });
    assert.equal(result.ok, false);
  });
}

test('native policy can explicitly enable localhost HTTP', () => {
  const uri = 'http://localhost:8080/cb';
  expectOk(uri, [uri], { policy: 'native', allowLocalhostHttp: true });
});

test('custom reverse-domain scheme requires exact explicit allowlist and passes with warning', () => {
  const uri = 'com.example.app:/callback';
  const result = expectOk(uri, [uri], {
    policy: 'native',
    allowCustomSchemes: true,
    allowedCustomSchemes: ['com.example.app']
  });
  assert.equal(hasCode(result, 'OAUTHCAGE_REDIRECT_CUSTOM_SCHEME'), true);
  assert.equal(result.findings.some((finding) => finding.severity === 'warning'), true);
});

for (const [label, uri, options] of [
  ['default custom scheme', 'com.example.app:/callback', { policy: 'native' }],
  ['unqualified custom scheme', 'myapp:/callback', { policy: 'native', allowCustomSchemes: true, allowedCustomSchemes: ['myapp'] }],
  ['different custom scheme', 'com.evil.app:/callback', { policy: 'native', allowCustomSchemes: true, allowedCustomSchemes: ['com.example.app'] }]
]) {
  test('custom scheme rejected for ' + label, () => {
    expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_CUSTOM_SCHEME', options);
  });
}

for (const [label, uri] of [
  ['empty authority', 'https:///cb'],
  ['missing authority', 'https:app.example/cb'],
  ['empty host with port', 'https://:443/cb'],
  ['unbracketed ipv6', 'https://::1/cb'],
  ['unclosed ipv6 bracket', 'https://[::1/cb'],
  ['unexpected ipv6 suffix', 'https://[::1]x/cb'],
  ['alpha port', 'https://app.example:abc/cb'],
  ['empty port', 'https://app.example:/cb'],
  ['port zero', 'https://app.example:0/cb'],
  ['port overflow', 'https://app.example:65536/cb'],
  ['negative port shape', 'https://app.example:-1/cb'],
  ['underscore host', 'https://bad_host.example/cb'],
  ['host percent encoding', 'https://app%2eexample/cb'],
  ['empty dns label', 'https://app..example/cb'],
  ['oversized dns label', 'https://' + 'a'.repeat(64) + '.example/cb'],
  ['oversized host', 'https://' + 'a'.repeat(250) + '.example/cb']
]) {
  test('redirect host or port rejected for ' + label, () => {
    const result = auditRedirectUri(uri, [uri]);
    assert.equal(result.ok, false, label);
  });
}

for (const [label, host] of [
  ['shorthand loopback', '127.1'],
  ['two part shorthand', '127.0.1'],
  ['decimal integer loopback', '2130706433'],
  ['hex integer loopback', '0x7f000001'],
  ['octal first octet', '0177.0.0.1'],
  ['hex octet', '0x7f.0.0.1'],
  ['leading zero decimal', '127.000.0.1'],
  ['overflow octet', '256.0.0.1'],
  ['overflow integer', '4294967296']
]) {
  test('ambiguous IPv4 host rejected for ' + label, () => {
    const uri = 'https://' + host + '/cb';
    expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_HOST_INVALID');
  });
}

for (const name of ['access_token', 'id_token', 'client_secret', 'refresh_token', 'code_verifier', 'password', 'code']) {
  test('redirect URI query secret parameter rejected: ' + name, () => {
    const uri = BASE + '?' + name + '=value';
    expectFail(uri, [uri], 'OAUTHCAGE_REDIRECT_SECRET_IN_QUERY');
  });
}

for (const [label, query] of [
  ['malformed percent end', 'x=%'],
  ['malformed percent short', 'x=%1'],
  ['malformed percent hex', 'x=%GG'],
  ['encoded nul', 'x=%00'],
  ['encoded newline', 'x=%0A'],
  ['invalid utf8', 'x=%ff']
]) {
  test('redirect query encoding rejected for ' + label, () => {
    const uri = BASE + '?' + query;
    const result = auditRedirectUri(uri, [uri]);
    assert.equal(result.ok, false, label);
  });
}

test('maximum URI length is enforced', () => {
  const longPath = '/'.repeat(1) + 'a'.repeat(2048);
  const result = auditRedirectUri('https://app.example' + longPath, [BASE]);
  assert.equal(result.ok, false);
  assert.equal(hasCode(result, 'OAUTHCAGE_INPUT_TOO_LONG'), true);
});

test('custom maximum URI length can be tightened', () => {
  const result = auditRedirectUri(BASE + '/' + 'a'.repeat(140), [BASE + '/' + 'a'.repeat(140)], { maxUriLength: 128 });
  assert.equal(result.ok, false);
  assert.equal(hasCode(result, 'OAUTHCAGE_INPUT_TOO_LONG'), true);
});

test('empty registered allowlist is rejected', () => {
  expectFail(BASE, [], 'OAUTHCAGE_REDIRECT_ALLOWLIST_REQUIRED');
});

test('unsafe registered URI is rejected even when candidate matches it', () => {
  const registered = 'https://app.example/a/../callback';
  const result = auditRedirectUri(registered, [registered]);
  assert.equal(result.ok, false);
  assert.equal(codes(result).filter((code) => code === 'OAUTHCAGE_REDIRECT_PATH_TRAVERSAL').length >= 1, true);
});

test('redirect audit result is deeply frozen', () => {
  const result = expectOk(BASE, [BASE]);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.findings), true);
  assert.equal(Object.isFrozen(result.meta), true);
  assert.throws(() => {
    result.ok = false;
  }, TypeError);
});

test('validateRedirectUri returns canonical URI on success', () => {
  assert.equal(validateRedirectUri('HTTPS://APP.EXAMPLE/callback', [BASE]), BASE);
});

test('validateRedirectUri throws a typed error without echoing the candidate', () => {
  const hostile = 'https://app.example/callback/../secret-token-value';
  try {
    validateRedirectUri(hostile, [BASE]);
    assert.fail('expected redirect validation failure');
  } catch (error) {
    assert.equal(error.name, 'OAuthCageError');
    assert.match(error.code, /^OAUTHCAGE_/u);
    assert.equal(error.message.includes('secret-token-value'), false);
  }
});

for (const [label, candidate, registered] of [
  ['encoded question mark stays distinct', 'https://app.example/a%3Fb', ['https://app.example/a?b']],
  ['path case remains distinct', 'https://app.example/Case', ['https://app.example/case']],
  ['explicit nondefault port remains distinct', 'https://app.example:444/cb', ['https://app.example:443/cb']]
]) {
  test('canonical exact matching does not collapse security significant form: ' + label, () => {
    expectFail(candidate, registered, 'OAUTHCAGE_REDIRECT_MISMATCH');
  });
}
