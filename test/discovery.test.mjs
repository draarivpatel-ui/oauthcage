import test from 'node:test';
import assert from 'node:assert/strict';
import { auditDiscoveryMetadata, auditEndpointUrl, createOAuthPolicy } from '../src/index.mjs';
import { ISSUER, codes, hasCode, validDiscovery } from './helpers.mjs';

function expectEndpointFail(url, code, options) {
  const result = auditEndpointUrl(url, options);
  assert.equal(result.ok, false, 'expected endpoint failure for ' + url);
  if (code) assert.equal(hasCode(result, code), true, url + ' ' + JSON.stringify(codes(result)));
  return result;
}

function expectDiscoveryFail(input, code, options = { expectedIssuer: ISSUER }) {
  const result = auditDiscoveryMetadata(input, options);
  assert.equal(result.ok, false, 'expected discovery failure');
  if (code) assert.equal(hasCode(result, code), true, JSON.stringify(codes(result)));
  return result;
}

for (const [label, url] of [
  ['public domain', 'https://issuer.example/token'],
  ['public domain with deep path', 'https://issuer.example/oauth2/v1/token'],
  ['public IPv4 dns server', 'https://8.8.8.8/token'],
  ['public IPv4 cloudflare', 'https://1.1.1.1/token'],
  ['public IPv6 cloudflare', 'https://[2606:4700:4700::1111]/token'],
  ['explicit default port', 'https://issuer.example:443/token']
]) {
  test('endpoint accepts public HTTPS target for ' + label, () => {
    const result = auditEndpointUrl(url);
    assert.equal(result.ok, true, JSON.stringify(result.findings));
  });
}

test('endpoint accepts a custom port when policy explicitly allows it', () => {
  const policy = createOAuthPolicy('strict', { allowedEndpointPorts: ['443', '8443'] });
  const result = auditEndpointUrl('https://issuer.example:8443/token', { policy });
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

for (const [label, url] of [
  ['HTTP scheme', 'http://issuer.example/token'],
  ['FTP scheme', 'ftp://issuer.example/token'],
  ['javascript scheme', 'javascript:alert(1)'],
  ['missing scheme', 'issuer.example/token'],
  ['scheme relative', '//issuer.example/token'],
  ['uppercase HTTPS accepted shape with userinfo', 'HTTPS://user@issuer.example/token']
]) {
  test('endpoint rejects scheme or authority failure for ' + label, () => {
    const result = auditEndpointUrl(url);
    assert.equal(result.ok, false);
  });
}

for (const [label, url, expected] of [
  ['userinfo', 'https://user@issuer.example/token', 'OAUTHCAGE_ENDPOINT_USERINFO'],
  ['password userinfo', 'https://user:pass@issuer.example/token', 'OAUTHCAGE_ENDPOINT_USERINFO'],
  ['fragment', 'https://issuer.example/token#x', 'OAUTHCAGE_ENDPOINT_FRAGMENT'],
  ['query', 'https://issuer.example/token?x=1', 'OAUTHCAGE_ENDPOINT_QUERY_DENIED'],
  ['denied custom port', 'https://issuer.example:444/token', 'OAUTHCAGE_ENDPOINT_PORT_DENIED'],
  ['alpha port', 'https://issuer.example:abc/token', 'OAUTHCAGE_ENDPOINT_PORT_DENIED'],
  ['zero port', 'https://issuer.example:0/token', 'OAUTHCAGE_ENDPOINT_PORT_DENIED'],
  ['overflow port', 'https://issuer.example:65536/token', 'OAUTHCAGE_ENDPOINT_PORT_DENIED'],
  ['backslash', 'https://issuer.example\\token', null],
  ['whitespace', 'https://issuer.example/token path', null]
]) {
  test('endpoint rejects URL shape for ' + label, () => {
    expectEndpointFail(url, expected);
  });
}

for (const [label, host] of [
  ['localhost', 'localhost'],
  ['localhost trailing dot', 'localhost.'],
  ['subdomain localhost', 'x.localhost'],
  ['dot local', 'service.local'],
  ['dot internal', 'service.internal'],
  ['single label', 'intranet'],
  ['single numeric-looking label bypass', '2130706433x']
]) {
  test('endpoint rejects internal host ' + label, () => {
    expectEndpointFail('https://' + host + '/token', 'OAUTHCAGE_ENDPOINT_INTERNAL_HOST');
  });
}

for (const [label, address] of [
  ['unspecified octet zero', '0.0.0.0'],
  ['current network', '0.1.2.3'],
  ['private ten', '10.0.0.1'],
  ['private ten high', '10.255.255.255'],
  ['cgnat low', '100.64.0.1'],
  ['cgnat high', '100.127.255.254'],
  ['loopback exact', '127.0.0.1'],
  ['loopback high', '127.255.255.255'],
  ['link local', '169.254.0.1'],
  ['aws metadata', '169.254.169.254'],
  ['eks pod identity', '169.254.170.23'],
  ['private 172 low', '172.16.0.1'],
  ['private 172 high', '172.31.255.255'],
  ['private 192', '192.168.0.1'],
  ['documentation one', '192.0.2.1'],
  ['benchmark low', '198.18.0.1'],
  ['benchmark high', '198.19.255.255'],
  ['documentation two', '198.51.100.1'],
  ['documentation three', '203.0.113.1'],
  ['multicast low', '224.0.0.1'],
  ['multicast high', '239.255.255.255'],
  ['reserved low', '240.0.0.1'],
  ['broadcast', '255.255.255.255'],
  ['protocol anchor', '192.0.0.1']
]) {
  test('endpoint blocks IPv4 special range ' + label, () => {
    expectEndpointFail('https://' + address + '/token', null);
  });
}

for (const [label, host] of [
  ['decimal integer loopback', '2130706433'],
  ['hex integer loopback', '0x7f000001'],
  ['octal integer loopback', '017700000001'],
  ['shorthand two parts', '127.1'],
  ['shorthand three parts', '127.0.1'],
  ['octal octet', '0177.0.0.1'],
  ['hex octet', '0x7f.0.0.1'],
  ['mixed hex octet', '127.0x0.0.1'],
  ['leading zero decimal', '127.000.0.1'],
  ['overflow octet', '256.0.0.1'],
  ['overflow integer', '4294967296'],
  ['trailing dot numeric', '127.0.0.1.'],
  ['empty numeric label', '127..0.1']
]) {
  test('endpoint blocks ambiguous IPv4 representation ' + label, () => {
    const result = auditEndpointUrl('https://' + host + '/token');
    assert.equal(result.ok, false, label);
  });
}

for (const [label, address] of [
  ['unspecified', '::'],
  ['loopback', '::1'],
  ['unique local fc00', 'fc00::1'],
  ['unique local fd00', 'fd12::1'],
  ['EKS pod identity IPv6', 'fd00:ec2::23'],
  ['link local', 'fe80::1'],
  ['multicast', 'ff02::1'],
  ['documentation', '2001:db8::1'],
  ['discard', '100::'],
  ['reserved low', '4000::1']
]) {
  test('endpoint blocks IPv6 special range ' + label, () => {
    expectEndpointFail('https://[' + address + ']/token', null);
  });
}

for (const [label, address] of [
  ['IPv4 mapped dotted', '::ffff:192.0.0.1'],
  ['IPv4 mapped hex', '::ffff:c000:201'],
  ['IPv4 translated dotted', '::ffff:0:192.0.0.1'],
  ['IPv4 compatible dotted', '::192.0.0.1'],
  ['IPv4 compatible hex', '::c000:201'],
  ['NAT64 dotted', '64:ff9b::192.0.0.1'],
  ['NAT64 hex', '64:ff9b::c000:201'],
  ['NAT64 local use', '64:ff9b:1::1'],
  ['6to4 public embedding', '2002:c000:201::1'],
  ['6to4 private embedding', '2002:a00:1::1'],
  ['Teredo shape', '2001::c000:201'],
  ['Teredo zero shape', '2001::1']
]) {
  test('endpoint blocks IPv6 transition encoding ' + label, () => {
    expectEndpointFail('https://[' + address + ']/token', null);
  });
}

test('endpoint result is deeply frozen and does not expose raw URL secrets', () => {
  const result = auditEndpointUrl('https://issuer.example/token');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.findings), true);
  assert.equal(JSON.stringify(result).includes('client_secret'), false);
});

test('valid discovery object passes strict audit', () => {
  const result = auditDiscoveryMetadata(validDiscovery(), { expectedIssuer: ISSUER });
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.issuerMatches, true);
  assert.equal(result.requiredEndpointsPresent, true);
  assert.equal(result.endpointsAudited, 6);
});

test('valid discovery JSON string passes strict audit', () => {
  const result = auditDiscoveryMetadata(JSON.stringify(validDiscovery()), { expectedIssuer: ISSUER });
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

for (const [label, mutate, expected] of [
  ['missing issuer', (doc) => { delete doc.issuer; }, 'OAUTHCAGE_DISCOVERY_ISSUER_REQUIRED'],
  ['empty issuer', (doc) => { doc.issuer = ''; }, 'OAUTHCAGE_DISCOVERY_ISSUER_REQUIRED'],
  ['issuer host mismatch', (doc) => { doc.issuer = 'https://evil.example'; }, 'OAUTHCAGE_DISCOVERY_ISSUER_MISMATCH'],
  ['issuer path mismatch', (doc) => { doc.issuer = ISSUER + '/other'; }, 'OAUTHCAGE_DISCOVERY_ISSUER_MISMATCH'],
  ['issuer trailing slash mismatch', (doc) => { doc.issuer = ISSUER + '/'; }, 'OAUTHCAGE_DISCOVERY_ISSUER_MISMATCH'],
  ['issuer HTTP', (doc) => { doc.issuer = 'http://issuer.example'; }, null],
  ['issuer query', (doc) => { doc.issuer = ISSUER + '?x=1'; }, null]
]) {
  test('discovery rejects issuer failure for ' + label, () => {
    const doc = validDiscovery();
    mutate(doc);
    expectDiscoveryFail(doc, expected);
  });
}

test('discovery accepts issuer host case canonicalization', () => {
  const result = auditDiscoveryMetadata(validDiscovery({ issuer: 'https://ISSUER.EXAMPLE' }), { expectedIssuer: ISSUER });
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

test('discovery requires expectedIssuer', () => {
  expectDiscoveryFail(validDiscovery(), 'OAUTHCAGE_ISSUER_EXPECTED_REQUIRED', {});
});

for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
  test('discovery requires endpoint ' + key, () => {
    const doc = validDiscovery();
    delete doc[key];
    expectDiscoveryFail(doc, 'OAUTHCAGE_DISCOVERY_ENDPOINT_REQUIRED');
  });
}

for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'revocation_endpoint', 'pushed_authorization_request_endpoint']) {
  test('discovery rejects insecure endpoint URL in ' + key, () => {
    expectDiscoveryFail(validDiscovery({ [key]: 'http://issuer.example/insecure' }), 'OAUTHCAGE_ENDPOINT_SCHEME_DENIED');
  });
}

for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
  test('discovery endpoint type must be a string for ' + key, () => {
    expectDiscoveryFail(validDiscovery({ [key]: 42 }), 'OAUTHCAGE_ENDPOINT_INVALID');
  });
}

for (const [label, endpoint] of [
  ['loopback IPv4', 'https://127.0.0.1/jwks'],
  ['private IPv4', 'https://10.0.0.8/jwks'],
  ['metadata IPv4', 'https://169.254.169.254/latest/meta-data'],
  ['pod identity IPv4', 'https://169.254.170.23/v1/credentials'],
  ['mapped IPv6 loopback', 'https://[::ffff:127.0.0.1]/jwks'],
  ['pod identity IPv6', 'https://[fd00:ec2::23]/jwks'],
  ['internal name', 'https://keys.internal/jwks'],
  ['localhost name', 'https://localhost/jwks']
]) {
  test('discovery blocks SSRF-sensitive jwks_uri target ' + label, () => {
    expectDiscoveryFail(validDiscovery({ jwks_uri: endpoint }), null);
  });
}

for (const [label, algorithms, expected] of [
  ['none algorithm', ['none'], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM'],
  ['none plus RS256', ['RS256', 'none'], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM'],
  ['HS256 symmetric', ['HS256'], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM'],
  ['HS384 symmetric', ['HS384'], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM'],
  ['HS512 symmetric', ['HS512'], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM'],
  ['missing asymmetric', ['Ed25519'], 'OAUTHCAGE_DISCOVERY_ASYMMETRIC_REQUIRED'],
  ['empty array', [], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM'],
  ['non-string member', ['RS256', 7], 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM']
]) {
  test('discovery rejects signing algorithm metadata for ' + label, () => {
    expectDiscoveryFail(validDiscovery({ id_token_signing_alg_values_supported: algorithms }), expected);
  });
}

test('discovery rejects missing signing algorithm metadata', () => {
  const doc = validDiscovery();
  delete doc.id_token_signing_alg_values_supported;
  expectDiscoveryFail(doc, 'OAUTHCAGE_DISCOVERY_INSECURE_ALGORITHM');
});

for (const algorithms of [['RS256'], ['ES256'], ['PS256'], ['EdDSA'], ['RS256', 'ES384', 'PS512']]) {
  test('discovery accepts asymmetric algorithm set ' + algorithms.join(','), () => {
    const result = auditDiscoveryMetadata(validDiscovery({ id_token_signing_alg_values_supported: algorithms }), { expectedIssuer: ISSUER });
    assert.equal(result.ok, true, JSON.stringify(result.findings));
  });
}

for (const [label, responseType] of [
  ['implicit token', 'token'],
  ['implicit id_token', 'id_token'],
  ['implicit pair', 'id_token token'],
  ['hybrid code token', 'code token'],
  ['hybrid code id_token', 'code id_token']
]) {
  test('discovery rejects advertised implicit or hybrid flow ' + label, () => {
    expectDiscoveryFail(validDiscovery({ response_types_supported: ['code', responseType] }), 'OAUTHCAGE_DISCOVERY_INSECURE_FLOW');
  });
}

test('discovery rejects advertised ROPC grant', () => {
  expectDiscoveryFail(validDiscovery({ grant_types_supported: ['authorization_code', 'password'] }), 'OAUTHCAGE_DISCOVERY_INSECURE_FLOW');
});

test('discovery rejects plain PKCE advertisement', () => {
  expectDiscoveryFail(validDiscovery({ code_challenge_methods_supported: ['S256', 'plain'] }), 'OAUTHCAGE_DISCOVERY_INSECURE_FLOW');
});

test('discovery rejects missing S256 in advertised methods', () => {
  expectDiscoveryFail(validDiscovery({ code_challenge_methods_supported: ['plain'] }), 'OAUTHCAGE_DISCOVERY_PKCE_MISSING');
});

test('discovery rejects absent PKCE methods in strict policy', () => {
  const doc = validDiscovery();
  delete doc.code_challenge_methods_supported;
  expectDiscoveryFail(doc, 'OAUTHCAGE_DISCOVERY_PKCE_MISSING');
});

for (const key of ['__proto__', 'constructor', 'prototype']) {
  test('discovery rejects top-level prototype pollution key ' + key, () => {
    const doc = JSON.parse('{"' + key + '":{}}');
    Object.assign(doc, validDiscovery());
    expectDiscoveryFail(doc, 'OAUTHCAGE_PROTOTYPE_POLLUTION');
  });

  test('discovery rejects nested prototype pollution key ' + key, () => {
    const doc = validDiscovery({ nested: JSON.parse('{"' + key + '":{}}') });
    expectDiscoveryFail(doc, 'OAUTHCAGE_PROTOTYPE_POLLUTION');
  });
}

test('discovery rejects a cyclic object without hanging', () => {
  const doc = validDiscovery();
  doc.self = doc;
  expectDiscoveryFail(doc, 'OAUTHCAGE_RESOURCE_LIMIT');
});

test('discovery rejects excessive depth', () => {
  let nested = {};
  let root = nested;
  for (let index = 0; index < 14; index += 1) {
    nested.next = {};
    nested = nested.next;
  }
  expectDiscoveryFail(validDiscovery({ nested: root }), 'OAUTHCAGE_RESOURCE_LIMIT');
});

test('discovery rejects excessive key count', () => {
  const extra = {};
  for (let index = 0; index < 270; index += 1) extra['k' + index] = index;
  expectDiscoveryFail(validDiscovery({ extra }), 'OAUTHCAGE_RESOURCE_LIMIT');
});

for (const [label, input] of [
  ['invalid JSON', '{not json'],
  ['empty JSON string', ''],
  ['JSON array', '[]'],
  ['JSON string scalar', '"text"'],
  ['JSON null', 'null'],
  ['nonobject input array', []]
]) {
  test('discovery rejects malformed document input for ' + label, () => {
    expectDiscoveryFail(input, null);
  });
}

test('discovery rejects oversized JSON input', () => {
  const large = '{"issuer":"' + 'a'.repeat(140000) + '"}';
  expectDiscoveryFail(large, 'OAUTHCAGE_RESOURCE_LIMIT');
});

test('discovery endpoint query is denied by default', () => {
  expectDiscoveryFail(validDiscovery({ jwks_uri: ISSUER + '/keys?x=1' }), 'OAUTHCAGE_ENDPOINT_QUERY_DENIED');
});

test('discovery result is deeply frozen', () => {
  const result = auditDiscoveryMetadata(validDiscovery(), { expectedIssuer: ISSUER });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.findings), true);
  assert.throws(() => {
    result.issuerMatches = false;
  }, TypeError);
});
