import test from 'node:test';
import assert from 'node:assert/strict';
import { auditAuthRequest, auditCallback, auditTokenRequest } from '../src/index.mjs';
import {
  AUTH_CODE,
  CHALLENGE,
  ISSUER,
  NONCE,
  REDIRECT_URI,
  STATE,
  VERIFIER,
  codes,
  hasCode,
  serialized,
  validAuthParams,
  validAuthQuery,
  validCallbackOptions,
  validCallbackQuery,
  validTokenBody,
  validTokenOptions
} from './helpers.mjs';

const AUTH_OPTIONS = Object.freeze({
  registeredRedirectUris: [REDIRECT_URI],
  allowedScopes: ['openid', 'profile', 'email']
});

function expectAuthFail(input, code, options = AUTH_OPTIONS) {
  const result = auditAuthRequest(input, options);
  assert.equal(result.ok, false, 'expected authorization request failure');
  if (code) assert.equal(hasCode(result, code), true, JSON.stringify(codes(result)));
  return result;
}

function expectCallbackFail(input, code, options = validCallbackOptions()) {
  const result = auditCallback(input, options);
  assert.equal(result.ok, false, 'expected callback failure');
  if (code) assert.equal(hasCode(result, code), true, JSON.stringify(codes(result)));
  return result;
}

function expectTokenFail(input, code, options = validTokenOptions()) {
  const result = auditTokenRequest(input, options);
  assert.equal(result.ok, false, 'expected token request failure');
  if (code) assert.equal(hasCode(result, code), true, JSON.stringify(codes(result)));
  return result;
}

test('valid strict authorization request passes from encoded query input', () => {
  const result = auditAuthRequest(validAuthQuery(), AUTH_OPTIONS);
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.flow, 'authorization_code');
  assert.equal(result.hasPkce, true);
  assert.equal(result.hasState, true);
});

test('valid authorization request passes from object input', () => {
  const result = auditAuthRequest(validAuthParams(), AUTH_OPTIONS);
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

test('valid authorization request passes in spa preset', () => {
  const result = auditAuthRequest(validAuthQuery(), { ...AUTH_OPTIONS, policy: 'spa' });
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

test('confidential preset requires pushed authorization requests', () => {
  const result = auditAuthRequest(validAuthQuery(), { ...AUTH_OPTIONS, policy: 'confidential' });
  assert.equal(result.ok, false);
  assert.equal(hasCode(result, 'OAUTHCAGE_PAR_REQUIRED'), true);
});

test('confidential preset accepts a bounded PAR request URI', () => {
  const query = validAuthQuery({ request_uri: 'urn:ietf:params:oauth:request_uri:abcdefgh123456' });
  const result = auditAuthRequest(query, { ...AUTH_OPTIONS, policy: 'confidential' });
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.usesPar, true);
});

for (const [label, mutate] of [
  ['missing response_type', (params) => { delete params.response_type; }],
  ['implicit token', (params) => { params.response_type = 'token'; }],
  ['implicit id_token', (params) => { params.response_type = 'id_token'; }],
  ['implicit both ordered', (params) => { params.response_type = 'id_token token'; }],
  ['implicit both reverse', (params) => { params.response_type = 'token id_token'; }],
  ['hybrid code token', (params) => { params.response_type = 'code token'; }],
  ['hybrid code id_token', (params) => { params.response_type = 'code id_token'; }],
  ['typo response type', (params) => { params.response_type = 'codex'; }],
  ['uppercase response type', (params) => { params.response_type = 'CODE'; }]
]) {
  test('authorization request rejects ' + label, () => {
    const params = validAuthParams();
    mutate(params);
    const expected = label.includes('implicit') || label.includes('hybrid') ? 'OAUTHCAGE_IMPLICIT_GRANT_DENIED' : null;
    expectAuthFail(new URLSearchParams(params).toString(), expected);
  });
}

for (const [label, clientId] of [
  ['missing', undefined],
  ['empty', ''],
  ['space', 'bad client'],
  ['newline', 'bad\nclient'],
  ['control', 'bad\x01client'],
  ['oversized', 'a'.repeat(257)]
]) {
  test('authorization request rejects client_id ' + label, () => {
    const params = validAuthParams();
    if (clientId === undefined) delete params.client_id;
    else params.client_id = clientId;
    expectAuthFail(new URLSearchParams(params).toString(), 'OAUTHCAGE_CLIENT_ID_INVALID');
  });
}

for (const [label, mutate, expected] of [
  ['missing redirect_uri', (params) => { delete params.redirect_uri; }, 'OAUTHCAGE_REDIRECT_INVALID'],
  ['unregistered redirect_uri', (params) => { params.redirect_uri = 'https://app.example/other'; }, 'OAUTHCAGE_REDIRECT_MISMATCH'],
  ['traversal redirect_uri', (params) => { params.redirect_uri = REDIRECT_URI + '/../evil'; }, 'OAUTHCAGE_REDIRECT_PATH_TRAVERSAL'],
  ['HTTP redirect_uri', (params) => { params.redirect_uri = 'http://app.example/callback'; }, null]
]) {
  test('authorization request rejects ' + label, () => {
    const params = validAuthParams();
    mutate(params);
    expectAuthFail(new URLSearchParams(params).toString(), expected);
  });
}

test('authorization request requires registered redirect allowlist in strict policy', () => {
  expectAuthFail(validAuthQuery(), 'OAUTHCAGE_REDIRECT_ALLOWLIST_REQUIRED', {});
});

for (const [label, state] of [
  ['missing', undefined],
  ['short', 'abc'],
  ['repeated', 'a'.repeat(32)],
  ['sequential', 'abcdefghijklmnopqrstuvwx'],
  ['space', STATE.slice(0, 4) + ' ' + STATE.slice(5)],
  ['nonascii', STATE.slice(0, 4) + 'é' + STATE.slice(5)]
]) {
  test('authorization request rejects state ' + label, () => {
    const params = validAuthParams();
    if (state === undefined) delete params.state;
    else params.state = state;
    const result = expectAuthFail(new URLSearchParams(params).toString(), null);
    assert.equal(codes(result).some((code) => code.startsWith('OAUTHCAGE_STATE')), true);
  });
}

for (const [label, nonce] of [
  ['short', 'abc'],
  ['repeated', 'n'.repeat(32)],
  ['space', NONCE.slice(0, 4) + ' ' + NONCE.slice(5)]
]) {
  test('authorization request rejects nonce ' + label, () => {
    expectAuthFail(validAuthQuery({ nonce }), null);
  });
}

test('authorization request accepts a valid nonce', () => {
  const result = auditAuthRequest(validAuthQuery({ nonce: NONCE }), AUTH_OPTIONS);
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

for (const [label, mutate, expected] of [
  ['missing PKCE challenge', (params) => { delete params.code_challenge; }, 'OAUTHCAGE_PKCE_REQUIRED'],
  ['missing challenge method', (params) => { delete params.code_challenge_method; }, 'OAUTHCAGE_PKCE_PLAIN_DOWNGRADE'],
  ['plain challenge method', (params) => { params.code_challenge_method = 'plain'; }, 'OAUTHCAGE_PKCE_PLAIN_DOWNGRADE'],
  ['lowercase method', (params) => { params.code_challenge_method = 's256'; }, 'OAUTHCAGE_PKCE_METHOD_DENIED'],
  ['unknown method', (params) => { params.code_challenge_method = 'S512'; }, 'OAUTHCAGE_PKCE_METHOD_DENIED'],
  ['short challenge', (params) => { params.code_challenge = 'abc'; }, 'OAUTHCAGE_PKCE_INVALID_CHALLENGE'],
  ['padded challenge', (params) => { params.code_challenge = CHALLENGE.slice(0, -1) + '='; }, 'OAUTHCAGE_PKCE_INVALID_CHALLENGE'],
  ['method without challenge', (params) => { delete params.code_challenge; }, 'OAUTHCAGE_PKCE_REQUIRED']
]) {
  test('authorization request rejects ' + label, () => {
    const params = validAuthParams();
    mutate(params);
    expectAuthFail(new URLSearchParams(params).toString(), expected);
  });
}

for (const [label, scope, options, expected] of [
  ['control injection', 'openid%0aadmin', AUTH_OPTIONS, null],
  ['duplicate scope', 'openid openid', AUTH_OPTIONS, 'OAUTHCAGE_SCOPE_INVALID'],
  ['outside allowlist', 'openid admin', AUTH_OPTIONS, 'OAUTHCAGE_SCOPE_DENIED'],
  ['denylist hit', 'openid admin', { ...AUTH_OPTIONS, deniedScopes: ['admin'] }, 'OAUTHCAGE_SCOPE_DENIED'],
  ['double spacing', 'openid  profile', AUTH_OPTIONS, 'OAUTHCAGE_SCOPE_INVALID'],
  ['leading space', ' openid', AUTH_OPTIONS, 'OAUTHCAGE_SCOPE_INVALID'],
  ['quote injection', 'openid"admin', AUTH_OPTIONS, 'OAUTHCAGE_SCOPE_INVALID'],
  ['backslash injection', 'openid\\admin', AUTH_OPTIONS, 'OAUTHCAGE_SCOPE_INVALID']
]) {
  test('authorization request rejects scope ' + label, () => {
    expectAuthFail(validAuthQuery({ scope }), expected, options);
  });
}

for (const scope of ['openid', 'openid profile', 'openid profile email']) {
  test('authorization request accepts scope set ' + scope, () => {
    const result = auditAuthRequest(validAuthQuery({ scope }), AUTH_OPTIONS);
    assert.equal(result.ok, true, JSON.stringify(result.findings));
  });
}

test('fragment response mode is rejected in authorization request', () => {
  expectAuthFail(validAuthQuery({ response_mode: 'fragment' }), 'OAUTHCAGE_RESPONSE_MODE_DENIED');
});

for (const [label, requestUri] of [
  ['https instead of URN', 'https://issuer.example/request'],
  ['short opaque URN', 'urn:x:abc'],
  ['whitespace URN', 'urn:ietf:params:oauth:request_uri:abc def'],
  ['oversized URN', 'urn:ietf:params:oauth:request_uri:' + 'a'.repeat(520)]
]) {
  test('authorization request rejects request_uri ' + label, () => {
    expectAuthFail(validAuthQuery({ request_uri: requestUri }), 'OAUTHCAGE_REQUEST_URI_INVALID', { ...AUTH_OPTIONS, policy: 'confidential' });
  });
}

for (const name of ['access_token', 'id_token', 'refresh_token', 'client_secret', 'code_verifier', 'password', 'code']) {
  test('authorization request rejects embedded secret parameter ' + name, () => {
    expectAuthFail(validAuthQuery({ [name]: 'secret-value' }), 'OAUTHCAGE_SECRET_LEAK');
  });
}

for (const name of ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge']) {
  test('authorization request detects duplicate parameter ' + name, () => {
    const first = validAuthQuery();
    const second = new URLSearchParams(validAuthParams({ [name]: 'duplicate-value' })).toString().split('&').find((piece) => piece.startsWith(encodeURIComponent(name) + '=') || piece.startsWith(name + '='));
    const result = expectAuthFail(first + '&' + name + '=duplicate', 'OAUTHCAGE_DUPLICATE_PARAMETER');
    assert.equal(result.ok, false);
    void second;
  });
}

test('authorization request enforces parameter count cap', () => {
  const extras = Array.from({ length: 65 }, (_, index) => 'x' + index + '=v').join('&');
  expectAuthFail(validAuthQuery() + '&' + extras, 'OAUTHCAGE_PARAMETER_COUNT_EXCEEDED');
});

test('authorization request enforces parameter length cap', () => {
  expectAuthFail(validAuthQuery({ scope: 'openid' }) + '&long=' + 'a'.repeat(5000), 'OAUTHCAGE_PARAMETER_TOO_LONG');
});

test('valid strict callback passes', () => {
  const result = auditCallback(validCallbackQuery(), validCallbackOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.hasCode, true);
  assert.equal(result.hasIssuer, true);
  assert.equal(result.hasState, true);
});

test('valid OAuth error callback with state and issuer passes shape audit', () => {
  const query = new URLSearchParams({ error: 'access_denied', state: STATE, iss: ISSUER }).toString();
  const result = auditCallback(query, validCallbackOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.errorResponse, true);
});

for (const [label, mutate, expected] of [
  ['missing code', (params) => { delete params.code; }, 'OAUTHCAGE_CALLBACK_CODE_REQUIRED'],
  ['error and code together', (params) => { params.error = 'access_denied'; }, 'OAUTHCAGE_CALLBACK_ERROR_AND_CODE'],
  ['short code', (params) => { params.code = 'abc'; }, 'OAUTHCAGE_CALLBACK_CODE_INVALID'],
  ['space in code', (params) => { params.code = 'abc def'; }, 'OAUTHCAGE_CALLBACK_CODE_INVALID'],
  ['control in code', (params) => { params.code = 'abc\x01def'; }, null],
  ['oversized code', (params) => { params.code = 'a'.repeat(2100); }, 'OAUTHCAGE_CALLBACK_CODE_INVALID']
]) {
  test('callback rejects ' + label, () => {
    const params = { code: AUTH_CODE, state: STATE, iss: ISSUER };
    mutate(params);
    expectCallbackFail(new URLSearchParams(params).toString(), expected);
  });
}

for (const [label, state, expectedState] of [
  ['missing state', undefined, STATE],
  ['short state', 'abc', STATE],
  ['mismatched state', NONCE, STATE],
  ['case mismatch', 'A' + STATE.slice(1), STATE],
  ['predictable state', 'a'.repeat(32), undefined]
]) {
  test('callback rejects ' + label, () => {
    const params = { code: AUTH_CODE, state, iss: ISSUER };
    if (state === undefined) delete params.state;
    const options = validCallbackOptions();
    if (expectedState === undefined) delete options.expectedState;
    else options.expectedState = expectedState;
    const result = expectCallbackFail(new URLSearchParams(params).toString(), null, options);
    assert.equal(codes(result).some((code) => code.startsWith('OAUTHCAGE_STATE')), true);
  });
}

for (const [label, actualIssuer, expectedIssuer, expectedCode] of [
  ['missing iss', undefined, ISSUER, 'OAUTHCAGE_ISSUER_REQUIRED'],
  ['issuer host mismatch', 'https://evil.example', ISSUER, 'OAUTHCAGE_ISSUER_MISMATCH'],
  ['issuer path mismatch', ISSUER + '/other', ISSUER, 'OAUTHCAGE_ISSUER_MISMATCH'],
  ['issuer trailing slash mismatch', ISSUER + '/', ISSUER, 'OAUTHCAGE_ISSUER_MISMATCH'],
  ['issuer HTTP scheme', 'http://issuer.example', ISSUER, 'OAUTHCAGE_ISSUER_INVALID'],
  ['issuer query', ISSUER + '?x=1', ISSUER, 'OAUTHCAGE_ISSUER_INVALID']
]) {
  test('callback RFC 9207 validation rejects ' + label, () => {
    const params = { code: AUTH_CODE, state: STATE, iss: actualIssuer };
    if (actualIssuer === undefined) delete params.iss;
    expectCallbackFail(new URLSearchParams(params).toString(), expectedCode, validCallbackOptions({ expectedIssuer }));
  });
}

test('callback accepts issuer host case canonicalization', () => {
  const query = new URLSearchParams({ code: AUTH_CODE, state: STATE, iss: 'https://ISSUER.EXAMPLE' }).toString();
  const result = auditCallback(query, validCallbackOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

test('callback requires expectedIssuer in strict policy even when iss is present', () => {
  const options = validCallbackOptions();
  delete options.expectedIssuer;
  expectCallbackFail(validCallbackQuery(), 'OAUTHCAGE_ISSUER_EXPECTED_REQUIRED', options);
});

for (const name of ['access_token', 'id_token', 'client_secret', 'refresh_token', 'code_verifier', 'password', 'token']) {
  test('callback query rejects leaked secret parameter ' + name, () => {
    expectCallbackFail(validCallbackQuery({ [name]: 'secret-value' }), 'OAUTHCAGE_SECRET_LEAK');
  });
}

for (const [label, fragment] of [
  ['access token fragment', 'access_token=secret-token&state=' + STATE],
  ['id token fragment', 'id_token=secret-token&state=' + STATE],
  ['ordinary fragment response', 'code=' + AUTH_CODE + '&state=' + STATE]
]) {
  test('callback rejects ' + label, () => {
    const result = expectCallbackFail('https://app.example/callback#' + fragment, null);
    assert.equal(hasCode(result, 'OAUTHCAGE_RESPONSE_MODE_DENIED'), true);
  });
}

for (const name of ['code', 'state', 'iss', 'scope', 'error']) {
  test('callback detects duplicate parameter ' + name, () => {
    const suffix = (name === 'scope' || name === 'error') ? '&' + name + '=first&' + name + '=duplicate' : '&' + name + '=duplicate';
    expectCallbackFail(validCallbackQuery() + suffix, 'OAUTHCAGE_DUPLICATE_PARAMETER');
  });
}

test('callback accepts returned subset scope', () => {
  const result = auditCallback(validCallbackQuery({ scope: 'openid' }), validCallbackOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

for (const [label, scope, expected] of [
  ['scope escalation', 'openid profile admin', 'OAUTHCAGE_SCOPE_ESCALATION'],
  ['scope outside allowlist', 'openid email admin', 'OAUTHCAGE_SCOPE_DENIED'],
  ['duplicate scope', 'openid openid', 'OAUTHCAGE_SCOPE_INVALID'],
  ['control scope', 'openid\x01profile', null]
]) {
  test('callback rejects ' + label, () => {
    expectCallbackFail(validCallbackQuery({ scope }), expected);
  });
}

for (const [label, referer] of [
  ['code in referer query', 'https://app.example/callback?code=secret-code'],
  ['access token in referer query', 'https://app.example/callback?access_token=secret-token'],
  ['id token in referer query', 'https://app.example/callback?id_token=secret-token'],
  ['client secret in referer query', 'https://app.example/callback?client_secret=secret-value'],
  ['access token in referer fragment', 'https://app.example/callback#access_token=secret-token'],
  ['code in referer fragment', 'https://app.example/callback#code=secret-code']
]) {
  test('callback detects ' + label, () => {
    expectCallbackFail(validCallbackQuery(), 'OAUTHCAGE_SECRET_IN_REFERER', validCallbackOptions({ referer }));
  });
}

test('callback enforces parameter count cap', () => {
  const extras = Array.from({ length: 65 }, (_, index) => 'x' + index + '=v').join('&');
  expectCallbackFail(validCallbackQuery() + '&' + extras, 'OAUTHCAGE_PARAMETER_COUNT_EXCEEDED');
});

test('callback output never echoes authorization code or token values', () => {
  const secretCode = 'supersecretauthorizationcodevalue';
  const secretToken = 'supersecretaccesstokenvalue';
  const query = 'code=' + secretCode + '&code=other&state=' + STATE + '&iss=' + encodeURIComponent(ISSUER) + '&access_token=' + secretToken;
  const result = expectCallbackFail(query, null);
  const text = serialized(result);
  assert.equal(text.includes(secretCode), false);
  assert.equal(text.includes(secretToken), false);
});

test('valid authorization code token request passes with challenge verification', () => {
  const result = auditTokenRequest(validTokenBody(), validTokenOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.grantType, 'authorization_code');
  assert.equal(result.usesPkce, true);
});

for (const [label, body, expected] of [
  ['missing grant_type', new URLSearchParams({ client_id: 'public-client' }).toString(), 'OAUTHCAGE_GRANT_TYPE_REQUIRED'],
  ['ROPC password grant', 'grant_type=password&username=user&password=pass', 'OAUTHCAGE_ROPC_GRANT_DENIED'],
  ['password shaped parameter with authorization code grant', validTokenBody({ password: 'secret' }), 'OAUTHCAGE_ROPC_GRANT_DENIED'],
  ['unsupported grant type', 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code', 'OAUTHCAGE_GRANT_TYPE_DENIED'],
  ['client credentials denied in strict', 'grant_type=client_credentials&client_id=public-client', 'OAUTHCAGE_GRANT_TYPE_DENIED']
]) {
  test('token request rejects ' + label, () => {
    expectTokenFail(body, expected);
  });
}

for (const [label, mutate, expected] of [
  ['missing code', (params) => { delete params.code; }, 'OAUTHCAGE_CALLBACK_CODE_INVALID'],
  ['missing redirect_uri', (params) => { delete params.redirect_uri; }, 'OAUTHCAGE_REDIRECT_INVALID'],
  ['mismatched redirect_uri', (params) => { params.redirect_uri = 'https://app.example/other'; }, 'OAUTHCAGE_REDIRECT_MISMATCH'],
  ['missing verifier', (params) => { delete params.code_verifier; }, 'OAUTHCAGE_PKCE_REQUIRED'],
  ['short verifier', (params) => { params.code_verifier = 'abc'; }, 'OAUTHCAGE_PKCE_INVALID_VERIFIER'],
  ['wrong verifier', (params) => { params.code_verifier = 'A' + VERIFIER.slice(1); }, 'OAUTHCAGE_PKCE_MISMATCH']
]) {
  test('token request rejects ' + label, () => {
    const params = {
      grant_type: 'authorization_code',
      client_id: 'public-client',
      code: AUTH_CODE,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER
    };
    mutate(params);
    expectTokenFail(new URLSearchParams(params).toString(), expected);
  });
}

test('token request rejects client_secret in spa preset', () => {
  expectTokenFail(validTokenBody({ client_secret: 'secret-value' }), 'OAUTHCAGE_CLIENT_SECRET_DENIED', validTokenOptions({ policy: 'spa' }));
});

test('token request permits client_secret in strict confidential-style use', () => {
  const result = auditTokenRequest(validTokenBody({ client_secret: 'secret-value' }), validTokenOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
  assert.equal(result.usesClientSecret, true);
});

test('valid refresh token request passes', () => {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: 'public-client',
    refresh_token: 'validrefreshtokenvalue'
  }).toString();
  const result = auditTokenRequest(body, validTokenOptions());
  assert.equal(result.ok, true, JSON.stringify(result.findings));
});

for (const [label, refreshToken] of [
  ['missing', undefined],
  ['short', 'abc'],
  ['space', 'token with space'],
  ['control', 'token\x01value']
]) {
  test('refresh token request rejects token ' + label, () => {
    const params = { grant_type: 'refresh_token', client_id: 'public-client', refresh_token: refreshToken };
    if (refreshToken === undefined) delete params.refresh_token;
    expectTokenFail(new URLSearchParams(params).toString(), null);
  });
}

for (const name of ['grant_type', 'code', 'redirect_uri', 'code_verifier', 'client_id']) {
  test('token request detects duplicate parameter ' + name, () => {
    expectTokenFail(validTokenBody() + '&' + name + '=duplicate', 'OAUTHCAGE_DUPLICATE_PARAMETER');
  });
}

for (const [label, scope, expected] of [
  ['outside allowlist', 'openid admin', 'OAUTHCAGE_SCOPE_DENIED'],
  ['denied scope', 'openid admin', 'OAUTHCAGE_SCOPE_DENIED'],
  ['duplicate scope', 'openid openid', 'OAUTHCAGE_SCOPE_INVALID']
]) {
  test('token request rejects ' + label, () => {
    expectTokenFail(validTokenBody({ scope }), expected, validTokenOptions({ allowedScopes: ['openid', 'profile'], deniedScopes: ['admin'] }));
  });
}

test('token request output never echoes verifier or client secret', () => {
  const secretVerifier = VERIFIER;
  const secretClient = 'supersecretclientvalue';
  const result = auditTokenRequest(validTokenBody({ client_secret: secretClient }), validTokenOptions({ policy: 'spa' }));
  const text = serialized(result);
  assert.equal(result.ok, false);
  assert.equal(text.includes(secretVerifier), false);
  assert.equal(text.includes(secretClient), false);
});

for (const input of [
  validTokenBody({ client_secret: 'supersecretclientvalue' }),
  validCallbackQuery({ access_token: 'supersecretaccesstoken' }),
  validAuthQuery({ code_verifier: 'supersecretverifier' })
]) {
  test('audit serialization never echoes secret material for input shape ' + input.slice(0, 12), () => {
    const result = input.startsWith('grant_type=') ? auditTokenRequest(input, validTokenOptions()) : input.startsWith('code=') ? auditCallback(input, validCallbackOptions()) : auditAuthRequest(input, AUTH_OPTIONS);
    const text = serialized(result);
    assert.equal(text.includes('supersecret'), false);
  });
}
