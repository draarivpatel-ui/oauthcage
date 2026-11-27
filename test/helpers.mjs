import { createHash } from 'node:crypto';

export const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
export const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
export const STATE = 's7Kp9Xw2Qm4Vz8Rt6Yu1Nb5Lc0Df3Hj7Ga9Ex';
export const NONCE = 'n8Lp6Xw2Qm4Vz8Rt6Yu1Nb5Lc0Df3Hj7Ga9Ey';
export const AUTH_CODE = 'exampleauthorizationcode';
export const REDIRECT_URI = 'https://app.example/callback';
export const ISSUER = 'https://issuer.example';

export function sha256Base64url(text) {
  return createHash('sha256').update(text, 'ascii').digest('base64url');
}

export function validAuthParams(overrides = {}) {
  return {
    response_type: 'code',
    client_id: 'public-client',
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile',
    state: STATE,
    code_challenge: CHALLENGE,
    code_challenge_method: 'S256',
    ...overrides
  };
}

export function validAuthQuery(overrides = {}) {
  return new URLSearchParams(validAuthParams(overrides)).toString();
}

export function validCallbackParams(overrides = {}) {
  return {
    code: AUTH_CODE,
    state: STATE,
    iss: ISSUER,
    ...overrides
  };
}

export function validCallbackQuery(overrides = {}) {
  return new URLSearchParams(validCallbackParams(overrides)).toString();
}

export function validCallbackOptions(overrides = {}) {
  return {
    expectedState: STATE,
    expectedIssuer: ISSUER,
    requestedScope: 'openid profile',
    allowedScopes: ['openid', 'profile', 'email'],
    ...overrides
  };
}

export function validTokenParams(overrides = {}) {
  return {
    grant_type: 'authorization_code',
    client_id: 'public-client',
    code: AUTH_CODE,
    redirect_uri: REDIRECT_URI,
    code_verifier: VERIFIER,
    ...overrides
  };
}

export function validTokenBody(overrides = {}) {
  return new URLSearchParams(validTokenParams(overrides)).toString();
}

export function validTokenOptions(overrides = {}) {
  return {
    registeredRedirectUris: [REDIRECT_URI],
    expectedCodeChallenge: CHALLENGE,
    ...overrides
  };
}

export function validDiscovery(overrides = {}) {
  return {
    issuer: ISSUER,
    authorization_endpoint: ISSUER + '/authorize',
    token_endpoint: ISSUER + '/token',
    jwks_uri: ISSUER + '/keys',
    userinfo_endpoint: ISSUER + '/userinfo',
    revocation_endpoint: ISSUER + '/revoke',
    pushed_authorization_request_endpoint: ISSUER + '/par',
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    ...overrides
  };
}

export function codes(result) {
  return result.findings.map((finding) => finding.code);
}

export function hasCode(result, code) {
  return codes(result).includes(code);
}

export function serialized(result) {
  return JSON.stringify(result);
}

export function repeated(char, length) {
  return char.repeat(length);
}
