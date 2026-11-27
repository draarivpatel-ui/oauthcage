/* OAuth 2.0 authorization request, callback, token request, and RFC 9207 mix-up defenses. */

import { CODE, OAuthCageError, OAUTHCAGE_SEVERITY } from './errors.mjs';
import { firstValue, hasParameter, parseParameterObject, parseParameterString, splitUrlParameters } from './params.mjs';
import { resolvePolicy } from './policy.mjs';
import { validateNonceShape, validatePkceVerifierShape, validateStateShape, verifyPkce, verifyState } from './pkce.mjs';
import { analyzeUri, auditRedirectUri } from './uri.mjs';
import { containsSensitiveParameter, finishAudit, makeFinding, validateOptionsObject } from './util.mjs';

const IMPLICIT_RESPONSE_TYPES = new Set(['token', 'id_token', 'id_token token', 'token id_token']);
const SECRET_CALLBACK_KEYS = Object.freeze(['access_token', 'id_token', 'refresh_token', 'client_secret', 'code_verifier', 'password', 'assertion', 'token']);

const AUTH_REQUEST_OPTION_KEYS = Object.freeze([
  'policy',
  'registeredRedirectUris',
  'allowedScopes',
  'deniedScopes',
  'requestedScope',
  'expectedScope'
]);
const CALLBACK_OPTION_KEYS = Object.freeze([
  'policy',
  'expectedState',
  'expectedIssuer',
  'referer',
  'referrer',
  'allowedScopes',
  'deniedScopes',
  'requestedScope',
  'expectedScope'
]);
const TOKEN_REQUEST_OPTION_KEYS = Object.freeze([
  'policy',
  'registeredRedirectUris',
  'expectedCodeChallenge',
  'codeChallengeMethod',
  'allowedScopes',
  'deniedScopes',
  'requestedScope',
  'expectedScope'
]);

const VISIBLE_ASCII = /^[\x21-\x7E]+$/u;
const SCOPE_TOKEN = /^[!#-\[\]-~]+$/u;

function parameterNames(values) {
  return Object.keys(values);
}

function errorFinding(error, field, fallbackCode) {
  if (error instanceof OAuthCageError) return makeFinding(error.code, error.detail, field);
  return makeFinding(fallbackCode, 'security validation failed', field);
}

function parseInput(input, policy, field) {
  if (typeof input === 'string') {
    const split = splitUrlParameters(input, policy, field);
    const query = split.query === null ? null : parseParameterString(split.query, policy, field);
    const fragment = split.fragment === null ? null : parseParameterString(split.fragment, policy, field + ' fragment');
    const findings = split.findings.slice();
    if (query) findings.push(...query.findings);
    if (fragment) findings.push(...fragment.findings);
    return {
      base: split.base,
      queryText: split.query,
      fragmentText: split.fragment,
      values: query ? query.values : Object.create(null),
      fragmentValues: fragment ? fragment.values : Object.create(null),
      findings
    };
  }
  const parsed = parseParameterObject(input, policy, field);
  return {
    base: null,
    queryText: null,
    fragmentText: null,
    values: parsed.values,
    fragmentValues: Object.create(null),
    findings: parsed.findings
  };
}

function validateClientId(values, findings, required, field) {
  const clientId = firstValue(values, 'client_id');
  if (clientId === undefined || clientId.length === 0) {
    if (required) findings.push(makeFinding(CODE.CLIENT_ID_INVALID, field + ' requires a client_id', 'client_id'));
    return;
  }
  if (clientId.length > 256 || !VISIBLE_ASCII.test(clientId)) {
    findings.push(makeFinding(CODE.CLIENT_ID_INVALID, 'client_id must be visible ASCII without whitespace or controls', 'client_id'));
  }
}

function validateScope(scope, options, findings, field) {
  if (scope === undefined) return;
  if (typeof scope !== 'string' || scope.length === 0 || scope.length > 1024 || scope !== scope.trim() || /\s{2,}/u.test(scope)) {
    findings.push(makeFinding(CODE.SCOPE_INVALID, 'scope must be a compact space separated token list', field));
    return;
  }
  const tokens = scope.split(' ');
  if (tokens.some((token) => token.length === 0 || token.length > 128 || !SCOPE_TOKEN.test(token))) {
    findings.push(makeFinding(CODE.SCOPE_INVALID, 'scope contains a token with forbidden characters', field));
    return;
  }
  if (new Set(tokens).size !== tokens.length) {
    findings.push(makeFinding(CODE.SCOPE_INVALID, 'scope contains duplicate tokens', field));
  }
  const allowed = Array.isArray(options.allowedScopes) ? options.allowedScopes : null;
  if (allowed) {
    for (const token of tokens) {
      if (!allowed.includes(token)) findings.push(makeFinding(CODE.SCOPE_DENIED, 'scope token is outside the configured allowlist', field));
    }
  }
  const denied = Array.isArray(options.deniedScopes) ? options.deniedScopes : [];
  for (const token of tokens) {
    if (denied.includes(token)) findings.push(makeFinding(CODE.SCOPE_DENIED, 'scope token is explicitly denied', field));
  }
  const requestedText = typeof options.requestedScope === 'string' ? options.requestedScope : typeof options.expectedScope === 'string' ? options.expectedScope : null;
  if (requestedText !== null) {
    const requested = new Set(requestedText.split(' ').filter((token) => token.length > 0));
    for (const token of tokens) {
      if (!requested.has(token)) findings.push(makeFinding(CODE.SCOPE_ESCALATION, 'returned scope exceeds the originally requested scope', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
  }
}

function scanSensitiveKeys(values, field, findings, includeCode) {
  for (const name of parameterNames(values)) {
    if (SECRET_CALLBACK_KEYS.includes(name) || (includeCode && name === 'code')) {
      findings.push(makeFinding(CODE.SECRET_LEAK, field + ' carries a secret or token parameter in an unsafe location', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
  }
}

function validateChallengeShape(challenge, method, findings) {
  if (method === undefined || method.length === 0) {
    findings.push(makeFinding(CODE.PKCE_PLAIN_DOWNGRADE, 'missing code_challenge_method defaults to plain PKCE and is denied', 'code_challenge_method', OAUTHCAGE_SEVERITY.CRITICAL));
    return;
  }
  if (method === 'plain') {
    findings.push(makeFinding(CODE.PKCE_PLAIN_DOWNGRADE, 'plain PKCE is a downgrade and is denied', 'code_challenge_method', OAUTHCAGE_SEVERITY.CRITICAL));
    return;
  }
  if (method !== 'S256') {
    findings.push(makeFinding(CODE.PKCE_METHOD_DENIED, 'only S256 PKCE is accepted', 'code_challenge_method'));
    return;
  }
  if (!/^[A-Za-z0-9_-]{43}$/u.test(challenge)) {
    findings.push(makeFinding(CODE.PKCE_INVALID_CHALLENGE, 'code_challenge must be a 43 character unpadded base64url SHA-256 value', 'code_challenge'));
  }
}

function validateShape(fn, value, field, findings) {
  try {
    fn(value);
  } catch (error) {
    findings.push(errorFinding(error, field, CODE.INVALID_INPUT));
  }
}

function auditRedirectValue(redirectUri, options, policy, findings, field) {
  if (typeof redirectUri !== 'string' || redirectUri.length === 0) return;
  const registered = options.registeredRedirectUris;
  const hasRegistered = typeof registered === 'string' || (Array.isArray(registered) && registered.length > 0);
  if (!hasRegistered) {
    if (policy.requireRedirectAllowlist) {
      findings.push(makeFinding(CODE.REDIRECT_ALLOWLIST_REQUIRED, 'redirect URI validation requires the registered allowlist', field));
    } else {
      const analyzed = analyzeUri(redirectUri, policy, field);
      findings.push(...analyzed.findings);
    }
    return;
  }
  const nested = auditRedirectUri(redirectUri, registered, { policy });
  for (const finding of nested.findings) findings.push(finding);
}

function validateIssuerText(value, policy, field, findings) {
  if (typeof value !== 'string' || value.length === 0) {
    findings.push(makeFinding(CODE.ISSUER_INVALID, field + ' issuer must be a non-empty string', field));
    return null;
  }
  const analyzed = analyzeUri(value, policy, field);
  const errors = analyzed.findings.filter((finding) => finding.severity === 'critical' || finding.severity === 'error');
  for (const finding of errors) findings.push(makeFinding(CODE.ISSUER_INVALID, field + ' issuer is not a valid canonical HTTPS URI', field));
  if (analyzed.meta === null || analyzed.meta.scheme !== 'https') {
    findings.push(makeFinding(CODE.ISSUER_INVALID, field + ' issuer must use HTTPS', field));
    return null;
  }
  if (analyzed.meta.hasQuery) {
    findings.push(makeFinding(CODE.ISSUER_INVALID, field + ' issuer must not contain a query', field));
    return null;
  }
  return errors.length === 0 ? analyzed.canonical : null;
}

function compareIssuer(actual, expected, policy, findings) {
  const actualCanonical = validateIssuerText(actual, policy, 'iss', findings);
  const expectedCanonical = validateIssuerText(expected, policy, 'expectedIssuer', findings);
  if (actualCanonical !== null && expectedCanonical !== null && actualCanonical !== expectedCanonical) {
    findings.push(makeFinding(CODE.ISSUER_MISMATCH, 'callback issuer does not exactly match the expected issuer', 'iss', OAUTHCAGE_SEVERITY.CRITICAL));
  }
}

function scanReferer(referer, policy, findings) {
  if (referer === undefined) return;
  if (typeof referer !== 'string') {
    findings.push(makeFinding(CODE.INVALID_INPUT, 'Referer header must be a string', 'referer'));
    return;
  }
  const split = splitUrlParameters(referer, policy, 'referer');
  const sources = [];
  if (split.query !== null) sources.push(parseParameterString(split.query, policy, 'referer query'));
  if (split.fragment !== null) sources.push(parseParameterString(split.fragment, policy, 'referer fragment'));
  for (const parsed of sources) {
    for (const name of Object.keys(parsed.values)) {
      if (SECRET_CALLBACK_KEYS.includes(name) || name === 'code') {
        findings.push(makeFinding(CODE.SECRET_IN_REFERER, 'sensitive OAuth material appears in a Referer header', 'referer', OAUTHCAGE_SEVERITY.CRITICAL));
      }
    }
  }
}

export function auditAuthRequest(input, options = {}) {
  const checkedOptions = validateOptionsObject(options, AUTH_REQUEST_OPTION_KEYS, 'auditAuthRequest');
  const policy = resolvePolicy(checkedOptions, 'auditAuthRequest');
  const parsed = parseInput(input, policy, 'authorization request');
  const findings = parsed.findings.slice();
  const values = parsed.values;
  if (parsed.fragmentText !== null && parsed.fragmentText.length > 0) {
    findings.push(makeFinding(CODE.RESPONSE_MODE_DENIED, 'authorization request URL must not carry response parameters in a fragment', 'fragment'));
  }

  const responseType = firstValue(values, 'response_type');
  if (responseType === undefined) {
    findings.push(makeFinding(CODE.RESPONSE_TYPE_REQUIRED, 'authorization request requires response_type', 'response_type'));
  } else if (IMPLICIT_RESPONSE_TYPES.has(responseType) || /(?:^| )(?:token|id_token)(?: |$)/u.test(responseType)) {
    findings.push(makeFinding(CODE.IMPLICIT_GRANT_DENIED, 'implicit and hybrid token response types are denied by RFC 9700 policy', 'response_type', OAUTHCAGE_SEVERITY.CRITICAL));
  } else if (!policy.allowedResponseTypes.includes(responseType)) {
    findings.push(makeFinding(CODE.RESPONSE_TYPE_DENIED, 'response_type is denied by policy', 'response_type'));
  }

  validateClientId(values, findings, true, 'authorization request');
  const redirectUri = firstValue(values, 'redirect_uri');
  if (redirectUri === undefined) {
    findings.push(makeFinding(CODE.REDIRECT_INVALID, 'authorization request requires redirect_uri', 'redirect_uri'));
  } else {
    auditRedirectValue(redirectUri, checkedOptions, policy, findings, 'redirect_uri');
  }

  validateScope(firstValue(values, 'scope'), checkedOptions, findings, 'scope');

  const state = firstValue(values, 'state');
  if (state === undefined) {
    if (policy.requireState) findings.push(makeFinding(CODE.STATE_REQUIRED, 'authorization request requires a high entropy state value', 'state', OAUTHCAGE_SEVERITY.CRITICAL));
  } else {
    validateShape((value) => validateStateShape(value, policy.minStateLength), state, 'state', findings);
  }
  const nonce = firstValue(values, 'nonce');
  if (nonce !== undefined) validateShape((value) => validateNonceShape(value, policy.minNonceLength), nonce, 'nonce', findings);

  const challenge = firstValue(values, 'code_challenge');
  const challengeMethod = firstValue(values, 'code_challenge_method');
  if (challenge === undefined) {
    if (policy.requirePkce) findings.push(makeFinding(CODE.PKCE_REQUIRED, 'authorization code flow requires an S256 PKCE challenge', 'code_challenge', OAUTHCAGE_SEVERITY.CRITICAL));
  } else {
    validateChallengeShape(challenge, challengeMethod, findings);
  }
  if (challenge === undefined && challengeMethod !== undefined) {
    findings.push(makeFinding(CODE.PKCE_INVALID_CHALLENGE, 'code_challenge_method without code_challenge is invalid', 'code_challenge_method'));
  }

  const requestUri = firstValue(values, 'request_uri');
  if (policy.requirePar && requestUri === undefined) {
    findings.push(makeFinding(CODE.PAR_REQUIRED, 'confidential client policy requires a pushed authorization request URI', 'request_uri'));
  }
  if (requestUri !== undefined && (!/^urn:[A-Za-z0-9][A-Za-z0-9-]{1,30}:[A-Za-z0-9._~:-]{8,512}$/u.test(requestUri))) {
    findings.push(makeFinding(CODE.REQUEST_URI_INVALID, 'request_uri must be a bounded opaque URN', 'request_uri'));
  }
  const responseMode = firstValue(values, 'response_mode');
  if (responseMode === 'fragment') {
    findings.push(makeFinding(CODE.RESPONSE_MODE_DENIED, 'fragment response mode is denied', 'response_mode', OAUTHCAGE_SEVERITY.CRITICAL));
  }
  scanSensitiveKeys(values, 'authorization request', findings, true);

  return finishAudit('authorization-request', policy.name, findings, {
    flow: responseType === 'code' ? 'authorization_code' : null,
    usesPar: requestUri !== undefined,
    hasPkce: challenge !== undefined,
    hasState: state !== undefined
  }, policy.maxFindings);
}

export function auditCallback(input, options = {}) {
  const checkedOptions = validateOptionsObject(options, CALLBACK_OPTION_KEYS, 'auditCallback');
  const policy = resolvePolicy(checkedOptions, 'auditCallback');
  const parsed = parseInput(input, policy, 'authorization callback');
  const findings = parsed.findings.slice();
  const values = parsed.values;
  const fragmentValues = parsed.fragmentValues;

  if (parsed.fragmentText !== null) {
    findings.push(makeFinding(CODE.RESPONSE_MODE_DENIED, 'callback uses fragment response mode, which is denied', 'fragment', OAUTHCAGE_SEVERITY.CRITICAL));
    if (containsSensitiveParameter(Object.keys(fragmentValues))) {
      findings.push(makeFinding(CODE.TOKEN_IN_FRAGMENT, 'token material appears in the callback fragment', 'fragment', OAUTHCAGE_SEVERITY.CRITICAL));
    }
  }
  scanSensitiveKeys(values, 'authorization callback query', findings, false);

  const error = firstValue(values, 'error');
  const code = firstValue(values, 'code');
  if (error !== undefined && code !== undefined) {
    findings.push(makeFinding(CODE.CALLBACK_ERROR_AND_CODE, 'callback cannot contain both error and code', 'code'));
  }
  if (error !== undefined && !/^[A-Za-z0-9._-]{1,128}$/u.test(error)) {
    findings.push(makeFinding(CODE.CALLBACK_INVALID, 'OAuth error value has an invalid shape', 'error'));
  }
  if (error === undefined && code === undefined) {
    findings.push(makeFinding(CODE.CALLBACK_CODE_REQUIRED, 'successful authorization callback requires exactly one code', 'code'));
  }
  if (code !== undefined) {
    if (code.length < policy.minAuthorizationCodeLength || code.length > policy.maxAuthorizationCodeLength || !VISIBLE_ASCII.test(code)) {
      findings.push(makeFinding(CODE.CALLBACK_CODE_INVALID, 'authorization code must be bounded visible ASCII', 'code'));
    }
  }

  const state = firstValue(values, 'state');
  if (state === undefined) {
    if (policy.requireState) findings.push(makeFinding(CODE.STATE_REQUIRED, 'authorization callback requires state for CSRF protection', 'state', OAUTHCAGE_SEVERITY.CRITICAL));
  } else if (typeof checkedOptions.expectedState === 'string') {
    try {
      verifyState(checkedOptions.expectedState, state, { minStateLength: policy.minStateLength });
    } catch (shapeError) {
      findings.push(errorFinding(shapeError, 'state', CODE.STATE_MISMATCH));
    }
  } else {
    validateShape((value) => validateStateShape(value, policy.minStateLength), state, 'state', findings);
  }

  const nonce = firstValue(values, 'nonce');
  if (nonce !== undefined) {
    validateShape((value) => validateNonceShape(value, policy.minNonceLength), nonce, 'nonce', findings);
  }

  const issuer = firstValue(values, 'iss');
  if (issuer === undefined) {
    if (policy.requireIssuerInCallback) {
      findings.push(makeFinding(CODE.ISSUER_REQUIRED, 'RFC 9207 issuer parameter is required on the callback', 'iss', OAUTHCAGE_SEVERITY.CRITICAL));
    }
  } else if (typeof checkedOptions.expectedIssuer !== 'string' || checkedOptions.expectedIssuer.length === 0) {
    if (policy.requireIssuerInCallback) {
      findings.push(makeFinding(CODE.ISSUER_EXPECTED_REQUIRED, 'an expected issuer is required to validate RFC 9207 iss', 'expectedIssuer'));
    }
  } else {
    compareIssuer(issuer, checkedOptions.expectedIssuer, policy, findings);
  }
  if (issuer === undefined && typeof checkedOptions.expectedIssuer === 'string' && !policy.requireIssuerInCallback) {
    findings.push(makeFinding(CODE.ISSUER_REQUIRED, 'issuer validation was configured but no iss value was returned', 'iss'));
  }

  validateScope(firstValue(values, 'scope'), checkedOptions, findings, 'scope');
  scanReferer(checkedOptions.referer === undefined ? checkedOptions.referrer : checkedOptions.referer, policy, findings);

  return finishAudit('authorization-callback', policy.name, findings, {
    errorResponse: error !== undefined,
    hasCode: code !== undefined,
    hasIssuer: issuer !== undefined,
    hasState: state !== undefined
  }, policy.maxFindings);
}

export function auditTokenRequest(input, options = {}) {
  const checkedOptions = validateOptionsObject(options, TOKEN_REQUEST_OPTION_KEYS, 'auditTokenRequest');
  const policy = resolvePolicy(checkedOptions, 'auditTokenRequest');
  const parsed = parseInput(input, policy, 'token request');
  const findings = parsed.findings.slice();
  const values = parsed.values;

  const grantType = firstValue(values, 'grant_type');
  if (grantType === undefined) {
    findings.push(makeFinding(CODE.GRANT_TYPE_REQUIRED, 'token request requires grant_type', 'grant_type'));
  } else if (grantType === 'password' || hasParameter(values, 'password') || hasParameter(values, 'username')) {
    findings.push(makeFinding(CODE.ROPC_GRANT_DENIED, 'resource owner password credentials grant is denied by RFC 9700 policy', 'grant_type', OAUTHCAGE_SEVERITY.CRITICAL));
  } else if (!policy.allowedGrantTypes.includes(grantType)) {
    findings.push(makeFinding(CODE.GRANT_TYPE_DENIED, 'grant_type is denied by policy', 'grant_type'));
  }

  validateClientId(values, findings, false, 'token request');
  if (firstValue(values, 'client_id') === undefined) {
    findings.push(makeFinding(CODE.CLIENT_ID_INVALID, 'client_id is absent from the token request body; client authentication must use a controlled channel', 'client_id', OAUTHCAGE_SEVERITY.WARNING));
  }

  if (grantType === 'authorization_code') {
    const code = firstValue(values, 'code');
    if (code === undefined || code.length < policy.minAuthorizationCodeLength || code.length > policy.maxAuthorizationCodeLength || !VISIBLE_ASCII.test(code)) {
      findings.push(makeFinding(CODE.CALLBACK_CODE_INVALID, 'authorization code must be bounded visible ASCII', 'code'));
    }
    const redirectUri = firstValue(values, 'redirect_uri');
    if (redirectUri === undefined) {
      findings.push(makeFinding(CODE.REDIRECT_INVALID, 'authorization code token request requires redirect_uri', 'redirect_uri'));
    } else {
      auditRedirectValue(redirectUri, checkedOptions, policy, findings, 'redirect_uri');
    }
    const verifier = firstValue(values, 'code_verifier');
    if (verifier === undefined) {
      if (policy.requirePkce) findings.push(makeFinding(CODE.PKCE_REQUIRED, 'authorization code token request requires a PKCE verifier', 'code_verifier', OAUTHCAGE_SEVERITY.CRITICAL));
    } else {
      validateShape(validatePkceVerifierShape, verifier, 'code_verifier', findings);
      if (typeof checkedOptions.expectedCodeChallenge === 'string') {
        try {
          verifyPkce(verifier, checkedOptions.expectedCodeChallenge, checkedOptions.codeChallengeMethod || 'S256', policy);
        } catch (pkceError) {
          findings.push(errorFinding(pkceError, 'code_verifier', CODE.PKCE_MISMATCH));
        }
      }
    }
  }

  if (grantType === 'refresh_token') {
    const refreshToken = firstValue(values, 'refresh_token');
    if (refreshToken === undefined || refreshToken.length < 16 || refreshToken.length > 4096 || !VISIBLE_ASCII.test(refreshToken)) {
      findings.push(makeFinding(CODE.INVALID_INPUT, 'refresh_token must be bounded visible ASCII', 'refresh_token'));
    }
  }

  if (hasParameter(values, 'client_secret') && !policy.allowClientSecret) {
    findings.push(makeFinding(CODE.CLIENT_SECRET_DENIED, 'public client policy denies client_secret', 'client_secret', OAUTHCAGE_SEVERITY.CRITICAL));
  }
  validateScope(firstValue(values, 'scope'), checkedOptions, findings, 'scope');

  return finishAudit('token-request', policy.name, findings, {
    grantType: grantType === undefined ? null : grantType,
    usesPkce: firstValue(values, 'code_verifier') !== undefined,
    usesClientSecret: hasParameter(values, 'client_secret')
  }, policy.maxFindings);
}
