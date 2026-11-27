/* RFC 7636 PKCE and CSRF token generation and verification using only node:crypto. */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { CODE, OAuthCageError } from './errors.mjs';
import { predictableToken, timingSafeStringEqual } from './util.mjs';

const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const S256_CHALLENGE_LENGTH = 43;

function assertVerifier(verifier) {
  if (typeof verifier !== 'string' || !VERIFIER_PATTERN.test(verifier)) {
    throw new OAuthCageError(CODE.PKCE_INVALID_VERIFIER, 'PKCE verifier must be 43 to 128 RFC 7636 unreserved characters', { field: 'code_verifier' });
  }
}

function assertChallenge(challenge, method) {
  const challengePattern = method === 'plain' ? VERIFIER_PATTERN : BASE64URL_PATTERN;
  if (typeof challenge !== 'string' || challenge.length === 0 || challenge.length > 512 || !challengePattern.test(challenge)) {
    throw new OAuthCageError(CODE.PKCE_INVALID_CHALLENGE, 'PKCE challenge has an invalid shape for its method', { field: 'code_challenge' });
  }
  if (method === 'S256' && challenge.length !== S256_CHALLENGE_LENGTH) {
    throw new OAuthCageError(CODE.PKCE_INVALID_CHALLENGE, 'S256 PKCE challenge must be a 43 character SHA-256 base64url value', { field: 'code_challenge' });
  }
}

export function createPkcePair() {
  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  return Object.freeze({ verifier, challenge, method: 'S256' });
}

function policyMethods(policy) {
  if (policy && Array.isArray(policy.allowedPkceMethods)) return policy.allowedPkceMethods;
  return ['S256'];
}

export function verifyPkce(verifier, challenge, method = 'S256', policy = null) {
  if (method !== 'S256' && method !== 'plain') {
    throw new OAuthCageError(CODE.PKCE_METHOD_DENIED, 'PKCE method is not recognized', { field: 'code_challenge_method' });
  }
  const methods = policyMethods(policy);
  if (method === 'plain' && !methods.includes('plain')) {
    throw new OAuthCageError(CODE.PKCE_PLAIN_DOWNGRADE, 'plain PKCE is a downgrade and is denied by policy', { field: 'code_challenge_method' });
  }
  if (!methods.includes(method)) {
    throw new OAuthCageError(CODE.PKCE_METHOD_DENIED, 'PKCE method is denied by policy', { field: 'code_challenge_method' });
  }
  assertVerifier(verifier);
  assertChallenge(challenge, method);
  const expected = method === 'S256' ? createHash('sha256').update(verifier, 'ascii').digest('base64url') : verifier;
  const left = Buffer.from(expected, 'utf8');
  const right = Buffer.from(challenge, 'utf8');
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new OAuthCageError(CODE.PKCE_MISMATCH, 'PKCE verifier does not match the challenge', { field: 'code_verifier' });
  }
  return true;
}

function assertToken(value, field, minimumLength, codes) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new OAuthCageError(codes.invalid, field + ' must be a non-empty string', { field });
  }
  if (value.length < minimumLength) {
    throw new OAuthCageError(codes.tooShort, field + ' does not carry enough encoded entropy', { field });
  }
  if (value.length > 512 || !BASE64URL_PATTERN.test(value) || /[\s\u0080-\uFFFF]/u.test(value)) {
    throw new OAuthCageError(codes.invalid, field + ' must be ASCII unpadded base64url without whitespace', { field });
  }
  if (predictableToken(value)) {
    throw new OAuthCageError(codes.predictable, field + ' has a predictable structure', { field });
  }
}

const STATE_CODES = Object.freeze({
  invalid: CODE.STATE_INVALID,
  tooShort: CODE.STATE_TOO_SHORT,
  predictable: CODE.STATE_PREDICTABLE
});
const NONCE_CODES = Object.freeze({
  invalid: CODE.NONCE_INVALID,
  tooShort: CODE.NONCE_TOO_SHORT,
  predictable: CODE.NONCE_PREDICTABLE
});

export function generateState() {
  return randomBytes(32).toString('base64url');
}

export function generateNonce() {
  return randomBytes(32).toString('base64url');
}

export function verifyState(expected, actual, options = {}) {
  const minimumLength = Number.isSafeInteger(options.minStateLength) ? options.minStateLength : 22;
  assertToken(expected, 'state', minimumLength, STATE_CODES);
  assertToken(actual, 'state', minimumLength, STATE_CODES);
  if (!timingSafeStringEqual(expected, actual)) {
    throw new OAuthCageError(CODE.STATE_MISMATCH, 'state values do not match', { field: 'state' });
  }
  return true;
}

export function verifyNonce(expected, actual, options = {}) {
  const minimumLength = Number.isSafeInteger(options.minNonceLength) ? options.minNonceLength : 22;
  assertToken(expected, 'nonce', minimumLength, NONCE_CODES);
  assertToken(actual, 'nonce', minimumLength, NONCE_CODES);
  if (!timingSafeStringEqual(expected, actual)) {
    throw new OAuthCageError(CODE.NONCE_MISMATCH, 'nonce values do not match', { field: 'nonce' });
  }
  return true;
}

export function validatePkceVerifierShape(verifier) {
  assertVerifier(verifier);
  return true;
}

export function validateStateShape(value, minimumLength = 22) {
  assertToken(value, 'state', minimumLength, STATE_CODES);
  return true;
}

export function validateNonceShape(value, minimumLength = 22) {
  assertToken(value, 'nonce', minimumLength, NONCE_CODES);
  return true;
}
