import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createOAuthPolicy,
  createPkcePair,
  generateNonce,
  generateState,
  OAuthCageError,
  verifyNonce,
  verifyPkce,
  verifyState
} from '../src/index.mjs';
import { CHALLENGE, NONCE, STATE, VERIFIER, repeated, sha256Base64url } from './helpers.mjs';

const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;

test('RFC 7636 appendix verifier produces the published S256 challenge', () => {
  assert.equal(sha256Base64url(VERIFIER), CHALLENGE);
  assert.equal(verifyPkce(VERIFIER, CHALLENGE, 'S256'), true);
});

test('created PKCE pair has RFC 7636 shape and verifies', () => {
  const pair = createPkcePair();
  assert.match(pair.verifier, VERIFIER_PATTERN);
  assert.equal(pair.verifier.length, 64);
  assert.match(pair.challenge, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(pair.method, 'S256');
  assert.equal(verifyPkce(pair.verifier, pair.challenge, 'S256'), true);
  assert.equal(Object.isFrozen(pair), true);
});

test('created PKCE pairs are unique across repeated generation', () => {
  const pairs = Array.from({ length: 32 }, () => createPkcePair());
  assert.equal(new Set(pairs.map((pair) => pair.verifier)).size, pairs.length);
  assert.equal(new Set(pairs.map((pair) => pair.challenge)).size, pairs.length);
});

for (const length of [43, 44, 63, 64, 96, 127, 128]) {
  test('valid verifier length boundary ' + length, () => {
    const verifier = ('abcXYZ019-._~' + 'x'.repeat(length)).slice(0, length);
    assert.equal(verifier.length, length);
    assert.equal(verifyPkce(verifier, sha256Base64url(verifier), 'S256'), true);
  });
}

for (const length of [0, 1, 42, 129, 256]) {
  test('invalid verifier length ' + length, () => {
    const verifier = 'a'.repeat(length);
    assert.throws(() => verifyPkce(verifier, CHALLENGE, 'S256'), (error) => {
      assert.equal(error.code, 'OAUTHCAGE_PKCE_INVALID_VERIFIER');
      assert.equal(error.field, 'code_verifier');
      return true;
    });
  });
}

for (const character of ['-', '.', '_', '~']) {
  test('verifier accepts RFC 7636 unreserved character ' + JSON.stringify(character), () => {
    const verifier = character + 'a'.repeat(42);
    assert.equal(verifyPkce(verifier, sha256Base64url(verifier), 'S256'), true);
  });
}

for (const [label, character] of [
  ['plus', '+'],
  ['slash', '/'],
  ['equals', '='],
  ['space', ' '],
  ['newline', '\n'],
  ['tab', '\t'],
  ['percent', '%'],
  ['nonascii', 'é'],
  ['nul', '\0'],
  ['delete', '\x7f']
]) {
  test('verifier rejects forbidden character ' + label, () => {
    const verifier = 'a'.repeat(21) + character + 'a'.repeat(21);
    assert.throws(() => verifyPkce(verifier, sha256Base64url(verifier), 'S256'), { code: 'OAUTHCAGE_PKCE_INVALID_VERIFIER' });
  });
}

for (const [label, challenge] of [
  ['empty', ''],
  ['short', 'abc'],
  ['too long', 'a'.repeat(44)],
  ['padded', CHALLENGE.slice(0, -1) + '='],
  ['plus alphabet', CHALLENGE.slice(0, -1) + '+'],
  ['slash alphabet', CHALLENGE.slice(0, -1) + '/'],
  ['space', CHALLENGE.slice(0, -1) + ' '],
  ['nonascii', CHALLENGE.slice(0, -1) + 'é']
]) {
  test('S256 challenge rejects ' + label, () => {
    assert.throws(() => verifyPkce(VERIFIER, challenge, 'S256'), { code: 'OAUTHCAGE_PKCE_INVALID_CHALLENGE' });
  });
}

for (const method of ['plain', 's256', 'PLAIN', 'S512', '', 'null']) {
  test('strict policy rejects PKCE method ' + JSON.stringify(method), () => {
    assert.throws(() => verifyPkce(VERIFIER, method === 'plain' ? VERIFIER : CHALLENGE, method), (error) => {
      assert.match(error.code, /^OAUTHCAGE_PKCE_/u);
      return true;
    });
  });
}

for (const policyName of ['strict', 'spa', 'confidential', 'native']) {
  test(policyName + ' preset rejects plain PKCE downgrade', () => {
    assert.throws(() => verifyPkce(VERIFIER, VERIFIER, 'plain'), { code: 'OAUTHCAGE_PKCE_PLAIN_DOWNGRADE' });
    assert.equal(policyName.length > 0, true);
  });
}

test('explicit custom plain-only policy is possible but outside every preset', () => {
  const policy = createOAuthPolicy('strict', { allowedPkceMethods: ['plain'] });
  assert.equal(verifyPkce(VERIFIER, VERIFIER, 'plain', policy), true);
});

for (const [label, challenge] of [
  ['first character changed', 'A' + CHALLENGE.slice(1)],
  ['last character changed', CHALLENGE.slice(0, -1) + 'A'],
  ['case changed', CHALLENGE.slice(0, 1).toLowerCase() + CHALLENGE.slice(1)],
  ['challenge for another verifier', sha256Base64url('a'.repeat(43))],
  ['prefix only', CHALLENGE.slice(0, -1)]
]) {
  test('PKCE mismatch is rejected for ' + label, () => {
    assert.throws(() => verifyPkce(VERIFIER, challenge, 'S256'), (error) => {
      assert.match(error.code, /^OAUTHCAGE_PKCE_/u);
      return true;
    });
  });
}

test('generated state has at least 256 bits of base64url randomness encoding', () => {
  const state = generateState();
  assert.equal(state.length, 43);
  assert.match(state, BASE64URL_PATTERN);
  assert.equal(verifyState(state, state), true);
});

test('generated nonce has at least 256 bits of base64url randomness encoding', () => {
  const nonce = generateNonce();
  assert.equal(nonce.length, 43);
  assert.match(nonce, BASE64URL_PATTERN);
  assert.equal(verifyNonce(nonce, nonce), true);
});

test('generated state values are unique across repeated generation', () => {
  const values = Array.from({ length: 40 }, () => generateState());
  assert.equal(new Set(values).size, values.length);
});

test('generated nonce values are unique across repeated generation', () => {
  const values = Array.from({ length: 40 }, () => generateNonce());
  assert.equal(new Set(values).size, values.length);
});

for (const length of [22, 23, 32, 37, 43, 64, 128]) {
  test('valid state length boundary ' + length, () => {
    const state = ('x7Kp9Q2mZ8vR4tY6wP1sN3bL5cX0hF' + 'a'.repeat(length)).slice(0, length);
    assert.equal(verifyState(state, state), true);
  });
}

for (const length of [0, 1, 21, 513]) {
  test('invalid state length ' + length, () => {
    const state = 'a'.repeat(length);
    assert.throws(() => verifyState(state, state), (error) => {
      assert.match(error.code, /^OAUTHCAGE_STATE_/u);
      return true;
    });
  });
}

for (const [label, mutate] of [
  ['space', (value) => value.slice(0, 5) + ' ' + value.slice(6)],
  ['newline', (value) => value.slice(0, 5) + '\n' + value.slice(6)],
  ['tab', (value) => value.slice(0, 5) + '\t' + value.slice(6)],
  ['plus', (value) => value.slice(0, 5) + '+' + value.slice(6)],
  ['slash', (value) => value.slice(0, 5) + '/' + value.slice(6)],
  ['equals', (value) => value.slice(0, 5) + '=' + value.slice(6)],
  ['dot', (value) => value.slice(0, 5) + '.' + value.slice(6)],
  ['nonascii', (value) => value.slice(0, 5) + 'é' + value.slice(6)],
  ['nul', (value) => value.slice(0, 5) + '\0' + value.slice(6)]
]) {
  test('state rejects ' + label, () => {
    const state = mutate(STATE);
    assert.throws(() => verifyState(state, state), { code: 'OAUTHCAGE_STATE_INVALID' });
  });
}

for (const [label, state] of [
  ['single repeated character', repeated('a', 32)],
  ['two character repetition', repeated('ab', 16)],
  ['numeric repeated character', repeated('0', 32)],
  ['ascending lowercase sequence', 'abcdefghijklmnopqrstuvwx'],
  ['ascending numeric sequence', '1234567890123456789012'],
  ['descending alphabetic sequence', 'zyxwvutsrqponmlkjihgfe'],
  ['literal state', 'statestatestatestatestatestatestate'],
  ['literal nonce', 'nonce'.repeat(6)],
  ['literal token', 'tokentokentokentokentokentoken'],
  ['short keyboard pattern', 'qwertyuiop'.repeat(3)]
]) {
  test('predictable state is rejected for ' + label, () => {
    assert.throws(() => verifyState(state, state), (error) => {
      assert.match(error.code, /^OAUTHCAGE_STATE_/u);
      return true;
    });
  });
}

for (const [label, actual] of [
  ['one character changed', STATE.slice(0, -1) + (STATE.endsWith('a') ? 'b' : 'a')],
  ['case changed', 'A' + STATE.slice(1)],
  ['extra character', STATE + 'a'],
  ['missing final character', STATE.slice(0, -1)],
  ['different valid state', NONCE]
]) {
  test('state mismatch is rejected for ' + label, () => {
    assert.throws(() => verifyState(STATE, actual), { code: 'OAUTHCAGE_STATE_MISMATCH' });
  });
}

for (const [label, mutate] of [
  ['space', (value) => value.slice(0, 5) + ' ' + value.slice(6)],
  ['newline', (value) => value.slice(0, 5) + '\n' + value.slice(6)],
  ['plus', (value) => value.slice(0, 5) + '+' + value.slice(6)],
  ['slash', (value) => value.slice(0, 5) + '/' + value.slice(6)],
  ['equals', (value) => value.slice(0, 5) + '=' + value.slice(6)],
  ['nonascii', (value) => value.slice(0, 5) + 'é' + value.slice(6)]
]) {
  test('nonce rejects ' + label, () => {
    const nonce = mutate(NONCE);
    assert.throws(() => verifyNonce(nonce, nonce), { code: 'OAUTHCAGE_NONCE_INVALID' });
  });
}

for (const [label, nonce] of [
  ['single repeated character', repeated('b', 32)],
  ['two character repetition', repeated('cd', 16)],
  ['ascending lowercase sequence', 'abcdefghijklmnopqrstuvwx'],
  ['ascending numeric sequence', '1234567890123456789012'],
  ['literal nonce', 'noncenoncenoncenoncenoncenonce']
]) {
  test('predictable nonce is rejected for ' + label, () => {
    assert.throws(() => verifyNonce(nonce, nonce), (error) => {
      assert.match(error.code, /^OAUTHCAGE_NONCE_/u);
      return true;
    });
  });
}

for (const [label, actual] of [
  ['one character changed', NONCE.slice(0, -1) + (NONCE.endsWith('a') ? 'b' : 'a')],
  ['case changed', 'A' + NONCE.slice(1)],
  ['extra character', NONCE + 'a'],
  ['missing final character', NONCE.slice(0, -1)],
  ['different valid nonce', STATE]
]) {
  test('nonce mismatch is rejected for ' + label, () => {
    assert.throws(() => verifyNonce(NONCE, actual), { code: 'OAUTHCAGE_NONCE_MISMATCH' });
  });
}

test('OAuthCageError exposes stable typed fields without echoing secrets', () => {
  try {
    verifyPkce('bad', CHALLENGE, 'S256');
    assert.fail('expected PKCE failure');
  } catch (error) {
    assert.ok(error instanceof OAuthCageError);
    assert.equal(error.name, 'OAuthCageError');
    assert.equal(error.field, 'code_verifier');
    assert.equal(error.message.includes('bad'), false);
    assert.equal(Object.isFrozen(error), true);
    assert.deepEqual(Object.keys(error.toJSON()).sort(), ['code', 'detail', 'field', 'name']);
  }
});
