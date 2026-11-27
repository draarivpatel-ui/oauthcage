import { createPkcePair, generateNonce, generateState, verifyNonce, verifyPkce, verifyState } from '../src/index.mjs';

const pair = createPkcePair();
const state = generateState();
const nonce = generateNonce();

verifyPkce(pair.verifier, pair.challenge, 'S256');
verifyState(state, state);
verifyNonce(nonce, nonce);

console.log('PKCE, state, and nonce generation plus verification passed');
