import { auditAuthRequest, auditCallback, auditTokenRequest, createPkcePair, generateState } from '../src/index.mjs';

const registered = ['https://app.example/callback'];
const pair = createPkcePair();
const state = generateState();
const issuer = 'https://issuer.example';

const authQuery = new URLSearchParams({
  response_type: 'code',
  client_id: 'example-public-client',
  redirect_uri: registered[0],
  scope: 'openid profile',
  state,
  code_challenge: pair.challenge,
  code_challenge_method: 'S256'
});

const authResult = auditAuthRequest(authQuery.toString(), {
  policy: 'spa',
  registeredRedirectUris: registered,
  allowedScopes: ['openid', 'profile']
});
if (!authResult.ok) throw new Error('authorization request audit failed');

const callbackQuery = new URLSearchParams({
  code: 'exampleauthorizationcode',
  state,
  iss: issuer
});

const callbackResult = auditCallback(callbackQuery.toString(), {
  policy: 'spa',
  expectedState: state,
  expectedIssuer: issuer,
  requestedScope: 'openid profile',
  allowedScopes: ['openid', 'profile']
});
if (!callbackResult.ok) throw new Error('callback audit failed');

const tokenBody = new URLSearchParams({
  grant_type: 'authorization_code',
  client_id: 'example-public-client',
  code: 'exampleauthorizationcode',
  redirect_uri: registered[0],
  code_verifier: pair.verifier
});

const tokenResult = auditTokenRequest(tokenBody.toString(), {
  policy: 'spa',
  registeredRedirectUris: registered,
  expectedCodeChallenge: pair.challenge
});
if (!tokenResult.ok) throw new Error('token request audit failed');

console.log('authorization request, callback, and token request audits passed');
