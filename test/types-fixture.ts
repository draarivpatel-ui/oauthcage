import oauthcage, {
  auditAuthRequest,
  auditCallback,
  auditDiscoveryMetadata,
  auditEndpointUrl,
  auditRedirectUri,
  auditTokenRequest,
  createOAuthPolicy,
  createPkcePair,
  generateNonce,
  generateState,
  getPolicy,
  neutralizeTerminal,
  redactSensitiveText,
  validateRedirectUri,
  verifyNonce,
  verifyPkce,
  verifyState
} from '../types/index.js';

const pair = createPkcePair();
const verifier: string = pair.verifier;
void verifier;
const pkceOk: true = verifyPkce(pair.verifier, pair.challenge, 'S256', getPolicy('strict'));
void pkceOk;

const state = generateState();
const nonce = generateNonce();
const stateOk: true = verifyState(state, state);
const nonceOk: true = verifyNonce(nonce, nonce);
void stateOk;
void nonceOk;

const redirect = auditRedirectUri('https://app.example/cb', ['https://app.example/cb']);
const matched: boolean = redirect.matched;
void matched;
const canonical: string = validateRedirectUri('https://app.example/cb', 'https://app.example/cb');
void canonical;

const auth = auditAuthRequest('response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=' + state + '&code_challenge=' + pair.challenge + '&code_challenge_method=S256', {
  registeredRedirectUris: ['https://app.example/cb']
});
const usesPkce: boolean = auth.hasPkce;
void usesPkce;

const callback = auditCallback('code=abcdefghijklmnop&state=' + state + '&iss=https%3A%2F%2Fissuer.example', {
  expectedState: state,
  expectedIssuer: 'https://issuer.example'
});
const hasIssuer: boolean = callback.hasIssuer;
void hasIssuer;

const token = auditTokenRequest('grant_type=authorization_code&client_id=client&code=abcdefghijklmnop&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_verifier=' + pair.verifier, {
  registeredRedirectUris: ['https://app.example/cb'],
  expectedCodeChallenge: pair.challenge
});
const grantType: string | null = token.grantType;
void grantType;

const endpoint = auditEndpointUrl('https://issuer.example/token');
const hostKind = endpoint.hostKind;
void hostKind;

const discovery = auditDiscoveryMetadata({
  issuer: 'https://issuer.example',
  authorization_endpoint: 'https://issuer.example/auth',
  token_endpoint: 'https://issuer.example/token',
  jwks_uri: 'https://issuer.example/jwks',
  id_token_signing_alg_values_supported: ['RS256'],
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256']
}, { expectedIssuer: 'https://issuer.example' });
const issuerMatches: boolean = discovery.issuerMatches;
void issuerMatches;

const customPolicy = createOAuthPolicy('native', { allowLocalhostHttp: true });
const customName = customPolicy.name;
void customName;
const terminalSafe: string = neutralizeTerminal('safe');
const redacted: string = redactSensitiveText('access_token=value');
void terminalSafe;
void redacted;
void oauthcage.OAUTHCAGE_VERSION;

// @ts-expect-error unknown policy names are rejected
getPolicy('unknown');

// @ts-expect-error policy override booleans do not accept strings
createOAuthPolicy('strict', { requirePkce: 'yes' });

// @ts-expect-error redirect audits require string candidates
auditRedirectUri(42, ['https://app.example/cb']);
