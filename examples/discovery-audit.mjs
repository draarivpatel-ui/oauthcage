import { auditDiscoveryMetadata, auditEndpointUrl } from '../src/index.mjs';

const metadata = {
  issuer: 'https://issuer.example',
  authorization_endpoint: 'https://issuer.example/oauth2/authorize',
  token_endpoint: 'https://issuer.example/oauth2/token',
  jwks_uri: 'https://issuer.example/oauth2/keys',
  userinfo_endpoint: 'https://issuer.example/oauth2/userinfo',
  revocation_endpoint: 'https://issuer.example/oauth2/revoke',
  pushed_authorization_request_endpoint: 'https://issuer.example/oauth2/par',
  id_token_signing_alg_values_supported: ['RS256', 'ES256'],
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  code_challenge_methods_supported: ['S256']
};

const discoveryResult = auditDiscoveryMetadata(metadata, {
  expectedIssuer: 'https://issuer.example'
});
if (!discoveryResult.ok) throw new Error('discovery audit failed');

const endpointResult = auditEndpointUrl(metadata.jwks_uri);
if (!endpointResult.ok) throw new Error('endpoint audit failed');

console.log('discovery metadata and endpoint audits passed');
