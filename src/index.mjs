/* oauthcage public API. Zero network access, zero runtime dependencies, deterministic validation. */

import { CODE, OAuthCageError, OAUTHCAGE_ERROR_CODES, OAUTHCAGE_SEVERITY } from './errors.mjs';
import { createOAuthPolicy, getPolicy, OAUTHCAGE_POLICY_PRESETS } from './policy.mjs';
import { auditRedirectUri, validateRedirectUri } from './uri.mjs';
import { createPkcePair, generateNonce, generateState, verifyNonce, verifyPkce, verifyState } from './pkce.mjs';
import { auditAuthRequest, auditCallback, auditTokenRequest } from './oauth.mjs';
import { auditDiscoveryMetadata, auditEndpointUrl } from './discovery.mjs';
import { neutralizeTerminal, redactSensitiveText } from './util.mjs';

export const OAUTHCAGE_VERSION = '1.0.0';

const oauthcage = Object.freeze({
  OAUTHCAGE_VERSION,
  OAUTHCAGE_ERROR_CODES,
  OAUTHCAGE_SEVERITY,
  CODE,
  OAuthCageError,
  OAUTHCAGE_POLICY_PRESETS,
  createOAuthPolicy,
  getPolicy,
  auditRedirectUri,
  validateRedirectUri,
  createPkcePair,
  verifyPkce,
  generateState,
  generateNonce,
  verifyState,
  verifyNonce,
  auditAuthRequest,
  auditCallback,
  auditTokenRequest,
  auditEndpointUrl,
  auditDiscoveryMetadata,
  neutralizeTerminal,
  redactSensitiveText
});

export {
  CODE,
  OAuthCageError,
  OAUTHCAGE_ERROR_CODES,
  OAUTHCAGE_SEVERITY,
  OAUTHCAGE_POLICY_PRESETS,
  createOAuthPolicy,
  getPolicy,
  auditRedirectUri,
  validateRedirectUri,
  createPkcePair,
  verifyPkce,
  generateState,
  generateNonce,
  verifyState,
  verifyNonce,
  auditAuthRequest,
  auditCallback,
  auditTokenRequest,
  auditEndpointUrl,
  auditDiscoveryMetadata,
  neutralizeTerminal,
  redactSensitiveText
};

export default oauthcage;
