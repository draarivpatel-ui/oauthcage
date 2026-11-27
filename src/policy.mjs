/* Frozen security policy presets and validated custom policy construction. */

import { CODE, OAuthCageError } from './errors.mjs';
import { deepFreeze, isPlainObject } from './util.mjs';

const BOOLEAN_KEYS = Object.freeze([
  'allowLoopbackHttp',
  'allowLocalhostHttp',
  'allowCustomSchemes',
  'requirePkce',
  'requireState',
  'requireIssuerInCallback',
  'requireRedirectAllowlist',
  'requirePar',
  'allowClientSecret',
  'allowEndpointQueries',
  'requireS256InDiscovery',
  'requireAsymmetricIdTokenAlgorithms'
]);

const INTEGER_KEYS = Object.freeze({
  maxUriLength: [128, 16384],
  maxParameterCount: [1, 512],
  maxParameterLength: [64, 65536],
  maxInputLength: [128, 262144],
  maxDiscoveryBytes: [1024, 1048576],
  maxDiscoveryDepth: [2, 64],
  maxDiscoveryKeys: [16, 4096],
  maxJsonIntDigits: [128, 10000],
  maxFindings: [0, 1000],
  minStateLength: [22, 512],
  minNonceLength: [22, 512],
  minAuthorizationCodeLength: [8, 256],
  maxAuthorizationCodeLength: [64, 8192]
});

const STRING_ARRAY_KEYS = Object.freeze([
  'allowedRedirectSchemes',
  'allowedCustomSchemes',
  'allowedPkceMethods',
  'allowedResponseTypes',
  'allowedGrantTypes',
  'allowedEndpointPorts'
]);

const BASE_POLICY = {
  name: 'strict',
  allowLoopbackHttp: false,
  allowLocalhostHttp: false,
  allowCustomSchemes: false,
  allowedRedirectSchemes: ['https'],
  allowedCustomSchemes: [],
  requirePkce: true,
  allowedPkceMethods: ['S256'],
  requireState: true,
  minStateLength: 22,
  minNonceLength: 22,
  requireIssuerInCallback: true,
  requireRedirectAllowlist: true,
  requirePar: false,
  allowClientSecret: true,
  allowedResponseTypes: ['code'],
  allowedGrantTypes: ['authorization_code', 'refresh_token'],
  maxUriLength: 2048,
  maxParameterCount: 64,
  maxParameterLength: 4096,
  maxInputLength: 65536,
  minAuthorizationCodeLength: 16,
  maxAuthorizationCodeLength: 2048,
  allowedEndpointPorts: ['443'],
  allowEndpointQueries: false,
  maxDiscoveryBytes: 131072,
  maxDiscoveryDepth: 10,
  maxDiscoveryKeys: 256,
  maxJsonIntDigits: 4300,
  maxFindings: 150,
  requireS256InDiscovery: true,
  requireAsymmetricIdTokenAlgorithms: true
};


function copyArray(value, fallback) {
  if (value === undefined) return fallback.slice();
  return Array.isArray(value) ? value.slice() : value;
}

function makePolicy(name, overrides) {
  return deepFreeze({
    ...BASE_POLICY,
    ...overrides,
    name,
    allowedRedirectSchemes: copyArray(overrides.allowedRedirectSchemes, BASE_POLICY.allowedRedirectSchemes),
    allowedCustomSchemes: copyArray(overrides.allowedCustomSchemes, BASE_POLICY.allowedCustomSchemes),
    allowedPkceMethods: copyArray(overrides.allowedPkceMethods, BASE_POLICY.allowedPkceMethods),
    allowedResponseTypes: copyArray(overrides.allowedResponseTypes, BASE_POLICY.allowedResponseTypes),
    allowedGrantTypes: copyArray(overrides.allowedGrantTypes, BASE_POLICY.allowedGrantTypes),
    allowedEndpointPorts: copyArray(overrides.allowedEndpointPorts, BASE_POLICY.allowedEndpointPorts)
  });
}

export const OAUTHCAGE_POLICY_PRESETS = deepFreeze({
  strict: makePolicy('strict', {}),
  spa: makePolicy('spa', {
    allowClientSecret: false,
    allowedGrantTypes: ['authorization_code', 'refresh_token']
  }),
  confidential: makePolicy('confidential', {
    requirePar: true,
    allowClientSecret: true,
    allowedGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials']
  }),
  native: makePolicy('native', {
    allowLoopbackHttp: true,
    allowLocalhostHttp: false,
    allowClientSecret: false,
    allowedRedirectSchemes: ['https', 'http']
  })
});

function assertBoolean(policy, key) {
  if (typeof policy[key] !== 'boolean') {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'policy boolean field is invalid', { field: key });
  }
}

function assertInteger(policy, key, range) {
  const value = policy[key];
  if (!Number.isSafeInteger(value) || value < range[0] || value > range[1]) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'policy integer field is outside its supported range', { field: key });
  }
}

function assertStringArray(policy, key, integerStrings) {
  const value = policy[key];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item.length === 0)) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'policy string array field is invalid', { field: key });
  }
  if (integerStrings && value.some((item) => !/^[0-9]{1,5}$/u.test(item) || Number(item) > 65535)) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'policy port list contains an invalid port', { field: key });
  }
}

function validatePolicy(policy) {
  for (const key of BOOLEAN_KEYS) assertBoolean(policy, key);
  for (const [key, range] of Object.entries(INTEGER_KEYS)) assertInteger(policy, key, range);
  for (const key of STRING_ARRAY_KEYS) assertStringArray(policy, key, key === 'allowedEndpointPorts');
  if (!policy.allowedRedirectSchemes.includes('https') && !policy.allowCustomSchemes) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'policy must allow HTTPS redirects unless custom schemes are explicit', { field: 'allowedRedirectSchemes' });
  }
  if (!policy.allowLoopbackHttp && policy.allowLocalhostHttp) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'localhost HTTP cannot be enabled without loopback HTTP', { field: 'allowLocalhostHttp' });
  }
  if (policy.allowedPkceMethods.includes('plain') && policy.allowedPkceMethods.length > 1) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'plain PKCE cannot be combined with secure methods in one policy', { field: 'allowedPkceMethods' });
  }
  return policy;
}

export function createOAuthPolicy(base = 'strict', overrides = {}) {
  let baseName = base;
  let basePolicy = null;
  let patch = overrides;
  if (isPlainObject(base) && overrides && Object.keys(overrides).length === 0) {
    patch = base;
    baseName = typeof base.name === 'string' && OAUTHCAGE_POLICY_PRESETS[base.name] ? base.name : 'strict';
  }
  if (typeof baseName !== 'string' || !OAUTHCAGE_POLICY_PRESETS[baseName]) {
    throw new OAuthCageError(CODE.POLICY_UNKNOWN, 'unknown OAuth security policy preset', { field: 'policy' });
  }
  basePolicy = OAUTHCAGE_POLICY_PRESETS[baseName];
  if (!isPlainObject(patch)) {
    throw new OAuthCageError(CODE.POLICY_INVALID, 'policy overrides must be a plain object', { field: 'overrides' });
  }
  const allowedKeys = new Set([...BOOLEAN_KEYS, ...Object.keys(INTEGER_KEYS), ...STRING_ARRAY_KEYS, 'name']);
  for (const key of Object.keys(patch)) {
    if (!allowedKeys.has(key) || key === 'name') {
      throw new OAuthCageError(CODE.POLICY_INVALID, 'policy override uses an unsupported field', { field: key });
    }
  }
  const merged = {
    ...basePolicy,
    ...patch,
    name: baseName,
    allowedRedirectSchemes: copyArray(patch.allowedRedirectSchemes, basePolicy.allowedRedirectSchemes),
    allowedCustomSchemes: copyArray(patch.allowedCustomSchemes, basePolicy.allowedCustomSchemes),
    allowedPkceMethods: copyArray(patch.allowedPkceMethods, basePolicy.allowedPkceMethods),
    allowedResponseTypes: copyArray(patch.allowedResponseTypes, basePolicy.allowedResponseTypes),
    allowedGrantTypes: copyArray(patch.allowedGrantTypes, basePolicy.allowedGrantTypes),
    allowedEndpointPorts: copyArray(patch.allowedEndpointPorts, basePolicy.allowedEndpointPorts)
  };
  return deepFreeze(validatePolicy(merged));
}

export function getPolicy(name = 'strict') {
  if (typeof name !== 'string' || !OAUTHCAGE_POLICY_PRESETS[name]) {
    throw new OAuthCageError(CODE.POLICY_UNKNOWN, 'unknown OAuth security policy preset', { field: 'policy' });
  }
  return OAUTHCAGE_POLICY_PRESETS[name];
}

export function resolvePolicy(options, caller) {
  const value = options && options.policy;
  if (value === undefined) return OAUTHCAGE_POLICY_PRESETS.strict;
  if (typeof value === 'string') {
    try {
      return getPolicy(value);
    } catch (error) {
      throw new OAuthCageError(CODE.POLICY_UNKNOWN, caller + ' received an unknown policy preset', { field: 'policy' });
    }
  }
  if (isPlainObject(value)) {
    const baseName = typeof value.name === 'string' && OAUTHCAGE_POLICY_PRESETS[value.name] ? value.name : 'strict';
    const overrides = {};
    for (const key of Object.keys(value)) if (key !== 'name') overrides[key] = value[key];
    return createOAuthPolicy(baseName, overrides);
  }
  throw new OAuthCageError(CODE.POLICY_INVALID, caller + ' policy must be a preset name or plain object', { field: 'policy' });
}
