/* OIDC discovery metadata, endpoint URL integrity, and offline SSRF perimeter checks. */

import { domainToASCII } from 'node:url';
import { CODE, OAUTHCAGE_SEVERITY } from './errors.mjs';
import { internalHostname, ipv4Scope, ipv6Analysis, parseIpv4Like, parseIpv6Literal } from './network.mjs';
import { resolvePolicy } from './policy.mjs';
import { analyzeUri } from './uri.mjs';
import { collectStringFindings, finishAudit, hasErrorFinding, isPlainObject, makeFinding, scanPrototypeKeys, validateOptionsObject } from './util.mjs';


const ENDPOINT_OPTION_KEYS = Object.freeze(['policy']);
const DISCOVERY_OPTION_KEYS = Object.freeze(['policy', 'expectedIssuer']);

const ENDPOINT_KEYS = Object.freeze([
  'authorization_endpoint',
  'token_endpoint',
  'jwks_uri',
  'userinfo_endpoint',
  'revocation_endpoint',
  'pushed_authorization_request_endpoint',
  'introspection_endpoint',
  'end_session_endpoint'
]);
const REQUIRED_ENDPOINT_KEYS = Object.freeze(['authorization_endpoint', 'token_endpoint', 'jwks_uri']);
const ASYMMETRIC_ALGORITHMS = new Set([
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512',
  'EdDSA'
]);

function endpointParts(input, field, findings) {
  if (input.includes('#')) {
    findings.push(makeFinding(CODE.ENDPOINT_FRAGMENT, field + ' must not contain a fragment', field));
  }
  if (input.includes('\\')) {
    findings.push(makeFinding(CODE.ENDPOINT_INVALID, field + ' must not contain a backslash', field));
  }
  const match = /^https:(.*)$/iu.exec(input);
  if (!match) {
    findings.push(makeFinding(CODE.ENDPOINT_SCHEME_DENIED, field + ' must use HTTPS', field, OAUTHCAGE_SEVERITY.CRITICAL));
    return null;
  }
  const rest = match[1];
  if (!rest.startsWith('//')) {
    findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' must include an authority host', field));
    return null;
  }
  const withoutSlashes = rest.slice(2);
  const pathStart = withoutSlashes.search(/[/?#]/u);
  const authority = pathStart === -1 ? withoutSlashes : withoutSlashes.slice(0, pathStart);
  const suffix = pathStart === -1 ? '' : withoutSlashes.slice(pathStart);
  if (authority.length === 0) {
    findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' has an empty host', field));
    return null;
  }
  if (authority.includes('@')) {
    findings.push(makeFinding(CODE.ENDPOINT_USERINFO, field + ' must not contain user information', field, OAUTHCAGE_SEVERITY.CRITICAL));
  }
  let host = '';
  let port = null;
  let bracketed = false;
  if (authority.startsWith('[')) {
    bracketed = true;
    const close = authority.indexOf(']');
    if (close === -1) {
      findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' has malformed IPv6 brackets', field));
      return null;
    }
    host = authority.slice(1, close);
    const tail = authority.slice(close + 1);
    if (tail.length > 0) {
      if (!tail.startsWith(':')) {
        findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' has malformed text after an IPv6 host', field));
        return null;
      }
      port = tail.slice(1);
    }
  } else {
    const colonCount = (authority.match(/:/gu) || []).length;
    if (colonCount > 1) {
      findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' contains an unbracketed IPv6 literal', field));
      return null;
    }
    if (colonCount === 1) {
      const colon = authority.lastIndexOf(':');
      host = authority.slice(0, colon);
      port = authority.slice(colon + 1);
    } else {
      host = authority;
    }
  }
  if (port !== null && (!/^[0-9]{1,5}$/u.test(port) || Number(port) > 65535 || Number(port) === 0)) {
    findings.push(makeFinding(CODE.ENDPOINT_PORT_DENIED, field + ' contains an invalid port', field));
    port = null;
  }
  const queryIndex = suffix.indexOf('?');
  return {
    host,
    port,
    bracketed,
    path: queryIndex === -1 ? suffix : suffix.slice(0, queryIndex),
    query: queryIndex === -1 ? null : suffix.slice(queryIndex + 1)
  };
}

function auditHost(parts, policy, field, findings) {
  if (parts.bracketed) {
    const parsed = parseIpv6Literal(parts.host);
    if (!parsed || !parsed.valid) {
      findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' has an invalid IPv6 literal', field));
      return { hostKind: 'ipv6', ipScope: 'invalid', tunnel: null };
    }
    const analysis = ipv6Analysis(parsed.groups);
    if (analysis.tunnel !== null) {
      findings.push(makeFinding(CODE.ENDPOINT_TUNNEL_DENIED, field + ' uses an IPv6 transition or tunnel encoding', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
    if (analysis.scope === 'metadata' || analysis.embeddedScope === 'metadata') {
      findings.push(makeFinding(CODE.ENDPOINT_METADATA_DENIED, field + ' targets cloud instance metadata infrastructure', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
    const effectiveScope = analysis.embeddedScope && analysis.embeddedScope !== 'public' ? analysis.embeddedScope : analysis.scope;
    if (effectiveScope !== 'public') {
      findings.push(makeFinding(CODE.ENDPOINT_IP_NOT_PUBLIC, field + ' targets a non-public or special-purpose IP range', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
    return { hostKind: 'ipv6', ipScope: effectiveScope, tunnel: analysis.tunnel };
  }

  const host = parts.host.toLowerCase();
  if (host.length === 0 || host.includes('%')) {
    findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' host is empty or percent encoded', field));
    return { hostKind: 'domain', ipScope: null, tunnel: null };
  }
  const ipv4 = parseIpv4Like(host);
  if (ipv4 && ipv4.numericLike) {
    if (!ipv4.valid || ipv4.obfuscated) {
      findings.push(makeFinding(CODE.ENDPOINT_IP_OBFUSCATED, field + ' uses an ambiguous decimal, octal, hexadecimal, or shorthand IPv4 form', field, OAUTHCAGE_SEVERITY.CRITICAL));
      return { hostKind: 'ipv4', ipScope: 'obfuscated', tunnel: null };
    }
    const scope = ipv4Scope(ipv4.bytes);
    if (scope === 'metadata') {
      findings.push(makeFinding(CODE.ENDPOINT_METADATA_DENIED, field + ' targets cloud instance metadata infrastructure', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
    if (scope !== 'public') {
      findings.push(makeFinding(CODE.ENDPOINT_IP_NOT_PUBLIC, field + ' targets a non-public or special-purpose IP range', field, OAUTHCAGE_SEVERITY.CRITICAL));
    }
    return { hostKind: 'ipv4', ipScope: scope, tunnel: null };
  }

  const normalized = host.endsWith('.') ? host.slice(0, -1) : host;
  if (internalHostname(normalized)) {
    findings.push(makeFinding(CODE.ENDPOINT_INTERNAL_HOST, field + ' targets localhost, a single-label, .local, or .internal name', field, OAUTHCAGE_SEVERITY.CRITICAL));
  }
  const ascii = domainToASCII(host);
  if (ascii.length === 0 || ascii.length > 253) {
    findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' host is not a valid DNS name', field));
  } else {
    const labels = (ascii.endsWith('.') ? ascii.slice(0, -1) : ascii).split('.');
    if (labels.some((label) => label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/iu.test(label))) {
      findings.push(makeFinding(CODE.ENDPOINT_HOST_INVALID, field + ' host is not a valid DNS name', field));
    }
  }
  return { hostKind: 'domain', ipScope: null, tunnel: null };
}

function canonicalHttps(value, policy, field, findings) {
  const analyzed = analyzeUri(value, policy, field);
  const errors = analyzed.findings.filter((finding) => finding.severity === 'error' || finding.severity === 'critical');
  if (errors.length > 0) {
    findings.push(makeFinding(CODE.ENDPOINT_INVALID, field + ' is not a valid canonical HTTPS URI', field));
    return null;
  }
  if (analyzed.meta === null || analyzed.meta.scheme !== 'https') {
    findings.push(makeFinding(CODE.ENDPOINT_SCHEME_DENIED, field + ' must use HTTPS', field));
    return null;
  }
  return analyzed.canonical;
}

export function auditEndpointUrl(endpoint, options = {}) {
  validateOptionsObject(options, ENDPOINT_OPTION_KEYS, 'auditEndpointUrl');
  const policy = resolvePolicy(options, 'auditEndpointUrl');
  const findings = [];
  collectStringFindings(endpoint, 'endpoint', policy.maxUriLength, findings);
  const analyzed = typeof endpoint === 'string' ? analyzeUri(endpoint, policy, 'endpoint') : { findings: [], meta: null, canonical: null };
  findings.push(...analyzed.findings);
  const parts = typeof endpoint === 'string' ? endpointParts(endpoint, 'endpoint', findings) : null;
  let hostResult = { hostKind: null, ipScope: null, tunnel: null };
  if (parts !== null) {
    hostResult = auditHost(parts, policy, 'endpoint', findings);
    const effectivePort = parts.port === null ? '443' : String(Number(parts.port));
    if (!policy.allowedEndpointPorts.includes(effectivePort)) {
      findings.push(makeFinding(CODE.ENDPOINT_PORT_DENIED, 'endpoint uses a port denied by policy', 'endpoint'));
    }
    if (parts.query !== null && !policy.allowEndpointQueries) {
      findings.push(makeFinding(CODE.ENDPOINT_QUERY_DENIED, 'endpoint URL must not contain a query component', 'endpoint'));
    }
  }
  return finishAudit('endpoint-url', policy.name, findings, {
    canonical: hasErrorFinding(findings) ? null : analyzed.canonical,
    hostKind: hostResult.hostKind,
    ipScope: hostResult.ipScope,
    tunnel: hostResult.tunnel,
    port: parts && parts.port !== null ? String(Number(parts.port)) : '443'
  });
}

function documentStats(value) {
  const state = { keys: 0, maxDepth: 0, cyclic: false };
  const active = new Set();
  const visit = (item, depth) => {
    if (item === null || typeof item !== 'object') return;
    if (active.has(item)) {
      state.cyclic = true;
      return;
    }
    active.add(item);
    state.maxDepth = Math.max(state.maxDepth, depth);
    const keys = Array.isArray(item) ? item.map((_, index) => String(index)) : Object.keys(item);
    state.keys += keys.length;
    for (const key of keys) visit(item[key], depth + 1);
    active.delete(item);
  };
  visit(value, 0);
  return state;
}

function parseDiscoveryInput(input, policy, findings) {
  if (typeof input === 'string') {
    if (input.length === 0) {
      findings.push(makeFinding(CODE.DISCOVERY_INVALID_JSON, 'discovery JSON must not be empty', 'discovery'));
      return null;
    }
    if (input.length > policy.maxDiscoveryBytes) {
      findings.push(makeFinding(CODE.RESOURCE_LIMIT, 'discovery JSON exceeds the byte limit', 'discovery'));
      return null;
    }
    try {
      return JSON.parse(input);
    } catch {
      findings.push(makeFinding(CODE.DISCOVERY_INVALID_JSON, 'discovery document is not valid JSON', 'discovery'));
      return null;
    }
  }
  return input;
}

function endpointFindingCopy(finding, field) {
  return makeFinding(finding.code, finding.message, field, finding.severity);
}

function auditAlgorithmMetadata(document, policy, findings) {
  const algorithms = document.id_token_signing_alg_values_supported;
  if (!Array.isArray(algorithms) || algorithms.length === 0 || algorithms.some((item) => typeof item !== 'string')) {
    findings.push(makeFinding(CODE.DISCOVERY_INSECURE_ALGORITHM, 'discovery document must publish a non-empty signing algorithm array', 'id_token_signing_alg_values_supported'));
    return;
  }
  if (algorithms.includes('none')) {
    findings.push(makeFinding(CODE.DISCOVERY_INSECURE_ALGORITHM, 'discovery document permits unsigned ID tokens', 'id_token_signing_alg_values_supported', OAUTHCAGE_SEVERITY.CRITICAL));
  }
  if (algorithms.some((algorithm) => /^HS(?:256|384|512)$/u.test(algorithm))) {
    findings.push(makeFinding(CODE.DISCOVERY_INSECURE_ALGORITHM, 'discovery document permits symmetric ID token signatures in an asymmetric flow', 'id_token_signing_alg_values_supported', OAUTHCAGE_SEVERITY.CRITICAL));
  }
  if (policy.requireAsymmetricIdTokenAlgorithms && !algorithms.some((algorithm) => ASYMMETRIC_ALGORITHMS.has(algorithm))) {
    findings.push(makeFinding(CODE.DISCOVERY_ASYMMETRIC_REQUIRED, 'discovery document does not offer a recognized asymmetric ID token algorithm', 'id_token_signing_alg_values_supported'));
  }
}

function auditFlowMetadata(document, findings) {
  const responseTypes = document.response_types_supported;
  if (Array.isArray(responseTypes)) {
    for (const responseType of responseTypes) {
      if (typeof responseType === 'string' && /(?:^| )(?:token|id_token)(?: |$)/u.test(responseType)) {
        findings.push(makeFinding(CODE.DISCOVERY_INSECURE_FLOW, 'discovery document advertises implicit or hybrid token flows', 'response_types_supported', OAUTHCAGE_SEVERITY.CRITICAL));
        break;
      }
    }
  }
  const grants = document.grant_types_supported;
  if (Array.isArray(grants) && grants.includes('password')) {
    findings.push(makeFinding(CODE.DISCOVERY_INSECURE_FLOW, 'discovery document advertises the resource owner password credentials grant', 'grant_types_supported', OAUTHCAGE_SEVERITY.CRITICAL));
  }
}

function auditPkceMetadata(document, policy, findings) {
  const methods = document.code_challenge_methods_supported;
  if (!Array.isArray(methods) || methods.length === 0) {
    if (policy.requireS256InDiscovery) {
      findings.push(makeFinding(CODE.DISCOVERY_PKCE_MISSING, 'discovery document does not advertise PKCE methods', 'code_challenge_methods_supported'));
    }
    return;
  }
  if (!methods.includes('S256')) {
    findings.push(makeFinding(CODE.DISCOVERY_PKCE_MISSING, 'discovery document does not advertise S256 PKCE', 'code_challenge_methods_supported', OAUTHCAGE_SEVERITY.CRITICAL));
  }
  if (methods.includes('plain')) {
    findings.push(makeFinding(CODE.DISCOVERY_INSECURE_FLOW, 'discovery document advertises plain PKCE downgrade support', 'code_challenge_methods_supported', OAUTHCAGE_SEVERITY.CRITICAL));
  }
}

export function auditDiscoveryMetadata(input, options = {}) {
  const checkedOptions = validateOptionsObject(options, DISCOVERY_OPTION_KEYS, 'auditDiscoveryMetadata');
  const policy = resolvePolicy(checkedOptions, 'auditDiscoveryMetadata');
  const findings = [];
  const document = parseDiscoveryInput(input, policy, findings);
  if (document === null || !isPlainObject(document)) {
    findings.push(makeFinding(CODE.DISCOVERY_INVALID_DOCUMENT, 'discovery document must be a JSON object', 'discovery'));
  }
  let usable = isPlainObject(document);
  if (usable) {
    const prototypeKey = scanPrototypeKeys(document);
    if (prototypeKey !== null) {
      findings.push(makeFinding(CODE.PROTOTYPE_POLLUTION, 'discovery document contains a prototype pollution key', 'discovery', OAUTHCAGE_SEVERITY.CRITICAL));
      usable = false;
    }
    const stats = documentStats(document);
    if (stats.cyclic || stats.maxDepth > policy.maxDiscoveryDepth || stats.keys > policy.maxDiscoveryKeys) {
      findings.push(makeFinding(CODE.RESOURCE_LIMIT, 'discovery document exceeds depth, key count, or structure limits', 'discovery'));
      usable = false;
    }
  }

  let issuerCanonical = null;
  let expectedCanonical = null;
  if (usable) {
    if (typeof document.issuer !== 'string' || document.issuer.length === 0) {
      findings.push(makeFinding(CODE.DISCOVERY_ISSUER_REQUIRED, 'discovery document requires issuer', 'issuer'));
    } else {
      issuerCanonical = canonicalHttps(document.issuer, policy, 'issuer', findings);
      const issuerParts = typeof document.issuer === 'string' ? endpointParts(document.issuer, 'issuer', findings) : null;
      if (issuerParts && issuerParts.query !== null) {
        findings.push(makeFinding(CODE.DISCOVERY_INVALID_DOCUMENT, 'issuer must not contain a query component', 'issuer'));
      }
    }
    if (typeof checkedOptions.expectedIssuer !== 'string' || checkedOptions.expectedIssuer.length === 0) {
      findings.push(makeFinding(CODE.ISSUER_EXPECTED_REQUIRED, 'expectedIssuer is required for issuer confusion defense', 'expectedIssuer'));
    } else {
      expectedCanonical = canonicalHttps(checkedOptions.expectedIssuer, policy, 'expectedIssuer', findings);
    }
    if (issuerCanonical !== null && expectedCanonical !== null && issuerCanonical !== expectedCanonical) {
      findings.push(makeFinding(CODE.DISCOVERY_ISSUER_MISMATCH, 'discovery issuer does not exactly match the expected issuer', 'issuer', OAUTHCAGE_SEVERITY.CRITICAL));
    }

    for (const key of ENDPOINT_KEYS) {
      const value = document[key];
      const required = REQUIRED_ENDPOINT_KEYS.includes(key);
      if (value === undefined) {
        if (required) findings.push(makeFinding(CODE.DISCOVERY_ENDPOINT_REQUIRED, 'discovery document lacks a required HTTPS endpoint', key));
        continue;
      }
      if (typeof value !== 'string') {
        findings.push(makeFinding(CODE.ENDPOINT_INVALID, 'discovery endpoint must be a string', key));
        continue;
      }
      const endpointResult = auditEndpointUrl(value, { policy });
      for (const finding of endpointResult.findings) findings.push(endpointFindingCopy(finding, key));
    }
    auditAlgorithmMetadata(document, policy, findings);
    auditFlowMetadata(document, findings);
    auditPkceMetadata(document, policy, findings);
  }

  return finishAudit('discovery-metadata', policy.name, findings, {
    issuerMatches: issuerCanonical !== null && expectedCanonical !== null && issuerCanonical === expectedCanonical,
    requiredEndpointsPresent: usable ? REQUIRED_ENDPOINT_KEYS.every((key) => typeof document[key] === 'string') : false,
    endpointsAudited: usable ? ENDPOINT_KEYS.filter((key) => typeof document[key] === 'string').length : 0
  });
}
