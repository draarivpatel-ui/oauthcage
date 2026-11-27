/* RFC 3986 aware redirect URI parsing, canonicalization, and exact-match enforcement. */

import { domainToASCII } from 'node:url';
import { CODE, OAuthCageError, OAUTHCAGE_SEVERITY } from './errors.mjs';
import { parseIpv4Like, parseIpv6Literal } from './network.mjs';
import { collectStringFindings, deepFreeze, finishAudit, hasErrorFinding, makeFinding, percentDecode, SENSITIVE_PARAMETER_NAMES, validateOptionsObject } from './util.mjs';
import { createOAuthPolicy, resolvePolicy } from './policy.mjs';

const REDIRECT_OPTION_KEYS = Object.freeze([
  'policy',
  'registeredRedirectUris',
  'allowLoopbackHttp',
  'allowLocalhostHttp',
  'allowCustomSchemes',
  'allowedCustomSchemes',
  'maxUriLength'
]);
const UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
const DANGEROUS_SCHEMES = new Set(['javascript', 'data', 'vbscript', 'file', 'blob', 'filesystem']);
const FORBIDDEN_ASCII = new Set(['<', '>', '"', '{', '}', '|', '^', '`']);

function canonicalizeIpv6Groups(groups) {
  const tokens = groups.map((group) => group.toString(16));
  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;
  for (let index = 0; index < groups.length; index += 1) {
    if (groups[index] === 0) {
      if (currentStart === -1) currentStart = index;
      currentLength += 1;
    } else {
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
      currentStart = -1;
      currentLength = 0;
    }
  }
  if (currentLength > bestLength) {
    bestStart = currentStart;
    bestLength = currentLength;
  }
  if (bestLength < 2) return tokens.join(':');
  const left = tokens.slice(0, bestStart).join(':');
  const right = tokens.slice(bestStart + bestLength).join(':');
  if (left === '' && right === '') return '::';
  if (left === '') return '::' + right;
  if (right === '') return left + '::';
  return left + '::' + right;
}

function addBasicFindings(input, field, maxLength, findings) {
  const before = findings.length;
  collectStringFindings(input, field, maxLength, findings);
  return findings.length === before;
}

function splitScheme(input) {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/u.exec(input);
  if (!match) return null;
  return { scheme: match[1].toLowerCase(), rest: match[2] };
}

function splitQuery(text) {
  const index = text.indexOf('?');
  if (index === -1) return { beforeQuery: text, query: null };
  return { beforeQuery: text.slice(0, index), query: text.slice(index + 1) };
}

function parseAuthority(beforeQuery, field, findings) {
  if (!beforeQuery.startsWith('//')) return { authority: null, path: beforeQuery };
  const remainder = beforeQuery.slice(2);
  const slash = remainder.indexOf('/');
  const authority = slash === -1 ? remainder : remainder.slice(0, slash);
  const path = slash === -1 ? '' : remainder.slice(slash);
  if (authority.length === 0) {
    findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' has an empty authority', field));
    return { authority: null, path };
  }
  if (authority.includes('@')) {
    findings.push(makeFinding(CODE.REDIRECT_USERINFO, field + ' contains user information', field));
  }
  let hostText = '';
  let portText = null;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close === -1) {
      findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' has malformed IPv6 brackets', field));
      hostText = authority;
    } else {
      hostText = authority.slice(1, close);
      const suffix = authority.slice(close + 1);
      if (suffix.length > 0) {
        if (!suffix.startsWith(':')) {
          findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' has malformed text after an IPv6 host', field));
        } else {
          portText = suffix.slice(1);
        }
      }
    }
  } else {
    const colonCount = (authority.match(/:/gu) || []).length;
    if (colonCount > 1) {
      findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' contains an unbracketed IPv6 literal', field));
      hostText = authority;
    } else if (colonCount === 1) {
      const colon = authority.lastIndexOf(':');
      hostText = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
    } else {
      hostText = authority;
    }
  }
  if (hostText.length === 0) findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' has an empty host', field));
  let port = null;
  if (portText !== null) {
    if (!/^[0-9]{1,5}$/u.test(portText) || Number(portText) > 65535 || Number(portText) === 0) {
      findings.push(makeFinding(CODE.REDIRECT_PORT_INVALID, field + ' has an invalid port', field));
    } else {
      port = portText.replace(/^0+(?=[0-9])/u, '');
    }
  }
  return { authority: { rawHost: hostText, port, bracketed: authority.startsWith('[') }, path };
}

function canonicalHost(hostText, bracketed, field, findings) {
  if (bracketed) {
    const parsed = parseIpv6Literal(hostText);
    if (!parsed || !parsed.valid) {
      findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' has an invalid IPv6 host', field));
      return null;
    }
    return { text: '[' + canonicalizeIpv6Groups(parsed.groups) + ']', kind: 'ipv6', loopback: parsed.groups.every((group, index) => index < 7 ? group === 0 : group === 1) };
  }
  if (/[%\[\]]/u.test(hostText)) {
    findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' host contains forbidden characters', field));
    return null;
  }
  const ipv4 = parseIpv4Like(hostText);
  if (ipv4 && ipv4.valid && !ipv4.obfuscated) {
    return { text: ipv4.canonical, kind: 'ipv4', loopback: ipv4.canonical === '127.0.0.1' };
  }
  if (ipv4 && ipv4.numericLike) {
    findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' host uses an ambiguous IPv4 representation', field));
    return null;
  }
  const ascii = domainToASCII(hostText);
  if (ascii.length === 0 || ascii.length > 253) {
    findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' host is not a valid DNS name', field));
    return null;
  }
  const lower = ascii.toLowerCase();
  const labels = lower.endsWith('.') ? lower.slice(0, -1).split('.') : lower.split('.');
  if (labels.some((label) => label.length === 0 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) {
    findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' host is not a valid DNS name', field));
    return null;
  }
  const stripped = lower.endsWith('.') ? lower.slice(0, -1) : lower;
  return { text: lower, kind: 'domain', loopback: stripped === 'localhost' };
}

function canonicalizeComponent(text, context, field, findings) {
  try {
    const fullyDecoded = percentDecode(text);
    if (/[\u0000-\u001F\u007F-\u009F]/u.test(fullyDecoded)) {
      findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' contains an encoded control character', field));
    }
    if (/[\u00AD\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(fullyDecoded)) {
      findings.push(makeFinding(CODE.BIDI_CONTROL, field + ' contains an encoded hidden or bidi character', field));
    }
  } catch {
    findings.push(makeFinding(CODE.INVALID_ENCODING, field + ' percent encoding does not form valid UTF-8', field));
  }
  let output = '';
  let valid = true;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '%') {
      if (index + 2 >= text.length || !/^[0-9A-Fa-f]{2}$/u.test(text.slice(index + 1, index + 3))) {
        findings.push(makeFinding(CODE.INVALID_ENCODING, field + ' contains malformed percent encoding', field));
        valid = false;
        output += '%';
        continue;
      }
      const byte = Number.parseInt(text.slice(index + 1, index + 3), 16);
      const decoded = String.fromCharCode(byte);
      if (byte <= 0x1F || byte === 0x7F) {
        findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' contains a percent encoded control character', field));
        valid = false;
      }
      if (context === 'path' && byte === 0x25) {
        findings.push(makeFinding(CODE.REDIRECT_DOUBLE_ENCODING, field + ' contains an encoded percent sign that can double decode', field));
        valid = false;
      }
      if (context === 'path' && (byte === 0x2F || byte === 0x5C)) {
        findings.push(makeFinding(byte === 0x2F ? CODE.REDIRECT_PATH_TRAVERSAL : CODE.REDIRECT_BACKSLASH, field + ' contains an encoded path separator', field));
        valid = false;
      }
      if (UNRESERVED.includes(decoded)) output += decoded;
      else output += '%' + text.slice(index + 1, index + 3).toUpperCase();
      index += 2;
    } else {
      if (FORBIDDEN_ASCII.has(character) || character === '\\') {
        findings.push(makeFinding(character === '\\' ? CODE.REDIRECT_BACKSLASH : CODE.REDIRECT_INVALID, field + ' contains a character that must be percent encoded', field));
        valid = false;
      }
      output += character;
    }
  }
  return valid ? output : output;
}

function scanPath(path, field, findings) {
  if (path.includes('//')) {
    findings.push(makeFinding(CODE.REDIRECT_DOUBLE_SLASH, field + ' contains a repeated path slash', field));
  }
  for (const segment of path.split('/')) {
    if (segment.length === 0) continue;
    let decoded;
    try {
      decoded = percentDecode(segment);
    } catch {
      findings.push(makeFinding(CODE.INVALID_ENCODING, field + ' path contains invalid percent encoded UTF-8', field));
      continue;
    }
    if (decoded === '.' || decoded === '..' || /^\.+$/u.test(decoded)) {
      findings.push(makeFinding(CODE.REDIRECT_PATH_TRAVERSAL, field + ' path contains a dot traversal segment', field));
    }
    if (decoded.includes('/')) {
      findings.push(makeFinding(CODE.REDIRECT_PATH_TRAVERSAL, field + ' path contains an encoded slash separator', field));
    }
    if (decoded.includes('\\')) {
      findings.push(makeFinding(CODE.REDIRECT_BACKSLASH, field + ' path contains an encoded backslash', field));
    }
    if (/\s/u.test(decoded)) {
      findings.push(makeFinding(CODE.WHITESPACE, field + ' path contains encoded whitespace', field));
    }
    if (/[\u0000-\u001F\u007F-\u009F]/u.test(decoded)) {
      findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' path contains an encoded control character', field));
    }
    if (/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/u.test(decoded)) {
      findings.push(makeFinding(CODE.BIDI_CONTROL, field + ' path contains an encoded bidirectional control', field));
    }
  }
}

function scanQuery(query, field, findings) {
  if (query === null) return;
  for (const piece of query.split('&')) {
    const equals = piece.indexOf('=');
    const rawName = equals === -1 ? piece : piece.slice(0, equals);
    let decodedPiece;
    let name;
    try {
      decodedPiece = percentDecode(piece, { plusAsSpace: true });
      name = percentDecode(rawName, { plusAsSpace: true }).toLowerCase();
    } catch {
      findings.push(makeFinding(CODE.INVALID_ENCODING, field + ' query contains invalid percent encoded UTF-8', field));
      continue;
    }
    if (/\s/u.test(decodedPiece)) {
      findings.push(makeFinding(CODE.WHITESPACE, field + ' query contains encoded whitespace', field));
    }
    if (/[\u0000-\u001F\u007F-\u009F]/u.test(decodedPiece)) {
      findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' query contains an encoded control character', field));
    }
    if (/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/u.test(decodedPiece)) {
      findings.push(makeFinding(CODE.BIDI_CONTROL, field + ' query contains an encoded bidirectional control', field));
    }
    if (SENSITIVE_PARAMETER_NAMES.includes(name) || name === 'code') {
      findings.push(makeFinding(CODE.REDIRECT_SECRET_IN_QUERY, field + ' query contains a sensitive OAuth parameter name', field));
    }
  }
}

export function analyzeUri(input, policy, field) {
  const findings = [];
  if (!addBasicFindings(input, field, policy.maxUriLength, findings)) {
    return { canonical: null, meta: null, findings };
  }
  if (input.includes('#')) {
    findings.push(makeFinding(CODE.REDIRECT_FRAGMENT, field + ' must not contain a fragment', field));
  }
  if (input.includes('\\')) {
    findings.push(makeFinding(CODE.REDIRECT_BACKSLASH, field + ' must not contain a backslash', field));
  }
  const schemeParts = splitScheme(input);
  if (!schemeParts) {
    findings.push(makeFinding(CODE.REDIRECT_NOT_ABSOLUTE, field + ' must be an absolute URI with a scheme', field));
    return { canonical: null, meta: null, findings };
  }
  const { scheme, rest } = schemeParts;
  if (DANGEROUS_SCHEMES.has(scheme)) {
    findings.push(makeFinding(CODE.REDIRECT_DANGEROUS_SCHEME, field + ' uses a dangerous URI scheme', field));
  }
  const custom = scheme !== 'https' && scheme !== 'http';
  if (custom) {
    const explicitlyAllowed = policy.allowCustomSchemes && policy.allowedCustomSchemes.includes(scheme);
    if (!explicitlyAllowed) {
      findings.push(makeFinding(CODE.REDIRECT_CUSTOM_SCHEME, field + ' uses a custom scheme that is not explicitly allowlisted', field));
    } else if (!scheme.includes('.')) {
      findings.push(makeFinding(CODE.REDIRECT_CUSTOM_SCHEME, field + ' custom scheme is not reverse domain qualified', field));
    } else {
      findings.push(makeFinding(CODE.REDIRECT_CUSTOM_SCHEME, field + ' uses a custom scheme with platform hijacking risk', field, OAUTHCAGE_SEVERITY.WARNING));
    }
  } else if (!policy.allowedRedirectSchemes.includes(scheme)) {
    findings.push(makeFinding(CODE.REDIRECT_SCHEME_DENIED, field + ' uses a URI scheme denied by policy', field));
  }

  const querySplit = splitQuery(rest);
  const authorityParts = parseAuthority(querySplit.beforeQuery, field, findings);
  let canonicalAuthority = '';
  let hostInfo = null;
  if ((scheme === 'https' || scheme === 'http') && authorityParts.authority === null) {
    findings.push(makeFinding(CODE.REDIRECT_HOST_INVALID, field + ' requires an authority host', field));
  }
  if (authorityParts.authority !== null) {
    hostInfo = canonicalHost(authorityParts.authority.rawHost, authorityParts.authority.bracketed, field, findings);
    if (hostInfo !== null) {
      canonicalAuthority = '//' + hostInfo.text + (authorityParts.authority.port === null ? '' : ':' + authorityParts.authority.port);
    }
  }
  if (scheme === 'http' && hostInfo !== null) {
    const hostText = hostInfo.text;
    const loopback = hostInfo.kind === 'ipv4' ? hostText === '127.0.0.1' : hostInfo.kind === 'ipv6' ? hostText === '[::1]' : false;
    const localhost = hostInfo.kind === 'domain' && hostText.replace(/\.$/u, '') === 'localhost';
    if (!loopback && !(localhost && policy.allowLocalhostHttp)) {
      findings.push(makeFinding(localhost ? CODE.REDIRECT_LOCALHOST_HTTP : CODE.REDIRECT_HTTP_NOT_LOOPBACK, field + ' uses HTTP outside an approved loopback redirect', field));
    }
    if ((loopback || localhost) && !policy.allowLoopbackHttp) {
      findings.push(makeFinding(CODE.REDIRECT_HTTP_NOT_LOOPBACK, field + ' uses HTTP when loopback HTTP is disabled', field));
    }
  }

  const canonicalPath = canonicalizeComponent(authorityParts.path, 'path', field, findings);
  scanPath(canonicalPath, field, findings);
  const canonicalQuery = querySplit.query === null ? null : canonicalizeComponent(querySplit.query, 'query', field, findings);
  scanQuery(querySplit.query, field, findings);
  const canonical = scheme + ':' + canonicalAuthority + canonicalPath + (canonicalQuery === null ? '' : '?' + canonicalQuery);
  const meta = deepFreeze({
    scheme,
    customScheme: custom,
    hasAuthority: authorityParts.authority !== null,
    hostKind: hostInfo ? hostInfo.kind : null,
    loopback: hostInfo ? hostInfo.loopback : false,
    port: authorityParts.authority ? authorityParts.authority.port : null,
    hasQuery: querySplit.query !== null
  });
  return { canonical, meta, findings };
}

function normalizeRegistered(registeredRedirectUris) {
  if (typeof registeredRedirectUris === 'string') return [registeredRedirectUris];
  if (Array.isArray(registeredRedirectUris)) return registeredRedirectUris.slice();
  return [];
}

function directPolicyOverrides(options) {
  const patch = {};
  for (const key of ['allowLoopbackHttp', 'allowLocalhostHttp', 'allowCustomSchemes', 'allowedCustomSchemes', 'maxUriLength']) {
    if (Object.prototype.hasOwnProperty.call(options, key)) patch[key] = options[key];
  }
  if (Object.keys(patch).length === 0) return null;
  return patch;
}

function effectivePolicy(options, caller) {
  const base = resolvePolicy(options, caller);
  const patch = directPolicyOverrides(options);
  if (!patch) return base;
  return createOAuthPolicy(base.name, patch);
}


export function auditRedirectUri(candidate, registeredRedirectUris, options = {}) {
  const sourceOptions = validateOptionsObject(options, REDIRECT_OPTION_KEYS, 'auditRedirectUri');
  const policy = effectivePolicy(sourceOptions, 'auditRedirectUri');
  const registeredInput = registeredRedirectUris === undefined ? sourceOptions.registeredRedirectUris : registeredRedirectUris;
  const registeredList = normalizeRegistered(registeredInput);
  const findings = [];
  if (registeredList.length === 0) {
    findings.push(makeFinding(CODE.REDIRECT_ALLOWLIST_REQUIRED, 'a registered redirect URI allowlist is required', 'registeredRedirectUris'));
  }
  const analyzedCandidate = analyzeUri(candidate, policy, 'redirect_uri');
  findings.push(...analyzedCandidate.findings);
  const canonicalRegistered = [];
  for (let index = 0; index < registeredList.length; index += 1) {
    const analyzed = analyzeUri(registeredList[index], policy, 'registered_redirect_uri');
    for (const finding of analyzed.findings) {
      findings.push(makeFinding(finding.code, 'registered redirect URI is unsafe: ' + finding.message, 'registeredRedirectUris', finding.severity));
    }
    if (analyzed.canonical !== null && !hasErrorFinding(analyzed.findings)) canonicalRegistered.push(analyzed.canonical);
  }
  const matched = analyzedCandidate.canonical !== null && canonicalRegistered.includes(analyzedCandidate.canonical);
  if (!matched && canonicalRegistered.length > 0) {
    findings.push(makeFinding(CODE.REDIRECT_MISMATCH, 'redirect URI does not exactly match a registered canonical URI', 'redirect_uri', OAUTHCAGE_SEVERITY.CRITICAL));
  }
  const safeCandidate = !hasErrorFinding(analyzedCandidate.findings);
  return finishAudit('redirect-uri', policy.name, findings, {
    uri: safeCandidate && matched ? analyzedCandidate.canonical : null,
    matched,
    matchedUri: safeCandidate && matched ? analyzedCandidate.canonical : null,
    meta: analyzedCandidate.meta
  }, policy.maxFindings);
}

export function validateRedirectUri(candidate, registeredRedirectUris, options = {}) {
  const result = auditRedirectUri(candidate, registeredRedirectUris, options);
  if (!result.ok) {
    const first = result.findings.find((finding) => finding.severity === 'critical' || finding.severity === 'error') || result.findings[0];
    throw new OAuthCageError(first.code, first.message, { field: first.field });
  }
  return result.uri;
}
