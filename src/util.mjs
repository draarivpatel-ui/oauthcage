/* Shared validation, freezing, constant-time comparison, and encoding helpers. */

import { createHash, timingSafeEqual } from 'node:crypto';
import { CODE, OAuthCageError, OAUTHCAGE_SEVERITY } from './errors.mjs';

export const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001F\u007F-\u009F]/u;
export const BIDI_OR_INVISIBLE_PATTERN = /[\u00AD\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u;
export const WHITESPACE_PATTERN = /\s/u;
export const SENSITIVE_PARAMETER_NAMES = Object.freeze([
  'access_token',
  'id_token',
  'refresh_token',
  'client_secret',
  'code_verifier',
  'password',
  'assertion',
  'token'
]);

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function deepFreeze(value, seen = new Set()) {
  if (value === null || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const key of Object.keys(value)) deepFreeze(value[key], seen);
  return Object.freeze(value);
}

export function makeFinding(code, message, field, severity = OAUTHCAGE_SEVERITY.ERROR) {
  return deepFreeze({ code, severity, message, field });
}

export function hasErrorFinding(findings) {
  return findings.some((finding) => finding.severity === OAUTHCAGE_SEVERITY.ERROR || finding.severity === OAUTHCAGE_SEVERITY.CRITICAL);
}

export function finishAudit(kind, policyName, findings, extra) {
  return deepFreeze({
    kind,
    policy: policyName,
    ok: !hasErrorFinding(findings),
    findings: findings.slice(),
    ...(extra || {})
  });
}

export function validateOptionsObject(options, allowedKeys, caller) {
  if (options === undefined) return {};
  if (!isPlainObject(options)) {
    throw new OAuthCageError(CODE.INVALID_OPTIONS, caller + ' options must be a plain object');
  }
  for (const key of Object.keys(options)) {
    if (!allowedKeys.includes(key)) {
      throw new OAuthCageError(CODE.INVALID_OPTIONS, caller + ' received an unknown option', { field: key });
    }
  }
  return options;
}

export function hasUnpairedSurrogate(text) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 0xD800 && code <= 0xDBFF) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) return true;
      index += 1;
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      return true;
    }
  }
  return false;
}

export function firstUnsafeCharacter(text) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.codePointAt(index);
    if (code <= 0x1F || (code >= 0x7F && code <= 0x9F)) return { kind: 'control', index };
    if (
      code === 0x00AD ||
      (code >= 0x200B && code <= 0x200F) ||
      (code >= 0x202A && code <= 0x202E) ||
      (code >= 0x2066 && code <= 0x2069) ||
      code === 0xFEFF
    ) {
      return { kind: 'bidi', index };
    }
    if (code > 0xFFFF) index += 1;
  }
  return null;
}

export function collectStringFindings(input, field, maxLength, findings) {
  if (typeof input !== 'string') {
    findings.push(makeFinding(CODE.INVALID_INPUT, field + ' must be a string', field));
    return false;
  }
  if (input.length === 0) {
    findings.push(makeFinding(CODE.INVALID_INPUT, field + ' must not be empty', field));
    return false;
  }
  if (input.length > maxLength) {
    findings.push(makeFinding(CODE.INPUT_TOO_LONG, field + ' exceeds the configured length limit', field));
    return false;
  }
  if (hasUnpairedSurrogate(input)) {
    findings.push(makeFinding(CODE.UNPAIRED_SURROGATE, field + ' contains an unpaired surrogate', field));
  }
  const unsafe = firstUnsafeCharacter(input);
  if (unsafe) {
    findings.push(makeFinding(
      unsafe.kind === 'control' ? CODE.CONTROL_CHARACTER : CODE.BIDI_CONTROL,
      field + ' contains a hidden or control character',
      field
    ));
  }
  if (WHITESPACE_PATTERN.test(input)) {
    findings.push(makeFinding(CODE.WHITESPACE, field + ' contains whitespace', field));
  }
  return findings.length === 0;
}

export function assertString(input, caller, field) {
  if (typeof input !== 'string') {
    throw new OAuthCageError(CODE.INVALID_INPUT, caller + ' requires ' + field + ' to be a string', { field });
  }
  return input;
}

export function asciiHex(byte) {
  return byte.toString(16).toUpperCase().padStart(2, '0');
}

export function percentDecode(text, options = {}) {
  const plusAsSpace = options.plusAsSpace === true;
  const bytes = [];
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === '%') {
      if (index + 2 >= text.length || !/^[0-9A-Fa-f]{2}$/u.test(text.slice(index + 1, index + 3))) {
        throw new OAuthCageError(CODE.INVALID_ENCODING, 'percent encoding is incomplete or malformed');
      }
      bytes.push(Number.parseInt(text.slice(index + 1, index + 3), 16));
      index += 2;
    } else if (character === '+' && plusAsSpace) {
      bytes.push(0x20);
    } else {
      bytes.push(...Buffer.from(character, 'utf8'));
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes));
  } catch {
    throw new OAuthCageError(CODE.INVALID_ENCODING, 'percent encoding does not decode as valid UTF-8');
  }
}

export function timingSafeStringEqual(left, right) {
  const leftHash = createHash('sha256').update(left, 'utf8').digest();
  const rightHash = createHash('sha256').update(right, 'utf8').digest();
  return timingSafeEqual(leftHash, rightHash);
}

export function repeatedChunkPattern(value) {
  for (let width = 1; width <= 12; width += 1) {
    if (value.length % width !== 0) continue;
    const chunk = value.slice(0, width);
    let repeats = true;
    for (let index = width; index < value.length; index += width) {
      if (value.slice(index, index + width) !== chunk) {
        repeats = false;
        break;
      }
    }
    if (repeats) return true;
  }
  return false;
}

export function sequentialCharacters(value) {
  if (value.length < 4) return false;
  let ascending = true;
  let descending = true;
  for (let index = 1; index < value.length; index += 1) {
    const difference = value.charCodeAt(index) - value.charCodeAt(index - 1);
    if (difference !== 1) ascending = false;
    if (difference !== -1) descending = false;
  }
  return ascending || descending;
}

export function predictableToken(value) {
  const lower = value.toLowerCase();
  const known = new Set([
    'state',
    'nonce',
    'token',
    'secret',
    'password',
    '1234567890123456789012',
    'abcdefghijklmnopqrstuv',
    'abcdefghijklmnopqrstuvwxyz',
    'aaaaaaaaaaaaaaaaaaaaaa',
    '0000000000000000000000'
  ]);
  if (known.has(lower)) return true;
  if (new Set(value).size <= 2) return true;
  if (sequentialCharacters(value)) return true;
  return repeatedChunkPattern(value);
}

export function scanPrototypeKeys(value, depth = 0, state = { count: 0, maxDepth: 0, seen: new Set() }) {
  if (value === null || typeof value !== 'object') return null;
  if (state.seen.has(value)) return null;
  state.seen.add(value);
  state.count += 1;
  state.maxDepth = Math.max(state.maxDepth, depth);
  const keys = Array.isArray(value) ? value.map((_, index) => String(index)) : Object.keys(value);
  for (const key of keys) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return key;
    const nested = scanPrototypeKeys(value[key], depth + 1, state);
    if (nested !== null) return nested;
  }
  return null;
}

export function escapeCodePoint(codePoint) {
  if (codePoint <= 0xFF) return '\\x' + codePoint.toString(16).toUpperCase().padStart(2, '0');
  return '\\u' + codePoint.toString(16).toUpperCase().padStart(4, '0');
}

export function neutralizeTerminal(text) {
  let output = '';
  for (let index = 0; index < text.length; index += 1) {
    const codePoint = text.codePointAt(index);
    if (codePoint > 0xFFFF) index += 1;
    if (codePoint === 0x0A) {
      output += '\n';
    } else if (
      codePoint <= 0x1F ||
      (codePoint >= 0x7F && codePoint <= 0x9F) ||
      codePoint === 0x00AD ||
      (codePoint >= 0x200B && codePoint <= 0x200F) ||
      (codePoint >= 0x2028 && codePoint <= 0x202E) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069) ||
      codePoint === 0xFEFF
    ) {
      output += escapeCodePoint(codePoint);
    } else {
      output += String.fromCodePoint(codePoint);
    }
  }
  return output;
}

export function redactSensitiveText(text) {
  let output = String(text);
  output = output.replace(/([?&#]?(?:access_token|id_token|refresh_token|client_secret|code_verifier|password|assertion|token|code)=)[^&\s#]*/giu, '$1[REDACTED]');
  return neutralizeTerminal(output);
}

export function containsSensitiveParameter(names) {
  return names.some((name) => SENSITIVE_PARAMETER_NAMES.includes(name));
}
