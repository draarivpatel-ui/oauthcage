/* Duplicate-preserving application/x-www-form-urlencoded parameter parsing. */

import { CODE } from './errors.mjs';
import { collectStringFindings, isPlainObject, makeFinding, percentDecode, scanPrototypeKeys } from './util.mjs';

function pushParameter(target, name, value) {
  if (!Object.prototype.hasOwnProperty.call(target, name)) target[name] = [];
  target[name].push(value);
}

export function parseParameterString(text, policy, field) {
  const findings = [];
  const values = Object.create(null);
  const entries = [];
  if (typeof text !== 'string') {
    findings.push(makeFinding(CODE.INVALID_INPUT, field + ' parameters must be a string', field));
    return { values, entries, findings };
  }
  collectStringFindings(text, field, policy.maxInputLength, findings);
  if (text.length === 0) return { values, entries, findings };
  const pieces = text.split('&');
  if (pieces.length > policy.maxParameterCount) {
    findings.push(makeFinding(CODE.PARAMETER_COUNT_EXCEEDED, field + ' exceeds the parameter count limit', field));
  }
  for (const piece of pieces) {
    if (piece.length === 0) {
      findings.push(makeFinding(CODE.INVALID_INPUT, field + ' contains an empty parameter segment', field));
      continue;
    }
    if (piece.length > policy.maxParameterLength) {
      findings.push(makeFinding(CODE.PARAMETER_TOO_LONG, field + ' contains an oversized parameter', field));
      continue;
    }
    const equals = piece.indexOf('=');
    const rawName = equals === -1 ? piece : piece.slice(0, equals);
    const rawValue = equals === -1 ? '' : piece.slice(equals + 1);
    let name;
    let value;
    try {
      name = percentDecode(rawName, { plusAsSpace: true });
      value = percentDecode(rawValue, { plusAsSpace: true });
    } catch {
      findings.push(makeFinding(CODE.INVALID_ENCODING, field + ' contains malformed percent encoded UTF-8', field));
      continue;
    }
    if (/[\u0000-\u001F\u007F-\u009F]/u.test(value)) {
      findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' contains a control character in a parameter value', field));
      continue;
    }
    if (/[\u00AD\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(value)) {
      findings.push(makeFinding(CODE.BIDI_CONTROL, field + ' contains a hidden or bidi character in a parameter value', field));
      continue;
    }
    if (name.length === 0) {
      findings.push(makeFinding(CODE.INVALID_INPUT, field + ' contains an empty parameter name', field));
      continue;
    }
    if (name.length > 128 || value.length > policy.maxParameterLength) {
      findings.push(makeFinding(CODE.PARAMETER_TOO_LONG, field + ' contains an oversized parameter component', field));
      continue;
    }
    if (/[\u0000-\u001F\u007F-\u009F]/u.test(name)) {
      findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' contains a control character in a parameter name', field));
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(values, name)) {
      findings.push(makeFinding(CODE.DUPLICATE_PARAMETER, field + ' contains a duplicate parameter name', field));
    }
    pushParameter(values, name, value);
    entries.push(Object.freeze({ name, value }));
  }
  return { values, entries, findings };
}

export function parseParameterObject(input, policy, field) {
  const findings = [];
  const values = Object.create(null);
  const entries = [];
  if (!isPlainObject(input)) {
    findings.push(makeFinding(CODE.INVALID_INPUT, field + ' parameters must be a plain object or encoded string', field));
    return { values, entries, findings };
  }
  if (scanPrototypeKeys(input) !== null) {
    findings.push(makeFinding(CODE.PROTOTYPE_POLLUTION, field + ' contains a prototype pollution key', field, 'critical'));
    return { values, entries, findings };
  }
  const keys = Object.keys(input);
  if (keys.length > policy.maxParameterCount) {
    findings.push(makeFinding(CODE.PARAMETER_COUNT_EXCEEDED, field + ' exceeds the parameter count limit', field));
  }
  for (const name of keys) {
    if (name.length === 0 || name.length > 128) {
      findings.push(makeFinding(CODE.INVALID_INPUT, field + ' contains an invalid parameter name', field));
      continue;
    }
    if (/[\u0000-\u001F\u007F-\u009F\s]/u.test(name)) {
      findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' contains whitespace or a control character in a parameter name', field));
      continue;
    }
    const raw = input[name];
    const list = Array.isArray(raw) ? raw : [raw];
    if (list.length !== 1) {
      findings.push(makeFinding(CODE.DUPLICATE_PARAMETER, field + ' contains repeated values for one parameter name', field));
    }
    for (const item of list) {
      if (typeof item !== 'string') {
        findings.push(makeFinding(CODE.INVALID_INPUT, field + ' parameter values must be strings', field));
        continue;
      }
      if (item.length > policy.maxParameterLength) {
        findings.push(makeFinding(CODE.PARAMETER_TOO_LONG, field + ' contains an oversized parameter value', field));
        continue;
      }
      if (/[\u0000-\u001F\u007F-\u009F]/u.test(item)) {
        findings.push(makeFinding(CODE.CONTROL_CHARACTER, field + ' contains a control character in a parameter value', field));
        continue;
      }
      if (/[\u00AD\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(item)) {
        findings.push(makeFinding(CODE.BIDI_CONTROL, field + ' contains a hidden or bidi character in a parameter value', field));
        continue;
      }
      pushParameter(values, name, item);
      entries.push(Object.freeze({ name, value: item }));
    }
  }
  return { values, entries, findings };
}

export function firstValue(values, name) {
  const list = values[name];
  return Array.isArray(list) && list.length > 0 ? list[0] : undefined;
}

export function hasParameter(values, name) {
  return Object.prototype.hasOwnProperty.call(values, name);
}

export function splitUrlParameters(input, policy, field) {
  const findings = [];
  collectStringFindings(input, field, policy.maxInputLength, findings);
  if (typeof input !== 'string') return { base: null, query: null, fragment: null, findings };
  let text = input;
  if (text.startsWith('#')) return { base: null, query: null, fragment: text.slice(1), findings };
  if (text.startsWith('?')) {
    const shorthand = text.slice(1);
    const shorthandHash = shorthand.indexOf('#');
    if (shorthandHash === -1) return { base: null, query: shorthand, fragment: null, findings };
    return { base: null, query: shorthand.slice(0, shorthandHash), fragment: shorthand.slice(shorthandHash + 1), findings };
  }
  const hash = text.indexOf('#');
  let fragment = null;
  if (hash !== -1) {
    fragment = text.slice(hash + 1);
    text = text.slice(0, hash);
  }
  const question = text.indexOf('?');
  if (question !== -1) {
    return { base: text.slice(0, question), query: text.slice(question + 1), fragment, findings };
  }
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(text)) {
    return { base: text, query: null, fragment, findings };
  }
  return { base: null, query: text, fragment, findings };
}

export function parseParameters(input, policy, field) {
  if (typeof input === 'string') return parseParameterString(input, policy, field);
  return parseParameterObject(input, policy, field);
}
