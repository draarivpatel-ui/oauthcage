#!/usr/bin/env node
/* oauthcage command line interface. Output never echoes caller supplied secret values. */

import {
  auditAuthRequest,
  auditCallback,
  auditDiscoveryMetadata,
  auditRedirectUri,
  createPkcePair,
  getPolicy,
  neutralizeTerminal,
  verifyPkce,
  OAUTHCAGE_VERSION
} from '../src/index.mjs';

const STDIN_LIMIT = 1024 * 1024;
const COMMANDS = new Set(['audit-redirect', 'audit-auth-url', 'audit-callback', 'audit-discovery', 'verify-pkce', 'gen-pkce', 'help', '--help', '-h', '--version']);

class CliUsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CliUsageError';
  }
}

function writeOut(text) {
  process.stdout.write(neutralizeTerminal(text) + '\n');
}

function writeErr(text) {
  process.stderr.write(neutralizeTerminal(text) + '\n');
}

function usage() {
  return [
    'oauthcage ' + OAUTHCAGE_VERSION,
    '',
    'Usage:',
    '  oauthcage gen-pkce [--json]',
    '  oauthcage verify-pkce --verifier <verifier> --challenge <challenge> [--method S256] [--policy strict] [--json]',
    '  oauthcage audit-redirect <uri|-> --registered <uri> [--registered <uri>] [--policy strict] [--json]',
    '  oauthcage audit-auth-url <url|-> --registered <uri> [--registered <uri>] [--policy strict] [--json]',
    '  oauthcage audit-callback <url|-> [--expected-state <state>] [--expected-issuer <issuer>] [--policy strict] [--json]',
    '  oauthcage audit-discovery <json|-> --expected-issuer <issuer> [--policy strict] [--json]',
    '',
    'Use - to read exactly bounded stdin. Input whitespace is never trimmed away.'
  ].join('\n');
}

function parseArgs(argv) {
  const positional = [];
  const options = Object.create(null);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') {
      positional.push(...argv.slice(index + 1));
      break;
    }
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf('=');
    const key = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    if (key === 'json') {
      options.json = true;
      continue;
    }
    let value;
    if (eq !== -1) {
      value = arg.slice(eq + 1);
    } else {
      index += 1;
      if (index >= argv.length) throw new CliUsageError('missing value for --' + key);
      value = argv[index];
    }
    if (Object.prototype.hasOwnProperty.call(options, key)) {
      if (!Array.isArray(options[key])) options[key] = [options[key]];
      options[key].push(value);
    } else {
      options[key] = value;
    }
  }
  return { positional, options };
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > STDIN_LIMIT) throw new CliUsageError('stdin exceeds the one mebibyte input limit');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function inputValue(positional) {
  if (positional.length > 1) throw new CliUsageError('too many positional input arguments');
  if (positional.length === 0 || positional[0] === '-') return await readStdin();
  return positional[0];
}

function listOption(options, key) {
  const value = options[key];
  if (value === undefined) return [];
  return Array.isArray(value) ? value.slice() : [value];
}

function policyOptions(options) {
  return { policy: options.policy === undefined ? 'strict' : options.policy };
}

function rejectUnknown(options, allowed) {
  for (const key of Object.keys(options)) {
    if (!allowed.includes(key)) throw new CliUsageError('unknown option --' + key);
  }
}

function errorObject(error) {
  return {
    code: typeof error.code === 'string' ? error.code : 'OAUTHCAGE_INVALID_INPUT',
    detail: typeof error.code === 'string' && error.code.startsWith('OAUTHCAGE_') && typeof error.detail === 'string' ? error.detail : 'command input could not be processed',
    field: typeof error.field === 'string' ? error.field : undefined
  };
}

function emitResult(command, result, json) {
  if (json) {
    writeOut(JSON.stringify(result, null, 2));
    return;
  }
  writeOut(command + ': ' + (result.ok ? 'pass' : 'fail'));
  for (const finding of result.findings || []) {
    writeOut(finding.severity + ' ' + finding.code + ' ' + finding.field + ' - ' + finding.message);
  }
}

function emitFailure(command, error, json) {
  const safe = errorObject(error);
  if (json) {
    writeOut(JSON.stringify({ kind: command, ok: false, error: safe }, null, 2));
  } else {
    writeErr(command + ': fail');
    writeErr('error ' + safe.code + (safe.field ? ' ' + safe.field : '') + ' - ' + safe.detail);
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const command = argv[0] || 'help';
  if (!COMMANDS.has(command)) throw new CliUsageError('unknown command');
  if (command === 'help' || command === '--help' || command === '-h') {
    writeOut(usage());
    return 0;
  }
  if (command === '--version') {
    writeOut(OAUTHCAGE_VERSION);
    return 0;
  }
  const { positional, options } = parseArgs(argv.slice(1));
  if (options.policy !== undefined) getPolicy(options.policy);

  if (command === 'gen-pkce') {
    rejectUnknown(options, ['json']);
    const pair = createPkcePair();
    if (options.json) writeOut(JSON.stringify(pair, null, 2));
    else {
      writeOut('code_verifier: ' + pair.verifier);
      writeOut('code_challenge: ' + pair.challenge);
      writeOut('code_challenge_method: S256');
    }
    return 0;
  }

  if (command === 'verify-pkce') {
    rejectUnknown(options, ['json', 'policy', 'verifier', 'challenge', 'method']);
    if (typeof options.verifier !== 'string' || typeof options.challenge !== 'string') {
      throw new CliUsageError('verify-pkce requires --verifier and --challenge');
    }
    try {
      verifyPkce(options.verifier, options.challenge, options.method || 'S256', getPolicy(options.policy || 'strict'));
      const result = { kind: 'verify-pkce', ok: true, findings: [] };
      emitResult(command, result, options.json === true);
      return 0;
    } catch (error) {
      emitFailure(command, error, options.json === true);
      return 1;
    }
  }

  if (command === 'audit-redirect') {
    rejectUnknown(options, ['json', 'policy', 'registered']);
    const input = await inputValue(positional);
    const registered = listOption(options, 'registered');
    const result = auditRedirectUri(input, registered, policyOptions(options));
    emitResult(command, result, options.json === true);
    return result.ok ? 0 : 1;
  }

  if (command === 'audit-auth-url') {
    rejectUnknown(options, ['json', 'policy', 'registered']);
    const input = await inputValue(positional);
    const result = auditAuthRequest(input, { ...policyOptions(options), registeredRedirectUris: listOption(options, 'registered') });
    emitResult(command, result, options.json === true);
    return result.ok ? 0 : 1;
  }

  if (command === 'audit-callback') {
    rejectUnknown(options, ['json', 'policy', 'expected-state', 'expected-issuer', 'referer']);
    const input = await inputValue(positional);
    const auditOptions = policyOptions(options);
    if (typeof options['expected-state'] === 'string') auditOptions.expectedState = options['expected-state'];
    if (typeof options['expected-issuer'] === 'string') auditOptions.expectedIssuer = options['expected-issuer'];
    if (typeof options.referer === 'string') auditOptions.referer = options.referer;
    const result = auditCallback(input, auditOptions);
    emitResult(command, result, options.json === true);
    return result.ok ? 0 : 1;
  }

  if (command === 'audit-discovery') {
    rejectUnknown(options, ['json', 'policy', 'expected-issuer']);
    if (typeof options['expected-issuer'] !== 'string') throw new CliUsageError('audit-discovery requires --expected-issuer');
    const input = await inputValue(positional);
    const result = auditDiscoveryMetadata(input, { ...policyOptions(options), expectedIssuer: options['expected-issuer'] });
    emitResult(command, result, options.json === true);
    return result.ok ? 0 : 1;
  }

  throw new CliUsageError('unknown command');
}

try {
  const code = await main();
  process.exitCode = code;
} catch (error) {
  if (error instanceof CliUsageError) {
    writeErr('usage error - ' + error.message);
    writeErr(usage());
    process.exitCode = 2;
  } else {
    emitFailure('oauthcage', error, false);
    process.exitCode = 2;
  }
}
