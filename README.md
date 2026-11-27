# oauthcage

`oauthcage` is a zero-dependency OAuth 2.0 and OpenID Connect security firewall for Node.js. It audits redirect URIs, authorization requests, callbacks, token requests, PKCE values, OIDC discovery metadata, and security-sensitive endpoint URLs before secrets or tokens are trusted.

The library implements defenses aligned with RFC 9700, RFC 7636, RFC 8252, RFC 9207, OIDC Core, and OIDC Discovery. It uses only Node.js built-ins and performs no network access.

## Why it exists

OAuth implementations often fail at integration boundaries rather than in cryptographic primitives. Common failures include prefix-matched redirect URIs, parser differentials, missing PKCE, implicit flow leftovers, missing `state`, authorization server mix-up, duplicate query parameters, token leakage through URLs, malicious discovery metadata, and JWKS endpoints pointed at internal network targets.

`oauthcage` makes those checks explicit, deterministic, typed, and testable.

## Install

```sh
npm install oauthcage
```

Node.js 18 or newer is required.

```js
import {
  auditRedirectUri,
  createPkcePair,
  generateState,
  auditAuthRequest,
  auditCallback,
  auditTokenRequest,
  auditDiscoveryMetadata
} from 'oauthcage';
```

CommonJS is supported too:

```js
const { createPkcePair, auditCallback } = require('oauthcage');
```

## Redirect URI firewall

```js
import { auditRedirectUri, validateRedirectUri } from 'oauthcage';

const result = auditRedirectUri(
  'https://app.example/callback',
  ['https://app.example/callback']
);

if (!result.ok) {
  console.error(result.findings);
}

const canonical = validateRedirectUri(
  'https://app.example/callback',
  ['https://app.example/callback']
);
```

The redirect firewall:

- requires an exact canonical match against a registered allowlist
- never uses prefix matching, wildcard hosts, or subdomain matching
- rejects fragments, userinfo, backslashes, repeated path slashes, dot traversal, encoded traversal, encoded separators, malformed percent encoding, raw or encoded whitespace, controls, bidi controls, and unpaired surrogates
- rejects dangerous schemes such as `javascript:`, `data:`, `vbscript:`, and `file:`
- rejects HTTP redirects except exact loopback `127.0.0.1` or `[::1]` in the `native` policy
- rejects `localhost` HTTP unless `allowLocalhostHttp` is explicitly enabled
- rejects custom URI schemes unless `allowCustomSchemes` is enabled and the exact lowercase scheme appears in `allowedCustomSchemes`
- treats OAuth secrets in redirect URI query strings as unsafe

Canonical matching normalizes scheme and host case, percent-encoding case, and unreserved percent-encoded characters. It does not resolve dot segments because dot segments are rejected instead. It does not add or remove path slashes or perform wildcard matching.

## PKCE, state, and nonce

```js
import { createPkcePair, verifyPkce, generateState, verifyState } from 'oauthcage';

const pair = createPkcePair();
const state = generateState();

verifyPkce(pair.verifier, pair.challenge, 'S256');
verifyState(state, state);
```

`createPkcePair()` uses `node:crypto` randomness and returns a 64 character RFC 7636 verifier plus its S256 challenge. `verifyPkce` validates the verifier charset and length, enforces policy-approved methods, computes the SHA-256 base64url challenge, and compares with `crypto.timingSafeEqual`.

The `strict`, `spa`, `confidential`, and `native` presets reject `plain` PKCE. A custom policy must explicitly weaken itself to accept `plain`.

`generateState()` and `generateNonce()` return 256 bits of base64url randomness. Verification rejects short, empty, whitespace-bearing, non-ASCII, predictable, repeated, or sequential values before constant-time comparison.

## Authorization request audit

```js
const auth = auditAuthRequest(authUrlOrParameters, {
  policy: 'spa',
  registeredRedirectUris: ['https://app.example/callback'],
  allowedScopes: ['openid', 'profile', 'email']
});
```

The authorization request firewall:

- accepts authorization code flow by default
- rejects implicit and hybrid token response types
- requires high entropy `state`
- requires an S256 PKCE challenge and rejects a missing method as a plain downgrade
- validates the redirect URI against the registered allowlist
- rejects fragment response mode
- validates scope token syntax, allowlists, denylists, duplicates, and control characters
- rejects secrets and tokens embedded in authorization request parameters
- supports PAR-oriented confidential policies through `requirePar`

## Callback and mix-up firewall

```js
const callback = auditCallback(callbackUrlOrParameters, {
  expectedState: storedState,
  expectedIssuer: 'https://issuer.example',
  requestedScope: 'openid profile',
  referer: request.headers.referer
});
```

The callback firewall:

- implements RFC 9207 `iss` validation with exact canonical issuer matching
- detects duplicate parameters such as `?code=a&code=b` and `?state=x&state=y`
- rejects fragment response mode and token material in fragments
- requires `state` and compares it in constant time when `expectedState` is supplied
- validates authorization code shape without echoing it in findings
- detects token and secret parameters in callback query strings
- detects OAuth secrets in Referer query strings or fragments
- detects returned scope escalation relative to the original request
- rejects conflicting `error` and `code` combinations

## Token request audit

```js
const token = auditTokenRequest(formBodyOrObject, {
  policy: 'spa',
  registeredRedirectUris: ['https://app.example/callback'],
  expectedCodeChallenge: storedChallenge
});
```

The token request firewall:

- rejects the resource owner password credentials grant
- enforces policy-approved grant types
- requires PKCE verifier shape for authorization code redemption
- can verify the verifier against a stored challenge
- validates redirect URI exact matching
- rejects client secrets for public-client presets
- detects duplicate form parameters and bounded-length violations

## OIDC discovery and endpoint firewall

```js
const discovery = auditDiscoveryMetadata(metadataJsonOrObject, {
  expectedIssuer: 'https://issuer.example'
});
```

The discovery firewall validates required endpoints, exact issuer equality, signing algorithm metadata, flow metadata, PKCE support, object shape, duplicate JSON object keys, numeric resource bounds, UTF-8 byte length, depth, key count, and object-injection keys. Malformed flow metadata and noncanonical whitespace in response or grant type values fail closed. Audit reports cap findings with `maxFindings`; truncation is itself a failure so `maxFindings: 0` cannot hide findings.

Endpoint validation requires HTTPS and rejects:

- userinfo, fragments, unapproved query strings, and unapproved ports
- loopback, private, link-local, multicast, reserved, documentation, benchmark, CGNAT, and unspecified IP ranges
- cloud metadata targets including `169.254.169.254`, `169.254.170.23`, and `fd00:ec2::23`
- IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, NAT64-local, 6to4, Teredo, and ISATAP transition encodings
- decimal integer, octal, hexadecimal, shorthand, overflowing, or otherwise ambiguous IPv4 forms
- `localhost`, single-label names, `.local`, and `.internal`

This is an offline static firewall. It does not resolve DNS. A public hostname that later resolves to a private address still requires network egress controls or a checked resolver in the calling application.

## Policies

```js
import { getPolicy, createOAuthPolicy } from 'oauthcage';

const strict = getPolicy('strict');
const native = getPolicy('native');
const custom = createOAuthPolicy('native', { allowLocalhostHttp: true });
```

Presets:

| Preset | Purpose |
| --- | --- |
| `strict` | RFC 9700 oriented baseline for server-side validation |
| `spa` | Public browser client with mandatory S256 PKCE and no client secret |
| `confidential` | Confidential server-side client with PAR, PKCE, and client secret support |
| `native` | RFC 8252 native application mode with loopback HTTP allowed |

Policies and audit results are deeply frozen. Preset objects must not be mutated.

## CLI

```sh
oauthcage gen-pkce
oauthcage verify-pkce --verifier <verifier> --challenge <challenge>
oauthcage audit-redirect https://app.example/cb --registered https://app.example/cb
oauthcage audit-auth-url - --registered https://app.example/cb < auth-url.txt
oauthcage audit-callback - --expected-state <state> --expected-issuer https://issuer.example < callback.txt
oauthcage audit-discovery - --expected-issuer https://issuer.example < discovery.json
```

Use `--json` for machine-readable output and `--policy` to select `strict`, `spa`, `confidential`, or `native`. Passing `-` reads at most one mebibyte from standard input without trimming hostile whitespace.

The CLI prints stable codes, fields, severities, and messages. It does not echo caller-supplied `code`, `code_verifier`, `client_secret`, `access_token`, or `refresh_token` values in audit findings or errors. Terminal output is neutralized for ANSI escapes, C0 and C1 controls, bidi controls, U+2028, and U+2029.

## Errors

Validation functions that are boolean-style verifiers throw `OAuthCageError` on failure. Audit functions return frozen result objects with stable findings:

```js
try {
  verifyState(expectedState, returnedState);
} catch (error) {
  console.error(error.code, error.field, error.detail);
}
```

Finding and error messages are deliberately static. Attacker-controlled values are not interpolated into them.

## Security boundary

`oauthcage` is a validation layer, not a complete OAuth client. It does not exchange tokens, fetch discovery documents, fetch JWKS, validate JWT signatures, validate ID token claims, resolve DNS, or replace TLS. Use it before and after those operations in a correctly implemented client or authorization server integration.

## Development

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
npm pack --dry-run
```

The package has no runtime dependencies and no development dependencies. The generated CommonJS bundle is committed and checked for freshness.
