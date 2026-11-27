# Contributing

## Requirements

- Node.js 18 or newer
- No runtime dependencies
- No development dependencies in `package.json`
- Deterministic offline tests
- ESM source in `src/` with generated CommonJS in `cjs/`
- Complete declarations in `types/index.d.ts`

## Checks

Run these before submitting a change:

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
npm pack --dry-run
```

If `src/` changes, regenerate the CommonJS bundle:

```sh
node scripts/build-cjs.mjs
```

## Security rules

- Do not echo secrets or attacker-controlled values in findings, errors, logs, or tests that assert output.
- Do not use network access in library code.
- Do not weaken exact redirect matching, S256 enforcement, issuer matching, duplicate parameter detection, or endpoint range checks.
- Add adversarial regression tests for every security fix.
- Keep result objects deeply frozen and safe from prototype pollution.
