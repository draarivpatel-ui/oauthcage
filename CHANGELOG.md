# Changelog

## 1.0.0

Initial release.

- Exact canonical redirect URI matching and open redirect defenses
- RFC 7636 S256 PKCE generation and timing-safe verification
- High entropy state and nonce generation and verification
- Authorization request, callback, and token request firewalls
- RFC 9207 issuer validation and duplicate parameter detection
- OIDC discovery metadata validation with duplicate-key, numeric, UTF-8 byte, depth, and key-count limits
- HTTPS endpoint SSRF and cloud metadata defenses including ISATAP transition decoding
- Fail-closed bounded audit findings and encoded secret redaction
- Frozen strict, spa, confidential, and native policy presets
- Dual ESM and CommonJS builds with TypeScript declarations
- Security-focused command line interface
