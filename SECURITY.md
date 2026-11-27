# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Use GitHub private vulnerability reporting for the repository when available. Include the affected version, a minimal reproduction, the security impact, and whether attacker-controlled input is required.

## Supported versions

The latest published minor release receives security fixes. Older releases are not maintained unless a release note explicitly says otherwise.

## Scope

`oauthcage` validates OAuth 2.0 and OIDC integration inputs. It is not a complete OAuth client, authorization server, JWT validator, DNS resolver, or network egress firewall. Reports are in scope when the library incorrectly accepts input that its documented policy claims to reject, leaks a secret in findings or CLI output, performs unexpected network access, or permits a parser differential within its documented validation boundary.

## Operational guidance

Use the strictest preset that matches the client type. Keep redirect URI allowlists exact and small. Validate `iss`, `state`, PKCE, scopes, discovery metadata, and endpoint URLs before using them. Pair this library with TLS, correct JWT validation, checked DNS resolution or egress filtering, secret storage, and framework-level header protections.
