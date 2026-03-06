# Security

This document describes the security properties of the `github.com/abhipray-cpu/auth` library, as verified by automated penetration testing (Epic 13, AUTH-0040 through AUTH-0045).

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly via
[GitHub Security Advisories](https://github.com/abhipray-cpu/auth/security/advisories/new).
Do **not** open a public issue.

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for Critical/High severity issues.

## Tested Security Guarantees

The following properties are verified by 60+ automated pen tests that run in CI with the Go race detector enabled.

### Timing Attack Resistance

- Login response timing is indistinguishable for existing vs non-existing users (dummy Argon2id hash on user-not-found path).
- API key, session, and magic link validation timing is consistent regardless of token existence or status.
- Passwords exceeding `MaxLength` (default: 128) are rejected **before** hashing, preventing Argon2id DoS.

### User Enumeration Resistance

- Login returns identical error message (`"Unauthorized"`) and HTTP status (`401`) for both existing and non-existing users.
- Registration does not reveal whether an identifier is already taken.
- Magic link initiation always returns HTTP `202 Accepted` regardless of user existence.
- All error messages are generic — no `"user not found"`, `"wrong password"`, or `"account locked"`.

### Session Security

- **256-bit entropy**: Session IDs are 32 cryptographically random bytes, hex-encoded (64 characters).
- **Hashed storage**: Session IDs are SHA-256 hashed before storage. The cookie value cannot be used to query the store directly.
- **Fixation prevention**: Pre-existing session IDs are invalidated on login; a new ID is always generated.
- **Cookie flags**: `Secure`, `HttpOnly`, `SameSite=Strict` are set on all session cookies.
- **Replay prevention**: Logged-out sessions cannot be replayed.
- **Concurrent session limits**: Configurable `MaxConcurrent`; oldest sessions are evicted when exceeded.
- **Idle timeout**: Sessions expire after configurable idle period.
- **Absolute timeout**: Sessions expire after configurable absolute lifetime, regardless of activity.
- **Cross-user isolation**: Session IDs from one user cannot access another user's resources.

### Password Security

- Passwords are **never** included in any HTTP response body, header, or error message.
- Passwords are hashed with **Argon2id** (time=1, memory=64 MiB, parallelism=4, salt=16 bytes, key=32 bytes).
- Password policy is enforced at registration: `MinLength=8`, `MaxLength=128`.
- `MaxLength` is enforced before hashing to prevent CPU-bound DoS.

### OAuth Security

- OAuth state tokens are single-use (replay is rejected).
- State tampering is detected (callback fails on mismatch).
- Redirect URI manipulation is rejected by the IdP and the library.

### Magic Link Security

- Magic link tokens have **256 bits of entropy** (32 cryptographically random bytes).
- Tokens are **single-use** — the second verification attempt fails.
- Token TTL is enforced — expired tokens are rejected.
- Brute-force is infeasible — 1,000 random tokens against the verify endpoint all fail.

### API Key Security

- API keys are **hashed before storage** — the stored value differs from the original key.
- Expired API keys are rejected.
- Revoked API keys are rejected.
- Brute-force is infeasible — 1,000 random keys all fail.

### Identity Propagation (JWT)

- **EdDSA only**: The library rejects JWTs with algorithms other than `EdDSA` (blocks `alg: none`, HMAC confusion, RSA confusion).
- Tampered JWT payloads are rejected (signature verification).
- Audience bypass is rejected (JWT minted for service-A fails at service-B).
- Replay window is limited to the configured TTL (default: 30 seconds).
- Forged JWTs signed with attacker keys are rejected.
- Session revocation is immediately propagated via `SessionPropagator`.

### mTLS / SPIFFE Security

- Certificates from untrusted CAs are rejected at the TLS handshake layer.
- Self-signed certificates are rejected.
- Expired certificates are rejected.
- SPIFFE trust domain spoofing is detected (wrong `spiffe://` URI SAN).
- Certificates without a SPIFFE SAN URI are accepted with CN-based identity only (no SPIFFE ID extracted).

### Input Validation

- XSS payloads in login fields are not reflected in responses.
- Error messages do not render raw HTML.
- Oversized passwords (1 MB) are rejected before hashing.
- Null bytes in identifiers are handled safely (no crash, no bypass).
- SQL injection patterns are handled safely (no SQL error leakage).
- CRLF/header injection in cookie values is handled safely.

### Error Handling

- No stack traces appear in any HTTP response body.
- No internal details (file paths, function names, package names, library versions) are leaked in responses.
- HTTP auth failures return `401 Unauthorized` (never `200` with error body, never `404`).
- gRPC auth failures return `codes.Unauthenticated` (never `PermissionDenied`).
- Error responses follow a consistent format.

## Known Limitations

| Finding | Severity | Description | Mitigation |
|---|---|---|---|
| No brute-force lockout | MEDIUM | The engine does not lock accounts after failed attempts. | Consuming applications should implement rate limiting via middleware, Redis, or a WAF. The library provides `hooks.Manager` for external lockout logic. |
| No breached password check | INFO | The engine does not check passwords against breach databases. | Consuming applications can implement this via the `PasswordPolicy` interface or pre-registration hooks. |
| No `Cache-Control: no-store` | LOW | Auth endpoints do not set cache headers. | Add `Cache-Control: no-store` middleware in the consuming application. |
| No `Referrer-Policy` header | LOW | Auth pages do not set referrer policy. | Add `Referrer-Policy: strict-origin-when-cross-origin` middleware. |
| No clickjacking headers | LOW | Auth pages do not set `X-Frame-Options` or CSP. | Add `X-Frame-Options: DENY` middleware. |
| Unicode normalization | INFO | Default `Normalize` function uses `ToLower + TrimSpace` but not NFC. | Configure `Normalize` to include `unicode/norm.NFC.String()` if needed. |

## Audit Report

The full penetration test report with methodology, evidence, and remediation details is available at [`docs/security-audit.md`](docs/security-audit.md).
