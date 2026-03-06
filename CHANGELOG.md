# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-07

### Added

- **Core:** `auth.Identity` and `auth.WorkloadIdentity` types with context accessors (`GetIdentity`, `SetIdentity`, `GetWorkloadIdentity`, `SetWorkloadIdentity`)
- **Core:** `auth.UserStore`, `auth.User`, `auth.Hasher`, `auth.Authorizer`, `auth.Notifier`, `auth.AuthMode` interfaces
- **Core:** Sentinel errors: `ErrInvalidCredentials`, `ErrAccountLocked`, `ErrSessionExpired`, `ErrSessionNotFound`, `ErrUserNotFound`, `ErrUserAlreadyExists`, `ErrPasswordPolicyViolation`, `ErrAPIKeyExpired`, `ErrAPIKeyRevoked`, `ErrPropagationFailed`, `ErrSchemaVersionMismatch`, `ErrTokenNotFound`
- **Core:** `auth.CredentialType` enum: password, OAuth2, magic link, API key, mTLS, SPIFFE
- **Engine:** Authentication orchestrator with `Register`, `Login`, `Verify`, `Logout`, `ChangePassword` operations
- **Engine:** Multi-mode dispatch: password, OAuth2/OIDC, magic link, API key, mTLS/SPIFFE
- **Session:** Session manager with idle timeout (30 min), absolute timeout (24 h), concurrent session limits
- **Session:** Redis adapter with configurable key prefix
- **Session:** PostgreSQL adapter with migration
- **Session:** 256-bit session IDs from `crypto/rand`, SHA-256 hashed at rest
- **Session:** Schema versioning with startup check
- **Session:** Magic link token store with single-use enforcement
- **Password:** NIST 800-63B password policy with breached password check (HaveIBeenPwned k-anonymity)
- **Password:** Argon2id hasher with OWASP parameters (19 MiB, 2 iterations, 1 parallelism)
- **OAuth:** OIDC discovery for any compliant provider (Google, Okta, Entra ID, Auth0, Keycloak)
- **OAuth:** PKCE support, server-side state tokens (CSRF), auto-registration
- **API Key:** First-class API key authentication with hashing, expiry, revocation, scopes
- **mTLS:** Client certificate validation with trust anchors
- **mTLS:** SPIFFE SVID support with trust domain validation
- **Propagation:** SignedJWTPropagator with Ed25519, 30 s TTL, automatic key rotation, JWKS endpoint
- **Propagation:** SessionPropagator for shared session store architectures
- **Propagation:** SPIFFEPropagator for SPIRE-based workload identity
- **HTTP:** `RequireAuth` and `OptionalAuth` middleware
- **HTTP:** Route registration helper (`RegisterRoutes`) with configurable prefix
- **HTTP:** Cookie configuration (Secure, HttpOnly, SameSite)
- **HTTP:** JWKS endpoint at `/.well-known/auth-keys`
- **gRPC:** Unary and streaming server interceptors with mTLS peer identity
- **gRPC:** Unary and streaming client interceptors for identity propagation
- **Hooks:** Lifecycle event system (before/after) for login, registration, logout, password reset, magic link, account locked
- **Hooks:** Typed payloads: `LoginPayload`, `RegisterPayload`, `LogoutPayload`, `OAuthPayload`, `MagicLinkPayload`
- **Setup:** `authsetup.New()` with functional options for one-line wiring
- **Setup:** Automatic mode detection based on configured options
- **Setup:** Validation of required dependencies (e.g., Notifier required for magic link)
- **Testing:** 960+ tests across 19 packages, race-clean
- **Testing:** 80 pen test cases across 12 security categories
- **Testing:** Integration tests with Testcontainers (Keycloak, Redis, PostgreSQL)
- **Testing:** E2E browser tests with Playwright

[1.0.0]: https://github.com/abhipray-cpu/auth/releases/tag/v1.0.0
