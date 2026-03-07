# Attestor v1.0.0 Release

**Date:** March 7, 2026  
**Module:** `github.com/abhipray-cpu/auth`  
**Go:** 1.25+  
**License:** Apache 2.0

## Overview

Attestor is a production-ready, pluggable authentication library for Go. It handles credential verification, session management, identity propagation, and protocol bindings (HTTP middleware, gRPC interceptors) — enabling your business logic to read `auth.GetIdentity(ctx)` and never import auth internals.

## 🎯 Key Features

| Feature | Details |
|---|---|
| **Multi-mode auth** | Password, OAuth2/OIDC, magic link, API key, mTLS/SPIFFE — all behind a single interface |
| **Session management** | Redis and Postgres adapters; idle + absolute timeouts; concurrent session limits; schema versioning |
| **Identity propagation** | SignedJWT (Ed25519, 30s TTL, auto-rotation), session-based, SPIFFE |
| **HTTP middleware** | `RequireAuth` / `OptionalAuth`; route registration; JWKS endpoint |
| **gRPC interceptors** | Unary + streaming server/client; mTLS peer identity; S2S dual identity |
| **Lifecycle hooks** | Before/after login, registration, logout, password reset, magic link — extend without modifying code |
| **Password policy** | NIST 800-63B defaults; breached password check (HaveIBeenPwned k-anonymity); custom validators |
| **Argon2id hashing** | OWASP-recommended parameters (19 MiB, 2 iterations, 1 thread) |
| **Security tested** | 80 pen test cases across 12 categories — zero critical/high findings |

## 📊 Quality Metrics

| Metric | Result |
|---|---|
| **Tests** | 639 pass, 0 fail (18 packages) |
| **Race detector** | 0 data races (17 packages) |
| **Coverage** | 88.6% (7 packages at 100%) |
| **Vulnerabilities** | 0 (govulncheck clean) |
| **Lint issues** | 0 (golangci-lint) |
| **SPDX headers** | 111/111 Go files ✅ |
| **Examples** | 9/9 compile ✅ |

## 📚 Documentation

- **Usage Guide** (`docs/usage.md`) — 1,099 lines covering installation, all auth modes, session management, HTTP/gRPC integration, hooks, identity propagation, API keys, password policy, interfaces, error handling, FAQ, and migration
- **Architecture** (`docs/architecture.md`) — 1,884 lines of internal design, package structure, and data flow
- **9 runnable examples** — HTTP (password, OAuth, magic link, API key), gRPC (mTLS, propagation), full-stack, custom session store, hooks

## 🔒 Security

**Guarantees:**
- Constant-time credential verification (prevents timing-based user enumeration)
- Generic error messages on auth failure (no user/password distinction)
- Session IDs: 32 bytes entropy, SHA-256 hashed at rest, idle + absolute timeouts
- Argon2id with OWASP parameters
- Ed25519-signed propagation JWTs with 30s TTL and automatic key rotation
- Pen tested: 80 test cases, zero critical/high findings

**Out of scope (by design):**
- Rate limiting → use API gateway / reverse proxy
- CSRF protection → use framework middleware
- Health endpoint → your app's responsibility
- Metrics/tracing → use hooks for observability

## 🚀 Getting Started

```bash
go get github.com/abhipray-cpu/auth
```

```go
import (
    "github.com/abhipray-cpu/auth"
    "github.com/abhipray-cpu/auth/authsetup"
)

a, err := authsetup.New(
    authsetup.WithUserStore(yourUserStore),
    authsetup.WithIdentifierConfig(auth.IdentifierConfig{Field: "email"}),
    authsetup.WithSessionRedis(redisClient, ""),
)
// identity := auth.GetIdentity(ctx) — that's it
```

## 📦 Packages (18 public)

| Package | Purpose |
|---|---|
| `auth` | Core types (`Identity`, `Credential`, errors) |
| `authsetup` | Wiring and configuration |
| `engine` | Orchestrates auth flows (login, register, verify) |
| `session`, `session/redis`, `session/postgres` | Session lifecycle and storage |
| `password` | NIST 800-63B policy and validation |
| `hash` | Argon2id hashing |
| `mode/password`, `mode/oauth`, `mode/magiclink`, `mode/apikey`, `mode/mtls` | Auth modes |
| `apikey` | API key lifecycle |
| `propagator` | Identity propagation (SignedJWT, JWKS) |
| `http` | HTTP middleware, handlers, routes |
| `grpc` | gRPC server/client interceptors |
| `hooks` | Lifecycle event system |

## ✅ What's Production Ready

- Core auth engine with 5 modes
- Session management (Redis + Postgres)
- HTTP middleware and route registration
- gRPC interceptors with S2S dual identity
- All error handling with proper sentinel errors
- Security audit passed (80 pen tests)
- Documentation complete (usage guide + architecture)
- All examples compile and run

## 🔗 Links

- **Module:** `github.com/abhipray-cpu/auth`
- **Repository:** https://github.com/abhipray-cpu/Attestor
- **Usage Guide:** See `docs/usage.md`
- **Examples:** See `examples/`
- **Security:** See `SECURITY.md`
- **Contributing:** See `CONTRIBUTING.md`

## 📝 License

Apache License 2.0 — see `LICENSE`

---

## v1.0.0 Changelog

See `CHANGELOG.md` for the full feature list.

**Major items:**
- ✅ Core engine with Register, Login, Verify, Logout, ChangePassword
- ✅ 5 auth modes: password, OAuth2/OIDC, magic link, API key, mTLS/SPIFFE
- ✅ Session manager with Redis and Postgres adapters
- ✅ NIST 800-63B password policy with breached check
- ✅ Argon2id hashing with OWASP parameters
- ✅ SignedJWT identity propagation with auto-rotating Ed25519 keys
- ✅ HTTP middleware, handlers, and route registration
- ✅ gRPC server/client interceptors
- ✅ Lifecycle hooks system
- ✅ 639 tests, 0 races, 88.6% coverage
- ✅ 80 pen test cases, zero critical/high findings
- ✅ Complete documentation and 9 examples
