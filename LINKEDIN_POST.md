# LinkedIn Post — Attestor Launch

> Copy and paste the text below directly into LinkedIn.

---

🚀 **I just open-sourced Attestor — a production-ready, pluggable authentication & identity-propagation library for Go, built across 8 focused packages. Here's the full story.**

---

Six months ago I sat down to wire up authentication for a new Go service for the third time in my career. Copy-paste from a previous project. Tweak the session store. Argue with myself about where to put the JWT logic. Repeat.

I was tired of it.

So instead of building *another* auth system I decided to build *the last one I'd ever need to build* — modular, production-hardened, thoroughly tested, and easy enough to wire up in five minutes without reading a book.

The result is **Attestor** (`github.com/abhipray-cpu/auth`): a single Go module composed of 8 packages, each with a clear responsibility, each independently testable, and all wired together through a thin `authsetup.New()` one-liner.

---

### 📦 The 8 Libraries — What They Are & Why I Built Each One

**1. `engine` — The orchestrator**
Every auth operation (Register, Login, Verify, Logout, ChangePassword) flows through one place. Your business code never imports auth internals — it only calls `auth.GetIdentity(ctx)`. I wanted a single, auditable surface that every security fix could land in once.


**2. `session` — Sessions done right**
Redis and Postgres adapters included. 256-bit session IDs from `crypto/rand`, SHA-256-hashed at rest, idle + absolute timeouts, concurrent session limits, and schema versioning. I was frustrated by libraries that stored the raw session ID — so I built one that hashes it by default.

**3. `hash` — Argon2id with OWASP parameters**
One file. One job: hash and verify passwords using Argon2id (19 MiB memory, 2 iterations) — the OWASP-recommended defaults. No configuration footguns.

**4. `password` — NIST 800-63B policy**
Password validation is surprisingly nuanced. This package enforces length (8–128), blocks common passwords, and optionally checks against HaveIBeenPwned's k-anonymity API — all via a composable `PasswordPolicy` interface so you can plug in your own validators.

**5. `propagator` — Identity travels between services**
The hardest part of microservices auth isn't the edge — it's passing identity *between* services securely. I built three propagators: `SignedJWTPropagator` (Ed25519, 30 s TTL, auto key-rotation, JWKS endpoint), `SessionPropagator` (shared session store), and `SPIFFEPropagator` (SPIRE workload identity).

**6. `hooks` — Extend without forking**
Before/after hooks for every auth event (login, registration, logout, password reset, magic link, account locked). The canonical use case: send a welcome email on `AfterRegister` without touching auth code. Typed payloads. Zero dependencies on auth internals.

**7. `http` — Middleware that disappears**
`RequireAuth` and `OptionalAuth` middleware, route registration helper, cookie config (Secure, HttpOnly, SameSite=Strict), and a JWKS endpoint at `/.well-known/auth-keys`. Drop it in front of any `http.Handler` and move on.

**8. `grpc` — First-class gRPC support**
Unary + streaming server and client interceptors. mTLS peer identity extraction. Identity propagation via gRPC metadata. Most auth libraries treat gRPC as an afterthought — I wanted it to be a first-class citizen from day one.

---

### 🔒 Production-Hardening Patterns I Applied Across Every Package

These aren't optional extras — they're the baseline I held every package to:

- **Constant-time comparisons** everywhere credentials are verified. Timing-based user enumeration is a real attack. I benchmarked the dummy-hash path to match the real path.
- **Generic error messages.** `"Unauthorized"` always. Never `"user not found"` or `"wrong password"` in HTTP responses.
- **No secrets in responses.** Passwords, session IDs, and tokens never appear in response bodies, headers, or error messages.
- **Cryptographic entropy.** Session IDs: 32 bytes from `crypto/rand`. Magic link tokens: 32 bytes from `crypto/rand`. API keys: hashed before storage.
- **Short-lived propagation tokens.** Ed25519-signed JWTs with a 30-second TTL and automatic key rotation. An intercepted token is worthless in 30 seconds.
- **Race-detector-clean.** Every test runs with `go test -race`. No exceptions.
- **80 automated penetration-test cases across 12 security categories** — timing attacks, user enumeration, session fixation, CSRF, token replay, mTLS spoofing, input injection, header injection. Zero critical or high findings.
- **960+ unit and integration tests** across 19 packages with Testcontainers (Redis, PostgreSQL, Keycloak) and end-to-end Playwright browser tests.

---

### 🤝 It's Open Source — Contributions Welcome!

Attestor is licensed under **Apache 2.0** and I genuinely want collaborators.

Here's where you can make an immediate impact:

- 🧩 **New auth modes** — WebAuthn/Passkeys, SMS OTP, TOTP/FIDO2 (`mode/` package, `auth.AuthMode` interface)
- 🗄️ **New session adapters** — DynamoDB, MongoDB, etcd (`session/SessionStore` interface)
- 🌐 **New propagators** — AWS IAM, Azure AD workload identity
- 📖 **Docs & examples** — more real-world examples are always welcome
- 🐛 **Bug reports & security findings** — see `SECURITY.md` for responsible disclosure

Start here: **https://github.com/abhipray-cpu/auth**

Read `CONTRIBUTING.md` for setup, testing, and submission guidelines. The architecture doc in `docs/architecture.md` explains every design decision.

---

If you've ever copy-pasted auth code between projects, or spent a week fighting a JWT library, I hope Attestor saves you that time.

⭐ Star it if it looks useful. Fork it if you want to contribute. And if you build something with it, I'd love to hear about it.

---

#golang #go #opensourcesoftware #opensource #authentication #security #softwaredevelopment #microservices #backenddevelopment #apidevelopment #devops #softwareengineering #programming #jwt #grpc #sessionmanagement #cryptography #cybersecurity #appsecurity #cloudsecurity #devsecops #golangnews #golangdeveloper #golangcommunity #buildinpublic #sideproject #developer #100daysofcode #techcommunity #softwarearchitecture
