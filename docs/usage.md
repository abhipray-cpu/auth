# Attestor — Usage Guide

> **Module:** `github.com/abhipray-cpu/auth` · **Version:** 1.0.0 · **Go:** 1.25+

This is the single reference for everything you need to use Attestor in production:
getting started, configuration, every auth mode, session management, HTTP/gRPC
integration, hooks, identity propagation, API keys, password policy, and migration.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Configuration Reference](#2-configuration-reference)
3. [Auth Modes](#3-auth-modes)
   - [Password](#31-password)
   - [OAuth2 / OIDC](#32-oauth2--oidc)
   - [Magic Link](#33-magic-link)
   - [API Key](#34-api-key)
   - [mTLS / SPIFFE](#35-mtls--spiffe)
4. [Session Management](#4-session-management)
5. [HTTP Integration](#5-http-integration)
6. [gRPC Integration](#6-grpc-integration)
7. [Lifecycle Hooks](#7-lifecycle-hooks)
8. [Identity Propagation](#8-identity-propagation)
9. [Password Policy](#9-password-policy)
10. [Interfaces You Must Implement](#10-interfaces-you-must-implement)
11. [Error Handling](#11-error-handling)
12. [Security Guarantees](#12-security-guarantees)
13. [FAQ](#13-faq)
14. [Migration Guide](#14-migration-guide)

---

## 1. Getting Started

### Install

```bash
go get github.com/abhipray-cpu/auth
```

### Minimal wiring (password + Redis sessions)

```go
package main

import (
    "context"
    "log"
    "net/http"
    "strings"

    "github.com/abhipray-cpu/auth"
    "github.com/abhipray-cpu/auth/authsetup"
    authhttp "github.com/abhipray-cpu/auth/http"
    goredis "github.com/redis/go-redis/v9"
)

type userStore struct{ /* your DB */ }

func (s *userStore) FindByIdentifier(_ context.Context, id string) (auth.User, error) {
    return nil, auth.ErrUserNotFound // replace with your DB lookup
}
func (s *userStore) Create(_ context.Context, u auth.User) error                      { return nil }
func (s *userStore) UpdatePassword(_ context.Context, _, _ string) error               { return nil }
func (s *userStore) IncrementFailedAttempts(_ context.Context, _ string) error         { return nil }
func (s *userStore) ResetFailedAttempts(_ context.Context, _ string) error             { return nil }
func (s *userStore) SetLocked(_ context.Context, _ string, _ bool) error               { return nil }

func main() {
    rdb := goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})

    a, err := authsetup.New(
        authsetup.WithUserStore(&userStore{}),
        authsetup.WithIdentifierConfig(auth.IdentifierConfig{
            Field:     "email",
            Normalize: strings.ToLower,
        }),
        authsetup.WithSessionRedis(rdb, ""),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer a.Close()

    mux := http.NewServeMux()
    handlers := authhttp.NewHandlers(a.Engine, authhttp.DefaultCookieConfig())
    authhttp.RegisterRoutes(mux, handlers, authhttp.DefaultRouteConfig())

    middleware := authhttp.NewMiddleware(a.Engine, authhttp.DefaultCookieConfig())
    mux.Handle("/api/", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        identity := auth.GetIdentity(r.Context()) // the only contract
        w.Write([]byte("Hello " + identity.SubjectID))
    })))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

This gives you:

| Route | Description |
|---|---|
| `POST /auth/register` | Register with email + password |
| `POST /auth/login` | Login, receive session cookie |
| `POST /auth/logout` | Destroy session |
| `GET /api/*` | Protected — returns 401 if not authenticated |

**The only symbol your business logic needs:** `auth.GetIdentity(ctx)`.

---

## 2. Configuration Reference

All configuration is via `authsetup.New(options...)`.

### Required options

| Option | Purpose |
|---|---|
| `WithUserStore(store)` | Your user persistence (see §10) |
| `WithIdentifierConfig(cfg)` | What field identifies a user, how to normalize it |
| One session store option | `WithSessionRedis`, `WithSessionPostgres`, or `WithCustomSessionStore` |

### `IdentifierConfig`

```go
auth.IdentifierConfig{
    Field:         "email",            // field name — informational only
    CaseSensitive: false,              // false for emails, true for UUIDs
    Normalize:     strings.ToLower,   // applied before every lookup
}
```

### Session store options

```go
// Redis (recommended for production)
authsetup.WithSessionRedis(redisClient, "myapp:session:")

// PostgreSQL
authsetup.WithSessionPostgres(sqlDB)

// Custom
authsetup.WithCustomSessionStore(myStore)
```

### Session behavior

```go
authsetup.WithSessionConfig(session.SessionConfig{
    IdleTimeout:     30 * time.Minute, // default
    AbsoluteTimeout: 24 * time.Hour,   // default
    MaxConcurrent:   5,                // 0 = unlimited
    CookieName:      "auth_session",
    CookieDomain:    "example.com",
    CookieSecure:    true,             // always true in production
    CookieSameSite:  "Strict",
})
```

### All options

| Option | Default | Notes |
|---|---|---|
| `WithUserStore(store)` | — | Required |
| `WithIdentifierConfig(cfg)` | — | Required |
| `WithSessionRedis(client, prefix)` | — | One session option required |
| `WithSessionPostgres(db)` | — | One session option required |
| `WithCustomSessionStore(store)` | — | One session option required |
| `WithSessionConfig(cfg)` | See above | Override timeouts, concurrency, cookie |
| `WithPasswordPolicy(policy)` | NIST 800-63B defaults | See §9 |
| `WithHasher(hasher)` | Argon2id | Override for legacy schemes |
| `WithOAuthProvider(cfg)` | — | Call once per provider |
| `WithOAuthStateStore(store)` | — | Required when using OAuth |
| `WithOAuthHTTPClient(client)` | `http.DefaultClient` | Override for proxies/testing |
| `WithNotifier(notifier)` | — | Required for magic link |
| `WithMagicLinkStore(store)` | — | Required for magic link |
| `WithAPIKeyStore(store)` | — | Required for API key mode |
| `WithTrustAnchors(pool)` | — | Required for mTLS mode |
| `WithIdentityPropagator(p)` | `SignedJWTPropagator` | Override default propagator |
| `WithSignedJWTPropagator(cfg)` | See §8 | Configure default propagator |
| `WithHook(event, fn)` | — | Register lifecycle hooks (see §7) |
| `WithAuthorizer(authz)` | — | Custom authorization logic |
| `WithSkipSchemaCheck()` | false | Skip schema version check (testing only) |

---

## 3. Auth Modes

Modes are activated automatically when you provide the required stores/config.
Multiple modes can be active at the same time — the engine dispatches by
`auth.CredentialType`.

### 3.1 Password

**Activated by:** `WithUserStore` + a session store (always enabled).

#### Registration

```go
// HTTP: POST /auth/register
// Body: {"identifier": "alice@example.com", "password": "hunter2"}

// Direct engine call:
identity, _, err := engine.Register(ctx, auth.Credential{
    Type:       auth.CredentialTypePassword,
    Identifier: "alice@example.com",
    Secret:     "hunter2",
})
```

#### Login

```go
// HTTP: POST /auth/login
// Body: {"identifier": "alice@example.com", "password": "hunter2"}

identity, sessionID, err := engine.Login(ctx, auth.Credential{
    Type:       auth.CredentialTypePassword,
    Identifier: "alice@example.com",
    Secret:     "hunter2",
})
```

#### Password change

```go
err := engine.ChangePassword(ctx, subjectID, oldPassword, newPassword)
```

---

### 3.2 OAuth2 / OIDC

**Activated by:** `WithOAuthProvider(cfg)` + `WithOAuthStateStore(store)`.

Works with any OIDC-compliant provider. Security: PKCE mandatory (S256),
CSRF state tokens, nonce, id_token signature verification via JWKS.

#### Configuration

```go
authsetup.WithOAuthProvider(oauth.ProviderConfig{
    Name:         "google",
    IssuerURL:    "https://accounts.google.com",
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  "https://yourapp.com/auth/oauth/google/callback",
    Scopes:       []string{"openid", "profile", "email"}, // default
}),
authsetup.WithOAuthProvider(oauth.ProviderConfig{
    Name:      "entra-id",
    IssuerURL: "https://login.microsoftonline.com/{tenant}/v2.0",
    ClientID:  os.Getenv("AZURE_CLIENT_ID"),
    // ...
}),
```

#### Provider-specific IssuerURLs

| Provider | IssuerURL |
|---|---|
| Google | `https://accounts.google.com` |
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant}/v2.0` |
| Okta | `https://{your-domain}.okta.com` |
| Auth0 | `https://{your-domain}.auth0.com/` |
| Keycloak | `https://{host}/realms/{realm}` |

#### Flow (HTTP auto-wired)

```
GET  /auth/oauth/google           → redirect to Google
GET  /auth/oauth/google/callback  → exchange code, create session, redirect to /
```

#### Custom state store

The `oauth.StateStore` interface manages CSRF state tokens (10-minute TTL):

```go
type StateStore interface {
    Save(ctx context.Context, state, nonce string, ttl time.Duration) error
    Consume(ctx context.Context, state string) (nonce string, err error)
}
```

---

### 3.3 Magic Link

**Activated by:** `WithNotifier(notifier)` + `WithMagicLinkStore(store)`.

Passwordless email/SMS login. Tokens are 256-bit random, single-use, 15-minute TTL.

#### Configuration

```go
authsetup.WithNotifier(&emailNotifier{}),
authsetup.WithMagicLinkStore(myTokenStore),
```

#### Notifier interface

```go
type Notifier interface {
    Send(ctx context.Context, identifier, token string) error
}
```

Example implementation:

```go
type emailNotifier struct{ mailer *smtp.Client }

func (n *emailNotifier) Send(ctx context.Context, identifier, token string) error {
    link := "https://yourapp.com/auth/magic-link/verify?token=" + token
    return n.mailer.SendMail(identifier, "Your login link", link)
}
```

#### MagicLinkStore interface

```go
// From session.MagicLinkStore
type MagicLinkStore interface {
    Save(ctx context.Context, token, identifier string, ttl time.Duration) error
    Consume(ctx context.Context, token string) (identifier string, err error) // single-use
}
```

#### Flow (HTTP auto-wired)

```
POST /auth/magic-link         body: {"identifier": "alice@example.com"}
   → generates token, calls Notifier.Send, returns 200

GET  /auth/magic-link/verify  ?token=<token>
   → validates token (single-use), creates session, redirects to /
```

---

### 3.4 API Key

**Activated by:** `WithAPIKeyStore(store)`.

API keys are a first-class concept with their own lifecycle, scopes, and expiry.
They are intentionally separate from user records.

#### APIKeyStore interface

```go
type APIKeyStore interface {
    FindByKey(ctx context.Context, keyHash string) (*APIKey, error)
    Create(ctx context.Context, apiKey *APIKey) error
    Revoke(ctx context.Context, keyID string) error
    ListBySubject(ctx context.Context, subjectID string) ([]*APIKey, error)
    UpdateLastUsed(ctx context.Context, keyID string, timestamp time.Time) error
}
```

#### APIKey struct

```go
type APIKey struct {
    ID         string
    SubjectID  string    // owning user/service
    KeyHash    string    // always store hashed — never the raw key
    Name       string    // human-readable label
    Scopes     []string
    CreatedAt  time.Time
    ExpiresAt  time.Time // zero = no expiry
    LastUsedAt time.Time
    Revoked    bool
}
```

#### HTTP: sending API key

The middleware checks these in order:

```
Authorization: Bearer <key>
Authorization: ApiKey <key>
X-API-Key: <key>
?api_key=<key>
```

#### Key lifecycle (your code)

```go
// Create
rawKey := generateSecureKey() // your function — 256-bit random
hash := sha256.Sum256([]byte(rawKey))
store.Create(ctx, &apikey.APIKey{
    ID:        uuid.New().String(),
    SubjectID: "user-123",
    KeyHash:   hex.EncodeToString(hash[:]),
    Name:      "CI/CD pipeline",
    Scopes:    []string{"read:deployments"},
    CreatedAt: time.Now(),
})
// Return rawKey to user — this is the only time it's visible.

// Revoke
store.Revoke(ctx, keyID)
```

---

### 3.5 mTLS / SPIFFE

**Activated by:** `WithTrustAnchors(certPool)`.

Authenticates services (not users) via mutual TLS client certificates.
Supports both raw X.509 certificates and SPIFFE SVIDs.

#### Configuration

```go
pool := x509.NewCertPool()
pool.AddCert(caCert)

authsetup.WithTrustAnchors(pool),
```

#### Identity in context

On successful mTLS auth, both identities are set in context:

```go
// WorkloadIdentity — the service/machine
wid := auth.GetWorkloadIdentity(ctx)
wid.WorkloadID  // SPIFFE ID or CN from cert (e.g., "spiffe://acme.com/svc/payments")
wid.TrustDomain // "acme.com"

// Identity — also set for uniform handling
id := auth.GetIdentity(ctx)
id.AuthMethod  // "mtls" or "spiffe"
id.WorkloadID  // same as wid.WorkloadID
```

#### SPIFFE trust domain validation

```go
// If the cert contains a SPIFFE URI SAN, the library extracts it:
// spiffe://trust-domain/path → WorkloadID = full URI, TrustDomain = "trust-domain"
```

---

## 4. Session Management

### Default behavior

| Setting | Default |
|---|---|
| Session ID entropy | 256 bits (`crypto/rand`) |
| Session ID storage | SHA-256 hash (raw ID only in cookie) |
| Idle timeout | 30 minutes |
| Absolute timeout | 24 hours |
| Concurrent sessions | Unlimited (0) |
| Fixation prevention | Existing session destroyed on new login |

### Redis adapter

```go
authsetup.WithSessionRedis(
    goredis.NewClient(&goredis.Options{Addr: "localhost:6379"}),
    "myapp:session:", // key prefix (default: "auth:session:")
)
```

Sessions stored as Redis hashes with automatic TTL. No background cleanup needed.

### PostgreSQL adapter

```go
db, _ := sql.Open("pgx", os.Getenv("DATABASE_URL"))
authsetup.WithSessionPostgres(db)
```

The library auto-creates the `auth_sessions` table on first use (schema v1).
For expired session cleanup, run periodically:

```go
// Postgres store implements CleanupExpired
postgresStore.CleanupExpired(ctx)
```

Or via a background goroutine:

```go
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    for range ticker.C {
        if err := postgresStore.CleanupExpired(context.Background()); err != nil {
            slog.Warn("session cleanup failed", "err", err)
        }
    }
}()
```

### Custom session store

Implement `session.SessionStore`:

```go
type SessionStore interface {
    Create(ctx context.Context, session *Session) error
    Get(ctx context.Context, sessionID string) (*Session, error)
    Update(ctx context.Context, session *Session) error
    Delete(ctx context.Context, sessionID string) error
    DeleteBySubject(ctx context.Context, subjectID string) error
    CountBySubject(ctx context.Context, subjectID string) (int, error)
}
```

Then:

```go
authsetup.WithCustomSessionStore(myStore)
```

### Schema versioning

On startup the library checks `SchemaVersion = 1` in the session store.
A mismatch returns `auth.ErrSchemaVersionMismatch` — never silently migrates.
Use `WithSkipSchemaCheck()` to disable during testing.

### Graceful shutdown

```go
a, _ := authsetup.New(...)
defer a.Close() // closes Redis/Postgres connections
```

---

## 5. HTTP Integration

### Route registration

```go
handlers := authhttp.NewHandlers(a.Engine, authhttp.DefaultCookieConfig())
authhttp.RegisterRoutes(mux, handlers, authhttp.DefaultRouteConfig())
```

Routes registered:

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/login` | Password login → sets session cookie |
| `POST` | `/auth/register` | Register → sets session cookie |
| `POST` | `/auth/logout` | Destroys session, clears cookie |
| `GET` | `/auth/oauth/{provider}` | Initiates OAuth flow |
| `GET` | `/auth/oauth/{provider}/callback` | OAuth callback |
| `POST` | `/auth/magic-link` | Sends magic link |
| `GET` | `/auth/magic-link/verify` | Verifies magic link token |
| `GET` | `/.well-known/auth-keys` | JWKS (if propagator configured) |

### Customising the prefix

```go
authhttp.RegisterRoutes(mux, handlers, authhttp.RouteConfig{
    Prefix:           "/v1/auth",
    LoginRedirectURL: "/dashboard",
    JWKSHandler:      a.Engine.Propagator().JWKSHandler(),
})
```

### Middleware

```go
middleware := authhttp.NewMiddleware(a.Engine, authhttp.DefaultCookieConfig())

// Require auth — 401 if unauthenticated
mux.Handle("/api/", middleware.RequireAuth(yourHandler))

// Optional auth — nil identity if unauthenticated
mux.Handle("/feed", middleware.OptionalAuth(yourHandler))
```

### Credential extraction order

The middleware tries credentials in this order:

1. Session cookie (`auth_session` by default)
2. `Authorization: Bearer <token>` — session ID or propagated JWT
3. `Authorization: ApiKey <key>` — API key
4. `X-API-Key: <key>` — API key
5. `?api_key=<key>` — API key query param

### Cookie config

```go
authhttp.CookieConfig{
    Name:     "auth_session",          // cookie name
    Domain:   "example.com",          // cookie domain
    Path:     "/",
    Secure:   true,                   // always true in production
    SameSite: http.SameSiteStrictMode,
    MaxAge:   0,                      // 0 = session cookie
}
```

---

## 6. gRPC Integration

### Server interceptors

```go
import authgrpc "github.com/abhipray-cpu/auth/grpc"

grpcServer := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
            Engine:      a.Engine,
            Propagator:  a.Engine.Propagator(),
            RequireAuth: true, // false = allow unauthenticated
        }),
    ),
    grpc.ChainStreamInterceptor(
        authgrpc.StreamServerInterceptor(authgrpc.ServerConfig{
            Engine:     a.Engine,
            Propagator: a.Engine.Propagator(),
        }),
    ),
)
```

Authentication order (server):

1. mTLS peer certificate → `WorkloadIdentity` in context
2. Propagated JWT header (`x-auth-identity`) → `Identity` in context
3. Bearer session token in metadata → `Identity` in context

### Client interceptors

```go
conn, _ := grpc.NewClient("payments:443",
    grpc.WithChainUnaryInterceptor(
        authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
            Propagator: a.Engine.Propagator(),
        }),
    ),
)
// Identity from ctx is automatically encoded into outgoing metadata.
```

### S2S authentication with dual identity

When service A calls service B:

```go
// Service B handler:
func (s *Server) GetOrder(ctx context.Context, req *pb.GetOrderRequest) (*pb.Order, error) {
    workload := auth.GetWorkloadIdentity(ctx) // service A's mTLS identity
    user := auth.GetIdentity(ctx)             // end-user propagated from service A
    // workload.WorkloadID = "spiffe://acme.com/svc/orders"
    // user.SubjectID = "alice@example.com"
}
```

---

## 7. Lifecycle Hooks

Hooks let you extend auth flows without modifying library code.

### Before hooks (can abort)

Return a non-nil error to abort the flow. The user receives a generic error.

```go
authsetup.WithHook(auth.EventLogin, func(ctx context.Context, p hooks.HookPayload) error {
    payload := p.(*hooks.LoginPayload)
    if isIPBlocked(getIP(ctx)) {
        return errors.New("login blocked")
    }
    return nil
}),
```

### After hooks (logged on error, flow never aborted)

```go
authsetup.WithHook(auth.EventRegistration, func(ctx context.Context, p hooks.HookPayload) error {
    payload := p.(*hooks.RegisterPayload)
    return sendWelcomeEmail(payload.Identifier)
}),
```

### Available events and payloads

| Event | Payload type | Notes |
|---|---|---|
| `auth.EventRegistration` | `*hooks.RegisterPayload` | Before + After |
| `auth.EventLogin` | `*hooks.LoginPayload` | Before + After |
| `auth.EventLoginFailed` | `*hooks.LoginPayload` | After only; `.Error` is set |
| `auth.EventLogout` | `*hooks.LogoutPayload` | After only |
| `auth.EventPasswordReset` | `*hooks.LoginPayload` | Before + After |
| `auth.EventMagicLinkSent` | `*hooks.MagicLinkPayload` | After only |
| `auth.EventAccountLocked` | `*hooks.LoginPayload` | After only |

### Payload fields

**LoginPayload**
```go
type LoginPayload struct {
    Identifier string  // user identifier
    AuthMethod string  // "password", "oauth2", etc.
    SubjectID  string  // empty for failed/before
    SessionID  string  // empty for failed/before
    Error      error   // nil for successful
}
```

**RegisterPayload**
```go
type RegisterPayload struct {
    Identifier string
    AuthMethod string
    SubjectID  string  // empty for BeforeRegister
    SessionID  string  // empty for BeforeRegister
}
```

**OAuthPayload**
```go
type OAuthPayload struct {
    ProviderName string
    Identifier   string
    AuthMethod   string  // always "oauth2"
    SubjectID    string
    SessionID    string
    IsNewUser    bool    // true = auto-registered on first OAuth login
}
```

### Registering multiple hooks

Multiple hooks per event execute in registration order:

```go
authsetup.WithHook(auth.EventLogin, auditLogger),
authsetup.WithHook(auth.EventLogin, metricsRecorder),
authsetup.WithHook(auth.EventLogin, rateLimiter),
```

---

## 8. Identity Propagation

Identity propagation carries the authenticated user identity between services
via HTTP headers or gRPC metadata — no database lookup needed downstream.

### Default: SignedJWTPropagator

Short-lived Ed25519-signed JWTs (30 s TTL), auto-rotating keys, JWKS endpoint.

```go
// Default — no config needed, keys auto-generated
a, _ := authsetup.New(
    // ...other options
    // SignedJWTPropagator is the default, no option needed
)

// Custom config
authsetup.WithSignedJWTPropagator(propagator.SignedJWTConfig{
    Issuer:           "auth.myapp.com",
    Audience:         "internal-services",
    TTL:              30 * time.Second,   // default
    KeyOverlapPeriod: 60 * time.Second,   // old key valid 60s after rotation
}),
```

### JWKS endpoint

Expose `/.well-known/auth-keys` for downstream services to verify tokens:

```go
authhttp.RegisterRoutes(mux, handlers, authhttp.RouteConfig{
    JWKSHandler: a.Engine.Propagator().JWKSHandler(),
})
// Serves: GET /.well-known/auth-keys → {"keys":[{"kty":"OKP","crv":"Ed25519",...}]}
```

### Custom propagator

Implement `propagator.IdentityPropagator`:

```go
type IdentityPropagator interface {
    Encode(ctx context.Context, id *auth.Identity) (map[string]string, error)
    Decode(ctx context.Context, headers map[string]string) (*auth.Identity, error)
}
```

```go
authsetup.WithIdentityPropagator(myPropagator)
```

### Key persistence across restarts

By default, keys are in-memory and lost on restart. For persistence:

```go
type KeyStore interface {
    Save(ctx context.Context, keyID string, privateKey []byte, expiresAt time.Time) error
    Load(ctx context.Context) ([]KeyEntry, error)
}
```

Provide via `SignedJWTConfig.KeyStore`.

---

## 9. Password Policy

NIST 800-63B defaults. Composition rules (uppercase, digits, specials) are
disabled by default — NIST explicitly discourages them.

### Default policy

| Setting | Default | NIST rationale |
|---|---|---|
| `MinLength` | 8 | Minimum acceptable |
| `MaxLength` | 128 | Prevents DoS via hash computation |
| `RequireUppercase` | false | Composition rules hurt usability |
| `RequireLowercase` | false | Same |
| `RequireDigit` | false | Same |
| `RequireSpecial` | false | Same |
| `CheckBreached` | true | k-anonymity check via HaveIBeenPwned |

### Customise

```go
authsetup.WithPasswordPolicy(password.PasswordPolicy{
    MinLength:    12,
    MaxLength:    128,
    CheckBreached: true,
    CustomValidator: func(pw string) error {
        if strings.Contains(strings.ToLower(pw), "acme") {
            return errors.New("password must not contain company name")
        }
        return nil
    },
}),
```

### Breached password check

Uses HaveIBeenPwned k-anonymity API — only the first 5 characters of the
SHA-1 hash are sent. The raw password never leaves your server.

```go
// Check is automatic during registration and password change.
// To disable (e.g., in tests):
authsetup.WithPasswordPolicy(password.PasswordPolicy{
    MinLength:    8,
    MaxLength:    128,
    CheckBreached: false,
}),
```

### Hashing (Argon2id)

Default parameters (OWASP-recommended):

| Parameter | Value |
|---|---|
| Memory | 19 MiB |
| Iterations | 2 |
| Parallelism | 1 |
| Salt | 16 bytes (`crypto/rand`) |
| Key length | 32 bytes |

Override only for legacy schemes or testing:

```go
authsetup.WithHasher(myBcryptHasher) // implement auth.Hasher
```

---

## 10. Interfaces You Must Implement

### `auth.UserStore` (required)

```go
type UserStore interface {
    FindByIdentifier(ctx context.Context, identifier string) (User, error)
    Create(ctx context.Context, user User) error
    UpdatePassword(ctx context.Context, identifier, hashedPassword string) error
    IncrementFailedAttempts(ctx context.Context, identifier string) error
    ResetFailedAttempts(ctx context.Context, identifier string) error
    SetLocked(ctx context.Context, identifier string, locked bool) error
}
```

### `auth.User` (required)

```go
type User interface {
    GetIdentifier() string
    GetHashedPassword() string
    GetFailedAttempts() int
    IsLocked() bool
}
```

### `auth.Notifier` (required for magic link)

```go
type Notifier interface {
    Send(ctx context.Context, identifier, token string) error
}
```

### `session.MagicLinkStore` (required for magic link)

```go
type MagicLinkStore interface {
    Save(ctx context.Context, token, identifier string, ttl time.Duration) error
    Consume(ctx context.Context, token string) (identifier string, err error)
}
```

### `apikey.APIKeyStore` (required for API key mode)

```go
type APIKeyStore interface {
    FindByKey(ctx context.Context, keyHash string) (*APIKey, error)
    Create(ctx context.Context, apiKey *APIKey) error
    Revoke(ctx context.Context, keyID string) error
    ListBySubject(ctx context.Context, subjectID string) ([]*APIKey, error)
    UpdateLastUsed(ctx context.Context, keyID string, timestamp time.Time) error
}
```

### `auth.Authorizer` (optional)

```go
type Authorizer interface {
    Authorize(ctx context.Context, identity *Identity, action, resource string) error
}
```

---

## 11. Error Handling

All sentinel errors can be matched with `errors.Is()`.

| Error | When |
|---|---|
| `auth.ErrInvalidCredentials` | Wrong password, bad token, unknown API key |
| `auth.ErrAccountLocked` | Too many failed attempts |
| `auth.ErrSessionExpired` | Session exceeded idle or absolute timeout |
| `auth.ErrSessionNotFound` | Session ID does not exist |
| `auth.ErrUserNotFound` | User not in UserStore |
| `auth.ErrUserAlreadyExists` | Register with duplicate identifier |
| `auth.ErrPasswordPolicyViolation` | Password fails policy |
| `auth.ErrAPIKeyExpired` | API key past `ExpiresAt` |
| `auth.ErrAPIKeyRevoked` | API key has `Revoked = true` |
| `auth.ErrPropagationFailed` | JWT sign/verify error between services |
| `auth.ErrSchemaVersionMismatch` | Session store schema version mismatch |
| `auth.ErrTokenNotFound` | Magic link token consumed, expired, or never created |

### Pattern

```go
identity, _, err := engine.Login(ctx, cred)
switch {
case err == nil:
    // success
case errors.Is(err, auth.ErrInvalidCredentials):
    // return generic 401 — do NOT distinguish user/password
case errors.Is(err, auth.ErrAccountLocked):
    // return 423 or 401
case errors.Is(err, auth.ErrSessionExpired):
    // clear cookie, redirect to login
default:
    // internal error — log, return 500
}
```

> **Security:** Never distinguish between "user not found" and "wrong password" in
> your HTTP response. `ErrInvalidCredentials` is returned for both — this prevents
> user enumeration attacks.

---

## 12. Security Guarantees

| Property | Implementation |
|---|---|
| Timing-safe verification | Dummy hash computed for non-existent users; `subtle.ConstantTimeCompare` throughout |
| Generic error messages | All auth failures return `ErrInvalidCredentials` — no user/password distinction |
| Session ID entropy | 256 bits, `crypto/rand` |
| Session IDs at rest | SHA-256 hashed — raw ID only in cookie, never persisted |
| Session fixation | Existing session destroyed before new session created |
| PKCE | Mandatory S256 for all OAuth flows |
| Magic link tokens | Single-use, 256-bit random, 15-minute TTL |
| Password hashing | Argon2id, OWASP parameters |
| Breached passwords | k-anonymity check — only SHA-1 prefix sent to API |
| Propagation JWTs | Ed25519, 30 s TTL, auto-rotating keys, audience+issuer bound |
| Pen tested | 80 test cases across 12 security categories — zero critical/high findings |

**What Attestor does NOT do (by design):**

| Feature | Why not |
|---|---|
| Rate limiting | Infrastructure concern — use API gateway / reverse proxy |
| CSRF protection | Framework concern — use `gorilla/csrf` or similar |
| Metrics / tracing | Avoid coupling to specific observability stack; use hooks for metrics |
| Email / SMS delivery | You implement `Notifier` with your own provider |
| Health endpoint | Your app knows what health means for your stack |

---

## 13. FAQ

**Why not just use an SDK from Google/Okta/Auth0?**
Vendor SDKs couple your code to a provider. Attestor is provider-agnostic —
switching from Okta to Entra ID is one config line change.

**Why no rate limiting in the library?**
Rate limiting requires infrastructure context (IP, user agent, load balancer).
A library cannot make these decisions. Use your API gateway, nginx
`limit_req_zone`, or a sidecar.

**Why no SAML?**
SAML is XML-based, complex to implement securely, and mostly relevant for
enterprise SSO. Use Entra ID or Okta's OIDC endpoint instead — both support
OIDC natively and forward SAML assertions internally.

**Why is `auth.GetIdentity(ctx)` the only thing my business logic needs?**
By putting identity in `context.Context`, your handlers and services don't need
to import auth internals. You can swap the entire auth implementation without
touching business logic.

**Can I use multiple auth modes at the same time?**
Yes. Provide the stores/config for each mode you want. The engine dispatches
by `auth.CredentialType` — a request with an API key gets API key auth even if
password auth is also enabled.

**How do I rotate Ed25519 signing keys?**
Automatically. `SignedJWTPropagator` rotates keys with a 60-second overlap —
tokens signed by the old key remain valid during the overlap window. No
downtime, no manual intervention.

**What if I need to log users out of all sessions?**
```go
err := engine.Logout(ctx, "", subjectID) // second arg empty = logout all
```

---

## 14. Migration Guide

### v0.x → v1.0

v1.0 is the initial public release. No migration needed.

### Schema migration (Postgres)

If you have existing `auth_sessions` data with `schema_version = 0` (pre-release):

```sql
-- Check current version
SELECT DISTINCT schema_version FROM auth_sessions;

-- Upgrade (no column changes in v0 → v1)
UPDATE auth_sessions SET schema_version = 1;
```

Then restart — the library will see `schema_version = 1` and proceed.

### Replacing `WithSkipSchemaCheck()` in production

`WithSkipSchemaCheck()` is for testing only. In production, run the migration
SQL above, then remove the option.

### Adding Redis session store to an existing Postgres setup

```go
// Week 1: dual-write (Postgres primary, Redis secondary)
// Week 2: flip to Redis primary
// Week 3: drain Postgres sessions (they expire naturally)
authsetup.WithSessionRedis(redisClient, "")
```

Sessions are independent — there is no cross-store migration. Old Postgres
sessions will be rejected (not found in Redis) and users re-login once.
