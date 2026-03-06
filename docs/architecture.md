# Attestor — Architecture

> **Version:** 1.0 · **Date:** 2026-02-17

---

## Table of Contents

1. [Scope — What We Own, What We Don't](#1-scope--what-we-own-what-we-dont)
2. [Architecture Diagrams](#2-architecture-diagrams)
   - 2.1 [System Context](#21-system-context)
   - 2.2 [Inside the Go Process](#22-inside-the-go-process)
   - 2.3 [Auth Engine Internals](#23-auth-engine-internals)
   - 2.4 [Responsibility Boundary](#24-responsibility-boundary)
3. [Authentication Modes](#3-authentication-modes)
   - 3.1 [Enterprise IdP Support](#31-enterprise-idp-support)
4. [Session Management — Library Owned](#4-session-management--library-owned)
5. [Identity Propagation — Cross-Service](#5-identity-propagation--cross-service)
6. [Password Policy](#6-password-policy)
7. [Interceptor Model](#7-interceptor-model)
8. [Interface Contracts](#8-interface-contracts)
9. [C4 Level 4 — Code Diagrams (UML)](#9-c4-level-4--code-diagrams-uml)
   - 9.1 [Session Store — Interfaces and Adapters](#91-session-store--interfaces-and-adapters)
   - 9.2 [User Store, Authorizer, Notifier, Hasher — Interfaces and Types](#92-user-store-authorizer-notifier-hasher--interfaces-and-types)
   - 9.3 [API Key Store and Password Policy](#93-api-key-store-and-password-policy)
   - 9.4 [Identity Propagator — Interfaces and Implementations](#94-identity-propagator--interfaces-and-implementations)
   - 9.5 [Auth Engine, Modes, and Protocol Bindings](#95-auth-engine-modes-and-protocol-bindings)
10. [Sequence Diagrams](#10-sequence-diagrams)
    - 10.1 [HTTP Request — Session Validation](#101-http-request--session-validation)
    - 10.2 [Password Login — With Security Protections](#102-password-login--with-security-protections)
    - 10.3 [OAuth2 / OIDC Login — With Auto-Registration](#103-oauth2--oidc-login--with-auto-registration)
    - 10.4 [Magic Link — Passwordless Login](#104-magic-link--passwordless-login)
    - 10.5 [User Registration — With Onboarding](#105-user-registration--with-onboarding)
    - 10.6 [Cross-Protocol — HTTP to gRPC Identity Propagation](#106-cross-protocol--http-to-grpc-identity-propagation)
    - 10.7 [System-to-System — Machine Identity Only](#107-system-to-system--machine-identity-only)
11. [Identity Context](#11-identity-context)
12. [Integration Summary](#12-integration-summary)
13. [Design Rationale](#13-design-rationale)

---

## Color Scheme Legend

All diagrams in this document follow a consistent color scheme:

| Color | Meaning |
|---|---|
| **Blue** (`#dbeafe` / `#2563eb`) | Attestor owned — we ship and maintain this |
| **Amber** (`#fef3c7` / `#d97706`) | Team-provided — team must implement or configure |
| **Green** (`#d1fae5` / `#059669`) | Identity context — the output of auth, flows into your code |
| **Gray** (`#f3f4f6` / `#9ca3af`) | Optional — team can skip entirely |
| **Light gray** (`#f9fafb` / `#d1d5db`) | External systems — outside our boundary |

Solid arrows = we call directly or we own. Dotted arrows = team-provided interface or optional.

---

## 1. Scope — What We Own, What We Don't

### We Own

| Area | Description |
|---|---|
| **Credential verification** | Passwords (via Hasher), OAuth2/OIDC token verification, magic link tokens, API key validation, mTLS cert verification, SPIFFE SVIDs |
| **Authentication modes** | Password, OAuth2/OIDC, Magic Link, API Key, mTLS/SPIFFE — pluggable via `AuthMode` interface |
| **Session management** | We own the session schema, lifecycle, and ship Redis + Postgres adapters. Team provides the infrastructure (Redis/Postgres instance). Session fixation prevention is a non-configurable security invariant. |
| **Identity normalization** | Any verified credential produces a canonical `Identity` value for `context.Context` |
| **Identity propagation** | `IdentityPropagator` interface with three shipped implementations (`SignedJWTPropagator`, `SessionPropagator`, `SPIFFEPropagator`). Controls how user identity travels between services. |
| **Protocol bindings** | HTTP middleware, gRPC interceptors (unary + stream, client + server), S2S credential exchange |
| **Password policy** | Configurable `PasswordPolicy` struct with NIST 800-63B defaults. Validated during registration and password change. |
| **Magic link token storage** | Uses the same session store infrastructure (same Redis/Postgres instance) with a separate key prefix / table. An optional `MagicLinkStore` interface is exposed via `WithMagicLinkStore()` for teams that need custom storage. Tokens are short-lived and single-use. |
| **Lifecycle hooks** | Before/After events on login, register, logout, MFA. Teams register typed callbacks. |
| **User onboarding** | Register-and-login-in-one-step. OAuth auto-registration on first login. Seamless experience. |
| **Session schema versioning** | Schema version tracked in the sessions table. Library checks version on startup and fails with a clear error + migration guide link if outdated. Never auto-migrates. |

### We Define (Interfaces — Team Implements)

| Interface | Required? | Description |
|---|---|---|
| **UserStore** | Yes | CRUD for users. Team owns the schema and database. |
| **User** | Yes | Wraps team's user model so the library can read subject ID, password hash, lock status. |
| **IdentifierConfig** | Yes | Team tells us what identifies a user: email, username, phone, UUID. We never assume. |
| **APIKeyStore** | If API Key mode enabled | Key lookup, creation, revocation. Separate from `UserStore` — API keys are a first-class concept with their own metadata (name, scopes, expiry, last used). |
| **Authorizer** | If AuthZ needed | `CanAccess(ctx, subject, action, resource) → bool`. Team implements with Casbin, OPA, Cedar, or custom. |
| **Notifier** | Optional | Team implements if they want notifications on auth events. If not configured, silently skipped. Required only if magic link mode is enabled. |
| **Hasher** | No (default provided) | Argon2id shipped as default. Override only for legacy schemes. |
| **SessionStore** | No (adapters shipped) | Redis + Postgres adapters shipped. Custom adapter only if neither fits. |

### Not Our Concern

| Area | Why |
|---|---|
| **Rate limiting** | Infrastructure concern. Use your API gateway, reverse proxy, or a dedicated library. Mixing rate limiting into an auth library creates configuration conflicts with API gateways. |
| **User storage / schema** | Team's database, team's migrations, team's schema. We ask for an interface. |
| **External token issuance** | We do NOT issue tokens for team APIs or end users. We verify credentials and manage sessions. The `SignedJWTPropagator` creates 30-second internal assertions for cross-service identity — this is infrastructure plumbing, not token issuance. |
| **Notifications** | Optional interface. If the team wants emails/SMS on auth events, they implement `Notifier`. We emit events; they decide delivery. |
| **Authorization decisions** | We produce an identity. What it's allowed to do is the team's domain. |
| **User identifier choice** | Email, username, phone, UUID, employee ID — the team configures this. |
| **SAML** | SAML is a legacy protocol. Every enterprise IdP that speaks SAML also speaks OIDC. For the rare SAML-only case, use a SAML-to-OIDC bridge (Dex, Keycloak). Supporting SAML would triple our protocol surface for <5% of use cases. |
| **CSRF protection** | Framework-level concern. |
| **Infrastructure** | Databases, Kubernetes, TLS certificate issuance, secret management — all team-owned. |

---

## 2. Architecture Diagrams

### 2.1 System Context

Where the Attestor sits in the broader ecosystem.

```mermaid
flowchart TB
    subgraph actors [" "]
        direction LR
        user(["End User<br/>Browser, Mobile, CLI"])
        dev(["Adopting Developer<br/>Go developer"])
    end

    subgraph core ["Attestor"]
        authLib["Authentication Engine<br/>Protocol-agnostic AuthN<br/>Interceptor-based<br/>Identity context propagation"]
    end

    subgraph external ["External Identity Systems"]
        direction LR
        idp["Identity Providers<br/>Any OIDC-compliant IdP<br/>Entra ID, Okta, PingOne<br/>Keycloak, Auth0, Google"]
        spiffe["SPIFFE / SPIRE<br/>Workload Identity"]
    end

    subgraph teamProvided ["Team-Provided"]
        direction LR
        userStore["User Store<br/>Team implements interface<br/>Any DB, any schema"]
        apiKeyStore["API Key Store<br/>Team implements interface<br/>Key metadata + scopes"]
        notifier["Notifier — Optional<br/>Team implements if needed<br/>Email, SMS, Push"]
        authzEngine["Authorizer<br/>Team implements interface<br/>Casbin, OPA, Cedar, Custom"]
    end

    user -- "Authenticates via<br/>HTTP / gRPC" --> authLib
    dev -- "Integrates via<br/>go get" --> authLib

    authLib -- "Verifies via OIDC<br/>Discovery + JWKS" --> idp
    authLib -- "Verifies workload<br/>SVIDs" --> spiffe

    authLib -. "Looks up user by<br/>team-configured identifier<br/>(UserStore interface)" .-> userStore
    authLib -. "Looks up API keys<br/>(APIKeyStore interface)" .-> apiKeyStore
    authLib -. "Optional: emits events<br/>(Notifier interface)" .-> notifier
    authLib -. "Passes identity context<br/>(Authorizer interface)" .-> authzEngine

    style core fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style external fill:#f9fafb,stroke:#d1d5db,color:#333
    style teamProvided fill:#fef3c7,stroke:#d97706,color:#333
    style actors fill:#fff,stroke:#fff,color:#333
    style authLib fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    style user fill:#eff6ff,stroke:#2563eb,color:#333
    style dev fill:#eff6ff,stroke:#2563eb,color:#333
    style idp fill:#f9fafb,stroke:#d1d5db,color:#333
    style spiffe fill:#f9fafb,stroke:#d1d5db,color:#333
    style userStore fill:#fef3c7,stroke:#d97706,color:#333
    style apiKeyStore fill:#fef3c7,stroke:#d97706,color:#333
    style notifier fill:#f3f4f6,stroke:#9ca3af,color:#666
    style authzEngine fill:#fef3c7,stroke:#d97706,color:#333
```

**Reading the diagram:**
- **Blue** = we own and ship it.
- **Amber** = team must provide an implementation.
- **Gray** (Notifier) = entirely optional.
- **Solid arrows** = direct calls we make (IdP verification, SPIFFE).
- **Dotted arrows** = team-provided interface implementations.

---

### 2.2 Inside the Go Process

How library components interact within a running application. Shows authentication modes, session management, identity propagation, and the flow to business logic.

```mermaid
flowchart TB
    user(["End User"]) -- "HTTP / gRPC" --> bindings

    subgraph app ["Go Application Process"]
        direction TB

        subgraph bindings ["Protocol Bindings — Interceptors"]
            direction LR
            httpBinding["HTTP Middleware<br/>Extracts credentials from<br/>cookies, headers, forms<br/>Injects identity into ctx"]
            grpcBinding["gRPC Interceptors<br/>Extracts credentials from<br/>metadata and TLS peer<br/>Injects identity into ctx"]
            s2sBinding["S2S Exchange<br/>mTLS cert identity<br/>SPIFFE SVIDs<br/>Service account tokens"]
        end

        subgraph modes ["Authentication Modes"]
            direction LR
            pwMode["Password Auth<br/>Identifier + password<br/>Argon2id hashing<br/>Account lockout"]
            oauthMode["OAuth2 / OIDC<br/>Any OIDC-compliant IdP<br/>Entra ID, Okta, PingOne<br/>Discovery-based config"]
            magicMode["Magic Link<br/>Passwordless login<br/>Time-limited token<br/>via Notifier"]
            apiKeyMode["API Key<br/>Header or query param<br/>Key lookup + verify"]
            mtlsMode["mTLS / SPIFFE<br/>Certificate identity<br/>Workload verification"]
        end

        subgraph engine ["Auth Engine — Protocol Agnostic"]
            authEngine["Credential Verification<br/>Session Management<br/>Identity Normalization<br/>Lifecycle Hooks"]
        end

        subgraph sessionLayer ["Session Management — Library Owned"]
            direction LR
            sessionMgr["Session Manager<br/>Create, validate, refresh, destroy<br/>Idle + absolute timeouts<br/>Concurrent session limits<br/>Session fixation prevention"]
            redisAdapter["Redis Adapter<br/>Shipped by library<br/>Production ready"]
            pgAdapter["Postgres Adapter<br/>Shipped by library<br/>Production ready"]
            customAdapter["Custom Adapter<br/>Optional: team implements<br/>SessionStore interface"]
        end

        subgraph propagation ["Identity Propagation — Library Owned"]
            direction LR
            propagator["IdentityPropagator<br/>Carries identity across services<br/>Pluggable strategy"]
            jwtProp["SignedJWTPropagator<br/>Default — 30s Ed25519 JWT<br/>Stateless, no shared infra"]
            sessionProp["SessionPropagator<br/>Re-validates against<br/>shared session store"]
            spiffeProp["SPIFFEPropagator<br/>Delegates to SPIRE<br/>Workload API"]
        end

        subgraph ctx ["Identity Context — context.Context"]
            identityCtx["Carries verified identity<br/>across protocol boundaries<br/>The ONLY thing your code sees"]
        end

        subgraph yourCode ["Your Application — Zero Auth Imports"]
            direction LR
            bizLogic["Business Logic<br/>Reads identity from ctx<br/>No Attestor dependency"]
            authzAdapter["Authorizer<br/>Team-provided<br/>Wraps any policy engine"]
        end

        httpBinding --> modes
        grpcBinding --> modes
        s2sBinding --> modes

        modes --> authEngine

        authEngine --> sessionMgr
        sessionMgr --> redisAdapter
        sessionMgr --> pgAdapter
        sessionMgr -.-> customAdapter

        authEngine --> propagator
        propagator --> jwtProp
        propagator --> sessionProp
        propagator --> spiffeProp

        authEngine -- "Writes verified identity" --> identityCtx
        identityCtx -- "Read by handlers" --> bizLogic
        bizLogic -- "Can I do X?" --> authzAdapter
    end

    subgraph teamImpl ["Team-Provided"]
        direction LR
        idp["Identity Providers<br/>Any OIDC-compliant IdP"]
        userStore["User Store<br/>Team implements"]
        apiKeyStore["API Key Store<br/>Team implements"]
    end

    authEngine -- "Verify external tokens" --> idp
    authEngine -. "Lookup user by<br/>configured identifier" .-> userStore
    authEngine -. "Lookup API key" .-> apiKeyStore

    style app fill:#eff6ff,stroke:#2563eb,color:#333
    style bindings fill:#dbeafe,stroke:#2563eb,color:#333
    style modes fill:#e0e7ff,stroke:#4f46e5,color:#333
    style engine fill:#dbeafe,stroke:#2563eb,color:#333
    style sessionLayer fill:#dbeafe,stroke:#2563eb,color:#333
    style propagation fill:#dbeafe,stroke:#2563eb,color:#333
    style ctx fill:#d1fae5,stroke:#059669,color:#333
    style yourCode fill:#fef3c7,stroke:#d97706,color:#333
    style teamImpl fill:#f9fafb,stroke:#d1d5db,color:#333

    style httpBinding fill:#fff,stroke:#2563eb,color:#333
    style grpcBinding fill:#fff,stroke:#2563eb,color:#333
    style s2sBinding fill:#fff,stroke:#2563eb,color:#333
    style pwMode fill:#fff,stroke:#4f46e5,color:#333
    style oauthMode fill:#fff,stroke:#4f46e5,color:#333
    style magicMode fill:#fff,stroke:#4f46e5,color:#333
    style apiKeyMode fill:#fff,stroke:#4f46e5,color:#333
    style mtlsMode fill:#fff,stroke:#4f46e5,color:#333
    style authEngine fill:#fff,stroke:#2563eb,color:#333
    style sessionMgr fill:#fff,stroke:#2563eb,color:#333
    style redisAdapter fill:#fff,stroke:#2563eb,color:#333
    style pgAdapter fill:#fff,stroke:#2563eb,color:#333
    style customAdapter fill:#f3f4f6,stroke:#9ca3af,color:#666
    style propagator fill:#fff,stroke:#2563eb,color:#333
    style jwtProp fill:#fff,stroke:#2563eb,color:#333
    style sessionProp fill:#fff,stroke:#2563eb,color:#333
    style spiffeProp fill:#fff,stroke:#2563eb,color:#333
    style identityCtx fill:#fff,stroke:#059669,color:#333
    style bizLogic fill:#fff,stroke:#d97706,color:#333
    style authzAdapter fill:#fff,stroke:#d97706,color:#333
    style user fill:#eff6ff,stroke:#2563eb,color:#333
    style idp fill:#f9fafb,stroke:#d1d5db,color:#333
    style userStore fill:#fef3c7,stroke:#d97706,color:#333
    style apiKeyStore fill:#fef3c7,stroke:#d97706,color:#333
```

**Key observations:**
- **Authentication Modes** are pluggable. The engine dispatches to the correct mode based on credential type.
- **Session Management** is entirely library-owned. We ship the schema and two production-ready adapters (Redis, Postgres). The team provides the infrastructure (a Redis or Postgres instance). A custom adapter is optional.
- **Identity Propagation** is library-owned with three strategy implementations. `SignedJWTPropagator` is the default.
- **API Key Mode** uses the `APIKeyStore` interface, separate from `UserStore`. API keys have their own metadata (scopes, expiry, last used).
- The **Custom Adapter** is grayed out — it exists only if Redis and Postgres don't fit the team's needs.

---

### 2.3 Auth Engine Internals

What's inside the auth engine. Session management and identity propagation are highlighted as library-owned.

```mermaid
flowchart TB
    subgraph engine ["Auth Engine — Components"]
        direction TB

        subgraph verify ["Credential Verification"]
            credVerifier["Credential Verifier<br/>Dispatches to correct auth mode<br/>Password, OAuth2, Magic Link<br/>API Key, mTLS, SPIFFE"]
        end

        subgraph session ["Session Management — Library Owned"]
            direction LR
            sessionMgr["Session Manager<br/>Create, validate, refresh, destroy<br/>Idle + absolute timeouts<br/>Concurrent session limits<br/>Session fixation prevention<br/>Schema versioning"]
        end

        subgraph prop ["Identity Propagation — Library Owned"]
            direction LR
            propagator["Identity Propagator<br/>Encode/Decode identity<br/>for cross-service calls<br/>SignedJWT default"]
        end

        subgraph output ["Identity Output"]
            direction LR
            identityNorm["Identity Normalizer<br/>Any credential source into<br/>canonical Identity struct<br/>for context propagation"]
            hookEmitter["Hook Emitter<br/>Before/After lifecycle events<br/>Login, logout, register, MFA<br/>Optional typed callbacks"]
        end

        credVerifier --> identityNorm
        sessionMgr --> identityNorm
        propagator --> identityNorm
        hookEmitter -. "fires on<br/>auth events" .-> credVerifier
    end

    subgraph sessionAdapters ["Session Store Adapters"]
        direction LR
        redis["Redis Adapter<br/>Library ships this<br/>Production ready"]
        postgres["Postgres Adapter<br/>Library ships this<br/>Production ready"]
        custom["Custom Adapter<br/>Optional: team implements<br/>SessionStore interface"]
    end

    subgraph interfaces ["Team-Provided via Interfaces"]
        direction LR
        userStore["User Store<br/>Lookup by configured identifier"]
        apiKeyStore["API Key Store<br/>Key lookup + metadata"]
        hasher["Hasher<br/>Argon2id default provided"]
        notifier["Notifier — Optional<br/>Team enables if needed"]
    end

    sessionMgr --> redis
    sessionMgr --> postgres
    sessionMgr -.-> custom

    credVerifier -. "lookup user" .-> userStore
    credVerifier -. "lookup API key" .-> apiKeyStore
    credVerifier -- "hash/verify" --> hasher
    hookEmitter -. "optional notify" .-> notifier

    style engine fill:#eff6ff,stroke:#2563eb,color:#333
    style verify fill:#dbeafe,stroke:#2563eb,color:#333
    style session fill:#dbeafe,stroke:#2563eb,color:#333
    style prop fill:#dbeafe,stroke:#2563eb,color:#333
    style output fill:#d1fae5,stroke:#059669,color:#333
    style sessionAdapters fill:#dbeafe,stroke:#2563eb,color:#333
    style interfaces fill:#fef3c7,stroke:#d97706,color:#333

    style credVerifier fill:#fff,stroke:#2563eb,color:#333
    style sessionMgr fill:#fff,stroke:#2563eb,color:#333
    style propagator fill:#fff,stroke:#2563eb,color:#333
    style identityNorm fill:#fff,stroke:#059669,color:#333
    style hookEmitter fill:#fff,stroke:#059669,color:#333
    style redis fill:#fff,stroke:#2563eb,color:#333
    style postgres fill:#fff,stroke:#2563eb,color:#333
    style custom fill:#f3f4f6,stroke:#9ca3af,color:#666
    style userStore fill:#fef3c7,stroke:#d97706,color:#333
    style apiKeyStore fill:#fef3c7,stroke:#d97706,color:#333
    style hasher fill:#fef3c7,stroke:#d97706,color:#333
    style notifier fill:#f3f4f6,stroke:#9ca3af,color:#666
```

---

### 2.4 Responsibility Boundary

The ownership boundary between Attestor and adopting team. Session management and identity propagation are on our side. Infrastructure and API key storage are on theirs.

```mermaid
flowchart LR
    subgraph ours ["Attestor Scope"]
        direction TB
        authN["Authentication<br/>Verifies identity<br/>Produces Identity value<br/>for context propagation"]
        sessionOwn["Session Management<br/>We own the schema + adapters<br/>Redis + Postgres shipped<br/>Session fixation prevention<br/>Schema versioning"]
        propagationOwn["Identity Propagation<br/>IdentityPropagator interface<br/>SignedJWT, Session, SPIFFE<br/>implementations shipped"]
        authzIface["Authorizer Interface<br/>CanAccess contract<br/>We define, team implements"]
        notifierIface["Notifier Interface<br/>Optional contract<br/>Team enables if needed"]
        authN --> sessionOwn
        authN --> propagationOwn
        authN --> authzIface
        authN --> notifierIface
    end

    subgraph theirs ["Adopting Team Scope"]
        direction TB
        infra["Infrastructure<br/>Redis / Postgres instance<br/>Connection config only"]
        apiKeyImpl["API Key Store<br/>Team implements<br/>APIKeyStore interface"]
        authzImpl["AuthZ Implementation<br/>Casbin, OPA, Cedar<br/>Custom RBAC/ABAC"]
        notifierImpl["Notifier Implementation<br/>Optional: SendGrid, SES<br/>or skip entirely"]
        bizLogic["Business Logic<br/>Reads Identity from ctx<br/>Calls Authorizer<br/>Zero Attestor imports"]
        authzImpl --> bizLogic
    end

    authN -- "Identity via<br/>context.Context" --> bizLogic
    sessionOwn -- "Uses team's<br/>infra" --> infra
    authzIface -- "Team implements" --> authzImpl
    notifierIface -. "Optional" .-> notifierImpl
    authN -. "API key mode" .-> apiKeyImpl

    style ours fill:#dbeafe,stroke:#2563eb,color:#333
    style theirs fill:#fef3c7,stroke:#d97706,color:#333
    style authN fill:#d1fae5,stroke:#059669,color:#333
    style sessionOwn fill:#dbeafe,stroke:#2563eb,color:#333
    style propagationOwn fill:#dbeafe,stroke:#2563eb,color:#333
    style authzIface fill:#dbeafe,stroke:#2563eb,color:#333
    style notifierIface fill:#f3f4f6,stroke:#9ca3af,color:#666
    style infra fill:#fef3c7,stroke:#d97706,color:#333
    style apiKeyImpl fill:#fef3c7,stroke:#d97706,color:#333
    style authzImpl fill:#fef3c7,stroke:#d97706,color:#333
    style notifierImpl fill:#f3f4f6,stroke:#9ca3af,color:#666
    style bizLogic fill:#fef3c7,stroke:#d97706,color:#333
```

---

## 3. Authentication Modes

The auth engine supports multiple authentication modes. Each mode implements the same `AuthMode` interface. The engine dispatches to the correct mode based on the credential type in the request.

| Mode | Credential | How It Works | Requires |
|---|---|---|---|
| **Password** | Identifier + password | Lookup user by configured identifier, verify password hash via Hasher. Constant-time comparison for non-existent users. Account lockout after N failures. Password validated against `PasswordPolicy` on registration and change. | UserStore, Hasher |
| **OAuth2 / OIDC** | Authorization code | Redirect to provider → callback with code → exchange for id_token → verify signature + claims → produce identity. Auto-registers new users on first login. **PKCE enabled by default for all flows** (mandatory, not optional). **Works with any OIDC-compliant provider** — see [Enterprise IdP Support](#31-enterprise-idp-support). | UserStore, Provider config |
| **Magic Link** | One-time token via email/SMS | Generate short-lived token, deliver via Notifier, user clicks link, verify token, produce identity. Passwordless. Token stored using session store infrastructure (separate key prefix/table) — no additional interface required. | UserStore, Notifier (**required** for this mode) |
| **API Key** | Key in header or query param | Lookup key via `APIKeyStore`, verify it hasn't expired or been revoked, produce identity. For programmatic access. API keys are a first-class concept — separate from user records. | APIKeyStore |
| **mTLS / SPIFFE** | X.509 certificate or SVID | Verify peer certificate against trust anchors. Extract workload identity from cert CN or SPIFFE ID. For service-to-service. | Trust anchor config |

**All modes produce the same output:** an `Identity` value written to `context.Context`. Your business logic doesn't know or care which mode was used.

> **Design note — PKCE:** [PKCE (Proof Key for Code Exchange)](https://datatracker.ietf.org/doc/html/rfc7636) is mandatory for public clients (SPAs, mobile apps) and strongly recommended for all clients per the [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics). The library generates `code_verifier` + `code_challenge` automatically for every OAuth flow. This is a non-negotiable security requirement, not a configurable option.

### 3.1 Enterprise IdP Support

The OAuth2/OIDC mode is **provider-agnostic by design**. We program against the OIDC protocol, not individual providers. Any identity provider that implements the [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) specification (`/.well-known/openid-configuration`) works out of the box.

#### How It Works

Our `OAuthMode` uses **OIDC Discovery** at startup:

1. Team provides the **Issuer URL** (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`)
2. Library fetches `{issuer}/.well-known/openid-configuration` automatically
3. From that document, we discover: authorization endpoint, token endpoint, JWKS URI, supported scopes, supported claims
4. JWKS (public signing keys) are cached and rotated automatically via the `jwks_uri`
5. All subsequent token verification uses the discovered endpoints and keys

This means **zero provider-specific code**. Adding a new IdP is a configuration change, not a code change.

#### Verified Compatible Providers

| Provider | Issuer URL Pattern | Notes |
|---|---|---|
| **Microsoft Entra ID** (Azure AD) | `https://login.microsoftonline.com/{tenant}/v2.0` | Supports `common`, `organizations`, `consumers`, or specific tenant. Multi-tenant apps supported. |
| **Okta** | `https://{domain}.okta.com/oauth2/{authServerId}` | Org authorization server or custom authorization server. |
| **Auth0** | `https://{domain}.auth0.com/` | Universal Login. Custom domains supported. |
| **PingFederate / PingOne** | `https://{host}/as` or `https://auth.pingone.{region}/` | Enterprise SSO and federation. |
| **Keycloak** | `https://{host}/realms/{realm}` | Open source. Common in on-premise deployments. |
| **AWS Cognito** | `https://cognito-idp.{region}.amazonaws.com/{poolId}` | User pools with hosted UI. |
| **Google Workspace** | `https://accounts.google.com` | Consumer + enterprise (Google Workspace). |
| **OneLogin** | `https://{domain}.onelogin.com/oidc/2` | Enterprise SSO. |
| **ForgeRock / PingIdentity** | `https://{host}/am/oauth2/{realm}` | AM server with OIDC support. |
| **Any OIDC-certified provider** | Provider's documented issuer URL | If it has `/.well-known/openid-configuration`, it works. |

#### What the Team Configures Per Provider

```go
authsetup.WithOAuthProvider(oauth.ProviderConfig{
    Name:         "entra-id",                                         // arbitrary name
    IssuerURL:    "https://login.microsoftonline.com/{tenant}/v2.0",  // we discover everything from this
    ClientID:     "from-env",                                         // team registers app with IdP
    ClientSecret: "from-env",                                         // team registers app with IdP
    Scopes:       []string{"openid", "profile", "email"},             // standard OIDC scopes
    RedirectURL:  "https://app.example.com/auth/oauth/entra-id/callback",
})
```

That's it. No provider-specific adapters. No "Okta plugin" or "Azure AD module". The OIDC spec handles the rest.

#### Multiple Providers Simultaneously

Teams can register multiple providers. The library routes to the correct one based on the OAuth initiation URL:

- `/auth/oauth/entra-id` → Microsoft Entra ID
- `/auth/oauth/okta` → Okta
- `/auth/oauth/google` → Google

Each provider has its own client credentials, scopes, and redirect URL. The engine handles state, nonce, PKCE, and token verification per-provider.

---

## 4. Session Management — Library Owned

Session management is too critical to leave to individual teams. A misconfigured session schema or a broken TTL policy is a security vulnerability. We own this.

### What We Own

| Concern | Details |
|---|---|
| **Session schema** | We define the session structure: ID, SubjectID, CreatedAt, ExpiresAt, LastActiveAt, SchemaVersion, Metadata |
| **Session lifecycle** | Create, validate, refresh, destroy. Idle timeout, absolute timeout, sliding window refresh. |
| **Session fixation prevention** | On every successful authentication (login, register, OAuth callback), the library destroys any existing session for the request and generates a completely new session ID. Pre-authentication session IDs are never reused. This is an invariant — not configurable. |
| **Concurrent session limits** | Configurable max sessions per subject. Oldest session evicted when limit is exceeded. |
| **Magic link token storage** | Magic link tokens are stored using the same session store infrastructure (same Redis/Postgres instance) with a separate key prefix (`magiclink:`) or table (`magic_link_tokens`). An optional `MagicLinkStore` interface is exposed via `WithMagicLinkStore()` for teams that need custom token storage. Tokens have a short TTL and are single-use. |
| **Schema versioning** | A `schema_version` field is stored in the sessions table. On startup, the library reads the schema version. If outdated, the library fails with a clear error message and a link to the migration guide. **The library never auto-migrates in production.** Migration SQL is shipped as files; the team runs them explicitly. |
| **Redis adapter** | Production-ready. Automatic TTL via Redis EXPIRE. Prefix-based key isolation. |
| **Postgres adapter** | Production-ready. Automatic cleanup of expired sessions. Index on SubjectID + ExpiresAt. |
| **Session config** | IdleTimeout, AbsoluteTimeout, MaxConcurrent, CookieName, CookieSecure, CookieSameSite |

### What the Team Provides

| Concern | Details |
|---|---|
| **Infrastructure** | A Redis or Postgres instance. Connection string / config. |
| **Custom adapter** | Optional. Only if Redis and Postgres don't fit. Implement the `SessionStore` interface. |
| **Migrations** | When upgrading the library, the team runs migration SQL we ship. Explicit, auditable, safe. |

### Security Guarantees

These are invariants — not configurable:

1. **Session fixation prevention.** Every authentication event (login, register, OAuth callback) destroys the old session and creates a new one. This is built into `SessionManager.CreateSession()`.
2. **Session IDs are hashed in storage.** The raw session ID is in the cookie; the stored version is a SHA-256 hash. Compromised storage doesn't leak valid session IDs.
3. **Timing-safe session lookup.** Session validation uses constant-time comparison to prevent timing attacks.

### Why We Don't Leave This to Teams

If we ship only an interface and let teams build the session store:
- They might forget `ExpiresAt` and sessions live forever.
- They might not index `SubjectID` and concurrent session checks become O(n) table scans.
- They might store session IDs in plain text instead of hashing them.
- They might not implement idle timeout, only absolute timeout.
- They might use client-side sessions (signed cookies) without understanding the revocation problem.
- They might miss session fixation prevention entirely.

By owning the session store adapters, we guarantee the schema is correct, timeouts work, session IDs are handled securely, and session fixation is prevented.

---

## 5. Identity Propagation — Cross-Service

When Service A calls Service B on behalf of a user, the user's identity must travel with the request. This is the hardest problem in multi-service authentication — if done wrong, any service can forge user identities.

### The Problem

A gRPC client interceptor forwards user identity from Service A to Service B. But:
- Who signs the identity claim?
- How does Service B verify it?
- Does this require shared infrastructure?

If the identity claim is unsigned, **any service can impersonate any user** by writing arbitrary metadata in gRPC calls.

### The Solution: `IdentityPropagator` Interface

We ship a **propagation strategy interface** with three built-in implementations. Teams pick based on their deployment topology.

```go
// IdentityPropagator controls how user identity travels between services.
// The library ships three implementations. Teams pick one (or build custom).
type IdentityPropagator interface {
    // Encode creates a portable identity claim from the current context.
    // Called by client interceptor before outbound gRPC call.
    Encode(ctx context.Context, identity Identity) (map[string]string, error)

    // Decode verifies and extracts identity from inbound gRPC metadata.
    // Called by server interceptor on incoming gRPC call.
    Decode(ctx context.Context, metadata map[string]string, peerIdentity *WorkloadIdentity) (Identity, error)
}
```

### Shipped Implementations

| Implementation | When to Use | Key Management | Verification | Revocation |
|---|---|---|---|---|
| **`SignedJWTPropagator`** (default) | Multi-cluster, multi-region, event-driven. No SPIFFE. Enterprise scale. | Library generates Ed25519 keypair. Public key served at `/.well-known/auth-keys` (JWKS format). Team configures trusted issuers. Auto-rotation with overlap period. | Standard JWT verification. 30-second expiry. Audience-restricted. | 30-second revocation gap (acceptable for most use cases). |
| **`SessionPropagator`** | Small deployments, shared infra, monolith-to-microservices migration. | None — uses existing session store. | Re-validates session ID against shared SessionStore. | Instant — delete session, all services lose access. |
| **`SPIFFEPropagator`** | Large enterprises with SPIFFE/SPIRE deployed. Highest security requirements. | Fully delegated to SPIRE. Zero key management by the library. | JWT-SVID verification via SPIFFE Workload API. Audience-restricted. | Depends on SVID TTL (typically minutes). |

### Decision Tree

```
Do your services share a session store (same Redis/Postgres)?
  ├── Yes → SessionPropagator (simplest, instant revocation)
  └── No
        ├── Do you have SPIFFE/SPIRE deployed?
        │     ├── Yes → SPIFFEPropagator (best-in-class zero-trust)
        │     └── No → SignedJWTPropagator (stateless, scales everywhere)
        └── Event-driven (Kafka, NATS)?
              └── SignedJWTPropagator (only stateless option works here)
```

**Default:** `SignedJWTPropagator` — it works everywhere, has no infrastructure assumptions, and key management is automated by the library. Teams that want simpler (shared session) or stronger (SPIFFE) can switch with one config line.

### SignedJWTPropagator — Key Details

The `SignedJWTPropagator` creates a **30-second internal assertion** (not an external-facing token) that carries user identity between services:

| Aspect | Detail |
|---|---|
| **Algorithm** | Ed25519 (EdDSA) |
| **TTL** | 30 seconds |
| **Claims** | `sub` (subject ID), `iss` (issuing service), `aud` (target service), `iat`, `exp`, `auth_method`, `auth_time` |
| **Key distribution** | Public key served at `/.well-known/auth-keys` in JWKS format. Verifying services configure trusted issuers. |
| **Key rotation** | Automatic. Overlap period = 2× JWT TTL (60 seconds). Old key accepted during overlap. |
| **Key bootstrapping** | Generated on first start. Persisted via session store infrastructure (or file / env var). |
| **Audience restriction** | Each JWT targets a specific service. Can't replay a JWT intended for Service B against Service C. |

> **On the "we don't issue tokens" principle:** The `SignedJWTPropagator` creates internal assertions that are infrastructure plumbing — the same way mTLS certs are infrastructure plumbing. These are not access tokens for team APIs. They are not exposed to end users. They have a 30-second lifespan and are audience-restricted. The principle "we don't issue tokens" means we don't issue tokens for team APIs or end users.

### Tradeoffs

| Concern | Detail |
|---|---|
| **Revocation gap** | A revoked session still has valid JWTs for up to 30 seconds (`SignedJWTPropagator`). For instant revocation requirements, use `SessionPropagator`. |
| **Clock skew** | Verify services must have reasonably synchronized clocks (NTP). The 30-second window accommodates typical skew. |
| **Custom propagation** | Teams can implement `IdentityPropagator` for anything we didn't anticipate (e.g., Vault transit engine, custom HSM signing). |

---

## 6. Password Policy

Password policy is a configurable struct, not an interface. We ship sane defaults based on [NIST 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) and the team overrides as needed.

### Default Policy (NIST 800-63B)

| Rule | Default | Rationale |
|---|---|---|
| **Min length** | 8 characters | NIST 800-63B minimum |
| **Max length** | 128 characters | Prevents denial-of-service via hash computation on extremely long inputs |
| **Breached password check** | Enabled | k-anonymity check against known breached password lists (e.g., HaveIBeenPwned API). Only the first 5 characters of the SHA-1 hash are sent — the full password never leaves the library. |
| **Composition rules** (uppercase, digit, special) | Disabled | NIST 800-63B explicitly discourages composition rules. They reduce usable password space and lead to predictable patterns ("Password1!"). |
| **Custom validator** | nil | Teams can add domain-specific rules (e.g., "password must not contain company name") via a `func(string) error`. |

### Configuration

```go
auth.WithPasswordPolicy(auth.PasswordPolicy{
    MinLength:       12,             // override default of 8
    MaxLength:       128,
    CheckBreached:   true,           // default
    RequireUppercase: false,         // NIST recommends against
    RequireLowercase: false,
    RequireDigit:     false,
    RequireSpecial:   false,
    CustomValidator: func(pw string) error {
        if strings.Contains(strings.ToLower(pw), "acme") {
            return errors.New("password must not contain company name")
        }
        return nil
    },
})
```

### When It's Enforced

- **Registration** — `Engine.Register()` validates the password before hashing.
- **Password change** — any password update validates the new password.
- **Never on login** — we don't reject a login because the existing password doesn't meet a new policy. Instead, teams can use the `AfterLogin` hook to prompt for a password change.

---

## 7. Interceptor Model

The Attestor integrates exclusively as interceptors. It never appears in business logic.

| Layer | What Happens | Who Writes It |
|---|---|---|
| **Protocol binding** (Attestor) | Extract credentials, dispatch to auth mode, verify, create/validate session, inject identity into ctx | Attestor |
| **Wiring** (`main.go`) | Configure auth, register middleware/interceptors, provide connection config for session store | Adopting team (5–20 lines) |
| **Business logic** (handlers) | Read identity from context | Adopting team (zero auth imports) |

### HTTP

```
Incoming HTTP Request
        │
        ▼
┌────────────────────────┐
│  Auth Middleware        │  ← Attestor
│  • Extract credential   │
│    from cookie/header   │
│  • Dispatch to mode     │
│  • Validate session     │
│  • Identity → ctx       │
└───────────┬─────────────┘
            │
            ▼
┌────────────────────────┐
│  YOUR HANDLER           │  ← Your code
│  identity :=            │
│    auth.GetIdentity(ctx)│
└─────────────────────────┘
```

### gRPC

```
Incoming gRPC Call
        │
        ▼
┌────────────────────────┐
│  Auth Interceptor       │  ← Attestor
│  • Extract creds from   │
│    metadata + TLS peer  │
│  • Dispatch to mode     │
│  • Validate session     │
│  • Identity → ctx       │
└───────────┬─────────────┘
            │
            ▼
┌────────────────────────┐
│  YOUR gRPC HANDLER      │  ← Your code
│  identity :=            │
│    auth.GetIdentity(ctx)│
└─────────────────────────┘
```

For **outgoing** gRPC calls, a client-side interceptor reads identity from context, delegates to `IdentityPropagator.Encode()`, and attaches the result to outgoing metadata automatically.

### System-to-System

```
Service Start / Job Start
        │
        ▼
┌──────────────────────────┐
│  Credential Exchange      │  ← Attestor
│  • mTLS cert / SPIFFE     │
│  • Produce Workload       │
│    Identity               │
└───────────┬───────────────┘
            │
            ▼
┌──────────────────────────┐
│  YOUR JOB LOGIC           │  ← Your code
│  • Identity in context    │
│  • Outbound calls auto-   │
│    attach via interceptor │
└───────────────────────────┘
```

---

## 8. Interface Contracts

What the library ships vs what the team provides. Solid arrows = required. Dotted arrows = optional.

```mermaid
flowchart LR
    subgraph lib ["Attestor Ships"]
        direction TB
        i1["UserStore interface"]
        i2["User interface"]
        i3["SessionStore interface"]
        i4["Hasher interface"]
        i5["Authorizer interface"]
        i6["Notifier interface"]
        i7["IdentifierConfig"]
        i8["APIKeyStore interface"]
        i9["IdentityPropagator interface"]
        i10["PasswordPolicy config"]
    end

    subgraph libImpl ["Attestor Also Ships"]
        direction TB
        a1["Redis SessionStore adapter"]
        a2["Postgres SessionStore adapter"]
        a3["Argon2id Hasher default"]
        a4["SignedJWTPropagator default"]
        a5["SessionPropagator"]
        a6["SPIFFEPropagator"]
        a7["NIST 800-63B password defaults"]
    end

    subgraph team ["Team Provides"]
        direction TB
        t1["UserStore implementation<br/>Any DB, any schema"]
        t2["User model wrapper<br/>Wraps team's user struct"]
        t3["Infra: Redis or Postgres<br/>Connection config only"]
        t4["Hasher — optional override"]
        t5["Authorizer implementation<br/>Casbin, OPA, custom"]
        t6["Notifier — optional<br/>Skip if not needed"]
        t7["Identifier field config<br/>email, username, phone, UUID"]
        t8["APIKeyStore implementation<br/>Key storage + metadata"]
        t9["Password policy overrides<br/>Optional — defaults are sane"]
    end

    i1 -- "team implements" --> t1
    i2 -- "team implements" --> t2
    i3 --> a1
    i3 --> a2
    i3 -. "or team implements" .-> t3
    i4 --> a3
    i4 -. "optional override" .-> t4
    i5 -- "team implements" --> t5
    i6 -. "optional" .-> t6
    i7 -- "team configures" --> t7
    i8 -- "team implements" --> t8
    i9 --> a4
    i9 --> a5
    i9 --> a6
    i10 --> a7
    i10 -. "optional override" .-> t9

    style lib fill:#dbeafe,stroke:#2563eb,color:#333
    style libImpl fill:#dbeafe,stroke:#2563eb,color:#333
    style team fill:#fef3c7,stroke:#d97706,color:#333
    style i1 fill:#fff,stroke:#2563eb,color:#333
    style i2 fill:#fff,stroke:#2563eb,color:#333
    style i3 fill:#fff,stroke:#2563eb,color:#333
    style i4 fill:#fff,stroke:#2563eb,color:#333
    style i5 fill:#fff,stroke:#2563eb,color:#333
    style i6 fill:#f3f4f6,stroke:#9ca3af,color:#666
    style i7 fill:#fff,stroke:#2563eb,color:#333
    style i8 fill:#fff,stroke:#2563eb,color:#333
    style i9 fill:#fff,stroke:#2563eb,color:#333
    style i10 fill:#fff,stroke:#2563eb,color:#333
    style a1 fill:#dbeafe,stroke:#2563eb,color:#333
    style a2 fill:#dbeafe,stroke:#2563eb,color:#333
    style a3 fill:#dbeafe,stroke:#2563eb,color:#333
    style a4 fill:#dbeafe,stroke:#2563eb,color:#333
    style a5 fill:#dbeafe,stroke:#2563eb,color:#333
    style a6 fill:#dbeafe,stroke:#2563eb,color:#333
    style a7 fill:#dbeafe,stroke:#2563eb,color:#333
    style t1 fill:#fef3c7,stroke:#d97706,color:#333
    style t2 fill:#fef3c7,stroke:#d97706,color:#333
    style t3 fill:#f3f4f6,stroke:#9ca3af,color:#666
    style t4 fill:#f3f4f6,stroke:#9ca3af,color:#666
    style t5 fill:#fef3c7,stroke:#d97706,color:#333
    style t6 fill:#f3f4f6,stroke:#9ca3af,color:#666
    style t7 fill:#fef3c7,stroke:#d97706,color:#333
    style t8 fill:#fef3c7,stroke:#d97706,color:#333
    style t9 fill:#f3f4f6,stroke:#9ca3af,color:#666
```

### Key Points

- **Interface count:** 8 interfaces total (UserStore, User, SessionStore, Hasher, Authorizer, Notifier, APIKeyStore, IdentityPropagator). Only 2 are required (UserStore, User). This is minimal for an enterprise auth library.
- **SessionStore**: unlike other interfaces, we ship two adapters (Redis, Postgres). The team provides the infrastructure, not the implementation. A custom adapter is the exception, not the norm.
- **APIKeyStore**: separate from UserStore. API keys have their own lifecycle (create, revoke, list) and metadata (scopes, expiry, last used). Shoehorning them into UserStore would pollute a clean interface.
- **IdentityPropagator**: three shipped implementations cover the full deployment spectrum. `SignedJWTPropagator` is the default. Custom implementations are possible for uncommon infrastructure.
- **PasswordPolicy**: a config struct, not an interface. NIST 800-63B defaults are sane; override only if you have domain-specific requirements.
- **Notifier**: grayed out because it's optional. Exception: if magic link mode is enabled, Notifier becomes required (validated at startup).
- **IdentifierConfig**: not an interface — it's configuration. The team tells us what field identifies a user.

---

## 9. C4 Level 4 — Code Diagrams (UML)

These diagrams zoom into the interfaces, structs, and their relationships at the code level. This is the C4 "Code" layer — UML class diagrams showing how interfaces connect to implementations.

### 9.1 Session Store — Interfaces and Adapters

The session subsystem is library-owned. We define the interface, the session struct, the config, and ship two adapters.

```mermaid
classDiagram
    direction TB

    namespace AuthLibrary {
        class SessionStore {
            <<interface>>
            +Create(ctx, session) error
            +Get(ctx, sessionID) Session, error
            +Update(ctx, session) error
            +Delete(ctx, sessionID) error
            +DeleteBySubject(ctx, subjectID) error
            +CountBySubject(ctx, subjectID) int, error
        }

        class SessionManager {
            -store SessionStore
            -config SessionConfig
            +CreateSession(ctx, subjectID) Session, error
            +ValidateSession(ctx, sessionID) Session, error
            +RefreshSession(ctx, sessionID) Session, error
            +DestroySession(ctx, sessionID) error
            +DestroyAllSessions(ctx, subjectID) error
        }

        class RedisSessionStore {
            -client redis.Client
            -prefix string
            -ttl time.Duration
            +Create(ctx, session) error
            +Get(ctx, sessionID) Session, error
            +Update(ctx, session) error
            +Delete(ctx, sessionID) error
            +DeleteBySubject(ctx, subjectID) error
            +CountBySubject(ctx, subjectID) int, error
        }

        class PostgresSessionStore {
            -db sql.DB
            -tableName string
            +Create(ctx, session) error
            +Get(ctx, sessionID) Session, error
            +Update(ctx, session) error
            +Delete(ctx, sessionID) error
            +DeleteBySubject(ctx, subjectID) error
            +CountBySubject(ctx, subjectID) int, error
        }

        class Session {
            +ID string
            +SubjectID string
            +CreatedAt time.Time
            +ExpiresAt time.Time
            +LastActiveAt time.Time
            +SchemaVersion int
            +Metadata map~string, any~
        }

        class SessionConfig {
            +IdleTimeout time.Duration
            +AbsoluteTimeout time.Duration
            +MaxConcurrent int
            +CookieName string
            +CookieDomain string
            +CookieSecure bool
            +CookieSameSite string
        }
    }

    SessionManager --> SessionStore : uses
    SessionManager --> Session : manages
    SessionManager --> SessionConfig : configured by
    RedisSessionStore ..|> SessionStore : implements
    PostgresSessionStore ..|> SessionStore : implements

    note for SessionStore "Team can implement this interface\nfor a custom session store\nif Redis/Postgres don't fit"
    note for SessionManager "Invariant: CreateSession always\ndestroys existing session first\n(session fixation prevention)"
    note for Session "SchemaVersion checked on startup.\nMismatch = fail with migration link."
```

**Reading this diagram:**
- `SessionStore` is the `<<interface>>`. We ship two implementations: `RedisSessionStore` and `PostgresSessionStore`.
- `SessionManager` is the orchestrator — it uses the store, enforces timeouts, manages concurrent sessions, and prevents session fixation.
- The dotted arrow (`..|>`) means "implements". Both adapters implement the `SessionStore` interface.
- The solid arrow (`-->`) means "uses" or "depends on".
- `Session.SchemaVersion` enables safe migrations — the library checks this on startup and fails clearly if outdated.
- Teams can add a third implementation if Redis/Postgres don't fit.

---

### 9.2 User Store, Authorizer, Notifier, Hasher — Interfaces and Types

These are the interfaces the team implements. We define the contracts; they fill in the logic.

```mermaid
classDiagram
    direction TB

    namespace AuthLibrary {
        class UserStore {
            <<interface>>
            +FindByIdentifier(ctx, identifier) User, error
            +Create(ctx, user) error
            +UpdatePassword(ctx, subjectID, hash) error
            +IncrementFailedAttempts(ctx, subjectID) error
            +ResetFailedAttempts(ctx, subjectID) error
            +SetLocked(ctx, subjectID, locked) error
        }

        class User {
            <<interface>>
            +GetSubjectID() string
            +GetIdentifier() string
            +GetPasswordHash() string
            +GetFailedAttempts() int
            +IsLocked() bool
            +IsMFAEnabled() bool
            +GetMetadata() map~string, any~
        }

        class IdentifierConfig {
            +Field string
            +CaseSensitive bool
            +Normalize func~string~ string
        }

        class Authorizer {
            <<interface>>
            +CanAccess(ctx, subject, action, resource) bool, error
        }

        class Notifier {
            <<interface>>
            +Notify(ctx, event, payload) error
        }

        class Hasher {
            <<interface>>
            +Hash(password) string, error
            +Verify(password, hash) bool, error
        }

        class Argon2idHasher {
            -timeCost uint32
            -memoryCost uint32
            -parallelism uint8
            +Hash(password) string, error
            +Verify(password, hash) bool, error
        }

        class AuthEvent {
            <<enumeration>>
            EventRegistration
            EventLogin
            EventLoginFailed
            EventLogout
            EventPasswordReset
            EventMagicLinkSent
            EventAccountLocked
        }

        class Identity {
            +SubjectID string
            +AuthMethod string
            +AuthTime time.Time
            +SessionID string
            +WorkloadID string
            +TrustDomain string
            +Metadata map~string, any~
        }
    }

    Argon2idHasher ..|> Hasher : implements
    Notifier --> AuthEvent : receives

    note for UserStore "Team implements this for\ntheir user schema and database"
    note for User "Team implements this interface\nto wrap their own user model"
    note for Authorizer "Team implements with\nCasbin, OPA, Cedar, or custom"
    note for Notifier "Optional: team implements\nonly if notifications needed"
```

**Key design decisions:**
- `User` is an **interface**, not a struct. The team wraps their own user model to satisfy it. We never dictate the user schema.
- `IdentifierConfig` is a struct with a `Normalize` function — e.g., lowercase for emails, trim for usernames.
- `Argon2idHasher` is the default `Hasher` we ship. Teams override only for legacy password schemes.
- `AuthEvent` is an enumeration. The `Notifier` receives these events. The `HookManager` also emits them.
- `Identity` is what goes into `context.Context`. It has no hardcoded `Email` or `Roles` — those go in `Metadata`.

---

### 9.3 API Key Store and Password Policy

API keys are a first-class concept, separate from user records. Password policy is a configurable struct with NIST 800-63B defaults.

```mermaid
classDiagram
    direction TB

    namespace AuthLibrary {
        class APIKeyStore {
            <<interface>>
            +FindByKey(ctx, key) APIKey, error
            +Create(ctx, apiKey) error
            +Revoke(ctx, keyID) error
            +ListBySubject(ctx, subjectID) list~APIKey~, error
            +UpdateLastUsed(ctx, keyID) error
        }

        class APIKey {
            +ID string
            +SubjectID string
            +KeyHash string
            +Name string
            +Scopes list~string~
            +CreatedAt time.Time
            +ExpiresAt time.Time
            +LastUsedAt time.Time
            +Revoked bool
        }

        class PasswordPolicy {
            +MinLength int
            +MaxLength int
            +RequireUppercase bool
            +RequireLowercase bool
            +RequireDigit bool
            +RequireSpecial bool
            +CheckBreached bool
            +CustomValidator func~string~ error
        }
    }

    APIKeyStore --> APIKey : manages

    note for APIKeyStore "Team implements this interface.\nSeparate from UserStore —\nAPI keys are a first-class concept."
    note for PasswordPolicy "Configurable struct, not an interface.\nNIST 800-63B defaults:\nMinLength=8, CheckBreached=true,\nno composition rules."
```

**Key design decisions:**
- `APIKeyStore` is separate from `UserStore`. API keys have their own lifecycle (create, revoke, list) and metadata (scopes, expiry, last used). A user may have multiple API keys. Shoehorning this into `UserStore` would pollute a clean interface.
- `APIKey.KeyHash` — we store hashes, not raw keys. The raw key is returned only on creation.
- `PasswordPolicy` is a struct, not an interface. It's configuration, not behavior. Teams override fields; they don't need to implement methods.
- **NIST 800-63B defaults** means no composition rules by default. The `RequireUppercase`, `RequireDigit`, etc. fields exist for teams with legacy compliance requirements, but they are `false` by default because NIST explicitly discourages them.

---

### 9.4 Identity Propagator — Interfaces and Implementations

The `IdentityPropagator` interface controls how user identity travels between services. Three implementations cover the full deployment spectrum.

```mermaid
classDiagram
    direction TB

    namespace IdentityPropagation {
        class IdentityPropagator {
            <<interface>>
            +Encode(ctx, identity) map~string string~, error
            +Decode(ctx, metadata, peerIdentity) Identity, error
        }

        class SessionPropagator {
            -sessionStore SessionStore
            +Encode(ctx, identity) map~string string~, error
            +Decode(ctx, metadata, peerIdentity) Identity, error
        }

        class SignedJWTPropagator {
            -signingKey ed25519.PrivateKey
            -verifyKeys JWKSKeySet
            -issuer string
            -audience string
            -ttl time.Duration
            +Encode(ctx, identity) map~string string~, error
            +Decode(ctx, metadata, peerIdentity) Identity, error
            +JWKSHandler() http.Handler
        }

        class SPIFFEPropagator {
            -workloadAPI workloadapi.Client
            -audience string
            +Encode(ctx, identity) map~string string~, error
            +Decode(ctx, metadata, peerIdentity) Identity, error
        }

        class PropagatorConfig {
            +Strategy string
            +JWTIssuer string
            +JWTAudience string
            +JWTTTL time.Duration
            +JWKSEndpoint string
            +SPIFFESocketPath string
            +TrustedIssuers list~string~
        }
    }

    SessionPropagator ..|> IdentityPropagator : implements
    SignedJWTPropagator ..|> IdentityPropagator : implements
    SPIFFEPropagator ..|> IdentityPropagator : implements
    SignedJWTPropagator --> PropagatorConfig : configured by

    note for IdentityPropagator "Controls how user identity travels\nbetween services. Library ships three\nimplementations. Teams pick one\nor build custom."
    note for SignedJWTPropagator "DEFAULT. 30-second Ed25519 JWT.\nStateless. No shared infra.\nExposes JWKS endpoint for\nverifier key distribution."
    note for SessionPropagator "Simplest. Re-validates session\nagainst shared store.\nBest for small deployments."
    note for SPIFFEPropagator "Best-in-class zero-trust.\nDelegates to SPIRE Workload API.\nFor enterprises with SPIFFE deployed."
```

**Key design decisions:**
- `IdentityPropagator` has only two methods (`Encode` / `Decode`). Minimal surface. Easy to implement custom propagators.
- `SignedJWTPropagator` exposes `JWKSHandler()` — an HTTP handler that serves the public verification key in JWKS format. Verifying services add this to their trusted issuers config.
- `SPIFFEPropagator` never touches keys directly. All signing and verification is delegated to the SPIRE Workload API. The library is just a consumer.
- `Decode` receives `peerIdentity *WorkloadIdentity` — the mTLS peer identity is always available alongside the propagated user identity.

---

### 9.5 Auth Engine, Modes, and Protocol Bindings

The engine dispatches to auth modes. Protocol bindings are thin adapters that extract credentials and feed them to the engine.

```mermaid
classDiagram
    direction TB

    namespace AuthEngine {
        class Engine {
            -userStore UserStore
            -apiKeyStore APIKeyStore
            -sessionMgr SessionManager
            -propagator IdentityPropagator
            -hasher Hasher
            -hookMgr HookManager
            -notifier Notifier
            -modes map~string, AuthMode~
            -identifierCfg IdentifierConfig
            -passwordPolicy PasswordPolicy
            +Register(ctx, credentials) error
            +Login(ctx, credentials) Session, Identity, error
            +Logout(ctx, sessionID) error
            +Verify(ctx, credential) Identity, error
            +Close() error
        }

        class AuthMode {
            <<interface>>
            +Name() string
            +Authenticate(ctx, credential) Identity, error
            +Supports(credentialType) bool
        }

        class PasswordMode {
            -userStore UserStore
            -hasher Hasher
            -policy PasswordPolicy
            +Name() string
            +Authenticate(ctx, credential) Identity, error
            +Supports(credentialType) bool
        }

        class OAuthMode {
            -providers map~string, OAuthProvider~
            +Name() string
            +Authenticate(ctx, credential) Identity, error
            +Supports(credentialType) bool
        }

        class MagicLinkMode {
            -userStore UserStore
            -notifier Notifier
            -sessionStore SessionStore
            +Name() string
            +Authenticate(ctx, credential) Identity, error
            +Supports(credentialType) bool
        }

        class APIKeyMode {
            -apiKeyStore APIKeyStore
            +Name() string
            +Authenticate(ctx, credential) Identity, error
            +Supports(credentialType) bool
        }

        class MTLSMode {
            -trustAnchors x509.CertPool
            +Name() string
            +Authenticate(ctx, credential) Identity, error
            +Supports(credentialType) bool
        }

        class HookManager {
            -hooks map~AuthEvent, list~HookFn~~
            +Register(event, fn)
            +Emit(ctx, event, payload) error
        }

        class HTTPMiddleware {
            -engine Engine
            +RequireAuth() Middleware
            +OptionalAuth() Middleware
        }

        class GRPCInterceptor {
            -engine Engine
            -propagator IdentityPropagator
            +UnaryServerInterceptor() grpc.UnaryServerInterceptor
            +StreamServerInterceptor() grpc.StreamServerInterceptor
            +UnaryClientInterceptor() grpc.UnaryClientInterceptor
            +StreamClientInterceptor() grpc.StreamClientInterceptor
        }
    }

    Engine --> AuthMode : dispatches to
    Engine --> HookManager : emits events
    Engine --> IdentityPropagator : propagates via
    PasswordMode ..|> AuthMode : implements
    OAuthMode ..|> AuthMode : implements
    MagicLinkMode ..|> AuthMode : implements
    APIKeyMode ..|> AuthMode : implements
    MTLSMode ..|> AuthMode : implements

    HTTPMiddleware --> Engine : uses
    GRPCInterceptor --> Engine : uses
```

**Key patterns:**
- `AuthMode` is the **strategy pattern**. Each mode implements the same interface. The engine dispatches based on `Supports(credentialType)`.
- `APIKeyMode` depends on `APIKeyStore` (not `UserStore`). API keys are a separate domain.
- `MagicLinkMode` depends on `Notifier` — this is why Notifier becomes required when magic link mode is enabled.
- `MagicLinkMode` depends on `MagicLinkStore` — magic link tokens are stored using the same session store infrastructure. An optional `MagicLinkStore` interface is exposed for custom storage.
- `PasswordMode` holds a `PasswordPolicy` reference — validates passwords on registration and change.
- `Engine` holds an `IdentityPropagator` — used by `GRPCInterceptor` for cross-service identity propagation.
- `HTTPMiddleware` and `GRPCInterceptor` are thin wrappers around `Engine`. They extract credentials from protocol-specific locations and feed them into `Engine.Verify()`.
- `HookManager` lets teams register callbacks for lifecycle events without modifying any auth code.

---

## 10. Sequence Diagrams

### 10.1 HTTP Request — Session Validation

The most common flow. Session cookie → validate session via library-owned session store → identity in context → business logic.

```mermaid
sequenceDiagram
    autonumber
    participant U as End User
    participant HB as HTTP Middleware
    participant AE as Auth Engine
    participant SM as Session Manager
    participant SS as Session Store (Library)
    participant US as User Store (Team)
    participant BL as Business Logic (Your Code)
    participant AZ as Authorizer (Team)

    U->>HB: POST /api/orders (session cookie)
    activate HB
    HB->>AE: Verify(ctx, sessionCookie)
    activate AE
    AE->>SM: ValidateSession(ctx, sessionID)
    SM->>SS: Get(ctx, sessionID)
    SS-->>SM: Session{SubjectID, ExpiresAt, LastActiveAt}
    SM->>SM: Check idle + absolute timeout
    SM->>SS: Update(ctx, session) — refresh LastActiveAt
    SM-->>AE: Session valid
    AE->>US: FindByIdentifier(ctx, subjectID)
    Note right of US: subjectID uses whatever<br/>identifier the team configured
    US-->>AE: User{identifier, attributes}
    AE-->>HB: Identity{subject, authMethod, authTime, sessionID}
    deactivate AE
    HB->>BL: next.ServeHTTP(w, r.WithContext(ctx))
    deactivate HB
    activate BL

    Note over BL: Your handler reads identity from ctx.<br/>No Attestor imports needed.

    BL->>AZ: CanAccess(ctx, subject, "create", "order")
    activate AZ
    AZ-->>BL: allowed / denied
    deactivate AZ

    alt Allowed
        BL-->>U: 201 Created
    else Denied
        BL-->>U: 403 Forbidden
    end
    deactivate BL
```

---

### 10.2 Password Login — With Security Protections

Shows the Password auth mode dispatching, constant-time dummy hash, account lockout, session fixation prevention, and session creation via library-owned session store.

```mermaid
sequenceDiagram
    autonumber
    participant U as End User
    participant HB as HTTP Middleware
    participant AE as Auth Engine
    participant PM as Password Mode
    participant US as User Store (Team)
    participant HP as Hasher
    participant SM as Session Manager
    participant SS as Session Store (Library)
    participant HK as Hooks

    U->>HB: POST /auth/login {identifier, password}
    activate HB
    HB->>AE: Login(ctx, credentials)
    activate AE

    AE->>HK: BeforeLogin(ctx, identifier)
    HK-->>AE: ok

    AE->>PM: Authenticate(ctx, credential)
    activate PM
    PM->>US: FindByIdentifier(ctx, identifier)

    alt User not found
        US-->>PM: nil
        PM->>HP: Hash(dummy) — constant time
        Note right of HP: Prevents user enumeration<br/>via timing side-channel
        PM-->>AE: ErrInvalidCredentials
        AE-->>HB: ErrInvalidCredentials
        HB-->>U: 401 Invalid credentials
    else User found but locked
        US-->>PM: User{locked: true}
        PM-->>AE: ErrAccountLocked
        AE-->>HB: ErrAccountLocked
        HB-->>U: 401 Invalid credentials
        Note right of HB: Same generic error<br/>prevents enumeration
    else User found — verify password
        US-->>PM: User{passwordHash, locked: false}
        PM->>HP: Verify(password, passwordHash)
        alt Wrong password
            HP-->>PM: false
            PM->>US: IncrementFailedAttempts(ctx, subjectID)
            PM-->>AE: ErrInvalidCredentials
            AE->>HK: AfterFailedLogin(ctx, identifier)
            AE-->>HB: ErrInvalidCredentials
            HB-->>U: 401 Invalid credentials
        else Correct password
            HP-->>PM: true
            PM->>US: ResetFailedAttempts(ctx, subjectID)
            PM-->>AE: Identity
        end
    end
    deactivate PM

    opt Login successful
        AE->>SM: CreateSession(ctx, subjectID)
        Note right of SM: Session fixation prevention:<br/>destroys any existing session<br/>before creating new one
        SM->>SS: Delete(ctx, existingSessionID)
        SM->>SS: Create(ctx, newSession)
        SS-->>SM: ok
        SM-->>AE: Session
        AE->>HK: AfterLogin(ctx, user, session)
        AE-->>HB: Session + Identity
        HB-->>U: 200 OK + Set-Cookie
    end

    deactivate AE
    deactivate HB
```

**Security protections (that ARE our concern):**
- Constant-time dummy hash when user doesn't exist (timing attack prevention)
- Generic error messages for all failure paths (user enumeration prevention)
- Account lockout after N failed attempts (brute-force protection at the auth level)
- Session fixation prevention — old session destroyed, new session ID generated

**What is NOT our concern:**
- Rate limiting — infrastructure layer (API gateway, reverse proxy)

---

### 10.3 OAuth2 / OIDC Login — With Auto-Registration

Shows the full OAuth flow with PKCE. Key feature: **auto-registration on first login** for seamless user onboarding.

```mermaid
sequenceDiagram
    autonumber
    participant U as End User
    participant HB as HTTP Middleware
    participant AE as Auth Engine
    participant OM as OAuth Mode
    participant IdP as Identity Provider
    participant US as User Store (Team)
    participant SM as Session Manager
    participant SS as Session Store (Library)
    participant HK as Hooks

    U->>HB: GET /auth/oauth/google
    activate HB
    HB->>AE: InitiateOAuth(ctx, "google")
    activate AE
    AE->>OM: BuildAuthURL("google", state, nonce, pkceChallenge)
    Note right of OM: PKCE: generate code_verifier,<br/>derive code_challenge (S256).<br/>Mandatory for all OAuth flows.
    OM-->>AE: redirect URL + state cookie + PKCE verifier
    AE-->>HB: redirect URL + state cookie
    deactivate AE
    HB-->>U: 302 Redirect to Google
    deactivate HB

    Note over U,IdP: User authenticates with Google

    U->>HB: GET /auth/oauth/google/callback?code=xxx&state=yyy
    activate HB
    HB->>AE: HandleOAuthCallback(ctx, code, state)
    activate AE
    AE->>OM: Authenticate(ctx, code)
    activate OM
    OM->>IdP: Exchange code for tokens (+ code_verifier for PKCE)
    IdP-->>OM: id_token + access_token
    OM->>OM: Verify id_token signature, nonce, claims
    OM-->>AE: Identity{subjectID, provider: google}
    deactivate OM

    AE->>US: FindByIdentifier(ctx, googleSubjectID)
    alt New user
        US-->>AE: nil
        AE->>US: Create(ctx, user)
        US-->>AE: ok
        AE->>HK: AfterRegister(ctx, user)
        Note over AE: Auto-registration on first OAuth login<br/>— seamless onboarding
    else Existing user
        US-->>AE: User
    end

    AE->>SM: CreateSession(ctx, subjectID)
    Note right of SM: Session fixation prevention:<br/>destroys any pre-auth session
    SM->>SS: Create(ctx, session)
    SS-->>SM: ok
    SM-->>AE: Session
    AE->>HK: AfterLogin(ctx, user, session)
    AE-->>HB: Session + Identity
    deactivate AE
    HB-->>U: 302 Redirect to app + Set-Cookie
    deactivate HB
```

**Onboarding:** First-time OAuth users are automatically registered. No separate registration step. The `AfterRegister` hook fires so teams can run onboarding logic (create default settings, send welcome notification via Notifier, etc.).

---

### 10.4 Magic Link — Passwordless Login

Shows the magic link flow. The `Notifier` is **required** for this mode — validated at startup. Magic link tokens are stored using the session store infrastructure.

```mermaid
sequenceDiagram
    autonumber
    participant U as End User
    participant HB as HTTP Middleware
    participant AE as Auth Engine
    participant ML as Magic Link Mode
    participant US as User Store (Team)
    participant SM as Session Manager
    participant SS as Session Store (Library)
    participant NF as Notifier (Required for Magic Link)
    participant HK as Hooks

    U->>HB: POST /auth/magic-link {identifier}
    activate HB
    HB->>AE: InitiateMagicLink(ctx, identifier)
    activate AE
    AE->>US: FindByIdentifier(ctx, identifier)
    US-->>AE: User exists

    AE->>ML: GenerateToken(ctx, subjectID)
    ML->>SS: Create(ctx, magicLinkToken)
    Note right of SS: Stored in same infra as sessions<br/>Separate key prefix: magiclink:<br/>Short TTL, single-use
    SS-->>ML: ok
    ML-->>AE: one-time token (short TTL)

    AE->>NF: Notify(ctx, EventMagicLinkSent, token + identifier)
    Note right of NF: Notifier is REQUIRED when<br/>magic link mode is enabled.<br/>Library validates this at startup.
    NF-->>AE: ok

    AE-->>HB: accepted
    deactivate AE
    HB-->>U: 202 Accepted — check your inbox
    deactivate HB

    Note over U: User clicks magic link in email/SMS

    U->>HB: GET /auth/magic-link/verify?token=xxx
    activate HB
    HB->>AE: VerifyMagicLink(ctx, token)
    activate AE
    AE->>ML: Authenticate(ctx, token)
    activate ML
    ML->>SS: Get(ctx, tokenID)
    ML->>ML: Verify token not expired, not used
    ML->>SS: Delete(ctx, tokenID)
    Note right of SS: Single-use: delete after verification
    ML-->>AE: Identity{subjectID}
    deactivate ML

    AE->>SM: CreateSession(ctx, subjectID)
    SM->>SS: Create(ctx, session)
    SS-->>SM: ok
    SM-->>AE: Session
    AE->>HK: AfterLogin(ctx, user, session)
    AE-->>HB: Session + Identity
    deactivate AE
    HB-->>U: 302 Redirect to app + Set-Cookie
    deactivate HB
```

---

### 10.5 User Registration — With Onboarding

Registration creates the user AND immediately creates a session — the user is logged in from the moment they register. No redirect to a login page. Password is validated against the configured `PasswordPolicy`.

```mermaid
sequenceDiagram
    autonumber
    participant U as End User
    participant HB as HTTP Middleware
    participant AE as Auth Engine
    participant PM as Password Mode
    participant US as User Store (Team)
    participant HP as Hasher
    participant SM as Session Manager
    participant SS as Session Store (Library)
    participant HK as Hooks
    participant NF as Notifier (Optional)

    U->>HB: POST /auth/register {identifier, password}
    activate HB
    HB->>AE: Register(ctx, credentials)
    activate AE

    AE->>HK: BeforeRegister(ctx, credentials)
    HK-->>AE: ok or abort

    AE->>AE: Validate password against PasswordPolicy
    Note right of AE: NIST 800-63B defaults:<br/>min 8 chars, breached check,<br/>no composition rules.<br/>Team can override.
    AE->>US: FindByIdentifier(ctx, identifier)
    Note right of US: Identifier is whatever the team<br/>configured: email, username, phone
    US-->>AE: nil — does not exist

    AE->>HP: Hash(password)
    HP-->>AE: argon2id hash

    AE->>US: Create(ctx, user)
    US-->>AE: ok

    AE->>SM: CreateSession(ctx, subjectID)
    SM->>SS: Create(ctx, session)
    SS-->>SM: ok
    SM-->>AE: Session

    Note over AE: User is registered AND<br/>logged in — seamless onboarding

    AE->>HK: AfterRegister(ctx, user, session)

    opt Notifier configured
        AE->>NF: Notify(ctx, EventRegistration, payload)
        NF-->>AE: ok
    end

    AE-->>HB: Session + Identity
    deactivate AE
    HB-->>U: 201 Created + Set-Cookie
    deactivate HB
```

**Onboarding experience:**
- User registers → password validated → session is created immediately → user is logged in.
- No "please check your email and then login" friction.
- `AfterRegister` hook fires with the session — teams can run onboarding logic (create default workspace, preferences, etc.).
- If Notifier is configured, a welcome notification is sent. If not, silently skipped.

---

### 10.6 Cross-Protocol — HTTP to gRPC Identity Propagation

Identity propagates automatically when an HTTP handler makes a gRPC call to a downstream service. The `IdentityPropagator` controls how identity is encoded and verified.

```mermaid
sequenceDiagram
    autonumber
    participant U as End User
    participant HB as HTTP Middleware (Gateway)
    participant AE1 as Auth Engine (Gateway)
    participant SM as Session Manager
    participant GCI as gRPC Client Interceptor
    participant IP as IdentityPropagator
    participant GSI as gRPC Server Interceptor
    participant AE2 as Auth Engine (Order Svc)
    participant BL as Order Service Handler

    U->>HB: POST /api/orders (session cookie)
    activate HB
    HB->>AE1: Verify session
    AE1->>SM: ValidateSession(ctx, sessionID)
    SM-->>AE1: Session valid
    AE1-->>HB: Identity{user: alice, workload: api-gw}
    HB->>GCI: Call OrderService.Create(ctx)
    deactivate HB
    activate GCI

    Note over GCI,IP: Client interceptor reads identity from ctx<br/>and delegates to IdentityPropagator.Encode()

    GCI->>IP: Encode(ctx, identity)
    activate IP

    alt SignedJWTPropagator (default)
        IP->>IP: Sign 30s Ed25519 JWT<br/>(sub=alice, aud=order-svc, exp=30s)
        IP-->>GCI: metadata: x-identity-jwt=ey...
    else SessionPropagator
        IP-->>GCI: metadata: x-session-id=sid_xxx
    else SPIFFEPropagator
        IP->>IP: RequestJWTSVID from SPIRE agent
        IP-->>GCI: metadata: x-identity-svid=ey...
    end
    deactivate IP

    GCI->>GSI: gRPC call + mTLS + metadata
    deactivate GCI
    activate GSI
    GSI->>AE2: Verify workload identity (mTLS cert)
    AE2-->>GSI: WorkloadIdentity{api-gateway}
    GSI->>IP: Decode(ctx, metadata, peerIdentity)
    activate IP
    IP->>IP: Verify signature or session
    IP-->>GSI: UserIdentity{alice}
    deactivate IP

    Note over GSI: Both user and workload<br/>identity verified and<br/>injected into ctx

    GSI->>BL: handler(ctx) — dual identity in context
    deactivate GSI
    activate BL
    BL-->>U: 201 Created (propagated back)
    deactivate BL
```

**Key points:**
- The `IdentityPropagator` is pluggable. The sequence diagram shows all three implementations in an `alt` block.
- **`SignedJWTPropagator` (default):** Creates a 30-second Ed25519 JWT. Stateless verification. Works across clusters, regions, and event-driven architectures.
- **`SessionPropagator`:** Forwards the session ID. Service B re-validates against the shared session store. Simplest, but requires shared infrastructure.
- **`SPIFFEPropagator`:** Requests a JWT-SVID from the local SPIRE agent. Best-in-class zero-trust, but requires SPIFFE/SPIRE infrastructure.
- Zero developer code. The client interceptor calls `Encode()` automatically; the server interceptor calls `Decode()` automatically.

---

### 10.7 System-to-System — Machine Identity Only

A cron job or background worker authenticating as a workload. No user involved.

```mermaid
sequenceDiagram
    autonumber
    participant CJ as Cron Job / Worker
    participant AE1 as Auth Engine (Local)
    participant MM as mTLS Mode
    participant GCI as gRPC Client Interceptor
    participant GSI as gRPC Server Interceptor
    participant AE2 as Auth Engine (Target Svc)
    participant BL as Target Service Handler

    Note over CJ: No user. Machine identity only.

    CJ->>AE1: Verify(ctx, mTLS cert / SPIFFE SVID)
    activate AE1
    AE1->>MM: Authenticate(ctx, cert)
    MM-->>AE1: WorkloadIdentity{cron-job, trust-domain}
    AE1-->>CJ: Identity in ctx
    deactivate AE1

    CJ->>GCI: Call ReportService.Generate(ctx)
    activate GCI
    Note over GCI: Attaches workload identity<br/>to outgoing gRPC metadata<br/>mTLS provides channel identity
    GCI->>GSI: gRPC + mTLS + metadata[workload-identity]
    deactivate GCI
    activate GSI
    GSI->>AE2: Verify mTLS peer cert
    AE2-->>GSI: WorkloadIdentity{cron-job}
    GSI->>AE2: Is cron-job in trust policy?
    AE2-->>GSI: Allowed
    GSI->>BL: ctx with WorkloadIdentity only, no UserIdentity
    deactivate GSI
    activate BL
    BL-->>CJ: Report generated
    deactivate BL
```

---

## 11. Identity Context

### 11.1 What It Contains

The `Identity` struct in `context.Context` is the only contract between the Attestor and your code:

| Field | Type | Description |
|---|---|---|
| **SubjectID** | `string` | The user identifier (whatever the team configured). Empty for system-to-system. |
| **AuthMethod** | `string` | How identity was established: `"password"`, `"oauth2"`, `"magic_link"`, `"api_key"`, `"mtls"`, `"spiffe"` |
| **AuthTime** | `time.Time` | When authentication occurred |
| **SessionID** | `string` | Current session ID. Empty for stateless/S2S auth. |
| **WorkloadID** | `string` | SPIFFE ID or service name. Empty for direct user requests. |
| **TrustDomain** | `string` | Workload trust domain (e.g., `acme.com`) |
| **Metadata** | `map[string]any` | Extensible. Teams attach custom claims via hooks. |

**Note:** No hardcoded `Email`, `Roles`, or `Name`. SubjectID is whatever the team configured. Additional attributes go in `Metadata`.

### 11.2 Accessing It

```
identity := auth.GetIdentity(ctx)
```

Returns the identity or nil for unauthenticated requests. This is the **only** import your code needs.

### 11.3 Dual Identity

When Service A calls Service B on behalf of User X, context carries both:

| Identity | Source |
|---|---|
| **User Identity** | Propagated via `IdentityPropagator` from the original request |
| **Workload Identity** | mTLS peer certificate of the calling service |

This is necessary for zero-trust: a gRPC request in production carries both "who is the human" and "which service is calling". Without this, you can't do proper audit or authorization.

---

## 12. Integration Summary

### What the Team Provides

| Requirement | Effort |
|---|---|
| `UserStore` implementation | Implement 6 methods for your user model |
| `User` interface wrapper | Wrap your user struct (7 getter methods) |
| `IdentifierConfig` | One config value: what field is the user identifier |
| Redis or Postgres connection | Connection string for session store |
| `APIKeyStore` implementation | 4 methods — only if API key mode is used |
| `Authorizer` implementation | 10–30 lines wrapping your policy engine (if AuthZ needed) |
| `Notifier` implementation | Only if you want auth event notifications (or use magic link) |

### What the Team Writes in Business Logic

Nothing from the Attestor. Just:

```
identity := auth.GetIdentity(ctx)
```

Zero other auth imports. No session validation. No credential extraction. No password hashing. The interceptors handled everything before your code runs.

---

## 13. Design Rationale

Key architectural decisions and why they are correct. This section captures the reasoning behind non-obvious choices to prevent future re-litigation.

### Protocol-Level OIDC, Not Provider SDKs

We depend on `/.well-known/openid-configuration` and JWKS — the OIDC spec. Zero provider-specific code. Okta, Entra ID, PingOne, Keycloak, Auth0, ForgeRock, Cognito — they all implement this. If a new IdP appears tomorrow, it works if it's OIDC-compliant. This is the right abstraction.

### Library as Interceptor, Not Framework

Middleware/interceptor pattern means zero coupling to business logic. Teams import one function (`auth.GetIdentity(ctx)`). No framework lock-in. Can be removed in a day.

### Identity Normalization via `context.Context`

All auth modes produce the same `Identity`. Business logic is completely decoupled from how authentication happened. This is fundamental and correct.

### `UserStore` as Interface, Not Schema

We never dictate user schema. We never own migrations for user tables. The interface is minimal (6 methods). Teams keep full ownership of their data model.

### Hooks Instead of Inheritance

`HookManager` with typed callbacks avoids the template method antipattern. Teams add behavior without subclassing. Composable and testable.

### Interface Count Is Minimal

8 interfaces total (UserStore, User, SessionStore, Hasher, Authorizer, Notifier, APIKeyStore, IdentityPropagator). Only 2 are required (UserStore, User). The rest have defaults, shipped implementations, or are optional. This is minimal for an enterprise auth library.

### Redis/Postgres Only for Session Adapters

Two adapters cover >90% of deployments. The `SessionStore` interface exists for the rest. We're not a database driver library.

### No Rate Limiting

Rate limiting is an infrastructure concern. Mixing it into an auth library creates configuration conflicts with API gateways. Correct scope exclusion.

### Internal Assertions ≠ Token Issuance

The `SignedJWTPropagator` creates 30-second internal assertions for cross-service identity propagation. These are infrastructure plumbing — not access tokens for team APIs or end users. The principle "we don't issue tokens" applies to external-facing tokens.

### No SAML

SAML is a legacy protocol. Every enterprise IdP that speaks SAML also speaks OIDC. Supporting SAML would triple our protocol surface for <5% of use cases. For the rare SAML-only case, a SAML-to-OIDC bridge (Dex, Keycloak) is the correct approach.

---

*Architecture v1.0 — 2026-02-17*
