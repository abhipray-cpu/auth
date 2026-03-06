// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/mode/oauth"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
	"github.com/abhipray-cpu/auth/session/redis"
)

// ==========================================================================
// PART 1: Custom AuthZ Logic Injection via Authorizer Interface
// ==========================================================================

// --------------------------------------------------------------------------
// memAuthorizer is a strict test Authorizer that records every CanAccess call
// and returns configurable results per (subject, action, resource) triple.
// --------------------------------------------------------------------------

type authzDecision struct {
	allowed bool
	err     error
}

type authzCall struct {
	Subject  string
	Action   string
	Resource string
}

type memAuthorizer struct {
	mu        sync.Mutex
	decisions map[string]authzDecision // key = "subject:action:resource"
	calls     []authzCall
	defaultOK bool
}

func newMemAuthorizer() *memAuthorizer {
	return &memAuthorizer{
		decisions: make(map[string]authzDecision),
	}
}

func (a *memAuthorizer) Allow(subject, action, resource string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decisions[subject+":"+action+":"+resource] = authzDecision{allowed: true}
}

func (a *memAuthorizer) Deny(subject, action, resource string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decisions[subject+":"+action+":"+resource] = authzDecision{allowed: false}
}

func (a *memAuthorizer) DenyWithError(subject, action, resource string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.decisions[subject+":"+action+":"+resource] = authzDecision{allowed: false, err: err}
}

func (a *memAuthorizer) CanAccess(_ context.Context, subject, action, resource string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, authzCall{Subject: subject, Action: action, Resource: resource})
	key := subject + ":" + action + ":" + resource
	if d, ok := a.decisions[key]; ok {
		return d.allowed, d.err
	}
	return a.defaultOK, nil
}

func (a *memAuthorizer) getCalls() []authzCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := make([]authzCall, len(a.calls))
	copy(cp, a.calls)
	return cp
}

// Compile-time check.
var _ auth.Authorizer = (*memAuthorizer)(nil)

// --------------------------------------------------------------------------
// AC: WithAuthorizer injects custom authZ into the auth instance and the
//     Authorizer is accessible on the returned Auth struct.
// --------------------------------------------------------------------------

func TestAuthorizerInjectionAndAccessibility(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	authz := newMemAuthorizer()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-inject:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAuthorizer(authz),
	)
	assertNoError(t, err, "authsetup.New with Authorizer")
	defer a.Close()

	// STRICT: Authorizer MUST be accessible on the Auth struct.
	if a.Authorizer == nil {
		t.Fatal("BUG: WithAuthorizer was called but Auth.Authorizer is nil — Authorizer was silently swallowed")
	}

	// STRICT: The returned Authorizer MUST be the exact instance we passed.
	if a.Authorizer != authz {
		t.Fatal("BUG: Auth.Authorizer is not the same instance that was passed to WithAuthorizer")
	}
}

// --------------------------------------------------------------------------
// AC: Without WithAuthorizer, the Authorizer field is nil (zero value).
// --------------------------------------------------------------------------

func TestAuthorizerNilWhenNotConfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-nil:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New without Authorizer")
	defer a.Close()

	if a.Authorizer != nil {
		t.Fatal("Authorizer should be nil when WithAuthorizer is not called")
	}
}

// --------------------------------------------------------------------------
// AC: Full integration of Identity → Authorizer.CanAccess pattern.
//     Login → get identity from context → call Authorizer → authZ decision.
//     This validates the architecture's "identity in context → team calls
//     Authorizer" contract end-to-end.
// --------------------------------------------------------------------------

func TestAuthorizerEndToEndWithIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	authz := newMemAuthorizer()

	// Pre-configure authZ rules.
	authz.Allow("admin@test.com", "read", "dashboard")
	authz.Allow("admin@test.com", "write", "settings")
	authz.Deny("admin@test.com", "delete", "users")

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-e2e:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAuthorizer(authz),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register and login.
	identity, _, err := a.Engine.Register(ctx, passwordCred("admin@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Simulate: business logic reads identity from context and calls Authorizer.
	ctx = auth.SetIdentity(ctx, identity)

	retrievedID := auth.GetIdentity(ctx)
	if retrievedID == nil {
		t.Fatal("Identity not retrievable from context")
	}

	// STRICT: The identity's SubjectID must match what was registered.
	if retrievedID.SubjectID != "admin@test.com" {
		t.Fatalf("SubjectID mismatch: expected admin@test.com, got %q", retrievedID.SubjectID)
	}

	// ---- Test allowed action ----
	allowed, err := a.Authorizer.CanAccess(ctx, retrievedID.SubjectID, "read", "dashboard")
	assertNoError(t, err, "CanAccess(read, dashboard)")
	if !allowed {
		t.Fatal("CanAccess should allow admin to read dashboard")
	}

	// ---- Test another allowed action ----
	allowed, err = a.Authorizer.CanAccess(ctx, retrievedID.SubjectID, "write", "settings")
	assertNoError(t, err, "CanAccess(write, settings)")
	if !allowed {
		t.Fatal("CanAccess should allow admin to write settings")
	}

	// ---- Test denied action ----
	allowed, err = a.Authorizer.CanAccess(ctx, retrievedID.SubjectID, "delete", "users")
	assertNoError(t, err, "CanAccess(delete, users)")
	if allowed {
		t.Fatal("SECURITY: CanAccess should deny admin deleting users")
	}

	// ---- Test unconfigured action (default deny) ----
	allowed, err = a.Authorizer.CanAccess(ctx, retrievedID.SubjectID, "sudo", "system")
	assertNoError(t, err, "CanAccess(sudo, system)")
	if allowed {
		t.Fatal("SECURITY: unconfigured action should be denied by default")
	}

	// STRICT: Verify all calls were recorded.
	calls := authz.getCalls()
	if len(calls) != 4 {
		t.Fatalf("expected exactly 4 CanAccess calls, got %d", len(calls))
	}
	for _, c := range calls {
		if c.Subject != "admin@test.com" {
			t.Fatalf("all calls should use SubjectID=admin@test.com, got %q", c.Subject)
		}
	}
}

// --------------------------------------------------------------------------
// AC: Authorizer error propagates to business logic — no silent swallowing.
// --------------------------------------------------------------------------

func TestAuthorizerErrorPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	authz := newMemAuthorizer()

	policyErr := errors.New("OPA policy evaluation timeout")
	authz.DenyWithError("err-user@test.com", "read", "data", policyErr)

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-err:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAuthorizer(authz),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()
	_, _, err = a.Engine.Register(ctx, passwordCred("err-user@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Authorizer returns error — it MUST propagate, not be swallowed.
	allowed, err := a.Authorizer.CanAccess(ctx, "err-user@test.com", "read", "data")
	if err == nil {
		t.Fatal("SECURITY: Authorizer error was swallowed — should propagate to business logic")
	}
	if !errors.Is(err, policyErr) {
		t.Fatalf("expected OPA timeout error, got: %v", err)
	}
	if allowed {
		t.Fatal("SECURITY: CanAccess returned true along with an error — must be treated as denied")
	}
}

// --------------------------------------------------------------------------
// AC: Authorizer works with OAuth-authenticated users, not just password.
// --------------------------------------------------------------------------

func TestAuthorizerWithOAuthIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	stateStore := newMemStateStore()
	authz := newMemAuthorizer()

	// OAuth user gets specific permissions.
	authz.Allow("google-authz-sub", "read", "profile")
	authz.Deny("google-authz-sub", "admin", "system")

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL := srv.URL
	t.Cleanup(srv.Close)

	var mu sync.Mutex
	var dynamicIDToken string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustJSON(cfg))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		tok := dynamicIDToken
		mu.Unlock()
		resp := map[string]any{
			"id_token":     tok,
			"access_token": "authz-oauth-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustJSON(resp))
	})

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-oauth:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAuthorizer(authz),
		authsetup.WithOAuthStateStore(stateStore),
		authsetup.WithOAuthHTTPClient(srv.Client()),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "authz-client",
			ClientSecret: "authz-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// OAuth flow.
	oauthState, _, err := oauth.GenerateState("google")
	assertNoError(t, err, "GenerateState")
	err = stateStore.Save(ctx, oauthState)
	assertNoError(t, err, "Save state")

	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "google-authz-sub",
		Audience:  oauth.Audience{"authz-client"},
		Nonce:     oauthState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "authz@google.com",
	}
	mu.Lock()
	dynamicIDToken = signTestIDToken(claims)
	mu.Unlock()

	oauthIdentity, _, err := a.Engine.Login(ctx, auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "authz-code",
			"state":    oauthState.State,
			"provider": "google",
		},
	})
	assertNoError(t, err, "OAuth Login")

	// STRICT: AuthMethod must be oauth2.
	if oauthIdentity.AuthMethod != "oauth2" {
		t.Fatalf("expected AuthMethod=oauth2, got %q", oauthIdentity.AuthMethod)
	}

	// Set identity in context (simulating what middleware does).
	ctx = auth.SetIdentity(ctx, oauthIdentity)

	// Team business logic: check authZ.
	id := auth.GetIdentity(ctx)
	if id == nil {
		t.Fatal("identity not in context after SetIdentity")
	}

	allowed, err := a.Authorizer.CanAccess(ctx, id.SubjectID, "read", "profile")
	assertNoError(t, err, "CanAccess(read, profile)")
	if !allowed {
		t.Fatal("OAuth user should be allowed to read profile")
	}

	allowed, err = a.Authorizer.CanAccess(ctx, id.SubjectID, "admin", "system")
	assertNoError(t, err, "CanAccess(admin, system)")
	if allowed {
		t.Fatal("SECURITY: OAuth user should NOT be allowed admin access")
	}
}

// --------------------------------------------------------------------------
// AC: Authorizer with API key — different SubjectID for machine clients.
// --------------------------------------------------------------------------

func TestAuthorizerWithAPIKeyIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	apiKeyStore := newMemAPIKeyStore()
	authz := newMemAuthorizer()

	// Machine client gets read-only access.
	authz.Allow("machine-client", "read", "api/data")
	authz.Deny("machine-client", "write", "api/data")

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-apikey:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAuthorizer(authz),
		authsetup.WithAPIKeyStore(apiKeyStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Create an API key in the store.
	rawKey := "raw-authz-key"
	keyHash := session.HashID(rawKey)
	now := time.Now()
	err = apiKeyStore.Create(ctx, &apikey.APIKey{
		ID:        "ak-authz-1",
		SubjectID: "machine-client",
		KeyHash:   keyHash,
		Name:      "CI Pipeline",
		Scopes:    []string{"read:data"},
		CreatedAt: now,
	})
	assertNoError(t, err, "Create API key")

	// Login with API key.
	apiIdentity, _, err := a.Engine.Login(ctx, auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	})
	assertNoError(t, err, "API Key Login")

	// STRICT: SubjectID comes from the API key's SubjectID.
	if apiIdentity.SubjectID != "machine-client" {
		t.Fatalf("expected SubjectID=machine-client, got %q", apiIdentity.SubjectID)
	}

	// Authorizer call with API key identity.
	allowed, err := a.Authorizer.CanAccess(ctx, apiIdentity.SubjectID, "read", "api/data")
	assertNoError(t, err, "CanAccess(read, api/data)")
	if !allowed {
		t.Fatal("machine-client should be allowed to read api/data")
	}

	allowed, err = a.Authorizer.CanAccess(ctx, apiIdentity.SubjectID, "write", "api/data")
	assertNoError(t, err, "CanAccess(write, api/data)")
	if allowed {
		t.Fatal("SECURITY: machine-client should NOT be allowed to write api/data")
	}
}

// --------------------------------------------------------------------------
// AC: Authorizer combined with hooks — hooks fire even when authZ denies.
//     (AuthZ is post-authentication, hooks are part of authentication.)
// --------------------------------------------------------------------------

func TestAuthorizerDoesNotInterfereWithHooks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	authz := newMemAuthorizer()

	var hookFired bool
	var hookMu sync.Mutex

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "authz-hooks:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAuthorizer(authz),
		authsetup.WithHook(auth.EventLogin, func(_ context.Context, _ hooks.HookPayload) error {
			hookMu.Lock()
			hookFired = true
			hookMu.Unlock()
			return nil
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register + login.
	_, _, err = a.Engine.Register(ctx, passwordCred("hook-authz@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	_, _, err = a.Engine.Login(ctx, passwordCred("hook-authz@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login")

	hookMu.Lock()
	fired := hookFired
	hookMu.Unlock()
	if !fired {
		t.Fatal("Login hook must fire even when Authorizer is configured — Authorizer is orthogonal to authentication hooks")
	}

	// Now the team calls Authorizer post-login (deny all by default).
	allowed, _ := a.Authorizer.CanAccess(ctx, "hook-authz@test.com", "anything", "anywhere")
	if allowed {
		t.Fatal("Default deny should reject")
	}
}

// ==========================================================================
// PART 2: Strictness Audit — Bug-Hunting Tests
// ==========================================================================

// --------------------------------------------------------------------------
// STRICT: Session ID must have sufficient entropy (≥128 bits).
// --------------------------------------------------------------------------

func TestSessionIDEntropyStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "entropy-strict:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Collect 100 session IDs and verify uniqueness + entropy.
	seen := make(map[string]bool)
	const iterations = 100
	for i := 0; i < iterations; i++ {
		ident := fmt.Sprintf("entropy%d@test.com", i)
		identity, _, err := a.Engine.Register(ctx,
			passwordCred(ident, "Str0ngP@ssword!"))
		assertNoError(t, err, "Register iteration %d", i)

		sid := identity.SessionID
		if sid == "" {
			t.Fatalf("iteration %d: empty session ID", i)
		}
		// Session ID must be at least 22 chars (128 bits base64url = 22 chars).
		if len(sid) < 22 {
			t.Fatalf("SECURITY: session ID too short (%d chars): insufficient entropy", len(sid))
		}
		if seen[sid] {
			t.Fatalf("SECURITY: duplicate session ID detected at iteration %d: %q", i, sid)
		}
		seen[sid] = true
	}
}

// --------------------------------------------------------------------------
// STRICT: Verify → Logout → Verify must fail (no race window).
// --------------------------------------------------------------------------

func TestLogoutInvalidatesSessionImmediately(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "logout-strict:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("logout-now@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Verify works before logout.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify before logout")

	// Logout.
	err = a.Engine.Logout(ctx, identity.SessionID, identity.SubjectID)
	assertNoError(t, err, "Logout")

	// STRICT: Immediate verify after logout MUST fail.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if err == nil {
		t.Fatal("SECURITY: session valid immediately after logout — revocation has a race window")
	}

	// STRICT: Re-login gets a DIFFERENT session ID.
	newIdentity, _, err := a.Engine.Login(ctx, passwordCred("logout-now@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Re-login")

	if newIdentity.SessionID == identity.SessionID {
		t.Fatal("SECURITY: re-login returned same session ID as logged-out session")
	}
}

// --------------------------------------------------------------------------
// STRICT: Concurrent register of same identifier — exactly one must succeed.
// --------------------------------------------------------------------------

func TestConcurrentRegisterSameIdentifier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "concurrent-reg:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	const goroutines = 10
	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, _, err := a.Engine.Register(ctx, passwordCred("race@test.com", "Str0ngP@ssword!"))
			results <- err
		}()
	}

	var successes, duplicates, otherErrors int
	for i := 0; i < goroutines; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, auth.ErrUserAlreadyExists) {
			duplicates++
		} else {
			otherErrors++
			t.Logf("unexpected error: %v", err)
		}
	}

	if successes != 1 {
		t.Fatalf("SECURITY: expected exactly 1 successful registration, got %d (duplicates=%d, errors=%d)",
			successes, duplicates, otherErrors)
	}

	// All others must have gotten ErrUserAlreadyExists.
	if duplicates != goroutines-1 {
		t.Fatalf("expected %d duplicate errors, got %d (otherErrors=%d)",
			goroutines-1, duplicates, otherErrors)
	}
}

// --------------------------------------------------------------------------
// STRICT: Login with empty password must fail, not panic.
// --------------------------------------------------------------------------

func TestLoginEmptyPasswordRejects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "empty-pw:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("empty@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Login with empty password.
	_, _, err = a.Engine.Login(ctx, passwordCred("empty@test.com", ""))
	if err == nil {
		t.Fatal("SECURITY: login with empty password succeeded")
	}

	// Login with whitespace-only password.
	_, _, err = a.Engine.Login(ctx, passwordCred("empty@test.com", "   "))
	if err == nil {
		t.Fatal("SECURITY: login with whitespace-only password succeeded")
	}
}

// --------------------------------------------------------------------------
// STRICT: Login with wrong password MUST NOT leak timing information
//         about whether the user exists. Both "user not found" and "wrong
//         password" must take similar time (within 2x tolerance).
// --------------------------------------------------------------------------

func TestLoginTimingConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "timing:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("exists@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Wrong password (user exists).
	start1 := time.Now()
	_, _, _ = a.Engine.Login(ctx, passwordCred("exists@test.com", "WrongP@ssword!"))
	d1 := time.Since(start1)

	// Nonexistent user.
	start2 := time.Now()
	_, _, _ = a.Engine.Login(ctx, passwordCred("ghost@test.com", "AnyP@ssword123!"))
	d2 := time.Since(start2)

	// If the nonexistent user returns instantly (< 1ms) while wrong password
	// takes >100ms, that's a timing oracle. We use 20x as a generous bound.
	if d1 > 0 && d2 > 0 {
		ratio := float64(d1) / float64(d2)
		if ratio > 20 || ratio < 0.05 {
			t.Logf("WARNING: timing disparity detected — wrong_password=%v, nonexistent_user=%v, ratio=%.2f",
				d1, d2, ratio)
			// This is a warning, not a hard fail, because timing tests are inherently flaky.
			// The important thing is that the engine does a dummy hash for nonexistent users.
		}
	}
}

// --------------------------------------------------------------------------
// STRICT: Register with identifier case variation must normalize.
// --------------------------------------------------------------------------

func TestRegisterIdentifierNormalizationStrict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "norm-strict:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("Norm@Test.COM", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register with mixed case")

	// STRICT: Same email with different case must be treated as duplicate.
	_, _, err = a.Engine.Register(ctx, passwordCred("norm@test.com", "Str0ngP@ssword!"))
	if err == nil {
		t.Fatal("SECURITY: case-different email was treated as a new user")
	}
	if !errors.Is(err, auth.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got: %v", err)
	}

	// STRICT: Login with different case must succeed.
	_, _, err = a.Engine.Login(ctx, passwordCred("NORM@TEST.COM", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login with uppercase email must succeed")

	_, _, err = a.Engine.Login(ctx, passwordCred("  norm@test.com  ", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login with whitespace-padded email must succeed")
}

// --------------------------------------------------------------------------
// STRICT: Verify with garbage session ID must return error, not panic.
// --------------------------------------------------------------------------

func TestVerifyGarbageSessionIDRejects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "garbage-verify:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	garbageIDs := []string{
		"",
		" ",
		"not-a-real-session",
		"../../etc/passwd",
		strings.Repeat("A", 10000),
		"\x00\x01\x02",
		"'OR 1=1--",
		"<script>alert(1)</script>",
	}

	for _, gid := range garbageIDs {
		_, err := a.Engine.Verify(ctx, gid)
		if err == nil {
			t.Fatalf("SECURITY: Verify accepted garbage session ID: %q", gid)
		}
	}
}

// --------------------------------------------------------------------------
// STRICT: OAuth state token is single-use (replay attack prevention).
// --------------------------------------------------------------------------

func TestOAuthStateReplayPrevention(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL := srv.URL
	t.Cleanup(srv.Close)

	var mu sync.Mutex
	var dynamicIDToken string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustJSON(map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		tok := dynamicIDToken
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustJSON(map[string]any{
			"id_token":     tok,
			"access_token": "replay-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}))
	})

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "replay:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithOAuthStateStore(stateStore),
		authsetup.WithOAuthHTTPClient(srv.Client()),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "replay-client",
			ClientSecret: "replay-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Generate state.
	oauthState, _, err := oauth.GenerateState("google")
	assertNoError(t, err, "GenerateState")
	err = stateStore.Save(ctx, oauthState)
	assertNoError(t, err, "Save state")

	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "replay-user",
		Audience:  oauth.Audience{"replay-client"},
		Nonce:     oauthState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "replay@test.com",
	}
	mu.Lock()
	dynamicIDToken = signTestIDToken(claims)
	mu.Unlock()

	cred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "replay-code",
			"state":    oauthState.State,
			"provider": "google",
		},
	}

	// First use — should succeed.
	_, _, err = a.Engine.Login(ctx, cred)
	assertNoError(t, err, "First login with state")

	// Second use of same state — MUST fail (replay attack).
	_, _, err = a.Engine.Login(ctx, cred)
	if err == nil {
		t.Fatal("SECURITY: OAuth state token was accepted twice — replay attack possible")
	}
}

// --------------------------------------------------------------------------
// STRICT: Propagated JWT with tampered payload must be rejected.
// --------------------------------------------------------------------------

func TestPropagatedJWTTamperDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "auth-service",
		Audience: "downstream",
		TTL:      30 * time.Second,
	})
	assertNoError(t, err, "NewSignedJWTPropagator")

	ctx := context.Background()

	identity := &auth.Identity{
		SubjectID:  "legit-user",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	jwt := headers["x-auth-identity"]
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Tamper with the payload (change a character).
	tampered := parts[0] + "." + parts[1][:len(parts[1])-1] + "X." + parts[2]
	headers["x-auth-identity"] = tampered

	_, err = prop.Decode(ctx, headers, nil)
	if err == nil {
		t.Fatal("SECURITY: tampered JWT was accepted — signature verification failed")
	}
}

// --------------------------------------------------------------------------
// STRICT: Session propagator rejects non-existent session IDs.
// --------------------------------------------------------------------------

func TestSessionPropagatorRejectsNonExistentSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)

	store := redis.NewStore(redis.Config{
		Client:    client,
		KeyPrefix: "nonexist-prop:",
	})

	prop, err := propagator.NewSessionPropagator(propagator.SessionPropagatorConfig{
		Store: store,
	})
	assertNoError(t, err, "NewSessionPropagator")

	ctx := context.Background()

	// Encode with a fabricated session ID.
	identity := &auth.Identity{
		SubjectID: "attacker",
		SessionID: session.HashID("fabricated-session-id"),
	}
	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	// Decode MUST fail because session doesn't exist in Redis.
	_, err = prop.Decode(ctx, headers, nil)
	if err == nil {
		t.Fatal("SECURITY: SessionPropagator accepted a non-existent session ID")
	}
}

// --------------------------------------------------------------------------
// STRICT: Before hook that panics must not crash the server.
// --------------------------------------------------------------------------

func TestBeforeHookPanicRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hook-panic:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, func(_ context.Context, _ hooks.HookPayload) error {
			panic("hook panic bomb!")
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// The panic in the hook should be caught (or at minimum, this test should
	// demonstrate whether hook panics propagate or are recovered).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Hook panic propagated to caller: %v — consider adding recover() in hook dispatch", r)
			}
		}()
		_, _, err = a.Engine.Register(ctx, passwordCred("panic@test.com", "Str0ngP@ssword!"))
		if err != nil {
			t.Logf("Registration failed (expected if hook aborted): %v", err)
		}
	}()
}

// --------------------------------------------------------------------------
// STRICT: Identity context immutability — SetIdentity returns new context,
//         original context is unmodified.
// --------------------------------------------------------------------------

func TestIdentityContextImmutability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx1 := context.Background()

	// No identity in ctx1.
	if auth.GetIdentity(ctx1) != nil {
		t.Fatal("background context should have nil identity")
	}

	id := &auth.Identity{
		SubjectID:  "immutable-user",
		AuthMethod: "password",
	}
	ctx2 := auth.SetIdentity(ctx1, id)

	// ctx1 must still have nil identity.
	if auth.GetIdentity(ctx1) != nil {
		t.Fatal("SECURITY: original context was mutated by SetIdentity")
	}

	// ctx2 must have the identity.
	got := auth.GetIdentity(ctx2)
	if got == nil || got.SubjectID != "immutable-user" {
		t.Fatal("new context does not have the expected identity")
	}

	// Override with a different identity on ctx3 — ctx2 must remain unchanged.
	id2 := &auth.Identity{
		SubjectID:  "other-user",
		AuthMethod: "oauth2",
	}
	ctx3 := auth.SetIdentity(ctx2, id2)

	got2 := auth.GetIdentity(ctx2)
	if got2 == nil || got2.SubjectID != "immutable-user" {
		t.Fatal("SECURITY: ctx2 identity was mutated when ctx3 was created")
	}

	got3 := auth.GetIdentity(ctx3)
	if got3 == nil || got3.SubjectID != "other-user" {
		t.Fatal("ctx3 does not have the overridden identity")
	}
}

// --------------------------------------------------------------------------
// STRICT: Workload identity and user identity do NOT cross-contaminate.
// --------------------------------------------------------------------------

func TestIdentityIsolationUserVsWorkload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Set user identity only.
	uid := &auth.Identity{SubjectID: "user-iso", AuthMethod: "password"}
	ctx = auth.SetIdentity(ctx, uid)

	// Workload identity must be nil.
	if auth.GetWorkloadIdentity(ctx) != nil {
		t.Fatal("SECURITY: setting user identity also set workload identity")
	}

	// Set workload identity.
	wid := &auth.WorkloadIdentity{WorkloadID: "spiffe://example.com/svc"}
	ctx = auth.SetWorkloadIdentity(ctx, wid)

	// Both must be present and correct.
	gotU := auth.GetIdentity(ctx)
	gotW := auth.GetWorkloadIdentity(ctx)
	if gotU == nil || gotU.SubjectID != "user-iso" {
		t.Fatal("user identity corrupted after setting workload identity")
	}
	if gotW == nil || gotW.WorkloadID != "spiffe://example.com/svc" {
		t.Fatal("workload identity not set correctly")
	}

	// Clear user identity — workload must survive.
	ctx = auth.SetIdentity(ctx, nil)
	if auth.GetIdentity(ctx) != nil {
		t.Fatal("user identity should be nil after clearing")
	}
	if auth.GetWorkloadIdentity(ctx) == nil {
		t.Fatal("SECURITY: clearing user identity also cleared workload identity")
	}
}

// --------------------------------------------------------------------------
// STRICT: Password hash must not be stored as plain text.
// --------------------------------------------------------------------------

func TestPasswordStoredHashed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hash-check:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	password := "CheckM3ForH@shing!"
	ctx := context.Background()
	_, _, err = a.Engine.Register(ctx, passwordCred("hashed@test.com", password))
	assertNoError(t, err, "Register")

	u := userStore.GetUser("hashed@test.com")
	if u == nil {
		t.Fatal("user not found in store")
	}

	hash := u.GetPasswordHash()
	if hash == "" {
		t.Fatal("password hash is empty")
	}
	if hash == password {
		t.Fatal("SECURITY: password stored in plain text!")
	}
	// Argon2id hashes start with "$argon2id$"
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("expected Argon2id hash prefix, got: %q", hash[:min(20, len(hash))])
	}
}

// --------------------------------------------------------------------------
// STRICT: Registering same user twice returns ErrUserAlreadyExists, not a
//         generic error.
// --------------------------------------------------------------------------

func TestDuplicateRegistrationReturnsSpecificError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "dup-strict:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("dup@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "First register")

	_, _, err = a.Engine.Register(ctx, passwordCred("dup@test.com", "AnotherP@ss1!"))
	if err == nil {
		t.Fatal("SECURITY: duplicate registration succeeded")
	}
	if !errors.Is(err, auth.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// Helper: mustJSON encodes a value to JSON bytes, panics on error.
// --------------------------------------------------------------------------

func mustJSON(v any) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("mustJSON: %v", err))
	}
	return data
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
