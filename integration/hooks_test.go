// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/mode/oauth"
)

// --------------------------------------------------------------------------
// AUTH-0028: Lifecycle hooks integration tests
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Helper: startHooksIdP starts a mock OIDC IdP whose id_token is set after
// server start (needed because the issuer URL must match).
// --------------------------------------------------------------------------

type hookIdPState struct {
	mu      sync.RWMutex
	idToken string
	issuer  string
}

func (s *hookIdPState) setIDToken(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idToken = tok
}

func (s *hookIdPState) getIDToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.idToken
}

func startHooksIdP(t *testing.T) (*httptest.Server, *hookIdPState) {
	t.Helper()

	st := &hookIdPState{}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		cfg := map[string]string{
			"issuer":                 st.issuer,
			"authorization_endpoint": st.issuer + "/authorize",
			"token_endpoint":         st.issuer + "/token",
			"jwks_uri":               st.issuer + "/jwks",
			"userinfo_endpoint":      st.issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"id_token":     st.getIDToken(),
			"access_token": "hooks-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	srv := httptest.NewServer(mux)
	st.issuer = srv.URL
	t.Cleanup(srv.Close)

	return srv, st
}

// --------------------------------------------------------------------------
// AC: Hooks fire in correct order across password login, registration,
//     OAuth and magic link.
// --------------------------------------------------------------------------

func TestHooksFireAcrossAllModes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	stateStore := newMemStateStore()
	mlStore := newMemMagicLinkStore()
	notifier := newMemNotifier()

	srv, idpSt := startHooksIdP(t)
	idpURL := srv.URL

	// Track hook events.
	type hookEntry struct {
		event      auth.AuthEvent
		authMethod string
	}
	var hookLog []hookEntry
	var hookMu sync.Mutex

	makeHook := func(event auth.AuthEvent) hooks.HookFn {
		return func(_ context.Context, payload hooks.HookPayload) error {
			hookMu.Lock()
			defer hookMu.Unlock()
			hookLog = append(hookLog, hookEntry{
				event:      event,
				authMethod: payload.GetAuthMethod(),
			})
			return nil
		}
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hooks-all:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithOAuthStateStore(stateStore),
		authsetup.WithOAuthHTTPClient(srv.Client()),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "hooks-client",
			ClientSecret: "hooks-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}),
		authsetup.WithNotifier(notifier),
		authsetup.WithMagicLinkStore(mlStore),
		authsetup.WithHook(auth.EventRegistration, makeHook(auth.EventRegistration)),
		authsetup.WithHook(auth.EventLogin, makeHook(auth.EventLogin)),
		authsetup.WithHook(auth.EventLoginFailed, makeHook(auth.EventLoginFailed)),
		authsetup.WithHook(auth.EventLogout, makeHook(auth.EventLogout)),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// ---- 1. Registration ----
	hookMu.Lock()
	hookLog = nil
	hookMu.Unlock()

	_, _, err = a.Engine.Register(ctx, passwordCred("hooks-user@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	hookMu.Lock()
	found := false
	for _, e := range hookLog {
		if e.event == auth.EventRegistration && e.authMethod == "password" {
			found = true
		}
	}
	hookMu.Unlock()
	if !found {
		t.Fatal("registration hook did not fire with authMethod=password")
	}

	// ---- 2. Password login ----
	hookMu.Lock()
	hookLog = nil
	hookMu.Unlock()

	_, _, err = a.Engine.Login(ctx, passwordCred("hooks-user@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Password Login")

	hookMu.Lock()
	found = false
	for _, e := range hookLog {
		if e.event == auth.EventLogin && e.authMethod == "password" {
			found = true
		}
	}
	hookMu.Unlock()
	if !found {
		t.Fatal("password login hook did not fire with authMethod=password")
	}

	// ---- 3. OAuth login ----
	oauthState, _, err := oauth.GenerateState("google")
	assertNoError(t, err, "GenerateState")
	err = stateStore.Save(ctx, oauthState)
	assertNoError(t, err, "Save state")

	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "hooks-oauth-sub",
		Audience:  oauth.Audience{"hooks-client"},
		Nonce:     oauthState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "hooks-oauth@test.com",
	}
	idpSt.setIDToken(signTestIDToken(claims))

	hookMu.Lock()
	hookLog = nil
	hookMu.Unlock()

	oauthCred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "hooks-code",
			"state":    oauthState.State,
			"provider": "google",
		},
	}
	_, _, err = a.Engine.Login(ctx, oauthCred)
	assertNoError(t, err, "OAuth Login")

	hookMu.Lock()
	found = false
	for _, e := range hookLog {
		if e.event == auth.EventLogin && e.authMethod == "oauth2" {
			found = true
		}
	}
	hookMu.Unlock()
	if !found {
		t.Fatal("OAuth login hook did not fire with authMethod=oauth2")
	}

	// ---- 4. Magic link login ----
	mlMode, err := newMagicLinkModeForTest(userStore, mlStore, notifier)
	assertNoError(t, err, "newMagicLinkModeForTest")

	rawToken, err := mlMode.Initiate(ctx, "hooks-user@test.com")
	assertNoError(t, err, "Initiate magic link")
	if rawToken == "" {
		t.Fatal("Initiate returned empty token")
	}

	hookMu.Lock()
	hookLog = nil
	hookMu.Unlock()

	_, _, err = a.Engine.Login(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	})
	assertNoError(t, err, "Magic link Login")

	hookMu.Lock()
	found = false
	for _, e := range hookLog {
		if e.event == auth.EventLogin && e.authMethod == "magic_link" {
			found = true
		}
	}
	hookMu.Unlock()
	if !found {
		t.Fatal("magic link login hook did not fire with authMethod=magic_link")
	}
}

// --------------------------------------------------------------------------
// AC: Before hooks abort flows (registration blocked).
// --------------------------------------------------------------------------

func TestBeforeHookAbortsRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	blockErr := errors.New("registration blocked by policy")

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookabort-reg:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, func(_ context.Context, _ hooks.HookPayload) error {
			return blockErr
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()
	_, _, err = a.Engine.Register(ctx, passwordCred("blocked@test.com", "Str0ngP@ssword!"))
	if err == nil {
		t.Fatal("expected registration to be blocked by before hook")
	}
	if !errors.Is(err, blockErr) {
		t.Fatalf("expected blockErr, got: %v", err)
	}

	// SECURITY: user must NOT have been created.
	if userStore.UserCount() != 0 {
		t.Fatal("SECURITY: user was created despite before hook aborting registration")
	}
}

// --------------------------------------------------------------------------
// AC: Before hooks abort login.
// --------------------------------------------------------------------------

func TestBeforeHookAbortsLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookabort-login:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventLogin, func(_ context.Context, _ hooks.HookPayload) error {
			return errors.New("login suspended for maintenance")
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register first (no EventLogin hook for registration).
	_, _, err = a.Engine.Register(ctx, passwordCred("hooklogin@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Login must be blocked.
	_, _, err = a.Engine.Login(ctx, passwordCred("hooklogin@test.com", "Str0ngP@ssword!"))
	if err == nil {
		t.Fatal("expected login to be blocked by before hook")
	}
	if !strings.Contains(err.Error(), "maintenance") {
		t.Fatalf("expected maintenance error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AC: Mode-specific payloads contain correct data.
//     (Identifier, AuthMethod, SubjectID, SessionID)
// --------------------------------------------------------------------------

func TestHookPayloadContainsCorrectData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	var capturedPayloads []hooks.HookPayload
	var payloadMu sync.Mutex

	capture := func(_ context.Context, payload hooks.HookPayload) error {
		payloadMu.Lock()
		defer payloadMu.Unlock()
		capturedPayloads = append(capturedPayloads, payload)
		return nil
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookpayload:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, capture),
		authsetup.WithHook(auth.EventLogin, capture),
		authsetup.WithHook(auth.EventLogout, capture),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// ---- 1. Registration payload ----
	payloadMu.Lock()
	capturedPayloads = nil
	payloadMu.Unlock()

	regIdentity, _, err := a.Engine.Register(ctx, passwordCred("payload-user@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	payloadMu.Lock()
	for _, p := range capturedPayloads {
		if rp, ok := p.(*hooks.RegisterPayload); ok {
			if rp.AuthMethod != "password" {
				t.Fatalf("RegisterPayload.AuthMethod: expected password, got %q", rp.AuthMethod)
			}
			if rp.Identifier != "payload-user@test.com" {
				t.Fatalf("RegisterPayload.Identifier: expected payload-user@test.com, got %q", rp.Identifier)
			}
		}
	}
	payloadMu.Unlock()

	// ---- 2. Login payload ----
	payloadMu.Lock()
	capturedPayloads = nil
	payloadMu.Unlock()

	loginIdentity, _, err := a.Engine.Login(ctx, passwordCred("payload-user@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login")

	payloadMu.Lock()
	foundAfterLogin := false
	for _, p := range capturedPayloads {
		if lp, ok := p.(*hooks.LoginPayload); ok {
			if lp.SubjectID != "" {
				foundAfterLogin = true
				if lp.AuthMethod != "password" {
					t.Fatalf("LoginPayload.AuthMethod: expected password, got %q", lp.AuthMethod)
				}
				if lp.SessionID == "" {
					t.Fatal("LoginPayload.SessionID is empty in after-login hook")
				}
			}
		}
	}
	payloadMu.Unlock()
	if !foundAfterLogin {
		t.Fatal("after-login hook payload with populated SubjectID not found")
	}
	_ = loginIdentity

	// ---- 3. Logout payload ----
	payloadMu.Lock()
	capturedPayloads = nil
	payloadMu.Unlock()

	err = a.Engine.Logout(ctx, regIdentity.SessionID, regIdentity.SubjectID)
	assertNoError(t, err, "Logout")

	payloadMu.Lock()
	foundLogout := false
	for _, p := range capturedPayloads {
		if lp, ok := p.(*hooks.LogoutPayload); ok {
			foundLogout = true
			if lp.SubjectID != regIdentity.SubjectID {
				t.Fatalf("LogoutPayload.SubjectID: expected %q, got %q",
					regIdentity.SubjectID, lp.SubjectID)
			}
		}
	}
	payloadMu.Unlock()
	if !foundLogout {
		t.Fatal("logout hook did not fire")
	}
}

// --------------------------------------------------------------------------
// AC: Failed login fires EventLoginFailed hook.
// --------------------------------------------------------------------------

func TestFailedLoginHookFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	var failedPayloads []*hooks.LoginPayload
	var mu sync.Mutex

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookfail:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventLoginFailed, func(_ context.Context, p hooks.HookPayload) error {
			if lp, ok := p.(*hooks.LoginPayload); ok {
				mu.Lock()
				failedPayloads = append(failedPayloads, lp)
				mu.Unlock()
			}
			return nil
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register a user, then login with wrong password.
	_, _, err = a.Engine.Register(ctx, passwordCred("failhook@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	_, _, err = a.Engine.Login(ctx, passwordCred("failhook@test.com", "WrongPassword!"))
	if err == nil {
		t.Fatal("expected login to fail with wrong password")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(failedPayloads) == 0 {
		t.Fatal("EventLoginFailed hook did not fire")
	}
	if failedPayloads[0].Error == nil {
		t.Fatal("EventLoginFailed payload.Error is nil — should carry the login error")
	}
	if failedPayloads[0].AuthMethod != "password" {
		t.Fatalf("EventLoginFailed payload.AuthMethod: expected password, got %q", failedPayloads[0].AuthMethod)
	}
}

// --------------------------------------------------------------------------
// AC: Multiple hooks on same event fire in registration order.
// --------------------------------------------------------------------------

func TestMultipleHooksFireInOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	var order []int
	var mu sync.Mutex

	makeOrderedHook := func(idx int) hooks.HookFn {
		return func(_ context.Context, _ hooks.HookPayload) error {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, idx)
			return nil
		}
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookorder:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, makeOrderedHook(1)),
		authsetup.WithHook(auth.EventRegistration, makeOrderedHook(2)),
		authsetup.WithHook(auth.EventRegistration, makeOrderedHook(3)),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()
	_, _, err = a.Engine.Register(ctx, passwordCred("order@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	mu.Lock()
	defer mu.Unlock()

	if len(order) < 3 {
		t.Fatalf("expected at least 3 hook calls, got %d", len(order))
	}

	// Before hooks fire in order 1,2,3 — then after hooks also 1,2,3.
	// The combined order should be [1,2,3,1,2,3].
	// But we only care that the relative order within each phase is correct.
	// Since we can't distinguish before vs after with a single counter,
	// check that 1 always appears before 2 and 2 before 3 in each triplet.
	for i := 0; i+2 < len(order); i += 3 {
		if order[i] != 1 || order[i+1] != 2 || order[i+2] != 3 {
			t.Fatalf("hooks fired out of order: %v", order)
		}
	}
}

// --------------------------------------------------------------------------
// AC: After-hook errors do not fail the operation.
// --------------------------------------------------------------------------

func TestAfterHookErrorDoesNotFailOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	afterHookCalled := false
	var mu sync.Mutex

	// We register a hook on EventRegistration that will be called both
	// before AND after. The EmitBefore call happens first; we must NOT error
	// there or registration will abort. After hooks swallow errors, so we
	// use a flag to only error on the second call (after).
	callCount := 0
	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookaftererr:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, func(_ context.Context, p hooks.HookPayload) error {
			mu.Lock()
			defer mu.Unlock()
			callCount++
			if callCount == 1 {
				// Before hook — succeed.
				return nil
			}
			// After hook — fail (should be logged, not propagated).
			afterHookCalled = true
			return errors.New("after-hook explosion")
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Operation should succeed despite the after-hook returning an error.
	identity, sess, err := a.Engine.Register(ctx, passwordCred("aftererr@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register should succeed despite after-hook error")
	if identity == nil || sess == nil {
		t.Fatal("Register returned nil identity or session")
	}

	mu.Lock()
	defer mu.Unlock()
	if !afterHookCalled {
		t.Fatal("after hook was never called")
	}
}
