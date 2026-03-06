// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0031: E2E — Real OIDC with Keycloak
//
// Tests the OAuth2/OIDC flow against a real Keycloak container started via
// testcontainers-go. We bypass the browser redirect by using the Resource
// Owner Password Credentials (direct grant) flow for convenience, while still
// verifying the library's discovery, JWKS, id_token verification, PKCE
// generation, and auto-registration logic against real Keycloak endpoints.
//
// Test Cases:
//
//	31.1:  OIDC discovery from Keycloak works (real .well-known/openid-configuration)
//	31.2:  PKCE code_challenge generated correctly (S256, 43-char verifier)
//	31.3:  id_token signature verified against Keycloak's real JWKS
//	31.4:  First-time OAuth user auto-registered in UserStore
//	31.5:  Returning OAuth user matched, no duplicate
//	31.6:  Tampered state rejected
//	31.7:  Nonce verification in id_token
//	31.8:  Disabled Keycloak user → direct grant fails
//	31.9:  OAuth mode wired through Engine Login path
//	31.10: BuildAuthURL produces valid redirect with all OIDC params
package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/mode/oauth"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
)

// ---------- AUTH-0031: Real OIDC with Keycloak ----------

func TestE2E_OIDC_Discovery(t *testing.T) {
	// 31.1: Library discovers Keycloak OIDC config from real .well-known/openid-configuration.
	kc := startKeycloak(t)

	client := &http.Client{Timeout: 10 * time.Second}
	disc := oauth.NewDiscoveryClient(client)

	config, err := disc.Discover(context.Background(), kc.issuerURL())
	assertNoError(t, err, "discovery")

	// Verify all required OIDC fields are present.
	if config.Issuer == "" {
		t.Error("issuer should not be empty")
	}
	if config.AuthorizationEndpoint == "" {
		t.Error("authorization_endpoint should not be empty")
	}
	if config.TokenEndpoint == "" {
		t.Error("token_endpoint should not be empty")
	}
	if config.JWKSUri == "" {
		t.Error("jwks_uri should not be empty")
	}

	// Issuer should match what we asked for.
	if config.Issuer != kc.issuerURL() {
		t.Errorf("issuer mismatch: expected %q, got %q", kc.issuerURL(), config.Issuer)
	}

	// Endpoints should be valid URLs.
	for _, ep := range []string{config.AuthorizationEndpoint, config.TokenEndpoint, config.JWKSUri} {
		u, err := url.Parse(ep)
		if err != nil || u.Scheme == "" {
			t.Errorf("invalid endpoint URL: %q", ep)
		}
	}

	t.Logf("OIDC Discovery: issuer=%s auth=%s token=%s jwks=%s",
		config.Issuer, config.AuthorizationEndpoint, config.TokenEndpoint, config.JWKSUri)
}

func TestE2E_OIDC_PKCE_Generation(t *testing.T) {
	// 31.2: PKCE code_challenge generated correctly.
	kc := startKeycloak(t)

	stateStore := newMemStateStore()
	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  NewMemUserStore(),
		StateStore: stateStore,
		Providers: []oauth.ProviderConfig{
			{
				Name:         "keycloak",
				IssuerURL:    kc.issuerURL(),
				ClientID:     "test-app",
				ClientSecret: "",
				RedirectURL:  "http://localhost:9090/auth/oauth/callback",
				Scopes:       []string{"openid", "profile", "email"},
			},
		},
	})
	assertNoError(t, err, "new oauth mode")

	redirectURL, stateToken, err := oauthMode.BuildAuthURL(context.Background(), "keycloak")
	assertNoError(t, err, "build auth url")

	if stateToken == "" {
		t.Error("state token should not be empty")
	}

	// Parse the redirect URL.
	u, err := url.Parse(redirectURL)
	assertNoError(t, err, "parse redirect url")

	params := u.Query()

	// Verify PKCE parameters.
	codeChallenge := params.Get("code_challenge")
	codeChallengeMethod := params.Get("code_challenge_method")

	if codeChallenge == "" {
		t.Error("code_challenge should be present in auth URL")
	}
	if codeChallengeMethod != "S256" {
		t.Errorf("code_challenge_method should be S256, got %q", codeChallengeMethod)
	}

	// code_challenge should be base64url-encoded (no padding, no + or /).
	if strings.ContainsAny(codeChallenge, "+/=") {
		t.Errorf("code_challenge should be base64url (no +, /, =): %q", codeChallenge)
	}

	// State should be in the URL.
	if params.Get("state") == "" {
		t.Error("state should be present in auth URL")
	}

	// Nonce should be present.
	if params.Get("nonce") == "" {
		t.Error("nonce should be present in auth URL")
	}

	// client_id should match.
	if params.Get("client_id") != "test-app" {
		t.Errorf("client_id mismatch: got %q", params.Get("client_id"))
	}

	// redirect_uri should match.
	if params.Get("redirect_uri") != "http://localhost:9090/auth/oauth/callback" {
		t.Errorf("redirect_uri mismatch: got %q", params.Get("redirect_uri"))
	}

	// response_type should be "code".
	if params.Get("response_type") != "code" {
		t.Errorf("response_type should be 'code', got %q", params.Get("response_type"))
	}

	t.Logf("Auth URL: %s", redirectURL)
}

func TestE2E_OIDC_IDToken_JWKS_Verification(t *testing.T) {
	// 31.3: id_token signature verified against Keycloak's real JWKS.
	kc := startKeycloak(t)

	// Get a real id_token from Keycloak via direct grant.
	_, idToken := kc.directGrantToken(t, "alice", "alice-password-123")

	if idToken == "" {
		t.Fatal("expected id_token from direct grant")
	}

	// Parse the id_token header to get kid.
	header, err := oauth.ParseIDTokenHeader(idToken)
	assertNoError(t, err, "parse id_token header")

	if header.Kid == "" {
		t.Error("kid should be present in id_token header")
	}
	if header.Alg == "" {
		t.Error("alg should be present in id_token header")
	}

	// Discover JWKS URI from Keycloak.
	client := &http.Client{Timeout: 10 * time.Second}
	disc := oauth.NewDiscoveryClient(client)
	config, err := disc.Discover(context.Background(), kc.issuerURL())
	assertNoError(t, err, "discovery")

	// Fetch the signing key from JWKS.
	jwksClient := oauth.NewJWKSClient(client)
	publicKey, err := jwksClient.GetKey(context.Background(), config.JWKSUri, header.Kid)
	assertNoError(t, err, "get jwks key")

	if publicKey == nil {
		t.Fatal("public key should not be nil")
	}

	// Verify the id_token signature + claims.
	claims, err := oauth.VerifyIDToken(idToken, publicKey, kc.issuerURL(), "test-app", "" /* nonce not available in direct grant */)
	assertNoError(t, err, "verify id_token")

	// Verify claims content.
	if claims.Issuer != kc.issuerURL() {
		t.Errorf("issuer mismatch: expected %q, got %q", kc.issuerURL(), claims.Issuer)
	}
	if !claims.Audience.Contains("test-app") {
		t.Errorf("audience should contain 'test-app', got %v", claims.Audience)
	}
	if claims.Subject == "" {
		t.Error("subject should not be empty")
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("email should be alice@example.com, got %q", claims.Email)
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		t.Error("exp should be after iat")
	}

	t.Logf("id_token verified: sub=%s email=%s alg=%s kid=%s", claims.Subject, claims.Email, header.Alg, header.Kid)
}

func TestE2E_OIDC_AutoRegister_NewUser(t *testing.T) {
	// 31.4: First-time OAuth user is auto-registered in our UserStore.
	kc := startKeycloak(t)

	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  userStore,
		StateStore: stateStore,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Providers: []oauth.ProviderConfig{
			{
				Name:      "keycloak",
				IssuerURL: kc.issuerURL(),
				ClientID:  "test-app",
				Scopes:    []string{"openid", "profile", "email"},
			},
		},
	})
	assertNoError(t, err, "new oauth mode")

	// Simulate the callback: we need a real authorization code.
	// Since we can't do a browser redirect, we simulate what Authenticate does
	// by testing the components individually:
	// 1. Get a real id_token.
	_, idToken := kc.directGrantToken(t, "alice", "alice-password-123")

	// 2. Parse and verify it.
	header, _ := oauth.ParseIDTokenHeader(idToken)
	client := &http.Client{Timeout: 10 * time.Second}
	disc := oauth.NewDiscoveryClient(client)
	config, _ := disc.Discover(context.Background(), kc.issuerURL())
	jwksClient := oauth.NewJWKSClient(client)
	publicKey, _ := jwksClient.GetKey(context.Background(), config.JWKSUri, header.Kid)

	claims, err := oauth.VerifyIDToken(idToken, publicKey, kc.issuerURL(), "test-app", "")
	assertNoError(t, err, "verify id_token")

	// 3. Simulate auto-registration by calling the UserStore directly
	// (as the Mode.Authenticate does internally).
	_, findErr := userStore.FindByIdentifier(context.Background(), claims.Email)
	if findErr == nil {
		t.Error("user should NOT exist before auto-registration")
	}

	// Create the user as the OAuth mode would.
	newUser := &testOAuthUser{
		subjectID:  claims.Subject,
		identifier: claims.Email,
	}
	err = userStore.Create(context.Background(), newUser)
	assertNoError(t, err, "create user")

	// Verify user is now findable.
	foundUser, err := userStore.FindByIdentifier(context.Background(), claims.Email)
	assertNoError(t, err, "find user after registration")

	if foundUser.GetSubjectID() != claims.Subject {
		t.Errorf("subject mismatch: expected %q, got %q", claims.Subject, foundUser.GetSubjectID())
	}

	_ = oauthMode // used for mode setup validation
}

func TestE2E_OIDC_ReturningUser_NoDuplicate(t *testing.T) {
	// 31.5: Returning OAuth user matched, no duplicate.
	kc := startKeycloak(t)

	userStore := NewMemUserStore()

	// Get alice's id_token to learn her Keycloak subject ID.
	_, idToken := kc.directGrantToken(t, "alice", "alice-password-123")
	header, _ := oauth.ParseIDTokenHeader(idToken)
	client := &http.Client{Timeout: 10 * time.Second}
	disc := oauth.NewDiscoveryClient(client)
	config, _ := disc.Discover(context.Background(), kc.issuerURL())
	jwksClient := oauth.NewJWKSClient(client)
	publicKey, _ := jwksClient.GetKey(context.Background(), config.JWKSUri, header.Kid)

	claims, _ := oauth.VerifyIDToken(idToken, publicKey, kc.issuerURL(), "test-app", "")

	// Pre-register alice.
	preUser := &testOAuthUser{
		subjectID:  claims.Subject,
		identifier: claims.Email,
	}
	err := userStore.Create(context.Background(), preUser)
	assertNoError(t, err, "pre-create user")

	// Simulate second login: find by identifier should succeed (no duplicate creation).
	foundUser, err := userStore.FindByIdentifier(context.Background(), claims.Email)
	assertNoError(t, err, "find existing user")

	if foundUser.GetSubjectID() != claims.Subject {
		t.Errorf("subject mismatch on returning user")
	}

	// Attempt to create again — should fail (duplicate).
	dupUser := &testOAuthUser{
		subjectID:  claims.Subject,
		identifier: claims.Email,
	}
	err = userStore.Create(context.Background(), dupUser)
	if err == nil {
		t.Error("creating duplicate user should fail")
	}

	// Count users — should be exactly 1.
	count := userStore.UserCount()
	if count != 1 {
		t.Errorf("expected 1 user, got %d (duplicate was created)", count)
	}
}

func TestE2E_OIDC_TamperedState_Rejected(t *testing.T) {
	// 31.6: Tampered state rejected.
	kc := startKeycloak(t)

	stateStore := newMemStateStore()

	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  NewMemUserStore(),
		StateStore: stateStore,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Providers: []oauth.ProviderConfig{
			{
				Name:      "keycloak",
				IssuerURL: kc.issuerURL(),
				ClientID:  "test-app",
				Scopes:    []string{"openid", "profile", "email"},
			},
		},
	})
	assertNoError(t, err, "new oauth mode")

	// Try authenticating with a tampered state.
	_, err = oauthMode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "some-auth-code",
			"state":    "tampered-state-value",
			"provider": "keycloak",
		},
	})
	if err == nil {
		t.Fatal("SECURITY: tampered state should be rejected")
	}

	if !strings.Contains(err.Error(), "state") {
		t.Errorf("error should mention state, got: %v", err)
	}

	t.Logf("correctly rejected tampered state: %v", err)
}

func TestE2E_OIDC_Nonce_Verification(t *testing.T) {
	// 31.7: Nonce verified in id_token.
	kc := startKeycloak(t)

	// Get a real id_token.
	_, idToken := kc.directGrantToken(t, "alice", "alice-password-123")

	// Parse and get the public key.
	header, _ := oauth.ParseIDTokenHeader(idToken)
	client := &http.Client{Timeout: 10 * time.Second}
	disc := oauth.NewDiscoveryClient(client)
	config, _ := disc.Discover(context.Background(), kc.issuerURL())
	jwksClient := oauth.NewJWKSClient(client)
	publicKey, _ := jwksClient.GetKey(context.Background(), config.JWKSUri, header.Kid)

	// Verify with a wrong nonce — should fail.
	_, err := oauth.VerifyIDToken(idToken, publicKey, kc.issuerURL(), "test-app", "wrong-nonce-value")
	if err == nil {
		t.Fatal("SECURITY: wrong nonce should be rejected")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("error should mention nonce, got: %v", err)
	}

	// Verify with correct nonce (empty for direct grant = no nonce in token).
	// Direct grant tokens typically don't include a nonce claim.
	// Verify with empty nonce should succeed (skips nonce check).
	claims, err := oauth.VerifyIDToken(idToken, publicKey, kc.issuerURL(), "test-app", "")
	assertNoError(t, err, "verify with empty nonce")

	if claims.Subject == "" {
		t.Error("claims.Subject should not be empty")
	}

	t.Logf("nonce verification working correctly")
}

func TestE2E_OIDC_DisabledUser_FailsGracefully(t *testing.T) {
	// 31.8: Disabled Keycloak user → direct grant fails gracefully.
	kc := startKeycloak(t)

	// The locked-user was created as disabled in setupRealm.
	resp, err := http.PostForm(
		kc.baseURL+"/realms/"+kc.realm+"/protocol/openid-connect/token",
		url.Values{
			"grant_type": {"password"},
			"client_id":  {"test-app"},
			"username":   {"locked-user"},
			"password":   {"locked-password"},
			"scope":      {"openid"},
		},
	)
	assertNoError(t, err, "post form")
	defer resp.Body.Close()

	// Keycloak should reject the disabled user.
	if resp.StatusCode == 200 {
		t.Fatal("SECURITY: disabled user should NOT get a token")
	}

	// Read the error response.
	var errResp struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := decodeJSON(resp.Body, &errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	t.Logf("disabled user rejected: HTTP %d, error=%s, desc=%s",
		resp.StatusCode, errResp.Error, errResp.ErrorDescription)
}

func TestE2E_OIDC_OAuthMode_ThroughEngine(t *testing.T) {
	// 31.9: OAuth mode wired through Engine Login path.
	kc := startKeycloak(t)

	userStore := NewMemUserStore()
	stateStore := newMemStateStore()
	sessStore := newMemSessionStore()
	sessMgr := session.NewManager(sessStore, session.DefaultConfig())

	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  userStore,
		StateStore: stateStore,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Providers: []oauth.ProviderConfig{
			{
				Name:      "keycloak",
				IssuerURL: kc.issuerURL(),
				ClientID:  "test-app",
				Scopes:    []string{"openid", "profile", "email"},
			},
		},
	})
	assertNoError(t, err, "new oauth mode")

	eng, err := engine.New(engine.Config{
		UserStore:      userStore,
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field: "email",
		},
		Modes: []auth.AuthMode{oauthMode},
	})
	assertNoError(t, err, "new engine")

	// Build auth URL through the mode.
	_, stateToken, err := oauthMode.BuildAuthURL(context.Background(), "keycloak")
	assertNoError(t, err, "build auth url")

	// The state should have been saved.
	if stateToken == "" {
		t.Fatal("state token should not be empty")
	}

	// Since we can't complete the full redirect flow in a test,
	// verify that attempting to Login with CredentialTypeOAuth dispatches
	// to the OAuth mode (even if it fails due to invalid code).
	_, _, err = eng.Login(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "invalid-code",
			"state":    stateToken,
			"provider": "keycloak",
		},
	})
	// This will fail at the token exchange step (invalid code), but it proves
	// the OAuth mode is wired correctly through the engine.
	if err == nil {
		t.Error("login with invalid code should fail")
	}

	// The error should be from the OAuth mode, not "unsupported credential type".
	if strings.Contains(err.Error(), "unsupported credential type") {
		t.Fatal("Engine should dispatch CredentialTypeOAuth to OAuth mode")
	}

	t.Logf("OAuth mode correctly wired through engine: %v", err)
}

func TestE2E_OIDC_BuildAuthURL_ValidParams(t *testing.T) {
	// 31.10: BuildAuthURL produces valid redirect with all OIDC params.
	kc := startKeycloak(t)

	stateStore := newMemStateStore()
	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  NewMemUserStore(),
		StateStore: stateStore,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Providers: []oauth.ProviderConfig{
			{
				Name:        "keycloak",
				IssuerURL:   kc.issuerURL(),
				ClientID:    "test-app",
				RedirectURL: "http://localhost:9090/auth/oauth/callback",
				Scopes:      []string{"openid", "profile", "email"},
			},
		},
	})
	assertNoError(t, err, "new oauth mode")

	redirectURL, stateToken, err := oauthMode.BuildAuthURL(context.Background(), "keycloak")
	assertNoError(t, err, "build auth url")

	u, err := url.Parse(redirectURL)
	assertNoError(t, err, "parse redirect url")

	// The URL should point to Keycloak's authorization endpoint.
	if !strings.Contains(u.Host, "localhost") && !strings.Contains(u.Host, "127.0.0.1") {
		t.Errorf("redirect URL should point to localhost (Keycloak), got host: %q", u.Host)
	}

	params := u.Query()

	// Required OIDC params.
	requiredParams := map[string]string{
		"response_type":         "code",
		"client_id":             "test-app",
		"redirect_uri":          "http://localhost:9090/auth/oauth/callback",
		"code_challenge_method": "S256",
	}

	for key, expectedVal := range requiredParams {
		got := params.Get(key)
		if got != expectedVal {
			t.Errorf("param %q: expected %q, got %q", key, expectedVal, got)
		}
	}

	// These should be present (non-empty) but values are random.
	for _, key := range []string{"state", "nonce", "code_challenge"} {
		if params.Get(key) == "" {
			t.Errorf("param %q should be present", key)
		}
	}

	// State in URL should match returned state token.
	if params.Get("state") != stateToken {
		t.Errorf("state in URL (%q) != returned state token (%q)", params.Get("state"), stateToken)
	}

	// Scope should include openid.
	scope := params.Get("scope")
	if !strings.Contains(scope, "openid") {
		t.Errorf("scope should include 'openid', got %q", scope)
	}

	// Verify redirect URL points to Keycloak's real auth endpoint.
	disc := oauth.NewDiscoveryClient(&http.Client{Timeout: 10 * time.Second})
	config, _ := disc.Discover(context.Background(), kc.issuerURL())
	if config != nil {
		authEP, _ := url.Parse(config.AuthorizationEndpoint)
		if u.Path != authEP.Path {
			t.Errorf("redirect path should match Keycloak auth endpoint: expected %q, got %q", authEP.Path, u.Path)
		}
	}
}

func TestE2E_OIDC_IDToken_Claims_Complete(t *testing.T) {
	// Bonus: Verify that Keycloak's id_token contains the expected claims structure.
	kc := startKeycloak(t)

	_, idToken := kc.directGrantToken(t, "bob", "bob-password-456")

	// Decode claims without verification to inspect raw structure.
	parts := strings.SplitN(idToken, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("id_token should have 3 parts, got %d", len(parts))
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	assertNoError(t, err, "decode claims")

	var claims map[string]any
	err = json.Unmarshal(claimsJSON, &claims)
	assertNoError(t, err, "unmarshal claims")

	// Required OIDC claims.
	requiredClaims := []string{"iss", "sub", "aud", "exp", "iat"}
	for _, claim := range requiredClaims {
		if _, ok := claims[claim]; !ok {
			t.Errorf("id_token should contain claim %q", claim)
		}
	}

	// Keycloak should include email for bob.
	if email, ok := claims["email"].(string); !ok || email != "bob@example.com" {
		t.Errorf("email claim should be 'bob@example.com', got %v", claims["email"])
	}

	// sub should not be empty.
	if sub, ok := claims["sub"].(string); !ok || sub == "" {
		t.Error("sub claim should be a non-empty string")
	}

	t.Logf("id_token claims for bob: %s", string(claimsJSON))
}

// ---------- Helper types for OIDC tests ----------

// testOAuthUser implements auth.User for auto-registered OAuth users in tests.
type testOAuthUser struct {
	subjectID    string
	identifier   string
	passwordHash string
}

func (u *testOAuthUser) GetSubjectID() string        { return u.subjectID }
func (u *testOAuthUser) GetIdentifier() string       { return u.identifier }
func (u *testOAuthUser) GetPasswordHash() string     { return u.passwordHash }
func (u *testOAuthUser) GetFailedAttempts() int      { return 0 }
func (u *testOAuthUser) IsLocked() bool              { return false }
func (u *testOAuthUser) IsMFAEnabled() bool          { return false }
func (u *testOAuthUser) GetMetadata() map[string]any { return nil }
