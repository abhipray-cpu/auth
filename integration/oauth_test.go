// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/mode/oauth"
)

// --------------------------------------------------------------------------
// Test infrastructure: Mock OIDC Identity Provider
// --------------------------------------------------------------------------

// testRSAKey is a shared RSA key used for signing id_tokens in tests.
var testRSAKey *rsa.PrivateKey

func init() {
	var err error
	testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
}

const testKid = "inttest-key-1"

// createTestJWKSJSON returns the JWKS JSON for the test RSA key.
func createTestJWKSJSON() []byte {
	pub := &testRSAKey.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type jwks struct {
		Keys []jwk `json:"keys"`
	}

	data, _ := json.Marshal(jwks{Keys: []jwk{{
		Kty: "RSA",
		Kid: testKid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}}})
	return data
}

// signTestIDToken signs a JWT with the test RSA key.
func signTestIDToken(claims oauth.IDTokenClaims) string {
	header := oauth.IDTokenHeader{Alg: "RS256", Kid: testKid, Typ: "JWT"}
	token, err := oauth.CreateTestJWT(header, claims, func(input string) ([]byte, error) {
		h := sha256.Sum256([]byte(input))
		return rsa.SignPKCS1v15(rand.Reader, testRSAKey, crypto.SHA256, h[:])
	})
	if err != nil {
		panic("failed to sign test id_token: " + err.Error())
	}
	return token
}

// tokenExchangeRequest records what the token endpoint received.
type tokenExchangeRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
}

// memStateStore is a thread-safe in-memory StateStore for integration tests.
type memStateStore struct {
	mu     sync.Mutex
	states map[string]*oauth.OAuthState
}

func newMemStateStore() *memStateStore {
	return &memStateStore{states: make(map[string]*oauth.OAuthState)}
}

func (s *memStateStore) Save(_ context.Context, state *oauth.OAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *memStateStore) Load(_ context.Context, stateToken string) (*oauth.OAuthState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[stateToken]
	if !ok {
		return nil, errors.New("state not found")
	}
	delete(s.states, stateToken) // single-use
	return st, nil
}

// Compile-time check.
var _ oauth.StateStore = (*memStateStore)(nil)

// --------------------------------------------------------------------------
// AUTH-0025 AC: Full OAuth flow with mock Google IdP
// --------------------------------------------------------------------------

func TestOAuthFullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	// Dynamic id_token holder — set after we know the nonce.
	var mu sync.Mutex
	var dynamicIDToken string
	var capturedExchange tokenExchangeRequest

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL := srv.URL
	t.Cleanup(srv.Close)

	// Register handlers BEFORE any OAuth operation (discovery must be reachable).
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedExchange.GrantType = r.FormValue("grant_type")
		capturedExchange.Code = r.FormValue("code")
		capturedExchange.RedirectURI = r.FormValue("redirect_uri")
		capturedExchange.ClientID = r.FormValue("client_id")
		capturedExchange.ClientSecret = r.FormValue("client_secret")
		capturedExchange.CodeVerifier = r.FormValue("code_verifier")

		mu.Lock()
		tok := dynamicIDToken
		mu.Unlock()

		resp := map[string]any{
			"id_token":     tok,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "oauth:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithOAuthStateStore(stateStore),
		authsetup.WithOAuthHTTPClient(srv.Client()),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Create OAuth mode for BuildAuthURL (engine doesn't expose it).
	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  userStore,
		StateStore: stateStore,
		HTTPClient: srv.Client(),
		Providers: []oauth.ProviderConfig{{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
		}},
	})
	assertNoError(t, err, "oauth.NewMode")

	redirectURL, stateToken, err := oauthMode.BuildAuthURL(ctx, "google")
	assertNoError(t, err, "BuildAuthURL")

	if redirectURL == "" {
		t.Fatal("BuildAuthURL returned empty redirectURL")
	}
	if stateToken == "" {
		t.Fatal("BuildAuthURL returned empty stateToken")
	}

	// Verify the redirect URL contains required OAuth params.
	if !strings.Contains(redirectURL, "response_type=code") {
		t.Fatal("redirectURL missing response_type=code")
	}
	if !strings.Contains(redirectURL, "client_id=test-client-id") {
		t.Fatal("redirectURL missing client_id")
	}
	if !strings.Contains(redirectURL, "code_challenge=") {
		t.Fatal("redirectURL missing PKCE code_challenge")
	}
	if !strings.Contains(redirectURL, "code_challenge_method=S256") {
		t.Fatal("redirectURL missing code_challenge_method=S256")
	}
	if !strings.Contains(redirectURL, "state=") {
		t.Fatal("redirectURL missing state parameter")
	}
	if !strings.Contains(redirectURL, "nonce=") {
		t.Fatal("redirectURL missing nonce parameter")
	}

	// Peek at state to get nonce, then re-save for Authenticate.
	storedState, err := stateStore.Load(ctx, stateToken)
	assertNoError(t, err, "Load state for nonce peek")
	err = stateStore.Save(ctx, storedState)
	assertNoError(t, err, "Re-save state")

	// Sign a proper id_token with the nonce.
	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "google-user-123",
		Audience:  oauth.Audience{"test-client-id"},
		Nonce:     storedState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "alice@gmail.com",
		Name:      "Alice User",
	}
	mu.Lock()
	dynamicIDToken = signTestIDToken(claims)
	mu.Unlock()

	// Simulate the callback — call Authenticate.
	cred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "test-authorization-code",
			"state":    stateToken,
			"provider": "google",
		},
	}

	identity, err := oauthMode.Authenticate(ctx, cred)
	assertNoError(t, err, "Authenticate")

	if identity == nil {
		t.Fatal("Authenticate returned nil identity")
	}
	if identity.SubjectID == "" {
		t.Fatal("identity.SubjectID is empty")
	}
	if identity.AuthMethod != "oauth2" {
		t.Fatalf("expected AuthMethod=oauth2, got %q", identity.AuthMethod)
	}

	// Verify email from claims is in metadata.
	email, _ := identity.Metadata["email"].(string)
	if email != "alice@gmail.com" {
		t.Fatalf("expected email=alice@gmail.com in metadata, got %q", email)
	}
	provider, _ := identity.Metadata["provider"].(string)
	if provider != "google" {
		t.Fatalf("expected provider=google in metadata, got %q", provider)
	}
}

// --------------------------------------------------------------------------
// AUTH-0025 AC: PKCE verifier sent in token exchange
// AUTH-0025 AC: PKCE verifier survives initiate → redirect → callback
// --------------------------------------------------------------------------

func TestOAuthPKCERoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	var capturedExchange tokenExchangeRequest
	var mu sync.Mutex
	var dynamicIDToken string

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL := srv.URL
	t.Cleanup(srv.Close)

	// Register handlers BEFORE any OAuth operation.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capturedExchange.GrantType = r.FormValue("grant_type")
		capturedExchange.Code = r.FormValue("code")
		capturedExchange.RedirectURI = r.FormValue("redirect_uri")
		capturedExchange.ClientID = r.FormValue("client_id")
		capturedExchange.ClientSecret = r.FormValue("client_secret")
		capturedExchange.CodeVerifier = r.FormValue("code_verifier")

		mu.Lock()
		tok := dynamicIDToken
		mu.Unlock()

		resp := map[string]any{
			"id_token":     tok,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  userStore,
		StateStore: stateStore,
		HTTPClient: srv.Client(),
		Providers: []oauth.ProviderConfig{{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "pkce-client",
			ClientSecret: "pkce-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}},
	})
	assertNoError(t, err, "oauth.NewMode")

	ctx := context.Background()

	// BuildAuthURL generates state, nonce, and PKCE.
	redirectURL, stateToken, err := oauthMode.BuildAuthURL(ctx, "google")
	assertNoError(t, err, "BuildAuthURL")

	// Verify PKCE challenge is in the redirect URL.
	if !strings.Contains(redirectURL, "code_challenge=") {
		t.Fatal("PKCE code_challenge not in redirect URL")
	}
	if !strings.Contains(redirectURL, "code_challenge_method=S256") {
		t.Fatal("PKCE code_challenge_method not in redirect URL")
	}

	// Peek at state to get nonce and verify verifier is stored.
	storedState, err := stateStore.Load(ctx, stateToken)
	assertNoError(t, err, "Load state")

	if storedState.PKCEVerifier == "" {
		t.Fatal("PKCE verifier not stored in state — will not survive round-trip")
	}

	// Re-save for Authenticate.
	err = stateStore.Save(ctx, storedState)
	assertNoError(t, err, "Re-save state")

	// Sign a matching id_token.
	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "pkce-user",
		Audience:  oauth.Audience{"pkce-client"},
		Nonce:     storedState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "pkce@test.com",
	}
	mu.Lock()
	dynamicIDToken = signTestIDToken(claims)
	mu.Unlock()

	// Authenticate (callback phase).
	cred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code-123",
			"state":    stateToken,
			"provider": "google",
		},
	}

	identity, err := oauthMode.Authenticate(ctx, cred)
	assertNoError(t, err, "Authenticate")

	if identity == nil {
		t.Fatal("Authenticate returned nil identity")
	}

	// STRICT: PKCE verifier MUST have been sent to the token endpoint.
	if capturedExchange.CodeVerifier == "" {
		t.Fatal("SECURITY: PKCE code_verifier was NOT sent in token exchange")
	}
	// Verify the captured verifier matches what was stored.
	if capturedExchange.CodeVerifier != storedState.PKCEVerifier {
		t.Fatal("PKCE code_verifier sent to token endpoint does not match stored verifier")
	}
	if capturedExchange.GrantType != "authorization_code" {
		t.Fatalf("expected grant_type=authorization_code, got %q", capturedExchange.GrantType)
	}
}

// --------------------------------------------------------------------------
// AUTH-0025 AC: Auto-register on first OAuth login
// AUTH-0025 AC: Existing user matched on second login
// --------------------------------------------------------------------------

func TestOAuthAutoRegisterAndRelogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	userStore := NewMemUserStore()

	initialCount := userStore.UserCount()
	if initialCount != 0 {
		t.Fatalf("expected 0 users initially, got %d", initialCount)
	}

	// First login — should auto-register.
	identity1 := doOAuthLogin(t, userStore, "auto-user-1", "autouser@gmail.com", "google")
	if identity1.SubjectID == "" {
		t.Fatal("first login: empty SubjectID")
	}

	afterFirstCount := userStore.UserCount()
	if afterFirstCount != 1 {
		t.Fatalf("expected 1 user after first OAuth login, got %d", afterFirstCount)
	}

	// Second login with same email — should match existing user, NOT create new.
	identity2 := doOAuthLogin(t, userStore, "auto-user-1", "autouser@gmail.com", "google")
	if identity2.SubjectID == "" {
		t.Fatal("second login: empty SubjectID")
	}

	afterSecondCount := userStore.UserCount()
	if afterSecondCount != 1 {
		t.Fatalf("SECURITY: expected 1 user after second OAuth login (reuse), got %d — duplicate created", afterSecondCount)
	}

	// SubjectID should be the same across logins.
	if identity1.SubjectID != identity2.SubjectID {
		t.Fatalf("expected same SubjectID across logins: got %q vs %q", identity1.SubjectID, identity2.SubjectID)
	}
}

// --------------------------------------------------------------------------
// AUTH-0025 AC: Multi-provider configured, both work
// --------------------------------------------------------------------------

func TestOAuthMultiProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	userStore := NewMemUserStore()

	// Login via "google".
	googleIdentity := doOAuthLogin(t, userStore, "google-sub", "user@gmail.com", "google")
	if googleIdentity.AuthMethod != "oauth2" {
		t.Fatalf("expected oauth2 for google, got %q", googleIdentity.AuthMethod)
	}
	googleProvider, _ := googleIdentity.Metadata["provider"].(string)
	if googleProvider != "google" {
		t.Fatalf("expected provider=google, got %q", googleProvider)
	}

	// Login via "github" with different email.
	githubIdentity := doOAuthLogin(t, userStore, "github-sub", "user@github.com", "github")
	if githubIdentity.AuthMethod != "oauth2" {
		t.Fatalf("expected oauth2 for github, got %q", githubIdentity.AuthMethod)
	}
	githubProvider, _ := githubIdentity.Metadata["provider"].(string)
	if githubProvider != "github" {
		t.Fatalf("expected provider=github, got %q", githubProvider)
	}

	// Both users exist.
	if userStore.UserCount() != 2 {
		t.Fatalf("expected 2 users after multi-provider login, got %d", userStore.UserCount())
	}
}

// --------------------------------------------------------------------------
// AUTH-0025 AC: Tampered state rejected
// --------------------------------------------------------------------------

func TestOAuthTamperedStateRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL := srv.URL
	t.Cleanup(srv.Close)

	// Register discovery handler BEFORE BuildAuthURL.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})

	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  userStore,
		StateStore: stateStore,
		HTTPClient: srv.Client(),
		Providers: []oauth.ProviderConfig{{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid"},
		}},
	})
	assertNoError(t, err, "oauth.NewMode")

	ctx := context.Background()

	// Build a valid auth URL (which stores state).
	_, _, err = oauthMode.BuildAuthURL(ctx, "google")
	assertNoError(t, err, "BuildAuthURL")

	// Attempt auth with tampered state — should fail.
	cred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "valid-code",
			"state":    "tampered-state-value-that-does-not-exist",
			"provider": "google",
		},
	}

	_, err = oauthMode.Authenticate(ctx, cred)
	if err == nil {
		t.Fatal("SECURITY: tampered state was accepted — expected rejection")
	}
	if !strings.Contains(err.Error(), "state") {
		t.Fatalf("expected state-related error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0025 AC: Session fixation prevention on OAuth login
// --------------------------------------------------------------------------

func TestOAuthSessionFixation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	var idpURL string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL = srv.URL
	t.Cleanup(srv.Close)

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "fixation:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithOAuthStateStore(stateStore),
		authsetup.WithOAuthHTTPClient(srv.Client()),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "fixation-client",
			ClientSecret: "fixation-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Create a pre-existing session (e.g., from an attacker).
	regIdentity, _, err := a.Engine.Register(ctx, passwordCred("victim@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register victim")
	preExistingSessionID := regIdentity.SessionID

	// Now do OAuth login through engine with pre-existing session ID.
	// First, build OAuth state manually.
	oauthState, _, err := oauth.GenerateState("google")
	assertNoError(t, err, "GenerateState")
	err = stateStore.Save(ctx, oauthState)
	assertNoError(t, err, "Save state")

	// Sign matching id_token.
	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "fixation-oauth-user",
		Audience:  oauth.Audience{"fixation-client"},
		Nonce:     oauthState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "oauth-fixation@test.com",
	}
	idToken := signTestIDToken(claims)

	// Set up mock endpoints.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id_token":     idToken,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Login via engine with existing_session_id.
	oauthCred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":                "fixation-code",
			"state":               oauthState.State,
			"provider":            "google",
			"existing_session_id": preExistingSessionID,
		},
	}

	loginIdentity, loginSess, err := a.Engine.Login(ctx, oauthCred)
	assertNoError(t, err, "OAuth Login")

	// STRICT: New session MUST have different ID from pre-existing one.
	if loginIdentity.SessionID == preExistingSessionID {
		t.Fatal("SECURITY: OAuth login reused pre-existing session ID — session fixation vulnerability")
	}
	if loginSess == nil {
		t.Fatal("expected non-nil session")
	}

	// Old session should be destroyed.
	_, err = a.Engine.Verify(ctx, preExistingSessionID)
	if err == nil {
		t.Fatal("SECURITY: pre-existing session still valid after OAuth login — fixation not prevented")
	}
}

// --------------------------------------------------------------------------
// AUTH-0025 AC: Auto-registered OAuth user cannot login via password
// --------------------------------------------------------------------------

func TestOAuthUserCannotPasswordLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	stateStore := newMemStateStore()

	var idpURL string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL = srv.URL
	t.Cleanup(srv.Close)

	// Build OAuth state.
	oauthState, _, err := oauth.GenerateState("google")
	assertNoError(t, err, "GenerateState")
	err = stateStore.Save(context.Background(), oauthState)
	assertNoError(t, err, "Save state")

	// Sign id_token.
	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   "oauth-only-user",
		Audience:  oauth.Audience{"crossmode-client"},
		Nonce:     oauthState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     "oauthonly@test.com",
	}
	idToken := signTestIDToken(claims)

	// Set up mock endpoints.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id_token":     idToken,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "crossmode:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithOAuthStateStore(stateStore),
		authsetup.WithOAuthHTTPClient(srv.Client()),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			IssuerURL:    idpURL,
			ClientID:     "crossmode-client",
			ClientSecret: "crossmode-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// OAuth login — auto-registers the user.
	oauthCred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "some-code",
			"state":    oauthState.State,
			"provider": "google",
		},
	}

	oauthIdentity, _, err := a.Engine.Login(ctx, oauthCred)
	assertNoError(t, err, "OAuth Login")

	if oauthIdentity.SubjectID == "" {
		t.Fatal("OAuth login returned empty SubjectID")
	}

	// STRICT: The auto-registered user has empty password hash.
	user := userStore.GetUser("oauthonly@test.com")
	if user == nil {
		t.Fatal("OAuth user not found in user store")
	}
	if user.GetPasswordHash() != "" {
		t.Fatal("SECURITY: OAuth auto-registered user has non-empty password hash")
	}

	// Attempt password login with same identifier — MUST fail.
	_, _, err = a.Engine.Login(ctx, passwordCred("oauthonly@test.com", "AnyPassword123!"))
	if err == nil {
		t.Fatal("SECURITY: password login succeeded for OAuth-only user — expected ErrInvalidCredentials")
	}
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// Helper: doOAuthLogin performs a complete OAuth login flow end-to-end.
// --------------------------------------------------------------------------

func doOAuthLogin(t *testing.T, userStore *MemUserStore, subject, email, providerName string) *auth.Identity {
	t.Helper()

	stateStore := newMemStateStore()

	var mu sync.Mutex
	var dynamicIDToken string

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL := srv.URL
	t.Cleanup(srv.Close)

	// Register handlers BEFORE any OAuth operation.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := map[string]string{
			"issuer":                 idpURL,
			"authorization_endpoint": idpURL + "/authorize",
			"token_endpoint":         idpURL + "/token",
			"jwks_uri":               idpURL + "/jwks",
			"userinfo_endpoint":      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKSJSON())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tok := dynamicIDToken
		mu.Unlock()

		resp := map[string]any{
			"id_token":     tok,
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	oauthMode, err := oauth.NewMode(oauth.Config{
		UserStore:  userStore,
		StateStore: stateStore,
		HTTPClient: srv.Client(),
		Providers: []oauth.ProviderConfig{{
			Name:         providerName,
			IssuerURL:    idpURL,
			ClientID:     providerName + "-client",
			ClientSecret: providerName + "-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "email"},
		}},
	})
	assertNoError(t, err, "oauth.NewMode")

	ctx := context.Background()

	// BuildAuthURL.
	_, stateToken, err := oauthMode.BuildAuthURL(ctx, providerName)
	assertNoError(t, err, "BuildAuthURL")

	// Peek at state for nonce.
	storedState, err := stateStore.Load(ctx, stateToken)
	assertNoError(t, err, "Load state")
	err = stateStore.Save(ctx, storedState)
	assertNoError(t, err, "Re-save state")

	// Sign id_token.
	now := time.Now()
	claims := oauth.IDTokenClaims{
		Issuer:    idpURL,
		Subject:   subject,
		Audience:  oauth.Audience{providerName + "-client"},
		Nonce:     storedState.Nonce,
		ExpiresAt: now.Add(10 * time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		Email:     email,
	}
	mu.Lock()
	dynamicIDToken = signTestIDToken(claims)
	mu.Unlock()

	// Authenticate.
	cred := auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    stateToken,
			"provider": providerName,
		},
	}

	identity, err := oauthMode.Authenticate(ctx, cred)
	assertNoError(t, err, "Authenticate")

	if identity == nil {
		t.Fatal("Authenticate returned nil identity")
	}

	return identity
}
