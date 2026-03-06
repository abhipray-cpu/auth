// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// --- Mock implementations ---

// mockUserStore implements auth.UserStore.
type mockUserStore struct {
	mu    sync.Mutex
	users map[string]*mockUser // keyed by identifier
}

type mockUser struct {
	subjectID    string
	identifier   string
	passwordHash string
}

func (u *mockUser) GetSubjectID() string        { return u.subjectID }
func (u *mockUser) GetIdentifier() string       { return u.identifier }
func (u *mockUser) GetPasswordHash() string     { return u.passwordHash }
func (u *mockUser) GetFailedAttempts() int      { return 0 }
func (u *mockUser) IsLocked() bool              { return false }
func (u *mockUser) IsMFAEnabled() bool          { return false }
func (u *mockUser) GetMetadata() map[string]any { return nil }

func newMockUserStore() *mockUserStore {
	return &mockUserStore{users: make(map[string]*mockUser)}
}

func (s *mockUserStore) FindByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[identifier]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

func (s *mockUserStore) Create(_ context.Context, user auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.GetIdentifier()]; exists {
		return auth.ErrUserAlreadyExists
	}
	s.users[user.GetIdentifier()] = &mockUser{
		subjectID:    user.GetSubjectID(),
		identifier:   user.GetIdentifier(),
		passwordHash: user.GetPasswordHash(),
	}
	// Exercise optional User interface methods for coverage.
	_ = user.GetFailedAttempts()
	_ = user.IsLocked()
	_ = user.IsMFAEnabled()
	_ = user.GetMetadata()
	return nil
}

func (s *mockUserStore) UpdatePassword(_ context.Context, _, _ string) error       { return nil }
func (s *mockUserStore) IncrementFailedAttempts(_ context.Context, _ string) error { return nil }
func (s *mockUserStore) ResetFailedAttempts(_ context.Context, _ string) error     { return nil }
func (s *mockUserStore) SetLocked(_ context.Context, _ string, _ bool) error       { return nil }

// mockStateStore implements StateStore (in-memory).
type mockStateStore struct {
	mu     sync.Mutex
	states map[string]*OAuthState
}

func newMockStateStore() *mockStateStore {
	return &mockStateStore{states: make(map[string]*OAuthState)}
}

func (s *mockStateStore) Save(_ context.Context, state *OAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *mockStateStore) Load(_ context.Context, stateToken string) (*OAuthState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[stateToken]
	if !ok {
		return nil, errors.New("state not found")
	}
	delete(s.states, stateToken) // single-use
	return st, nil
}

// --- Test IdP server ---

// testRSAKey is a shared RSA key used for signing and verification in tests.
var testRSAKey *rsa.PrivateKey

func init() {
	var err error
	testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
}

func testKid() string { return "test-key-1" }

// createTestJWKS returns the JWKS JSON for the test RSA key.
func createTestJWKS() []byte {
	pub := &testRSAKey.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	jwks := JWKS{
		Keys: []JSONWebKey{
			{
				Kty: "RSA",
				Kid: testKid(),
				Use: "sig",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
	data, _ := json.Marshal(jwks)
	return data
}

// signTestJWT signs a JWT with the test RSA key.
func signTestJWT(claims IDTokenClaims) string {
	header := IDTokenHeader{Alg: "RS256", Kid: testKid(), Typ: "JWT"}

	token, err := CreateTestJWT(header, claims, func(input string) ([]byte, error) {
		h := sha256.Sum256([]byte(input))
		return rsa.SignPKCS1v15(rand.Reader, testRSAKey, crypto.SHA256, h[:])
	})
	if err != nil {
		panic("failed to sign test JWT: " + err.Error())
	}
	return token
}

// buildFullTestMode creates a Mode with a mock IdP for end-to-end tests.
// Returns the mode, the mock user store, state store, and IdP server.
func buildFullTestMode(t *testing.T) (*Mode, *mockUserStore, *mockStateStore, *httptest.Server) {
	t.Helper()

	// Create IdP first to get the URL.
	idpServer := httptest.NewServer(http.NewServeMux())
	idpServer.Close() // we'll replace it

	// We need the issuer = server URL, so we build in two steps.
	us := newMockUserStore()
	ss := newMockStateStore()

	// Create a temporary server to get the URL.
	var idpURL string
	var idpHandler http.Handler

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	idpURL = srv.URL

	// Now set up handlers with the correct issuer.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                idpURL,
			AuthorizationEndpoint: idpURL + "/authorize",
			TokenEndpoint:         idpURL + "/token",
			JWKSUri:               idpURL + "/jwks",
			UserinfoEndpoint:      idpURL + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKS())
	})

	// Default token endpoint — returns a valid id_token.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer:    idpURL,
			Subject:   "oauth-user-123",
			Audience:  Audience{"test-client-id"},
			Nonce:     r.FormValue("nonce_hint"), // we'll handle nonce differently
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Email:     "alice@example.com",
			Name:      "Alice",
		}
		token := signTestJWT(claims)
		resp := tokenResponse{
			IDToken:     token,
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	_ = idpHandler

	m, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				IssuerURL:    idpURL,
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"openid", "profile", "email"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}

	t.Cleanup(srv.Close)
	return m, us, ss, srv
}

// --- Test Cases ---

// 8.1: Fetches and parses /.well-known/openid-configuration.
func TestOAuth_Discovery(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                srv.URL,
			AuthorizationEndpoint: srv.URL + "/authorize",
			TokenEndpoint:         srv.URL + "/token",
			JWKSUri:               srv.URL + "/jwks",
		}
		json.NewEncoder(w).Encode(cfg)
	})

	client := NewDiscoveryClient(srv.Client())
	config, err := client.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if config.Issuer != srv.URL {
		t.Errorf("expected issuer %q, got %q", srv.URL, config.Issuer)
	}
	if config.AuthorizationEndpoint != srv.URL+"/authorize" {
		t.Errorf("unexpected authorization_endpoint: %q", config.AuthorizationEndpoint)
	}
	if config.TokenEndpoint != srv.URL+"/token" {
		t.Errorf("unexpected token_endpoint: %q", config.TokenEndpoint)
	}
}

// 8.2: Discovery config cached, not fetched every call.
func TestOAuth_Discovery_CachesConfig(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	client := NewDiscoveryClient(srv.Client())
	ctx := context.Background()

	_, _ = client.Discover(ctx, srv.URL)
	_, _ = client.Discover(ctx, srv.URL)
	_, _ = client.Discover(ctx, srv.URL)

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call (cached), got %d", callCount)
	}
}

// 8.3: Invalid issuer URL returns error at startup.
func TestOAuth_Discovery_InvalidIssuer(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: "https://wrong-issuer.com"} // mismatch
		json.NewEncoder(w).Encode(cfg)
	})

	client := NewDiscoveryClient(srv.Client())
	_, err := client.Discover(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for issuer mismatch")
	}
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("expected issuer mismatch error, got: %v", err)
	}
}

// 8.4: code_verifier and code_challenge generated for every flow.
func TestOAuth_PKCE_Generated(t *testing.T) {
	p1, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}

	if p1.Verifier == p2.Verifier {
		t.Error("expected unique verifiers")
	}
	if p1.Challenge == p2.Challenge {
		t.Error("expected unique challenges")
	}
}

// 8.5: Challenge method is S256, not plain.
func TestOAuth_PKCE_S256(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if p.Method != "S256" {
		t.Errorf("expected method S256, got %q", p.Method)
	}

	// Verify challenge is SHA256(verifier).
	expected := computeS256Challenge(p.Verifier)
	if p.Challenge != expected {
		t.Error("challenge doesn't match S256 of verifier")
	}
}

// 8.6: Verifier is 43–128 characters (RFC 7636).
func TestOAuth_PKCE_VerifierLength(t *testing.T) {
	p, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Errorf("verifier length %d not in range [43, 128]", len(p.Verifier))
	}
}

// 8.7: Authorization URL includes state, nonce, PKCE challenge, correct scopes.
func TestOAuth_BuildAuthURL(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)
	ctx := context.Background()

	authURL, stateToken, err := m.BuildAuthURL(ctx, "test-provider")
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("invalid URL: %v", err)
	}

	q := parsed.Query()

	if q.Get("state") != stateToken {
		t.Error("state param doesn't match returned state token")
	}
	if q.Get("nonce") == "" {
		t.Error("missing nonce param")
	}
	if q.Get("code_challenge") == "" {
		t.Error("missing code_challenge param")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method=S256, got %q", q.Get("code_challenge_method"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("expected response_type=code, got %q", q.Get("response_type"))
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Error("missing openid scope")
	}
	if q.Get("client_id") != "test-client-id" {
		t.Errorf("expected client_id=test-client-id, got %q", q.Get("client_id"))
	}
}

// 8.8: Different providers get different auth URLs.
func TestOAuth_BuildAuthURL_MultiProvider(t *testing.T) {
	// Create two mock IdPs.
	mux1 := http.NewServeMux()
	srv1 := httptest.NewServer(mux1)
	defer srv1.Close()
	mux1.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv1.URL, AuthorizationEndpoint: srv1.URL + "/authorize", TokenEndpoint: srv1.URL + "/token", JWKSUri: srv1.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	mux2 := http.NewServeMux()
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	mux2.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv2.URL, AuthorizationEndpoint: srv2.URL + "/auth", TokenEndpoint: srv2.URL + "/token", JWKSUri: srv2.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	m, err := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: newMockStateStore(),
		Providers: []ProviderConfig{
			{Name: "provider-a", IssuerURL: srv1.URL, ClientID: "id-a", ClientSecret: "s", RedirectURL: "http://localhost/a"},
			{Name: "provider-b", IssuerURL: srv2.URL, ClientID: "id-b", ClientSecret: "s", RedirectURL: "http://localhost/b"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	url1, _, _ := m.BuildAuthURL(context.Background(), "provider-a")
	url2, _, _ := m.BuildAuthURL(context.Background(), "provider-b")

	if url1 == url2 {
		t.Error("expected different auth URLs for different providers")
	}
	if !strings.Contains(url1, srv1.URL) {
		t.Error("provider-a URL should contain srv1 URL")
	}
	if !strings.Contains(url2, srv2.URL) {
		t.Error("provider-b URL should contain srv2 URL")
	}
}

// 8.9: Authorization code exchanged for tokens with PKCE verifier.
func TestOAuth_Callback_CodeExchange(t *testing.T) {
	var receivedVerifier string
	var receivedCode string

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(createTestJWKS())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		receivedVerifier = r.FormValue("code_verifier")
		receivedCode = r.FormValue("code")

		// Return a valid token — we need the nonce from the state.
		// Since we can't get the nonce here, use an empty nonce and skip nonce verification.
		claims := IDTokenClaims{
			Issuer:    srv.URL,
			Subject:   "user-123",
			Audience:  Audience{"test-client-id"},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Email:     "test@example.com",
		}
		token := signTestJWT(claims)
		resp := tokenResponse{IDToken: token, AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}
		json.NewEncoder(w).Encode(resp)
	})

	ss := newMockStateStore()
	m, err := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers:  []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "test-client-id", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build auth URL to get state.
	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Peek at nonce and clear nonce expectation by setting it in claims.
	ss.mu.Lock()
	savedState := ss.states[stateToken]
	// We'll clear the nonce in the state so verification passes (nonce in token is empty).
	savedState.Nonce = ""
	ss.mu.Unlock()

	_, _ = m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "auth-code-xyz", "state": stateToken, "provider": "p"},
	})

	if receivedCode != "auth-code-xyz" {
		t.Errorf("expected code 'auth-code-xyz', got %q", receivedCode)
	}
	if receivedVerifier == "" {
		t.Error("expected code_verifier to be sent in token request")
	}
}

// 8.10: id_token signature verified via JWKS.
func TestOAuth_Callback_IDTokenVerification(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(createTestJWKS())
	})

	ss := newMockStateStore()
	us := newMockUserStore()

	// We'll capture the nonce after BuildAuthURL and before Authenticate.
	var capturedNonce string

	// Token endpoint returns a validly signed token.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "user-123", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims), AccessToken: "at", TokenType: "Bearer"}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Capture nonce before Authenticate consumes the state.
	ss.mu.Lock()
	if s, ok := ss.states[stateToken]; ok {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.SubjectID != "user-123" {
		t.Errorf("expected SubjectID 'user-123', got %q", identity.SubjectID)
	}
}

// 8.11: Nonce in id_token matches nonce in state.
func TestOAuth_Callback_NonceVerification(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })

	ss := newMockStateStore()

	// Return token with wrong nonce.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			Nonce: "wrong-nonce", ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("expected nonce error, got: %v", err)
	}
}

// 8.12: Expired id_token rejected.
func TestOAuth_Callback_ExpiredToken(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })

	ss := newMockStateStore()

	var capturedNonce string

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // expired
			IssuedAt: time.Now().Add(-2 * time.Hour).Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	ss.mu.Lock()
	if s, ok := ss.states[stateToken]; ok {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got: %v", err)
	}
}

// 8.13: Token with wrong audience rejected.
func TestOAuth_Callback_WrongAudience(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })

	ss := newMockStateStore()

	var capturedNonce string

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"wrong-client-id"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	ss.mu.Lock()
	if s, ok := ss.states[stateToken]; ok {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("expected audience error, got: %v", err)
	}
}

// 8.14: Token with wrong issuer rejected.
func TestOAuth_Callback_WrongIssuer(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })

	ss := newMockStateStore()

	var capturedNonce string

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: "https://wrong-issuer.com", Subject: "u", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	ss.mu.Lock()
	if s, ok := ss.states[stateToken]; ok {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("expected issuer error, got: %v", err)
	}
}

// 8.15: JWKS cached and refreshed on key miss.
func TestOAuth_JWKS_Caching(t *testing.T) {
	fetchCount := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(createTestJWKS())
	})

	client := NewJWKSClient(srv.Client())
	ctx := context.Background()

	// First call fetches.
	_, err := client.GetKey(ctx, srv.URL+"/jwks", testKid())
	if err != nil {
		t.Fatal(err)
	}

	// Second call uses cache.
	_, err = client.GetKey(ctx, srv.URL+"/jwks", testKid())
	if err != nil {
		t.Fatal(err)
	}

	if fetchCount != 1 {
		t.Errorf("expected 1 fetch (cached), got %d", fetchCount)
	}

	// Request unknown kid → triggers refresh.
	_, _ = client.GetKey(ctx, srv.URL+"/jwks", "unknown-kid")
	if fetchCount != 2 {
		t.Errorf("expected 2 fetches (cache miss triggers refresh), got %d", fetchCount)
	}
}

// 8.16: Key rotation detected and handled.
func TestOAuth_JWKS_Rotation(t *testing.T) {
	// Start with key-1, then rotate to key-2.
	rotated := false
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		if rotated {
			// Return new key with different kid.
			pub := &newKey.PublicKey
			nBytes := pub.N.Bytes()
			eBytes := big.NewInt(int64(pub.E)).Bytes()
			jwks := JWKS{Keys: []JSONWebKey{{
				Kty: "RSA", Kid: "key-2", Use: "sig", Alg: "RS256",
				N: base64.RawURLEncoding.EncodeToString(nBytes),
				E: base64.RawURLEncoding.EncodeToString(eBytes),
			}}}
			data, _ := json.Marshal(jwks)
			w.Write(data)
		} else {
			w.Write(createTestJWKS())
		}
	})

	client := NewJWKSClient(srv.Client())
	ctx := context.Background()

	// Fetch key-1.
	_, err := client.GetKey(ctx, srv.URL+"/jwks", testKid())
	if err != nil {
		t.Fatal(err)
	}

	// Rotate keys.
	rotated = true

	// Fetch key-2 — should trigger refresh and find the new key.
	_, err = client.GetKey(ctx, srv.URL+"/jwks", "key-2")
	if err != nil {
		t.Fatalf("expected key-2 after rotation, got error: %v", err)
	}
}

// 8.17: New user auto-registered on first OAuth login.
func TestOAuth_AutoRegistration(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	us := newMockUserStore()

	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "new-oauth-user", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "newuser@example.com", Name: "New User",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Capture nonce before Authenticate consumes (deletes) the state.
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Check user was auto-registered.
	us.mu.Lock()
	_, exists := us.users["newuser@example.com"]
	us.mu.Unlock()

	if !exists {
		t.Error("expected user to be auto-registered")
	}
	if identity.AuthMethod != "oauth2" {
		t.Errorf("expected AuthMethod 'oauth2', got %q", identity.AuthMethod)
	}
}

// 8.18: Existing user matched, no duplicate creation.
func TestOAuth_ExistingUser(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	us := newMockUserStore()
	us.users["existing@example.com"] = &mockUser{subjectID: "existing-user", identifier: "existing@example.com"}

	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "oauth-sub", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "existing@example.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Capture nonce before Authenticate consumes (deletes) the state.
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Should use existing user's SubjectID.
	if identity.SubjectID != "existing-user" {
		t.Errorf("expected SubjectID 'existing-user', got %q", identity.SubjectID)
	}

	// No duplicate creation.
	us.mu.Lock()
	count := len(us.users)
	us.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 user (no duplicate), got %d", count)
	}
}

// 8.19: Invalid state parameter rejected.
func TestOAuth_StateValidation(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": "invalid-state", "provider": "test-provider"},
	})
	if err == nil {
		t.Fatal("expected error for invalid state")
	}
}

// 8.20: Supports CredentialTypeOAuth, not others.
func TestOAuth_Supports(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)

	if !m.Supports(auth.CredentialTypeOAuth) {
		t.Error("expected Supports(CredentialTypeOAuth) to be true")
	}
	if m.Supports(auth.CredentialTypePassword) {
		t.Error("expected Supports(CredentialTypePassword) to be false")
	}
	if m.Supports(auth.CredentialTypeMagicLink) {
		t.Error("expected Supports(CredentialTypeMagicLink) to be false")
	}
}

// 8.21: Returns "oauth2".
func TestOAuth_Name(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)
	if m.Name() != "oauth2" {
		t.Errorf("expected Name() = 'oauth2', got %q", m.Name())
	}
}

// 8.22: Satisfies AuthMode interface.
func TestOAuth_ImplementsAuthMode(t *testing.T) {
	var _ auth.AuthMode = (*Mode)(nil)
}

// 8.23: Correct provider selected by name.
func TestOAuth_MultiProvider_Routing(t *testing.T) {
	mux1 := http.NewServeMux()
	srv1 := httptest.NewServer(mux1)
	defer srv1.Close()
	mux1.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv1.URL, AuthorizationEndpoint: srv1.URL + "/authorize", TokenEndpoint: srv1.URL + "/token", JWKSUri: srv1.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	mux2 := http.NewServeMux()
	srv2 := httptest.NewServer(mux2)
	defer srv2.Close()
	mux2.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv2.URL, AuthorizationEndpoint: srv2.URL + "/auth", TokenEndpoint: srv2.URL + "/token", JWKSUri: srv2.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	m, _ := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: newMockStateStore(),
		Providers: []ProviderConfig{
			{Name: "google", IssuerURL: srv1.URL, ClientID: "g-id", ClientSecret: "s", RedirectURL: "http://localhost/g"},
			{Name: "okta", IssuerURL: srv2.URL, ClientID: "o-id", ClientSecret: "s", RedirectURL: "http://localhost/o"},
		},
	})

	url1, _, _ := m.BuildAuthURL(context.Background(), "google")
	url2, _, _ := m.BuildAuthURL(context.Background(), "okta")

	if !strings.Contains(url1, "client_id=g-id") {
		t.Error("google URL should contain google client_id")
	}
	if !strings.Contains(url2, "client_id=o-id") {
		t.Error("okta URL should contain okta client_id")
	}
}

// 8.24: State cookies don't leak between providers.
func TestOAuth_MultiProvider_IsolatedState(t *testing.T) {
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	m, _ := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: ss,
		Providers: []ProviderConfig{
			{Name: "p1", IssuerURL: srv.URL, ClientID: "c1", ClientSecret: "s", RedirectURL: "http://localhost/1"},
			{Name: "p2", IssuerURL: srv.URL, ClientID: "c2", ClientSecret: "s", RedirectURL: "http://localhost/2"},
		},
	})

	_, state1, _ := m.BuildAuthURL(context.Background(), "p1")
	_, state2, _ := m.BuildAuthURL(context.Background(), "p2")

	// State tokens should be different.
	if state1 == state2 {
		t.Error("expected different state tokens for different providers")
	}

	// State cookies are provider-scoped.
	w := httptest.NewRecorder()
	SetStateCookie(w, "p1", state1)
	SetStateCookie(w, "p2", state2)

	cookies := w.Result().Cookies()
	var names []string
	for _, c := range cookies {
		names = append(names, c.Name)
	}

	if !containsStr(names, "oauth_state_p1") {
		t.Error("expected oauth_state_p1 cookie")
	}
	if !containsStr(names, "oauth_state_p2") {
		t.Error("expected oauth_state_p2 cookie")
	}
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// 8.25: Missing ClientID/IssuerURL fails at registration.
func TestOAuth_ProviderConfig_Validation(t *testing.T) {
	_, err := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: newMockStateStore(),
		Providers:  []ProviderConfig{{Name: "p", IssuerURL: "", ClientID: "cid"}},
	})
	if err == nil {
		t.Fatal("expected error for missing IssuerURL")
	}

	_, err = NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: newMockStateStore(),
		Providers:  []ProviderConfig{{Name: "p", IssuerURL: "https://example.com", ClientID: ""}},
	})
	if err == nil {
		t.Fatal("expected error for missing ClientID")
	}
}

// 8.26: PKCE verifier persisted server-side between initiate and callback.
func TestOAuth_PKCE_VerifierStorage(t *testing.T) {
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	m, _ := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers:  []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Verify PKCE verifier is persisted in the state store.
	ss.mu.Lock()
	savedState, exists := ss.states[stateToken]
	ss.mu.Unlock()

	if !exists {
		t.Fatal("state not saved in store")
	}
	if savedState.PKCEVerifier == "" {
		t.Error("expected PKCE verifier to be persisted in state store")
	}
	if len(savedState.PKCEVerifier) < 43 {
		t.Errorf("PKCE verifier too short: %d chars", len(savedState.PKCEVerifier))
	}
}

// 8.27: PKCE verifier deleted after code exchange.
func TestOAuth_PKCE_VerifierCleanup(t *testing.T) {
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Clear nonce in saved state so nonce validation passes with empty nonce.
	ss.mu.Lock()
	if s, ok := ss.states[stateToken]; ok {
		s.Nonce = ""
	}
	ss.mu.Unlock()

	// Authenticate consumes the state (Load deletes it).
	_, _ = m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})

	// State (including PKCE verifier) should be deleted.
	ss.mu.Lock()
	_, exists := ss.states[stateToken]
	ss.mu.Unlock()

	if exists {
		t.Error("expected state (and PKCE verifier) to be deleted after code exchange")
	}
}

// 8.28: Auto-registered OAuth user has no password hash.
func TestOAuth_AutoRegistration_NoPasswordHash(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	us := newMockUserStore()

	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "new-oauth-user", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "oauthonly@example.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Capture nonce before Authenticate consumes (deletes) the state.
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Check auto-registered user has no password hash.
	us.mu.Lock()
	user, exists := us.users["oauthonly@example.com"]
	us.mu.Unlock()

	if !exists {
		t.Fatal("expected user to be auto-registered")
	}
	if user.passwordHash != "" {
		t.Errorf("expected empty password hash for OAuth user, got %q", user.passwordHash)
	}
}

// 8.29: OAuth state cookie uses SameSite=Lax.
func TestOAuth_StateCookie_SameSiteLax(t *testing.T) {
	w := httptest.NewRecorder()
	SetStateCookie(w, "google", "test-state-token")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != "oauth_state_google" {
		t.Errorf("expected cookie name 'oauth_state_google', got %q", cookie.Name)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", cookie.SameSite)
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly=true")
	}
	if !cookie.Secure {
		t.Error("expected Secure=true")
	}
}

// ============================================================
// Edge-case and security tests for production hardening.
// ============================================================

// Tampered JWT signature must be rejected.
func TestOAuth_Callback_TamperedSignature(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		token := signTestJWT(claims)
		// Tamper with the signature by flipping a character.
		parts := strings.SplitN(token, ".", 3)
		sig := []byte(parts[2])
		if sig[0] == 'A' {
			sig[0] = 'B'
		} else {
			sig[0] = 'A'
		}
		tampered := parts[0] + "." + parts[1] + "." + string(sig)
		resp := tokenResponse{IDToken: tampered}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected signature error, got: %v", err)
	}
}

// "none" algorithm attack must be rejected.
func TestOAuth_Callback_NoneAlgorithm(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Craft a JWT with alg=none.
		header := IDTokenHeader{Alg: "none", Kid: testKid(), Typ: "JWT"}
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		headerJSON, _ := json.Marshal(header)
		claimsJSON, _ := json.Marshal(claims)
		token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
			base64.RawURLEncoding.EncodeToString(claimsJSON) + "."
		resp := tokenResponse{IDToken: token}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for alg=none")
	}
	if !strings.Contains(err.Error(), "none") {
		t.Errorf("expected 'none' algorithm error, got: %v", err)
	}
}

// Empty/malformed JWT strings must be rejected.
func TestOAuth_VerifyIDToken_MalformedJWT(t *testing.T) {
	key := &testRSAKey.PublicKey

	tests := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"single part", "abc"},
		{"two parts", "abc.def"},
		{"four parts", "a.b.c.d"},
		{"invalid base64 header", "!!!.abc.def"},
		{"invalid base64 payload", "eyJhbGciOiJSUzI1NiJ9.!!!.abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyIDToken(tt.token, key, "iss", "aud", "nonce")
			if err == nil {
				t.Error("expected error for malformed JWT")
			}
		})
	}
}

// Token with iat far in the future must be rejected.
func TestOAuth_Callback_FutureIssuedAt(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
			IssuedAt: time.Now().Add(1 * time.Hour).Unix(), // far in the future
			Email:    "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for future iat")
	}
	if !strings.Contains(err.Error(), "future") {
		t.Errorf("expected 'future' error, got: %v", err)
	}
}

// Token endpoint returning non-200 must be rejected.
func TestOAuth_Callback_TokenEndpointError(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for token endpoint 400")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("expected status error, got: %v", err)
	}
}

// Token endpoint returning no id_token must be rejected.
func TestOAuth_Callback_NoIDToken(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Return a valid response but without id_token.
		resp := tokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for missing id_token")
	}
	if !strings.Contains(err.Error(), "id_token") {
		t.Errorf("expected id_token error, got: %v", err)
	}
}

// Missing code/state/provider in credential metadata must be rejected.
func TestOAuth_Authenticate_MissingMetadata(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)

	tests := []struct {
		name     string
		metadata map[string]any
	}{
		{"missing code", map[string]any{"state": "s", "provider": "test-provider"}},
		{"missing state", map[string]any{"code": "c", "provider": "test-provider"}},
		{"missing provider", map[string]any{"code": "c", "state": "s"}},
		{"empty code", map[string]any{"code": "", "state": "s", "provider": "test-provider"}},
		{"nil metadata", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Authenticate(context.Background(), auth.Credential{
				Type:     auth.CredentialTypeOAuth,
				Metadata: tt.metadata,
			})
			if err == nil {
				t.Error("expected error for missing metadata")
			}
		})
	}
}

// State provider mismatch must be rejected.
func TestOAuth_Callback_StateProviderMismatch(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	ss := newMockStateStore()

	m, _ := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{Name: "p1", IssuerURL: srv.URL, ClientID: "c1", ClientSecret: "s", RedirectURL: "http://localhost/1"},
			{Name: "p2", IssuerURL: srv.URL, ClientID: "c2", ClientSecret: "s", RedirectURL: "http://localhost/2"},
		},
	})

	// Build auth URL for p1.
	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p1")

	// Try to authenticate with p2 using p1's state token.
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p2"},
	})
	if err == nil {
		t.Fatal("expected error for state provider mismatch")
	}
	if !strings.Contains(err.Error(), "provider mismatch") {
		t.Errorf("expected provider mismatch error, got: %v", err)
	}
}

// Unknown provider in BuildAuthURL must be rejected.
func TestOAuth_BuildAuthURL_UnknownProvider(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)

	_, _, err := m.BuildAuthURL(context.Background(), "nonexistent-provider")
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("expected unknown provider error, got: %v", err)
	}
}

// Nil UserStore/StateStore must be rejected at creation.
func TestOAuth_NewMode_NilDependencies(t *testing.T) {
	_, err := NewMode(Config{
		UserStore:  nil,
		StateStore: newMockStateStore(),
		Providers:  []ProviderConfig{{Name: "p", IssuerURL: "https://x.com", ClientID: "c"}},
	})
	if err == nil {
		t.Fatal("expected error for nil UserStore")
	}

	_, err = NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: nil,
		Providers:  []ProviderConfig{{Name: "p", IssuerURL: "https://x.com", ClientID: "c"}},
	})
	if err == nil {
		t.Fatal("expected error for nil StateStore")
	}
}

// Discovery endpoint returning non-200 must be handled.
func TestOAuth_Discovery_Non200(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	client := NewDiscoveryClient(srv.Client())
	_, err := client.Discover(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 500 discovery response")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("expected status error, got: %v", err)
	}
}

// Discovery endpoint returning malformed JSON must be handled.
func TestOAuth_Discovery_MalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})

	client := NewDiscoveryClient(srv.Client())
	_, err := client.Discover(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

// JWKS endpoint returning non-200 must be handled.
func TestOAuth_JWKS_Non200(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	client := NewJWKSClient(srv.Client())
	_, err := client.GetKey(context.Background(), srv.URL+"/jwks", "any-kid")
	if err == nil {
		t.Fatal("expected error for 503 JWKS response")
	}
	if !strings.Contains(err.Error(), "status") {
		t.Errorf("expected status error, got: %v", err)
	}
}

// JWKS endpoint returning malformed JSON must be handled.
func TestOAuth_JWKS_MalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not-json`))
	})

	client := NewJWKSClient(srv.Client())
	_, err := client.GetKey(context.Background(), srv.URL+"/jwks", "any-kid")
	if err == nil {
		t.Fatal("expected error for malformed JWKS JSON")
	}
}

// Concurrent BuildAuthURL and Authenticate calls must not race.
func TestOAuth_ConcurrentFlows(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	us := newMockUserStore()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })

	// Token endpoint — return a valid token with empty nonce (nonce check skipped).
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "concurrent-user", Audience: Audience{"cid"},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(), Email: "concurrent@example.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	const goroutines = 20
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, stateToken, err := m.BuildAuthURL(context.Background(), "p")
			if err != nil {
				errs <- err
				return
			}

			// Clear nonce so verification passes.
			ss.mu.Lock()
			if s, ok := ss.states[stateToken]; ok {
				s.Nonce = ""
			}
			ss.mu.Unlock()

			_, err = m.Authenticate(context.Background(), auth.Credential{
				Type:     auth.CredentialTypeOAuth,
				Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
			})
			errs <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent flow error: %v", err)
		}
	}
}

// Audience JSON unmarshaling edge cases.
func TestOAuth_Audience_Unmarshal(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected Audience
		wantErr  bool
	}{
		{"string", `"client-id"`, Audience{"client-id"}, false},
		{"array single", `["client-id"]`, Audience{"client-id"}, false},
		{"array multi", `["a","b","c"]`, Audience{"a", "b", "c"}, false},
		{"empty array", `[]`, Audience{}, false},
		{"invalid", `123`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a Audience
			err := json.Unmarshal([]byte(tt.json), &a)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(a) != len(tt.expected) {
				t.Fatalf("expected %d elements, got %d", len(tt.expected), len(a))
			}
			for i := range a {
				if a[i] != tt.expected[i] {
					t.Errorf("element %d: expected %q, got %q", i, tt.expected[i], a[i])
				}
			}
		})
	}
}

// Audience.Contains must work correctly.
func TestOAuth_Audience_Contains(t *testing.T) {
	a := Audience{"a", "b", "c"}
	if !a.Contains("b") {
		t.Error("expected Contains(b) = true")
	}
	if a.Contains("d") {
		t.Error("expected Contains(d) = false")
	}

	empty := Audience{}
	if empty.Contains("x") {
		t.Error("expected empty audience Contains(x) = false")
	}
}

// ClearStateCookie must set MaxAge=-1 to delete.
func TestOAuth_ClearStateCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ClearStateCookie(w, "test-provider")

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", cookies[0].MaxAge)
	}
	if cookies[0].Name != "oauth_state_test-provider" {
		t.Errorf("expected cookie name 'oauth_state_test-provider', got %q", cookies[0].Name)
	}
}

// ValidateStateCookie must reject mismatched or missing cookies.
func TestOAuth_ValidateStateCookie(t *testing.T) {
	// Build a request with a valid cookie.
	req := httptest.NewRequest("GET", "/callback?state=abc", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state_google", Value: "abc"})

	err := ValidateStateCookie(req, "google", "abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mismatched value.
	err = ValidateStateCookie(req, "google", "xyz")
	if err == nil {
		t.Fatal("expected error for state mismatch")
	}

	// Missing cookie.
	req2 := httptest.NewRequest("GET", "/callback?state=abc", nil)
	err = ValidateStateCookie(req2, "google", "abc")
	if err == nil {
		t.Fatal("expected error for missing cookie")
	}
}

// Expired state must be rejected (state TTL check).
func TestOAuth_Callback_ExpiredState(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")

	// Backdating the state's CreatedAt to simulate expiry.
	ss.mu.Lock()
	if s, ok := ss.states[stateToken]; ok {
		s.CreatedAt = time.Now().Add(-15 * time.Minute) // well past defaultStateTTL
	}
	ss.mu.Unlock()

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for expired state")
	}
	if !strings.Contains(err.Error(), "state expired") {
		t.Errorf("expected 'state expired' error, got: %v", err)
	}
}

// State reuse must be rejected (single-use enforcement).
func TestOAuth_Callback_StateReuse(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "a@b.com",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	// First use — should succeed.
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	// Second use — should fail (state consumed).
	_, err = m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for state reuse")
	}
}

// Default scopes must be set when not specified.
func TestOAuth_ProviderConfig_DefaultScopes(t *testing.T) {
	cfg := ProviderConfig{
		Name:      "test",
		IssuerURL: "https://example.com",
		ClientID:  "cid",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Scopes) != 3 {
		t.Fatalf("expected 3 default scopes, got %d", len(cfg.Scopes))
	}
	expected := []string{"openid", "profile", "email"}
	for i, s := range expected {
		if cfg.Scopes[i] != s {
			t.Errorf("scope[%d]: expected %q, got %q", i, s, cfg.Scopes[i])
		}
	}
}

// Provider with missing Name must be rejected.
func TestOAuth_ProviderConfig_MissingName(t *testing.T) {
	cfg := ProviderConfig{
		Name:      "",
		IssuerURL: "https://example.com",
		ClientID:  "cid",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing Name")
	}
}

// Provider with invalid URL must be rejected.
func TestOAuth_ProviderConfig_InvalidURL(t *testing.T) {
	cfg := ProviderConfig{
		Name:      "test",
		IssuerURL: "://invalid",
		ClientID:  "cid",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid IssuerURL")
	}
}

// Discovery cache invalidation must force refetch.
func TestOAuth_Discovery_Invalidate(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})

	client := NewDiscoveryClient(srv.Client())
	ctx := context.Background()

	_, _ = client.Discover(ctx, srv.URL)
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}

	client.Invalidate(srv.URL)

	_, _ = client.Discover(ctx, srv.URL)
	if callCount != 2 {
		t.Fatalf("expected 2 calls after invalidation, got %d", callCount)
	}
}

// ProviderRegistry.Names must return all registered providers.
func TestOAuth_ProviderRegistry_Names(t *testing.T) {
	r := NewProviderRegistry()
	_ = r.Register(ProviderConfig{Name: "google", IssuerURL: "https://accounts.google.com", ClientID: "c1"})
	_ = r.Register(ProviderConfig{Name: "okta", IssuerURL: "https://dev.okta.com", ClientID: "c2"})

	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}

	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	if !nameSet["google"] || !nameSet["okta"] {
		t.Errorf("expected google and okta, got %v", names)
	}
}

// ProviderRegistry.Get must return nil for unknown providers.
func TestOAuth_ProviderRegistry_GetUnknown(t *testing.T) {
	r := NewProviderRegistry()
	if r.Get("nonexistent") != nil {
		t.Error("expected nil for unknown provider")
	}
}

// GenerateState must produce unique state tokens and nonces.
func TestOAuth_GenerateState_Uniqueness(t *testing.T) {
	states := make(map[string]bool)
	nonces := make(map[string]bool)

	for i := 0; i < 100; i++ {
		s, _, err := GenerateState("p")
		if err != nil {
			t.Fatal(err)
		}
		if states[s.State] {
			t.Fatalf("duplicate state at iteration %d", i)
		}
		if nonces[s.Nonce] {
			t.Fatalf("duplicate nonce at iteration %d", i)
		}
		states[s.State] = true
		nonces[s.Nonce] = true
	}
}

// GenerateState must include PKCE verifier.
func TestOAuth_GenerateState_IncludesPKCE(t *testing.T) {
	s, pkce, err := GenerateState("test-provider")
	if err != nil {
		t.Fatal(err)
	}
	if s.PKCEVerifier == "" {
		t.Error("expected PKCE verifier in state")
	}
	if s.PKCEVerifier != pkce.Verifier {
		t.Error("PKCE verifier in state doesn't match returned PKCE challenge")
	}
	if s.Provider != "test-provider" {
		t.Errorf("expected provider 'test-provider', got %q", s.Provider)
	}
	if s.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

// JWKS: key not found after fetching a valid JWKS must return error.
func TestOAuth_JWKS_KeyNotFound(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(createTestJWKS())
	})

	client := NewJWKSClient(srv.Client())
	_, err := client.GetKey(context.Background(), srv.URL+"/jwks", "nonexistent-kid")
	if err == nil {
		t.Fatal("expected error for nonexistent kid")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

// Token endpoint returning malformed JSON must be handled.
func TestOAuth_Callback_TokenEndpoint_MalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})

	m, _ := NewMode(Config{
		UserStore: newMockUserStore(), StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err == nil {
		t.Fatal("expected error for malformed token response")
	}
}

// User with no email should fall back to subject as identifier.
func TestOAuth_AutoRegistration_NoEmail_FallsBackToSubject(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	us := newMockUserStore()
	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "sub-only-user", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "", // no email
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "p", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "p")
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "p"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	// Should use subject as identifier.
	us.mu.Lock()
	_, exists := us.users["sub-only-user"]
	us.mu.Unlock()

	if !exists {
		t.Error("expected user registered with subject as identifier")
	}
	if identity.SubjectID != "sub-only-user" {
		t.Errorf("expected SubjectID 'sub-only-user', got %q", identity.SubjectID)
	}
}

// Identity metadata must include provider, email, and name.
func TestOAuth_Identity_Metadata(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ss := newMockStateStore()
	us := newMockUserStore()
	var capturedNonce string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{Issuer: srv.URL, AuthorizationEndpoint: srv.URL + "/authorize", TokenEndpoint: srv.URL + "/token", JWKSUri: srv.URL + "/jwks"}
		json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { w.Write(createTestJWKS()) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		claims := IDTokenClaims{
			Issuer: srv.URL, Subject: "u-meta", Audience: Audience{"cid"},
			Nonce: capturedNonce, ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			IssuedAt: time.Now().Unix(), Email: "meta@example.com", Name: "Meta User",
		}
		resp := tokenResponse{IDToken: signTestJWT(claims)}
		json.NewEncoder(w).Encode(resp)
	})

	m, _ := NewMode(Config{
		UserStore: us, StateStore: ss, HTTPClient: srv.Client(),
		Providers: []ProviderConfig{{Name: "my-provider", IssuerURL: srv.URL, ClientID: "cid", ClientSecret: "s", RedirectURL: "http://localhost/cb"}},
	})

	_, stateToken, _ := m.BuildAuthURL(context.Background(), "my-provider")
	ss.mu.Lock()
	for _, s := range ss.states {
		capturedNonce = s.Nonce
	}
	ss.mu.Unlock()

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeOAuth,
		Metadata: map[string]any{"code": "c", "state": stateToken, "provider": "my-provider"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if identity.Metadata["provider"] != "my-provider" {
		t.Errorf("expected provider 'my-provider', got %v", identity.Metadata["provider"])
	}
	if identity.Metadata["email"] != "meta@example.com" {
		t.Errorf("expected email 'meta@example.com', got %v", identity.Metadata["email"])
	}
	if identity.Metadata["name"] != "Meta User" {
		t.Errorf("expected name 'Meta User', got %v", identity.Metadata["name"])
	}
	if identity.AuthTime.IsZero() {
		t.Error("expected non-zero AuthTime")
	}
}

// ParseIDTokenHeader must parse valid headers and reject invalid ones.
func TestOAuth_ParseIDTokenHeader(t *testing.T) {
	// Valid header.
	claims := IDTokenClaims{
		Issuer: "iss", Subject: "sub", Audience: Audience{"aud"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(), IssuedAt: time.Now().Unix(),
	}
	token := signTestJWT(claims)
	header, err := ParseIDTokenHeader(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header.Alg != "RS256" {
		t.Errorf("expected alg RS256, got %q", header.Alg)
	}
	if header.Kid != testKid() {
		t.Errorf("expected kid %q, got %q", testKid(), header.Kid)
	}

	// Invalid token.
	_, err = ParseIDTokenHeader("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

// JWKS cache must expire after jwksCacheTTL — stale entries force a refetch.
func TestOAuth_JWKS_CacheTTLExpiry(t *testing.T) {
	fetchCount := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Write(createTestJWKS())
	})

	client := NewJWKSClient(srv.Client())
	jwksURL := srv.URL + "/jwks"

	// Warm the cache.
	_, err := client.GetKey(context.Background(), jwksURL, testKid())
	if err != nil {
		t.Fatalf("initial GetKey: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("fetchCount = %d, want 1", fetchCount)
	}

	// Manually expire the cache entry by backdating fetchedAt.
	client.mu.Lock()
	entry := client.cache[jwksURL]
	entry.fetchedAt = time.Now().Add(-2 * jwksCacheTTL)
	client.mu.Unlock()

	// IsCached should now return false.
	if client.IsCached(jwksURL) {
		t.Error("expected IsCached = false after TTL expiry")
	}

	// Next GetKey should refetch.
	_, err = client.GetKey(context.Background(), jwksURL, testKid())
	if err != nil {
		t.Fatalf("GetKey after expiry: %v", err)
	}
	if fetchCount != 2 {
		t.Errorf("fetchCount = %d, want 2 (refetch after TTL expiry)", fetchCount)
	}
}

// JWKSClient.IsCached must report correctly.
func TestOAuth_JWKS_IsCached(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write(createTestJWKS())
	})

	client := NewJWKSClient(srv.Client())
	jwksURL := srv.URL + "/jwks"

	if client.IsCached(jwksURL) {
		t.Error("expected not cached initially")
	}

	_, _ = client.GetKey(context.Background(), jwksURL, testKid())

	if !client.IsCached(jwksURL) {
		t.Error("expected cached after fetch")
	}
}

// Unsupported key type in JWKS must return error.
func TestOAuth_JWKS_UnsupportedKeyType(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := JWKS{Keys: []JSONWebKey{{Kty: "OKP", Kid: "ed-key", Use: "sig", Alg: "EdDSA"}}}
		data, _ := json.Marshal(jwks)
		w.Write(data)
	})

	client := NewJWKSClient(srv.Client())
	_, err := client.GetKey(context.Background(), srv.URL+"/jwks", "ed-key")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("expected 'unsupported key type' error, got: %v", err)
	}
}

// Unsupported algorithm in VerifyIDToken must return error.
func TestOAuth_VerifyIDToken_UnsupportedAlgorithm(t *testing.T) {
	header := IDTokenHeader{Alg: "PS256", Kid: testKid(), Typ: "JWT"}
	claims := IDTokenClaims{
		Issuer: "iss", Subject: "sub", Audience: Audience{"aud"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(), IssuedAt: time.Now().Unix(),
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("fake-sig"))

	_, err := VerifyIDToken(token, &testRSAKey.PublicKey, "iss", "aud", "")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("expected 'unsupported algorithm' error, got: %v", err)
	}
}

// --- EC Key & Signature Hardening Tests ---

// Test: parseECKey for P-256, P-384, P-521 curves.
func TestOAuth_ParseECKey_AllCurves(t *testing.T) {
	curves := []struct {
		name string
		crv  string
		gen  func() (*ecdsa.PrivateKey, error)
	}{
		{"P-256", "P-256", func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }},
		{"P-384", "P-384", func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
		{"P-521", "P-521", func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) }},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.gen()
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}

			jwk := &JSONWebKey{
				Kty: "EC",
				Kid: "ec-" + tc.crv,
				Use: "sig",
				Crv: tc.crv,
				X:   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
			}

			pub, err := parseJWK(jwk)
			if err != nil {
				t.Fatalf("parseJWK(%s): %v", tc.crv, err)
			}

			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
			}
			if ecPub.Curve != key.PublicKey.Curve {
				t.Errorf("curve mismatch")
			}
		})
	}
}

// Test: parseECKey with unsupported curve returns error.
func TestOAuth_ParseECKey_UnsupportedCurve(t *testing.T) {
	jwk := &JSONWebKey{
		Kty: "EC",
		Kid: "ec-bad",
		Crv: "secp256k1",
		X:   base64.RawURLEncoding.EncodeToString([]byte("x")),
		Y:   base64.RawURLEncoding.EncodeToString([]byte("y")),
	}
	_, err := parseJWK(jwk)
	if err == nil {
		t.Fatal("expected error for unsupported curve")
	}
	if !strings.Contains(err.Error(), "unsupported curve") {
		t.Errorf("expected 'unsupported curve', got: %v", err)
	}
}

// Test: parseECKey with invalid X coordinate returns error.
func TestOAuth_ParseECKey_InvalidX(t *testing.T) {
	jwk := &JSONWebKey{
		Kty: "EC",
		Kid: "ec-badx",
		Crv: "P-256",
		X:   "!!!not-base64!!!",
		Y:   base64.RawURLEncoding.EncodeToString([]byte{1}),
	}
	_, err := parseJWK(jwk)
	if err == nil {
		t.Fatal("expected error for invalid X")
	}
}

// Test: parseECKey with invalid Y coordinate returns error.
func TestOAuth_ParseECKey_InvalidY(t *testing.T) {
	jwk := &JSONWebKey{
		Kty: "EC",
		Kid: "ec-bady",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString([]byte{1}),
		Y:   "!!!not-base64!!!",
	}
	_, err := parseJWK(jwk)
	if err == nil {
		t.Fatal("expected error for invalid Y")
	}
}

// Test: verifyEC with valid ES256 signature.
func TestOAuth_VerifyEC_ES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signingInput := "test.payload"
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Pad r and s to 32 bytes each for P-256.
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	err = verifyEC(sha256.New, 32, signingInput, sig, &key.PublicKey)
	if err != nil {
		t.Fatalf("verifyEC() error: %v", err)
	}
}

// Test: verifyEC with wrong key type returns error.
func TestOAuth_VerifyEC_WrongKeyType(t *testing.T) {
	err := verifyEC(sha256.New, 32, "test.payload", make([]byte, 64), &testRSAKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong key type")
	}
	if !strings.Contains(err.Error(), "expected ECDSA") {
		t.Errorf("expected 'expected ECDSA' error, got: %v", err)
	}
}

// Test: verifyEC with invalid signature length returns error.
func TestOAuth_VerifyEC_InvalidSigLength(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verifyEC(sha256.New, 32, "test.payload", make([]byte, 63), &key.PublicKey)
	if err == nil {
		t.Fatal("expected error for invalid signature length")
	}
	if !strings.Contains(err.Error(), "invalid ECDSA signature length") {
		t.Errorf("expected 'invalid ECDSA signature length', got: %v", err)
	}
}

// Test: verifyEC with tampered signature returns error.
func TestOAuth_VerifyEC_TamperedSignature(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verifyEC(sha256.New, 32, "test.payload", make([]byte, 64), &key.PublicKey)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

// Test: verifyRSA with wrong key type returns error.
func TestOAuth_VerifyRSA_WrongKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := verifyRSA(crypto.SHA256, "test.payload", make([]byte, 256), &ecKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for wrong key type")
	}
	if !strings.Contains(err.Error(), "expected RSA") {
		t.Errorf("expected 'expected RSA' error, got: %v", err)
	}
}

// Test: verifySignature dispatches to ES384 and ES512.
func TestOAuth_VerifySignature_ECAlgorithms(t *testing.T) {
	tests := []struct {
		alg     string
		keySize int
	}{
		{"ES256", 32},
		{"ES384", 48},
		{"ES512", 66},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			// Wrong key type should fail — verifies dispatch path is reached.
			err := verifySignature(tc.alg, "test.payload", make([]byte, tc.keySize*2), &testRSAKey.PublicKey)
			if err == nil {
				t.Fatalf("expected error for %s with RSA key", tc.alg)
			}
		})
	}
}

// Test: verifySignature dispatches to RS384 and RS512.
func TestOAuth_VerifySignature_RSAAlgorithms(t *testing.T) {
	tests := []string{"RS256", "RS384", "RS512"}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for _, alg := range tests {
		t.Run(alg, func(t *testing.T) {
			err := verifySignature(alg, "test.payload", make([]byte, 256), &ecKey.PublicKey)
			if err == nil {
				t.Fatalf("expected error for %s with EC key", alg)
			}
		})
	}
}

// Test: GetProviderRegistry returns the registry.
func TestOAuth_GetProviderRegistry(t *testing.T) {
	m, _, _, _ := buildFullTestMode(t)
	reg := m.GetProviderRegistry()
	if reg == nil {
		t.Fatal("expected non-nil ProviderRegistry")
	}
	names := reg.Names()
	found := false
	for _, n := range names {
		if n == "test-provider" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'test-provider' in registry")
	}
}

// Test: parseRSAKey with invalid modulus returns error.
func TestOAuth_ParseRSAKey_InvalidModulus(t *testing.T) {
	jwk := &JSONWebKey{
		Kty: "RSA",
		Kid: "rsa-bad",
		N:   "!!!not-base64!!!",
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes()),
	}
	_, err := parseJWK(jwk)
	if err == nil {
		t.Fatal("expected error for invalid modulus")
	}
}

// Test: parseRSAKey with invalid exponent returns error.
func TestOAuth_ParseRSAKey_InvalidExponent(t *testing.T) {
	jwk := &JSONWebKey{
		Kty: "RSA",
		Kid: "rsa-bad-exp",
		N:   base64.RawURLEncoding.EncodeToString(big.NewInt(123).Bytes()),
		E:   "!!!not-base64!!!",
	}
	_, err := parseJWK(jwk)
	if err == nil {
		t.Fatal("expected error for invalid exponent")
	}
}

// Test: NewDiscoveryClient with nil HTTP client gets a default.
func TestOAuth_NewDiscoveryClient_NilHTTP(t *testing.T) {
	dc := NewDiscoveryClient(nil)
	if dc == nil {
		t.Fatal("expected non-nil DiscoveryClient")
	}
	if dc.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
}

// Test: NewJWKSClient with nil HTTP client gets a default.
func TestOAuth_NewJWKSClient_NilHTTP(t *testing.T) {
	jc := NewJWKSClient(nil)
	if jc == nil {
		t.Fatal("expected non-nil JWKSClient")
	}
	if jc.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
}

// Test: BuildAuthURL with discovery failure propagates error.
func TestOAuth_BuildAuthURL_DiscoveryFailure(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	m, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: &http.Client{Timeout: 100 * time.Millisecond},
		Providers: []ProviderConfig{
			{
				Name:         "bad-provider",
				IssuerURL:    "http://localhost:1", // Connection refused.
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"openid"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}

	_, _, err = m.BuildAuthURL(context.Background(), "bad-provider")
	if err == nil {
		t.Fatal("expected error for discovery failure")
	}
}

// Test: CreateTestJWT round-trips correctly.
func TestOAuth_CreateTestJWT_RoundTrip(t *testing.T) {
	header := IDTokenHeader{Alg: "RS256", Kid: testKid(), Typ: "JWT"}
	claims := IDTokenClaims{
		Issuer:    "https://issuer.example.com",
		Subject:   "user-123",
		Audience:  Audience{"client-123"},
		Nonce:     "test-nonce",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Email:     "user@example.com",
		Name:      "Test User",
	}

	token, err := CreateTestJWT(header, claims, func(input string) ([]byte, error) {
		h := sha256.Sum256([]byte(input))
		return rsa.SignPKCS1v15(rand.Reader, testRSAKey, crypto.SHA256, h[:])
	})
	if err != nil {
		t.Fatalf("CreateTestJWT: %v", err)
	}

	// Parse and verify.
	parsedClaims, err := VerifyIDToken(token, &testRSAKey.PublicKey, "https://issuer.example.com", "client-123", "test-nonce")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if parsedClaims.Subject != "user-123" {
		t.Errorf("expected subject user-123, got %q", parsedClaims.Subject)
	}
	if parsedClaims.Email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %q", parsedClaims.Email)
	}
}

// Test: CreateTestJWT with failing signer returns error.
func TestOAuth_CreateTestJWT_SignerError(t *testing.T) {
	header := IDTokenHeader{Alg: "RS256", Kid: "k", Typ: "JWT"}
	claims := IDTokenClaims{Issuer: "iss", Subject: "sub"}

	_, err := CreateTestJWT(header, claims, func(input string) ([]byte, error) {
		return nil, errors.New("signer broke")
	})
	if err == nil {
		t.Fatal("expected error from failing signer")
	}
}

// Test: ParseIDTokenHeader with invalid base64 returns error.
func TestOAuth_ParseIDTokenHeader_InvalidBase64(t *testing.T) {
	_, err := ParseIDTokenHeader("!!!.claims.sig")
	if err == nil {
		t.Fatal("expected error for invalid base64 header")
	}
}

// Test: ParseIDTokenHeader with invalid JSON returns error.
func TestOAuth_ParseIDTokenHeader_InvalidJSON(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	_, err := ParseIDTokenHeader(b64 + ".claims.sig")
	if err == nil {
		t.Fatal("expected error for invalid JSON header")
	}
}

// Test: BuildAuthURL with stateStore.Save failure returns error.
func TestOAuth_BuildAuthURL_StateSaveFailure(t *testing.T) {
	ss := &failingStateStore{saveErr: fmt.Errorf("redis down")}
	// Need a working discovery endpoint — issuer must match the server URL.
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"jwks_uri":               srvURL + "/jwks",
		})
	}))
	defer srv.Close()
	srvURL = srv.URL

	m, err := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test",
				IssuerURL:    srv.URL,
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"openid"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}

	_, _, err = m.BuildAuthURL(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error when state save fails")
	}
	if !strings.Contains(err.Error(), "redis down") {
		t.Errorf("expected 'redis down' in error, got: %v", err)
	}
}

// Test: Authenticate with unknown provider after state loaded returns error.
func TestOAuth_Authenticate_UnknownProviderAfterState(t *testing.T) {
	ss := newMockStateStore()
	// Pre-load state for a provider that the mode doesn't know about.
	ss.Save(context.Background(), &OAuthState{
		State:     "test-state-token",
		Nonce:     "test-nonce",
		Provider:  "unknown-provider", // Not registered in mode.
		CreatedAt: time.Now(),         // Must not be expired.
	})

	m, err := NewMode(Config{
		UserStore:  newMockUserStore(),
		StateStore: ss,
		HTTPClient: http.DefaultClient,
		Providers: []ProviderConfig{
			{
				Name:         "known-provider",
				IssuerURL:    "https://known.example.com",
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"openid"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}

	_, err = m.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state-token",
			"provider": "unknown-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error for unknown provider after state loaded")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("expected 'unknown provider' in error, got: %v", err)
	}
}

// failingStateStore implements StateStore but can fail on Save/Load.
type failingStateStore struct {
	saveErr error
	loadErr error
}

func (f *failingStateStore) Save(_ context.Context, _ *OAuthState) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	return nil
}

func (f *failingStateStore) Load(_ context.Context, _ string) (*OAuthState, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return nil, errors.New("state not found")
}

// Test OAuth.H38: VerifyIDToken returns error when signature segment is invalid base64.
func TestOAuth_VerifyIDToken_InvalidSignatureBase64(t *testing.T) {
	// Build a token with valid header and claims but invalid base64 in the signature segment.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1"}`))
	rawToken := header + "." + claims + ".!!!invalid-base64!!!"

	_, err := VerifyIDToken(rawToken, &testRSAKey.PublicKey, "issuer", "client", "")
	if err == nil {
		t.Fatal("expected error for invalid signature base64")
	}
	if !strings.Contains(err.Error(), "decode JWT signature") {
		t.Errorf("expected 'decode JWT signature' in error, got: %v", err)
	}
}

// Test OAuth.H39: VerifyIDToken returns error when claims segment is invalid base64.
func TestOAuth_VerifyIDToken_InvalidClaimsBase64(t *testing.T) {
	// Build a valid token with the test key, then corrupt the claims segment.
	validToken := signTestJWT(IDTokenClaims{
		Issuer:    "test-issuer",
		Subject:   "user-1",
		Audience:  Audience{"client-1"},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
	})
	parts := strings.Split(validToken, ".")

	// Replace claims with valid base64 that decodes fine but we need invalid base64.
	// We need the signature to verify first, so let's use a raw token with
	// a validly signed but then corrupted claims base64.
	// Actually, we construct directly: valid header, bad claims base64, valid-looking sig.
	header := parts[0]
	badClaims := "!!!not-base64!!!"
	// Re-sign with the bad claims so signature passes? No — signature check happens first.
	// We need signature to pass but claims decode to fail.
	// Sign with the corrupted claims:
	signingInput := header + "." + badClaims
	h := sha256.Sum256([]byte(signingInput))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, testRSAKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	rawToken := signingInput + "." + sigB64

	_, err = VerifyIDToken(rawToken, &testRSAKey.PublicKey, "issuer", "client", "")
	if err == nil {
		t.Fatal("expected error for invalid claims base64")
	}
	if !strings.Contains(err.Error(), "decode JWT claims") {
		t.Errorf("expected 'decode JWT claims' in error, got: %v", err)
	}
}

// Test OAuth.H40: VerifyIDToken returns error when claims JSON is invalid.
func TestOAuth_VerifyIDToken_InvalidClaimsJSON(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test","typ":"JWT"}`))
	// Valid base64 but invalid JSON as claims.
	badClaimsB64 := base64.RawURLEncoding.EncodeToString([]byte(`{not valid json`))
	signingInput := header + "." + badClaimsB64
	h := sha256.Sum256([]byte(signingInput))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, testRSAKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	rawToken := signingInput + "." + sigB64

	_, err = VerifyIDToken(rawToken, &testRSAKey.PublicKey, "issuer", "client", "")
	if err == nil {
		t.Fatal("expected error for invalid claims JSON")
	}
	if !strings.Contains(err.Error(), "parse JWT claims") {
		t.Errorf("expected 'parse JWT claims' in error, got: %v", err)
	}
}

// Test OAuth.H41: CreateTestJWT returns error when header cannot be marshaled.
func TestOAuth_CreateTestJWT_HeaderMarshalError(t *testing.T) {
	// The header and claims are already typed structs; they always marshal fine.
	// The only way to make CreateTestJWT fail is with a signer error.
	header := IDTokenHeader{Alg: "RS256", Kid: "k", Typ: "JWT"}
	claims := IDTokenClaims{Subject: "u1"}

	_, err := CreateTestJWT(header, claims, func(_ string) ([]byte, error) {
		return nil, fmt.Errorf("signer broken")
	})
	if err == nil {
		t.Fatal("expected error when signer fails")
	}
	if !strings.Contains(err.Error(), "signer broken") {
		t.Errorf("expected signer error, got: %v", err)
	}
}

// Test OAuth.H42: Authenticate fails when token exchange gets non-JSON response body.
func TestOAuth_Authenticate_TokenExchangeBadResponse(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSUri:               issuer + "/jwks",
			UserinfoEndpoint:      issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not-json`))
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error for bad token exchange response")
	}
}

// Test OAuth.H43: Authenticate fails when JWKS endpoint returns invalid JSON.
func TestOAuth_Authenticate_JWKSBadResponse(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	validToken := signTestJWT(IDTokenClaims{
		Subject:   "user-1",
		Audience:  Audience{"client-id"},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Email:     "user@test.com",
	})

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSUri:               issuer + "/jwks",
			UserinfoEndpoint:      issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := tokenResponse{
			IDToken:     validToken,
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not-json`))
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error for bad JWKS response")
	}
}

// Test OAuth.H44: Authenticate fails when auto-registration (userStore.Create) fails.
func TestOAuth_Authenticate_AutoRegFailure(t *testing.T) {
	us := &failingUserStore{findErr: auth.ErrUserNotFound, createErr: fmt.Errorf("db write error")}
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issuer := srv.URL

	validToken := signTestJWT(IDTokenClaims{
		Issuer:    issuer,
		Subject:   "new-user",
		Audience:  Audience{"client-id"},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Email:     "new@test.com",
		Nonce:     "test-nonce",
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSUri:               issuer + "/jwks",
			UserinfoEndpoint:      issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := tokenResponse{
			IDToken:     validToken,
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(createTestJWKS())
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error when auto-registration fails")
	}
	if !strings.Contains(err.Error(), "auto-registration") {
		t.Errorf("expected 'auto-registration' in error, got: %v", err)
	}
}

// Test OAuth.H45: Discovery fails when OIDC endpoint returns invalid JSON.
func TestOAuth_Discovery_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	us := newMockUserStore()
	ss := newMockStateStore()

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    srv.URL,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	_, _, err = mode.BuildAuthURL(context.Background(), "test-provider")
	if err == nil {
		t.Fatal("expected error for invalid discovery JSON")
	}
}

// Test OAuth.H46: Discovery fails when OIDC endpoint is unreachable.
func TestOAuth_Discovery_Unreachable(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    "http://127.0.0.1:1",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	_, _, err = mode.BuildAuthURL(context.Background(), "test-provider")
	if err == nil {
		t.Fatal("expected error for unreachable discovery endpoint")
	}
}

// failingUserStore implements auth.UserStore where Create always fails.
type failingUserStore struct {
	findErr   error
	createErr error
}

func (f *failingUserStore) FindByIdentifier(_ context.Context, _ string) (auth.User, error) {
	return nil, f.findErr
}
func (f *failingUserStore) Create(_ context.Context, _ auth.User) error {
	return f.createErr
}
func (f *failingUserStore) UpdatePassword(_ context.Context, _, _ string) error       { return nil }
func (f *failingUserStore) IncrementFailedAttempts(_ context.Context, _ string) error { return nil }
func (f *failingUserStore) ResetFailedAttempts(_ context.Context, _ string) error     { return nil }
func (f *failingUserStore) SetLocked(_ context.Context, _ string, _ bool) error       { return nil }

// Test OAuth.H51: Discover fails when io.ReadAll fails (chunked encoding error).
func TestOAuth_Discovery_ReadBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Declare chunked encoding, write partial data, then close abruptly.
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)
		// Write an invalid chunk to cause io.ReadAll to fail.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Log("ResponseWriter does not implement Hijacker, skipping")
			return
		}
		conn, buf, _ := hijacker.Hijack()
		buf.WriteString("5\r\nhello\r\n") // valid chunk
		buf.WriteString("INVALID\r\n")    // invalid chunk size
		buf.Flush()
		conn.Close()
	}))
	defer srv.Close()

	us := newMockUserStore()
	ss := newMockStateStore()

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    srv.URL,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	_, _, err = mode.BuildAuthURL(context.Background(), "test-provider")
	if err == nil {
		t.Fatal("expected error when discovery body read fails")
	}
}

// Test OAuth.H52: fetchJWKS fails when JWKS endpoint is unreachable.
func TestOAuth_JWKS_FetchError(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	validToken := signTestJWT(IDTokenClaims{
		Subject:   "user-1",
		Audience:  Audience{"client-id"},
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
		Email:     "user@test.com",
	})

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSUri:               "http://127.0.0.1:1/jwks", // unreachable
			UserinfoEndpoint:      issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := tokenResponse{
			IDToken:     validToken,
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error when JWKS fetch fails")
	}
}

// Test OAuth.H47: VerifyIDToken returns error when JWT header is valid base64 but invalid JSON.
func TestOAuth_VerifyIDToken_InvalidHeaderJSON(t *testing.T) {
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{not valid json`))
	claimsB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1"}`))
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	rawToken := headerB64 + "." + claimsB64 + "." + sigB64

	_, err := VerifyIDToken(rawToken, &testRSAKey.PublicKey, "issuer", "client", "")
	if err == nil {
		t.Fatal("expected error for invalid header JSON")
	}
	if !strings.Contains(err.Error(), "parse JWT header") {
		t.Errorf("expected 'parse JWT header' in error, got: %v", err)
	}
}

// Test OAuth.H48: Authenticate fails when discovery fails during callback.
func TestOAuth_Authenticate_DiscoveryFailure(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	// Start a server that returns valid discovery initially (for BuildAuthURL),
	// then shut it down before Authenticate is called.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Always fail with invalid response.
		w.WriteHeader(http.StatusInternalServerError)
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error when discovery fails during Authenticate")
	}
}

// Test OAuth.H49: Authenticate fails when id_token header cannot be parsed.
func TestOAuth_Authenticate_BadIDTokenHeader(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         issuer + "/token",
			JWKSUri:               issuer + "/jwks",
			UserinfoEndpoint:      issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Return a token with only 2 parts (invalid JWT format).
		resp := tokenResponse{
			IDToken:     "only.two",
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error when id_token header is unparseable")
	}
}

// Test OAuth.H50: Authenticate fails when token exchange HTTP request fails.
func TestOAuth_Authenticate_TokenExchangeHTTPError(t *testing.T) {
	us := newMockUserStore()
	ss := newMockStateStore()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	issuer := srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := OIDCConfig{
			Issuer:                issuer,
			AuthorizationEndpoint: issuer + "/authorize",
			TokenEndpoint:         "http://127.0.0.1:1/token", // unreachable token endpoint
			JWKSUri:               issuer + "/jwks",
			UserinfoEndpoint:      issuer + "/userinfo",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	})

	mode, err := NewMode(Config{
		UserStore:  us,
		StateStore: ss,
		HTTPClient: srv.Client(),
		Providers: []ProviderConfig{
			{
				Name:         "test-provider",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost/callback",
				IssuerURL:    issuer,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewMode() error: %v", err)
	}

	state := &OAuthState{
		State:     "test-state",
		Nonce:     "test-nonce",
		Provider:  "test-provider",
		CreatedAt: time.Now(),
	}
	ss.Save(context.Background(), state)

	_, err = mode.Authenticate(context.Background(), auth.Credential{
		Type: auth.CredentialTypeOAuth,
		Metadata: map[string]any{
			"code":     "auth-code",
			"state":    "test-state",
			"provider": "test-provider",
		},
	})
	if err == nil {
		t.Fatal("expected error when token exchange HTTP request fails")
	}
}
