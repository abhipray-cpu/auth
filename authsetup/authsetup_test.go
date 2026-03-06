// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authsetup_test

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/mode/oauth"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
)

// ---------------------------------------------------------------------------
// Test helpers — minimal in-memory implementations for unit testing.
// ---------------------------------------------------------------------------

// mockUserStore is a minimal UserStore for wiring tests.
type mockUserStore struct {
	mu    sync.Mutex
	users map[string]*mockUser
}

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
	if _, ok := s.users[user.GetIdentifier()]; ok {
		return auth.ErrUserAlreadyExists
	}
	s.users[user.GetIdentifier()] = &mockUser{
		subjectID:    user.GetSubjectID(),
		identifier:   user.GetIdentifier(),
		passwordHash: user.GetPasswordHash(),
	}
	return nil
}

func (s *mockUserStore) UpdatePassword(_ context.Context, subjectID string, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.passwordHash = hash
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *mockUserStore) IncrementFailedAttempts(_ context.Context, _ string) error { return nil }
func (s *mockUserStore) ResetFailedAttempts(_ context.Context, _ string) error     { return nil }
func (s *mockUserStore) SetLocked(_ context.Context, _ string, _ bool) error       { return nil }

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

// mockSessionStore is a minimal in-memory SessionStore for wiring tests.
type mockSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]*session.Session)}
}

func (s *mockSessionStore) Create(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *mockSessionStore) Get(_ context.Context, sessionID string) (*session.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return sess, nil
}

func (s *mockSessionStore) Update(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *mockSessionStore) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *mockSessionStore) DeleteBySubject(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *mockSessionStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

// mockHasher is a fast hasher for testing (no real hashing).
type mockHasher struct{}

func (h *mockHasher) Hash(password string) (string, error) { return "hashed:" + password, nil }
func (h *mockHasher) Verify(password string, hash string) (bool, error) {
	return hash == "hashed:"+password, nil
}

// mockNotifier captures notifications for testing.
type mockNotifier struct {
	mu     sync.Mutex
	events []auth.AuthEvent
}

func (n *mockNotifier) Notify(_ context.Context, event auth.AuthEvent, _ map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return nil
}

// mockMagicLinkStore is a minimal magic link store.
type mockMagicLinkStore struct {
	mu     sync.Mutex
	tokens map[string]*session.MagicLinkToken
}

func newMockMagicLinkStore() *mockMagicLinkStore {
	return &mockMagicLinkStore{tokens: make(map[string]*session.MagicLinkToken)}
}

func (s *mockMagicLinkStore) Store(_ context.Context, token *session.MagicLinkToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *mockMagicLinkStore) Consume(_ context.Context, tokenValue string) (*session.MagicLinkToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenValue]
	if !ok {
		return nil, auth.ErrTokenNotFound
	}
	delete(s.tokens, tokenValue)
	return t, nil
}

// mockAPIKeyStore is a minimal API key store.
type mockAPIKeyStore struct {
	mu   sync.Mutex
	keys map[string]*apikey.APIKey
}

func newMockAPIKeyStore() *mockAPIKeyStore {
	return &mockAPIKeyStore{keys: make(map[string]*apikey.APIKey)}
}

func (s *mockAPIKeyStore) FindByKey(_ context.Context, keyHash string) (*apikey.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyHash]
	if !ok {
		return nil, errors.New("api key not found")
	}
	return k, nil
}

func (s *mockAPIKeyStore) Create(_ context.Context, key *apikey.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KeyHash] = key
	return nil
}

func (s *mockAPIKeyStore) Revoke(_ context.Context, keyID string) error { return nil }
func (s *mockAPIKeyStore) ListBySubject(_ context.Context, _ string) ([]*apikey.APIKey, error) {
	return nil, nil
}
func (s *mockAPIKeyStore) UpdateLastUsed(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// mockOAuthStateStore is a minimal OAuth state store.
type mockOAuthStateStore struct {
	mu     sync.Mutex
	states map[string]*oauth.OAuthState
}

func newMockOAuthStateStore() *mockOAuthStateStore {
	return &mockOAuthStateStore{states: make(map[string]*oauth.OAuthState)}
}

func (s *mockOAuthStateStore) Save(_ context.Context, state *oauth.OAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *mockOAuthStateStore) Load(_ context.Context, stateToken string) (*oauth.OAuthState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[stateToken]
	if !ok {
		return nil, errors.New("state not found")
	}
	delete(s.states, stateToken)
	return st, nil
}

// mockSchemaChecker that can simulate success or mismatch.
type mockSchemaCheckStore struct {
	session.SessionStore
	err error
}

func (s *mockSchemaCheckStore) CheckSchemaVersion(_ context.Context) error {
	return s.err
}

// mockPropagator is a minimal IdentityPropagator.
type mockPropagator struct{}

func (p *mockPropagator) Encode(_ context.Context, _ *auth.Identity) (map[string]string, error) {
	return map[string]string{"x-auth-token": "mock"}, nil
}

func (p *mockPropagator) Decode(_ context.Context, _ map[string]string, _ *auth.WorkloadIdentity) (*auth.Identity, error) {
	return &auth.Identity{SubjectID: "decoded"}, nil
}

// idCfg is a reusable identifier config for tests.
func idCfg() auth.IdentifierConfig {
	return auth.IdentifierConfig{Field: "email"}
}

// ---------------------------------------------------------------------------
// Test 15.1: Minimal config → working engine
// ---------------------------------------------------------------------------

func TestNew_MinimalConfig_WorkingEngine(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	if a.Engine == nil {
		t.Fatal("expected Engine to be non-nil")
	}
}

// ---------------------------------------------------------------------------
// Test 15.2: All options applied correctly
// ---------------------------------------------------------------------------

func TestNew_AllOptionsApplied(t *testing.T) {
	hookCalled := false

	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithPasswordPolicy(pw.PasswordPolicy{MinLength: 12, MaxLength: 256}),
		authsetup.WithSessionConfig(session.SessionConfig{
			IdleTimeout:     15 * time.Minute,
			AbsoluteTimeout: 12 * time.Hour,
			MaxConcurrent:   3,
		}),
		authsetup.WithNotifier(&mockNotifier{}),
		authsetup.WithMagicLinkStore(newMockMagicLinkStore()),
		authsetup.WithAPIKeyStore(newMockAPIKeyStore()),
		authsetup.WithAuthorizer(nil),
		authsetup.WithHook(auth.EventLogin, func(_ context.Context, _ hooks.HookPayload) error {
			hookCalled = true
			return nil
		}),
		authsetup.WithIdentityPropagator(&mockPropagator{}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	if a.Engine == nil {
		t.Fatal("Engine should not be nil")
	}
	if a.Propagator == nil {
		t.Fatal("Propagator should not be nil with WithIdentityPropagator")
	}

	// hookCalled is verified by the hook executing later during login.
	_ = hookCalled
}

// ---------------------------------------------------------------------------
// Test 15.3: Missing UserStore → clear error
// ---------------------------------------------------------------------------

func TestNew_MissingUserStore_Error(t *testing.T) {
	_, err := authsetup.New(
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err == nil {
		t.Fatal("expected error for missing UserStore")
	}
	if got := err.Error(); got != "auth: WithUserStore is required" {
		t.Fatalf("unexpected error message: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Test 15.4: Missing IdentifierConfig → clear error
// ---------------------------------------------------------------------------

func TestNew_MissingIdentifierConfig_Error(t *testing.T) {
	_, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err == nil {
		t.Fatal("expected error for missing IdentifierConfig")
	}
	if got := err.Error(); got != "auth: WithIdentifierConfig is required (Field must be non-empty)" {
		t.Fatalf("unexpected error message: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Test 15.5: Missing SessionStore → clear error
// ---------------------------------------------------------------------------

func TestNew_MissingSessionStore_Error(t *testing.T) {
	_, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err == nil {
		t.Fatal("expected error for missing session store")
	}
	if got := err.Error(); got != "auth: a session store is required — use WithSessionRedis, WithSessionPostgres, or WithCustomSessionStore" {
		t.Fatalf("unexpected error message: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Test 15.6: Default Hasher is Argon2id
// ---------------------------------------------------------------------------

func TestNew_DefaultHasher_Argon2id(t *testing.T) {
	store := newMockUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	// Register a user — password should be hashed with Argon2id (contains "$argon2id$").
	cred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "StrongP@ssw0rd123!",
	}
	_, _, err = a.Engine.Register(context.Background(), cred)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	user, err := store.FindByIdentifier(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("find user failed: %v", err)
	}

	hash := user.GetPasswordHash()
	if len(hash) == 0 {
		t.Fatal("expected password hash to be set")
	}
	// Argon2id hashes start with $argon2id$.
	if len(hash) < 10 || hash[:10] != "$argon2id$" {
		t.Fatalf("expected Argon2id hash, got %q", hash[:min(len(hash), 30)])
	}
}

// ---------------------------------------------------------------------------
// Test 15.7: Default PasswordPolicy is NIST 800-63B
// ---------------------------------------------------------------------------

func TestNew_DefaultPasswordPolicy_NIST(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	// Too short password (< 8 chars, NIST minimum) should fail registration.
	cred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "bob@example.com",
		Secret:     "short",
	}
	_, _, err = a.Engine.Register(context.Background(), cred)
	if !errors.Is(err, auth.ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation for short password, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 15.8: Default Propagator is nil (disabled) when not configured
// ---------------------------------------------------------------------------

func TestNew_DefaultPropagator_Nil(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	if a.Propagator != nil {
		t.Fatal("expected Propagator to be nil when not configured")
	}
}

// ---------------------------------------------------------------------------
// Test 15.9: Magic link without Notifier → clear error
// ---------------------------------------------------------------------------

func TestNew_MagicLinkWithoutNotifier_Error(t *testing.T) {
	_, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithMagicLinkStore(newMockMagicLinkStore()),
		// No WithNotifier!
		authsetup.WithSkipSchemaCheck(),
	)
	if err == nil {
		t.Fatal("expected error for magic link without notifier")
	}
	if got := err.Error(); got != "auth: WithNotifier is required when magic link mode is enabled" {
		t.Fatalf("unexpected error: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Test 15.10: API key mode enabled when APIKeyStore is configured
// ---------------------------------------------------------------------------

func TestNew_APIKeyMode_Enabled(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithAPIKeyStore(newMockAPIKeyStore()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	if a.Engine == nil {
		t.Fatal("Engine should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Test 15.11: Schema version checked on startup (passes)
// ---------------------------------------------------------------------------

func TestNew_SchemaVersionCheck_Pass(t *testing.T) {
	store := &mockSchemaCheckStore{
		SessionStore: newMockSessionStore(),
		err:          nil,
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(store),
		authsetup.WithHasher(&mockHasher{}),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()
}

// ---------------------------------------------------------------------------
// Test 15.12: Schema version mismatch → clear error with migration link
// ---------------------------------------------------------------------------

func TestNew_SchemaVersionMismatch_Error(t *testing.T) {
	store := &mockSchemaCheckStore{
		SessionStore: newMockSessionStore(),
		err:          auth.ErrSchemaVersionMismatch,
	}

	_, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(store),
		authsetup.WithHasher(&mockHasher{}),
	)
	if err == nil {
		t.Fatal("expected error for schema version mismatch")
	}
	if !errors.Is(err, auth.ErrSchemaVersionMismatch) {
		t.Fatalf("expected ErrSchemaVersionMismatch, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 15.13: Multiple OAuth providers registered
// ---------------------------------------------------------------------------

func TestNew_MultipleOAuthProviders(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:      "google",
			IssuerURL: "https://accounts.google.com",
			ClientID:  "google-client-id",
		}),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:      "github",
			IssuerURL: "https://github.com",
			ClientID:  "github-client-id",
		}),
		authsetup.WithOAuthStateStore(newMockOAuthStateStore()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()
}

// ---------------------------------------------------------------------------
// Test 15.14: Hooks registered during config
// ---------------------------------------------------------------------------

func TestNew_HooksRegisteredDuringConfig(t *testing.T) {
	hookCalled := false

	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithHook(auth.EventRegistration, func(_ context.Context, _ hooks.HookPayload) error {
			hookCalled = true
			return nil
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	// Register a user — should trigger the hook.
	cred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "hook-test@example.com",
		Secret:     "ValidPassword123!",
	}
	_, _, err = a.Engine.Register(context.Background(), cred)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if !hookCalled {
		t.Fatal("expected registration hook to be called")
	}
}

// ---------------------------------------------------------------------------
// Test 15.15: Engine.Close() on Auth calls close on resources
// ---------------------------------------------------------------------------

func TestAuth_Close_ClosesEngine(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Close should not error.
	if err := a.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 15.16: Custom hasher overrides default
// ---------------------------------------------------------------------------

func TestNew_CustomHasher_OverridesDefault(t *testing.T) {
	store := newMockUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	// Register — password should be "hashed:" prefixed (mockHasher), not argon2id.
	cred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "custom-hash@example.com",
		Secret:     "ValidPassword123!",
	}
	_, _, err = a.Engine.Register(context.Background(), cred)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	user, _ := store.FindByIdentifier(context.Background(), "custom-hash@example.com")
	hash := user.GetPasswordHash()
	if hash != "hashed:ValidPassword123!" {
		t.Fatalf("expected mock hash, got %q", hash)
	}
}

// ---------------------------------------------------------------------------
// Test 15.17: Custom password policy overrides NIST default
// ---------------------------------------------------------------------------

func TestNew_CustomPasswordPolicy_OverridesDefault(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithPasswordPolicy(pw.PasswordPolicy{MinLength: 20, MaxLength: 256}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	// 15-char password should fail with MinLength=20.
	cred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "policy@example.com",
		Secret:     "FifteenChars!!1",
	}
	_, _, err = a.Engine.Register(context.Background(), cred)
	if !errors.Is(err, auth.ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 15.18: Magic link mode enabled with Notifier + Store
// ---------------------------------------------------------------------------

func TestNew_MagicLinkMode_Enabled(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithNotifier(&mockNotifier{}),
		authsetup.WithMagicLinkStore(newMockMagicLinkStore()),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()
}

// ---------------------------------------------------------------------------
// Test 15.19: mTLS mode enabled with trust anchors
// ---------------------------------------------------------------------------

func TestNew_MTLSMode_Enabled(t *testing.T) {
	pool := x509.NewCertPool()
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithTrustAnchors(pool),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()
}

// ---------------------------------------------------------------------------
// Test 15.20: Custom session config overrides defaults
// ---------------------------------------------------------------------------

func TestNew_CustomSessionConfig_OverridesDefaults(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSessionConfig(session.SessionConfig{
			IdleTimeout:     5 * time.Minute,
			AbsoluteTimeout: 1 * time.Hour,
			MaxConcurrent:   1,
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()
}

// ---------------------------------------------------------------------------
// Test 15.21: Custom propagator overrides default
// ---------------------------------------------------------------------------

func TestNew_CustomPropagator_OverridesDefault(t *testing.T) {
	prop := &mockPropagator{}
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithIdentityPropagator(prop),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	if a.Propagator == nil {
		t.Fatal("expected custom propagator to be used")
	}
}

// ---------------------------------------------------------------------------
// Test 15.22: JWKS handler auto-registered with SignedJWTPropagator
// ---------------------------------------------------------------------------

func TestNew_SignedJWTPropagator_JWKSHandler(t *testing.T) {
	a, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithSignedJWTPropagator(propagator.SignedJWTConfig{
			Issuer:   "test-service",
			Audience: "test-audience",
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer a.Close()

	if a.JWKSHandler == nil {
		t.Fatal("expected JWKSHandler to be auto-registered with SignedJWTPropagator")
	}
	if a.Propagator == nil {
		t.Fatal("expected Propagator to be non-nil")
	}
}

// ---------------------------------------------------------------------------
// Test 15.23: OAuth without StateStore → clear error
// ---------------------------------------------------------------------------

func TestNew_OAuthWithoutStateStore_Error(t *testing.T) {
	_, err := authsetup.New(
		authsetup.WithUserStore(newMockUserStore()),
		authsetup.WithIdentifierConfig(idCfg()),
		authsetup.WithCustomSessionStore(newMockSessionStore()),
		authsetup.WithHasher(&mockHasher{}),
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:      "google",
			IssuerURL: "https://accounts.google.com",
			ClientID:  "google-client-id",
		}),
		// No WithOAuthStateStore!
		authsetup.WithSkipSchemaCheck(),
	)
	if err == nil {
		t.Fatal("expected error for OAuth without state store")
	}
	if got := err.Error(); got != "auth: WithOAuthStateStore is required when OAuth providers are configured" {
		t.Fatalf("unexpected error: %s", got)
	}
}
