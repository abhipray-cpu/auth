// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package magiclink

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"
)

// --- Mock implementations ---

// mockUser implements auth.User.
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

// mockUserStore implements auth.UserStore.
type mockUserStore struct {
	users map[string]*mockUser // keyed by identifier
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{users: make(map[string]*mockUser)}
}

func (s *mockUserStore) FindByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	u, ok := s.users[identifier]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

func (s *mockUserStore) Create(_ context.Context, _ auth.User) error               { return nil }
func (s *mockUserStore) UpdatePassword(_ context.Context, _, _ string) error       { return nil }
func (s *mockUserStore) IncrementFailedAttempts(_ context.Context, _ string) error { return nil }
func (s *mockUserStore) ResetFailedAttempts(_ context.Context, _ string) error     { return nil }
func (s *mockUserStore) SetLocked(_ context.Context, _ string, _ bool) error       { return nil }

// mockMagicLinkStore implements session.MagicLinkStore.
type mockMagicLinkStore struct {
	mu     sync.Mutex
	tokens map[string]*session.MagicLinkToken // keyed by hashed token (with prefix)
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

// mockNotifier implements auth.Notifier.
type mockNotifier struct {
	mu         sync.Mutex
	calls      []notifyCall
	shouldFail bool
}

type notifyCall struct {
	event   auth.AuthEvent
	payload map[string]any
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{}
}

func (n *mockNotifier) Notify(_ context.Context, event auth.AuthEvent, payload map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.shouldFail {
		return errors.New("notify failed")
	}
	n.calls = append(n.calls, notifyCall{event: event, payload: payload})
	return nil
}

func (n *mockNotifier) callCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.calls)
}

func (n *mockNotifier) lastCall() notifyCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls[len(n.calls)-1]
}

// --- Helper ---

func buildTestMode(t *testing.T) (*Mode, *mockUserStore, *mockMagicLinkStore, *mockNotifier) {
	t.Helper()
	us := newMockUserStore()
	ts := newMockMagicLinkStore()
	notif := newMockNotifier()

	us.users["alice@example.com"] = &mockUser{
		subjectID:  "user-alice",
		identifier: "alice@example.com",
	}

	m, err := NewMode(Config{
		UserStore:      us,
		MagicLinkStore: ts,
		Notifier:       notif,
		IdentifierConfig: auth.IdentifierConfig{
			Field:     "email",
			Normalize: strings.ToLower,
		},
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}
	return m, us, ts, notif
}

// --- Test Cases ---

// 9.1: Token generated with correct length and entropy.
func TestMagicLink_GenerateToken(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	ctx := context.Background()

	token, err := m.Initiate(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	// Token is hex-encoded 32 bytes → 64 hex chars.
	if len(token) != 64 {
		t.Errorf("expected token length 64, got %d", len(token))
	}
}

// 9.2: Token stored in session store with magiclink: prefix.
func TestMagicLink_TokenStored(t *testing.T) {
	m, _, ts, _ := buildTestMode(t)
	ctx := context.Background()

	_, err := m.Initiate(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if len(ts.tokens) != 1 {
		t.Fatalf("expected 1 stored token, got %d", len(ts.tokens))
	}
	for key := range ts.tokens {
		if !strings.HasPrefix(key, "magiclink:") {
			t.Errorf("expected token key to have 'magiclink:' prefix, got %q", key)
		}
	}
}

// 9.3: Token has configurable TTL (default: 15 min).
func TestMagicLink_TokenTTL(t *testing.T) {
	us := newMockUserStore()
	ts := newMockMagicLinkStore()
	notif := newMockNotifier()
	us.users["alice@example.com"] = &mockUser{subjectID: "user-alice", identifier: "alice@example.com"}

	// Default TTL.
	m1, _ := NewMode(Config{
		UserStore:      us,
		MagicLinkStore: ts,
		Notifier:       notif,
	})
	_, _ = m1.Initiate(context.Background(), "alice@example.com")

	ts.mu.Lock()
	for _, tok := range ts.tokens {
		expectedExpiry := tok.CreatedAt.Add(15 * time.Minute)
		if tok.ExpiresAt.Sub(expectedExpiry).Abs() > time.Second {
			t.Errorf("default TTL: expected expiry ~%v, got %v", expectedExpiry, tok.ExpiresAt)
		}
	}
	ts.mu.Unlock()

	// Custom TTL.
	ts2 := newMockMagicLinkStore()
	m2, _ := NewMode(Config{
		UserStore:      us,
		MagicLinkStore: ts2,
		Notifier:       notif,
		TTL:            5 * time.Minute,
	})
	_, _ = m2.Initiate(context.Background(), "alice@example.com")

	ts2.mu.Lock()
	for _, tok := range ts2.tokens {
		expectedExpiry := tok.CreatedAt.Add(5 * time.Minute)
		if tok.ExpiresAt.Sub(expectedExpiry).Abs() > time.Second {
			t.Errorf("custom TTL: expected expiry ~%v, got %v", expectedExpiry, tok.ExpiresAt)
		}
	}
	ts2.mu.Unlock()
}

// 9.4: Notifier.Notify called with EventMagicLinkSent.
func TestMagicLink_NotifySent(t *testing.T) {
	m, _, _, notif := buildTestMode(t)
	ctx := context.Background()

	rawToken, err := m.Initiate(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	if notif.callCount() != 1 {
		t.Fatalf("expected 1 notify call, got %d", notif.callCount())
	}

	call := notif.lastCall()
	if call.event != auth.EventMagicLinkSent {
		t.Errorf("expected event %q, got %q", auth.EventMagicLinkSent, call.event)
	}
	if call.payload["token"] != rawToken {
		t.Errorf("expected token in payload")
	}
	if call.payload["subject_id"] != "user-alice" {
		t.Errorf("expected subject_id in payload")
	}
}

// 9.5: Valid token → Identity.
func TestMagicLink_VerifyToken_Valid(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	ctx := context.Background()

	rawToken, err := m.Initiate(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	identity, err := m.Authenticate(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.SubjectID != "user-alice" {
		t.Errorf("expected SubjectID 'user-alice', got %q", identity.SubjectID)
	}
	if identity.AuthMethod != "magic_link" {
		t.Errorf("expected AuthMethod 'magic_link', got %q", identity.AuthMethod)
	}
}

// 9.6: Expired token → error.
func TestMagicLink_VerifyToken_Expired(t *testing.T) {
	us := newMockUserStore()
	ts := newMockMagicLinkStore()
	notif := newMockNotifier()
	us.users["alice@example.com"] = &mockUser{subjectID: "user-alice", identifier: "alice@example.com"}

	m, _ := NewMode(Config{
		UserStore:      us,
		MagicLinkStore: ts,
		Notifier:       notif,
		TTL:            1 * time.Millisecond, // Very short TTL.
	})

	rawToken, err := m.Initiate(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	// Wait for token to expire.
	time.Sleep(5 * time.Millisecond)

	_, err = m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for expired token, got %v", err)
	}
}

// 9.7: Token deleted after first verification (single-use).
func TestMagicLink_VerifyToken_SingleUse(t *testing.T) {
	m, _, ts, _ := buildTestMode(t)
	ctx := context.Background()

	rawToken, _ := m.Initiate(ctx, "alice@example.com")

	// First use succeeds.
	_, err := m.Authenticate(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	})
	if err != nil {
		t.Fatalf("first Authenticate: %v", err)
	}

	// Store should be empty now.
	ts.mu.Lock()
	count := len(ts.tokens)
	ts.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 tokens after consumption, got %d", count)
	}
}

// 9.8: Second verification attempt → error.
func TestMagicLink_VerifyToken_AlreadyUsed(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	ctx := context.Background()

	rawToken, _ := m.Initiate(ctx, "alice@example.com")

	// First use succeeds.
	_, _ = m.Authenticate(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	})

	// Second use fails.
	_, err := m.Authenticate(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for reused token, got %v", err)
	}
}

// 9.9: Non-existent token → error.
func TestMagicLink_VerifyToken_NotFound(t *testing.T) {
	m, _, _, _ := buildTestMode(t)

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: "nonexistent-token-value",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for non-existent token, got %v", err)
	}
}

// 9.10: User not found → generic error (no enumeration).
func TestMagicLink_UserNotFound(t *testing.T) {
	m, _, _, notif := buildTestMode(t)
	ctx := context.Background()

	// Initiate for non-existent user — should return no error and no token.
	token, err := m.Initiate(ctx, "unknown@example.com")
	if err != nil {
		t.Fatalf("expected nil error for non-existent user, got %v", err)
	}
	if token != "" {
		t.Errorf("expected empty token for non-existent user, got %q", token)
	}

	// Notifier should NOT have been called.
	if notif.callCount() != 0 {
		t.Errorf("expected 0 notify calls for non-existent user, got %d", notif.callCount())
	}
}

// 9.11: Mode fails to initialize without Notifier.
func TestMagicLink_NotifierRequired(t *testing.T) {
	_, err := NewMode(Config{
		UserStore:      newMockUserStore(),
		MagicLinkStore: newMockMagicLinkStore(),
		Notifier:       nil,
	})
	if err == nil {
		t.Fatal("expected error when Notifier is nil")
	}
}

// 9.12: Supports CredentialTypeMagicLink.
func TestMagicLink_Supports(t *testing.T) {
	m, _, _, _ := buildTestMode(t)

	if !m.Supports(auth.CredentialTypeMagicLink) {
		t.Error("expected Supports(CredentialTypeMagicLink) to be true")
	}
	if m.Supports(auth.CredentialTypePassword) {
		t.Error("expected Supports(CredentialTypePassword) to be false")
	}
	if m.Supports(auth.CredentialTypeAPIKey) {
		t.Error("expected Supports(CredentialTypeAPIKey) to be false")
	}
	if m.Supports(auth.CredentialTypeOAuth) {
		t.Error("expected Supports(CredentialTypeOAuth) to be false")
	}
}

// 9.13: Returns "magic_link".
func TestMagicLink_Name(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	if m.Name() != "magic_link" {
		t.Errorf("expected Name() = 'magic_link', got %q", m.Name())
	}
}

// 9.14: Satisfies AuthMode interface.
func TestMagicLink_ImplementsAuthMode(t *testing.T) {
	var _ auth.AuthMode = (*Mode)(nil)
}

// 9.15: Identifier normalized via IdentifierConfig before lookup.
func TestMagicLink_IdentifierNormalization(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	ctx := context.Background()

	// IdentifierConfig.Normalize = strings.ToLower, so "Alice@Example.COM" → "alice@example.com".
	token, err := m.Initiate(ctx, "Alice@Example.COM")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token for normalized identifier")
	}

	// Verify the token works.
	identity, err := m.Authenticate(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: token,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.SubjectID != "user-alice" {
		t.Errorf("expected SubjectID 'user-alice', got %q", identity.SubjectID)
	}
}

// --- Hardening Tests ---

// 9.16: Empty identifier in Initiate does not panic.
func TestMagicLink_Initiate_EmptyIdentifier(t *testing.T) {
	m, _, _, notif := buildTestMode(t)
	ctx := context.Background()

	token, err := m.Initiate(ctx, "")
	if err != nil {
		t.Fatalf("Initiate with empty identifier should not error, got: %v", err)
	}
	// Empty identifier maps to non-existent user → silent nil return.
	if token != "" {
		t.Errorf("expected empty token for non-existent user, got %q", token)
	}
	// Notifier should NOT be called.
	if notif.callCount() != 0 {
		t.Errorf("expected 0 notifier calls for non-existent user, got %d", notif.callCount())
	}
}

// 9.17: Notifier failure propagates error from Initiate.
func TestMagicLink_Initiate_NotifierFailure(t *testing.T) {
	m, _, _, notif := buildTestMode(t)
	ctx := context.Background()

	notif.shouldFail = true

	_, err := m.Initiate(ctx, "alice@example.com")
	if err == nil {
		t.Fatal("expected error when notifier fails")
	}
	if !strings.Contains(err.Error(), "notification") && !strings.Contains(err.Error(), "notify") {
		// Accept any error that indicates notification failure.
		t.Logf("notifier failure error: %v", err)
	}
}

// 9.18: Concurrent token consumption — only one succeeds (single-use).
func TestMagicLink_Concurrent_Consume(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	ctx := context.Background()

	token, err := m.Initiate(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	const goroutines = 20
	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, err := m.Authenticate(ctx, auth.Credential{
				Type:   auth.CredentialTypeMagicLink,
				Secret: token,
			})
			results <- err
		}()
	}

	successes := 0
	failures := 0
	for i := 0; i < goroutines; i++ {
		err := <-results
		if err == nil {
			successes++
		} else {
			failures++
		}
	}

	if successes != 1 {
		t.Errorf("expected exactly 1 success for single-use token, got %d", successes)
	}
	if failures != goroutines-1 {
		t.Errorf("expected %d failures, got %d", goroutines-1, failures)
	}
}

// 9.19: AuthTime is set on successful authentication.
func TestMagicLink_AuthTime_Set(t *testing.T) {
	m, _, _, _ := buildTestMode(t)
	ctx := context.Background()

	token, err := m.Initiate(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	before := time.Now()
	identity, err := m.Authenticate(ctx, auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: token,
	})
	after := time.Now()

	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.AuthTime.IsZero() {
		t.Fatal("expected AuthTime to be set")
	}
	if identity.AuthTime.Before(before) || identity.AuthTime.After(after) {
		t.Errorf("AuthTime %v out of expected range [%v, %v]", identity.AuthTime, before, after)
	}
}

// 9.20: NewMode returns error for nil UserStore.
func TestMagicLink_NewMode_NilUserStore(t *testing.T) {
	_, err := NewMode(Config{
		UserStore:      nil,
		MagicLinkStore: newMockMagicLinkStore(),
		Notifier:       newMockNotifier(),
	})
	if err == nil {
		t.Fatal("expected error for nil UserStore")
	}
	if !strings.Contains(err.Error(), "UserStore") {
		t.Errorf("expected error mentioning UserStore, got: %v", err)
	}
}

// 9.21: NewMode returns error for nil MagicLinkStore.
func TestMagicLink_NewMode_NilMagicLinkStore(t *testing.T) {
	_, err := NewMode(Config{
		UserStore:      newMockUserStore(),
		MagicLinkStore: nil,
		Notifier:       newMockNotifier(),
	})
	if err == nil {
		t.Fatal("expected error for nil MagicLinkStore")
	}
	if !strings.Contains(err.Error(), "MagicLinkStore") {
		t.Errorf("expected error mentioning MagicLinkStore, got: %v", err)
	}
}

// 9.22: Initiate with failing token store returns error.
func TestMagicLink_Initiate_StoreFailure(t *testing.T) {
	us := newMockUserStore()
	us.users["alice@example.com"] = &mockUser{
		subjectID:  "user-alice",
		identifier: "alice@example.com",
	}

	failStore := &failingMagicLinkStore{storeErr: errors.New("store broken")}
	notif := newMockNotifier()

	m, err := NewMode(Config{
		UserStore:      us,
		MagicLinkStore: failStore,
		Notifier:       notif,
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}

	_, err = m.Initiate(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("expected error when token store fails")
	}
	if !strings.Contains(err.Error(), "store") {
		t.Errorf("expected 'store' in error, got: %v", err)
	}
}

// 9.23: Authenticate with empty secret returns ErrInvalidCredentials.
func TestMagicLink_Authenticate_EmptySecret(t *testing.T) {
	m, _, _, _ := buildTestMode(t)

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: "",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

// 9.24: Default TTL is applied when not configured.
func TestMagicLink_DefaultTTL(t *testing.T) {
	us := newMockUserStore()
	ts := newMockMagicLinkStore()
	notif := newMockNotifier()

	m, err := NewMode(Config{
		UserStore:      us,
		MagicLinkStore: ts,
		Notifier:       notif,
		TTL:            0, // Should use default.
	})
	if err != nil {
		t.Fatalf("NewMode: %v", err)
	}
	if m.ttl != defaultTTL {
		t.Errorf("expected default TTL %v, got %v", defaultTTL, m.ttl)
	}
}

// 9.25: Initiate with normalizer applies normalization before lookup.
func TestMagicLink_Initiate_Normalization(t *testing.T) {
	m, us, ts, _ := buildTestMode(t)

	// Add user with lowercase.
	us.users["upper@example.com"] = &mockUser{
		subjectID:  "user-upper",
		identifier: "upper@example.com",
	}

	// Initiate with uppercase — normalizer (ToLower) should find it.
	rawToken, err := m.Initiate(context.Background(), "UPPER@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("Initiate() error: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected non-empty token")
	}

	// Token should be stored.
	ts.mu.Lock()
	tokenCount := len(ts.tokens)
	ts.mu.Unlock()
	if tokenCount != 1 {
		t.Errorf("expected 1 token stored, got %d", tokenCount)
	}
}

// failingMagicLinkStore always returns an error on Store.
type failingMagicLinkStore struct {
	storeErr error
}

func (f *failingMagicLinkStore) Store(_ context.Context, _ *session.MagicLinkToken) error {
	return f.storeErr
}

func (f *failingMagicLinkStore) Consume(_ context.Context, _ string) (*session.MagicLinkToken, error) {
	return nil, auth.ErrTokenNotFound
}
