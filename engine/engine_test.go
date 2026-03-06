// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
)

// --- Mock implementations ---

// mockUser implements auth.User.
type mockUser struct {
	subjectID    string
	identifier   string
	passwordHash string
	failed       int
	locked       bool
	mfa          bool
}

func (u *mockUser) GetSubjectID() string        { return u.subjectID }
func (u *mockUser) GetIdentifier() string       { return u.identifier }
func (u *mockUser) GetPasswordHash() string     { return u.passwordHash }
func (u *mockUser) GetFailedAttempts() int      { return u.failed }
func (u *mockUser) IsLocked() bool              { return u.locked }
func (u *mockUser) IsMFAEnabled() bool          { return u.mfa }
func (u *mockUser) GetMetadata() map[string]any { return nil }

// mockUserStore implements auth.UserStore.
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
	id := user.GetIdentifier()
	if _, exists := s.users[id]; exists {
		return auth.ErrUserAlreadyExists
	}
	s.users[id] = &mockUser{
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

func (s *mockUserStore) IncrementFailedAttempts(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.failed++
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *mockUserStore) ResetFailedAttempts(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.failed = 0
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *mockUserStore) SetLocked(_ context.Context, subjectID string, locked bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.locked = locked
			return nil
		}
	}
	return auth.ErrUserNotFound
}

// mockSessionManager implements engine.SessionManager.
type mockSessionManager struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
	counter  int
}

func newMockSessionManager() *mockSessionManager {
	return &mockSessionManager{sessions: make(map[string]*session.Session)}
}

func (m *mockSessionManager) CreateSession(_ context.Context, subjectID string, existingSessionID string, metadata map[string]any) (string, *session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Session fixation prevention.
	if existingSessionID != "" {
		delete(m.sessions, existingSessionID)
	}

	m.counter++
	rawID := fmt.Sprintf("raw-session-%d", m.counter)
	now := time.Now()
	sess := &session.Session{
		ID:            fmt.Sprintf("hashed-session-%d", m.counter),
		SubjectID:     subjectID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
		LastActiveAt:  now,
		SchemaVersion: session.SchemaVersion,
		Metadata:      metadata,
	}
	m.sessions[rawID] = sess
	return rawID, sess, nil
}

func (m *mockSessionManager) ValidateSession(_ context.Context, rawID string) (*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[rawID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return sess, nil
}

func (m *mockSessionManager) RefreshSession(_ context.Context, rawID string) (*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[rawID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	sess.LastActiveAt = time.Now()
	return sess, nil
}

func (m *mockSessionManager) DestroySession(_ context.Context, rawID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, rawID)
	return nil
}

func (m *mockSessionManager) DestroyAllSessions(_ context.Context, subjectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.sessions {
		if s.SubjectID == subjectID {
			delete(m.sessions, k)
		}
	}
	return nil
}

// mockHasher implements auth.Hasher.
type mockHasher struct{}

func (h *mockHasher) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

func (h *mockHasher) Verify(password string, hash string) (bool, error) {
	return hash == "hashed:"+password, nil
}

// mockAuthMode implements auth.AuthMode.
type mockAuthMode struct {
	name       string
	supports   auth.CredentialType
	authResult *auth.Identity
	authErr    error
}

func (m *mockAuthMode) Name() string { return m.name }

func (m *mockAuthMode) Authenticate(_ context.Context, cred auth.Credential) (*auth.Identity, error) {
	if m.authErr != nil {
		return nil, m.authErr
	}
	// Return a copy to avoid data races when callers mutate the identity.
	cp := *m.authResult
	return &cp, nil
}

func (m *mockAuthMode) Supports(ct auth.CredentialType) bool {
	return ct == m.supports
}

// mockNotifier implements auth.Notifier.
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

// mockMagicLinkMode is a mode that supports magic_link credential type.
type mockMagicLinkMode struct{}

func (m *mockMagicLinkMode) Name() string { return "magic_link" }
func (m *mockMagicLinkMode) Authenticate(_ context.Context, _ auth.Credential) (*auth.Identity, error) {
	return &auth.Identity{SubjectID: "ml-user"}, nil
}
func (m *mockMagicLinkMode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypeMagicLink
}

// --- import fmt for mockSessionManager ---

// (imported above)

// --- Helper to build a default engine for tests ---

func buildTestEngine(t *testing.T, opts ...func(*Config)) *Engine {
	t.Helper()
	us := newMockUserStore()
	sm := newMockSessionManager()
	h := &mockHasher{}
	pwMode := &mockAuthMode{
		name:     "password",
		supports: auth.CredentialTypePassword,
		authResult: &auth.Identity{
			SubjectID:  "alice",
			AuthMethod: "password",
		},
	}

	cfg := Config{
		UserStore:      us,
		Hasher:         h,
		SessionManager: sm,
		PasswordPolicy: password.DefaultPolicy(),
		Modes:          []auth.AuthMode{pwMode},
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	return eng
}

// --- Test 6.1: Registration success ---

func TestEngine_Register_Success(t *testing.T) {
	eng := buildTestEngine(t)

	id, sess, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "strongpassword123",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("expected identity, got nil")
	}
	if id.SubjectID != "alice@example.com" {
		t.Errorf("expected SubjectID alice@example.com, got %s", id.SubjectID)
	}
	if id.AuthMethod != "password" {
		t.Errorf("expected AuthMethod password, got %s", id.AuthMethod)
	}
	if id.SessionID == "" {
		t.Error("expected non-empty SessionID")
	}
	if sess == nil {
		t.Fatal("expected session, got nil")
	}
}

// --- Test 6.2: Registration with weak password ---

func TestEngine_Register_PasswordPolicyViolation(t *testing.T) {
	eng := buildTestEngine(t)

	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "bob@example.com",
		Secret:     "short", // Too short for default policy (min 8).
	})

	if !errors.Is(err, auth.ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation, got %v", err)
	}
}

// --- Test 6.3: Registration with duplicate user ---

func TestEngine_Register_DuplicateUser(t *testing.T) {
	eng := buildTestEngine(t)
	ctx := context.Background()

	// Register first user.
	_, _, err := eng.Register(ctx, auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "strongpassword123",
	})
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Try to register same user again.
	_, _, err = eng.Register(ctx, auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "anotherpassword123",
	})

	if !errors.Is(err, auth.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}
}

// --- Test 6.4: Registration hooks fire in order ---

func TestEngine_Register_HooksFireInOrder(t *testing.T) {
	hm := hooks.NewManager()
	var order []string

	hm.Register(hooks.Event(auth.EventRegistration), func(_ context.Context, p hooks.HookPayload) error {
		rp := p.(*hooks.RegisterPayload)
		if rp.SubjectID == "" {
			order = append(order, "before")
		} else {
			order = append(order, "after")
		}
		return nil
	})

	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = hm
	})

	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "strongpassword123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(order) != 2 {
		t.Fatalf("expected 2 hook calls, got %d: %v", len(order), order)
	}
	if order[0] != "before" || order[1] != "after" {
		t.Errorf("hooks out of order: %v", order)
	}
}

// --- Test 6.5: BeforeRegister hook aborts registration ---

func TestEngine_Register_BeforeHookAbort(t *testing.T) {
	hm := hooks.NewManager()
	abortErr := errors.New("blocked by policy")
	hm.Register(hooks.Event(auth.EventRegistration), func(_ context.Context, _ hooks.HookPayload) error {
		return abortErr
	})

	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = hm
	})

	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "strongpassword123",
	})

	if !errors.Is(err, abortErr) {
		t.Fatalf("expected abort error, got %v", err)
	}
}

// --- Test 6.6: Session created immediately on registration ---

func TestEngine_Register_SessionCreated(t *testing.T) {
	eng := buildTestEngine(t)

	id, sess, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "strongpassword123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the session can be validated.
	verifiedID, err := eng.Verify(context.Background(), id.SessionID)
	if err != nil {
		t.Fatalf("session validation failed: %v", err)
	}
	if verifiedID.SubjectID != "alice@example.com" {
		t.Errorf("expected SubjectID alice@example.com, got %s", verifiedID.SubjectID)
	}
	if sess.SubjectID != "alice@example.com" {
		t.Errorf("session SubjectID mismatch: %s", sess.SubjectID)
	}
}

// --- Test 6.7: Login dispatches to correct mode ---

func TestEngine_Login_DispatchesToCorrectMode(t *testing.T) {
	pwMode := &mockAuthMode{
		name:     "password",
		supports: auth.CredentialTypePassword,
		authResult: &auth.Identity{
			SubjectID:  "alice",
			AuthMethod: "password",
		},
	}
	apiMode := &mockAuthMode{
		name:     "api_key",
		supports: auth.CredentialTypeAPIKey,
		authResult: &auth.Identity{
			SubjectID:  "service-1",
			AuthMethod: "api_key",
		},
	}

	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.Modes = []auth.AuthMode{pwMode, apiMode}
	})

	// Login with password.
	id, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("password login failed: %v", err)
	}
	if id.SubjectID != "alice" {
		t.Errorf("expected alice, got %s", id.SubjectID)
	}

	// Login with API key.
	id, _, err = eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypeAPIKey,
		Identifier: "service-1",
		Secret:     "key-xxx",
	})
	if err != nil {
		t.Fatalf("api key login failed: %v", err)
	}
	if id.SubjectID != "service-1" {
		t.Errorf("expected service-1, got %s", id.SubjectID)
	}
}

// --- Test 6.8: Login creates session on success ---

func TestEngine_Login_SessionCreatedOnSuccess(t *testing.T) {
	eng := buildTestEngine(t)

	id, sess, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.SessionID == "" {
		t.Error("expected non-empty SessionID")
	}
	if sess == nil {
		t.Fatal("expected session, got nil")
	}
	if sess.SubjectID != "alice" {
		t.Errorf("expected session SubjectID alice, got %s", sess.SubjectID)
	}
}

// --- Test 6.9: Login hooks fire ---

func TestEngine_Login_HooksFire(t *testing.T) {
	hm := hooks.NewManager()
	var hookEvents []string

	hm.Register(hooks.Event(auth.EventLogin), func(_ context.Context, p hooks.HookPayload) error {
		lp := p.(*hooks.LoginPayload)
		if lp.SubjectID == "" {
			hookEvents = append(hookEvents, "before_login")
		} else {
			hookEvents = append(hookEvents, "after_login")
		}
		return nil
	})

	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = hm
	})

	_, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(hookEvents) != 2 {
		t.Fatalf("expected 2 hook events, got %d: %v", len(hookEvents), hookEvents)
	}
	if hookEvents[0] != "before_login" || hookEvents[1] != "after_login" {
		t.Errorf("hooks out of order: %v", hookEvents)
	}

	// Test failed login hook.
	failedHookCalled := false
	hm.Register(hooks.Event(auth.EventLoginFailed), func(_ context.Context, p hooks.HookPayload) error {
		failedHookCalled = true
		lp := p.(*hooks.LoginPayload)
		if lp.Error == nil {
			t.Error("expected error in failed login payload")
		}
		return nil
	})

	failMode := &mockAuthMode{
		name:     "password",
		supports: auth.CredentialTypePassword,
		authErr:  auth.ErrInvalidCredentials,
	}
	eng2 := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = hm
		cfg.Modes = []auth.AuthMode{failMode}
	})

	_, _, err = eng2.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "wrong",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if !failedHookCalled {
		t.Error("AfterFailedLogin hook was not called")
	}
}

// --- Test 6.10: No panic when Notifier is nil ---

func TestEngine_Login_NotifierOptional(t *testing.T) {
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.Notifier = nil // Explicitly nil.
	})

	// Should not panic.
	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "strongpassword123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Test 6.11: Logout destroys session ---

func TestEngine_Logout_SessionDestroyed(t *testing.T) {
	eng := buildTestEngine(t)

	// First login to create a session.
	id, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Logout.
	err = eng.Logout(context.Background(), id.SessionID, id.SubjectID)
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	// Verify session is gone.
	_, err = eng.Verify(context.Background(), id.SessionID)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound after logout, got %v", err)
	}
}

// --- Test 6.12: Logout hook fires ---

func TestEngine_Logout_HookFires(t *testing.T) {
	hm := hooks.NewManager()
	logoutHookCalled := false
	var logoutPayload *hooks.LogoutPayload

	hm.Register(hooks.Event(auth.EventLogout), func(_ context.Context, p hooks.HookPayload) error {
		logoutHookCalled = true
		logoutPayload = p.(*hooks.LogoutPayload)
		return nil
	})

	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = hm
	})

	// Login first.
	id, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Logout.
	err = eng.Logout(context.Background(), id.SessionID, "alice")
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}

	if !logoutHookCalled {
		t.Fatal("AfterLogout hook was not called")
	}
	if logoutPayload.SubjectID != "alice" {
		t.Errorf("expected SubjectID alice, got %s", logoutPayload.SubjectID)
	}
	if logoutPayload.SessionID != id.SessionID {
		t.Errorf("expected SessionID %s, got %s", id.SessionID, logoutPayload.SessionID)
	}
}

// --- Test 6.13: Verify validates session ---

func TestEngine_Verify_SessionValidation(t *testing.T) {
	eng := buildTestEngine(t)

	// Login to create session.
	id, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Verify.
	verified, err := eng.Verify(context.Background(), id.SessionID)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verified.SubjectID != "alice" {
		t.Errorf("expected SubjectID alice, got %s", verified.SubjectID)
	}

	// Verify with invalid session.
	_, err = eng.Verify(context.Background(), "nonexistent")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

// --- Test 6.14: Verify returns Identity ---

func TestEngine_Verify_ReturnsIdentity(t *testing.T) {
	eng := buildTestEngine(t)

	id, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	verified, err := eng.Verify(context.Background(), id.SessionID)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verified == nil {
		t.Fatal("expected identity, got nil")
	}
	if verified.SubjectID != "alice" {
		t.Errorf("expected SubjectID alice, got %s", verified.SubjectID)
	}
	if verified.SessionID != id.SessionID {
		t.Errorf("expected SessionID %s, got %s", id.SessionID, verified.SessionID)
	}
}

// --- Test 6.15: Mode registration ---

func TestEngine_ModeRegistration(t *testing.T) {
	pwMode := &mockAuthMode{
		name:       "password",
		supports:   auth.CredentialTypePassword,
		authResult: &auth.Identity{SubjectID: "user-pw"},
	}
	apiMode := &mockAuthMode{
		name:       "api_key",
		supports:   auth.CredentialTypeAPIKey,
		authResult: &auth.Identity{SubjectID: "user-api"},
	}

	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.Modes = []auth.AuthMode{pwMode, apiMode}
	})

	// Both modes should be registered.
	_, ok := eng.modes[auth.CredentialTypePassword]
	if !ok {
		t.Error("password mode not registered")
	}
	_, ok = eng.modes[auth.CredentialTypeAPIKey]
	if !ok {
		t.Error("api_key mode not registered")
	}
}

// --- Test 6.16: Unknown credential type ---

func TestEngine_UnknownCredentialType(t *testing.T) {
	eng := buildTestEngine(t)

	_, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       "unknown_type",
		Identifier: "alice",
		Secret:     "password123",
	})

	if err == nil {
		t.Fatal("expected error for unknown credential type")
	}
	if !containsString(err.Error(), "unsupported credential type") {
		t.Errorf("expected 'unsupported credential type' in error, got: %v", err)
	}
}

// --- Test 6.17: Notifier required for magic link ---

func TestEngine_NotifierRequired_ForMagicLink(t *testing.T) {
	us := newMockUserStore()
	sm := newMockSessionManager()
	ml := &mockMagicLinkMode{}

	cfg := Config{
		UserStore:      us,
		SessionManager: sm,
		Modes:          []auth.AuthMode{ml},
		Notifier:       nil, // No notifier.
	}

	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error when magic link mode enabled without Notifier")
	}
	if !containsString(err.Error(), "Notifier is required") {
		t.Errorf("expected 'Notifier is required' in error, got: %v", err)
	}

	// With Notifier, it should work.
	cfg.Notifier = &mockNotifier{}
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("expected no error with Notifier, got: %v", err)
	}
	if eng == nil {
		t.Fatal("expected engine, got nil")
	}
}

// containsString checks if s contains substr.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- Hardening Tests ---

// Test 6.18: New() returns error for nil UserStore.
func TestEngine_New_NilUserStore(t *testing.T) {
	_, err := New(Config{
		UserStore:      nil,
		SessionManager: newMockSessionManager(),
	})
	if err == nil {
		t.Fatal("expected error for nil UserStore")
	}
	if !containsString(err.Error(), "UserStore") {
		t.Errorf("expected error mentioning UserStore, got: %v", err)
	}
}

// Test 6.19: New() returns error for nil SessionManager.
func TestEngine_New_NilSessionManager(t *testing.T) {
	_, err := New(Config{
		UserStore:      newMockUserStore(),
		SessionManager: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil SessionManager")
	}
	if !containsString(err.Error(), "SessionManager") {
		t.Errorf("expected error mentioning SessionManager, got: %v", err)
	}
}

// Test 6.20: HookManager auto-created when nil.
func TestEngine_New_NilHookManager(t *testing.T) {
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = nil
	})
	if eng.hookMgr == nil {
		t.Fatal("expected non-nil HookManager even when config is nil")
	}
}

// Test 6.21: Concurrent Register does not panic.
func TestEngine_Register_Concurrent(t *testing.T) {
	eng := buildTestEngine(t)

	const goroutines = 20
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer func() { done <- struct{}{} }()
			eng.Register(context.Background(), auth.Credential{
				Type:       auth.CredentialTypePassword,
				Identifier: fmt.Sprintf("user-%d@example.com", i),
				Secret:     "strongpassword123",
			})
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
	// No panic = pass.
}

// Test 6.22: Concurrent Login does not panic.
func TestEngine_Login_Concurrent(t *testing.T) {
	eng := buildTestEngine(t)

	const goroutines = 20
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			eng.Login(context.Background(), auth.Credential{
				Type:       auth.CredentialTypePassword,
				Identifier: "alice",
				Secret:     "password123",
			})
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// Test 6.23: Register sets AuthTime on Identity.
func TestEngine_Register_AuthTime(t *testing.T) {
	eng := buildTestEngine(t)

	before := time.Now()
	id, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "timecheck@example.com",
		Secret:     "strongpassword123",
	})
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AuthTime.IsZero() {
		t.Fatal("expected AuthTime to be set on registration")
	}
	if id.AuthTime.Before(before) || id.AuthTime.After(after) {
		t.Errorf("AuthTime %v out of expected range [%v, %v]", id.AuthTime, before, after)
	}
}

// Test 6.24: Login with empty credential type.
func TestEngine_Login_EmptyCredentialType(t *testing.T) {
	eng := buildTestEngine(t)

	_, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       "",
		Identifier: "alice",
		Secret:     "password123",
	})
	if err == nil {
		t.Fatal("expected error for empty credential type")
	}
}

// Test 6.25: Verify with empty sessionID returns ErrSessionNotFound.
func TestEngine_Verify_EmptySessionID(t *testing.T) {
	eng := buildTestEngine(t)

	_, err := eng.Verify(context.Background(), "")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for empty sessionID, got: %v", err)
	}
}

// Test 6.26: Close returns nil (graceful shutdown).
func TestEngine_Close(t *testing.T) {
	eng := buildTestEngine(t)
	if err := eng.Close(); err != nil {
		t.Errorf("expected nil from Close(), got: %v", err)
	}
}

// Test 6.27: HookManager accessor returns the correct instance.
func TestEngine_HookManager_Accessor(t *testing.T) {
	hm := hooks.NewManager()
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.HookManager = hm
	})
	if eng.HookManager() != hm {
		t.Error("HookManager() did not return the configured hook manager")
	}
}

// Test 6.28: Register fires Notifier when configured.
func TestEngine_Register_WithNotifier(t *testing.T) {
	notifier := &mockNotifier{}
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.Notifier = notifier
	})

	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "notified@example.com",
		Secret:     "strongpassword123",
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	notifier.mu.Lock()
	defer notifier.mu.Unlock()
	if len(notifier.events) == 0 {
		t.Fatal("expected Notifier to be called on registration")
	}
	if notifier.events[0] != auth.EventRegistration {
		t.Errorf("expected EventRegistration, got %v", notifier.events[0])
	}
}

// Test 6.29: Login fires AfterLoginFailed hook on auth error.
func TestEngine_Login_FailedHookFires(t *testing.T) {
	var hookedErr error
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.Modes = []auth.AuthMode{&mockAuthMode{
			name:     "password",
			supports: auth.CredentialTypePassword,
			authErr:  auth.ErrInvalidCredentials,
		}}
	})

	eng.HookManager().Register(hooks.Event(auth.EventLoginFailed), func(ctx context.Context, payload hooks.HookPayload) error {
		if lp, ok := payload.(*hooks.LoginPayload); ok {
			hookedErr = lp.Error
		}
		return nil
	})

	_, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "wrong",
	})
	if err == nil {
		t.Fatal("expected Login to fail")
	}
	if !errors.Is(hookedErr, auth.ErrInvalidCredentials) {
		t.Errorf("expected hooked error ErrInvalidCredentials, got: %v", hookedErr)
	}
}

// Test 6.30: Login with session fixation prevention (existing_session_id metadata).
func TestEngine_Login_SessionFixation(t *testing.T) {
	eng := buildTestEngine(t)

	_, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
		Metadata: map[string]any{
			"existing_session_id": "old-session-123",
		},
	})
	if err != nil {
		t.Fatalf("Login() error: %v", err)
	}
	// No panic = pass; the mock session manager handles fixation prevention.
}

// Test 6.31: normalizeIdentifier with custom normalizer.
func TestEngine_NormalizeIdentifier(t *testing.T) {
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.IdentifierConfig = auth.IdentifierConfig{
			Normalize: func(id string) string {
				return "normalized:" + id
			},
		}
	})

	id, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "Alice@Example.com",
		Secret:     "strongpassword123",
	})
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if id.SubjectID != "normalized:Alice@Example.com" {
		t.Errorf("expected normalized subject ID, got %q", id.SubjectID)
	}
}

// Test 6.32: Logout with destroy failure propagates error.
func TestEngine_Logout_DestroyError(t *testing.T) {
	us := newMockUserStore()
	failSM := &failingSessionManager{err: fmt.Errorf("destroy failed")}
	eng, err := New(Config{
		UserStore:      us,
		SessionManager: failSM,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	err = eng.Logout(context.Background(), "sess-1", "user-1")
	if err == nil {
		t.Fatal("expected error from Logout when DestroySession fails")
	}
	if !containsString(err.Error(), "destroy") {
		t.Errorf("expected 'destroy' in error, got: %v", err)
	}
}

// Test 6.33: Register hash failure propagates error.
func TestEngine_Register_HashFailure(t *testing.T) {
	eng := buildTestEngine(t, func(cfg *Config) {
		cfg.Hasher = &failingHasher{err: fmt.Errorf("hash exploded")}
	})

	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "hashfail@example.com",
		Secret:     "strongpassword123",
	})
	if err == nil {
		t.Fatal("expected error from Register when hash fails")
	}
	if !containsString(err.Error(), "hash") {
		t.Errorf("expected 'hash' in error, got: %v", err)
	}
}

// Test 6.34: Register BeforeRegister hook can abort.
func TestEngine_Register_BeforeHookError(t *testing.T) {
	hookErr := fmt.Errorf("blocked by policy")
	eng := buildTestEngine(t)

	eng.HookManager().Register(hooks.Event(auth.EventRegistration), func(ctx context.Context, payload hooks.HookPayload) error {
		return hookErr
	})

	_, _, err := eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "blocked@example.com",
		Secret:     "strongpassword123",
	})
	if !errors.Is(err, hookErr) {
		t.Errorf("expected hook error, got: %v", err)
	}
}

// Test 6.35: Login BeforeLogin hook can abort.
func TestEngine_Login_BeforeHookError(t *testing.T) {
	hookErr := fmt.Errorf("rate limited")
	eng := buildTestEngine(t)

	eng.HookManager().Register(hooks.Event(auth.EventLogin), func(ctx context.Context, payload hooks.HookPayload) error {
		return hookErr
	})

	_, _, err := eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if !errors.Is(err, hookErr) {
		t.Errorf("expected hook error, got: %v", err)
	}
}

// failingSessionManager is a session manager that always returns an error.
type failingSessionManager struct {
	err error
}

func (f *failingSessionManager) CreateSession(_ context.Context, _ string, _ string, _ map[string]any) (string, *session.Session, error) {
	return "", nil, f.err
}
func (f *failingSessionManager) ValidateSession(_ context.Context, _ string) (*session.Session, error) {
	return nil, f.err
}
func (f *failingSessionManager) RefreshSession(_ context.Context, _ string) (*session.Session, error) {
	return nil, f.err
}
func (f *failingSessionManager) DestroySession(_ context.Context, _ string) error {
	return f.err
}
func (f *failingSessionManager) DestroyAllSessions(_ context.Context, _ string) error {
	return f.err
}

// failingHasher always returns an error.
type failingHasher struct {
	err error
}

func (h *failingHasher) Hash(_ string) (string, error)           { return "", h.err }
func (h *failingHasher) Verify(_ string, _ string) (bool, error) { return false, h.err }

// Test 6.36: Register with userStore.Create failure propagates error.
func TestEngine_Register_UserStoreCreateError(t *testing.T) {
	us := &failingUserStore{
		findErr:   auth.ErrUserNotFound,
		createErr: fmt.Errorf("constraint violation"),
	}
	sm := &mockSessionManager{}
	eng, err := New(Config{
		UserStore:      us,
		SessionManager: sm,
		PasswordPolicy: password.DefaultPolicy(),
		Modes: []auth.AuthMode{&mockAuthMode{
			name:     "password",
			supports: auth.CredentialTypePassword,
		}},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	_, _, err = eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "fail@example.com",
		Secret:     "strongpassword123",
	})
	if err == nil {
		t.Fatal("expected error when userStore.Create fails")
	}
}

// Test 6.37: Register with sessionMgr.CreateSession failure propagates error.
func TestEngine_Register_SessionCreateError(t *testing.T) {
	us := newMockUserStore()
	failSM := &failingSessionManager{err: fmt.Errorf("session store down")}
	eng, err := New(Config{
		UserStore:      us,
		SessionManager: failSM,
		PasswordPolicy: password.DefaultPolicy(),
		Modes: []auth.AuthMode{&mockAuthMode{
			name:     "password",
			supports: auth.CredentialTypePassword,
		}},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	_, _, err = eng.Register(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "sessdown@example.com",
		Secret:     "strongpassword123",
	})
	if err == nil {
		t.Fatal("expected error when sessionMgr.CreateSession fails")
	}
	if !containsString(err.Error(), "session") {
		t.Errorf("expected 'session' in error, got: %v", err)
	}
}

// Test 6.38: Login with sessionMgr.CreateSession failure propagates error.
func TestEngine_Login_SessionCreateError(t *testing.T) {
	us := newMockUserStore()
	us.Create(context.Background(), &mockUser{
		subjectID:    "alice",
		identifier:   "alice",
		passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash",
	})

	failSM := &failingSessionManager{err: fmt.Errorf("session db full")}
	eng, err := New(Config{
		UserStore:      us,
		SessionManager: failSM,
		PasswordPolicy: password.DefaultPolicy(),
		Modes: []auth.AuthMode{&mockAuthMode{
			name:     "password",
			supports: auth.CredentialTypePassword,
			authResult: &auth.Identity{
				SubjectID:  "alice",
				AuthMethod: "password",
			},
		}},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	_, _, err = eng.Login(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice",
		Secret:     "password123",
	})
	if err == nil {
		t.Fatal("expected error when sessionMgr.CreateSession fails during login")
	}
}

// failingUserStore implements auth.UserStore with configurable errors.
type failingUserStore struct {
	findErr   error
	createErr error
}

func (f *failingUserStore) FindByIdentifier(_ context.Context, _ string) (auth.User, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	return nil, auth.ErrUserNotFound
}

func (f *failingUserStore) Create(_ context.Context, _ auth.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	return nil
}

func (f *failingUserStore) UpdatePassword(_ context.Context, _, _ string) error       { return nil }
func (f *failingUserStore) IncrementFailedAttempts(_ context.Context, _ string) error { return nil }
func (f *failingUserStore) ResetFailedAttempts(_ context.Context, _ string) error     { return nil }
func (f *failingUserStore) SetLocked(_ context.Context, _ string, _ bool) error       { return nil }
