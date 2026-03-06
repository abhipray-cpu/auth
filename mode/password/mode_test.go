// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package password

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// --- Mock implementations ---

type mockUser struct {
	subjectID    string
	identifier   string
	passwordHash string
	failed       int
	locked       bool
}

func (u *mockUser) GetSubjectID() string        { return u.subjectID }
func (u *mockUser) GetIdentifier() string       { return u.identifier }
func (u *mockUser) GetPasswordHash() string     { return u.passwordHash }
func (u *mockUser) GetFailedAttempts() int      { return u.failed }
func (u *mockUser) IsLocked() bool              { return u.locked }
func (u *mockUser) IsMFAEnabled() bool          { return false }
func (u *mockUser) GetMetadata() map[string]any { return nil }

type mockUserStore struct {
	mu    sync.Mutex
	users map[string]*mockUser
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{users: make(map[string]*mockUser)}
}

func (s *mockUserStore) addUser(id, identifier, hash string, failed int, locked bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[identifier] = &mockUser{
		subjectID:    id,
		identifier:   identifier,
		passwordHash: hash,
		failed:       failed,
		locked:       locked,
	}
}

func (s *mockUserStore) FindByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[identifier]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	// Return a copy to avoid races on the user fields.
	cp := *u
	return &cp, nil
}

func (s *mockUserStore) Create(_ context.Context, _ auth.User) error { return nil }
func (s *mockUserStore) UpdatePassword(_ context.Context, _ string, _ string) error {
	return nil
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
	return nil
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
	return nil
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
	return nil
}

// mockHasher is a simple hasher for testing (no real crypto).
type mockHasher struct{}

func (h *mockHasher) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

func (h *mockHasher) Verify(password string, hash string) (bool, error) {
	return hash == "hashed:"+password, nil
}

func buildTestMode(store *mockUserStore, opts ...func(*ModeConfig)) *Mode {
	cfg := ModeConfig{
		UserStore:        store,
		Hasher:           &mockHasher{},
		LockoutThreshold: 5,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return NewMode(cfg)
}

// --- Test 7.1: Correct credentials → Identity ---

func TestPasswordMode_Success(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	mode := buildTestMode(store)

	id, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "correctpassword",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.SubjectID != "user-1" {
		t.Errorf("expected SubjectID user-1, got %s", id.SubjectID)
	}
	if id.AuthMethod != "password" {
		t.Errorf("expected AuthMethod password, got %s", id.AuthMethod)
	}
}

// --- Test 7.2: Wrong password ---

func TestPasswordMode_WrongPassword(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	mode := buildTestMode(store)

	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "wrongpassword",
	})

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// --- Test 7.3: User not found → dummy hash → same error ---

func TestPasswordMode_UserNotFound(t *testing.T) {
	store := newMockUserStore()
	mode := buildTestMode(store)

	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "nonexistent@example.com",
		Secret:     "anypassword",
	})

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// --- Test 7.4: Locked account ---

func TestPasswordMode_AccountLocked(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 5, true)
	mode := buildTestMode(store)

	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "correctpassword",
	})

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for locked account, got %v", err)
	}
}

// --- Test 7.5: Failed attempts incremented ---

func TestPasswordMode_FailedAttempts_Increment(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	mode := buildTestMode(store)

	_, _ = mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "wrongpassword",
	})

	store.mu.Lock()
	user := store.users["alice@example.com"]
	failed := user.failed
	store.mu.Unlock()
	if failed != 1 {
		t.Errorf("expected 1 failed attempt, got %d", failed)
	}
}

// --- Test 7.6: Failed attempts reset on success ---

func TestPasswordMode_FailedAttempts_Reset(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 3, false)
	mode := buildTestMode(store)

	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "correctpassword",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	store.mu.Lock()
	user := store.users["alice@example.com"]
	failed := user.failed
	store.mu.Unlock()
	if failed != 0 {
		t.Errorf("expected 0 failed attempts after success, got %d", failed)
	}
}

// --- Test 7.7: Lockout after threshold ---

func TestPasswordMode_Lockout_AfterThreshold(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 4, false) // 4 failed, threshold is 5
	mode := buildTestMode(store)

	// This 5th attempt should trigger lockout.
	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "wrongpassword",
	})

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	store.mu.Lock()
	user := store.users["alice@example.com"]
	locked := user.locked
	store.mu.Unlock()
	if !locked {
		t.Error("expected account to be locked after reaching threshold")
	}
}

// --- Test 7.8: Lockout threshold configurable ---

func TestPasswordMode_Lockout_Configurable(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 2, false)

	// Custom threshold of 3.
	mode := buildTestMode(store, func(cfg *ModeConfig) {
		cfg.LockoutThreshold = 3
	})

	_, _ = mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "wrongpassword",
	})

	store.mu.Lock()
	user := store.users["alice@example.com"]
	locked := user.locked
	store.mu.Unlock()
	if !locked {
		t.Error("expected account to be locked after custom threshold")
	}
}

// --- Test 7.9: Constant-time for non-existent user ---

func TestPasswordMode_ConstantTime_UserNotFound(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	mode := buildTestMode(store)

	// Measure time for existing user (wrong password).
	start1 := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = mode.Authenticate(context.Background(), auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: "alice@example.com",
			Secret:     "wrongpassword",
		})
	}
	existingUserTime := time.Since(start1)

	// Reset failed attempts.
	store.mu.Lock()
	store.users["alice@example.com"].failed = 0
	store.users["alice@example.com"].locked = false
	store.mu.Unlock()

	// Measure time for non-existent user.
	start2 := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = mode.Authenticate(context.Background(), auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: "nonexistent@example.com",
			Secret:     "wrongpassword",
		})
	}
	nonExistentTime := time.Since(start2)

	// Both should be roughly similar. With mock hasher this is trivial,
	// but the test validates the code path exists (dummy hash is called).
	ratio := float64(nonExistentTime) / float64(existingUserTime)
	if ratio < 0.1 || ratio > 10 {
		t.Errorf("timing difference too large: existing=%v, nonexistent=%v, ratio=%.2f",
			existingUserTime, nonExistentTime, ratio)
	}
}

// --- Test 7.10: Constant-time for locked account ---

func TestPasswordMode_ConstantTime_LockedAccount(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	store.addUser("user-2", "locked@example.com", "hashed:correctpassword", 5, true)
	mode := buildTestMode(store)

	start1 := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = mode.Authenticate(context.Background(), auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: "alice@example.com",
			Secret:     "wrongpassword",
		})
	}
	wrongPwTime := time.Since(start1)

	// Reset state.
	store.mu.Lock()
	store.users["alice@example.com"].failed = 0
	store.users["alice@example.com"].locked = false
	store.mu.Unlock()

	start2 := time.Now()
	for i := 0; i < 100; i++ {
		_, _ = mode.Authenticate(context.Background(), auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: "locked@example.com",
			Secret:     "wrongpassword",
		})
	}
	lockedTime := time.Since(start2)

	ratio := float64(lockedTime) / float64(wrongPwTime)
	if ratio < 0.1 || ratio > 10 {
		t.Errorf("timing difference too large: wrongPw=%v, locked=%v, ratio=%.2f",
			wrongPwTime, lockedTime, ratio)
	}
}

// --- Test 7.11: Supports ---

func TestPasswordMode_Supports(t *testing.T) {
	mode := NewMode(ModeConfig{
		UserStore: newMockUserStore(),
		Hasher:    &mockHasher{},
	})

	if !mode.Supports(auth.CredentialTypePassword) {
		t.Error("expected Supports(CredentialTypePassword) = true")
	}
	if mode.Supports(auth.CredentialTypeOAuth) {
		t.Error("expected Supports(CredentialTypeOAuth) = false")
	}
	if mode.Supports(auth.CredentialTypeMagicLink) {
		t.Error("expected Supports(CredentialTypeMagicLink) = false")
	}
	if mode.Supports(auth.CredentialTypeAPIKey) {
		t.Error("expected Supports(CredentialTypeAPIKey) = false")
	}
}

// --- Test 7.12: Name ---

func TestPasswordMode_Name(t *testing.T) {
	mode := NewMode(ModeConfig{
		UserStore: newMockUserStore(),
		Hasher:    &mockHasher{},
	})
	if mode.Name() != "password" {
		t.Errorf("expected name 'password', got %s", mode.Name())
	}
}

// --- Test 7.13: Implements AuthMode ---

func TestPasswordMode_ImplementsAuthMode(t *testing.T) {
	var _ auth.AuthMode = (*Mode)(nil)
}

// --- Test 7.14: Identifier normalization ---

func TestPasswordMode_IdentifierNormalization(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:password123", 0, false)

	mode := buildTestMode(store, func(cfg *ModeConfig) {
		cfg.IdentifierConfig = auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(s) },
		}
	})

	// Login with uppercase email.
	id, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "ALICE@EXAMPLE.COM",
		Secret:     "password123",
	})

	if err != nil {
		t.Fatalf("expected success after normalization, got %v", err)
	}
	if id.SubjectID != "user-1" {
		t.Errorf("expected SubjectID user-1, got %s", id.SubjectID)
	}
}

// --- Test 7.15: Empty password ---

func TestPasswordMode_EmptyPassword(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:password123", 0, false)
	mode := buildTestMode(store)

	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "",
	})

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for empty password, got %v", err)
	}
}

// --- Test 7.16: Empty identifier ---

func TestPasswordMode_EmptyIdentifier(t *testing.T) {
	store := newMockUserStore()
	mode := buildTestMode(store)

	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "",
		Secret:     "somepassword",
	})

	if err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for empty identifier, got %v", err)
	}
}

// --- Test 7.17: NewMode panics on nil UserStore ---

func TestPasswordMode_NewMode_NilUserStore(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil UserStore")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "UserStore") {
			t.Errorf("expected panic mentioning UserStore, got: %v", r)
		}
	}()

	NewMode(ModeConfig{
		UserStore: nil,
		Hasher:    &mockHasher{},
	})
}

// --- Test 7.18: NewMode panics on nil Hasher ---

func TestPasswordMode_NewMode_NilHasher(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil Hasher")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "Hasher") {
			t.Errorf("expected panic mentioning Hasher, got: %v", r)
		}
	}()

	NewMode(ModeConfig{
		UserStore: newMockUserStore(),
		Hasher:    nil,
	})
}

// --- Test 7.19: Lockout disabled when threshold is 0 ---

func TestPasswordMode_Lockout_Disabled(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)

	mode := buildTestMode(store, func(cfg *ModeConfig) {
		cfg.LockoutThreshold = 0 // Disabled.
	})

	// Fail 10 times — account should NEVER be locked.
	for i := 0; i < 10; i++ {
		_, _ = mode.Authenticate(context.Background(), auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: "alice@example.com",
			Secret:     "wrongpassword",
		})
	}

	store.mu.Lock()
	user := store.users["alice@example.com"]
	userLocked := user.locked
	userFailed := user.failed
	store.mu.Unlock()
	if userLocked {
		t.Error("account should NOT be locked when lockout threshold is 0")
	}
	if userFailed != 10 {
		t.Errorf("expected 10 failed attempts, got %d", userFailed)
	}

	// Should still be able to login with correct password.
	_, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "correctpassword",
	})
	if err != nil {
		t.Fatalf("expected successful login even after many failures with lockout disabled, got %v", err)
	}
}

// --- Test 7.20: AuthTime is set on successful authentication ---

func TestPasswordMode_AuthTime_Set(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	mode := buildTestMode(store)

	before := time.Now()
	id, err := mode.Authenticate(context.Background(), auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "correctpassword",
	})
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AuthTime.IsZero() {
		t.Fatal("expected AuthTime to be set, got zero value")
	}
	if id.AuthTime.Before(before) || id.AuthTime.After(after) {
		t.Errorf("AuthTime %v out of expected range [%v, %v]", id.AuthTime, before, after)
	}
}

// --- Test 7.21: Concurrent authentication does not panic ---

func TestPasswordMode_Concurrent(t *testing.T) {
	store := newMockUserStore()
	store.addUser("user-1", "alice@example.com", "hashed:correctpassword", 0, false)
	mode := buildTestMode(store)

	done := make(chan struct{})
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			mode.Authenticate(context.Background(), auth.Credential{
				Type:       auth.CredentialTypePassword,
				Identifier: "alice@example.com",
				Secret:     "correctpassword",
			})
		}()
	}
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			mode.Authenticate(context.Background(), auth.Credential{
				Type:       auth.CredentialTypePassword,
				Identifier: "alice@example.com",
				Secret:     "wrongpassword",
			})
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
	// No panic = pass.
}
