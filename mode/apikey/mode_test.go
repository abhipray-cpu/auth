// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package apikeymode

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/session"
)

// --- Mock implementations ---

// mockAPIKeyStore implements apikey.APIKeyStore.
type mockAPIKeyStore struct {
	mu            sync.Mutex
	keys          map[string]*apikey.APIKey // keyed by KeyHash
	lastUsedCalls []lastUsedCall
}

type lastUsedCall struct {
	keyID     string
	timestamp time.Time
}

func newMockAPIKeyStore() *mockAPIKeyStore {
	return &mockAPIKeyStore{
		keys: make(map[string]*apikey.APIKey),
	}
}

func (s *mockAPIKeyStore) FindByKey(_ context.Context, keyHash string) (*apikey.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyHash]
	if !ok {
		return nil, errors.New("not found")
	}
	return k, nil
}

func (s *mockAPIKeyStore) Create(_ context.Context, k *apikey.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[k.KeyHash] = k
	return nil
}

func (s *mockAPIKeyStore) Revoke(_ context.Context, _ string) error { return nil }

func (s *mockAPIKeyStore) ListBySubject(_ context.Context, _ string) ([]*apikey.APIKey, error) {
	return nil, nil
}

func (s *mockAPIKeyStore) UpdateLastUsed(_ context.Context, keyID string, ts time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUsedCalls = append(s.lastUsedCalls, lastUsedCall{keyID: keyID, timestamp: ts})
	return nil
}

// --- Helper ---

const testRawKey = "test-api-key-value-1234567890abcdef"

func buildTestMode(t *testing.T) (*Mode, *mockAPIKeyStore) {
	t.Helper()
	store := newMockAPIKeyStore()

	keyHash := session.HashID(testRawKey)
	store.keys[keyHash] = &apikey.APIKey{
		ID:        "key-1",
		SubjectID: "user-alice",
		KeyHash:   keyHash,
		Name:      "test-key",
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now().Add(-24 * time.Hour),
		ExpiresAt: time.Now().Add(24 * time.Hour), // expires tomorrow
	}

	m := NewMode(Config{APIKeyStore: store})
	return m, store
}

// --- Test Cases ---

// 10.1: Valid API key → Identity with correct SubjectID.
func TestAPIKey_ValidKey(t *testing.T) {
	m, _ := buildTestMode(t)

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.SubjectID != "user-alice" {
		t.Errorf("expected SubjectID 'user-alice', got %q", identity.SubjectID)
	}
	if identity.AuthMethod != "api_key" {
		t.Errorf("expected AuthMethod 'api_key', got %q", identity.AuthMethod)
	}
}

// 10.2: Expired key → ErrAPIKeyExpired.
func TestAPIKey_ExpiredKey(t *testing.T) {
	store := newMockAPIKeyStore()
	keyHash := session.HashID(testRawKey)
	store.keys[keyHash] = &apikey.APIKey{
		ID:        "key-expired",
		SubjectID: "user-alice",
		KeyHash:   keyHash,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired 1 hour ago
	}

	m := NewMode(Config{APIKeyStore: store})

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	if !errors.Is(err, auth.ErrAPIKeyExpired) {
		t.Errorf("expected ErrAPIKeyExpired, got %v", err)
	}
}

// 10.3: Revoked key → ErrAPIKeyRevoked.
func TestAPIKey_RevokedKey(t *testing.T) {
	store := newMockAPIKeyStore()
	keyHash := session.HashID(testRawKey)
	store.keys[keyHash] = &apikey.APIKey{
		ID:        "key-revoked",
		SubjectID: "user-alice",
		KeyHash:   keyHash,
		Revoked:   true,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	m := NewMode(Config{APIKeyStore: store})

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	if !errors.Is(err, auth.ErrAPIKeyRevoked) {
		t.Errorf("expected ErrAPIKeyRevoked, got %v", err)
	}
}

// 10.4: Unknown key → ErrInvalidCredentials.
func TestAPIKey_NotFound(t *testing.T) {
	m := NewMode(Config{APIKeyStore: newMockAPIKeyStore()})

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: "unknown-key",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

// 10.5: Key lookup uses hash, not raw key.
func TestAPIKey_KeyHashed(t *testing.T) {
	store := newMockAPIKeyStore()

	// Store the key by its hash.
	keyHash := session.HashID(testRawKey)
	store.keys[keyHash] = &apikey.APIKey{
		ID:        "key-1",
		SubjectID: "user-alice",
		KeyHash:   keyHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Storing by raw key should NOT find it.
	m := NewMode(Config{APIKeyStore: store})

	// This should work — lookup by hash.
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	if err != nil {
		t.Errorf("expected success when looking up by hash, got %v", err)
	}

	// Verify the raw key is NOT used as the lookup key.
	store.mu.Lock()
	_, rawExists := store.keys[testRawKey]
	store.mu.Unlock()
	if rawExists {
		t.Error("raw key should not be used as lookup key")
	}
}

// 10.6: LastUsedAt updated on successful auth.
func TestAPIKey_LastUsedUpdated(t *testing.T) {
	m, store := buildTestMode(t)

	before := time.Now()
	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	store.mu.Lock()
	calls := store.lastUsedCalls
	store.mu.Unlock()

	if len(calls) != 1 {
		t.Fatalf("expected 1 UpdateLastUsed call, got %d", len(calls))
	}
	if calls[0].keyID != "key-1" {
		t.Errorf("expected keyID 'key-1', got %q", calls[0].keyID)
	}
	if calls[0].timestamp.Before(before) {
		t.Error("expected LastUsedAt timestamp to be after test start")
	}
}

// 10.7: API key scopes included in Identity.Metadata.
func TestAPIKey_ScopesInIdentity(t *testing.T) {
	m, _ := buildTestMode(t)

	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	scopes, ok := identity.Metadata["scopes"]
	if !ok {
		t.Fatal("expected 'scopes' in Identity.Metadata")
	}

	scopeSlice, ok := scopes.([]string)
	if !ok {
		t.Fatalf("expected scopes to be []string, got %T", scopes)
	}
	if len(scopeSlice) != 2 || scopeSlice[0] != "read" || scopeSlice[1] != "write" {
		t.Errorf("expected scopes [read, write], got %v", scopeSlice)
	}
}

// 10.8: Key extracted from header (credential Secret passed through).
func TestAPIKey_FromHeader(t *testing.T) {
	m, _ := buildTestMode(t)

	// Simulate: middleware extracted API key from header and placed it in credential.Secret.
	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeAPIKey,
		Secret:   testRawKey,
		Metadata: map[string]any{"source": "header"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.SubjectID != "user-alice" {
		t.Errorf("expected SubjectID 'user-alice', got %q", identity.SubjectID)
	}
}

// 10.9: Key extracted from query param (credential Secret passed through).
func TestAPIKey_FromQueryParam(t *testing.T) {
	m, _ := buildTestMode(t)

	// Simulate: middleware extracted API key from query param and placed it in credential.Secret.
	identity, err := m.Authenticate(context.Background(), auth.Credential{
		Type:     auth.CredentialTypeAPIKey,
		Secret:   testRawKey,
		Metadata: map[string]any{"source": "query"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if identity.SubjectID != "user-alice" {
		t.Errorf("expected SubjectID 'user-alice', got %q", identity.SubjectID)
	}
}

// 10.10: Empty key → ErrInvalidCredentials.
func TestAPIKey_EmptyKey(t *testing.T) {
	m, _ := buildTestMode(t)

	_, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: "",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for empty key, got %v", err)
	}
}

// 10.11: Supports CredentialTypeAPIKey.
func TestAPIKey_Supports(t *testing.T) {
	m, _ := buildTestMode(t)

	if !m.Supports(auth.CredentialTypeAPIKey) {
		t.Error("expected Supports(CredentialTypeAPIKey) to be true")
	}
	if m.Supports(auth.CredentialTypePassword) {
		t.Error("expected Supports(CredentialTypePassword) to be false")
	}
	if m.Supports(auth.CredentialTypeMagicLink) {
		t.Error("expected Supports(CredentialTypeMagicLink) to be false")
	}
	if m.Supports(auth.CredentialTypeOAuth) {
		t.Error("expected Supports(CredentialTypeOAuth) to be false")
	}
}

// 10.12: Returns "api_key".
func TestAPIKey_Name(t *testing.T) {
	m, _ := buildTestMode(t)
	if m.Name() != "api_key" {
		t.Errorf("expected Name() = 'api_key', got %q", m.Name())
	}
}

// 10.13: Satisfies AuthMode interface.
func TestAPIKey_ImplementsAuthMode(t *testing.T) {
	var _ auth.AuthMode = (*Mode)(nil)
}

// --- Hardening Tests ---

// 10.14: NewMode panics on nil APIKeyStore.
func TestAPIKey_NewMode_NilStore(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil APIKeyStore")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if !containsStr(msg, "APIKeyStore") {
			t.Errorf("expected panic mentioning APIKeyStore, got: %s", msg)
		}
	}()

	NewMode(Config{APIKeyStore: nil})
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// 10.15: API key with no expiry (zero ExpiresAt) should succeed.
func TestAPIKey_NoExpiry(t *testing.T) {
	store := newMockAPIKeyStore()
	rawKey := "no-expiry-key-1234567890"
	keyHash := session.HashID(rawKey)

	store.keys[keyHash] = &apikey.APIKey{
		ID:        "key-no-expiry",
		SubjectID: "user-bob",
		KeyHash:   keyHash,
		Name:      "permanent-key",
		Scopes:    []string{"admin"},
		CreatedAt: time.Now().Add(-365 * 24 * time.Hour),
		// ExpiresAt is zero — no expiry.
	}

	m := NewMode(Config{APIKeyStore: store})

	id, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	})
	if err != nil {
		t.Fatalf("expected success for key with no expiry, got: %v", err)
	}
	if id.SubjectID != "user-bob" {
		t.Errorf("expected SubjectID user-bob, got %s", id.SubjectID)
	}
}

// 10.16: API key with empty scopes → no scopes in metadata.
func TestAPIKey_EmptyScopes(t *testing.T) {
	store := newMockAPIKeyStore()
	rawKey := "empty-scopes-key-1234567890"
	keyHash := session.HashID(rawKey)

	store.keys[keyHash] = &apikey.APIKey{
		ID:        "key-empty-scopes",
		SubjectID: "user-bob",
		KeyHash:   keyHash,
		Name:      "no-scopes-key",
		Scopes:    nil, // No scopes.
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	m := NewMode(Config{APIKeyStore: store})

	id, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	})
	if err != nil {
		t.Fatalf("expected success for key with empty scopes, got: %v", err)
	}
	if _, ok := id.Metadata["scopes"]; ok {
		t.Error("expected no 'scopes' key in metadata for key with nil scopes")
	}
}

// 10.17: Concurrent authentication does not panic.
func TestAPIKey_Concurrent(t *testing.T) {
	m, _ := buildTestMode(t)

	const goroutines = 50
	done := make(chan struct{}, goroutines*2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			m.Authenticate(context.Background(), auth.Credential{
				Type:   auth.CredentialTypeAPIKey,
				Secret: testRawKey,
			})
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			m.Authenticate(context.Background(), auth.Credential{
				Type:   auth.CredentialTypeAPIKey,
				Secret: "invalid-key-xxxxx",
			})
		}()
	}

	for i := 0; i < goroutines*2; i++ {
		<-done
	}
	// No panic = pass.
}

// 10.18: AuthTime is set on successful authentication.
func TestAPIKey_AuthTime_Set(t *testing.T) {
	m, _ := buildTestMode(t)

	before := time.Now()
	id, err := m.Authenticate(context.Background(), auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: testRawKey,
	})
	after := time.Now()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.AuthTime.IsZero() {
		t.Fatal("expected AuthTime to be set")
	}
	if id.AuthTime.Before(before) || id.AuthTime.After(after) {
		t.Errorf("AuthTime %v out of expected range", id.AuthTime)
	}
}
