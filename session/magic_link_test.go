// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// mockMagicLinkStore is an in-memory MagicLinkStore for testing.
type mockMagicLinkStore struct {
	mu     sync.RWMutex
	tokens map[string]*MagicLinkToken // keyed by hashed token
}

func newMockMagicLinkStore() *mockMagicLinkStore {
	return &mockMagicLinkStore{
		tokens: make(map[string]*MagicLinkToken),
	}
}

func (m *mockMagicLinkStore) Store(_ context.Context, token *MagicLinkToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[token.Token] = &MagicLinkToken{
		Token:     token.Token,
		SubjectID: token.SubjectID,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: token.CreatedAt,
	}
	return nil
}

func (m *mockMagicLinkStore) Consume(_ context.Context, tokenValue string) (*MagicLinkToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[tokenValue]
	if !ok {
		return nil, auth.ErrTokenNotFound
	}

	// Check expiry.
	if time.Now().After(t.ExpiresAt) {
		delete(m.tokens, tokenValue)
		return nil, auth.ErrTokenNotFound
	}

	// Single-use: delete after retrieval.
	delete(m.tokens, tokenValue)
	return t, nil
}

func (m *mockMagicLinkStore) count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tokens)
}

// --- Test 4.42: Token stored with correct key/prefix ---
func TestMagicLinkToken_Store(t *testing.T) {
	store := newMockMagicLinkStore()
	cfg := DefaultMagicLinkConfig()
	mgr := NewMagicLinkManager(store, cfg)

	rawToken, err := mgr.CreateToken(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected non-empty raw token")
	}

	// Token should be stored (keyed by hash, not raw).
	if store.count() != 1 {
		t.Errorf("expected 1 token in store, got %d", store.count())
	}

	// Raw token should NOT be stored directly — only its hash.
	store.mu.RLock()
	_, rawExists := store.tokens[rawToken]
	store.mu.RUnlock()
	if rawExists {
		t.Error("raw token should NOT be stored directly, only its hash")
	}

	// Hashed token should exist.
	hashedToken := HashID(rawToken)
	store.mu.RLock()
	_, hashExists := store.tokens[hashedToken]
	store.mu.RUnlock()
	if !hashExists {
		t.Error("expected hashed token to be stored")
	}
}

// --- Test 4.43: Token retrieved correctly ---
func TestMagicLinkToken_Get(t *testing.T) {
	store := newMockMagicLinkStore()
	cfg := DefaultMagicLinkConfig()
	mgr := NewMagicLinkManager(store, cfg)

	rawToken, err := mgr.CreateToken(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	token, err := mgr.ConsumeToken(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("ConsumeToken() error: %v", err)
	}
	if token.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", token.SubjectID)
	}
	if token.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
	if token.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

// --- Test 4.44: Token deleted after retrieval (single-use) ---
func TestMagicLinkToken_SingleUse(t *testing.T) {
	store := newMockMagicLinkStore()
	cfg := DefaultMagicLinkConfig()
	mgr := NewMagicLinkManager(store, cfg)

	rawToken, err := mgr.CreateToken(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	// First consume should succeed.
	_, err = mgr.ConsumeToken(context.Background(), rawToken)
	if err != nil {
		t.Fatalf("first ConsumeToken() error: %v", err)
	}

	// Store should be empty now.
	if store.count() != 0 {
		t.Errorf("expected 0 tokens after consume, got %d", store.count())
	}

	// Second consume should fail — token is gone.
	_, err = mgr.ConsumeToken(context.Background(), rawToken)
	if !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound on second consume, got: %v", err)
	}
}

// --- Test 4.45: Token expires after configured TTL ---
func TestMagicLinkToken_TTL(t *testing.T) {
	store := newMockMagicLinkStore()
	cfg := MagicLinkConfig{TTL: 1 * time.Millisecond} // Very short TTL.
	mgr := NewMagicLinkManager(store, cfg)

	rawToken, err := mgr.CreateToken(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)

	// Token should be expired.
	_, err = mgr.ConsumeToken(context.Background(), rawToken)
	if !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound for expired token, got: %v", err)
	}
}

// --- Test 4.46: Missing token returns error ---
func TestMagicLinkToken_NotFound(t *testing.T) {
	store := newMockMagicLinkStore()
	cfg := DefaultMagicLinkConfig()
	mgr := NewMagicLinkManager(store, cfg)

	_, err := mgr.ConsumeToken(context.Background(), "nonexistent-token")
	if !errors.Is(err, auth.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got: %v", err)
	}
}
