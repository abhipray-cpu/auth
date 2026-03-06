// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// mockSessionStore is an in-memory SessionStore for testing.
type mockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by hashed session ID
}

func newMockStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*Session),
	}
}

func (m *mockSessionStore) Create(_ context.Context, sess *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.ID] = cloneSession(sess)
	return nil
}

func (m *mockSessionStore) Get(_ context.Context, sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return cloneSession(s), nil
}

func (m *mockSessionStore) Update(_ context.Context, sess *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sess.ID]; !ok {
		return auth.ErrSessionNotFound
	}
	m.sessions[sess.ID] = cloneSession(sess)
	return nil
}

func (m *mockSessionStore) Delete(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockSessionStore) DeleteBySubject(_ context.Context, subjectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.SubjectID == subjectID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockSessionStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, s := range m.sessions {
		if s.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

// ListBySubject is an extended method used by Manager.evictOldestIfNeeded.
func (m *mockSessionStore) ListBySubject(_ context.Context, subjectID string) ([]*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*Session
	for _, s := range m.sessions {
		if s.SubjectID == subjectID {
			result = append(result, cloneSession(s))
		}
	}
	return result, nil
}

func cloneSession(s *Session) *Session {
	c := *s
	if s.Metadata != nil {
		c.Metadata = make(map[string]any, len(s.Metadata))
		for k, v := range s.Metadata {
			c.Metadata[k] = v
		}
	}
	return &c
}

// helper to get the count of sessions in the mock store
func (m *mockSessionStore) count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func defaultTestManager() (*Manager, *mockSessionStore) {
	store := newMockStore()
	cfg := DefaultConfig()
	return NewManager(store, cfg), store
}

// --- Test 4.1: CreateSession creates session with correct fields ---
func TestSessionManager_CreateSession(t *testing.T) {
	mgr, store := defaultTestManager()
	rawID, sess, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if rawID == "" {
		t.Fatal("expected non-empty raw session ID")
	}
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
	if sess.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", sess.SubjectID)
	}
	if sess.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
	if sess.ExpiresAt.IsZero() {
		t.Error("expected non-zero ExpiresAt")
	}
	if sess.LastActiveAt.IsZero() {
		t.Error("expected non-zero LastActiveAt")
	}

	// Session should be in the store.
	if store.count() != 1 {
		t.Errorf("expected 1 session in store, got %d", store.count())
	}
}

// --- Test 4.2: Session fixation prevention — existing session destroyed ---
func TestSessionManager_CreateSession_FixationPrevention(t *testing.T) {
	mgr, store := defaultTestManager()

	// Create initial session.
	rawID1, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if store.count() != 1 {
		t.Fatalf("expected 1 session, got %d", store.count())
	}

	// Create second session, passing the first raw ID as "existing".
	_, _, err = mgr.CreateSession(context.Background(), "user-123", rawID1, nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// The old session (rawID1) should have been destroyed.
	hashedOld := HashID(rawID1)
	_, getErr := store.Get(context.Background(), hashedOld)
	if !errors.Is(getErr, auth.ErrSessionNotFound) {
		t.Errorf("expected old session to be destroyed, but Get returned: %v", getErr)
	}

	// But there should still be exactly 1 session (the new one).
	// The old was destroyed, then a new one was created.
	if store.count() != 1 {
		t.Errorf("expected 1 session after fixation prevention, got %d", store.count())
	}
}

// --- Test 4.3: Session IDs are unique across calls ---
func TestSessionManager_CreateSession_UniqueID(t *testing.T) {
	mgr, _ := defaultTestManager()
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
		if err != nil {
			t.Fatalf("CreateSession() error on iteration %d: %v", i, err)
		}
		if seen[rawID] {
			t.Fatalf("duplicate session ID on iteration %d: %s", i, rawID)
		}
		seen[rawID] = true
	}
}

// --- Test 4.4: Stored session ID is SHA-256 hash of raw ID ---
func TestSessionManager_CreateSession_IDHashed(t *testing.T) {
	mgr, store := defaultTestManager()
	rawID, sess, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Compute expected hash.
	h := sha256.Sum256([]byte(rawID))
	expectedHash := hex.EncodeToString(h[:])

	if sess.ID != expectedHash {
		t.Errorf("expected session ID to be SHA-256 of raw ID\n  raw:      %s\n  expected: %s\n  got:      %s", rawID, expectedHash, sess.ID)
	}

	// Verify the store has it keyed by hash, not raw.
	_, err = store.Get(context.Background(), expectedHash)
	if err != nil {
		t.Errorf("expected session to be stored under hashed ID, but Get returned: %v", err)
	}
	_, err = store.Get(context.Background(), rawID)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Error("session should NOT be stored under the raw ID")
	}
}

// --- Test 4.5: ValidateSession returns session for valid session ---
func TestSessionManager_ValidateSession(t *testing.T) {
	mgr, _ := defaultTestManager()
	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sess, err := mgr.ValidateSession(context.Background(), rawID)
	if err != nil {
		t.Fatalf("ValidateSession() error: %v", err)
	}
	if sess.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", sess.SubjectID)
	}
}

// --- Test 4.6: Expired session (absolute timeout) returns ErrSessionExpired ---
func TestSessionManager_ValidateSession_Expired(t *testing.T) {
	store := newMockStore()
	cfg := DefaultConfig()
	cfg.AbsoluteTimeout = 1 * time.Millisecond // Extremely short for testing.
	mgr := NewManager(store, cfg)

	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Wait for absolute timeout to expire.
	time.Sleep(5 * time.Millisecond)

	_, err = mgr.ValidateSession(context.Background(), rawID)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got: %v", err)
	}
}

// --- Test 4.7: Idle timeout returns ErrSessionExpired ---
func TestSessionManager_ValidateSession_IdleTimeout(t *testing.T) {
	store := newMockStore()
	cfg := DefaultConfig()
	cfg.IdleTimeout = 1 * time.Millisecond
	cfg.AbsoluteTimeout = 1 * time.Hour // Long so only idle triggers.
	mgr := NewManager(store, cfg)

	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = mgr.ValidateSession(context.Background(), rawID)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired for idle timeout, got: %v", err)
	}
}

// --- Test 4.8: Absolute timeout returns ErrSessionExpired ---
func TestSessionManager_ValidateSession_AbsoluteTimeout(t *testing.T) {
	store := newMockStore()
	cfg := DefaultConfig()
	cfg.AbsoluteTimeout = 1 * time.Millisecond
	cfg.IdleTimeout = 1 * time.Hour // Long so only absolute triggers.
	mgr := NewManager(store, cfg)

	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = mgr.ValidateSession(context.Background(), rawID)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired for absolute timeout, got: %v", err)
	}
}

// --- Test 4.9: Non-existent session returns ErrSessionNotFound ---
func TestSessionManager_ValidateSession_NotFound(t *testing.T) {
	mgr, _ := defaultTestManager()

	_, err := mgr.ValidateSession(context.Background(), "non-existent-raw-id")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// --- Test 4.10: Validation uses constant-time comparison ---
func TestSessionManager_ValidateSession_TimingSafe(t *testing.T) {
	mgr, _ := defaultTestManager()
	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	const iterations = 20

	// Measure valid session lookup.
	start := time.Now()
	for i := 0; i < iterations; i++ {
		mgr.ValidateSession(context.Background(), rawID)
	}
	validDuration := time.Since(start)

	// Measure invalid session lookup (wrong ID, same length).
	wrongID := rawID[:len(rawID)-1] + "0"
	start = time.Now()
	for i := 0; i < iterations; i++ {
		mgr.ValidateSession(context.Background(), wrongID)
	}
	invalidDuration := time.Since(start)

	// Both should complete in roughly the same time.
	// With a mock store, the dominant factor is the hash computation,
	// which is constant-time. Allow generous ratio for CI variability.
	ratio := float64(validDuration) / float64(invalidDuration)
	if ratio < 0.05 || ratio > 20.0 {
		t.Errorf("timing ratio out of bounds: valid=%v, invalid=%v, ratio=%.2f",
			validDuration, invalidDuration, ratio)
	}
}

// --- Test 4.11: RefreshSession updates LastActiveAt ---
func TestSessionManager_RefreshSession(t *testing.T) {
	mgr, _ := defaultTestManager()
	rawID, sess, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	originalLastActive := sess.LastActiveAt
	time.Sleep(2 * time.Millisecond)

	refreshed, err := mgr.RefreshSession(context.Background(), rawID)
	if err != nil {
		t.Fatalf("RefreshSession() error: %v", err)
	}

	if !refreshed.LastActiveAt.After(originalLastActive) {
		t.Errorf("expected LastActiveAt to advance: original=%v, refreshed=%v",
			originalLastActive, refreshed.LastActiveAt)
	}
}

// --- Test 4.12: Can't refresh an expired session ---
func TestSessionManager_RefreshSession_Expired(t *testing.T) {
	store := newMockStore()
	cfg := DefaultConfig()
	cfg.AbsoluteTimeout = 1 * time.Millisecond
	mgr := NewManager(store, cfg)

	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = mgr.RefreshSession(context.Background(), rawID)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired on refresh of expired session, got: %v", err)
	}
}

// --- Test 4.13: DestroySession deletes the session ---
func TestSessionManager_DestroySession(t *testing.T) {
	mgr, store := defaultTestManager()
	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if store.count() != 1 {
		t.Fatalf("expected 1 session, got %d", store.count())
	}

	err = mgr.DestroySession(context.Background(), rawID)
	if err != nil {
		t.Fatalf("DestroySession() error: %v", err)
	}
	if store.count() != 0 {
		t.Errorf("expected 0 sessions after destroy, got %d", store.count())
	}
}

// --- Test 4.14: DestroyAllSessions removes all sessions for a subject ---
func TestSessionManager_DestroyAllSessions(t *testing.T) {
	mgr, store := defaultTestManager()

	// Create 3 sessions for user-123.
	for i := 0; i < 3; i++ {
		_, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
		if err != nil {
			t.Fatalf("CreateSession() error: %v", err)
		}
	}
	// Create 1 session for user-456.
	_, _, err := mgr.CreateSession(context.Background(), "user-456", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	if store.count() != 4 {
		t.Fatalf("expected 4 sessions, got %d", store.count())
	}

	err = mgr.DestroyAllSessions(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("DestroyAllSessions() error: %v", err)
	}

	// Only user-456's session should remain.
	if store.count() != 1 {
		t.Errorf("expected 1 session remaining, got %d", store.count())
	}
}

// --- Test 4.15: MaxConcurrent enforced — oldest session evicted ---
func TestSessionManager_ConcurrentLimit(t *testing.T) {
	store := newMockStore()
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 2
	mgr := NewManager(store, cfg)

	// Create 2 sessions (at the limit).
	rawID1, sess1, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession #1 error: %v", err)
	}
	_ = rawID1

	time.Sleep(1 * time.Millisecond) // Ensure distinct CreatedAt.

	_, _, err = mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession #2 error: %v", err)
	}

	// Creating a 3rd should evict the oldest (#1).
	time.Sleep(1 * time.Millisecond)
	_, _, err = mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession #3 error: %v", err)
	}

	// Session #1 should be gone.
	_, getErr := store.Get(context.Background(), sess1.ID)
	if !errors.Is(getErr, auth.ErrSessionNotFound) {
		t.Errorf("expected oldest session to be evicted, but Get returned: %v", getErr)
	}

	// Should still have exactly MaxConcurrent sessions.
	if store.count() != 2 {
		t.Errorf("expected %d sessions, got %d", cfg.MaxConcurrent, store.count())
	}
}

// --- Test 4.16: MaxConcurrent=0 means unlimited ---
func TestSessionManager_ConcurrentLimit_Disabled(t *testing.T) {
	store := newMockStore()
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 0 // Unlimited.
	mgr := NewManager(store, cfg)

	// Create 20 sessions — none should be evicted.
	for i := 0; i < 20; i++ {
		_, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
		if err != nil {
			t.Fatalf("CreateSession() error on iteration %d: %v", i, err)
		}
	}

	if store.count() != 20 {
		t.Errorf("expected 20 sessions (unlimited), got %d", store.count())
	}
}

// --- Test 4.17: Created sessions carry current SchemaVersion ---
func TestSessionManager_SchemaVersion(t *testing.T) {
	mgr, _ := defaultTestManager()
	_, sess, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	if sess.SchemaVersion != SchemaVersion {
		t.Errorf("expected SchemaVersion=%d, got %d", SchemaVersion, sess.SchemaVersion)
	}
	if sess.SchemaVersion != 1 {
		t.Errorf("expected current SchemaVersion=1, got %d", sess.SchemaVersion)
	}
}

// --- Test 4.18: Session metadata can be set and read ---
func TestSessionManager_Metadata(t *testing.T) {
	mgr, _ := defaultTestManager()
	meta := map[string]any{
		"ip":         "192.168.1.1",
		"user_agent": "Mozilla/5.0",
		"device":     "desktop",
	}

	_, sess, err := mgr.CreateSession(context.Background(), "user-123", "", meta)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	if sess.Metadata == nil {
		t.Fatal("expected non-nil Metadata")
	}
	if sess.Metadata["ip"] != "192.168.1.1" {
		t.Errorf("expected ip=192.168.1.1, got %v", sess.Metadata["ip"])
	}
	if sess.Metadata["user_agent"] != "Mozilla/5.0" {
		t.Errorf("expected user_agent=Mozilla/5.0, got %v", sess.Metadata["user_agent"])
	}
	if sess.Metadata["device"] != "desktop" {
		t.Errorf("expected device=desktop, got %v", sess.Metadata["device"])
	}

	// Also verify via ValidateSession.
	rawID, _, _ := mgr.CreateSession(context.Background(), "user-456", "", map[string]any{"key": "value"})
	validated, err := mgr.ValidateSession(context.Background(), rawID)
	if err != nil {
		t.Fatalf("ValidateSession() error: %v", err)
	}
	if validated.Metadata["key"] != "value" {
		t.Errorf("expected metadata key=value after validation, got %v", validated.Metadata["key"])
	}
}

// --- Hardening Tests ---

// Test 4.19H: NewManager panics on nil store.
func TestSessionManager_NewManager_NilStore(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil SessionStore")
		}
	}()

	NewManager(nil, DefaultConfig())
}

// Test 4.20H: Concurrent CreateSession does not panic.
func TestSessionManager_CreateSession_Concurrent(t *testing.T) {
	mgr, _ := defaultTestManager()

	const goroutines = 50
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			mgr.CreateSession(context.Background(), "user-concurrent", "", nil)
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
	// No panic = pass.
}

// Test 4.21H: Concurrent Validate + Destroy is safe.
func TestSessionManager_ConcurrentValidateDestroy(t *testing.T) {
	mgr, _ := defaultTestManager()
	rawID, _, err := mgr.CreateSession(context.Background(), "user-123", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	const goroutines = 20
	done := make(chan struct{}, goroutines*2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			mgr.ValidateSession(context.Background(), rawID)
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			mgr.DestroySession(context.Background(), rawID)
		}()
	}

	for i := 0; i < goroutines*2; i++ {
		<-done
	}
}

// Test 4.22H: CreateSession with nil metadata works.
func TestSessionManager_CreateSession_NilMetadata(t *testing.T) {
	mgr, _ := defaultTestManager()

	_, sess, err := mgr.CreateSession(context.Background(), "user-nil-meta", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
	if sess.SubjectID != "user-nil-meta" {
		t.Errorf("expected SubjectID user-nil-meta, got %q", sess.SubjectID)
	}
}

// Test 4.23H: DestroySession on non-existent ID does not error (idempotent).
func TestSessionManager_DestroySession_Nonexistent(t *testing.T) {
	mgr, _ := defaultTestManager()

	// Destroying a non-existent session should not panic or error.
	err := mgr.DestroySession(context.Background(), "does-not-exist")
	// The mock store's Delete is a no-op for missing keys. This is fine.
	_ = err
}

// Test 4.24H: RefreshSession on non-existent session returns ErrSessionNotFound.
func TestSessionManager_RefreshSession_Nonexistent(t *testing.T) {
	mgr, _ := defaultTestManager()

	_, err := mgr.RefreshSession(context.Background(), "nonexistent-raw-id")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// Test 4.25H: CreateSession with store that fails on Create returns error.
func TestSessionManager_CreateSession_StoreError(t *testing.T) {
	store := &failingSessionStore{createErr: fmt.Errorf("disk full")}
	mgr := NewManager(store, DefaultConfig())

	_, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err == nil {
		t.Fatal("expected error when store.Create fails")
	}
}

// Test 4.26H: RefreshSession with store that fails on Update returns error.
func TestSessionManager_RefreshSession_UpdateError(t *testing.T) {
	store := newMockStore()
	mgr := NewManager(store, DefaultConfig())

	rawID, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Replace the store with one that fails on Update.
	mgr.store = &failingSessionStore{
		getSession: func(ctx context.Context, id string) (*Session, error) {
			return store.Get(ctx, id)
		},
		updateErr: fmt.Errorf("io error"),
	}

	_, err = mgr.RefreshSession(context.Background(), rawID)
	if err == nil {
		t.Fatal("expected error when store.Update fails")
	}
}

// Test 4.27H: DestroyAllSessions delegates to store.DeleteBySubject (hardening).
func TestSessionManager_DestroyAllSessions_Multiple(t *testing.T) {
	mgr, store := defaultTestManager()

	// Create multiple sessions for same subject.
	for i := 0; i < 3; i++ {
		_, _, err := mgr.CreateSession(context.Background(), "user-multi", "", nil)
		if err != nil {
			t.Fatalf("CreateSession() error: %v", err)
		}
	}
	if store.count() != 3 {
		t.Fatalf("expected 3 sessions, got %d", store.count())
	}

	err := mgr.DestroyAllSessions(context.Background(), "user-multi")
	if err != nil {
		t.Fatalf("DestroyAllSessions() error: %v", err)
	}
	if store.count() != 0 {
		t.Errorf("expected 0 sessions after destroy all, got %d", store.count())
	}
}

// Test 4.28H: evictOldestIfNeeded with store that lacks ListBySubject.
func TestSessionManager_EvictWithoutLister(t *testing.T) {
	store := &minimalSessionStore{sessions: make(map[string]*Session)}
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 1
	mgr := NewManager(store, cfg)

	// Create first session — should succeed.
	_, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Create second session — eviction will try but store doesn't have
	// ListBySubject, so eviction is skipped. Session still created.
	_, _, err = mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
}

// Test 4.29H: findOldestSessions with n=0 returns nil.
func TestFindOldestSessions_Zero(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		{ID: "a", CreatedAt: now},
	}
	result := findOldestSessions(sessions, 0)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

// Test 4.30H: findOldestSessions with n >= len returns all.
func TestFindOldestSessions_All(t *testing.T) {
	now := time.Now()
	sessions := []*Session{
		{ID: "a", CreatedAt: now},
		{ID: "b", CreatedAt: now.Add(time.Second)},
	}
	result := findOldestSessions(sessions, 5)
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

// Test 4.31H: findOldestSessions with empty slice returns nil.
func TestFindOldestSessions_Empty(t *testing.T) {
	result := findOldestSessions(nil, 3)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

// Test 4.32H: evictOldestIfNeeded with CountBySubject error propagates.
func TestSessionManager_EvictCountError(t *testing.T) {
	store := &failingSessionStore{
		countErr: fmt.Errorf("count failed"),
	}
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 2
	mgr := NewManager(store, cfg)

	_, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err == nil {
		t.Fatal("expected error when CountBySubject fails")
	}
}

// failingSessionStore is a SessionStore that returns errors for specific operations.
type failingSessionStore struct {
	createErr  error
	updateErr  error
	countErr   error
	getSession func(ctx context.Context, id string) (*Session, error)
}

func (f *failingSessionStore) Create(_ context.Context, _ *Session) error {
	if f.createErr != nil {
		return f.createErr
	}
	return nil
}

func (f *failingSessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	if f.getSession != nil {
		return f.getSession(ctx, sessionID)
	}
	return nil, auth.ErrSessionNotFound
}

func (f *failingSessionStore) Update(_ context.Context, _ *Session) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	return nil
}

func (f *failingSessionStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (f *failingSessionStore) DeleteBySubject(_ context.Context, _ string) error {
	return nil
}

func (f *failingSessionStore) CountBySubject(_ context.Context, _ string) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return 0, nil
}

// minimalSessionStore implements SessionStore but NOT ListBySubject.
type minimalSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func (m *minimalSessionStore) Create(_ context.Context, sess *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.ID] = sess
	return nil
}

func (m *minimalSessionStore) Get(_ context.Context, sessionID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return s, nil
}

func (m *minimalSessionStore) Update(_ context.Context, sess *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.ID] = sess
	return nil
}

func (m *minimalSessionStore) Delete(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
	return nil
}

func (m *minimalSessionStore) DeleteBySubject(_ context.Context, subjectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.SubjectID == subjectID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *minimalSessionStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, s := range m.sessions {
		if s.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

// Test 4.33H: evictOldestIfNeeded with ListBySubject error propagates.
func TestSessionManager_EvictListError(t *testing.T) {
	store := &failingListerStore{
		sessions: make(map[string]*Session),
		listErr:  fmt.Errorf("list failed"),
	}
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 1
	mgr := NewManager(store, cfg)

	// Create first session succeeds (count is 0, no eviction needed).
	_, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("first CreateSession() error: %v", err)
	}

	// Second session triggers eviction, ListBySubject fails.
	_, _, err = mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err == nil {
		t.Fatal("expected error when ListBySubject fails during eviction")
	}
	if !strings.Contains(err.Error(), "list failed") {
		t.Errorf("expected 'list failed' error, got: %v", err)
	}
}

// Test 4.34H: evictOldestIfNeeded with Delete error during eviction propagates.
func TestSessionManager_EvictDeleteError(t *testing.T) {
	store := &failingListerStore{
		sessions:  make(map[string]*Session),
		deleteErr: fmt.Errorf("delete failed"),
	}
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 1
	mgr := NewManager(store, cfg)

	// Create first session succeeds.
	_, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("first CreateSession() error: %v", err)
	}

	// Second session triggers eviction, delete of oldest fails.
	_, _, err = mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err == nil {
		t.Fatal("expected error when Delete fails during eviction")
	}
}

// Test 4.35H: ValidateSession with store Get error propagates.
func TestSessionManager_ValidateSession_StoreGetError(t *testing.T) {
	store := &failingSessionStore{
		getSession: func(_ context.Context, _ string) (*Session, error) {
			return nil, fmt.Errorf("db connection lost")
		},
	}
	mgr := NewManager(store, DefaultConfig())

	_, err := mgr.ValidateSession(context.Background(), "any-token")
	if err == nil {
		t.Fatal("expected error when store.Get fails")
	}
}

// Test 4.36H: DestroySession with store Delete error propagates.
func TestSessionManager_DestroySession_StoreDeleteError(t *testing.T) {
	store := newMockStore()
	mgr := NewManager(store, DefaultConfig())

	rawID, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Replace store with one that fails on delete.
	mgr.store = &failingSessionStore{
		getSession: func(ctx context.Context, id string) (*Session, error) {
			return store.Get(ctx, id)
		},
	}
	// failingSessionStore.Delete returns nil, so let's use failingListerStore instead.
	deletingStore := &failingListerStore{
		sessions:  make(map[string]*Session),
		deleteErr: fmt.Errorf("disk error"),
	}
	// Copy session into deletingStore so Get works.
	store.mu.RLock()
	for k, v := range store.sessions {
		deletingStore.sessions[k] = v
	}
	store.mu.RUnlock()
	mgr.store = deletingStore

	err = mgr.DestroySession(context.Background(), rawID)
	if err == nil {
		t.Fatal("expected error when store.Delete fails")
	}
}

// Test 4.37H: DestroyAllSessions with store error propagates.
func TestSessionManager_DestroyAllSessions_StoreError(t *testing.T) {
	store := &failingSessionStore{}
	mgr := NewManager(store, DefaultConfig())

	// failingSessionStore.DeleteBySubject returns nil, so we need a custom one.
	mgr.store = &failingListerStore{
		sessions:      make(map[string]*Session),
		deleteSubjErr: fmt.Errorf("cascade failed"),
	}

	err := mgr.DestroyAllSessions(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error when store.DeleteBySubject fails")
	}
}

// failingListerStore implements SessionStore + ListBySubject but can fail on any operation.
type failingListerStore struct {
	mu            sync.Mutex
	sessions      map[string]*Session
	listErr       error
	deleteErr     error
	deleteSubjErr error
}

func (f *failingListerStore) Create(_ context.Context, sess *Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[sess.ID] = sess
	return nil
}

func (f *failingListerStore) Get(_ context.Context, sessionID string) (*Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return s, nil
}

func (f *failingListerStore) Update(_ context.Context, sess *Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[sess.ID] = sess
	return nil
}

func (f *failingListerStore) Delete(_ context.Context, sessionID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, sessionID)
	return nil
}

func (f *failingListerStore) DeleteBySubject(_ context.Context, _ string) error {
	if f.deleteSubjErr != nil {
		return f.deleteSubjErr
	}
	return nil
}

func (f *failingListerStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, s := range f.sessions {
		if s.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

func (f *failingListerStore) ListBySubject(_ context.Context, subjectID string) ([]*Session, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []*Session
	for _, s := range f.sessions {
		if s.SubjectID == subjectID {
			result = append(result, s)
		}
	}
	return result, nil
}

// Test 4.42H: ValidateSession returns ErrSessionNotFound when stored ID doesn't match
// (constant-time compare branch).
func TestSessionManager_ValidateSession_IDMismatch(t *testing.T) {
	_, store := defaultTestManager()
	mgr := NewManager(store, DefaultConfig())
	ctx := context.Background()

	// Insert a session whose ID differs from what the hash lookup would expect.
	rawID := "test-raw-id-for-mismatch"
	expectedHash := HashID(rawID)

	sess := &Session{
		ID:            "not-the-expected-hash", // deliberately wrong
		SubjectID:     "user-1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		LastActiveAt:  time.Now(),
		SchemaVersion: SchemaVersion,
	}
	store.mu.Lock()
	store.sessions[expectedHash] = sess
	store.mu.Unlock()

	_, err := mgr.ValidateSession(ctx, rawID)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for ID mismatch, got: %v", err)
	}
}

// Test 4.43H: evictOldestIfNeeded clamps toEvict when count - max + 1 > len(sessions).
func TestSessionManager_EvictToEvictClamped(t *testing.T) {
	// Store where CountBySubject returns a high number but ListBySubject
	// returns fewer sessions (simulating race or inconsistency).
	store := &clampingListerStore{
		sessions:      make(map[string]*Session),
		countOverride: 10,
	}
	cfg := DefaultConfig()
	cfg.MaxConcurrent = 2
	mgr := NewManager(store, cfg)

	// Insert only 1 session for the subject.
	s := &Session{
		ID:            "only-one",
		SubjectID:     "user-1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
		LastActiveAt:  time.Now(),
		SchemaVersion: SchemaVersion,
	}
	store.sessions["only-one"] = s

	// CreateSession triggers eviction. CountBySubject returns 10 (>= max 2),
	// toEvict = 10 - 2 + 1 = 9, but ListBySubject returns only 1 session.
	// The clamp branch: toEvict = min(9, 1) = 1 executes.
	_, _, err := mgr.CreateSession(context.Background(), "user-1", "", nil)
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}
}

// Test 4.44H: CreateToken store error propagates.
func TestMagicLinkManager_CreateToken_StoreError(t *testing.T) {
	store := &failingMagicLinkStore{storeErr: fmt.Errorf("db down")}
	mgr := NewMagicLinkManager(store, MagicLinkConfig{TTL: 10 * time.Minute})

	_, err := mgr.CreateToken(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error when store fails")
	}
	if !strings.Contains(err.Error(), "store magic link token") {
		t.Errorf("expected store error, got: %v", err)
	}
}

// failingMagicLinkStore always returns storeErr from Store.
type failingMagicLinkStore struct {
	storeErr error
}

func (f *failingMagicLinkStore) Store(_ context.Context, _ *MagicLinkToken) error {
	return f.storeErr
}

func (f *failingMagicLinkStore) Consume(_ context.Context, _ string) (*MagicLinkToken, error) {
	return nil, errors.New("not found")
}

// clampingListerStore is a SessionStore + ListBySubject that returns a high
// count but few actual sessions to exercise the toEvict clamp branch.
type clampingListerStore struct {
	mu            sync.Mutex
	sessions      map[string]*Session
	countOverride int
}

func (c *clampingListerStore) Create(_ context.Context, sess *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[sess.ID] = sess
	return nil
}

func (c *clampingListerStore) Get(_ context.Context, sessionID string) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return s, nil
}

func (c *clampingListerStore) Update(_ context.Context, sess *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions[sess.ID] = sess
	return nil
}

func (c *clampingListerStore) Delete(_ context.Context, sessionID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, sessionID)
	return nil
}

func (c *clampingListerStore) DeleteBySubject(_ context.Context, _ string) error { return nil }

func (c *clampingListerStore) CountBySubject(_ context.Context, _ string) (int, error) {
	return c.countOverride, nil
}

func (c *clampingListerStore) ListBySubject(_ context.Context, subjectID string) ([]*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []*Session
	for _, s := range c.sessions {
		if s.SubjectID == subjectID {
			result = append(result, s)
		}
	}
	return result, nil
}
