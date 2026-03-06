// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package propagator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"
)

// ---------------------------------------------------------------
// mock SessionStore for testing
// ---------------------------------------------------------------

type mockSessionStore struct {
	sessions map[string]*session.Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{sessions: make(map[string]*session.Session)}
}

func (m *mockSessionStore) Create(_ context.Context, s *session.Session) error {
	m.sessions[s.ID] = s
	return nil
}

func (m *mockSessionStore) Get(_ context.Context, id string) (*session.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return s, nil
}

func (m *mockSessionStore) Update(_ context.Context, s *session.Session) error {
	m.sessions[s.ID] = s
	return nil
}

func (m *mockSessionStore) Delete(_ context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionStore) DeleteBySubject(_ context.Context, subjectID string) error {
	for id, s := range m.sessions {
		if s.SubjectID == subjectID {
			delete(m.sessions, id)
		}
	}
	return nil
}

func (m *mockSessionStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	count := 0
	for _, s := range m.sessions {
		if s.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

// errorSessionStore always returns an error on Get.
type errorSessionStore struct{ mockSessionStore }

func (e *errorSessionStore) Get(_ context.Context, _ string) (*session.Session, error) {
	return nil, errors.New("store unavailable")
}

// ---------------------------------------------------------------
// 1. NewSessionPropagator validation
// ---------------------------------------------------------------

func TestNewSessionPropagator_NilStore(t *testing.T) {
	_, err := NewSessionPropagator(SessionPropagatorConfig{})
	if err == nil {
		t.Fatal("expected error for nil Store")
	}
}

func TestNewSessionPropagator_Valid(t *testing.T) {
	store := newMockSessionStore()
	p, err := NewSessionPropagator(SessionPropagatorConfig{Store: store})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil propagator")
	}
}

// ---------------------------------------------------------------
// 2. Encode puts session ID in metadata
// ---------------------------------------------------------------

func TestSessionPropagator_Encode(t *testing.T) {
	store := newMockSessionStore()
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})

	id := &auth.Identity{
		SubjectID: "user-42",
		SessionID: "sess-abc123",
	}

	meta, err := p.Encode(context.Background(), id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if meta[headerKeySession] != "sess-abc123" {
		t.Errorf("session ID = %q, want %q", meta[headerKeySession], "sess-abc123")
	}
}

// ---------------------------------------------------------------
// 3. Encode nil identity → error
// ---------------------------------------------------------------

func TestSessionPropagator_EncodeNilIdentity(t *testing.T) {
	store := newMockSessionStore()
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})

	_, err := p.Encode(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

// ---------------------------------------------------------------
// 4. Encode empty session ID → error
// ---------------------------------------------------------------

func TestSessionPropagator_EncodeEmptySessionID(t *testing.T) {
	store := newMockSessionStore()
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})

	id := &auth.Identity{SubjectID: "user-42"}
	_, err := p.Encode(context.Background(), id)
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

// ---------------------------------------------------------------
// 5. Decode validates session via SessionStore, returns identity
// ---------------------------------------------------------------

func TestSessionPropagator_DecodeValid(t *testing.T) {
	store := newMockSessionStore()
	now := time.Now()
	store.sessions["sess-abc"] = &session.Session{
		ID:        "sess-abc",
		SubjectID: "user-42",
		ExpiresAt: now.Add(time.Hour),
	}

	p, _ := NewSessionPropagator(SessionPropagatorConfig{
		Store:   store,
		NowFunc: func() time.Time { return now },
	})

	meta := map[string]string{headerKeySession: "sess-abc"}
	id, err := p.Decode(context.Background(), meta, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if id.SubjectID != "user-42" {
		t.Errorf("SubjectID = %q, want %q", id.SubjectID, "user-42")
	}
	if id.SessionID != "sess-abc" {
		t.Errorf("SessionID = %q, want %q", id.SessionID, "sess-abc")
	}
}

// ---------------------------------------------------------------
// 6. Invalid session ID → error
// ---------------------------------------------------------------

func TestSessionPropagator_DecodeInvalidSession(t *testing.T) {
	store := newMockSessionStore()
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})

	meta := map[string]string{headerKeySession: "nonexistent"}
	_, err := p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error for invalid session")
	}
}

// ---------------------------------------------------------------
// 7. Expired session → error
// ---------------------------------------------------------------

func TestSessionPropagator_DecodeExpiredSession(t *testing.T) {
	store := newMockSessionStore()
	now := time.Now()
	store.sessions["expired-sess"] = &session.Session{
		ID:        "expired-sess",
		SubjectID: "user-42",
		ExpiresAt: now.Add(-time.Hour), // Already expired.
	}

	p, _ := NewSessionPropagator(SessionPropagatorConfig{
		Store:   store,
		NowFunc: func() time.Time { return now },
	})

	meta := map[string]string{headerKeySession: "expired-sess"}
	_, err := p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
	if got := err.Error(); !containsStr(got, "expired") {
		t.Errorf("error = %q, want 'expired'", got)
	}
}

// ---------------------------------------------------------------
// 8. Deleted session immediately rejected (instant revocation)
// ---------------------------------------------------------------

func TestSessionPropagator_InstantRevocation(t *testing.T) {
	store := newMockSessionStore()
	now := time.Now()
	store.sessions["sess-to-delete"] = &session.Session{
		ID:        "sess-to-delete",
		SubjectID: "user-42",
		ExpiresAt: now.Add(time.Hour),
	}

	p, _ := NewSessionPropagator(SessionPropagatorConfig{
		Store:   store,
		NowFunc: func() time.Time { return now },
	})

	meta := map[string]string{headerKeySession: "sess-to-delete"}

	// Should succeed before deletion.
	_, err := p.Decode(context.Background(), meta, nil)
	if err != nil {
		t.Fatalf("Decode before delete: %v", err)
	}

	// Delete the session.
	if err := store.Delete(context.Background(), "sess-to-delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Should fail immediately.
	_, err = p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error after session deletion")
	}
}

// ---------------------------------------------------------------
// 9. No session ID in metadata → error
// ---------------------------------------------------------------

func TestSessionPropagator_NoSessionInMetadata(t *testing.T) {
	store := newMockSessionStore()
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})

	_, err := p.Decode(context.Background(), map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error for missing session ID")
	}
}

// ---------------------------------------------------------------
// 10. Store error propagated
// ---------------------------------------------------------------

func TestSessionPropagator_StoreError(t *testing.T) {
	store := &errorSessionStore{}
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})

	meta := map[string]string{headerKeySession: "any-id"}
	_, err := p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error when store fails")
	}
}

// ---------------------------------------------------------------
// 11. Satisfies IdentityPropagator interface
// ---------------------------------------------------------------

func TestSessionPropagator_ImplementsInterface(t *testing.T) {
	store := newMockSessionStore()
	p, _ := NewSessionPropagator(SessionPropagatorConfig{Store: store})
	var _ IdentityPropagator = p
}
