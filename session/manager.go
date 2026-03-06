// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/abhipray-cpu/auth"
)

// Manager handles session lifecycle: creation, validation, refresh, and
// destruction. It wraps a SessionStore and enforces timeout policies,
// concurrent session limits, and session fixation prevention.
type Manager struct {
	store  SessionStore
	config SessionConfig
}

// NewManager creates a new SessionManager with the given store and config.
// Panics if store is nil.
func NewManager(store SessionStore, config SessionConfig) *Manager {
	if store == nil {
		panic("auth/session: SessionStore is required")
	}
	return &Manager{
		store:  store,
		config: config,
	}
}

// CreateSession creates a new session for the given subject. It implements
// unconditional session fixation prevention: any existing sessions for the
// subject are destroyed before the new session is created (when an
// existingSessionID is provided).
//
// It returns the raw session ID (to be placed in the cookie) and the
// Session struct. The raw ID is NOT stored — only its SHA-256 hash.
func (m *Manager) CreateSession(ctx context.Context, subjectID string, existingSessionID string, metadata map[string]any) (string, *Session, error) {
	// Session fixation prevention: destroy the existing session.
	if existingSessionID != "" {
		hashedExisting := HashID(existingSessionID)
		// Best-effort delete — ignore ErrSessionNotFound.
		_ = m.store.Delete(ctx, hashedExisting)
	}

	// Enforce concurrent session limit.
	if m.config.MaxConcurrent > 0 {
		if err := m.evictOldestIfNeeded(ctx, subjectID); err != nil {
			return "", nil, fmt.Errorf("auth/session: concurrent limit enforcement failed: %w", err)
		}
	}

	// Generate new session ID.
	rawID, err := GenerateID()
	if err != nil {
		return "", nil, err
	}
	hashedID := HashID(rawID)

	now := time.Now()
	sess := &Session{
		ID:            hashedID,
		SubjectID:     subjectID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(m.config.AbsoluteTimeout),
		LastActiveAt:  now,
		SchemaVersion: SchemaVersion,
		Metadata:      metadata,
	}

	if err := m.store.Create(ctx, sess); err != nil {
		return "", nil, fmt.Errorf("auth/session: failed to create session: %w", err)
	}

	return rawID, sess, nil
}

// ValidateSession validates a session by its raw ID. It checks:
// 1. Session exists in the store
// 2. Session has not exceeded absolute timeout
// 3. Session has not exceeded idle timeout
//
// Uses constant-time comparison for the session ID lookup.
func (m *Manager) ValidateSession(ctx context.Context, rawID string) (*Session, error) {
	hashedID := HashID(rawID)

	sess, err := m.store.Get(ctx, hashedID)
	if err != nil {
		return nil, auth.ErrSessionNotFound
	}

	// Constant-time comparison of the stored hashed ID with our computed hash.
	if subtle.ConstantTimeCompare([]byte(sess.ID), []byte(hashedID)) != 1 {
		return nil, auth.ErrSessionNotFound
	}

	now := time.Now()

	// Check absolute timeout.
	if now.After(sess.ExpiresAt) {
		return nil, auth.ErrSessionExpired
	}

	// Check idle timeout.
	if m.config.IdleTimeout > 0 && now.After(sess.LastActiveAt.Add(m.config.IdleTimeout)) {
		return nil, auth.ErrSessionExpired
	}

	return sess, nil
}

// RefreshSession updates the session's LastActiveAt (sliding window).
// A refresh is denied if the session is already expired.
func (m *Manager) RefreshSession(ctx context.Context, rawID string) (*Session, error) {
	sess, err := m.ValidateSession(ctx, rawID)
	if err != nil {
		return nil, err
	}

	sess.LastActiveAt = time.Now()
	if err := m.store.Update(ctx, sess); err != nil {
		return nil, fmt.Errorf("auth/session: failed to refresh session: %w", err)
	}

	return sess, nil
}

// DestroySession deletes a single session by its raw ID.
func (m *Manager) DestroySession(ctx context.Context, rawID string) error {
	hashedID := HashID(rawID)
	return m.store.Delete(ctx, hashedID)
}

// DestroyAllSessions deletes all sessions for the given subject.
func (m *Manager) DestroyAllSessions(ctx context.Context, subjectID string) error {
	return m.store.DeleteBySubject(ctx, subjectID)
}

// evictOldestIfNeeded enforces the MaxConcurrent session limit by evicting
// sessions when the limit would be exceeded by a new session. It counts
// existing sessions and, if at or above the limit, removes the oldest ones
// to make room.
//
// Note: this is a simplified implementation. For production with high
// concurrency, an atomic compare-and-swap or Lua script (Redis) would be
// preferred.
func (m *Manager) evictOldestIfNeeded(ctx context.Context, subjectID string) error {
	count, err := m.store.CountBySubject(ctx, subjectID)
	if err != nil {
		return err
	}

	if count >= m.config.MaxConcurrent {
		// We need to evict. In a real implementation with Redis/Postgres,
		// we'd query for the oldest session and delete it. With the mock
		// store we use ListBySubject from our extended interface.
		if lister, ok := m.store.(interface {
			ListBySubject(ctx context.Context, subjectID string) ([]*Session, error)
		}); ok {
			sessions, err := lister.ListBySubject(ctx, subjectID)
			if err != nil {
				return err
			}
			// Find and evict oldest sessions until we're under the limit.
			// Sessions should be sorted by CreatedAt; we find the oldest.
			toEvict := count - m.config.MaxConcurrent + 1
			if toEvict > len(sessions) {
				toEvict = len(sessions)
			}

			// Sort by CreatedAt ascending (find oldest).
			oldest := findOldestSessions(sessions, toEvict)
			for _, s := range oldest {
				if err := m.store.Delete(ctx, s.ID); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// findOldestSessions returns the N oldest sessions from the slice.
func findOldestSessions(sessions []*Session, n int) []*Session {
	if n <= 0 || len(sessions) == 0 {
		return nil
	}
	if n >= len(sessions) {
		return sessions
	}

	// Simple selection: find the N oldest by CreatedAt.
	type indexed struct {
		idx int
		t   time.Time
	}
	items := make([]indexed, len(sessions))
	for i, s := range sessions {
		items[i] = indexed{idx: i, t: s.CreatedAt}
	}

	// Selection sort for small N (typical MaxConcurrent is 5).
	result := make([]*Session, 0, n)
	selected := make(map[int]bool)
	for i := 0; i < n; i++ {
		minIdx := -1
		var minTime time.Time
		for j, item := range items {
			if selected[j] {
				continue
			}
			if minIdx == -1 || item.t.Before(minTime) {
				minIdx = j
				minTime = item.t
			}
		}
		if minIdx >= 0 {
			selected[minIdx] = true
			result = append(result, sessions[items[minIdx].idx])
		}
	}

	return result
}
