// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package session provides session management types, configuration, and
// persistence interfaces. The library ships Redis and Postgres adapters;
// teams provide a custom SessionStore only if neither fits.
package session

import (
	"context"
	"time"
)

// SchemaVersion is the current schema version for session storage.
// The library checks this on startup and fails with a clear error
// if the stored version doesn't match.
const SchemaVersion = 1

// Session represents an authenticated session in the session store.
type Session struct {
	// ID is the session identifier (SHA-256 hash of the raw ID stored in the cookie).
	ID string

	// SubjectID is the authenticated user's identifier.
	SubjectID string

	// CreatedAt is when the session was created.
	CreatedAt time.Time

	// ExpiresAt is the absolute expiry time of the session.
	ExpiresAt time.Time

	// LastActiveAt is the last time the session was used (for idle timeout).
	LastActiveAt time.Time

	// SchemaVersion tracks the schema version for safe migrations.
	SchemaVersion int

	// Metadata holds extensible session data.
	Metadata map[string]any
}

// SessionConfig configures session behavior.
type SessionConfig struct {
	// IdleTimeout is the maximum time a session can be inactive before expiring.
	IdleTimeout time.Duration

	// AbsoluteTimeout is the maximum lifetime of a session regardless of activity.
	AbsoluteTimeout time.Duration

	// MaxConcurrent is the maximum number of concurrent sessions per user.
	// 0 means unlimited.
	MaxConcurrent int

	// CookieName is the name of the session cookie.
	CookieName string

	// CookieDomain is the domain scope for the session cookie.
	CookieDomain string

	// CookieSecure controls whether the cookie requires HTTPS.
	CookieSecure bool

	// CookieSameSite controls the SameSite attribute of the session cookie.
	// Valid values: "Strict", "Lax", "None".
	CookieSameSite string
}

// SessionStore is the persistence interface for sessions. The library ships
// Redis and Postgres adapters. Teams provide a custom implementation only
// if neither fits.
type SessionStore interface {
	// Create persists a new session.
	Create(ctx context.Context, session *Session) error

	// Get retrieves a session by its hashed ID.
	Get(ctx context.Context, sessionID string) (*Session, error)

	// Update persists changes to an existing session.
	Update(ctx context.Context, session *Session) error

	// Delete removes a single session by ID.
	Delete(ctx context.Context, sessionID string) error

	// DeleteBySubject removes all sessions for a given subject.
	DeleteBySubject(ctx context.Context, subjectID string) error

	// CountBySubject returns the number of active sessions for a subject.
	CountBySubject(ctx context.Context, subjectID string) (int, error)
}
