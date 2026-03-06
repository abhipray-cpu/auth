// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import "context"

// UserStore is the interface for user persistence. The team implements this
// for their own database and schema. The auth library never dictates
// user table structure.
type UserStore interface {
	// FindByIdentifier looks up a user by their configured identifier
	// (email, username, phone, etc.). Returns ErrUserNotFound if not found.
	FindByIdentifier(ctx context.Context, identifier string) (User, error)

	// Create persists a new user. Returns ErrUserAlreadyExists if the
	// identifier is already taken.
	Create(ctx context.Context, user User) error

	// UpdatePassword updates the password hash for a user.
	UpdatePassword(ctx context.Context, subjectID string, hash string) error

	// IncrementFailedAttempts increments the failed login attempt counter.
	IncrementFailedAttempts(ctx context.Context, subjectID string) error

	// ResetFailedAttempts resets the failed login attempt counter to zero.
	ResetFailedAttempts(ctx context.Context, subjectID string) error

	// SetLocked locks or unlocks a user account.
	SetLocked(ctx context.Context, subjectID string, locked bool) error
}

// User is the interface that wraps the team's user model. The library
// reads user attributes through this interface — it never accesses
// the underlying struct directly.
type User interface {
	// GetSubjectID returns the unique identifier for the user.
	GetSubjectID() string

	// GetIdentifier returns the login identifier (email, username, etc.).
	GetIdentifier() string

	// GetPasswordHash returns the stored password hash.
	// Returns empty string for users without a password (e.g., OAuth-only).
	GetPasswordHash() string

	// GetFailedAttempts returns the count of consecutive failed login attempts.
	GetFailedAttempts() int

	// IsLocked returns whether the account is locked.
	IsLocked() bool

	// IsMFAEnabled returns whether multi-factor authentication is enabled.
	IsMFAEnabled() bool

	// GetMetadata returns extensible user metadata.
	GetMetadata() map[string]any
}

// Hasher hashes and verifies passwords. The library ships Argon2id as the
// default. Teams override only for legacy password schemes.
type Hasher interface {
	// Hash takes a plain-text password and returns a hash string.
	Hash(password string) (string, error)

	// Verify checks a plain-text password against a hash.
	// Must use constant-time comparison.
	Verify(password string, hash string) (bool, error)
}

// Authorizer determines whether a subject is allowed to perform an action
// on a resource. Teams implement this with Casbin, OPA, Cedar, or custom logic.
type Authorizer interface {
	// CanAccess checks if the subject can perform the action on the resource.
	CanAccess(ctx context.Context, subject string, action string, resource string) (bool, error)
}

// Notifier sends notifications on auth events. Teams implement this if they
// want emails, SMS, or other notifications. If not configured, events are
// silently skipped. Required only if magic link mode is enabled.
type Notifier interface {
	// Notify sends a notification for the given auth event.
	// The payload contains event-specific data (e.g., magic link URL, user info).
	Notify(ctx context.Context, event AuthEvent, payload map[string]any) error
}

// AuthMode is the strategy interface for authentication methods.
// Each mode (password, OAuth, magic link, API key, mTLS) implements this.
type AuthMode interface {
	// Name returns the mode identifier (e.g., "password", "oauth2", "magic_link").
	Name() string

	// Authenticate verifies the credential and returns an Identity on success.
	Authenticate(ctx context.Context, credential Credential) (*Identity, error)

	// Supports returns whether this mode can handle the given credential type.
	Supports(credentialType CredentialType) bool
}
