// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package apikey defines the API key struct and persistence interface.
//
// API keys are a first-class concept with their own lifecycle (create,
// revoke, list) and metadata (scopes, expiry, last used) — intentionally
// separate from users.
package apikey

import (
	"context"
	"time"
)

// APIKey represents an API key with its associated metadata.
// API keys are a first-class concept, separate from user records.
type APIKey struct {
	// ID is the unique identifier for this API key record.
	ID string

	// SubjectID is the user or service that owns this key.
	SubjectID string

	// KeyHash is the hashed API key (never store raw keys).
	KeyHash string

	// Name is a human-readable label for the key.
	Name string

	// Scopes lists the permissions granted to this key.
	Scopes []string

	// CreatedAt is when the key was created.
	CreatedAt time.Time

	// ExpiresAt is when the key expires. Zero value means no expiry.
	ExpiresAt time.Time

	// LastUsedAt is the last time the key was used for authentication.
	LastUsedAt time.Time

	// Revoked indicates whether the key has been explicitly revoked.
	Revoked bool
}

// APIKeyStore is the persistence interface for API keys. The team implements
// this for their own database. API keys have their own lifecycle (create,
// revoke, list) and metadata (scopes, expiry, last used) — they are
// intentionally separate from UserStore.
type APIKeyStore interface {
	// FindByKey looks up an API key by its hash.
	FindByKey(ctx context.Context, keyHash string) (*APIKey, error)

	// Create persists a new API key.
	Create(ctx context.Context, apiKey *APIKey) error

	// Revoke marks an API key as revoked.
	Revoke(ctx context.Context, keyID string) error

	// ListBySubject returns all API keys for a given subject.
	ListBySubject(ctx context.Context, subjectID string) ([]*APIKey, error)

	// UpdateLastUsed updates the LastUsedAt timestamp for a key.
	// This method was identified as a critical gap (Gap 9) — tracking
	// key usage is essential for security auditing and key rotation decisions.
	UpdateLastUsed(ctx context.Context, keyID string, timestamp time.Time) error
}
