// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package apikeymode implements the API key authentication mode.
//
// Security features:
//   - Keys are hashed before lookup (never stored or transmitted in plaintext)
//   - Expiry and revocation checks
//   - LastUsedAt tracking for audit and key rotation decisions
//   - Scopes included in Identity.Metadata
package apikeymode

import (
	"context"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/session"
)

// Config configures the API key authentication mode.
type Config struct {
	// APIKeyStore is the persistence layer for API keys (required).
	APIKeyStore apikey.APIKeyStore
}

// Mode implements auth.AuthMode for API key authentication.
type Mode struct {
	store apikey.APIKeyStore
}

// NewMode creates a new APIKeyMode. Panics if APIKeyStore is nil.
func NewMode(cfg Config) *Mode {
	if cfg.APIKeyStore == nil {
		panic("auth/apikey: APIKeyStore is required")
	}
	return &Mode{
		store: cfg.APIKeyStore,
	}
}

// Name returns the mode identifier.
func (m *Mode) Name() string { return "api_key" }

// Supports returns true only for CredentialTypeAPIKey.
func (m *Mode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypeAPIKey
}

// Authenticate verifies an API key credential.
//
// The credential's Secret field contains the raw API key.
// The key is hashed before lookup, then checked for expiry and revocation.
// On success, LastUsedAt is updated and an Identity is returned with
// the key's scopes in Metadata.
func (m *Mode) Authenticate(ctx context.Context, cred auth.Credential) (*auth.Identity, error) {
	rawKey := cred.Secret
	if rawKey == "" {
		return nil, auth.ErrInvalidCredentials
	}

	// Hash the raw key for lookup.
	keyHash := session.HashID(rawKey)

	// Look up the key by its hash.
	apiKey, err := m.store.FindByKey(ctx, keyHash)
	if err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	// Check revocation.
	if apiKey.Revoked {
		return nil, auth.ErrAPIKeyRevoked
	}

	// Check expiry (zero ExpiresAt means no expiry).
	if !apiKey.ExpiresAt.IsZero() && time.Now().After(apiKey.ExpiresAt) {
		return nil, auth.ErrAPIKeyExpired
	}

	// Update LastUsedAt (best-effort — don't fail auth on tracking error).
	_ = m.store.UpdateLastUsed(ctx, apiKey.ID, time.Now())

	// Build identity with scopes in metadata.
	identity := &auth.Identity{
		SubjectID:  apiKey.SubjectID,
		AuthMethod: "api_key",
		AuthTime:   time.Now(),
		Metadata:   make(map[string]any),
	}

	if len(apiKey.Scopes) > 0 {
		identity.Metadata["scopes"] = apiKey.Scopes
	}

	return identity, nil
}

// Compile-time interface check.
var _ auth.AuthMode = (*Mode)(nil)
