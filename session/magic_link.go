// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// MagicLinkToken represents a single-use magic link token.
type MagicLinkToken struct {
	// Token is the hashed token value stored in the backend.
	Token string

	// SubjectID is the user this token authenticates.
	SubjectID string

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time

	// CreatedAt is when the token was created.
	CreatedAt time.Time
}

// MagicLinkConfig configures magic link token behavior.
type MagicLinkConfig struct {
	// TTL is the lifetime of a magic link token. Default: 15 minutes.
	TTL time.Duration
}

// DefaultMagicLinkConfig returns a MagicLinkConfig with sensible defaults.
func DefaultMagicLinkConfig() MagicLinkConfig {
	return MagicLinkConfig{
		TTL: 15 * time.Minute,
	}
}

// MagicLinkStore is the persistence interface for magic link tokens.
// Tokens are single-use: Consume retrieves and deletes atomically.
type MagicLinkStore interface {
	// Store persists a magic link token with a TTL.
	Store(ctx context.Context, token *MagicLinkToken) error

	// Consume retrieves a token and deletes it in one operation (single-use).
	// Returns ErrTokenNotFound if the token does not exist or has expired.
	Consume(ctx context.Context, tokenValue string) (*MagicLinkToken, error)
}

// MagicLinkManager handles creation and consumption of magic link tokens.
type MagicLinkManager struct {
	store  MagicLinkStore
	config MagicLinkConfig
}

// NewMagicLinkManager creates a new MagicLinkManager.
func NewMagicLinkManager(store MagicLinkStore, config MagicLinkConfig) *MagicLinkManager {
	return &MagicLinkManager{
		store:  store,
		config: config,
	}
}

// CreateToken generates a new magic link token for the given subject.
// Returns the raw token value (to be included in the magic link URL).
func (m *MagicLinkManager) CreateToken(ctx context.Context, subjectID string) (string, error) {
	rawToken, err := generateToken()
	if err != nil {
		return "", err
	}

	hashedToken := HashID(rawToken)
	now := time.Now()

	token := &MagicLinkToken{
		Token:     hashedToken,
		SubjectID: subjectID,
		ExpiresAt: now.Add(m.config.TTL),
		CreatedAt: now,
	}

	if err := m.store.Store(ctx, token); err != nil {
		return "", fmt.Errorf("auth/session: failed to store magic link token: %w", err)
	}

	return rawToken, nil
}

// ConsumeToken validates and consumes a magic link token. The token is
// deleted after retrieval (single-use). Returns ErrTokenNotFound if the
// token does not exist or has expired.
func (m *MagicLinkManager) ConsumeToken(ctx context.Context, rawToken string) (*MagicLinkToken, error) {
	hashedToken := HashID(rawToken)
	return m.store.Consume(ctx, hashedToken)
}

// generateToken produces a 32-byte cryptographically random token (hex-encoded).
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth/session: failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
