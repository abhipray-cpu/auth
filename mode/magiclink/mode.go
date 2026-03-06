// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package magiclink implements the magic link (passwordless) authentication mode.
//
// Flow:
//  1. Initiate: Generate token → store with "magiclink:" prefix → notify user
//  2. Authenticate: Receive token → consume (single-use) → look up user → return Identity
//
// Security features:
//   - Single-use tokens (deleted after first verification)
//   - Configurable TTL (default: 15 min)
//   - Identifier normalization via IdentifierConfig
//   - Generic errors to prevent user enumeration
package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"
)

const (
	// tokenPrefix is prepended to token keys in the session store.
	tokenPrefix = "magiclink:"

	// tokenLength is the number of random bytes used for token generation (256 bits).
	tokenLength = 32

	// defaultTTL is the default token lifetime.
	defaultTTL = 15 * time.Minute
)

// Config configures the magic link authentication mode.
type Config struct {
	// UserStore is the team's user persistence (required).
	UserStore auth.UserStore

	// MagicLinkStore stores and consumes magic link tokens (required).
	MagicLinkStore session.MagicLinkStore

	// Notifier sends the magic link to the user (required).
	Notifier auth.Notifier

	// IdentifierConfig controls identifier normalization.
	IdentifierConfig auth.IdentifierConfig

	// TTL is the token lifetime. Default: 15 minutes.
	TTL time.Duration
}

// Mode implements auth.AuthMode for magic link (passwordless) authentication.
type Mode struct {
	userStore     auth.UserStore
	tokenStore    session.MagicLinkStore
	notifier      auth.Notifier
	identifierCfg auth.IdentifierConfig
	ttl           time.Duration
}

// NewMode creates a new MagicLinkMode. Returns an error if Notifier is nil,
// since magic link authentication requires sending the link to the user.
func NewMode(cfg Config) (*Mode, error) {
	if cfg.Notifier == nil {
		return nil, errors.New("auth/magiclink: Notifier is required for magic link mode")
	}
	if cfg.UserStore == nil {
		return nil, errors.New("auth/magiclink: UserStore is required")
	}
	if cfg.MagicLinkStore == nil {
		return nil, errors.New("auth/magiclink: MagicLinkStore is required")
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}

	return &Mode{
		userStore:     cfg.UserStore,
		tokenStore:    cfg.MagicLinkStore,
		notifier:      cfg.Notifier,
		identifierCfg: cfg.IdentifierConfig,
		ttl:           ttl,
	}, nil
}

// Name returns the mode identifier.
func (m *Mode) Name() string { return "magic_link" }

// Supports returns true only for CredentialTypeMagicLink.
func (m *Mode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypeMagicLink
}

// Initiate generates a magic link token for the given identifier,
// stores it, and sends it to the user via the Notifier.
// Returns the raw token (for use in the magic link URL).
//
// If the user is not found, no token is generated, but a generic nil
// error is returned to prevent user enumeration. The Notifier is NOT
// called in this case.
func (m *Mode) Initiate(ctx context.Context, identifier string) (string, error) {
	identifier = m.normalizeIdentifier(identifier)

	// Look up the user — if not found, return nil silently (no enumeration).
	user, err := m.userStore.FindByIdentifier(ctx, identifier)
	if err != nil {
		// No user found — return nil with no error to prevent enumeration.
		return "", nil
	}

	// Generate a random token.
	rawToken, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("auth/magiclink: failed to generate token: %w", err)
	}

	// Hash the token for storage.
	hashedToken := session.HashID(rawToken)
	now := time.Now()

	// Store the token with the magiclink: prefix.
	mlToken := &session.MagicLinkToken{
		Token:     tokenPrefix + hashedToken,
		SubjectID: user.GetSubjectID(),
		ExpiresAt: now.Add(m.ttl),
		CreatedAt: now,
	}

	if err := m.tokenStore.Store(ctx, mlToken); err != nil {
		return "", fmt.Errorf("auth/magiclink: failed to store token: %w", err)
	}

	// Notify the user with the raw token.
	notifyPayload := map[string]any{
		"subject_id": user.GetSubjectID(),
		"identifier": identifier,
		"token":      rawToken,
		"expires_at": mlToken.ExpiresAt,
	}

	if err := m.notifier.Notify(ctx, auth.EventMagicLinkSent, notifyPayload); err != nil {
		return "", fmt.Errorf("auth/magiclink: failed to send notification: %w", err)
	}

	return rawToken, nil
}

// Authenticate verifies a magic link token. The token is consumed (deleted)
// after verification, enforcing single-use.
//
// The credential's Secret field should contain the raw token from the magic link URL.
func (m *Mode) Authenticate(ctx context.Context, cred auth.Credential) (*auth.Identity, error) {
	if cred.Secret == "" {
		return nil, auth.ErrInvalidCredentials
	}

	// Hash the raw token and add the magiclink: prefix for lookup.
	hashedToken := tokenPrefix + session.HashID(cred.Secret)

	// Consume the token (single-use — retrieves and deletes atomically).
	mlToken, err := m.tokenStore.Consume(ctx, hashedToken)
	if err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	// Check expiry (defense in depth — store may also enforce TTL).
	if time.Now().After(mlToken.ExpiresAt) {
		return nil, auth.ErrInvalidCredentials
	}

	// Build identity from the token's subject.
	identity := &auth.Identity{
		SubjectID:  mlToken.SubjectID,
		AuthMethod: "magic_link",
		AuthTime:   time.Now(),
	}

	return identity, nil
}

// normalizeIdentifier applies configured normalization to an identifier.
func (m *Mode) normalizeIdentifier(identifier string) string {
	if m.identifierCfg.Normalize != nil {
		return m.identifierCfg.Normalize(identifier)
	}
	return identifier
}

// generateToken produces a cryptographically random token (hex-encoded).
func generateToken() (string, error) {
	b := make([]byte, tokenLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth/magiclink: failed to generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Compile-time interface check.
var _ auth.AuthMode = (*Mode)(nil)
