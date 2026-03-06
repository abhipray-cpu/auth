// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package password implements the password authentication mode.
//
// Security features:
//   - Constant-time dummy hash when user doesn't exist (timing attack prevention)
//   - Account lockout after configurable N failed attempts
//   - Generic errors for all failure paths (user enumeration prevention)
//   - Identifier normalization via IdentifierConfig
package password

import (
	"context"
	"time"

	"github.com/abhipray-cpu/auth"
)

// ModeConfig configures the password authentication mode.
type ModeConfig struct {
	// UserStore is the team's user persistence (required).
	UserStore auth.UserStore

	// Hasher hashes and verifies passwords (required).
	Hasher auth.Hasher

	// IdentifierConfig controls identifier normalization.
	IdentifierConfig auth.IdentifierConfig

	// LockoutThreshold is the number of failed attempts before lockout.
	// 0 means lockout is disabled.
	LockoutThreshold int
}

// Mode implements auth.AuthMode for password-based authentication.
type Mode struct {
	userStore        auth.UserStore
	hasher           auth.Hasher
	identifierCfg    auth.IdentifierConfig
	lockoutThreshold int
}

// NewMode creates a new PasswordMode. Panics if UserStore or Hasher is nil,
// since these are hard dependencies without which Authenticate would panic anyway.
func NewMode(cfg ModeConfig) *Mode {
	if cfg.UserStore == nil {
		panic("auth/password: UserStore is required")
	}
	if cfg.Hasher == nil {
		panic("auth/password: Hasher is required")
	}
	return &Mode{
		userStore:        cfg.UserStore,
		hasher:           cfg.Hasher,
		identifierCfg:    cfg.IdentifierConfig,
		lockoutThreshold: cfg.LockoutThreshold,
	}
}

// Name returns the mode identifier.
func (m *Mode) Name() string { return "password" }

// Supports returns true only for CredentialTypePassword.
func (m *Mode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypePassword
}

// Authenticate verifies a password credential. It implements constant-time
// behavior for non-existent users and generic error messages for all
// failure paths to prevent user enumeration.
func (m *Mode) Authenticate(ctx context.Context, cred auth.Credential) (*auth.Identity, error) {
	// Reject empty credentials immediately — but still do a dummy hash
	// to maintain constant time.
	if cred.Identifier == "" || cred.Secret == "" {
		_ = m.dummyHash()
		return nil, auth.ErrInvalidCredentials
	}

	identifier := m.normalizeIdentifier(cred.Identifier)

	// Look up user.
	user, err := m.userStore.FindByIdentifier(ctx, identifier)
	if err != nil {
		// User not found — perform dummy hash to match timing of a
		// real password verification. This prevents user enumeration
		// via timing side-channel.
		_ = m.dummyHash()
		return nil, auth.ErrInvalidCredentials
	}

	// Check if account is locked. Still do a dummy hash for constant time.
	if user.IsLocked() {
		_ = m.dummyHash()
		return nil, auth.ErrInvalidCredentials
	}

	// Verify password (this is the real hash operation).
	match, err := m.hasher.Verify(cred.Secret, user.GetPasswordHash())
	if err != nil || !match {
		// Wrong password — increment failed attempts.
		_ = m.userStore.IncrementFailedAttempts(ctx, user.GetSubjectID())

		// Check if we should lock the account.
		if m.lockoutThreshold > 0 && user.GetFailedAttempts()+1 >= m.lockoutThreshold {
			_ = m.userStore.SetLocked(ctx, user.GetSubjectID(), true)
		}

		return nil, auth.ErrInvalidCredentials
	}

	// Correct password — reset failed attempts.
	_ = m.userStore.ResetFailedAttempts(ctx, user.GetSubjectID())

	identity := &auth.Identity{
		SubjectID:  user.GetSubjectID(),
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	return identity, nil
}

// dummyHash performs a hash operation on a dummy value to ensure
// constant timing regardless of whether the user exists.
func (m *Mode) dummyHash() error {
	_, err := m.hasher.Verify("dummy-password-for-timing", "$argon2id$v=19$m=65536,t=1,p=4$dW5rbm93bg$dW5rbm93bg")
	return err
}

// normalizeIdentifier applies configured normalization to an identifier.
func (m *Mode) normalizeIdentifier(identifier string) string {
	if m.identifierCfg.Normalize != nil {
		return m.identifierCfg.Normalize(identifier)
	}
	return identifier
}

// Compile-time interface check.
var _ auth.AuthMode = (*Mode)(nil)
