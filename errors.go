// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import "errors"

// Sentinel errors for the auth library. Each error represents a distinct
// failure condition that callers can match against using errors.Is().

var (
	// ErrInvalidCredentials is returned when credentials are incorrect.
	// Used for wrong password, invalid token, unknown API key, etc.
	// The error message is intentionally generic to prevent user enumeration.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrAccountLocked is returned when the account is locked due to
	// excessive failed login attempts.
	ErrAccountLocked = errors.New("auth: account locked")

	// ErrSessionExpired is returned when a session has exceeded its
	// idle or absolute timeout.
	ErrSessionExpired = errors.New("auth: session expired")

	// ErrSessionNotFound is returned when a session ID does not exist
	// in the session store.
	ErrSessionNotFound = errors.New("auth: session not found")

	// ErrUserNotFound is returned when a user cannot be found by identifier.
	ErrUserNotFound = errors.New("auth: user not found")

	// ErrUserAlreadyExists is returned when attempting to register a user
	// with an identifier that is already taken.
	ErrUserAlreadyExists = errors.New("auth: user already exists")

	// ErrPasswordPolicyViolation is returned when a password does not meet
	// the configured password policy requirements.
	ErrPasswordPolicyViolation = errors.New("auth: password policy violation")

	// ErrAPIKeyExpired is returned when an API key has passed its expiry date.
	ErrAPIKeyExpired = errors.New("auth: api key expired")

	// ErrAPIKeyRevoked is returned when an API key has been explicitly revoked.
	ErrAPIKeyRevoked = errors.New("auth: api key revoked")

	// ErrPropagationFailed is returned when identity propagation between
	// services fails (e.g., JWT signing/verification failure).
	ErrPropagationFailed = errors.New("auth: identity propagation failed")

	// ErrSchemaVersionMismatch is returned when the session store schema
	// version does not match the library's expected version.
	ErrSchemaVersionMismatch = errors.New("auth: schema version mismatch")

	// ErrTokenNotFound is returned when a magic link token does not exist
	// in the token store (never created, already consumed, or expired).
	ErrTokenNotFound = errors.New("auth: token not found")
)
