// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package hooks provides a lifecycle event hook system for the auth library.
//
// Teams register callbacks for auth events (login, registration, logout, etc.)
// without modifying auth code. Before hooks can abort flows; after hook errors
// are logged but don't fail the operation.
package hooks

import "time"

// HookPayload is the base interface for all event payloads.
// Every payload carries the AuthMethod for audit purposes.
type HookPayload interface {
	// GetAuthMethod returns the authentication method associated with this event.
	GetAuthMethod() string
}

// LoginPayload is the payload for login-related events
// (BeforeLogin, AfterLogin, AfterFailedLogin).
type LoginPayload struct {
	// Identifier is the user identifier attempted.
	Identifier string

	// AuthMethod is how authentication was attempted ("password", "oauth2", etc.).
	AuthMethod string

	// SubjectID is the authenticated user's ID (empty for failed logins).
	SubjectID string

	// SessionID is the created session ID (empty for failed/before logins).
	SessionID string

	// Error is the failure reason (nil for successful logins).
	Error error
}

// GetAuthMethod implements HookPayload.
func (p *LoginPayload) GetAuthMethod() string { return p.AuthMethod }

// RegisterPayload is the payload for registration events
// (BeforeRegister, AfterRegister).
type RegisterPayload struct {
	// Identifier is the user identifier being registered.
	Identifier string

	// AuthMethod is the registration method (typically "password").
	AuthMethod string

	// SubjectID is the newly created user's ID (empty for BeforeRegister).
	SubjectID string

	// SessionID is the session created on registration (empty for BeforeRegister).
	SessionID string
}

// GetAuthMethod implements HookPayload.
func (p *RegisterPayload) GetAuthMethod() string { return p.AuthMethod }

// LogoutPayload is the payload for logout events (AfterLogout).
type LogoutPayload struct {
	// SubjectID is the user who logged out.
	SubjectID string

	// SessionID is the destroyed session ID.
	SessionID string

	// AuthMethod is recorded for audit trail.
	AuthMethod string
}

// GetAuthMethod implements HookPayload.
func (p *LogoutPayload) GetAuthMethod() string { return p.AuthMethod }

// OAuthPayload is the payload for OAuth-related events.
// Includes the provider name for multi-provider setups.
type OAuthPayload struct {
	// ProviderName identifies the OAuth provider (e.g., "google", "github").
	ProviderName string

	// Identifier is the user identifier from the OAuth provider.
	Identifier string

	// AuthMethod is always "oauth2".
	AuthMethod string

	// SubjectID is the authenticated user's ID.
	SubjectID string

	// SessionID is the created session ID.
	SessionID string

	// IsNewUser indicates whether this was an auto-registration.
	IsNewUser bool
}

// GetAuthMethod implements HookPayload.
func (p *OAuthPayload) GetAuthMethod() string { return p.AuthMethod }

// MagicLinkPayload is the payload for magic link events.
// Includes the token TTL for observability.
type MagicLinkPayload struct {
	// Identifier is the user identifier the magic link was sent to.
	Identifier string

	// AuthMethod is always "magic_link".
	AuthMethod string

	// SubjectID is the user's ID.
	SubjectID string

	// TokenTTL is the lifetime of the magic link token.
	TokenTTL time.Duration

	// SessionID is the created session ID (empty for send events).
	SessionID string
}

// GetAuthMethod implements HookPayload.
func (p *MagicLinkPayload) GetAuthMethod() string { return p.AuthMethod }

// APIKeyPayload is the payload for API key events.
// Includes key name and scopes for audit.
type APIKeyPayload struct {
	// KeyName is the human-readable name of the API key.
	KeyName string

	// Scopes lists the permissions granted to the key.
	Scopes []string

	// AuthMethod is always "api_key".
	AuthMethod string

	// SubjectID is the key owner's ID.
	SubjectID string

	// KeyID is the API key record ID.
	KeyID string
}

// GetAuthMethod implements HookPayload.
func (p *APIKeyPayload) GetAuthMethod() string { return p.AuthMethod }
