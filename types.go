// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

// CredentialType identifies the kind of credential being presented.
type CredentialType string

const (
	// CredentialTypePassword is for username/email + password authentication.
	CredentialTypePassword CredentialType = "password"

	// CredentialTypeOAuth is for OAuth2/OIDC authentication.
	CredentialTypeOAuth CredentialType = "oauth2"

	// CredentialTypeMagicLink is for passwordless magic link authentication.
	CredentialTypeMagicLink CredentialType = "magic_link"

	// CredentialTypeAPIKey is for API key authentication.
	CredentialTypeAPIKey CredentialType = "api_key"

	// CredentialTypeMTLS is for mutual TLS certificate authentication.
	CredentialTypeMTLS CredentialType = "mtls"

	// CredentialTypeSPIFFE is for SPIFFE SVID authentication.
	CredentialTypeSPIFFE CredentialType = "spiffe"
)

// Credential represents an authentication credential presented by a user or service.
type Credential struct {
	// Type identifies the kind of credential.
	Type CredentialType

	// Identifier is the user identifier (email, username, etc.).
	Identifier string

	// Secret is the credential secret (password, token, API key, etc.).
	Secret string

	// Metadata holds additional credential-specific data (e.g., OAuth provider name, PKCE verifier).
	Metadata map[string]any
}

// AuthEvent represents a lifecycle event emitted by the auth engine.
type AuthEvent string

const (
	// EventRegistration is emitted when a new user registers.
	EventRegistration AuthEvent = "registration"

	// EventLogin is emitted on successful login.
	EventLogin AuthEvent = "login"

	// EventLoginFailed is emitted on failed login attempt.
	EventLoginFailed AuthEvent = "login_failed"

	// EventLogout is emitted when a user logs out.
	EventLogout AuthEvent = "logout"

	// EventPasswordReset is emitted on password reset/change.
	EventPasswordReset AuthEvent = "password_reset"

	// EventMagicLinkSent is emitted when a magic link is sent.
	EventMagicLinkSent AuthEvent = "magic_link_sent"

	// EventAccountLocked is emitted when an account is locked due to failed attempts.
	EventAccountLocked AuthEvent = "account_locked"
)

// IdentifierConfig tells the library what field identifies a user.
// The team configures this — the library never assumes email, username, or phone.
type IdentifierConfig struct {
	// Field is the name of the identifier field (e.g., "email", "username", "phone").
	Field string

	// CaseSensitive controls whether identifier comparisons are case-sensitive.
	// For emails, this should be false. For UUIDs, this should be true.
	CaseSensitive bool

	// Normalize transforms an identifier before lookup.
	// For emails, this typically lowercases. For usernames, this might trim whitespace.
	// If nil, no normalization is applied.
	Normalize func(string) string
}
