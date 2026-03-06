// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package password provides password policy configuration and validation
// following NIST 800-63B guidelines, including breached password checking
// via the HaveIBeenPwned API with k-anonymity.
package password

// PasswordPolicy configures password validation rules. This is a struct,
// not an interface — it's configuration, not behavior.
//
// Default values follow NIST 800-63B recommendations:
//   - MinLength: 8 (NIST minimum)
//   - MaxLength: 128 (prevents DoS via hash computation)
//   - CheckBreached: true (k-anonymity check against known breached passwords)
//   - Composition rules: disabled (NIST explicitly discourages them)
type PasswordPolicy struct {
	// MinLength is the minimum password length in characters (not bytes).
	MinLength int

	// MaxLength is the maximum password length in characters.
	// Prevents denial-of-service via hash computation on extremely long inputs.
	MaxLength int

	// RequireUppercase requires at least one uppercase letter.
	// Disabled by default per NIST 800-63B.
	RequireUppercase bool

	// RequireLowercase requires at least one lowercase letter.
	// Disabled by default per NIST 800-63B.
	RequireLowercase bool

	// RequireDigit requires at least one digit.
	// Disabled by default per NIST 800-63B.
	RequireDigit bool

	// RequireSpecial requires at least one special character.
	// Disabled by default per NIST 800-63B.
	RequireSpecial bool

	// CheckBreached enables checking passwords against known breached password
	// lists via the HaveIBeenPwned API using k-anonymity (only the first 5
	// characters of the SHA-1 hash are sent).
	CheckBreached bool

	// CustomValidator is an optional team-provided function for domain-specific
	// rules (e.g., "password must not contain company name").
	CustomValidator func(string) error
}

// DefaultPolicy returns a PasswordPolicy with NIST 800-63B defaults.
func DefaultPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireDigit:     false,
		RequireSpecial:   false,
		CheckBreached:    true,
		CustomValidator:  nil,
	}
}
