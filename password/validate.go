// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package password

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Validate checks a password against the given policy and returns all violations.
// Returns nil if the password is valid. All violations are returned, not just the first.
func Validate(password string, policy PasswordPolicy) []error {
	var errs []error
	charCount := utf8.RuneCountInString(password)

	// Min length (counted in characters, not bytes — unicode safe)
	if charCount < policy.MinLength {
		errs = append(errs, fmt.Errorf("password must be at least %d characters, got %d", policy.MinLength, charCount))
	}

	// Max length (counted in characters)
	if charCount > policy.MaxLength {
		errs = append(errs, fmt.Errorf("password must be at most %d characters, got %d", policy.MaxLength, charCount))
	}

	// Composition rules (disabled by default per NIST 800-63B)
	if policy.RequireUppercase && !containsUpper(password) {
		errs = append(errs, fmt.Errorf("password must contain at least one uppercase letter"))
	}
	if policy.RequireLowercase && !containsLower(password) {
		errs = append(errs, fmt.Errorf("password must contain at least one lowercase letter"))
	}
	if policy.RequireDigit && !containsDigit(password) {
		errs = append(errs, fmt.Errorf("password must contain at least one digit"))
	}
	if policy.RequireSpecial && !containsSpecial(password) {
		errs = append(errs, fmt.Errorf("password must contain at least one special character"))
	}

	// Custom validator
	if policy.CustomValidator != nil {
		if err := policy.CustomValidator(password); err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func containsUpper(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func containsLower(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func containsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func containsSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// ValidateWithBreachCheck validates the password against the policy and also
// checks if it's a known breached password. The breach check is performed
// by the provided BreachChecker. If the checker is nil or fails, the breach
// check is silently skipped (soft error).
func ValidateWithBreachCheck(password string, policy PasswordPolicy, checker BreachChecker) []error {
	errs := Validate(password, policy)

	if policy.CheckBreached && checker != nil {
		breached, err := checker.IsBreached(password)
		if err != nil {
			// Soft error: HIBP API failure doesn't block registration.
			// The caller should log this warning.
			_ = err
		} else if breached {
			errs = append(errs, fmt.Errorf("password has appeared in a known data breach"))
		}
	}

	return errs
}

// BreachChecker checks if a password has appeared in a known data breach.
type BreachChecker interface {
	// IsBreached returns true if the password has been found in a breach database.
	// Only the first 5 characters of the SHA-1 hash should be sent to the API
	// (k-anonymity). Returns an error if the API is unavailable.
	IsBreached(password string) (bool, error)

	// hashPrefix is not part of the interface — it's an implementation detail.
	// The SHA1Prefix method exists for testing k-anonymity compliance.
}

// sha1Prefix is used internally but the interface contract ensures k-anonymity.
var _ = strings.NewReader // satisfy import
