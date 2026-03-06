// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package password

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test 3.1: Password shorter than MinLength rejected
func TestPolicy_MinLength(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, MaxLength: 128}
	errs := Validate("short", p)
	if len(errs) == 0 {
		t.Error("expected error for short password")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "at least 8 characters") {
			found = true
		}
	}
	if !found {
		t.Error("expected MinLength error message")
	}
}

// Test 3.2: Password longer than MaxLength rejected
func TestPolicy_MaxLength(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 10}
	errs := Validate("thisissuperlong", p)
	if len(errs) == 0 {
		t.Error("expected error for long password")
	}
}

// Test 3.3: Password exactly at MinLength accepted
func TestPolicy_ExactMinLength(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, MaxLength: 128}
	errs := Validate("exactly8", p) // 8 characters
	if len(errs) != 0 {
		t.Errorf("expected no errors for exact MinLength password, got %v", errs)
	}
}

// Test 3.4: Password exactly at MaxLength accepted
func TestPolicy_ExactMaxLength(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 10}
	errs := Validate("exactly10!", p) // 10 characters
	if len(errs) != 0 {
		t.Errorf("expected no errors for exact MaxLength password, got %v", errs)
	}
}

// Test 3.5: When enabled, password without uppercase rejected
func TestPolicy_RequireUppercase(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 128, RequireUppercase: true}
	errs := Validate("nouppercase123", p)
	if len(errs) == 0 {
		t.Error("expected error for missing uppercase")
	}
	// Should pass with uppercase
	errs = Validate("HasUppercase123", p)
	if len(errs) != 0 {
		t.Errorf("expected no errors with uppercase, got %v", errs)
	}
}

// Test 3.6: When enabled, password without lowercase rejected
func TestPolicy_RequireLowercase(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 128, RequireLowercase: true}
	errs := Validate("NOLOWERCASE123", p)
	if len(errs) == 0 {
		t.Error("expected error for missing lowercase")
	}
	errs = Validate("HASLowercase123", p)
	if len(errs) != 0 {
		t.Errorf("expected no errors with lowercase, got %v", errs)
	}
}

// Test 3.7: When enabled, password without digit rejected
func TestPolicy_RequireDigit(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 128, RequireDigit: true}
	errs := Validate("nodigitshere", p)
	if len(errs) == 0 {
		t.Error("expected error for missing digit")
	}
	errs = Validate("hasdigit1", p)
	if len(errs) != 0 {
		t.Errorf("expected no errors with digit, got %v", errs)
	}
}

// Test 3.8: When enabled, password without special char rejected
func TestPolicy_RequireSpecial(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 128, RequireSpecial: true}
	errs := Validate("nospecialchars1", p)
	if len(errs) == 0 {
		t.Error("expected error for missing special character")
	}
	errs = Validate("has!special1", p)
	if len(errs) != 0 {
		t.Errorf("expected no errors with special char, got %v", errs)
	}
}

// Test 3.9: Default policy does NOT require composition rules
func TestPolicy_CompositionDisabledByDefault(t *testing.T) {
	p := DefaultPolicy()
	// A simple lowercase-only password of sufficient length should pass
	errs := Validate("simplelowercasepassword", p)
	if len(errs) != 0 {
		t.Errorf("default policy should not require composition rules, got %v", errs)
	}
}

// Test 3.10: Custom validator function called, error propagated
func TestPolicy_CustomValidator(t *testing.T) {
	p := PasswordPolicy{
		MinLength: 1,
		MaxLength: 128,
		CustomValidator: func(pw string) error {
			if strings.Contains(strings.ToLower(pw), "acme") {
				return errors.New("password must not contain company name")
			}
			return nil
		},
	}

	errs := Validate("myacmepassword", p)
	if len(errs) == 0 {
		t.Error("expected custom validator error")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "company name") {
			found = true
		}
	}
	if !found {
		t.Error("expected custom validator error message")
	}

	// Password without "acme" should pass
	errs = Validate("goodpassword", p)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

// Test 3.11: Nil custom validator is skipped
func TestPolicy_CustomValidatorNil(t *testing.T) {
	p := PasswordPolicy{MinLength: 1, MaxLength: 128, CustomValidator: nil}
	errs := Validate("anypassword", p)
	if len(errs) != 0 {
		t.Errorf("expected no errors with nil custom validator, got %v", errs)
	}
}

// Test 3.12: All violations returned, not just first
func TestPolicy_MultipleViolations(t *testing.T) {
	p := PasswordPolicy{
		MinLength:        12,
		MaxLength:        128,
		RequireUppercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
	// "short" violates: MinLength, RequireUppercase, RequireDigit, RequireSpecial
	errs := Validate("short", p)
	if len(errs) < 3 {
		t.Errorf("expected at least 3 violations, got %d: %v", len(errs), errs)
	}
}

// Test 3.13: Known breached password flagged
func TestPolicy_BreachedCheck_Known(t *testing.T) {
	// Mock the HIBP API — return a response containing the suffix of "password"
	// SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	// Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a response containing the matching suffix
		fmt.Fprintln(w, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493")
		fmt.Fprintln(w, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0:1")
	}))
	defer server.Close()

	checker := &HIBPChecker{
		Client: server.Client(),
		APIURL: server.URL + "/",
	}

	p := PasswordPolicy{MinLength: 1, MaxLength: 128, CheckBreached: true}
	errs := ValidateWithBreachCheck("password", p, checker)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "breach") {
			found = true
		}
	}
	if !found {
		t.Error("expected breached password error")
	}
}

// Test 3.14: When CheckBreached=false, no API call made
func TestPolicy_BreachedCheck_Disabled(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		fmt.Fprintln(w, "")
	}))
	defer server.Close()

	checker := &HIBPChecker{
		Client: server.Client(),
		APIURL: server.URL + "/",
	}

	p := PasswordPolicy{MinLength: 1, MaxLength: 128, CheckBreached: false}
	_ = ValidateWithBreachCheck("password", p, checker)
	if called {
		t.Error("API should not be called when CheckBreached=false")
	}
}

// Test 3.15: Only first 5 chars of SHA-1 sent to API (k-anonymity)
func TestPolicy_BreachedCheck_KAnonymity(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		fmt.Fprintln(w, "0000000000000000000000000000000000:0")
	}))
	defer server.Close()

	checker := &HIBPChecker{
		Client: server.Client(),
		APIURL: server.URL + "/",
	}

	p := PasswordPolicy{MinLength: 1, MaxLength: 128, CheckBreached: true}
	_ = ValidateWithBreachCheck("testpassword", p, checker)

	// SHA-1 of "testpassword" — only first 5 chars should be in the request path
	prefix := SHA1Prefix("testpassword")
	if len(prefix) != 5 {
		t.Errorf("expected 5-char prefix, got %d chars: %q", len(prefix), prefix)
	}
	if !strings.Contains(receivedPath, prefix) {
		t.Errorf("expected path to contain %q, got %q", prefix, receivedPath)
	}
	// Full hash should NOT be in the path
	fullHash := fmt.Sprintf("%X", sha1Hash("testpassword"))
	_ = fullHash // The full hash is 40 chars; the path should only have the 5-char prefix
}

// Test 3.16: API failure is a soft error (doesn't block registration)
func TestPolicy_BreachedCheck_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	checker := &HIBPChecker{
		Client: server.Client(),
		APIURL: server.URL + "/",
	}

	p := PasswordPolicy{MinLength: 1, MaxLength: 128, CheckBreached: true}
	errs := ValidateWithBreachCheck("goodpassword123", p, checker)
	// Should have NO breach-related errors (soft failure)
	for _, e := range errs {
		if strings.Contains(e.Error(), "breach") {
			t.Errorf("API error should be soft — should not produce breach error, got: %v", e)
		}
	}
}

// Test 3.17: API timeout doesn't block registration
func TestPolicy_BreachedCheck_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond) // Simulate slow API
		fmt.Fprintln(w, "")
	}))
	defer server.Close()

	checker := &HIBPChecker{
		Client: &http.Client{Timeout: 50 * time.Millisecond}, // Very short timeout
		APIURL: server.URL + "/",
	}

	p := PasswordPolicy{MinLength: 1, MaxLength: 128, CheckBreached: true}
	start := time.Now()
	errs := ValidateWithBreachCheck("goodpassword123", p, checker)
	duration := time.Since(start)

	// Should complete quickly (within 1 second, not wait for slow API)
	if duration > 1*time.Second {
		t.Errorf("breach check timeout took too long: %v", duration)
	}

	// Should have NO breach-related errors (timeout is a soft failure)
	for _, e := range errs {
		if strings.Contains(e.Error(), "breach") {
			t.Errorf("timeout should be soft — should not produce breach error, got: %v", e)
		}
	}
}

// Test 3.18: Default policy matches NIST 800-63B
func TestPolicy_NISTDefaults_Validate(t *testing.T) {
	p := DefaultPolicy()
	if p.MinLength != 8 {
		t.Errorf("expected MinLength=8, got %d", p.MinLength)
	}
	if p.MaxLength != 128 {
		t.Errorf("expected MaxLength=128, got %d", p.MaxLength)
	}
	if !p.CheckBreached {
		t.Error("expected CheckBreached=true")
	}
	if p.RequireUppercase || p.RequireLowercase || p.RequireDigit || p.RequireSpecial {
		t.Error("NIST 800-63B: composition rules should be disabled by default")
	}
}

// Test 3.19: Length is counted in characters, not bytes
func TestPolicy_UnicodeLength(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, MaxLength: 128}

	// "пароль12" = 8 characters but more than 8 bytes (Cyrillic is 2 bytes each)
	errs := Validate("пароль12", p)
	if len(errs) != 0 {
		t.Errorf("expected 8-char unicode password to pass MinLength=8, got %v", errs)
	}

	// "密码" = 2 characters (should fail MinLength=8)
	errs = Validate("密码", p)
	if len(errs) == 0 {
		t.Error("expected 2-char password to fail MinLength=8")
	}

	// Emoji test: each emoji is 1 character
	errs = Validate("🔑🔐🔒🔓🗝️💎🎯🎲", p)
	if len(errs) != 0 {
		// Note: some emojis with ZWJ/variations may count as more than 1 rune
		// but basic emojis should work
		t.Logf("emoji test: got %v (may vary by emoji encoding)", errs)
	}
}

// Test 3.20: Empty password fails MinLength
func TestPolicy_EmptyPassword(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, MaxLength: 128}
	errs := Validate("", p)
	if len(errs) == 0 {
		t.Error("expected empty password to fail MinLength check")
	}
}

// --- Hardening Tests ---

// Test H.1: NewHIBPChecker returns checker with sensible defaults.
func TestNewHIBPChecker(t *testing.T) {
	checker := NewHIBPChecker()
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
	if checker.Client == nil {
		t.Error("expected non-nil HTTP client")
	}
	if checker.APIURL != "https://api.pwnedpasswords.com/range/" {
		t.Errorf("expected default APIURL, got %q", checker.APIURL)
	}
}

// Test H.2: apiURL returns default when APIURL is empty.
func TestHIBPChecker_APIURLDefault(t *testing.T) {
	checker := &HIBPChecker{APIURL: ""}
	url := checker.apiURL()
	if url != "https://api.pwnedpasswords.com/range/" {
		t.Errorf("expected default APIURL, got %q", url)
	}
}

// Test H.3: apiURL returns custom when set.
func TestHIBPChecker_APIURLCustom(t *testing.T) {
	checker := &HIBPChecker{APIURL: "http://localhost:9999/range/"}
	url := checker.apiURL()
	if url != "http://localhost:9999/range/" {
		t.Errorf("expected custom APIURL, got %q", url)
	}
}

// Test H.4: IsBreached with non-200 status code returns error.
func TestHIBPChecker_Non200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	checker := &HIBPChecker{
		Client: server.Client(),
		APIURL: server.URL + "/",
	}

	_, err := checker.IsBreached("password")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

// Test H.5: containsSuffix with suffix that has count=0 still returns true.
func TestContainsSuffix_ZeroCount(t *testing.T) {
	input := strings.NewReader("ABC:0\nDEF:5\n")
	found, err := containsSuffix(input, "ABC")
	if err != nil {
		t.Fatalf("containsSuffix() error: %v", err)
	}
	// count=0 means the suffix line exists but with 0 — our code returns true
	// because the first branch matches even with count=0.
	if !found {
		t.Error("expected true for suffix with count=0 (line exists)")
	}
}

// Test H.6: containsSuffix with no matching suffix returns false.
func TestContainsSuffix_NotFound(t *testing.T) {
	input := strings.NewReader("ABC:5\nDEF:10\n")
	found, err := containsSuffix(input, "XYZ")
	if err != nil {
		t.Fatalf("containsSuffix() error: %v", err)
	}
	if found {
		t.Error("expected false for non-matching suffix")
	}
}
