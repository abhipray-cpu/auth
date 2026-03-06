// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Test 1.1: Zero-value Identity has empty SubjectID, nil Metadata
func TestIdentity_ZeroValue(t *testing.T) {
	var id Identity
	if id.SubjectID != "" {
		t.Errorf("expected empty SubjectID, got %q", id.SubjectID)
	}
	if id.AuthMethod != "" {
		t.Errorf("expected empty AuthMethod, got %q", id.AuthMethod)
	}
	if !id.AuthTime.IsZero() {
		t.Errorf("expected zero AuthTime, got %v", id.AuthTime)
	}
	if id.SessionID != "" {
		t.Errorf("expected empty SessionID, got %q", id.SessionID)
	}
	if id.WorkloadID != "" {
		t.Errorf("expected empty WorkloadID, got %q", id.WorkloadID)
	}
	if id.TrustDomain != "" {
		t.Errorf("expected empty TrustDomain, got %q", id.TrustDomain)
	}
	if id.Metadata != nil {
		t.Errorf("expected nil Metadata, got %v", id.Metadata)
	}
}

// Test 1.2: Metadata can be set and read
func TestIdentity_WithMetadata(t *testing.T) {
	id := Identity{
		SubjectID: "user-123",
		Metadata: map[string]any{
			"role":  "admin",
			"email": "alice@acme.com",
		},
	}
	if id.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", id.SubjectID)
	}
	if id.Metadata["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", id.Metadata["role"])
	}
	if id.Metadata["email"] != "alice@acme.com" {
		t.Errorf("expected email=alice@acme.com, got %v", id.Metadata["email"])
	}
}

// Test 1.3: GetIdentity returns identity when set
func TestGetIdentity_FromContext(t *testing.T) {
	id := &Identity{
		SubjectID:  "user-123",
		AuthMethod: "password",
		AuthTime:   time.Now(),
		SessionID:  "sess-abc",
	}
	ctx := SetIdentity(context.Background(), id)
	got := GetIdentity(ctx)
	if got == nil {
		t.Fatal("expected identity, got nil")
	}
	if got.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", got.SubjectID)
	}
	if got.AuthMethod != "password" {
		t.Errorf("expected AuthMethod=password, got %q", got.AuthMethod)
	}
	if got.SessionID != "sess-abc" {
		t.Errorf("expected SessionID=sess-abc, got %q", got.SessionID)
	}
}

// Test 1.4: GetIdentity returns nil for bare context
func TestGetIdentity_NilWhenMissing(t *testing.T) {
	ctx := context.Background()
	got := GetIdentity(ctx)
	if got != nil {
		t.Errorf("expected nil identity for bare context, got %+v", got)
	}
}

// Test 1.5: Setting identity returns new context, original unchanged
func TestSetIdentity_Immutable(t *testing.T) {
	original := context.Background()
	id := &Identity{SubjectID: "user-123"}
	newCtx := SetIdentity(original, id)

	// Original context should NOT have the identity
	if GetIdentity(original) != nil {
		t.Error("original context was modified — should be immutable")
	}

	// New context should have the identity
	got := GetIdentity(newCtx)
	if got == nil || got.SubjectID != "user-123" {
		t.Error("new context should have the identity")
	}
}

// Test 1.6: WorkloadIdentity has empty WorkloadID, TrustDomain
func TestWorkloadIdentity_ZeroValue(t *testing.T) {
	var wid WorkloadIdentity
	if wid.WorkloadID != "" {
		t.Errorf("expected empty WorkloadID, got %q", wid.WorkloadID)
	}
	if wid.TrustDomain != "" {
		t.Errorf("expected empty TrustDomain, got %q", wid.TrustDomain)
	}
	if wid.Metadata != nil {
		t.Errorf("expected nil Metadata, got %v", wid.Metadata)
	}
}

// Test 1.7: Both Identity and WorkloadIdentity on same context (dual identity)
func TestGetWorkloadIdentity_FromContext(t *testing.T) {
	uid := &Identity{SubjectID: "user-123", AuthMethod: "oauth2"}
	wid := &WorkloadIdentity{WorkloadID: "spiffe://acme.com/gateway", TrustDomain: "acme.com"}

	ctx := context.Background()
	ctx = SetIdentity(ctx, uid)
	ctx = SetWorkloadIdentity(ctx, wid)

	// Both should be retrievable
	gotUser := GetIdentity(ctx)
	gotWorkload := GetWorkloadIdentity(ctx)

	if gotUser == nil {
		t.Fatal("expected user identity, got nil")
	}
	if gotUser.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", gotUser.SubjectID)
	}

	if gotWorkload == nil {
		t.Fatal("expected workload identity, got nil")
	}
	if gotWorkload.WorkloadID != "spiffe://acme.com/gateway" {
		t.Errorf("expected WorkloadID=spiffe://acme.com/gateway, got %q", gotWorkload.WorkloadID)
	}
	if gotWorkload.TrustDomain != "acme.com" {
		t.Errorf("expected TrustDomain=acme.com, got %q", gotWorkload.TrustDomain)
	}
}

// Test 1.8: Normalize function applies (e.g., lowercase email)
func TestIdentifierConfig_Normalize(t *testing.T) {
	cfg := IdentifierConfig{
		Field:         "email",
		CaseSensitive: false,
		Normalize: func(s string) string {
			// Simple lowercase for test
			result := make([]byte, len(s))
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				result[i] = c
			}
			return string(result)
		},
	}
	if cfg.Field != "email" {
		t.Errorf("expected Field=email, got %q", cfg.Field)
	}
	if cfg.CaseSensitive {
		t.Error("expected CaseSensitive=false")
	}
	normalized := cfg.Normalize("Alice@ACME.COM")
	if normalized != "alice@acme.com" {
		t.Errorf("expected alice@acme.com, got %q", normalized)
	}
}

// Test 1.9: Case-sensitive identifier comparison
func TestIdentifierConfig_CaseSensitive(t *testing.T) {
	// Case-sensitive config (e.g., for UUIDs)
	cfg := IdentifierConfig{
		Field:         "uuid",
		CaseSensitive: true,
		Normalize:     nil,
	}
	if cfg.Field != "uuid" {
		t.Errorf("expected Field=uuid, got %q", cfg.Field)
	}
	if !cfg.CaseSensitive {
		t.Error("expected CaseSensitive=true")
	}
	if cfg.Normalize != nil {
		t.Error("expected Normalize=nil for UUID config")
	}

	// Case-insensitive config (e.g., for emails)
	cfgEmail := IdentifierConfig{
		Field:         "email",
		CaseSensitive: false,
	}
	if cfgEmail.Field != "email" {
		t.Errorf("expected Field=email, got %q", cfgEmail.Field)
	}
	if cfgEmail.CaseSensitive {
		t.Error("expected CaseSensitive=false for email")
	}
}

// Test 1.10: All auth event constants exist and are unique
func TestAuthEvent_Values(t *testing.T) {
	events := []AuthEvent{
		EventRegistration,
		EventLogin,
		EventLoginFailed,
		EventLogout,
		EventPasswordReset,
		EventMagicLinkSent,
		EventAccountLocked,
	}

	if len(events) != 7 {
		t.Errorf("expected 7 auth events, got %d", len(events))
	}

	// Check uniqueness
	seen := make(map[AuthEvent]bool)
	for _, e := range events {
		if e == "" {
			t.Error("auth event should not be empty")
		}
		if seen[e] {
			t.Errorf("duplicate auth event: %q", e)
		}
		seen[e] = true
	}
}

// Test 1.17: Credential type constants exist for all auth modes
func TestCredential_Types(t *testing.T) {
	types := []CredentialType{
		CredentialTypePassword,
		CredentialTypeOAuth,
		CredentialTypeMagicLink,
		CredentialTypeAPIKey,
		CredentialTypeMTLS,
		CredentialTypeSPIFFE,
	}

	if len(types) != 6 {
		t.Errorf("expected 6 credential types, got %d", len(types))
	}

	// Check uniqueness
	seen := make(map[CredentialType]bool)
	for _, ct := range types {
		if ct == "" {
			t.Error("credential type should not be empty")
		}
		if seen[ct] {
			t.Errorf("duplicate credential type: %q", ct)
		}
		seen[ct] = true
	}
}

// Test 1.18: All sentinel errors are distinct
func TestError_Types(t *testing.T) {
	errs := []error{
		ErrInvalidCredentials,
		ErrAccountLocked,
		ErrSessionExpired,
		ErrSessionNotFound,
		ErrUserNotFound,
		ErrUserAlreadyExists,
		ErrPasswordPolicyViolation,
		ErrAPIKeyExpired,
		ErrAPIKeyRevoked,
		ErrPropagationFailed,
		ErrSchemaVersionMismatch,
		ErrTokenNotFound,
	}

	if len(errs) != 12 {
		t.Errorf("expected 12 sentinel errors, got %d", len(errs))
	}

	// Check uniqueness by error message
	seen := make(map[string]bool)
	for _, e := range errs {
		msg := e.Error()
		if msg == "" {
			t.Error("error message should not be empty")
		}
		if seen[msg] {
			t.Errorf("duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}

// --- Hardening Tests ---

// Test: GetIdentity with wrong type in context returns nil gracefully.
func TestGetIdentity_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), identityKey, "not-an-identity")
	id := GetIdentity(ctx)
	if id != nil {
		t.Errorf("expected nil for wrong type in context, got %+v", id)
	}
}

// Test: GetWorkloadIdentity with wrong type in context returns nil gracefully.
func TestGetWorkloadIdentity_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), workloadIdentityKey, 42)
	wid := GetWorkloadIdentity(ctx)
	if wid != nil {
		t.Errorf("expected nil for wrong type in context, got %+v", wid)
	}
}

// Test: SetIdentity with nil stores nil retrievable as nil.
func TestSetIdentity_Nil(t *testing.T) {
	ctx := SetIdentity(context.Background(), nil)
	got := GetIdentity(ctx)
	if got != nil {
		t.Errorf("expected nil identity when nil was set, got %+v", got)
	}
}

// Test: GetWorkloadIdentity returns nil for empty context.
func TestGetWorkloadIdentity_NilWhenMissing(t *testing.T) {
	ctx := context.Background()
	got := GetWorkloadIdentity(ctx)
	if got != nil {
		t.Errorf("expected nil workload identity for bare context, got %+v", got)
	}
}

// Test: All sentinel errors satisfy errors.Is.
func TestError_ErrorsIs(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidCredentials", ErrInvalidCredentials},
		{"ErrAccountLocked", ErrAccountLocked},
		{"ErrSessionExpired", ErrSessionExpired},
		{"ErrSessionNotFound", ErrSessionNotFound},
		{"ErrUserNotFound", ErrUserNotFound},
		{"ErrUserAlreadyExists", ErrUserAlreadyExists},
		{"ErrPasswordPolicyViolation", ErrPasswordPolicyViolation},
		{"ErrAPIKeyExpired", ErrAPIKeyExpired},
		{"ErrAPIKeyRevoked", ErrAPIKeyRevoked},
		{"ErrPropagationFailed", ErrPropagationFailed},
		{"ErrSchemaVersionMismatch", ErrSchemaVersionMismatch},
		{"ErrTokenNotFound", ErrTokenNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Wrap the error and confirm errors.Is still matches.
			wrapped := fmt.Errorf("context: %w", tc.err)
			if !errors.Is(wrapped, tc.err) {
				t.Errorf("errors.Is failed for wrapped %s", tc.name)
			}
		})
	}
}
