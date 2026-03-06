// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package apikey

import (
	"testing"
	"time"
)

// Test 1.14: APIKey struct has all 9 fields
func TestAPIKey_Fields(t *testing.T) {
	now := time.Now()
	key := APIKey{
		ID:         "key-1",
		SubjectID:  "user-123",
		KeyHash:    "sha256:abc123",
		Name:       "My API Key",
		Scopes:     []string{"read", "write"},
		CreatedAt:  now,
		ExpiresAt:  now.Add(365 * 24 * time.Hour),
		LastUsedAt: now,
		Revoked:    false,
	}

	if key.ID != "key-1" {
		t.Errorf("expected ID=key-1, got %q", key.ID)
	}
	if key.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", key.SubjectID)
	}
	if key.KeyHash != "sha256:abc123" {
		t.Errorf("expected KeyHash=sha256:abc123, got %q", key.KeyHash)
	}
	if key.Name != "My API Key" {
		t.Errorf("expected Name=My API Key, got %q", key.Name)
	}
	if len(key.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(key.Scopes))
	}
	if key.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if key.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if key.LastUsedAt.IsZero() {
		t.Error("LastUsedAt should not be zero")
	}
	if key.Revoked {
		t.Error("Revoked should be false")
	}
}
