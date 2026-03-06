// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"testing"
	"time"
)

// Test 1.11: Session struct has correct zero values
func TestSession_ZeroValue(t *testing.T) {
	var s Session
	if s.ID != "" {
		t.Errorf("expected empty ID, got %q", s.ID)
	}
	if s.SubjectID != "" {
		t.Errorf("expected empty SubjectID, got %q", s.SubjectID)
	}
	if !s.CreatedAt.IsZero() {
		t.Error("expected zero CreatedAt")
	}
	if !s.ExpiresAt.IsZero() {
		t.Error("expected zero ExpiresAt")
	}
	if !s.LastActiveAt.IsZero() {
		t.Error("expected zero LastActiveAt")
	}
	if s.SchemaVersion != 0 {
		t.Errorf("expected SchemaVersion=0, got %d", s.SchemaVersion)
	}
	if s.Metadata != nil {
		t.Errorf("expected nil Metadata, got %v", s.Metadata)
	}
}

// Test 1.12: SchemaVersion field is present and settable
func TestSession_SchemaVersion(t *testing.T) {
	s := Session{
		ID:            "test-id",
		SubjectID:     "user-123",
		SchemaVersion: SchemaVersion,
	}
	if s.ID != "test-id" {
		t.Errorf("expected ID=test-id, got %q", s.ID)
	}
	if s.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", s.SubjectID)
	}
	if s.SchemaVersion != SchemaVersion {
		t.Errorf("expected SchemaVersion=%d, got %d", SchemaVersion, s.SchemaVersion)
	}
	if s.SchemaVersion != 1 {
		t.Errorf("expected current SchemaVersion=1, got %d", s.SchemaVersion)
	}
}

// Test 1.13: Default config values are sane
func TestSessionConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout should be > 0, got %v", cfg.IdleTimeout)
	}
	if cfg.AbsoluteTimeout <= 0 {
		t.Errorf("AbsoluteTimeout should be > 0, got %v", cfg.AbsoluteTimeout)
	}
	if cfg.AbsoluteTimeout <= cfg.IdleTimeout {
		t.Errorf("AbsoluteTimeout (%v) should be > IdleTimeout (%v)", cfg.AbsoluteTimeout, cfg.IdleTimeout)
	}
	if cfg.CookieName == "" {
		t.Error("CookieName should not be empty")
	}
	if !cfg.CookieSecure {
		t.Error("CookieSecure should default to true")
	}
	if cfg.CookieSameSite != "Strict" {
		t.Errorf("CookieSameSite should default to Strict, got %q", cfg.CookieSameSite)
	}

	// Verify specific values
	if cfg.IdleTimeout != 30*time.Minute {
		t.Errorf("expected IdleTimeout=30m, got %v", cfg.IdleTimeout)
	}
	if cfg.AbsoluteTimeout != 24*time.Hour {
		t.Errorf("expected AbsoluteTimeout=24h, got %v", cfg.AbsoluteTimeout)
	}
}
