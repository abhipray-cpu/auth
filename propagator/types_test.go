// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package propagator

import (
	"testing"
	"time"
)

// Test 1.16: Default propagator config has correct values
func TestPropagatorConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Strategy != "signed-jwt" {
		t.Errorf("expected Strategy=signed-jwt, got %q", cfg.Strategy)
	}
	if cfg.JWTTTL != 30*time.Second {
		t.Errorf("expected JWTTTL=30s, got %v", cfg.JWTTTL)
	}
	if cfg.JWKSEndpoint != "/.well-known/auth-keys" {
		t.Errorf("expected JWKSEndpoint=/.well-known/auth-keys, got %q", cfg.JWKSEndpoint)
	}
}
