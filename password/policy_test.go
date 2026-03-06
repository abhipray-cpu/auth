// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package password

import "testing"

// Test 1.15: Default policy has NIST 800-63B values
func TestPasswordPolicy_NISTDefaults(t *testing.T) {
	p := DefaultPolicy()

	if p.MinLength != 8 {
		t.Errorf("expected MinLength=8, got %d", p.MinLength)
	}
	if p.MaxLength != 128 {
		t.Errorf("expected MaxLength=128, got %d", p.MaxLength)
	}
	if !p.CheckBreached {
		t.Error("expected CheckBreached=true (NIST 800-63B)")
	}
	if p.RequireUppercase {
		t.Error("expected RequireUppercase=false (NIST 800-63B)")
	}
	if p.RequireLowercase {
		t.Error("expected RequireLowercase=false (NIST 800-63B)")
	}
	if p.RequireDigit {
		t.Error("expected RequireDigit=false (NIST 800-63B)")
	}
	if p.RequireSpecial {
		t.Error("expected RequireSpecial=false (NIST 800-63B)")
	}
	if p.CustomValidator != nil {
		t.Error("expected CustomValidator=nil")
	}
}
