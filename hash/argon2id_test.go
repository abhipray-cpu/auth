// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package hash

import (
	"strings"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// Test 2.1: Hash a password, verify it returns true
func TestArgon2id_HashAndVerify(t *testing.T) {
	h := NewArgon2idHasher(nil)
	hash, err := h.Hash("correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	ok, err := h.Verify("correcthorsebatterystaple", hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true for correct password")
	}
}

// Test 2.2: Wrong password returns false
func TestArgon2id_WrongPassword(t *testing.T) {
	h := NewArgon2idHasher(nil)
	hash, err := h.Hash("correctpassword")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	ok, err := h.Verify("wrongpassword", hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if ok {
		t.Error("expected Verify to return false for wrong password")
	}
}

// Test 2.3: Same password produces different hashes (random salt)
func TestArgon2id_DifferentHashesPerCall(t *testing.T) {
	h := NewArgon2idHasher(nil)
	hash1, err := h.Hash("samepassword")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	hash2, err := h.Hash("samepassword")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if hash1 == hash2 {
		t.Error("expected different hashes for same password (random salt)")
	}

	// Both should still verify
	ok1, _ := h.Verify("samepassword", hash1)
	ok2, _ := h.Verify("samepassword", hash2)
	if !ok1 || !ok2 {
		t.Error("both hashes should verify correctly")
	}
}

// Test 2.4: Empty password hashes without panic
func TestArgon2id_EmptyPassword(t *testing.T) {
	h := NewArgon2idHasher(nil)
	hash, err := h.Hash("")
	if err != nil {
		t.Fatalf("Hash() error on empty password: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash for empty password")
	}
	ok, err := h.Verify("", hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true for empty password against its hash")
	}
}

// Test 2.5: 128-char password hashes correctly
func TestArgon2id_LongPassword(t *testing.T) {
	h := NewArgon2idHasher(nil)
	longPw := strings.Repeat("a", 128)
	hash, err := h.Hash(longPw)
	if err != nil {
		t.Fatalf("Hash() error on long password: %v", err)
	}
	ok, err := h.Verify(longPw, hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true for long password")
	}
}

// Test 2.6: Unicode characters hash correctly
func TestArgon2id_UnicodePassword(t *testing.T) {
	h := NewArgon2idHasher(nil)
	unicodePw := "пароль密码パスワード🔑"
	hash, err := h.Hash(unicodePw)
	if err != nil {
		t.Fatalf("Hash() error on unicode password: %v", err)
	}
	ok, err := h.Verify(unicodePw, hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true for unicode password")
	}
}

// Test 2.7: Hash string contains $argon2id$v=19$ prefix
func TestArgon2id_HashFormat(t *testing.T) {
	h := NewArgon2idHasher(nil)
	hash, err := h.Hash("testpassword")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("expected hash to start with $argon2id$v=19$, got %q", hash)
	}
	// Verify PHC format: $argon2id$v=19$m=...,t=...,p=...$<salt>$<key>
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("expected 6 parts in PHC format, got %d", len(parts))
	}
}

// Test 2.8: Custom time, memory, parallelism respected
func TestArgon2id_CustomParams(t *testing.T) {
	params := &Argon2idParams{
		Time:        2,
		Memory:      32 * 1024, // 32 MiB
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	h := NewArgon2idHasher(params)
	hash, err := h.Hash("testpassword")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}
	// Verify the params are encoded in the hash
	if !strings.Contains(hash, "m=32768,t=2,p=2") {
		t.Errorf("expected custom params in hash, got %q", hash)
	}
	// Should still verify
	ok, err := h.Verify("testpassword", hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("expected Verify to return true with custom params")
	}
}

// Test 2.9: Default params: time=1, memory=64MB, parallelism=4
func TestArgon2id_DefaultParams(t *testing.T) {
	p := DefaultParams()
	if p.Time != 1 {
		t.Errorf("expected Time=1, got %d", p.Time)
	}
	if p.Memory != 64*1024 {
		t.Errorf("expected Memory=65536 (64MiB), got %d", p.Memory)
	}
	if p.Parallelism != 4 {
		t.Errorf("expected Parallelism=4, got %d", p.Parallelism)
	}

	// Verify default params show up in hash
	h := NewArgon2idHasher(nil)
	hash, _ := h.Hash("test")
	if !strings.Contains(hash, "m=65536,t=1,p=4") {
		t.Errorf("expected default params in hash, got %q", hash)
	}
}

// Test 2.10: Argon2idHasher satisfies Hasher interface
func TestArgon2id_ImplementsHasher(t *testing.T) {
	var _ auth.Hasher = (*Argon2idHasher)(nil)
}

// Test 2.11: Verification takes roughly the same time for correct vs wrong password
func TestArgon2id_ConstantTimeVerify(t *testing.T) {
	// Use fast params so the test doesn't take too long
	params := &Argon2idParams{
		Time:        1,
		Memory:      1024, // 1 MiB — fast for testing
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	h := NewArgon2idHasher(params)
	hash, _ := h.Hash("correctpassword")

	const iterations = 5

	// Measure correct password
	start := time.Now()
	for i := 0; i < iterations; i++ {
		h.Verify("correctpassword", hash)
	}
	correctDuration := time.Since(start)

	// Measure wrong password
	start = time.Now()
	for i := 0; i < iterations; i++ {
		h.Verify("wrongpassword", hash)
	}
	wrongDuration := time.Since(start)

	// They should be roughly the same (within 3x). The real constant-time
	// property is in the subtle.ConstantTimeCompare call — Argon2id takes
	// the same time regardless because it always computes the full hash.
	ratio := float64(correctDuration) / float64(wrongDuration)
	if ratio < 0.3 || ratio > 3.0 {
		t.Errorf("timing difference too large: correct=%v, wrong=%v, ratio=%.2f",
			correctDuration, wrongDuration, ratio)
	}
}

// Test 2.12: Corrupted hash string returns error, not panic
func TestArgon2id_CorruptedHash(t *testing.T) {
	h := NewArgon2idHasher(nil)
	testCases := []struct {
		name string
		hash string
	}{
		{"empty string", ""},
		{"random text", "not-a-hash"},
		{"wrong algorithm", "$bcrypt$v=19$m=65536,t=1,p=4$salt$key"},
		{"missing parts", "$argon2id$v=19"},
		{"corrupted salt", "$argon2id$v=19$m=65536,t=1,p=4$!!!invalid!!!$key"},
		{"corrupted key", "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$!!!invalid!!!"},
		{"wrong version", "$argon2id$v=99$m=65536,t=1,p=4$c2FsdA$a2V5"},
		{"bad parameters", "$argon2id$v=19$garbage$c2FsdA$a2V5"},
		{"bad version format", "$argon2id$vX$m=65536,t=1,p=4$c2FsdA$a2V5"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := h.Verify("password", tc.hash)
			if err == nil {
				t.Errorf("expected error for corrupted hash %q, got ok=%v", tc.hash, ok)
			}
			if ok {
				t.Error("expected false for corrupted hash")
			}
		})
	}
}
