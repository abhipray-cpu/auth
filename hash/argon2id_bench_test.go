// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package hash

import "testing"

// BenchmarkArgon2id_Hash benchmarks password hashing with default parameters.
// This is a hot path on every registration and password change.
func BenchmarkArgon2id_Hash(b *testing.B) {
	p := DefaultParams()
	h := NewArgon2idHasher(&p)
	b.ResetTimer()
	for b.Loop() {
		_, _ = h.Hash("correcthorsebatterystaple")
	}
}

// BenchmarkArgon2id_Verify benchmarks password verification with default parameters.
// This is a hot path on every password login.
func BenchmarkArgon2id_Verify(b *testing.B) {
	p := DefaultParams()
	h := NewArgon2idHasher(&p)
	hash, err := h.Hash("correcthorsebatterystaple")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		_, _ = h.Verify("correcthorsebatterystaple", hash)
	}
}

// BenchmarkArgon2id_Hash_LowMemory benchmarks hashing with low-memory parameters
// (suitable for testing or resource-constrained environments).
func BenchmarkArgon2id_Hash_LowMemory(b *testing.B) {
	h := NewArgon2idHasher(&Argon2idParams{
		Time:        1,
		Memory:      16 * 1024, // 16 MiB
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	})
	b.ResetTimer()
	for b.Loop() {
		_, _ = h.Hash("correcthorsebatterystaple")
	}
}
