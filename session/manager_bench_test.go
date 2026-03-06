// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"testing"
	"time"
)

// BenchmarkSessionManager_ValidateSession benchmarks session validation,
// the hottest path in the library — called on every authenticated request.
func BenchmarkSessionManager_ValidateSession(b *testing.B) {
	store := newMockStore()
	mgr := NewManager(store, SessionConfig{
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 24 * time.Hour,
		MaxConcurrent:   5,
	})

	rawID, _, err := mgr.CreateSession(context.Background(), "bench-user", "", nil)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		_, _ = mgr.ValidateSession(ctx, rawID)
	}
}

// BenchmarkSessionManager_CreateSession benchmarks session creation,
// called on every login.
func BenchmarkSessionManager_CreateSession(b *testing.B) {
	store := newMockStore()
	mgr := NewManager(store, SessionConfig{
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 24 * time.Hour,
		MaxConcurrent:   0, // unlimited for benchmark
	})

	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		_, _, _ = mgr.CreateSession(ctx, "bench-user", "", nil)
	}
}

// BenchmarkSessionManager_RefreshSession benchmarks session refresh (idle timeout sliding).
func BenchmarkSessionManager_RefreshSession(b *testing.B) {
	store := newMockStore()
	mgr := NewManager(store, SessionConfig{
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 24 * time.Hour,
		MaxConcurrent:   5,
	})

	rawID, _, err := mgr.CreateSession(context.Background(), "bench-user", "", nil)
	if err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		_, _ = mgr.RefreshSession(ctx, rawID)
	}
}

// BenchmarkHashID benchmarks the SHA-256 hash of a session ID,
// called on every session lookup.
func BenchmarkHashID(b *testing.B) {
	rawID := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	b.ResetTimer()
	for b.Loop() {
		_ = HashID(rawID)
	}
}
