// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package propagator

import (
	"context"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// BenchmarkSignedJWT_Encode benchmarks JWT creation (signing).
// This is called on every outgoing service-to-service request.
func BenchmarkSignedJWT_Encode(b *testing.B) {
	p, err := NewSignedJWTPropagator(SignedJWTConfig{
		Issuer:   "bench-issuer",
		Audience: "bench-audience",
		TTL:      30 * time.Second,
	})
	if err != nil {
		b.Fatal(err)
	}

	identity := &auth.Identity{
		SubjectID:  "user-123",
		AuthMethod: "password",
		AuthTime:   time.Now(),
		SessionID:  "sess-abc",
	}

	ctx := context.Background()

	// Warm up — first call generates the key.
	if _, err := p.Encode(ctx, identity); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Encode(ctx, identity)
	}
}

// BenchmarkSignedJWT_Decode benchmarks JWT verification (decoding).
// This is called on every incoming service-to-service request.
func BenchmarkSignedJWT_Decode(b *testing.B) {
	p, err := NewSignedJWTPropagator(SignedJWTConfig{
		Issuer:   "bench-issuer",
		Audience: "bench-audience",
		TTL:      30 * time.Second,
	})
	if err != nil {
		b.Fatal(err)
	}

	identity := &auth.Identity{
		SubjectID:  "user-123",
		AuthMethod: "password",
		AuthTime:   time.Now(),
		SessionID:  "sess-abc",
	}

	ctx := context.Background()
	headers, err := p.Encode(ctx, identity)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Decode(ctx, headers, nil)
	}
}

// BenchmarkSignedJWT_RoundTrip benchmarks a full encode→decode round trip.
func BenchmarkSignedJWT_RoundTrip(b *testing.B) {
	p, err := NewSignedJWTPropagator(SignedJWTConfig{
		Issuer:   "bench-issuer",
		Audience: "bench-audience",
		TTL:      30 * time.Second,
	})
	if err != nil {
		b.Fatal(err)
	}

	identity := &auth.Identity{
		SubjectID:  "user-123",
		AuthMethod: "password",
		AuthTime:   time.Now(),
		SessionID:  "sess-abc",
	}

	ctx := context.Background()

	// Warm up.
	if _, err := p.Encode(ctx, identity); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		headers, _ := p.Encode(ctx, identity)
		_, _ = p.Decode(ctx, headers, nil)
	}
}
