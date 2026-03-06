// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package propagator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
)

// ---------------------------------------------------------------
// helpers
// ---------------------------------------------------------------

func newTestPropagator(t *testing.T, opts ...func(*SignedJWTConfig)) *SignedJWTPropagator {
	t.Helper()
	cfg := SignedJWTConfig{
		Issuer:   "test-issuer",
		Audience: "test-audience",
		TTL:      30 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}
	p, err := NewSignedJWTPropagator(cfg)
	if err != nil {
		t.Fatalf("NewSignedJWTPropagator: %v", err)
	}
	return p
}

func testIdentity() *auth.Identity {
	return &auth.Identity{
		SubjectID:  "user-42",
		AuthMethod: "password",
		AuthTime:   time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Metadata:   make(map[string]any),
	}
}

// ---------------------------------------------------------------
// 1. NewSignedJWTPropagator validation
// ---------------------------------------------------------------

func TestNewSignedJWTPropagator_MissingIssuer(t *testing.T) {
	_, err := NewSignedJWTPropagator(SignedJWTConfig{Audience: "aud"})
	if err == nil {
		t.Fatal("expected error for missing Issuer")
	}
}

func TestNewSignedJWTPropagator_MissingAudience(t *testing.T) {
	_, err := NewSignedJWTPropagator(SignedJWTConfig{Issuer: "iss"})
	if err == nil {
		t.Fatal("expected error for missing Audience")
	}
}

// ---------------------------------------------------------------
// 2. Encode then Decode returns original identity (round-trip)
// ---------------------------------------------------------------

func TestSignedJWT_RoundTrip(t *testing.T) {
	p := newTestPropagator(t)
	ctx := context.Background()
	id := testIdentity()

	meta, err := p.Encode(ctx, id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := p.Decode(ctx, meta, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if decoded.SubjectID != id.SubjectID {
		t.Errorf("SubjectID = %q, want %q", decoded.SubjectID, id.SubjectID)
	}
	if decoded.AuthMethod != id.AuthMethod {
		t.Errorf("AuthMethod = %q, want %q", decoded.AuthMethod, id.AuthMethod)
	}
	if decoded.AuthTime.Unix() != id.AuthTime.Unix() {
		t.Errorf("AuthTime = %v, want %v", decoded.AuthTime, id.AuthTime)
	}
}

// ---------------------------------------------------------------
// 3. Produces a JWT in metadata
// ---------------------------------------------------------------

func TestSignedJWT_ProducesJWTInMetadata(t *testing.T) {
	p := newTestPropagator(t)
	meta, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	token, ok := meta[headerKeyJWT]
	if !ok {
		t.Fatal("expected JWT in metadata under x-auth-identity")
	}
	if token == "" {
		t.Fatal("expected non-empty JWT")
	}

	// JWT should have 3 dot-separated parts.
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected 2 dots in JWT, got %d", parts)
	}
}

// ---------------------------------------------------------------
// 4. Uses Ed25519 signing (EdDSA algorithm)
// ---------------------------------------------------------------

func TestSignedJWT_UsesEdDSA(t *testing.T) {
	p := newTestPropagator(t)
	meta, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	token := meta[headerKeyJWT]

	// Parse header to check algorithm.
	parts := splitJWT(t, token)
	var header jwtHeader
	if err := json.Unmarshal(parts.headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}

	if header.Alg != "EdDSA" {
		t.Errorf("Alg = %q, want EdDSA", header.Alg)
	}
	if header.Typ != "JWT" {
		t.Errorf("Typ = %q, want JWT", header.Typ)
	}
}

// ---------------------------------------------------------------
// 5. JWT expires in 30 seconds
// ---------------------------------------------------------------

func TestSignedJWT_ExpiresIn30Seconds(t *testing.T) {
	now := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	p := newTestPropagator(t, func(cfg *SignedJWTConfig) {
		cfg.NowFunc = func() time.Time { return now }
	})

	meta, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	claims := parseClaims(t, meta[headerKeyJWT])

	expectedExp := now.Add(30 * time.Second).Unix()
	if claims.Exp != expectedExp {
		t.Errorf("Exp = %d, want %d", claims.Exp, expectedExp)
	}
}

// ---------------------------------------------------------------
// 6. Expired JWT rejected
// ---------------------------------------------------------------

func TestSignedJWT_ExpiredRejected(t *testing.T) {
	now := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	current := now

	p := newTestPropagator(t, func(cfg *SignedJWTConfig) {
		cfg.NowFunc = func() time.Time { return current }
	})

	meta, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Advance time past expiry.
	current = now.Add(31 * time.Second)

	_, err = p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error for expired JWT")
	}
	if got := err.Error(); !containsStr(got, "expired") {
		t.Errorf("error = %q, want 'expired'", got)
	}
}

// ---------------------------------------------------------------
// 7. Wrong audience rejected
// ---------------------------------------------------------------

func TestSignedJWT_WrongAudienceRejected(t *testing.T) {
	p1 := newTestPropagator(t, func(cfg *SignedJWTConfig) {
		cfg.Audience = "service-a"
	})
	_ = newTestPropagator(t, func(cfg *SignedJWTConfig) {
		cfg.Audience = "service-b"
		cfg.Issuer = "test-issuer"
	})

	// Encode with audience "service-a".
	meta, err := p1.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decode with audience "service-b" — the JWT was signed by p1, p2 doesn't
	// have p1's keys. But the audience check would also fail.
	// We need to test audience check specifically, so share the key state.
	// Simpler: decode with p1 but change its audience after encoding.
	p1.mu.Lock()
	p1.audience = "different-audience"
	p1.mu.Unlock()

	_, err = p1.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
	if got := err.Error(); !containsStr(got, "audience") {
		t.Errorf("error = %q, want 'audience'", got)
	}
}

// ---------------------------------------------------------------
// 8. Wrong issuer rejected
// ---------------------------------------------------------------

func TestSignedJWT_WrongIssuerRejected(t *testing.T) {
	p := newTestPropagator(t)

	meta, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Change issuer after encoding.
	p.mu.Lock()
	p.issuer = "different-issuer"
	p.mu.Unlock()

	_, err = p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
	if got := err.Error(); !containsStr(got, "issuer") {
		t.Errorf("error = %q, want 'issuer'", got)
	}
}

// ---------------------------------------------------------------
// 9. JWT contains all required claims
// ---------------------------------------------------------------

func TestSignedJWT_ContainsAllClaims(t *testing.T) {
	now := time.Date(2025, 7, 1, 12, 0, 0, 0, time.UTC)
	p := newTestPropagator(t, func(cfg *SignedJWTConfig) {
		cfg.NowFunc = func() time.Time { return now }
	})

	id := testIdentity()
	meta, err := p.Encode(context.Background(), id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	claims := parseClaims(t, meta[headerKeyJWT])

	if claims.Sub != id.SubjectID {
		t.Errorf("sub = %q, want %q", claims.Sub, id.SubjectID)
	}
	if claims.Iss != "test-issuer" {
		t.Errorf("iss = %q, want %q", claims.Iss, "test-issuer")
	}
	if claims.Aud != "test-audience" {
		t.Errorf("aud = %q, want %q", claims.Aud, "test-audience")
	}
	if claims.Iat != now.Unix() {
		t.Errorf("iat = %d, want %d", claims.Iat, now.Unix())
	}
	if claims.Exp != now.Add(30*time.Second).Unix() {
		t.Errorf("exp = %d, want %d", claims.Exp, now.Add(30*time.Second).Unix())
	}
	if claims.AuthMethod != id.AuthMethod {
		t.Errorf("auth_method = %q, want %q", claims.AuthMethod, id.AuthMethod)
	}
	if claims.AuthTime != id.AuthTime.Unix() {
		t.Errorf("auth_time = %d, want %d", claims.AuthTime, id.AuthTime.Unix())
	}
}

// ---------------------------------------------------------------
// 10. Ed25519 keypair generated on first use
// ---------------------------------------------------------------

func TestSignedJWT_KeyGeneratedOnFirstUse(t *testing.T) {
	p := newTestPropagator(t)

	if p.KeyCount() != 0 {
		t.Fatalf("expected 0 keys before first Encode, got %d", p.KeyCount())
	}

	_, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if p.KeyCount() != 1 {
		t.Errorf("expected 1 key after first Encode, got %d", p.KeyCount())
	}
}

// ---------------------------------------------------------------
// 11. Key rotation: new key generated, old key accepted for overlap
// ---------------------------------------------------------------

func TestSignedJWT_KeyRotation(t *testing.T) {
	p := newTestPropagator(t)

	// Encode with initial key.
	meta1, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode 1: %v", err)
	}

	if p.KeyCount() != 1 {
		t.Fatalf("expected 1 key, got %d", p.KeyCount())
	}

	// Rotate.
	if err := p.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if p.KeyCount() != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", p.KeyCount())
	}

	// Old JWT should still be verifiable (overlap period).
	decoded, err := p.Decode(context.Background(), meta1, nil)
	if err != nil {
		t.Fatalf("Decode old JWT after rotation: %v", err)
	}
	if decoded.SubjectID != "user-42" {
		t.Errorf("SubjectID = %q, want %q", decoded.SubjectID, "user-42")
	}

	// New JWT should use the new key.
	meta2, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode 2: %v", err)
	}

	decoded2, err := p.Decode(context.Background(), meta2, nil)
	if err != nil {
		t.Fatalf("Decode new JWT: %v", err)
	}
	if decoded2.SubjectID != "user-42" {
		t.Errorf("SubjectID = %q, want %q", decoded2.SubjectID, "user-42")
	}
}

// ---------------------------------------------------------------
// 12. JWKS handler serves public key in correct format
// ---------------------------------------------------------------

func TestSignedJWT_JWKSHandler(t *testing.T) {
	p := newTestPropagator(t)

	// Generate a key by encoding.
	_, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	handler := p.JWKSHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/auth-keys", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var doc jwksDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}

	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(doc.Keys))
	}

	key := doc.Keys[0]
	if key.Kty != "OKP" {
		t.Errorf("kty = %q, want OKP", key.Kty)
	}
	if key.Crv != "Ed25519" {
		t.Errorf("crv = %q, want Ed25519", key.Crv)
	}
	if key.Alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("use = %q, want sig", key.Use)
	}
	if key.X == "" {
		t.Error("expected non-empty x (public key)")
	}
	if key.Kid == "" {
		t.Error("expected non-empty kid")
	}
}

// ---------------------------------------------------------------
// 13. JWKS contains both keys during overlap
// ---------------------------------------------------------------

func TestSignedJWT_JWKSOverlap(t *testing.T) {
	p := newTestPropagator(t)

	// Initial key.
	_, _ = p.Encode(context.Background(), testIdentity())

	// Rotate.
	_ = p.RotateKey()

	handler := p.JWKSHandler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var doc jwksDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}

	if len(doc.Keys) != 2 {
		t.Fatalf("expected 2 keys in JWKS during overlap, got %d", len(doc.Keys))
	}

	// Keys should have different KIDs.
	if doc.Keys[0].Kid == doc.Keys[1].Kid {
		t.Error("expected different KIDs for rotated keys")
	}
}

// ---------------------------------------------------------------
// 14. Tampered JWT rejected
// ---------------------------------------------------------------

func TestSignedJWT_TamperedRejected(t *testing.T) {
	p := newTestPropagator(t)
	meta, err := p.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	token := meta[headerKeyJWT]

	// Tamper with the payload (change a character).
	tampered := token[:len(token)/2] + "X" + token[len(token)/2+1:]

	_, err = p.Decode(context.Background(), map[string]string{headerKeyJWT: tampered}, nil)
	if err == nil {
		t.Fatal("expected error for tampered JWT")
	}
}

// ---------------------------------------------------------------
// 15. Satisfies IdentityPropagator interface
// ---------------------------------------------------------------

func TestSignedJWT_ImplementsInterface(t *testing.T) {
	p := newTestPropagator(t)
	var _ IdentityPropagator = p // compile-time check
}

// ---------------------------------------------------------------
// 16. Nil identity → error
// ---------------------------------------------------------------

func TestSignedJWT_NilIdentity(t *testing.T) {
	p := newTestPropagator(t)
	_, err := p.Encode(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

// ---------------------------------------------------------------
// 17. No token in metadata → error
// ---------------------------------------------------------------

func TestSignedJWT_NoTokenInMetadata(t *testing.T) {
	p := newTestPropagator(t)
	_, err := p.Decode(context.Background(), map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
}

// ---------------------------------------------------------------
// 18. Malformed JWT → error
// ---------------------------------------------------------------

func TestSignedJWT_MalformedJWT(t *testing.T) {
	p := newTestPropagator(t)

	tests := []struct {
		name  string
		token string
	}{
		{"no dots", "notajwt"},
		{"one dot", "header.payload"},
		{"invalid base64 header", "!!!.payload.sig"},
		{"invalid base64 claims", "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InRlc3QifQ.!!!.sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.Decode(context.Background(), map[string]string{headerKeyJWT: tt.token}, nil)
			if err == nil {
				t.Fatal("expected error for malformed JWT")
			}
		})
	}
}

// ---------------------------------------------------------------
// 19. Unsupported algorithm rejected
// ---------------------------------------------------------------

func TestSignedJWT_UnsupportedAlgorithm(t *testing.T) {
	p := newTestPropagator(t)

	// Craft a JWT with wrong algorithm.
	header := `{"alg":"HS256","typ":"JWT","kid":"test"}`
	claims := `{"sub":"user","iss":"test-issuer","aud":"test-audience","iat":0,"exp":9999999999}`

	headerB64 := base64URLEncode([]byte(header))
	claimsB64 := base64URLEncode([]byte(claims))
	token := headerB64 + "." + claimsB64 + ".fakesig"

	_, err := p.Decode(context.Background(), map[string]string{headerKeyJWT: token}, nil)
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if got := err.Error(); !containsStr(got, "unsupported algorithm") {
		t.Errorf("error = %q, want 'unsupported algorithm'", got)
	}
}

// ---------------------------------------------------------------
// 20. Default TTL is 30 seconds
// ---------------------------------------------------------------

func TestSignedJWT_DefaultTTL(t *testing.T) {
	cfg := SignedJWTConfig{
		Issuer:   "iss",
		Audience: "aud",
	}
	p, err := NewSignedJWTPropagator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.ttl != 30*time.Second {
		t.Errorf("default TTL = %v, want 30s", p.ttl)
	}
}

// ---------------------------------------------------------------
// 21. Default overlap period is 2× TTL
// ---------------------------------------------------------------

func TestSignedJWT_DefaultOverlapPeriod(t *testing.T) {
	cfg := SignedJWTConfig{
		Issuer:   "iss",
		Audience: "aud",
		TTL:      10 * time.Second,
	}
	p, err := NewSignedJWTPropagator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.keyOverlapPeriod != 20*time.Second {
		t.Errorf("default overlap = %v, want 20s", p.keyOverlapPeriod)
	}
}

// ---------------------------------------------------------------
// 22. JWT from different propagator (unknown key) → verification failed
// ---------------------------------------------------------------

func TestSignedJWT_UnknownKeyRejected(t *testing.T) {
	p1 := newTestPropagator(t)
	p2 := newTestPropagator(t, func(cfg *SignedJWTConfig) {
		cfg.Issuer = "test-issuer"
		cfg.Audience = "test-audience"
	})

	// Encode with p1.
	meta, err := p1.Encode(context.Background(), testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decode with p2 — different key.
	_, err = p2.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if got := err.Error(); !containsStr(got, "verification failed") {
		t.Errorf("error = %q, want 'verification failed'", got)
	}
}

// ---------------------------------------------------------------
// 23. Invalid JWT signature encoding → error
// ---------------------------------------------------------------

func TestSignedJWT_InvalidSigEncoding(t *testing.T) {
	p := newTestPropagator(t)

	// Craft JWT with valid header and claims but bad base64 signature.
	header := `{"alg":"EdDSA","typ":"JWT","kid":"test"}`
	claims := `{"sub":"user","iss":"test-issuer","aud":"test-audience","iat":0,"exp":9999999999,"auth_method":"password","auth_time":0,"kid":"test"}`

	headerB64 := base64URLEncode([]byte(header))
	claimsB64 := base64URLEncode([]byte(claims))
	token := headerB64 + "." + claimsB64 + ".!!invalid-base64!!"

	_, err := p.Decode(context.Background(), map[string]string{headerKeyJWT: token}, nil)
	if err == nil {
		t.Fatal("expected error for invalid signature encoding")
	}
}

// ---------------------------------------------------------------
// 24. Invalid JWT header JSON → error
// ---------------------------------------------------------------

func TestSignedJWT_InvalidHeaderJSON(t *testing.T) {
	p := newTestPropagator(t)

	// Valid base64, but invalid JSON.
	headerB64 := base64URLEncode([]byte(`{not valid json`))
	claimsB64 := base64URLEncode([]byte(`{"sub":"user"}`))
	token := headerB64 + "." + claimsB64 + ".fakesig"

	_, err := p.Decode(context.Background(), map[string]string{headerKeyJWT: token}, nil)
	if err == nil {
		t.Fatal("expected error for invalid header JSON")
	}
}

// ---------------------------------------------------------------
// 25. Invalid JWT claims JSON → error
// ---------------------------------------------------------------

func TestSignedJWT_InvalidClaimsJSON(t *testing.T) {
	p := newTestPropagator(t)

	headerB64 := base64URLEncode([]byte(`{"alg":"EdDSA","typ":"JWT","kid":"test"}`))
	claimsB64 := base64URLEncode([]byte(`{not valid json`))
	sigB64 := base64URLEncode([]byte("fakesig"))
	token := headerB64 + "." + claimsB64 + "." + sigB64

	_, err := p.Decode(context.Background(), map[string]string{headerKeyJWT: token}, nil)
	if err == nil {
		t.Fatal("expected error for invalid claims JSON")
	}
}

// ---------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------

type jwtParts struct {
	headerJSON []byte
	claimsJSON []byte
	sig        []byte
}

func splitJWT(t *testing.T, token string) jwtParts {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	c, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	s, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	return jwtParts{headerJSON: h, claimsJSON: c, sig: s}
}

func parseClaims(t *testing.T, token string) jwtClaims {
	t.Helper()
	parts := splitJWT(t, token)
	var claims jwtClaims
	if err := json.Unmarshal(parts.claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// ---------------------------------------------------------------
// InMemoryKeyStore — test double for KeyStore
// ---------------------------------------------------------------

type inMemoryKeyStore struct {
	mu      sync.Mutex
	records []KeyRecord
}

func (s *inMemoryKeyStore) SaveKeys(_ context.Context, keys []KeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make([]KeyRecord, len(keys))
	copy(s.records, keys)
	return nil
}

func (s *inMemoryKeyStore) LoadKeys(_ context.Context) ([]KeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		return nil, nil
	}
	out := make([]KeyRecord, len(s.records))
	copy(out, s.records)
	return out, nil
}

// ---------------------------------------------------------------
// Key Persistence Tests
// ---------------------------------------------------------------

func TestKeyPersistence_SurvivesRestart(t *testing.T) {
	store := &inMemoryKeyStore{}
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	// Propagator #1: generate key + encode.
	p1 := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	id := testIdentity()
	ctx := context.Background()

	hdr, err := p1.Encode(ctx, id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Propagator #2: simulate restart — new instance, same store.
	p2 := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	got, err := p2.Decode(ctx, hdr, nil)
	if err != nil {
		t.Fatalf("Decode after restart: %v", err)
	}
	if got.SubjectID != id.SubjectID {
		t.Errorf("SubjectID = %q, want %q", got.SubjectID, id.SubjectID)
	}
}

func TestKeyPersistence_RotatedKeysPersistedAndRestored(t *testing.T) {
	store := &inMemoryKeyStore{}
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p1 := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	ctx := context.Background()

	// Encode with first key.
	hdr1, err := p1.Encode(ctx, testIdentity())
	if err != nil {
		t.Fatalf("Encode pre-rotate: %v", err)
	}

	// Rotate — now two keys.
	if err := p1.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Encode with new key.
	hdr2, err := p1.Encode(ctx, testIdentity())
	if err != nil {
		t.Fatalf("Encode post-rotate: %v", err)
	}

	// Simulate restart — new propagator, same store.
	p2 := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	// Both tokens must decode on the restarted instance.
	if _, err := p2.Decode(ctx, hdr1, nil); err != nil {
		t.Errorf("Decode pre-rotate token after restart: %v", err)
	}
	if _, err := p2.Decode(ctx, hdr2, nil); err != nil {
		t.Errorf("Decode post-rotate token after restart: %v", err)
	}

	// The restarted propagator should have both keys.
	if p2.KeyCount() != 2 {
		t.Errorf("KeyCount = %d, want 2", p2.KeyCount())
	}
}

func TestKeyPersistence_NilKeyStore_InMemoryOnly(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p1 := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.NowFunc = func() time.Time { return now }
	})

	ctx := context.Background()
	hdr, err := p1.Encode(ctx, testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// New propagator without store — cannot decode (no shared keys).
	p2 := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.NowFunc = func() time.Time { return now }
	})

	_, err = p2.Decode(ctx, hdr, nil)
	if err == nil {
		t.Error("expected Decode to fail on fresh in-memory propagator")
	}
}

func TestKeyPersistence_EmptyStore_GeneratesNewKey(t *testing.T) {
	store := &inMemoryKeyStore{} // empty — no prior keys
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	ctx := context.Background()
	_, err := p.Encode(ctx, testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Store should now have the key.
	records, err := store.LoadKeys(ctx)
	if err != nil {
		t.Fatalf("LoadKeys: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("store key count = %d, want 1", len(records))
	}
}

// ---------------------------------------------------------------
// Concurrent Encode/Decode Stress Test
// ---------------------------------------------------------------

func TestSignedJWT_ConcurrentEncodeDecode(t *testing.T) {
	store := &inMemoryKeyStore{}
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	const goroutines = 20
	const opsPerGoroutine = 50

	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*opsPerGoroutine)

	// Half goroutines encode, half decode.
	// A few goroutines also rotate keys mid-flight.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				// Every 10th op in goroutine 0: rotate.
				if id == 0 && j%10 == 0 {
					if err := p.RotateKey(); err != nil {
						errs <- err
						return
					}
				}

				// Encode.
				identity := &auth.Identity{
					SubjectID:  "concurrent-user",
					AuthMethod: "password",
					AuthTime:   now,
					Metadata:   make(map[string]any),
				}
				hdr, err := p.Encode(ctx, identity)
				if err != nil {
					errs <- err
					return
				}

				// Decode.
				got, err := p.Decode(ctx, hdr, nil)
				if err != nil {
					errs <- err
					return
				}
				if got.SubjectID != "concurrent-user" {
					errs <- err
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent error: %v", err)
	}
}

// ---------------------------------------------------------------
// Failing KeyStore tests
// ---------------------------------------------------------------

type failingKeyStore struct {
	loadErr error
	saveErr error
}

func (f *failingKeyStore) SaveKeys(_ context.Context, _ []KeyRecord) error { return f.saveErr }
func (f *failingKeyStore) LoadKeys(_ context.Context) ([]KeyRecord, error) { return nil, f.loadErr }

func TestKeyPersistence_RotateKeyPersistError(t *testing.T) {
	store := &failingKeyStore{saveErr: errors.New("disk full")}
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	// Force a key to exist first (currentKey will best-effort persist, which fails silently).
	ctx := context.Background()
	if _, err := p.Encode(ctx, testIdentity()); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// RotateKey should propagate the persist error.
	err := p.RotateKey()
	if err == nil {
		t.Fatal("expected RotateKey to fail when KeyStore.SaveKeys fails")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Errorf("error = %q, want it to contain 'disk full'", err)
	}
}

func TestKeyPersistence_LoadError_IgnoredOnStartup(t *testing.T) {
	// LoadKeys fails — propagator should still start, generating a fresh key.
	store := &failingKeyStore{loadErr: errors.New("store unavailable")}
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	p := newTestPropagator(t, func(c *SignedJWTConfig) {
		c.KeyStore = store
		c.NowFunc = func() time.Time { return now }
	})

	ctx := context.Background()
	hdr, err := p.Encode(ctx, testIdentity())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Should still decode with the in-memory key.
	got, err := p.Decode(ctx, hdr, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.SubjectID != "user-42" {
		t.Errorf("SubjectID = %q, want %q", got.SubjectID, "user-42")
	}
}
