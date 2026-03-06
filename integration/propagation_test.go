// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
	"github.com/abhipray-cpu/auth/session/redis"
	goredis "github.com/redis/go-redis/v9"
)

// --------------------------------------------------------------------------
// AUTH-0027 AC: HTTP → gRPC with SignedJWTPropagator: identity propagated
// --------------------------------------------------------------------------

// memKeyStore is a thread-safe in-memory KeyStore for sharing signing keys
// between multiple SignedJWTPropagator instances in tests.
type memKeyStore struct {
	mu   sync.Mutex
	keys []propagator.KeyRecord
}

func (s *memKeyStore) SaveKeys(_ context.Context, keys []propagator.KeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = make([]propagator.KeyRecord, len(keys))
	copy(s.keys, keys)
	return nil
}

func (s *memKeyStore) LoadKeys(_ context.Context) ([]propagator.KeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]propagator.KeyRecord, len(s.keys))
	copy(out, s.keys)
	return out, nil
}

var _ propagator.KeyStore = (*memKeyStore)(nil)

func TestSignedJWTPropagatorRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "auth-service",
		Audience: "downstream-service",
		TTL:      30 * time.Second,
	})
	assertNoError(t, err, "NewSignedJWTPropagator")

	ctx := context.Background()

	// Encode an identity.
	identity := &auth.Identity{
		SubjectID:  "user-123",
		AuthMethod: "password",
		AuthTime:   time.Now(),
		SessionID:  "session-abc",
	}

	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	if len(headers) == 0 {
		t.Fatal("Encode returned empty headers")
	}
	jwtToken, ok := headers["x-auth-identity"]
	if !ok || jwtToken == "" {
		t.Fatal("expected x-auth-identity header in encoded metadata")
	}

	// Verify JWT has 3 parts.
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT with 3 parts, got %d", len(parts))
	}

	// Decode on the receiving end.
	decoded, err := prop.Decode(ctx, headers, nil)
	assertNoError(t, err, "Decode")

	if decoded.SubjectID != "user-123" {
		t.Fatalf("decoded SubjectID: expected user-123, got %q", decoded.SubjectID)
	}
	if decoded.AuthMethod != "password" {
		t.Fatalf("decoded AuthMethod: expected password, got %q", decoded.AuthMethod)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: HTTP → gRPC with SessionPropagator: identity propagated
// --------------------------------------------------------------------------

func TestSessionPropagatorRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)

	// Create session store.
	store := redis.NewStore(redis.Config{
		Client:    client,
		KeyPrefix: "proptest:",
	})

	ctx := context.Background()

	// Create a session in the store.
	sess := &session.Session{
		ID:            session.HashID("raw-session-for-propagation"),
		SubjectID:     "propagated-user",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		LastActiveAt:  time.Now(),
		SchemaVersion: session.SchemaVersion,
		Metadata:      map[string]any{},
	}
	err := store.Create(ctx, sess)
	assertNoError(t, err, "Create session")

	// Create session propagator.
	prop, err := propagator.NewSessionPropagator(propagator.SessionPropagatorConfig{
		Store: store,
	})
	assertNoError(t, err, "NewSessionPropagator")

	// Encode.
	identity := &auth.Identity{
		SubjectID: "propagated-user",
		SessionID: sess.ID,
	}
	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	sessionID, ok := headers["x-auth-session-id"]
	if !ok || sessionID == "" {
		t.Fatal("expected x-auth-session-id in headers")
	}

	// Decode.
	decoded, err := prop.Decode(ctx, headers, nil)
	assertNoError(t, err, "Decode")

	if decoded.SubjectID != "propagated-user" {
		t.Fatalf("decoded SubjectID: expected propagated-user, got %q", decoded.SubjectID)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: HTTP → gRPC with SPIFFEPropagator (mock): identity propagated
// --------------------------------------------------------------------------

func TestSPIFFEPropagatorRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	mockClient := &mockWorkloadAPIClient{
		svid:     "eyJ.mock.svid",
		spiffeID: "spiffe://acme.com/service-a",
	}

	prop, err := propagator.NewSPIFFEPropagator(propagator.SPIFFEPropagatorConfig{
		Client:   mockClient,
		Audience: "downstream",
	})
	assertNoError(t, err, "NewSPIFFEPropagator")

	ctx := context.Background()

	identity := &auth.Identity{
		SubjectID:  "",
		AuthMethod: "spiffe",
		WorkloadID: "spiffe://acme.com/service-a",
	}

	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	svidToken, ok := headers["x-auth-spiffe-svid"]
	if !ok || svidToken == "" {
		t.Fatal("expected x-auth-spiffe-svid in headers")
	}

	decoded, err := prop.Decode(ctx, headers, nil)
	assertNoError(t, err, "Decode")

	if decoded.WorkloadID != "spiffe://acme.com/service-a" {
		t.Fatalf("decoded WorkloadID: expected spiffe://acme.com/service-a, got %q", decoded.WorkloadID)
	}
	if decoded.AuthMethod != "spiffe" {
		t.Fatalf("decoded AuthMethod: expected spiffe, got %q", decoded.AuthMethod)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: Dual identity (user + workload) in downstream context
// --------------------------------------------------------------------------

func TestDualIdentityInContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Set user identity.
	userID := &auth.Identity{
		SubjectID:  "user-456",
		AuthMethod: "oauth2",
		AuthTime:   time.Now(),
	}
	ctx = auth.SetIdentity(ctx, userID)

	// Set workload identity.
	wid := &auth.WorkloadIdentity{
		WorkloadID:  "spiffe://acme.com/frontend",
		TrustDomain: "acme.com",
		Metadata:    map[string]any{"cert_serial": "12345"},
	}
	ctx = auth.SetWorkloadIdentity(ctx, wid)

	// Both should be retrievable.
	gotUser := auth.GetIdentity(ctx)
	if gotUser == nil {
		t.Fatal("user identity not in context")
	}
	if gotUser.SubjectID != "user-456" {
		t.Fatalf("expected user-456, got %q", gotUser.SubjectID)
	}

	gotWorkload := auth.GetWorkloadIdentity(ctx)
	if gotWorkload == nil {
		t.Fatal("workload identity not in context")
	}
	if gotWorkload.WorkloadID != "spiffe://acme.com/frontend" {
		t.Fatalf("expected spiffe://acme.com/frontend, got %q", gotWorkload.WorkloadID)
	}
	if gotWorkload.TrustDomain != "acme.com" {
		t.Fatalf("expected trust domain acme.com, got %q", gotWorkload.TrustDomain)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: 30s JWT expired → rejected
// --------------------------------------------------------------------------

func TestSignedJWTExpiredRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	nowTime := time.Now().Add(-1 * time.Minute) // start in the past
	mu := sync.Mutex{}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "auth-service",
		Audience: "downstream",
		TTL:      5 * time.Second,
		NowFunc: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return nowTime
		},
	})
	assertNoError(t, err, "NewSignedJWTPropagator")

	ctx := context.Background()

	identity := &auth.Identity{
		SubjectID:  "user-exp",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	// Encode at t=-60s.
	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	// Advance clock past expiry.
	mu.Lock()
	nowTime = time.Now().Add(2 * time.Minute) // well past 5s TTL
	mu.Unlock()

	// Decode should reject.
	_, err = prop.Decode(ctx, headers, nil)
	if err == nil {
		t.Fatal("SECURITY: expired JWT was accepted")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: Audience mismatch → rejected
// --------------------------------------------------------------------------

func TestSignedJWTAudienceMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Use a shared KeyStore so both propagators have the same signing key.
	// The encoder generates its key lazily on first Encode, so we must
	// Encode first, THEN create the decoder so it loads the encoder's key.
	sharedKeyStore := &memKeyStore{}

	// Encoder with audience "service-a".
	encoder, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "auth-service",
		Audience: "service-a",
		TTL:      30 * time.Second,
		KeyStore: sharedKeyStore,
	})
	assertNoError(t, err, "NewSignedJWTPropagator (encoder)")

	ctx := context.Background()

	identity := &auth.Identity{
		SubjectID:  "user-aud",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	// Encode first — this generates + persists the signing key.
	headers, err := encoder.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	// NOW create the decoder — it loads the encoder's key from the store.
	decoder, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "auth-service",
		Audience: "service-b",
		TTL:      30 * time.Second,
		KeyStore: sharedKeyStore,
	})
	assertNoError(t, err, "NewSignedJWTPropagator (decoder)")

	// Decode with wrong audience should reject.
	_, err = decoder.Decode(ctx, headers, nil)
	if err == nil {
		t.Fatal("SECURITY: audience mismatch was accepted")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: Key rotation: old key accepted during overlap
// --------------------------------------------------------------------------

func TestSignedJWTKeyRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:           "auth-service",
		Audience:         "downstream",
		TTL:              30 * time.Second,
		KeyOverlapPeriod: 5 * time.Minute, // long overlap for test
	})
	assertNoError(t, err, "NewSignedJWTPropagator")

	ctx := context.Background()

	identity := &auth.Identity{
		SubjectID:  "user-rotate",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	// Encode with the initial key.
	headers1, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode before rotation")

	keyCountBefore := prop.KeyCount()

	// Rotate key.
	err = prop.RotateKey()
	assertNoError(t, err, "RotateKey")

	keyCountAfter := prop.KeyCount()
	if keyCountAfter <= keyCountBefore {
		t.Fatalf("expected more keys after rotation: before=%d, after=%d", keyCountBefore, keyCountAfter)
	}

	// Encode with the NEW key.
	headers2, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode after rotation")

	// Both tokens should be different (different keys).
	if headers1["x-auth-identity"] == headers2["x-auth-identity"] {
		t.Fatal("expected different tokens after key rotation")
	}

	// STRICT: Old token MUST still verify during overlap period.
	decoded1, err := prop.Decode(ctx, headers1, nil)
	assertNoError(t, err, "Decode old token during overlap")
	if decoded1.SubjectID != "user-rotate" {
		t.Fatalf("old token decoded wrong SubjectID: %q", decoded1.SubjectID)
	}

	// New token should also verify.
	decoded2, err := prop.Decode(ctx, headers2, nil)
	assertNoError(t, err, "Decode new token")
	if decoded2.SubjectID != "user-rotate" {
		t.Fatalf("new token decoded wrong SubjectID: %q", decoded2.SubjectID)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: Revoked session instantly rejected (SessionPropagator)
// --------------------------------------------------------------------------

func TestSessionPropagatorRevokedSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)

	store := redis.NewStore(redis.Config{
		Client:    client,
		KeyPrefix: "revprop:",
	})

	ctx := context.Background()

	// Create a session.
	hashedID := session.HashID("revocable-session")
	sess := &session.Session{
		ID:            hashedID,
		SubjectID:     "revocable-user",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
		LastActiveAt:  time.Now(),
		SchemaVersion: session.SchemaVersion,
		Metadata:      map[string]any{},
	}
	err := store.Create(ctx, sess)
	assertNoError(t, err, "Create session")

	prop, err := propagator.NewSessionPropagator(propagator.SessionPropagatorConfig{
		Store: store,
	})
	assertNoError(t, err, "NewSessionPropagator")

	identity := &auth.Identity{
		SubjectID: "revocable-user",
		SessionID: hashedID,
	}

	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	// Decode should work before revocation.
	decoded, err := prop.Decode(ctx, headers, nil)
	assertNoError(t, err, "Decode before revocation")
	if decoded.SubjectID != "revocable-user" {
		t.Fatalf("expected revocable-user, got %q", decoded.SubjectID)
	}

	// Revoke (delete) the session.
	err = store.Delete(ctx, hashedID)
	assertNoError(t, err, "Delete session")

	// Decode should IMMEDIATELY fail.
	_, err = prop.Decode(ctx, headers, nil)
	if err == nil {
		t.Fatal("SECURITY: revoked session was accepted by SessionPropagator — instant revocation failed")
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: S2S context has WorkloadIdentity but no UserIdentity
// --------------------------------------------------------------------------

func TestS2SContextWorkloadOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Set only workload identity (service-to-service).
	wid := &auth.WorkloadIdentity{
		WorkloadID:  "spiffe://acme.com/backend-service",
		TrustDomain: "acme.com",
	}
	ctx = auth.SetWorkloadIdentity(ctx, wid)

	// User identity should be nil.
	userID := auth.GetIdentity(ctx)
	if userID != nil {
		t.Fatal("S2S context should NOT have user identity")
	}

	// Workload identity should be present.
	gotWID := auth.GetWorkloadIdentity(ctx)
	if gotWID == nil {
		t.Fatal("S2S context should have workload identity")
	}
	if gotWID.WorkloadID != "spiffe://acme.com/backend-service" {
		t.Fatalf("expected spiffe://acme.com/backend-service, got %q", gotWID.WorkloadID)
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: JWKS endpoint serves public key
// AUTH-0027 AC: JWKS endpoint accessible via HTTP
// --------------------------------------------------------------------------

func TestJWKSEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "jwks:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithSignedJWTPropagator(propagator.SignedJWTConfig{
			Issuer:   "auth-service",
			Audience: "downstream",
			TTL:      30 * time.Second,
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	if a.JWKSHandler == nil {
		t.Fatal("JWKSHandler is nil — JWKS endpoint not available")
	}

	// Trigger key generation by encoding an identity.
	ctx := context.Background()
	if a.Propagator != nil {
		identity := &auth.Identity{
			SubjectID:  "jwks-test-user",
			AuthMethod: "password",
			AuthTime:   time.Now(),
		}
		_, err = a.Propagator.Encode(ctx, identity)
		assertNoError(t, err, "Encode to trigger key generation")
	}

	// Serve the JWKS endpoint.
	srv := httptest.NewServer(a.JWKSHandler)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	assertNoError(t, err, "GET JWKS endpoint")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("JWKS endpoint Content-Type: expected application/json, got %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	assertNoError(t, err, "read JWKS body")

	// Parse JWKS.
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Use string `json:"use"`
			Alg string `json:"alg"`
		} `json:"keys"`
	}
	err = json.Unmarshal(body, &jwks)
	assertNoError(t, err, "parse JWKS JSON")

	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS endpoint returned no keys")
	}

	key := jwks.Keys[0]
	if key.Kty != "OKP" {
		t.Fatalf("expected key type OKP (Ed25519), got %q", key.Kty)
	}
	if key.Crv != "Ed25519" {
		t.Fatalf("expected curve Ed25519, got %q", key.Crv)
	}
	if key.Alg != "EdDSA" {
		t.Fatalf("expected algorithm EdDSA, got %q", key.Alg)
	}
	if key.Use != "sig" {
		t.Fatalf("expected use sig, got %q", key.Use)
	}
	if key.Kid == "" {
		t.Fatal("key ID is empty")
	}
	if key.X == "" {
		t.Fatal("public key X is empty")
	}
}

// --------------------------------------------------------------------------
// AUTH-0027 AC: HTTP identity propagation end-to-end
// (Simulates HTTP middleware → downstream with signed JWT)
// --------------------------------------------------------------------------

func TestHTTPPropagationEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "frontend",
		Audience: "backend",
		TTL:      30 * time.Second,
	})
	assertNoError(t, err, "NewSignedJWTPropagator")

	identity := &auth.Identity{
		SubjectID:  "http-user",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	// Upstream: encode identity into HTTP headers.
	ctx := context.Background()
	headers, err := prop.Encode(ctx, identity)
	assertNoError(t, err, "Encode")

	// Downstream: simulate receiving the request with identity headers.
	// Create an HTTP request with the propagated headers.
	req := httptest.NewRequest("GET", "/downstream", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// On the downstream side, extract headers and decode.
	metadata := make(map[string]string)
	for k, vals := range req.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-auth-") && len(vals) > 0 {
			metadata[lk] = vals[0]
		}
	}

	decoded, err := prop.Decode(ctx, metadata, nil)
	assertNoError(t, err, "Decode from HTTP headers")

	if decoded.SubjectID != "http-user" {
		t.Fatalf("expected http-user, got %q", decoded.SubjectID)
	}
}

// --------------------------------------------------------------------------
// Mock WorkloadAPIClient for SPIFFE tests
// --------------------------------------------------------------------------

type mockWorkloadAPIClient struct {
	svid     string
	spiffeID string
}

func (m *mockWorkloadAPIClient) FetchJWTSVID(_ context.Context, _ string) (string, error) {
	return m.svid, nil
}

func (m *mockWorkloadAPIClient) ValidateJWTSVID(_ context.Context, _ string, _ string) (string, error) {
	return m.spiffeID, nil
}

var _ propagator.WorkloadAPIClient = (*mockWorkloadAPIClient)(nil)

// Suppress unused import warning for goredis (used via startRedis).
var _ = (*goredis.Client)(nil)
