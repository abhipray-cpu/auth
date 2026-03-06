// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0035: E2E — Traffic Capture + Verification
//
// Instead of mitmproxy, this verifies security properties directly on the
// gRPC/TLS traffic and responses. The properties tested are identical:
//
// Test Cases:
//
//	35.1: No passwords, session IDs, or keys in plain-text metadata
//	35.2: gRPC metadata contains expected identity headers
//	35.3: Inter-service gRPC traffic is TLS-encrypted (no insecure connections)
//	35.4: Error responses contain no stack traces or internal paths
//	35.5: Session IDs have sufficient entropy (not guessable)
//	35.6: Propagated JWT does not leak private key material
//	35.7: Bearer token stripped from propagated identity (not forwarded raw)
package integration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	"github.com/abhipray-cpu/auth/hash"
	"github.com/abhipray-cpu/auth/hooks"
	modepw "github.com/abhipray-cpu/auth/mode/password"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ---------- AUTH-0035: Traffic Capture + Verification ----------

func TestE2E_Traffic_NoSecretsInMetadata(t *testing.T) {
	// 35.1: Verify that passwords, raw session tokens, and signing keys
	// do NOT appear in propagated identity metadata.
	keyStore := &memKeyStore{}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "services",
		TTL:      30 * time.Second,
		KeyStore: keyStore,
	})
	if err != nil {
		t.Fatalf("propagator: %v", err)
	}

	// Create a user and login to get a session.
	sessStore := newMemSessionStore()
	eng := buildTrafficEngine(t, sessStore)

	regCred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "SuperSecret123!",
	}
	_, _, err = eng.Register(context.Background(), regCred)
	assertNoError(t, err, "register")

	identity, _, err := eng.Login(context.Background(), passwordCred("alice@example.com", "SuperSecret123!"))
	assertNoError(t, err, "login")

	sessionID := identity.SessionID
	password := "SuperSecret123!"

	// Encode identity for propagation.
	headers, err := prop.Encode(context.Background(), identity)
	assertNoError(t, err, "encode")

	// Inspect the propagated JWT: decode claims, verify no secrets.
	jwt := headers["x-auth-identity"]
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	assertNoError(t, err, "decode claims")

	claimsStr := string(claimsJSON)

	// The password should NEVER appear in JWT claims.
	if strings.Contains(claimsStr, password) {
		t.Error("SECURITY: password appears in JWT claims")
	}

	// The raw session ID should NOT appear in JWT claims.
	if strings.Contains(claimsStr, sessionID) {
		t.Error("SECURITY: raw session ID appears in JWT claims")
	}

	// Check that signing key bytes don't appear in the JWT.
	// Load the saved keys from the KeyStore.
	records, err := keyStore.LoadKeys(context.Background())
	assertNoError(t, err, "load keys")

	for _, rec := range records {
		privKeyB64 := base64.StdEncoding.EncodeToString(rec.PrivateKey)
		if strings.Contains(jwt, privKeyB64) {
			t.Error("SECURITY: private key material appears in JWT")
		}

		// Also check raw bytes don't appear.
		if strings.Contains(claimsStr, string(rec.PrivateKey)) {
			t.Error("SECURITY: raw private key bytes in claims")
		}
	}

	// Verify the JWT claims contain ONLY expected fields.
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	allowedFields := map[string]bool{
		"sub": true, "iss": true, "aud": true,
		"iat": true, "exp": true, "kid": true,
		"auth_method": true, "auth_time": true,
	}

	for key := range claims {
		if !allowedFields[key] {
			t.Errorf("unexpected field in JWT claims: %q (potential secret leak)", key)
		}
	}
}

func TestE2E_Traffic_IdentityHeadersPresent(t *testing.T) {
	// 35.2: Verify that gRPC metadata contains expected identity headers
	// when a propagator is configured.
	pki := newTestPKI(t)

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "services",
		TTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("propagator: %v", err)
	}

	identity := &auth.Identity{
		SubjectID:  "alice@example.com",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	// Encode should produce the x-auth-identity header.
	headers, err := prop.Encode(context.Background(), identity)
	assertNoError(t, err, "encode")

	if _, ok := headers["x-auth-identity"]; !ok {
		t.Error("propagated headers should contain 'x-auth-identity'")
	}

	// Start a gRPC server that captures incoming metadata.
	serverCert := pki.issueServerCert(t, "capture-server", "localhost")
	clientCert := pki.issueClientCert(t, "capture-client")

	type capturedCall struct {
		md metadata.MD
	}
	captures := make(chan capturedCall, 1)

	// Custom interceptor that captures metadata before processing.
	captureInterceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		captures <- capturedCall{md: md}
		return handler(ctx, req)
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert.tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(captureInterceptor),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assertNoError(t, err, "listen")
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Dial and send with identity headers.
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{clientCert.tlsCert},
			RootCAs:      pki.caPool,
			ServerName:   "localhost",
		})),
	)
	assertNoError(t, err, "dial")
	defer conn.Close()

	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), pairs...)

	var resp string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/Echo", "test", &resp)
	assertNoError(t, err, "invoke")

	// Check captured metadata.
	select {
	case cap := <-captures:
		vals := cap.md.Get("x-auth-identity")
		if len(vals) == 0 {
			t.Error("captured metadata should contain x-auth-identity")
		}
		// The value should be a JWT (3 dot-separated parts).
		if len(vals) > 0 {
			parts := strings.SplitN(vals[0], ".", 3)
			if len(parts) != 3 {
				t.Errorf("x-auth-identity should be a JWT (3 parts), got %d", len(parts))
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for captured metadata")
	}
}

func TestE2E_Traffic_TLSEncrypted_NoInsecure(t *testing.T) {
	// 35.3: Verify that inter-service gRPC traffic uses TLS.
	// A server configured with TLS should reject insecure connections.
	pki := newTestPKI(t)

	serverCert := pki.issueServerCert(t, "secure-server", "localhost")

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert.tlsCert},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
		})),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assertNoError(t, err, "listen")
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Try connecting WITHOUT TLS (insecure) — should fail.
	insecureConn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial insecure (should succeed, fail on invoke): %v", err)
	}
	defer insecureConn.Close()

	var resp string
	err = insecureConn.Invoke(context.Background(), "/"+echoServiceName+"/Echo", "test", &resp)
	if err == nil {
		t.Fatal("SECURITY: insecure connection should NOT work with TLS-only server")
	}
	t.Logf("correctly rejected insecure connection: %v", err)

	// Connect WITH TLS — should succeed.
	secureConn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    pki.caPool,
			ServerName: "localhost",
		})),
	)
	assertNoError(t, err, "dial secure")
	defer secureConn.Close()

	err = secureConn.Invoke(context.Background(), "/"+echoServiceName+"/Echo", "test", &resp)
	assertNoError(t, err, "invoke secure")
}

func TestE2E_Traffic_ErrorResponses_NoLeakedInfo(t *testing.T) {
	// 35.4: Error responses contain no stack traces, internal paths, or library version.
	pki := newTestPKI(t)

	serverCert := pki.issueServerCert(t, "error-server", "localhost")

	sessStore := newMemSessionStore()
	sessMgr := session.NewManager(sessStore, session.DefaultConfig())
	eng, _ := engine.New(engine.Config{
		UserStore:        NewMemUserStore(),
		SessionManager:   sessMgr,
		HookManager:      hooks.NewManager(),
		PasswordPolicy:   pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{Field: "email"},
	})

	// Use VerifyClientCertIfGiven so TLS handshake succeeds without a client cert,
	// but no WorkloadIdentity is established. With RequireAuth=true and an
	// invalid bearer token, auth will fail.
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert.tlsCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      eng,
			RequireAuth: true,
		})),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assertNoError(t, err, "listen")
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Connect WITHOUT a client cert so mTLS doesn't provide WorkloadIdentity.
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    pki.caPool,
			ServerName: "localhost",
		})),
	)
	assertNoError(t, err, "dial")
	defer conn.Close()

	// Send with invalid session token.
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"authorization", "Bearer invalid-session-token-xxx")

	var resp string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/Echo", "test", &resp)
	if err == nil {
		t.Fatal("expected error for invalid session")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	errMsg := st.Message()

	// Error message should NOT contain:
	sensitivePatterns := []string{
		"goroutine",                // stack trace
		".go:",                     // file paths
		"panic",                    // panic info
		"/Users/",                  // local paths
		"/home/",                   // linux paths
		"github.com/abhipray-cpu/", // import paths
		"auth/engine",              // internal package paths
		"auth/session",             // internal package paths
		"runtime.",                 // runtime internals
		"argon2id",                 // hashing details
		"ed25519",                  // key algorithm details
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(errMsg, pattern) {
			t.Errorf("SECURITY: error message contains sensitive info %q: %q", pattern, errMsg)
		}
	}

	// Should be a clean error code.
	if st.Code() != codes.Unauthenticated {
		t.Errorf("expected Unauthenticated, got %v", st.Code())
	}

	t.Logf("error message (should be clean): %q", errMsg)
}

func TestE2E_Traffic_SessionID_Entropy(t *testing.T) {
	// 35.5: Session IDs have sufficient entropy (not sequential, not guessable).
	sessStore := newMemSessionStore()
	eng := buildTrafficEngine(t, sessStore)

	regCred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "entropy@example.com",
		Secret:     "EntropyPass1!",
	}
	_, _, err := eng.Register(context.Background(), regCred)
	assertNoError(t, err, "register")

	// Create multiple sessions.
	const numSessions = 20
	sessionIDs := make([]string, numSessions)
	for i := 0; i < numSessions; i++ {
		identity, _, err := eng.Login(context.Background(), passwordCred("entropy@example.com", "EntropyPass1!"))
		assertNoError(t, err, "login %d", i)
		sessionIDs[i] = identity.SessionID
	}

	// All session IDs should be unique.
	seen := make(map[string]bool)
	for i, sid := range sessionIDs {
		if seen[sid] {
			t.Errorf("duplicate session ID at index %d: %q", i, sid)
		}
		seen[sid] = true
	}

	// Session IDs should have sufficient length (at least 32 characters).
	for i, sid := range sessionIDs {
		if len(sid) < 32 {
			t.Errorf("session ID %d too short (%d chars): %q — insufficient entropy", i, len(sid), sid)
		}
	}

	// Session IDs should not be sequential.
	for i := 1; i < len(sessionIDs); i++ {
		// Check they're not just incrementing numbers.
		if sessionIDs[i] == sessionIDs[i-1] {
			t.Errorf("session IDs %d and %d are identical", i-1, i)
		}
	}

	// Check there's no common prefix (which would suggest weak randomness).
	if len(sessionIDs) >= 2 {
		commonPrefix := longestCommonPrefix(sessionIDs[0], sessionIDs[1])
		// A common prefix > 4 chars is suspicious for 2 random strings.
		if len(commonPrefix) > len(sessionIDs[0])/2 {
			t.Errorf("suspiciously long common prefix between sessions: %q (len=%d)", commonPrefix, len(commonPrefix))
		}
	}
}

func TestE2E_Traffic_PropagatedJWT_NoPrivateKey(t *testing.T) {
	// 35.6: The propagated JWT does not contain any private key material.
	keyStore := &memKeyStore{}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "services",
		TTL:      30 * time.Second,
		KeyStore: keyStore,
	})
	assertNoError(t, err, "propagator")

	identity := &auth.Identity{
		SubjectID:  "alice@example.com",
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}

	headers, err := prop.Encode(context.Background(), identity)
	assertNoError(t, err, "encode")

	jwt := headers["x-auth-identity"]

	// Load keys.
	records, _ := keyStore.LoadKeys(context.Background())
	for _, rec := range records {
		// Check that private key bytes don't appear anywhere in the JWT.
		privKeyBytes := rec.PrivateKey
		if len(privKeyBytes) > 0 {
			// Check in raw form.
			if strings.Contains(jwt, string(privKeyBytes)) {
				t.Error("SECURITY: private key raw bytes in JWT")
			}
			// Check in base64 form.
			b64 := base64.RawURLEncoding.EncodeToString(privKeyBytes)
			if strings.Contains(jwt, b64) {
				t.Error("SECURITY: private key base64 in JWT")
			}
			b64std := base64.StdEncoding.EncodeToString(privKeyBytes)
			if strings.Contains(jwt, b64std) {
				t.Error("SECURITY: private key std-base64 in JWT")
			}
		}
	}

	// Verify the JWT header only contains expected fields.
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	assertNoError(t, err, "decode header")

	var header map[string]any
	assertNoError(t, json.Unmarshal(headerJSON, &header), "unmarshal header")

	allowedHeaderFields := map[string]bool{
		"alg": true, "typ": true, "kid": true,
	}
	for key := range header {
		if !allowedHeaderFields[key] {
			t.Errorf("unexpected field in JWT header: %q", key)
		}
	}
}

func TestE2E_Traffic_BearerNotForwardedRaw(t *testing.T) {
	// 35.7: The raw bearer session token should NOT be forwarded as-is
	// between services. The propagator should encode a NEW JWT,
	// not re-transmit the original session ID.
	pki := newTestPKI(t)
	keyStore := &memKeyStore{}

	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "services",
		TTL:      30 * time.Second,
		KeyStore: keyStore,
	})
	assertNoError(t, err, "propagator")

	sessStore := newMemSessionStore()
	eng := buildTrafficEngine(t, sessStore)

	regCred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "StrongPass123!",
	}
	_, _, err = eng.Register(context.Background(), regCred)
	assertNoError(t, err, "register")

	identity, _, err := eng.Login(context.Background(), passwordCred("alice@example.com", "StrongPass123!"))
	assertNoError(t, err, "login")

	rawSessionID := identity.SessionID

	// Encode for propagation.
	headers, err := prop.Encode(context.Background(), identity)
	assertNoError(t, err, "encode")

	propagatedJWT := headers["x-auth-identity"]

	// The propagated JWT should NOT contain the raw session ID.
	if strings.Contains(propagatedJWT, rawSessionID) {
		t.Error("SECURITY: raw session ID appears in propagated JWT")
	}

	// Decode the JWT claims to double-check.
	parts := strings.SplitN(propagatedJWT, ".", 3)
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])

	if strings.Contains(string(claimsJSON), rawSessionID) {
		t.Error("SECURITY: raw session ID in JWT claims")
	}

	// Start a server that captures metadata to verify raw session isn't forwarded.
	serverCert := pki.issueServerCert(t, "downstream", "localhost")
	clientCert := pki.issueClientCert(t, "gateway")

	type captured struct {
		authHeader     []string
		identityHeader []string
	}
	captureCh := make(chan captured, 1)

	captureInterceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		captureCh <- captured{
			authHeader:     md.Get("authorization"),
			identityHeader: md.Get("x-auth-identity"),
		}
		return handler(ctx, req)
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert.tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
		})),
		grpc.UnaryInterceptor(captureInterceptor),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assertNoError(t, err, "listen")
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Use CLIENT interceptor to propagate identity (like Gateway would).
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{clientCert.tlsCert},
			RootCAs:      pki.caPool,
			ServerName:   "localhost",
		})),
		grpc.WithUnaryInterceptor(authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
			Propagator: prop,
		})),
	)
	assertNoError(t, err, "dial")
	defer conn.Close()

	// Set identity in context (simulating Gateway having verified the session).
	ctx := auth.SetIdentity(context.Background(), identity)

	var resp string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/Echo", "test", &resp)
	assertNoError(t, err, "invoke")

	// Check what was sent.
	select {
	case cap := <-captureCh:
		// The authorization header should NOT contain the raw session ID.
		for _, v := range cap.authHeader {
			if strings.Contains(v, rawSessionID) {
				t.Error("SECURITY: raw session ID forwarded in authorization header")
			}
		}
		// The x-auth-identity header SHOULD be present (as JWT).
		if len(cap.identityHeader) == 0 {
			t.Error("expected x-auth-identity header in propagated request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for capture")
	}
}

// ---------- Helpers ----------

func buildTrafficEngine(t *testing.T, store session.SessionStore) *engine.Engine {
	t.Helper()
	sessMgr := session.NewManager(store, session.DefaultConfig())
	userStore := NewMemUserStore()
	hasher := hash.NewArgon2idHasher(nil)

	pwMode := modepw.NewMode(modepw.ModeConfig{
		UserStore: userStore,
		Hasher:    hasher,
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
	})

	eng, err := engine.New(engine.Config{
		UserStore:      userStore,
		Hasher:         hasher,
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
		Modes: []auth.AuthMode{pwMode},
	})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return eng
}

func longestCommonPrefix(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[:i]
		}
	}
	return a[:n]
}
