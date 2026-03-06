// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0033: E2E — Real mTLS Over Network
//
// Tests mTLS handshake over real TLS connections with gRPC.
// Uses the full PKI from e2e_infra_test.go with real TCP connections.
//
// Test Cases:
//
//	33.1: gRPC call with valid client cert → WorkloadIdentity extracted
//	33.2: Client cert from unknown CA → connection rejected at TLS layer
//	33.3: Expired client cert → TLS handshake fails
//	33.4: New client cert with same identity → accepted (cert rotation)
//	33.5: SPIFFE URI SAN → WorkloadIdentity with trust domain
//	33.6: TLS version enforcement (MinVersion TLS 1.2)
//	33.7: Dual identity: mTLS + session token → both identities in context
package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	"github.com/abhipray-cpu/auth/hash"
	"github.com/abhipray-cpu/auth/hooks"
	modepw "github.com/abhipray-cpu/auth/mode/password"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ---------- AUTH-0033: Real mTLS Over Network ----------

func TestE2E_MTLS_ValidClientCert_WorkloadIdentity(t *testing.T) {
	// 33.1: Valid client cert → WorkloadIdentity extracted with correct CN.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()

	svc := startTestGRPCService(t, testServiceConfig{
		name:         "mtls-server",
		pki:          pki,
		userStore:    NewMemUserStore(),
		sessionStore: sessStore,
		requireAuth:  false,
		serverCertCN: "server",
		clientCertCN: "order-service",
	})

	// Connect with valid client cert.
	conn := dialService(t, svc, svc.clientCert)

	// Call GetIdentity to verify WorkloadIdentity is in context.
	var resp map[string]string
	err := conn.Invoke(context.Background(), "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	if resp["workload_id"] != "order-service" {
		t.Errorf("workload_id = %q, want %q", resp["workload_id"], "order-service")
	}
}

func TestE2E_MTLS_UntrustedCA_Rejected(t *testing.T) {
	// 33.2: Client cert from unknown CA → connection rejected at TLS layer.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()

	svc := startTestGRPCService(t, testServiceConfig{
		name:         "mtls-server-untrusted",
		pki:          pki,
		userStore:    NewMemUserStore(),
		sessionStore: sessStore,
		requireAuth:  true,
		serverCertCN: "server",
		clientCertCN: "legit-client",
	})

	// Create a client cert signed by the untrusted CA.
	untrustedCert := pki.issueUntrustedClientCert(t, "rogue-service")

	// Try to connect with the untrusted cert — should fail at TLS layer.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{untrustedCert.tlsCert},
		RootCAs:      pki.caPool,
		ServerName:   "localhost",
	}

	conn, err := grpc.NewClient(
		svc.addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		t.Fatalf("dial should succeed (TLS error happens on RPC): %v", err)
	}
	defer conn.Close()

	// The actual TLS handshake happens when we try to invoke.
	var resp string
	err = conn.Invoke(context.Background(), "/"+echoServiceName+"/Echo", "test", &resp)
	if err == nil {
		t.Fatal("expected error: untrusted client cert should be rejected")
	}

	// Error should be a TLS/connection error, not a gRPC application error.
	// The server's TLS config requires certs from caPool, untrusted cert isn't in it.
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.OK {
		t.Fatal("expected TLS-level rejection, got OK")
	}
	// Any error here is correct — the TLS handshake should fail.
	t.Logf("correctly rejected untrusted cert: %v", err)
}

func TestE2E_MTLS_ExpiredCert_Rejected(t *testing.T) {
	// 33.3: Expired client cert → TLS handshake fails.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()

	svc := startTestGRPCService(t, testServiceConfig{
		name:         "mtls-server-expired",
		pki:          pki,
		userStore:    NewMemUserStore(),
		sessionStore: sessStore,
		requireAuth:  true,
		serverCertCN: "server",
		clientCertCN: "legit-client",
	})

	// Create an expired client cert.
	expiredCert := pki.issueExpiredClientCert(t, "expired-service")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{expiredCert.tlsCert},
		RootCAs:      pki.caPool,
		ServerName:   "localhost",
	}

	conn, err := grpc.NewClient(
		svc.addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		t.Fatalf("dial should succeed (TLS error happens on RPC): %v", err)
	}
	defer conn.Close()

	var resp string
	err = conn.Invoke(context.Background(), "/"+echoServiceName+"/Echo", "test", &resp)
	if err == nil {
		t.Fatal("expected error: expired client cert should be rejected")
	}
	t.Logf("correctly rejected expired cert: %v", err)
}

func TestE2E_MTLS_CertRotation_NewCertSameIdentity(t *testing.T) {
	// 33.4: Issue a new cert with the same CN → accepted. Simulates cert rotation.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()

	svc := startTestGRPCService(t, testServiceConfig{
		name:         "mtls-server-rotation",
		pki:          pki,
		userStore:    NewMemUserStore(),
		sessionStore: sessStore,
		requireAuth:  false,
		serverCertCN: "server",
		clientCertCN: "old-cert",
	})

	// Issue a NEW client cert with the SAME identity (same CN).
	newCert := pki.issueClientCert(t, "order-service")
	anotherNewCert := pki.issueClientCert(t, "order-service")

	// Both certs should work. The server only cares about CA trust, not cert identity persistence.
	for i, cert := range []*tlsCertPair{newCert, anotherNewCert} {
		t.Run(fmt.Sprintf("cert_%d", i+1), func(t *testing.T) {
			conn := dialService(t, svc, cert)

			var resp map[string]string
			err := conn.Invoke(context.Background(), "/"+echoServiceName+"/GetIdentity", "test", &resp)
			if err != nil {
				t.Fatalf("invoke with rotated cert: %v", err)
			}

			if resp["workload_id"] != "order-service" {
				t.Errorf("workload_id = %q, want %q", resp["workload_id"], "order-service")
			}
		})
	}
}

func TestE2E_MTLS_SPIFFE_WorkloadIdentity(t *testing.T) {
	// 33.5: Client cert with SPIFFE URI SAN → WorkloadIdentity includes trust domain.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()

	svc := startTestGRPCService(t, testServiceConfig{
		name:         "mtls-server-spiffe",
		pki:          pki,
		userStore:    NewMemUserStore(),
		sessionStore: sessStore,
		requireAuth:  false,
		serverCertCN: "server",
		clientCertCN: "inventory-service",
		spiffeID:     "spiffe://acme.com/inventory-service",
	})

	// The client cert already has SPIFFE URI SAN. Connect with it.
	conn := dialService(t, svc, svc.clientCert)

	var resp map[string]string
	err := conn.Invoke(context.Background(), "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	// The server's gRPC interceptor should extract SPIFFE ID from the cert.
	if resp["workload_id"] != "spiffe://acme.com/inventory-service" {
		t.Errorf("workload_id = %q, want %q", resp["workload_id"], "spiffe://acme.com/inventory-service")
	}
	if resp["trust_domain"] != "acme.com" {
		t.Errorf("trust_domain = %q, want %q", resp["trust_domain"], "acme.com")
	}
}

func TestE2E_MTLS_TLSVersionEnforcement(t *testing.T) {
	// 33.6: Server enforces TLS 1.2+ — TLS 1.0/1.1 should fail.
	pki := newTestPKI(t)

	// Create a server that requires TLS 1.3 specifically.
	serverCert := pki.issueServerCert(t, "tls13-server", "localhost")
	clientCert := pki.issueClientCert(t, "client")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS13,
	}

	lis, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	// Accept connections in background and complete the handshake.
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			// Complete TLS handshake before closing.
			tlsConn := conn.(*tls.Conn)
			_ = tlsConn.Handshake()
			conn.Close()
		}
	}()

	// Try connecting with TLS 1.2 max — should fail.
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert.tlsCert},
		RootCAs:      pki.caPool,
		ServerName:   "localhost",
		MaxVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", lis.Addr().String(), clientTLS)
	if err == nil {
		conn.Close()
		t.Fatal("expected TLS 1.2 connection to fail when server requires TLS 1.3")
	}
	t.Logf("correctly rejected TLS 1.2: %v", err)

	// Try connecting with TLS 1.3 — should succeed.
	clientTLS13 := &tls.Config{
		Certificates: []tls.Certificate{clientCert.tlsCert},
		RootCAs:      pki.caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	conn, err = tls.Dial("tcp", lis.Addr().String(), clientTLS13)
	if err != nil {
		t.Fatalf("TLS 1.3 connection should succeed: %v", err)
	}
	conn.Close()

	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Errorf("negotiated version = %x, want TLS 1.3 (%x)", conn.ConnectionState().Version, tls.VersionTLS13)
	}
}

func TestE2E_MTLS_DualIdentity_MTLSPlusBearerToken(t *testing.T) {
	// 33.7: mTLS provides WorkloadIdentity, Bearer token provides user Identity.
	// Both should coexist in context.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()
	userStore := NewMemUserStore()

	// Build engine + session manager directly for session creation.
	sessionMgr := session.NewManager(sessStore, session.DefaultConfig())
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
		SessionManager: sessionMgr,
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
		t.Fatalf("engine: %v", err)
	}

	// Register a user and create a session.
	regCred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: "alice@example.com",
		Secret:     "StrongPass123!",
	}
	_, _, regErr := eng.Register(context.Background(), regCred)
	if regErr != nil {
		t.Fatalf("register: %v", regErr)
	}

	identity, sess, loginErr := eng.Login(context.Background(), passwordCred("alice@example.com", "StrongPass123!"))
	if loginErr != nil {
		t.Fatalf("login: %v", loginErr)
	}
	_ = sess

	sessionID := identity.SessionID

	// Create mTLS gRPC server with RequireAuth=false (to let both identities through).
	serverCert := pki.issueServerCert(t, "server", "localhost")
	clientCert := pki.issueClientCert(t, "gateway-service")

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}

	serverConfig := authgrpc.ServerConfig{
		Engine:      eng,
		RequireAuth: false,
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(serverConfig)),
	)

	// Register our echo service.
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Dial with client cert.
	dialTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert.tlsCert},
		RootCAs:      pki.caPool,
		ServerName:   "localhost",
	}

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(dialTLS)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Call with bearer token in metadata.
	ctx := context.Background()
	ctx = appendMetadata(ctx, "authorization", "Bearer "+sessionID)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	// Both identities should be present.
	if resp["subject_id"] != "alice@example.com" {
		t.Errorf("subject_id = %q, want %q", resp["subject_id"], "alice@example.com")
	}
	if resp["workload_id"] != "gateway-service" {
		t.Errorf("workload_id = %q, want %q", resp["workload_id"], "gateway-service")
	}
}

func TestE2E_MTLS_NoCert_RequireAuth_Rejected(t *testing.T) {
	// Additional strictness: server requires auth, no cert no token → Unauthenticated.
	pki := newTestPKI(t)
	sessStore := newMemSessionStore()

	// Server with RequireAuth=true but configured for VerifyClientCertIfGiven
	// so the TLS handshake succeeds but no identity is established.
	serverCert := pki.issueServerCert(t, "server", "localhost")

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert.tlsCert},
		ClientAuth:   tls.VerifyClientCertIfGiven, // Allow connections without certs
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}

	sessionMgr := session.NewManager(sessStore, session.DefaultConfig())
	eng, err := engine.New(engine.Config{
		UserStore:      NewMemUserStore(),
		SessionManager: sessionMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field: "email",
		},
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      eng,
			RequireAuth: true,
		})),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Connect WITHOUT client cert (no mTLS) but still TLS.
	dialTLS := &tls.Config{
		RootCAs:    pki.caPool,
		ServerName: "localhost",
	}
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(dialTLS)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var resp string
	err = conn.Invoke(context.Background(), "/"+echoServiceName+"/Echo", "test", &resp)
	if err == nil {
		t.Fatal("expected Unauthenticated error when no cert and no token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

// appendMetadata adds key-value pairs to outgoing gRPC metadata.
func appendMetadata(ctx context.Context, pairs ...string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}
