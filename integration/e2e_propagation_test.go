// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// AUTH-0032: E2E — Multi-Service Identity Propagation
//
// Tests identity propagation across 3 services over real gRPC connections
// with real mTLS. Validates that identity travels correctly:
//
//	Gateway → Order Service → Inventory Service
//
// Test Cases:
//
//	32.1:  Login at Gateway → call Order → identity propagated via SignedJWT
//	32.2:  Order Service verifies JWT: correct SubjectID, AuthMethod, AuthTime
//	32.3:  Chained: Gateway → Order → Inventory, identity through 3 services
//	32.4:  Dual identity: User Identity (JWT) + WorkloadIdentity (mTLS) at Order
//	32.5:  Expired JWT → downstream rejects
//	32.6:  Audience mismatch → rejected
//	32.7:  Tampered JWT → rejected
//	32.8:  S2S call without user context → WorkloadIdentity only
//	32.9:  Key rotation: old key accepted during overlap
//	32.10: No propagator configured → no identity forwarded
package integration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// ---------- Multi-service test harness ----------

// multiServiceEnv holds a 3-service setup: Gateway → Order → Inventory.
type multiServiceEnv struct {
	pki *tlsPKI

	gatewayEngine *engine.Engine
	gatewaySess   session.SessionStore
	gatewayProp   *propagator.SignedJWTPropagator
	gatewayServer *grpc.Server
	gatewayAddr   string

	orderProp   *propagator.SignedJWTPropagator
	orderServer *grpc.Server
	orderAddr   string

	inventoryProp   *propagator.SignedJWTPropagator
	inventoryServer *grpc.Server
	inventoryAddr   string
}

// buildMultiServiceEnv creates the full 3-service environment.
func buildMultiServiceEnv(t *testing.T, opts ...func(*multiServiceEnvConfig)) *multiServiceEnv {
	t.Helper()
	cfg := &multiServiceEnvConfig{
		jwtTTL: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	pki := newTestPKI(t)
	env := &multiServiceEnv{pki: pki}

	// Shared KeyStore so all services share verification keys.
	keyStore := &memKeyStore{}

	// Gateway propagator — issues JWTs.
	gatewayProp, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "internal-services",
		TTL:      cfg.jwtTTL,
		KeyStore: keyStore,
		NowFunc:  cfg.nowFunc,
	})
	if err != nil {
		t.Fatalf("gateway propagator: %v", err)
	}
	env.gatewayProp = gatewayProp

	// Force key generation so the shared KeyStore has the signing key
	// BEFORE downstream propagators are created (they load keys at creation time).
	dummyID := &auth.Identity{SubjectID: "keygen", AuthMethod: "init"}
	if _, err := gatewayProp.Encode(context.Background(), dummyID); err != nil {
		t.Fatalf("force gateway key generation: %v", err)
	}

	// Order propagator — verifies JWTs from Gateway, issues for downstream.
	orderProp, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "internal-services",
		TTL:      cfg.jwtTTL,
		KeyStore: keyStore,
		NowFunc:  cfg.nowFunc,
	})
	if err != nil {
		t.Fatalf("order propagator: %v", err)
	}
	env.orderProp = orderProp

	// Inventory propagator — verifies JWTs.
	inventoryProp, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "internal-services",
		TTL:      cfg.jwtTTL,
		KeyStore: keyStore,
		NowFunc:  cfg.nowFunc,
	})
	if err != nil {
		t.Fatalf("inventory propagator: %v", err)
	}
	env.inventoryProp = inventoryProp

	// Session store and engine for Gateway.
	sessStore := newMemSessionStore()
	env.gatewaySess = sessStore
	sessionMgr := session.NewManager(sessStore, session.DefaultConfig())
	gwUserStore := NewMemUserStore()
	gwHasher := hash.NewArgon2idHasher(nil)
	gwPwMode := modepw.NewMode(modepw.ModeConfig{
		UserStore: gwUserStore,
		Hasher:    gwHasher,
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
	})
	gatewayEngine, err := engine.New(engine.Config{
		UserStore:      gwUserStore,
		Hasher:         gwHasher,
		SessionManager: sessionMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field:         "email",
			CaseSensitive: false,
			Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
		},
		Modes: []auth.AuthMode{gwPwMode},
	})
	if err != nil {
		t.Fatalf("gateway engine: %v", err)
	}
	env.gatewayEngine = gatewayEngine

	// --- Start Inventory Service (leaf, no downstream) ---
	inventoryServerCert := pki.issueServerCert(t, "inventory-service", "localhost")
	inventoryClientCert := pki.issueClientCert(t, "inventory-service")
	_ = inventoryClientCert

	invSessMgr := session.NewManager(newMemSessionStore(), session.DefaultConfig())
	invEngine, _ := engine.New(engine.Config{
		UserStore:        NewMemUserStore(),
		SessionManager:   invSessMgr,
		HookManager:      hooks.NewManager(),
		PasswordPolicy:   pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{Field: "email"},
	})

	env.inventoryServer = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{inventoryServerCert.tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      invEngine,
			Propagator:  inventoryProp,
			RequireAuth: false,
		})),
	)
	env.inventoryServer.RegisterService(&echoServiceDesc, &echoServer{propagator: inventoryProp})

	invLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inventory listen: %v", err)
	}
	env.inventoryAddr = invLis.Addr().String()
	go func() { _ = env.inventoryServer.Serve(invLis) }()
	t.Cleanup(func() { env.inventoryServer.GracefulStop() })

	// --- Start Order Service (mid-tier, downstream to Inventory) ---
	orderServerCert := pki.issueServerCert(t, "order-service", "localhost")
	orderClientCert := pki.issueClientCert(t, "order-service")

	// Order → Inventory client connection.
	orderToInvConn, err := grpc.NewClient(
		env.inventoryAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{orderClientCert.tlsCert},
			RootCAs:      pki.caPool,
			ServerName:   "localhost",
		})),
		grpc.WithUnaryInterceptor(authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
			Propagator: orderProp,
		})),
	)
	if err != nil {
		t.Fatalf("order→inventory dial: %v", err)
	}
	t.Cleanup(func() { orderToInvConn.Close() })

	ordSessMgr := session.NewManager(newMemSessionStore(), session.DefaultConfig())
	ordEngine, _ := engine.New(engine.Config{
		UserStore:        NewMemUserStore(),
		SessionManager:   ordSessMgr,
		HookManager:      hooks.NewManager(),
		PasswordPolicy:   pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{Field: "email"},
	})

	env.orderServer = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{orderServerCert.tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      ordEngine,
			Propagator:  orderProp,
			RequireAuth: false,
		})),
	)
	env.orderServer.RegisterService(&echoServiceDesc, &echoServer{
		propagator: orderProp,
		downstream: orderToInvConn,
	})

	ordLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("order listen: %v", err)
	}
	env.orderAddr = ordLis.Addr().String()
	go func() { _ = env.orderServer.Serve(ordLis) }()
	t.Cleanup(func() { env.orderServer.GracefulStop() })

	// --- Gateway dial to Order Service ---
	gatewayClientCert := pki.issueClientCert(t, "gateway-service")

	gatewayToOrderConn, err := grpc.NewClient(
		env.orderAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{gatewayClientCert.tlsCert},
			RootCAs:      pki.caPool,
			ServerName:   "localhost",
		})),
		grpc.WithUnaryInterceptor(authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
			Propagator: gatewayProp,
		})),
	)
	if err != nil {
		t.Fatalf("gateway→order dial: %v", err)
	}
	t.Cleanup(func() { gatewayToOrderConn.Close() })

	// Store the gateway server cert and start it too for JWKS serving.
	gatewayServerCert := pki.issueServerCert(t, "gateway-service", "localhost")
	_ = gatewayServerCert

	env.gatewayServer = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{pki.issueServerCert(t, "gateway-service", "localhost").tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      gatewayEngine,
			Propagator:  gatewayProp,
			RequireAuth: false,
		})),
	)
	env.gatewayServer.RegisterService(&echoServiceDesc, &echoServer{
		propagator: gatewayProp,
		downstream: gatewayToOrderConn,
	})

	gwLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("gateway listen: %v", err)
	}
	env.gatewayAddr = gwLis.Addr().String()
	go func() { _ = env.gatewayServer.Serve(gwLis) }()
	t.Cleanup(func() { env.gatewayServer.GracefulStop() })

	return env
}

type multiServiceEnvConfig struct {
	jwtTTL  time.Duration
	nowFunc func() time.Time
}

// dialGateway creates a gRPC client connection to the gateway.
func (env *multiServiceEnv) dialGateway(t *testing.T) *grpc.ClientConn {
	t.Helper()
	clientCert := env.pki.issueClientCert(t, "e2e-test-client")
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert.tlsCert},
		RootCAs:      env.pki.caPool,
		ServerName:   "localhost",
	}
	conn, err := grpc.NewClient(
		env.gatewayAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// dialOrderDirect creates a direct connection to Order service (bypassing Gateway).
func (env *multiServiceEnv) dialOrderDirect(t *testing.T) *grpc.ClientConn {
	t.Helper()
	clientCert := env.pki.issueClientCert(t, "direct-test-client")
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert.tlsCert},
		RootCAs:      env.pki.caPool,
		ServerName:   "localhost",
	}
	conn, err := grpc.NewClient(
		env.orderAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("dial order: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// loginUser registers and logs in a user at the gateway, returning the session ID.
func (env *multiServiceEnv) loginUser(t *testing.T, email, password string) string {
	t.Helper()
	ctx := context.Background()

	regCred := auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: email,
		Secret:     password,
	}
	_, _, err := env.gatewayEngine.Register(ctx, regCred)
	if err != nil && err != auth.ErrUserAlreadyExists {
		t.Fatalf("register %s: %v", email, err)
	}

	identity, _, err := env.gatewayEngine.Login(ctx, passwordCred(email, password))
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}

	return identity.SessionID
}

// ---------- Test Cases ----------

func TestE2E_Propagation_GatewayToOrder_IdentityPropagated(t *testing.T) {
	// 32.1: User logs in at Gateway → Gateway calls Order → identity propagated via SignedJWT.
	env := buildMultiServiceEnv(t)

	sessionID := env.loginUser(t, "alice@example.com", "StrongPass123!")

	// Simulate: Gateway receives a request with the session token,
	// verifies it, and then calls Order Service with the identity in context.
	// In a real system, the Gateway's HTTP handler would do this.
	// Here we replicate the flow directly.

	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify session: %v", err)
	}

	// Set identity in context (as the Gateway interceptor would).
	ctx := auth.SetIdentity(context.Background(), identity)

	// Encode identity for propagation.
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Dial Order Service directly and send the propagated headers.
	conn := env.dialOrderDirect(t)

	// Attach propagation headers to outgoing metadata.
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke order: %v", err)
	}

	if resp["subject_id"] != "alice@example.com" {
		t.Errorf("subject_id = %q, want %q", resp["subject_id"], "alice@example.com")
	}
}

func TestE2E_Propagation_OrderVerifiesJWT_CorrectClaims(t *testing.T) {
	// 32.2: Order Service verifies JWT: correct SubjectID, AuthMethod.
	env := buildMultiServiceEnv(t)

	sessionID := env.loginUser(t, "bob@example.com", "BobPass456!")

	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	identity.AuthMethod = "password"
	identity.AuthTime = time.Now()

	ctx := auth.SetIdentity(context.Background(), identity)
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	conn := env.dialOrderDirect(t)
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	if resp["subject_id"] != "bob@example.com" {
		t.Errorf("subject_id = %q, want %q", resp["subject_id"], "bob@example.com")
	}
	if resp["auth_method"] != "password" {
		t.Errorf("auth_method = %q, want %q", resp["auth_method"], "password")
	}
}

func TestE2E_Propagation_ChainedThreeServices(t *testing.T) {
	// 32.3: Gateway → Order → Inventory, identity propagated through 3 services.
	env := buildMultiServiceEnv(t)

	sessionID := env.loginUser(t, "alice@example.com", "StrongPass123!")

	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	identity.AuthMethod = "password"
	identity.AuthTime = time.Now()

	ctx := auth.SetIdentity(context.Background(), identity)
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Call Gateway's Forward endpoint → Order → Inventory.
	conn := env.dialGateway(t)
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/Forward", "chain-test", &resp)
	if err != nil {
		t.Fatalf("forward chain: %v", err)
	}

	// The response comes from Inventory via Order — should still have alice's identity.
	if resp["subject_id"] != "alice@example.com" {
		t.Errorf("chained subject_id = %q, want %q", resp["subject_id"], "alice@example.com")
	}
}

func TestE2E_Propagation_DualIdentity_UserAndWorkload(t *testing.T) {
	// 32.4: Order Service sees User Identity (from JWT) + WorkloadIdentity (from mTLS).
	env := buildMultiServiceEnv(t)

	sessionID := env.loginUser(t, "alice@example.com", "StrongPass123!")
	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	identity.AuthMethod = "password"

	ctx := auth.SetIdentity(context.Background(), identity)
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	conn := env.dialOrderDirect(t)
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	// User identity from JWT.
	if resp["subject_id"] != "alice@example.com" {
		t.Errorf("subject_id = %q, want %q", resp["subject_id"], "alice@example.com")
	}
	// Workload identity from mTLS (client cert CN is "direct-test-client").
	if resp["workload_id"] == "" {
		t.Error("workload_id should be set from mTLS client cert")
	}
}

func TestE2E_Propagation_ExpiredJWT_Rejected(t *testing.T) {
	// 32.5: Expired JWT → downstream rejects.
	// Use a very short TTL and a custom NowFunc to simulate expiry.
	fakeNow := time.Now()
	env := buildMultiServiceEnv(t, func(cfg *multiServiceEnvConfig) {
		cfg.jwtTTL = 1 * time.Second
		cfg.nowFunc = func() time.Time { return fakeNow }
	})

	sessionID := env.loginUser(t, "alice@example.com", "StrongPass123!")
	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Encode JWT at fakeNow.
	ctx := auth.SetIdentity(context.Background(), identity)
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Advance time past the TTL.
	fakeNow = fakeNow.Add(10 * time.Second)

	// Try to use the JWT at Order Service — should be rejected as expired.
	conn := env.dialOrderDirect(t)
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx = metadata.AppendToOutgoingContext(context.Background(), pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	// The interceptor should fail to decode the expired JWT.
	// Since RequireAuth=false, the call succeeds but with no identity.
	if err != nil {
		t.Logf("correctly got error for expired JWT: %v", err)
		return
	}

	// If no error, identity should NOT be set (JWT was expired, decode failed silently).
	if resp["subject_id"] != "" {
		t.Errorf("expired JWT should not produce identity, got subject_id = %q", resp["subject_id"])
	}
}

func TestE2E_Propagation_AudienceMismatch_Rejected(t *testing.T) {
	// 32.6: JWT issued for wrong audience → rejected by downstream.
	pki := newTestPKI(t)

	// Gateway issues JWT with audience "order-only".
	gatewayProp, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "order-only",
		TTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("gateway prop: %v", err)
	}

	// Order Service expects audience "different-audience".
	orderProp, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",
		Audience: "different-audience",
		TTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("order prop: %v", err)
	}

	// Start Order Service with mismatched audience.
	serverCert := pki.issueServerCert(t, "order-service", "localhost")

	ordSessMgr := session.NewManager(newMemSessionStore(), session.DefaultConfig())
	ordEngine, _ := engine.New(engine.Config{
		UserStore:        NewMemUserStore(),
		SessionManager:   ordSessMgr,
		HookManager:      hooks.NewManager(),
		PasswordPolicy:   pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{Field: "email"},
	})

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert.tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      ordEngine,
			Propagator:  orderProp,
			RequireAuth: false,
		})),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	// Encode a JWT with the wrong audience.
	identity := &auth.Identity{SubjectID: "alice", AuthMethod: "password", AuthTime: time.Now()}
	headers, err := gatewayProp.Encode(context.Background(), identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Connect and send the JWT.
	clientCert := pki.issueClientCert(t, "gateway-service")
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{clientCert.tlsCert},
			RootCAs:      pki.caPool,
			ServerName:   "localhost",
		})),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	// Since RequireAuth=false, the call succeeds but identity should NOT be set.
	if err != nil {
		t.Logf("got error for audience mismatch: %v", err)
		return
	}
	if resp["subject_id"] != "" {
		t.Errorf("audience mismatch should not produce identity, got subject_id = %q", resp["subject_id"])
	}
}

func TestE2E_Propagation_TamperedJWT_Rejected(t *testing.T) {
	// 32.7: Tampered JWT → rejected.
	env := buildMultiServiceEnv(t)

	sessionID := env.loginUser(t, "alice@example.com", "StrongPass123!")
	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	identity.AuthMethod = "password"

	ctx := auth.SetIdentity(context.Background(), identity)
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Tamper with the JWT: modify one character in the signature.
	jwt := headers["x-auth-identity"]
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	// Flip a bit in the signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	tamperedJWT := strings.Join(parts, ".")

	// Send tampered JWT.
	conn := env.dialOrderDirect(t)
	ctx = metadata.AppendToOutgoingContext(context.Background(), "x-auth-identity", tamperedJWT)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Logf("correctly got error for tampered JWT: %v", err)
		return
	}
	// Identity should NOT be set.
	if resp["subject_id"] != "" {
		t.Errorf("tampered JWT should not produce identity, got subject_id = %q", resp["subject_id"])
	}
}

func TestE2E_Propagation_S2S_WorkloadIdentityOnly(t *testing.T) {
	// 32.8: S2S call without user context → only WorkloadIdentity.
	env := buildMultiServiceEnv(t)

	// Call Order Service without any identity JWT — just mTLS.
	conn := env.dialOrderDirect(t)

	var resp map[string]string
	err := conn.Invoke(context.Background(), "/"+echoServiceName+"/GetIdentity", "s2s-test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	// No user identity.
	if resp["subject_id"] != "" {
		t.Errorf("S2S call should have no user identity, got subject_id = %q", resp["subject_id"])
	}
	// But should have workload identity from mTLS.
	if resp["workload_id"] == "" {
		t.Error("S2S call should have WorkloadIdentity from mTLS")
	}
}

func TestE2E_Propagation_KeyRotation_OldKeyAccepted(t *testing.T) {
	// 32.9: After key rotation, old key remains accepted during overlap.
	env := buildMultiServiceEnv(t)

	sessionID := env.loginUser(t, "alice@example.com", "StrongPass123!")
	identity, err := env.gatewayEngine.Verify(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	identity.AuthMethod = "password"

	// Encode JWT with the INITIAL key.
	ctx := auth.SetIdentity(context.Background(), identity)
	headersOldKey, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode old: %v", err)
	}

	initialKeyCount := env.gatewayProp.KeyCount()

	// Rotate the key.
	if err := env.gatewayProp.RotateKey(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	newKeyCount := env.gatewayProp.KeyCount()
	if newKeyCount <= initialKeyCount {
		t.Errorf("key count should increase after rotation: was %d, now %d", initialKeyCount, newKeyCount)
	}

	// Encode JWT with the NEW key.
	headersNewKey, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode new: %v", err)
	}

	// Both JWTs should be different (different key IDs).
	if headersOldKey["x-auth-identity"] == headersNewKey["x-auth-identity"] {
		t.Error("old and new JWTs should be different after rotation")
	}

	// Both should be accepted by Order Service (which shares the KeyStore).
	conn := env.dialOrderDirect(t)

	// Old key JWT.
	pairs := make([]string, 0, len(headersOldKey)*2)
	for k, v := range headersOldKey {
		pairs = append(pairs, k, v)
	}
	ctx1 := metadata.AppendToOutgoingContext(context.Background(), pairs...)
	var resp1 map[string]string
	err = conn.Invoke(ctx1, "/"+echoServiceName+"/GetIdentity", "test", &resp1)
	if err != nil {
		t.Fatalf("old key JWT should be accepted: %v", err)
	}
	if resp1["subject_id"] != "alice@example.com" {
		t.Errorf("old key: subject_id = %q, want %q", resp1["subject_id"], "alice@example.com")
	}

	// New key JWT.
	pairs2 := make([]string, 0, len(headersNewKey)*2)
	for k, v := range headersNewKey {
		pairs2 = append(pairs2, k, v)
	}
	ctx2 := metadata.AppendToOutgoingContext(context.Background(), pairs2...)
	var resp2 map[string]string
	err = conn.Invoke(ctx2, "/"+echoServiceName+"/GetIdentity", "test", &resp2)
	if err != nil {
		t.Fatalf("new key JWT should be accepted: %v", err)
	}
	if resp2["subject_id"] != "alice@example.com" {
		t.Errorf("new key: subject_id = %q, want %q", resp2["subject_id"], "alice@example.com")
	}
}

func TestE2E_Propagation_NoPropagator_NoIdentityForwarded(t *testing.T) {
	// 32.10: When no propagator is configured, no identity is forwarded.
	pki := newTestPKI(t)

	serverCert := pki.issueServerCert(t, "server", "localhost")
	sessMgr := session.NewManager(newMemSessionStore(), session.DefaultConfig())
	eng, _ := engine.New(engine.Config{
		UserStore:        NewMemUserStore(),
		SessionManager:   sessMgr,
		HookManager:      hooks.NewManager(),
		PasswordPolicy:   pw.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{Field: "email"},
	})

	// Server WITHOUT propagator.
	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert.tlsCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.caPool,
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Engine:      eng,
			Propagator:  nil, // NO propagator
			RequireAuth: false,
		})),
	)
	server.RegisterService(&echoServiceDesc, &echoServer{})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(func() { server.GracefulStop() })

	clientCert := pki.issueClientCert(t, "client")
	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{clientCert.tlsCert},
			RootCAs:      pki.caPool,
			ServerName:   "localhost",
		})),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a JWT header anyway — the server should ignore it (no propagator).
	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-auth-identity", "some.fake.jwt")

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}

	// No user identity (no propagator to decode).
	if resp["subject_id"] != "" {
		t.Errorf("without propagator, should have no user identity, got %q", resp["subject_id"])
	}
}

// ---------- Strictness: Additional edge-case tests ----------

func TestE2E_Propagation_RandomJunkJWT_Rejected(t *testing.T) {
	// Send complete garbage as the JWT — should not crash, no identity.
	env := buildMultiServiceEnv(t)

	conn := env.dialOrderDirect(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"x-auth-identity", "not-a-jwt-at-all-!@#$%^&*()")

	var resp map[string]string
	err := conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		// Error is acceptable.
		return
	}
	if resp["subject_id"] != "" {
		t.Error("random junk JWT should not produce identity")
	}
}

func TestE2E_Propagation_WrongSigningKey_Rejected(t *testing.T) {
	// JWT signed by a completely different key — not in the shared KeyStore.
	env := buildMultiServiceEnv(t)

	// Create a rogue propagator with its own keys.
	rogueProp, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway",           // Same issuer.
		Audience: "internal-services", // Same audience.
		TTL:      30 * time.Second,
		// NO shared KeyStore — uses its own keys.
	})
	if err != nil {
		t.Fatalf("rogue prop: %v", err)
	}

	identity := &auth.Identity{SubjectID: "evil-alice", AuthMethod: "password"}
	headers, err := rogueProp.Encode(context.Background(), identity)
	if err != nil {
		t.Fatalf("rogue encode: %v", err)
	}

	conn := env.dialOrderDirect(t)
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		return // Error is fine.
	}
	if resp["subject_id"] == "evil-alice" {
		t.Fatal("JWT from rogue signing key should NOT be accepted")
	}
}

func TestE2E_Propagation_EmptySubjectID_Handled(t *testing.T) {
	// Edge case: identity with empty SubjectID (e.g., machine-only).
	env := buildMultiServiceEnv(t)

	identity := &auth.Identity{SubjectID: "", AuthMethod: "mtls"}
	ctx := auth.SetIdentity(context.Background(), identity)
	headers, err := env.gatewayProp.Encode(ctx, identity)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	conn := env.dialOrderDirect(t)
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	ctx = metadata.AppendToOutgoingContext(context.Background(), pairs...)

	var resp map[string]string
	err = conn.Invoke(ctx, "/"+echoServiceName+"/GetIdentity", "test", &resp)
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	// Subject ID should be empty but not crash.
	if resp["subject_id"] != "" {
		t.Errorf("empty SubjectID should propagate as empty, got %q", resp["subject_id"])
	}
}
