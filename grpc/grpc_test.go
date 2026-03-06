// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authgrpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type stubUser struct {
	subjectID    string
	identifier   string
	passwordHash string
}

func (u *stubUser) GetSubjectID() string        { return u.subjectID }
func (u *stubUser) GetIdentifier() string       { return u.identifier }
func (u *stubUser) GetPasswordHash() string     { return u.passwordHash }
func (u *stubUser) GetFailedAttempts() int      { return 0 }
func (u *stubUser) IsLocked() bool              { return false }
func (u *stubUser) IsMFAEnabled() bool          { return false }
func (u *stubUser) GetMetadata() map[string]any { return nil }

type stubUserStore struct {
	users map[string]*stubUser
}

func newStubUserStore() *stubUserStore {
	return &stubUserStore{users: make(map[string]*stubUser)}
}

func (s *stubUserStore) FindByIdentifier(_ context.Context, id string) (auth.User, error) {
	u, ok := s.users[id]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

func (s *stubUserStore) Create(_ context.Context, user auth.User) error {
	return nil
}

func (s *stubUserStore) UpdatePassword(_ context.Context, _ string, _ string) error { return nil }
func (s *stubUserStore) IncrementFailedAttempts(_ context.Context, _ string) error  { return nil }
func (s *stubUserStore) ResetFailedAttempts(_ context.Context, _ string) error      { return nil }
func (s *stubUserStore) SetLocked(_ context.Context, _ string, _ bool) error        { return nil }

type stubSessionManager struct {
	sessions map[string]*session.Session
}

func newStubSessionManager() *stubSessionManager {
	return &stubSessionManager{sessions: make(map[string]*session.Session)}
}

func (m *stubSessionManager) CreateSession(_ context.Context, subjectID string, _ string, _ map[string]any) (string, *session.Session, error) {
	return "", nil, nil
}

func (m *stubSessionManager) ValidateSession(_ context.Context, rawID string) (*session.Session, error) {
	sess, ok := m.sessions[rawID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, auth.ErrSessionExpired
	}
	return sess, nil
}

func (m *stubSessionManager) RefreshSession(_ context.Context, rawID string) (*session.Session, error) {
	return nil, nil
}

func (m *stubSessionManager) DestroySession(_ context.Context, _ string) error     { return nil }
func (m *stubSessionManager) DestroyAllSessions(_ context.Context, _ string) error { return nil }

// stubPropagator implements propagator.IdentityPropagator.
type stubPropagator struct {
	encodeResult map[string]string
	encodeErr    error
	decodeResult *auth.Identity
	decodeErr    error
	encodeCalled bool
	decodeCalled bool
}

func (p *stubPropagator) Encode(_ context.Context, identity *auth.Identity) (map[string]string, error) {
	p.encodeCalled = true
	if p.encodeErr != nil {
		return nil, p.encodeErr
	}
	if p.encodeResult != nil {
		return p.encodeResult, nil
	}
	return map[string]string{
		"x-auth-identity": "encoded:" + identity.SubjectID,
	}, nil
}

func (p *stubPropagator) Decode(_ context.Context, meta map[string]string, peerWID *auth.WorkloadIdentity) (*auth.Identity, error) {
	p.decodeCalled = true
	if p.decodeErr != nil {
		return nil, p.decodeErr
	}
	if p.decodeResult != nil {
		return p.decodeResult, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildEngine(t *testing.T) (*engine.Engine, *stubSessionManager) {
	t.Helper()
	sessMgr := newStubSessionManager()
	eng, err := engine.New(engine.Config{
		UserStore:      newStubUserStore(),
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		PasswordPolicy: password.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field: "email",
		},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng, sessMgr
}

// incomingCtx creates a context with incoming gRPC metadata.
func incomingCtx(pairs ...string) context.Context {
	md := metadata.Pairs(pairs...)
	return metadata.NewIncomingContext(context.Background(), md)
}

// mtlsCtx creates a context with mTLS peer info.
func mtlsCtx(cert *x509.Certificate) context.Context {
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}
	return peer.NewContext(context.Background(), p)
}

// mtlsIncomingCtx creates a context with both mTLS peer and incoming metadata.
func mtlsIncomingCtx(cert *x509.Certificate, pairs ...string) context.Context {
	ctx := mtlsCtx(cert)
	md := metadata.Pairs(pairs...)
	return metadata.NewIncomingContext(ctx, md)
}

// generateTestCert creates a self-signed X.509 certificate for testing.
func generateTestCert(t *testing.T, cn string, uris ...*url.URL) *x509.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		URIs:         uris,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// noopUnaryHandler is a unary handler that returns the identity from context.
func noopUnaryHandler(ctx context.Context, req any) (any, error) {
	return auth.GetIdentity(ctx), nil
}

// noopStreamHandler is a stream handler that does nothing.
func noopStreamHandler(_ any, stream grpc.ServerStream) error {
	// Check identity is available in stream context.
	_ = auth.GetIdentity(stream.Context())
	return nil
}

// stubServerStream implements grpc.ServerStream for testing.
type stubServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *stubServerStream) Context() context.Context { return s.ctx }

// ---------------------------------------------------------------------------
// Tests — UnaryServerInterceptor
// ---------------------------------------------------------------------------

func TestUnaryServer_SessionToken_IdentityInContext(t *testing.T) {
	eng, sessMgr := buildEngine(t)
	sessMgr.sessions["sess-1"] = &session.Session{
		ID:        "sess-1",
		SubjectID: "alice",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine: eng,
	})

	ctx := incomingCtx("authorization", "Bearer sess-1")
	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	identity, ok := resp.(*auth.Identity)
	if !ok || identity == nil {
		t.Fatal("expected identity in context")
	}
	if identity.SubjectID != "alice" {
		t.Errorf("SubjectID = %q, want %q", identity.SubjectID, "alice")
	}
}

func TestUnaryServer_NoCredentials_Unauthenticated(t *testing.T) {
	eng, _ := buildEngine(t)

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine:      eng,
		RequireAuth: true,
	})

	ctx := incomingCtx()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)
	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

func TestUnaryServer_MTLSPeerCert_WorkloadIdentity(t *testing.T) {
	eng, _ := buildEngine(t)
	cert := generateTestCert(t, "order-service")

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine: eng,
	})

	ctx := mtlsIncomingCtx(cert)
	handler := func(ctx context.Context, req any) (any, error) {
		wid := auth.GetWorkloadIdentity(ctx)
		return wid, nil
	}

	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wid, ok := resp.(*auth.WorkloadIdentity)
	if !ok || wid == nil {
		t.Fatal("expected workload identity in context")
	}
	if wid.WorkloadID != "order-service" {
		t.Errorf("WorkloadID = %q, want %q", wid.WorkloadID, "order-service")
	}
}

func TestUnaryServer_DualIdentity(t *testing.T) {
	eng, sessMgr := buildEngine(t)
	sessMgr.sessions["sess-dual"] = &session.Session{
		ID:        "sess-dual",
		SubjectID: "bob",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	cert := generateTestCert(t, "gateway-service")

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine: eng,
	})

	ctx := mtlsIncomingCtx(cert, "authorization", "Bearer sess-dual")
	handler := func(ctx context.Context, req any) (any, error) {
		id := auth.GetIdentity(ctx)
		wid := auth.GetWorkloadIdentity(ctx)
		return []any{id, wid}, nil
	}

	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pair := resp.([]any)
	identity := pair[0].(*auth.Identity)
	wid := pair[1].(*auth.WorkloadIdentity)

	if identity.SubjectID != "bob" {
		t.Errorf("user SubjectID = %q, want %q", identity.SubjectID, "bob")
	}
	if wid.WorkloadID != "gateway-service" {
		t.Errorf("WorkloadID = %q, want %q", wid.WorkloadID, "gateway-service")
	}
}

func TestUnaryServer_PropagatorDecode(t *testing.T) {
	eng, _ := buildEngine(t)
	prop := &stubPropagator{
		decodeResult: &auth.Identity{
			SubjectID:  "propagated-user",
			AuthMethod: "jwt",
		},
	}

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine:     eng,
		Propagator: prop,
	})

	ctx := incomingCtx("x-auth-identity", "some-jwt-token")
	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !prop.decodeCalled {
		t.Fatal("Propagator.Decode should have been called")
	}

	identity, ok := resp.(*auth.Identity)
	if !ok || identity == nil {
		t.Fatal("expected propagated identity in context")
	}
	if identity.SubjectID != "propagated-user" {
		t.Errorf("SubjectID = %q, want %q", identity.SubjectID, "propagated-user")
	}
}

func TestUnaryServer_SPIFFECert_WorkloadIdentity(t *testing.T) {
	eng, _ := buildEngine(t)
	spiffeURI, _ := url.Parse("spiffe://acme.com/order-service")
	cert := generateTestCert(t, "order-service", spiffeURI)

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine: eng,
	})

	ctx := mtlsIncomingCtx(cert)
	handler := func(ctx context.Context, req any) (any, error) {
		return auth.GetWorkloadIdentity(ctx), nil
	}

	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wid, ok := resp.(*auth.WorkloadIdentity)
	if !ok || wid == nil {
		t.Fatal("expected SPIFFE workload identity")
	}
	if wid.WorkloadID != "spiffe://acme.com/order-service" {
		t.Errorf("WorkloadID = %q, want %q", wid.WorkloadID, "spiffe://acme.com/order-service")
	}
	if wid.TrustDomain != "acme.com" {
		t.Errorf("TrustDomain = %q, want %q", wid.TrustDomain, "acme.com")
	}
}

// ---------------------------------------------------------------------------
// Tests — StreamServerInterceptor
// ---------------------------------------------------------------------------

func TestStreamServer_SessionToken_IdentityAvailable(t *testing.T) {
	eng, sessMgr := buildEngine(t)
	sessMgr.sessions["stream-sess"] = &session.Session{
		ID:        "stream-sess",
		SubjectID: "stream-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	interceptor := authgrpc.StreamServerInterceptor(authgrpc.ServerConfig{
		Engine: eng,
	})

	ctx := incomingCtx("authorization", "Bearer stream-sess")
	stream := &stubServerStream{ctx: ctx}

	var gotIdentity *auth.Identity
	handler := func(_ any, ss grpc.ServerStream) error {
		gotIdentity = auth.GetIdentity(ss.Context())
		return nil
	}

	err := interceptor(nil, stream, &grpc.StreamServerInfo{}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotIdentity == nil || gotIdentity.SubjectID != "stream-user" {
		t.Fatal("identity not available in stream context")
	}
}

func TestStreamServer_NoCredentials_Unauthenticated(t *testing.T) {
	eng, _ := buildEngine(t)

	interceptor := authgrpc.StreamServerInterceptor(authgrpc.ServerConfig{
		Engine:      eng,
		RequireAuth: true,
	})

	ctx := incomingCtx()
	stream := &stubServerStream{ctx: ctx}

	err := interceptor(nil, stream, &grpc.StreamServerInfo{}, noopStreamHandler)
	if err == nil {
		t.Fatal("expected error for unauthenticated stream")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

// ---------------------------------------------------------------------------
// Tests — UnaryClientInterceptor
// ---------------------------------------------------------------------------

func TestUnaryClient_IdentityPropagated(t *testing.T) {
	prop := &stubPropagator{
		encodeResult: map[string]string{
			"x-auth-identity": "encoded:alice",
		},
	}

	interceptor := authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
		Propagator: prop,
	})

	identity := &auth.Identity{SubjectID: "alice"}
	ctx := auth.SetIdentity(context.Background(), identity)

	var capturedCtx context.Context
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		capturedCtx = ctx
		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", nil, nil, nil, invoker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !prop.encodeCalled {
		t.Fatal("Propagator.Encode should have been called")
	}

	// Verify metadata was attached.
	md, ok := metadata.FromOutgoingContext(capturedCtx)
	if !ok {
		t.Fatal("no outgoing metadata")
	}
	vals := md.Get("x-auth-identity")
	if len(vals) == 0 || vals[0] != "encoded:alice" {
		t.Errorf("x-auth-identity = %v, want [encoded:alice]", vals)
	}
}

func TestUnaryClient_NoIdentity_NoMetadata(t *testing.T) {
	prop := &stubPropagator{}

	interceptor := authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
		Propagator: prop,
	})

	ctx := context.Background() // No identity.

	var capturedCtx context.Context
	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		capturedCtx = ctx
		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", nil, nil, nil, invoker)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if prop.encodeCalled {
		t.Fatal("Propagator.Encode should NOT be called when no identity")
	}

	// Should not have identity metadata.
	md, _ := metadata.FromOutgoingContext(capturedCtx)
	vals := md.Get("x-auth-identity")
	if len(vals) > 0 {
		t.Errorf("should not have identity metadata, got %v", vals)
	}
}

// ---------------------------------------------------------------------------
// Tests — StreamClientInterceptor
// ---------------------------------------------------------------------------

func TestStreamClient_IdentityPropagated(t *testing.T) {
	prop := &stubPropagator{
		encodeResult: map[string]string{
			"x-auth-identity": "encoded:bob",
		},
	}

	interceptor := authgrpc.StreamClientInterceptor(authgrpc.ClientConfig{
		Propagator: prop,
	})

	identity := &auth.Identity{SubjectID: "bob"}
	ctx := auth.SetIdentity(context.Background(), identity)

	var capturedCtx context.Context
	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		capturedCtx = ctx
		return nil, nil
	}

	_, err := interceptor(ctx, &grpc.StreamDesc{}, nil, "/test.Service/Stream", streamer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !prop.encodeCalled {
		t.Fatal("Propagator.Encode should have been called for stream")
	}

	md, ok := metadata.FromOutgoingContext(capturedCtx)
	if !ok {
		t.Fatal("no outgoing metadata for stream")
	}
	vals := md.Get("x-auth-identity")
	if len(vals) == 0 || vals[0] != "encoded:bob" {
		t.Errorf("stream x-auth-identity = %v, want [encoded:bob]", vals)
	}
}

func TestStreamClient_BidirectionalStream_IdentityPropagated(t *testing.T) {
	prop := &stubPropagator{
		encodeResult: map[string]string{
			"x-auth-identity": "encoded:charlie",
		},
	}

	interceptor := authgrpc.StreamClientInterceptor(authgrpc.ClientConfig{
		Propagator: prop,
	})

	identity := &auth.Identity{SubjectID: "charlie"}
	ctx := auth.SetIdentity(context.Background(), identity)

	var capturedCtx context.Context
	streamer := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		capturedCtx = ctx
		return nil, nil
	}

	desc := &grpc.StreamDesc{
		ClientStreams: true,
		ServerStreams: true,
	}
	_, err := interceptor(ctx, desc, nil, "/test.Service/BiDiStream", streamer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	md, ok := metadata.FromOutgoingContext(capturedCtx)
	if !ok {
		t.Fatal("no outgoing metadata for bidirectional stream")
	}
	vals := md.Get("x-auth-identity")
	if len(vals) == 0 || vals[0] != "encoded:charlie" {
		t.Errorf("bidi stream x-auth-identity = %v, want [encoded:charlie]", vals)
	}
}

// ---------------------------------------------------------------------------
// Tests — Auth failure status codes
// ---------------------------------------------------------------------------

func TestUnaryServer_AuthFailure_CorrectStatusCode(t *testing.T) {
	eng, _ := buildEngine(t)

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine:      eng,
		RequireAuth: true,
	})

	// No credentials.
	ctx := incomingCtx()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

func TestUnaryServer_InvalidSession_WithRequireAuth(t *testing.T) {
	eng, _ := buildEngine(t)

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine:      eng,
		RequireAuth: true,
	})

	ctx := incomingCtx("authorization", "Bearer nonexistent-session")
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("expected gRPC status error")
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

// ---------------------------------------------------------------------------
// Tests — Optional auth (RequireAuth=false)
// ---------------------------------------------------------------------------

func TestUnaryServer_OptionalAuth_NoCredentials_NilIdentity(t *testing.T) {
	eng, _ := buildEngine(t)

	interceptor := authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
		Engine:      eng,
		RequireAuth: false,
	})

	ctx := incomingCtx()
	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, noopUnaryHandler)
	if err != nil {
		t.Fatalf("optional auth should not error: %v", err)
	}

	if resp != nil {
		if identity, ok := resp.(*auth.Identity); ok && identity != nil {
			t.Error("expected nil identity for optional auth without credentials")
		}
	}
}

// ---------------------------------------------------------------------------
// Tests — NilPropagator
// ---------------------------------------------------------------------------

func TestUnaryClient_NilPropagator_NoError(t *testing.T) {
	interceptor := authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
		Propagator: nil,
	})

	identity := &auth.Identity{SubjectID: "alice"}
	ctx := auth.SetIdentity(context.Background(), identity)

	invoker := func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
		return nil
	}

	err := interceptor(ctx, "/test.Service/Method", nil, nil, nil, invoker)
	if err != nil {
		t.Fatalf("nil propagator should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests — gRPC per-RPC credential model compatibility
// ---------------------------------------------------------------------------

func TestStreamServer_MTLSPeer_WorkloadIdentityThroughoutStream(t *testing.T) {
	eng, _ := buildEngine(t)
	cert := generateTestCert(t, "streaming-service")

	interceptor := authgrpc.StreamServerInterceptor(authgrpc.ServerConfig{
		Engine: eng,
	})

	ctx := mtlsIncomingCtx(cert)
	stream := &stubServerStream{ctx: ctx}

	var gotWID *auth.WorkloadIdentity
	handler := func(_ any, ss grpc.ServerStream) error {
		gotWID = auth.GetWorkloadIdentity(ss.Context())
		return nil
	}

	err := interceptor(nil, stream, &grpc.StreamServerInfo{}, handler)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotWID == nil || gotWID.WorkloadID != "streaming-service" {
		t.Fatal("workload identity not available throughout stream")
	}
}
