// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authgrpc — server.go provides gRPC server interceptors for auth.
//
// UnaryServerInterceptor and StreamServerInterceptor extract credentials from
// incoming metadata and mTLS peer certificates, validate them via the engine,
// and inject Identity / WorkloadIdentity into context.
package authgrpc

import (
	"context"
	"crypto/x509"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	"github.com/abhipray-cpu/auth/propagator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServerConfig configures the gRPC server interceptors.
type ServerConfig struct {
	// Engine is the auth engine for session validation.
	Engine *engine.Engine

	// Propagator decodes inbound identity from metadata.
	// If nil, only session-based auth is supported.
	Propagator propagator.IdentityPropagator

	// RequireAuth requires authentication for all RPCs when true.
	// When false, unauthenticated requests get nil identity.
	RequireAuth bool
}

// UnaryServerInterceptor returns a gRPC unary server interceptor that
// authenticates incoming requests.
//
// Authentication order:
//  1. mTLS peer cert → WorkloadIdentity in context
//  2. Propagated identity headers → Identity in context (via IdentityPropagator.Decode)
//  3. Session token (Bearer) in metadata → Identity in context (via engine.Verify)
func UnaryServerInterceptor(cfg ServerConfig) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		ctx, err := authenticateServer(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that
// authenticates incoming streams. The identity is available throughout the stream.
func StreamServerInterceptor(cfg ServerConfig) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		_ *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx, err := authenticateServer(ss.Context(), cfg)
		if err != nil {
			return err
		}
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// authenticateServer performs server-side authentication.
func authenticateServer(ctx context.Context, cfg ServerConfig) (context.Context, error) {
	authenticated := false

	// 1. Extract mTLS peer certificate → WorkloadIdentity.
	peerCerts := extractPeerCertificates(ctx)
	if len(peerCerts) > 0 {
		wid := workloadIdentityFromCert(peerCerts[0])
		if wid != nil {
			ctx = auth.SetWorkloadIdentity(ctx, wid)
			authenticated = true
		}
	}

	// 2. Try identity propagation headers (e.g., signed JWT from upstream).
	if cfg.Propagator != nil {
		propagatedMeta := extractPropagatedIdentity(ctx)
		if propagatedMeta != nil {
			// Get workload identity for peer context.
			var peerWID *auth.WorkloadIdentity
			if wid := auth.GetWorkloadIdentity(ctx); wid != nil {
				peerWID = wid
			}
			identity, err := cfg.Propagator.Decode(ctx, propagatedMeta, peerWID)
			if err == nil && identity != nil {
				ctx = auth.SetIdentity(ctx, identity)
				authenticated = true
			}
		}
	}

	// 3. Try session token in metadata (Bearer token).
	if auth.GetIdentity(ctx) == nil {
		token := extractSessionToken(ctx)
		if token != "" && cfg.Engine != nil {
			identity, err := cfg.Engine.Verify(ctx, token)
			if err == nil && identity != nil {
				ctx = auth.SetIdentity(ctx, identity)
				authenticated = true
			}
		}
	}

	// Check if auth is required.
	if cfg.RequireAuth && !authenticated {
		return ctx, status.Error(codes.Unauthenticated, "authentication required")
	}

	return ctx, nil
}

// workloadIdentityFromCert extracts a WorkloadIdentity from an X.509 certificate.
// Checks for SPIFFE ID in SAN URIs first, falls back to CN.
func workloadIdentityFromCert(cert *x509.Certificate) *auth.WorkloadIdentity {
	if cert == nil {
		return nil
	}

	// Check for SPIFFE ID in URI SANs.
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return &auth.WorkloadIdentity{
				WorkloadID:  uri.String(),
				TrustDomain: uri.Host,
				Metadata: map[string]any{
					"cert_serial":  cert.SerialNumber.String(),
					"cert_subject": cert.Subject.CommonName,
				},
			}
		}
	}

	// Fall back to CN.
	if cert.Subject.CommonName != "" {
		return &auth.WorkloadIdentity{
			WorkloadID: cert.Subject.CommonName,
			Metadata: map[string]any{
				"cert_serial": cert.SerialNumber.String(),
			},
		}
	}

	return nil
}

// wrappedServerStream wraps a grpc.ServerStream with a custom context.
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the wrapped context.
func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
