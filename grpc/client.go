// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authgrpc — client.go provides gRPC client interceptors.
//
// UnaryClientInterceptor and StreamClientInterceptor read the Identity
// from context, encode it via IdentityPropagator.Encode, and attach the
// result to outgoing gRPC metadata.
package authgrpc

import (
	"context"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/propagator"
	"google.golang.org/grpc"
)

// ClientConfig configures the gRPC client interceptors.
type ClientConfig struct {
	// Propagator encodes identity for outbound calls.
	// If nil, no identity is propagated.
	Propagator propagator.IdentityPropagator
}

// UnaryClientInterceptor returns a gRPC unary client interceptor that
// propagates identity from context to outgoing metadata.
//
// If no identity is in context, no metadata is attached — the call proceeds
// without identity propagation.
func UnaryClientInterceptor(cfg ClientConfig) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		ctx = propagateOutgoing(ctx, cfg)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// StreamClientInterceptor returns a gRPC stream client interceptor that
// propagates identity from context to outgoing metadata for streaming calls.
func StreamClientInterceptor(cfg ClientConfig) grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		ctx = propagateOutgoing(ctx, cfg)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// propagateOutgoing reads identity from context and attaches encoded metadata.
func propagateOutgoing(ctx context.Context, cfg ClientConfig) context.Context {
	if cfg.Propagator == nil {
		return ctx
	}

	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return ctx
	}

	headers, err := cfg.Propagator.Encode(ctx, identity)
	if err != nil {
		// Propagation failure is logged but doesn't fail the call.
		return ctx
	}

	if len(headers) == 0 {
		return ctx
	}

	return attachOutgoingIdentity(ctx, headers)
}
