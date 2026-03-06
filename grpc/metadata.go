// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authgrpc — metadata.go provides helpers for reading and writing
// identity metadata in gRPC call context.
package authgrpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// metadataKey is the gRPC metadata key for session tokens.
const metadataKey = "authorization"

// identityMetadataPrefix is the prefix for identity propagation metadata keys.
const identityMetadataPrefix = "x-auth-"

// extractSessionToken reads the session/bearer token from gRPC metadata.
// Supports "Bearer <token>" format in the "authorization" metadata key.
func extractSessionToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	vals := md.Get(metadataKey)
	for _, v := range vals {
		if strings.HasPrefix(v, "Bearer ") {
			return strings.TrimPrefix(v, "Bearer ")
		}
		// Allow raw token without Bearer prefix.
		if v != "" && !strings.Contains(v, " ") {
			return v
		}
	}
	return ""
}

// extractPropagatedIdentity reads identity propagation metadata from incoming context.
func extractPropagatedIdentity(ctx context.Context) map[string]string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	result := make(map[string]string)
	for k, vals := range md {
		if strings.HasPrefix(k, identityMetadataPrefix) && len(vals) > 0 {
			result[k] = vals[0]
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// attachOutgoingIdentity attaches identity propagation metadata to outgoing context.
func attachOutgoingIdentity(ctx context.Context, headers map[string]string) context.Context {
	pairs := make([]string, 0, len(headers)*2)
	for k, v := range headers {
		pairs = append(pairs, k, v)
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

// extractPeerCertificates reads the TLS client certificates from the gRPC peer info.
// Returns nil if no mTLS peer is available.
func extractPeerCertificates(ctx context.Context) []*x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}

	state := tlsInfo.State
	return peerCertsFromState(state)
}

// peerCertsFromState extracts peer certificates from a TLS connection state.
func peerCertsFromState(state tls.ConnectionState) []*x509.Certificate {
	if len(state.PeerCertificates) > 0 {
		return state.PeerCertificates
	}
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		return state.VerifiedChains[0]
	}
	return nil
}
