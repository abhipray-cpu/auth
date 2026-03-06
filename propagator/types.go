// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package propagator

import (
	"context"
	"time"

	"github.com/abhipray-cpu/auth"
)

// IdentityPropagator controls how user identity travels between services.
// The library ships three implementations: SignedJWTPropagator (default),
// SessionPropagator, and SPIFFEPropagator.
type IdentityPropagator interface {
	// Encode takes an identity and produces metadata key-value pairs
	// to attach to outgoing requests (HTTP headers, gRPC metadata).
	Encode(ctx context.Context, identity *auth.Identity) (map[string]string, error)

	// Decode reads metadata from an incoming request and reconstructs
	// the identity. The optional peerIdentity carries the mTLS peer
	// identity if available.
	Decode(ctx context.Context, metadata map[string]string, peerIdentity *auth.WorkloadIdentity) (*auth.Identity, error)
}

// PropagatorConfig configures identity propagation behavior.
type PropagatorConfig struct {
	// Strategy selects the propagation implementation.
	// Valid values: "signed-jwt" (default), "session", "spiffe".
	Strategy string

	// JWTIssuer is the issuer claim for SignedJWTPropagator JWTs.
	JWTIssuer string

	// JWTAudience is the audience claim for SignedJWTPropagator JWTs.
	JWTAudience string

	// JWTTTL is the time-to-live for SignedJWTPropagator JWTs.
	JWTTTL time.Duration

	// JWKSEndpoint is the URL where the public verification key is served.
	JWKSEndpoint string

	// SPIFFESocketPath is the path to the SPIRE Workload API socket.
	SPIFFESocketPath string

	// TrustedIssuers lists the JWT issuers that this service trusts
	// for inbound identity verification.
	TrustedIssuers []string
}

// DefaultConfig returns a PropagatorConfig with sensible defaults.
func DefaultConfig() PropagatorConfig {
	return PropagatorConfig{
		Strategy:         "signed-jwt",
		JWTTTL:           30 * time.Second,
		JWKSEndpoint:     "/.well-known/auth-keys",
		TrustedIssuers:   nil,
		SPIFFESocketPath: "",
	}
}
