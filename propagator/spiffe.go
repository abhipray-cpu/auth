// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package propagator — spiffe.go implements SPIFFEPropagator.
//
// SPIFFEPropagator delegates identity propagation to the SPIRE Workload
// API for JWT-SVID signing and verification. This means zero key
// management by the auth library — SPIRE handles everything.
//
// This is a pluggable implementation: the actual SPIRE Workload API
// interaction is abstracted behind the WorkloadAPIClient interface,
// so callers can provide their own implementation or use a mock in tests.
package propagator

import (
	"context"
	"errors"
	"fmt"

	"github.com/abhipray-cpu/auth"
)

// Metadata key for the JWT-SVID.
const headerKeySPIFFE = "x-auth-spiffe-svid"

// WorkloadAPIClient abstracts the SPIRE Workload API.
// Callers provide an implementation that wraps the actual SPIRE SDK.
type WorkloadAPIClient interface {
	// FetchJWTSVID requests a JWT-SVID from the SPIRE agent for the given
	// audience. Returns the serialized JWT-SVID token.
	FetchJWTSVID(ctx context.Context, audience string) (string, error)

	// ValidateJWTSVID verifies a JWT-SVID against the SPIRE trust bundle
	// for the given audience. Returns the SPIFFE ID from the token.
	ValidateJWTSVID(ctx context.Context, token string, audience string) (spiffeID string, err error)
}

// SPIFFEPropagatorConfig configures the SPIFFEPropagator.
type SPIFFEPropagatorConfig struct {
	// Client is the SPIRE Workload API client. Required.
	Client WorkloadAPIClient

	// Audience is the intended audience for JWT-SVIDs. Required.
	Audience string
}

// SPIFFEPropagator implements IdentityPropagator using SPIRE JWT-SVIDs.
type SPIFFEPropagator struct {
	client   WorkloadAPIClient
	audience string
}

// NewSPIFFEPropagator creates a new SPIFFEPropagator.
func NewSPIFFEPropagator(cfg SPIFFEPropagatorConfig) (*SPIFFEPropagator, error) {
	if cfg.Client == nil {
		return nil, errors.New("propagator: WorkloadAPIClient is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("propagator: Audience is required")
	}

	return &SPIFFEPropagator{
		client:   cfg.Client,
		audience: cfg.Audience,
	}, nil
}

// Encode requests a JWT-SVID from SPIRE and puts it in metadata
// for outgoing requests.
func (p *SPIFFEPropagator) Encode(ctx context.Context, identity *auth.Identity) (map[string]string, error) {
	if identity == nil {
		return nil, errors.New("propagator: identity is nil")
	}

	svid, err := p.client.FetchJWTSVID(ctx, p.audience)
	if err != nil {
		return nil, fmt.Errorf("propagator: fetch JWT-SVID: %w", err)
	}

	return map[string]string{
		headerKeySPIFFE: svid,
	}, nil
}

// Decode verifies a JWT-SVID from metadata via the SPIRE Workload API
// and reconstructs the identity.
func (p *SPIFFEPropagator) Decode(ctx context.Context, metadata map[string]string, _ *auth.WorkloadIdentity) (*auth.Identity, error) {
	token, ok := metadata[headerKeySPIFFE]
	if !ok || token == "" {
		return nil, errors.New("propagator: no SPIFFE JWT-SVID in metadata")
	}

	spiffeID, err := p.client.ValidateJWTSVID(ctx, token, p.audience)
	if err != nil {
		return nil, fmt.Errorf("propagator: validate JWT-SVID: %w", err)
	}

	return &auth.Identity{
		SubjectID:  "",
		AuthMethod: "spiffe",
		WorkloadID: spiffeID,
		Metadata:   make(map[string]any),
	}, nil
}

// Compile-time interface check.
var _ IdentityPropagator = (*SPIFFEPropagator)(nil)
