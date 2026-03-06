// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a pluggable authentication library for Go applications.
//
// The library handles credential verification, session management, identity
// propagation, and protocol bindings (HTTP middleware, gRPC interceptors).
// It produces a canonical Identity value in context.Context — business logic
// reads identity from context and never imports auth internals.
//
// Usage:
//
//	identity := auth.GetIdentity(ctx)
package auth

import (
	"context"
	"time"
)

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey int

const (
	identityKey         contextKey = iota
	workloadIdentityKey contextKey = iota
)

// Identity represents an authenticated user. This is the canonical output
// of the auth library — it goes into context.Context and is the only contract
// between the auth library and business logic.
type Identity struct {
	// SubjectID is the user identifier (whatever the team configured via IdentifierConfig).
	// Empty for system-to-system (machine-only) requests.
	SubjectID string

	// AuthMethod describes how the identity was established:
	// "password", "oauth2", "magic_link", "api_key", "mtls", "spiffe".
	AuthMethod string

	// AuthTime is when authentication occurred.
	AuthTime time.Time

	// SessionID is the current session ID. Empty for stateless/S2S auth.
	SessionID string

	// WorkloadID is the SPIFFE ID or service name. Empty for direct user requests.
	WorkloadID string

	// TrustDomain is the workload trust domain (e.g., "acme.com").
	TrustDomain string

	// Metadata holds extensible custom claims. Teams attach additional attributes via hooks.
	Metadata map[string]any
}

// WorkloadIdentity represents an authenticated service/workload (machine identity).
// Used for system-to-system authentication via mTLS or SPIFFE.
type WorkloadIdentity struct {
	// WorkloadID is the SPIFFE ID or CN from the client certificate.
	WorkloadID string

	// TrustDomain is the workload trust domain.
	TrustDomain string

	// Metadata holds extensible attributes for the workload.
	Metadata map[string]any
}

// GetIdentity retrieves the user identity from context.
// Returns nil if no identity is set (unauthenticated request).
func GetIdentity(ctx context.Context) *Identity {
	val := ctx.Value(identityKey)
	if val == nil {
		return nil
	}
	id, ok := val.(*Identity)
	if !ok {
		return nil
	}
	return id
}

// SetIdentity stores a user identity in context.
// Returns a new context — the original context is not modified.
func SetIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// GetWorkloadIdentity retrieves the workload (machine) identity from context.
// Returns nil if no workload identity is set.
func GetWorkloadIdentity(ctx context.Context) *WorkloadIdentity {
	val := ctx.Value(workloadIdentityKey)
	if val == nil {
		return nil
	}
	wid, ok := val.(*WorkloadIdentity)
	if !ok {
		return nil
	}
	return wid
}

// SetWorkloadIdentity stores a workload identity in context.
// Returns a new context — the original context is not modified.
func SetWorkloadIdentity(ctx context.Context, wid *WorkloadIdentity) context.Context {
	return context.WithValue(ctx, workloadIdentityKey, wid)
}
