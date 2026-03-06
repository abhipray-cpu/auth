// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package propagator — session.go implements SessionPropagator.
//
// SessionPropagator is the simplest identity propagator. It forwards
// the session ID to downstream services, which re-validate it against
// the shared SessionStore. This gives instant revocation: deleting a
// session means all services immediately lose access.
package propagator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"
)

// SessionPropagatorConfig configures the SessionPropagator.
type SessionPropagatorConfig struct {
	// Store is the session store used to validate session IDs.
	// Required.
	Store session.SessionStore

	// NowFunc returns the current time. Defaults to time.Now.
	NowFunc func() time.Time
}

// SessionPropagator implements IdentityPropagator by forwarding
// session IDs between services.
type SessionPropagator struct {
	store   session.SessionStore
	nowFunc func() time.Time
}

// NewSessionPropagator creates a new SessionPropagator.
func NewSessionPropagator(cfg SessionPropagatorConfig) (*SessionPropagator, error) {
	if cfg.Store == nil {
		return nil, errors.New("propagator: Store is required")
	}

	nowFunc := cfg.NowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}

	return &SessionPropagator{
		store:   cfg.Store,
		nowFunc: nowFunc,
	}, nil
}

// Metadata key for the session ID.
const headerKeySession = "x-auth-session-id"

// Encode puts the session ID from the identity into metadata for
// outgoing requests.
func (p *SessionPropagator) Encode(ctx context.Context, identity *auth.Identity) (map[string]string, error) {
	if identity == nil {
		return nil, errors.New("propagator: identity is nil")
	}

	if identity.SessionID == "" {
		return nil, errors.New("propagator: identity has no session ID")
	}

	return map[string]string{
		headerKeySession: identity.SessionID,
	}, nil
}

// Decode reads the session ID from metadata, validates it against
// the SessionStore, and reconstructs the identity.
func (p *SessionPropagator) Decode(ctx context.Context, metadata map[string]string, _ *auth.WorkloadIdentity) (*auth.Identity, error) {
	sessionID, ok := metadata[headerKeySession]
	if !ok || sessionID == "" {
		return nil, errors.New("propagator: no session ID in metadata")
	}

	sess, err := p.store.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("propagator: session lookup failed: %w", err)
	}

	if sess == nil {
		return nil, errors.New("propagator: session not found")
	}

	// Check expiry.
	now := p.nowFunc()
	if now.After(sess.ExpiresAt) {
		return nil, errors.New("propagator: session has expired")
	}

	return &auth.Identity{
		SubjectID: sess.SubjectID,
		SessionID: sess.ID,
		Metadata:  make(map[string]any),
	}, nil
}

// Compile-time interface check.
var _ IdentityPropagator = (*SessionPropagator)(nil)
