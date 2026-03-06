// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"log/slog"
	"sync"
)

// Event identifies a lifecycle event. This is intentionally a plain string
// type so the hooks package has no import dependency on the auth package,
// preventing import cycles. The auth package passes its AuthEvent values
// (which are also strings) directly.
type Event string

// HookFn is the callback signature for lifecycle hooks.
// It receives a context and a typed payload. Returning an error from a
// "before" hook aborts the flow; errors from "after" hooks are logged.
type HookFn func(ctx context.Context, payload HookPayload) error

// Manager manages lifecycle event hooks. Thread-safe for concurrent
// registration and emission. Hooks are called in registration order.
type Manager struct {
	mu    sync.RWMutex
	hooks map[Event][]HookFn
}

// NewManager creates a new HookManager.
func NewManager() *Manager {
	return &Manager{
		hooks: make(map[Event][]HookFn),
	}
}

// Register adds a hook callback for the given event. Multiple hooks can
// be registered per event; they will be called in registration order.
// Thread-safe.
func (m *Manager) Register(event Event, fn HookFn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks[event] = append(m.hooks[event], fn)
}

// EmitBefore emits a "before" event. Hooks are called in registration order.
// If any hook returns an error, execution stops and the error is returned
// (aborting the flow). Returns nil if no hooks are registered or all succeed.
func (m *Manager) EmitBefore(ctx context.Context, event Event, payload HookPayload) error {
	m.mu.RLock()
	fns := make([]HookFn, len(m.hooks[event]))
	copy(fns, m.hooks[event])
	m.mu.RUnlock()

	for _, fn := range fns {
		if err := fn(ctx, payload); err != nil {
			return err
		}
	}
	return nil
}

// EmitAfter emits an "after" event. Hooks are called in registration order.
// Errors from hooks are logged but do NOT fail the flow — the operation
// has already succeeded by this point. Returns nil always.
func (m *Manager) EmitAfter(ctx context.Context, event Event, payload HookPayload) {
	m.mu.RLock()
	fns := make([]HookFn, len(m.hooks[event]))
	copy(fns, m.hooks[event])
	m.mu.RUnlock()

	for _, fn := range fns {
		if err := fn(ctx, payload); err != nil {
			slog.Warn("auth/hooks: after-hook error",
				"event", string(event),
				"error", err,
			)
		}
	}
}

// HasHooks returns whether any hooks are registered for the given event.
func (m *Manager) HasHooks(event Event) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.hooks[event]) > 0
}
