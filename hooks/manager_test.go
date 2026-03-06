// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Event constants mirroring auth.AuthEvent values.
// Defined here to avoid import cycle (hooks tests can't import auth).
const (
	testEventRegistration  Event = "registration"
	testEventLogin         Event = "login"
	testEventLoginFailed   Event = "login_failed"
	testEventLogout        Event = "logout"
	testEventPasswordReset Event = "password_reset"
	testEventMagicLinkSent Event = "magic_link_sent"
	testEventAccountLocked Event = "account_locked"
)

// --- Test 5.1: Register and Emit ---

func TestHookManager_RegisterAndEmit(t *testing.T) {
	m := NewManager()
	called := false

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		called = true
		return nil
	})

	m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{Identifier: "alice"})
	if !called {
		t.Fatal("hook was not called")
	}
}

// --- Test 5.2: Multiple hooks ---

func TestHookManager_MultipleHooks(t *testing.T) {
	m := NewManager()
	var calls []int

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		calls = append(calls, 1)
		return nil
	})
	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		calls = append(calls, 2)
		return nil
	})
	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		calls = append(calls, 3)
		return nil
	})

	m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{})
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(calls))
	}
}

// --- Test 5.3: Hooks called in registration order ---

func TestHookManager_Order(t *testing.T) {
	m := NewManager()
	var order []string

	m.Register(testEventRegistration, func(ctx context.Context, p HookPayload) error {
		order = append(order, "first")
		return nil
	})
	m.Register(testEventRegistration, func(ctx context.Context, p HookPayload) error {
		order = append(order, "second")
		return nil
	})
	m.Register(testEventRegistration, func(ctx context.Context, p HookPayload) error {
		order = append(order, "third")
		return nil
	})

	m.EmitBefore(context.Background(), testEventRegistration, &RegisterPayload{})
	if order[0] != "first" || order[1] != "second" || order[2] != "third" {
		t.Fatalf("hooks called out of order: %v", order)
	}
}

// --- Test 5.4: BeforeLogin receives correct payload ---

func TestHookManager_BeforeLogin(t *testing.T) {
	m := NewManager()
	var received *LoginPayload

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		lp, ok := p.(*LoginPayload)
		if !ok {
			t.Fatal("expected *LoginPayload")
		}
		received = lp
		return nil
	})

	m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{
		Identifier: "alice@example.com",
		AuthMethod: "password",
	})

	if received == nil {
		t.Fatal("hook was not called")
	}
	if received.Identifier != "alice@example.com" {
		t.Errorf("expected identifier alice@example.com, got %s", received.Identifier)
	}
	if received.AuthMethod != "password" {
		t.Errorf("expected AuthMethod password, got %s", received.AuthMethod)
	}
}

// --- Test 5.5: AfterLogin receives user + session ---

func TestHookManager_AfterLogin(t *testing.T) {
	m := NewManager()
	var received *LoginPayload

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		received = p.(*LoginPayload)
		return nil
	})

	m.EmitAfter(context.Background(), testEventLogin, &LoginPayload{
		Identifier: "alice",
		SubjectID:  "user-123",
		SessionID:  "sess-456",
		AuthMethod: "password",
	})

	if received == nil {
		t.Fatal("after hook was not called")
	}
	if received.SubjectID != "user-123" {
		t.Errorf("expected SubjectID user-123, got %s", received.SubjectID)
	}
	if received.SessionID != "sess-456" {
		t.Errorf("expected SessionID sess-456, got %s", received.SessionID)
	}
}

// --- Test 5.6: AfterFailedLogin fires ---

func TestHookManager_AfterFailedLogin(t *testing.T) {
	m := NewManager()
	var received *LoginPayload

	m.Register(testEventLoginFailed, func(ctx context.Context, p HookPayload) error {
		received = p.(*LoginPayload)
		return nil
	})

	testErr := errors.New("wrong password")
	m.EmitAfter(context.Background(), testEventLoginFailed, &LoginPayload{
		Identifier: "alice",
		AuthMethod: "password",
		Error:      testErr,
	})

	if received == nil {
		t.Fatal("after failed login hook was not called")
	}
	if received.Error != testErr {
		t.Error("expected error in payload")
	}
}

// --- Test 5.7: BeforeRegister can abort registration ---

func TestHookManager_BeforeRegister(t *testing.T) {
	m := NewManager()
	abortErr := errors.New("registration blocked by policy")

	m.Register(testEventRegistration, func(ctx context.Context, p HookPayload) error {
		rp := p.(*RegisterPayload)
		if rp.Identifier == "blocked@example.com" {
			return abortErr
		}
		return nil
	})

	err := m.EmitBefore(context.Background(), testEventRegistration, &RegisterPayload{
		Identifier: "blocked@example.com",
		AuthMethod: "password",
	})

	if !errors.Is(err, abortErr) {
		t.Fatalf("expected abort error, got %v", err)
	}
}

// --- Test 5.8: AfterRegister receives user + session ---

func TestHookManager_AfterRegister(t *testing.T) {
	m := NewManager()
	var received *RegisterPayload

	m.Register(testEventRegistration, func(ctx context.Context, p HookPayload) error {
		received = p.(*RegisterPayload)
		return nil
	})

	m.EmitAfter(context.Background(), testEventRegistration, &RegisterPayload{
		Identifier: "bob",
		SubjectID:  "user-789",
		SessionID:  "sess-012",
		AuthMethod: "password",
	})

	if received == nil {
		t.Fatal("after register hook was not called")
	}
	if received.SubjectID != "user-789" {
		t.Errorf("expected SubjectID user-789, got %s", received.SubjectID)
	}
	if received.SessionID != "sess-012" {
		t.Errorf("expected SessionID sess-012, got %s", received.SessionID)
	}
}

// --- Test 5.9: AfterLogout fires ---

func TestHookManager_AfterLogout(t *testing.T) {
	m := NewManager()
	var received *LogoutPayload

	m.Register(testEventLogout, func(ctx context.Context, p HookPayload) error {
		received = p.(*LogoutPayload)
		return nil
	})

	m.EmitAfter(context.Background(), testEventLogout, &LogoutPayload{
		SubjectID:  "user-123",
		SessionID:  "sess-456",
		AuthMethod: "password",
	})

	if received == nil {
		t.Fatal("logout hook was not called")
	}
	if received.SubjectID != "user-123" {
		t.Errorf("expected SubjectID user-123, got %s", received.SubjectID)
	}
}

// --- Test 5.10: No panic when no hooks registered ---

func TestHookManager_NoHooksRegistered(t *testing.T) {
	m := NewManager()

	// Should not panic.
	err := m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// EmitAfter also should not panic.
	m.EmitAfter(context.Background(), testEventLogout, &LogoutPayload{})
}

// --- Test 5.11: Before hook abort stops subsequent hooks ---

func TestHookManager_BeforeHookAbort(t *testing.T) {
	m := NewManager()
	abortErr := errors.New("abort")
	secondCalled := false

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		return abortErr
	})
	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		secondCalled = true
		return nil
	})

	err := m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{})
	if !errors.Is(err, abortErr) {
		t.Fatalf("expected abort error, got %v", err)
	}
	if secondCalled {
		t.Fatal("second hook should not have been called after abort")
	}
}

// --- Test 5.12: After hook error logged but doesn't fail ---

func TestHookManager_AfterHookError(t *testing.T) {
	m := NewManager()
	secondCalled := false

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		return errors.New("hook error")
	})
	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		secondCalled = true
		return nil
	})

	// EmitAfter should not panic and should call all hooks.
	m.EmitAfter(context.Background(), testEventLogin, &LoginPayload{})

	if !secondCalled {
		t.Fatal("second hook should still be called even when first errors")
	}
}

// --- Test 5.13: Concurrency safety ---

func TestHookManager_Concurrency(t *testing.T) {
	m := NewManager()
	var count atomic.Int64

	// Concurrent registration and emission.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
				count.Add(1)
				return nil
			})
		}()
		go func() {
			defer wg.Done()
			m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{})
		}()
	}
	wg.Wait()

	// No panics = pass. The count will vary due to race between register and emit.
	if count.Load() == 0 {
		// At least some hooks should have been called.
		// (It's possible all registers happen after emits, so just verify no panic.)
	}
}

// --- Test 5.14: All AuthEvent types can have hooks ---

func TestHookManager_EventTypes(t *testing.T) {
	events := []Event{
		testEventRegistration,
		testEventLogin,
		testEventLoginFailed,
		testEventLogout,
		testEventPasswordReset,
		testEventMagicLinkSent,
		testEventAccountLocked,
	}

	m := NewManager()
	for _, event := range events {
		event := event
		called := false

		m.Register(event, func(ctx context.Context, p HookPayload) error {
			called = true
			return nil
		})

		m.EmitBefore(context.Background(), event, &LoginPayload{AuthMethod: "test"})

		if !called {
			t.Errorf("hook for event %q was not called", event)
		}
	}
}

// --- Test 5.15: OAuthPayload includes provider name ---

func TestHookManager_OAuthPayload(t *testing.T) {
	m := NewManager()
	var received *OAuthPayload

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		received = p.(*OAuthPayload)
		return nil
	})

	m.EmitAfter(context.Background(), testEventLogin, &OAuthPayload{
		ProviderName: "google",
		Identifier:   "alice@gmail.com",
		AuthMethod:   "oauth2",
		SubjectID:    "user-123",
		SessionID:    "sess-456",
		IsNewUser:    true,
	})

	if received == nil {
		t.Fatal("oauth hook was not called")
	}
	if received.ProviderName != "google" {
		t.Errorf("expected ProviderName google, got %s", received.ProviderName)
	}
	if !received.IsNewUser {
		t.Error("expected IsNewUser to be true")
	}
}

// --- Test 5.16: MagicLinkPayload includes token TTL ---

func TestHookManager_MagicLinkPayload(t *testing.T) {
	m := NewManager()
	var received *MagicLinkPayload

	m.Register(testEventMagicLinkSent, func(ctx context.Context, p HookPayload) error {
		received = p.(*MagicLinkPayload)
		return nil
	})

	m.EmitAfter(context.Background(), testEventMagicLinkSent, &MagicLinkPayload{
		Identifier: "alice@example.com",
		AuthMethod: "magic_link",
		SubjectID:  "user-123",
		TokenTTL:   15 * time.Minute,
	})

	if received == nil {
		t.Fatal("magic link hook was not called")
	}
	if received.TokenTTL != 15*time.Minute {
		t.Errorf("expected TokenTTL 15m, got %v", received.TokenTTL)
	}
}

// --- Test 5.17: APIKeyPayload includes key name and scopes ---

func TestHookManager_APIKeyPayload(t *testing.T) {
	m := NewManager()
	var received *APIKeyPayload

	m.Register(testEventLogin, func(ctx context.Context, p HookPayload) error {
		received = p.(*APIKeyPayload)
		return nil
	})

	m.EmitAfter(context.Background(), testEventLogin, &APIKeyPayload{
		KeyName:    "production-key",
		Scopes:     []string{"read", "write"},
		AuthMethod: "api_key",
		SubjectID:  "user-123",
		KeyID:      "key-456",
	})

	if received == nil {
		t.Fatal("api key hook was not called")
	}
	if received.KeyName != "production-key" {
		t.Errorf("expected KeyName production-key, got %s", received.KeyName)
	}
	if len(received.Scopes) != 2 || received.Scopes[0] != "read" || received.Scopes[1] != "write" {
		t.Errorf("expected scopes [read write], got %v", received.Scopes)
	}
}

// --- Test 5.18: All payloads include AuthMethod field ---

func TestHookManager_AuthMethodInPayload(t *testing.T) {
	payloads := []struct {
		name    string
		payload HookPayload
		method  string
	}{
		{"LoginPayload", &LoginPayload{AuthMethod: "password"}, "password"},
		{"RegisterPayload", &RegisterPayload{AuthMethod: "password"}, "password"},
		{"LogoutPayload", &LogoutPayload{AuthMethod: "password"}, "password"},
		{"OAuthPayload", &OAuthPayload{AuthMethod: "oauth2"}, "oauth2"},
		{"MagicLinkPayload", &MagicLinkPayload{AuthMethod: "magic_link"}, "magic_link"},
		{"APIKeyPayload", &APIKeyPayload{AuthMethod: "api_key"}, "api_key"},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.payload.GetAuthMethod()
			if got != tc.method {
				t.Errorf("GetAuthMethod() = %q, want %q", got, tc.method)
			}
		})
	}
}

// --- Hardening Tests ---

// Test 5.19: HasHooks returns correct state.
func TestHookManager_HasHooks(t *testing.T) {
	m := NewManager()

	if m.HasHooks(testEventLogin) {
		t.Error("expected HasHooks=false for unregistered event")
	}

	m.Register(testEventLogin, func(_ context.Context, _ HookPayload) error {
		return nil
	})

	if !m.HasHooks(testEventLogin) {
		t.Error("expected HasHooks=true after registration")
	}

	// Different event should still be false.
	if m.HasHooks(testEventLogout) {
		t.Error("expected HasHooks=false for different event")
	}
}

// Test 5.20: Context cancellation is observable in hooks.
func TestHookManager_ContextCancellation(t *testing.T) {
	m := NewManager()
	var seenCancelled bool

	m.Register(testEventLogin, func(ctx context.Context, _ HookPayload) error {
		select {
		case <-ctx.Done():
			seenCancelled = true
		default:
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before emitting.

	m.EmitBefore(ctx, testEventLogin, &LoginPayload{})
	if !seenCancelled {
		t.Error("hook should see cancelled context")
	}
}

// Test 5.21: EmitBefore with no registered hooks returns nil.
func TestHookManager_EmitBefore_NoHooks(t *testing.T) {
	m := NewManager()
	err := m.EmitBefore(context.Background(), Event("nonexistent"), &LoginPayload{})
	if err != nil {
		t.Errorf("expected nil error for no hooks, got: %v", err)
	}
}

// Test 5.22: High-concurrency stress test.
func TestHookManager_HighConcurrency(t *testing.T) {
	m := NewManager()
	var count atomic.Int64

	const workers = 200

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Register(testEventLogin, func(_ context.Context, _ HookPayload) error {
				count.Add(1)
				return nil
			})
		}()
	}
	wg.Wait()

	// All registrations complete, now emit.
	m.EmitBefore(context.Background(), testEventLogin, &LoginPayload{})

	// Should have called all 200 hooks.
	if got := count.Load(); got != int64(workers) {
		t.Errorf("expected %d hook calls, got %d", workers, got)
	}
}
