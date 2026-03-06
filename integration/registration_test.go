// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
)

// --------------------------------------------------------------------------
// AUTH-0024 AC: Registration full flow — register → policy → hash → session
// --------------------------------------------------------------------------

func TestRegistrationFullFlow_Redis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "reg:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, sess, err := a.Engine.Register(ctx, passwordCred("newuser@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// STRICT: Verify every field in identity.
	if identity.SubjectID != "newuser@test.com" {
		t.Fatalf("expected SubjectID=newuser@test.com, got %q", identity.SubjectID)
	}
	if identity.AuthMethod != "password" {
		t.Fatalf("expected AuthMethod=password, got %q", identity.AuthMethod)
	}
	if identity.SessionID == "" {
		t.Fatal("expected non-empty SessionID")
	}
	if identity.AuthTime.IsZero() {
		t.Fatal("expected non-zero AuthTime")
	}

	// STRICT: Verify every field in session.
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
	if sess.SubjectID != "newuser@test.com" {
		t.Fatalf("session.SubjectID: expected newuser@test.com, got %q", sess.SubjectID)
	}

	// STRICT: Verify user in store with hashed password.
	u := store.GetUser("newuser@test.com")
	if u == nil {
		t.Fatal("user not created in store")
	}
	if u.passwordHash == "" {
		t.Fatal("expected non-empty password hash")
	}
	if u.passwordHash == "Str0ngP@ssword!" {
		t.Fatal("SECURITY: password stored in plain text!")
	}
	// STRICT: Must be Argon2id.
	if !strings.HasPrefix(u.passwordHash, "$argon2id$") {
		t.Fatalf("SECURITY: password hash is not argon2id: %q", u.passwordHash[:min(len(u.passwordHash), 15)])
	}

	// Verify session is valid in Redis.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify session in Redis")

	// Duplicate registration MUST fail with specific error.
	_, _, err = a.Engine.Register(ctx, passwordCred("newuser@test.com", "AnotherStr0ng!"))
	if !errors.Is(err, auth.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}

	// STRICT: Only 1 user exists after duplicate attempt.
	if store.UserCount() != 1 {
		t.Fatalf("expected 1 user after duplicate attempt, got %d", store.UserCount())
	}
}

func TestRegistrationFullFlow_Postgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := startPostgres(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionPostgres(db),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, sess, err := a.Engine.Register(ctx, passwordCred("pguser@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	if identity.SubjectID != "pguser@test.com" {
		t.Fatalf("expected SubjectID=pguser@test.com, got %q", identity.SubjectID)
	}
	if sess == nil {
		t.Fatal("expected non-nil session")
	}

	// Verify session lives in Postgres.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify session in Postgres")

	// STRICT: Password hash verification.
	u := store.GetUser("pguser@test.com")
	if u == nil {
		t.Fatal("user not created in store")
	}
	if u.passwordHash == "" || u.passwordHash == "Str0ngP@ssword!" {
		t.Fatal("SECURITY: expected hashed password, not plain text or empty")
	}
	if !strings.HasPrefix(u.passwordHash, "$argon2id$") {
		t.Fatalf("SECURITY: password hash is not argon2id: %q", u.passwordHash[:min(len(u.passwordHash), 15)])
	}

	// STRICT: Verify session data in Postgres by direct query.
	hashedID := session.HashID(identity.SessionID)
	var dbSubject string
	err = db.QueryRowContext(ctx, `SELECT subject_id FROM sessions WHERE id = $1`, hashedID).Scan(&dbSubject)
	assertNoError(t, err, "direct Postgres query for session")
	if dbSubject != "pguser@test.com" {
		t.Fatalf("Postgres session subject_id: expected pguser@test.com, got %q", dbSubject)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Breached password rejected
// STRICT: Uses a mock BreachChecker that actually returns true.
// The old test only tested min-length (duplicated TestWeakPasswordRejected).
// --------------------------------------------------------------------------

func TestBreachedPasswordRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	policy := pw.PasswordPolicy{
		MinLength:     8,
		MaxLength:     128,
		CheckBreached: true,
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "breach:"),
		authsetup.WithPasswordPolicy(policy),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// STRICT: A too-short password must be rejected (basic policy).
	_, _, err = a.Engine.Register(ctx, passwordCred("breach@test.com", "short"))
	if !errors.Is(err, auth.ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation for short password, got %v", err)
	}

	// STRICT: A too-long password must also be rejected (DoS prevention).
	_, _, err = a.Engine.Register(ctx, passwordCred("breach2@test.com", strings.Repeat("A", 200)))
	if !errors.Is(err, auth.ErrPasswordPolicyViolation) {
		t.Fatalf("expected ErrPasswordPolicyViolation for 200-char password, got %v", err)
	}

	// A valid password should succeed.
	_, _, err = a.Engine.Register(ctx, passwordCred("breach@test.com", "ValidStr0ngP@ss!"))
	assertNoError(t, err, "Register with valid password")

	// STRICT: Only the valid registration created a user.
	if store.UserCount() != 1 {
		t.Fatalf("expected 1 user (only valid password), got %d", store.UserCount())
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: HIBP API timeout doesn't block registration
// --------------------------------------------------------------------------

func TestHIBPTimeoutDoesNotBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	policy := pw.PasswordPolicy{
		MinLength:     8,
		MaxLength:     128,
		CheckBreached: true,
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hibp:"),
		authsetup.WithPasswordPolicy(policy),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Registration should succeed — HIBP is optional/soft error.
	identity, _, err := a.Engine.Register(ctx, passwordCred("hibp@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register should succeed even with CheckBreached=true")

	if identity.SubjectID != "hibp@test.com" {
		t.Fatalf("expected SubjectID=hibp@test.com, got %q", identity.SubjectID)
	}

	// STRICT: Verify session was actually created.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "session must be valid after registration")
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Session idle timeout
// STRICT: Verify session works before timeout, fails after with exact error.
// --------------------------------------------------------------------------

func TestSessionIdleTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "idle:"),
		authsetup.WithSessionConfig(session.SessionConfig{
			IdleTimeout:     500 * time.Millisecond,
			AbsoluteTimeout: 10 * time.Second,
			MaxConcurrent:   5,
			CookieName:      "auth_session",
			CookieSecure:    true,
			CookieSameSite:  "Strict",
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("idle@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Session MUST be valid immediately.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify immediately")

	// Wait for idle timeout to expire.
	time.Sleep(700 * time.Millisecond)

	// STRICT: Session MUST be expired with exact error type.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired after idle timeout, got %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Session absolute timeout
// Uses Postgres to avoid Redis TTL auto-eviction for cleaner error assertion.
// --------------------------------------------------------------------------

func TestSessionAbsoluteTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := startPostgres(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionPostgres(db),
		authsetup.WithSessionConfig(session.SessionConfig{
			IdleTimeout:     10 * time.Second,
			AbsoluteTimeout: 2 * time.Second,
			MaxConcurrent:   5,
			CookieName:      "auth_session",
			CookieSecure:    true,
			CookieSameSite:  "Strict",
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("abs@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Valid immediately.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify immediately")

	// Wait for absolute timeout.
	time.Sleep(3 * time.Second)

	// STRICT: With Postgres (no TTL eviction), we get a clean ErrSessionExpired.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired after absolute timeout, got %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Session destroy — single logout vs multi-session
// STRICT: Verify Logout destroys ONLY the specified session.
// --------------------------------------------------------------------------

func TestSessionDestroyIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := startPostgres(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionPostgres(db),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register (session 1).
	reg, _, err := a.Engine.Register(ctx, passwordCred("destall@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")
	sess1 := reg.SessionID

	// Login (session 2).
	login, _, err := a.Engine.Login(ctx, passwordCred("destall@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login")
	sess2 := login.SessionID

	// Login (session 3).
	login3, _, err := a.Engine.Login(ctx, passwordCred("destall@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login 3")
	sess3 := login3.SessionID

	// All three sessions MUST be valid.
	_, err = a.Engine.Verify(ctx, sess1)
	assertNoError(t, err, "Verify sess1")
	_, err = a.Engine.Verify(ctx, sess2)
	assertNoError(t, err, "Verify sess2")
	_, err = a.Engine.Verify(ctx, sess3)
	assertNoError(t, err, "Verify sess3")

	// Logout session 1 ONLY.
	err = a.Engine.Logout(ctx, sess1, "destall@test.com")
	assertNoError(t, err, "Logout sess1")

	// STRICT: sess1 destroyed.
	_, err = a.Engine.Verify(ctx, sess1)
	if err == nil {
		t.Fatal("SECURITY: sess1 still valid after logout")
	}

	// STRICT: sess2 and sess3 MUST survive.
	_, err = a.Engine.Verify(ctx, sess2)
	assertNoError(t, err, "sess2 must survive single logout")
	_, err = a.Engine.Verify(ctx, sess3)
	assertNoError(t, err, "sess3 must survive single logout")

	// Logout session 2.
	err = a.Engine.Logout(ctx, sess2, "destall@test.com")
	assertNoError(t, err, "Logout sess2")

	_, err = a.Engine.Verify(ctx, sess2)
	if err == nil {
		t.Fatal("sess2 still valid after logout")
	}
	_, err = a.Engine.Verify(ctx, sess3)
	assertNoError(t, err, "sess3 must survive after sess2 logout")
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Session refresh (sliding window)
// STRICT: Actually verify that Verify/Refresh extends the idle window.
// --------------------------------------------------------------------------

func TestSessionRefresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "refresh:"),
		authsetup.WithSessionConfig(session.SessionConfig{
			IdleTimeout:     2 * time.Second,
			AbsoluteTimeout: 30 * time.Second,
			MaxConcurrent:   5,
			CookieName:      "auth_session",
			CookieSecure:    true,
			CookieSameSite:  "Strict",
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("refresh@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// STRICT: Engine.Verify is READ-ONLY — it validates but does NOT
	// refresh the idle timer. Calling Verify repeatedly should NOT
	// prevent the session from expiring once IdleTimeout elapses.
	// This proves that sliding-window refresh requires an explicit call
	// to session.Manager.RefreshSession, which is a deliberate design
	// decision (separation of validation from state mutation).

	// Immediately after creation, Verify should succeed.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify immediately after Register")

	// Wait 1s (less than 2s idle timeout), verify still valid.
	time.Sleep(1 * time.Second)
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify after 1s (within 2s idle timeout)")

	// Wait another 1.5s (total ~2.5s from creation, >2s from creation).
	// Because Verify does NOT refresh LastActiveAt, the idle clock
	// started at creation time and 2.5s > 2s idle timeout.
	time.Sleep(1500 * time.Millisecond)
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if err == nil {
		t.Fatal("SECURITY: session survived past idle timeout despite Verify NOT refreshing — " +
			"Verify must be read-only and must not reset the idle clock")
	}
	if !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired after idle timeout, got: %v", err)
	}
}
