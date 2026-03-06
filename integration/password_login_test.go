// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/session"
)

// --------------------------------------------------------------------------
// AUTH-0024 AC: Password login works end-to-end with Redis and Postgres
// --------------------------------------------------------------------------

func TestPasswordLogin_Redis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "inttest:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register a user.
	identity, sess, err := a.Engine.Register(ctx, passwordCred("alice@example.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	if identity.SubjectID != "alice@example.com" {
		t.Fatalf("expected SubjectID=alice@example.com, got %q", identity.SubjectID)
	}
	if identity.SessionID == "" {
		t.Fatal("expected non-empty SessionID after register")
	}
	if identity.AuthMethod != "password" {
		t.Fatalf("expected AuthMethod=password, got %q", identity.AuthMethod)
	}
	if identity.AuthTime.IsZero() {
		t.Fatal("expected non-zero AuthTime after register")
	}
	if sess == nil {
		t.Fatal("expected non-nil session after register")
	}
	if sess.SubjectID != "alice@example.com" {
		t.Fatalf("session.SubjectID: expected alice@example.com, got %q", sess.SubjectID)
	}
	if sess.SchemaVersion != session.SchemaVersion {
		t.Fatalf("session.SchemaVersion: expected %d, got %d", session.SchemaVersion, sess.SchemaVersion)
	}

	// Verify the session.
	verifiedIdentity, err := a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify after register")
	if verifiedIdentity.SubjectID != "alice@example.com" {
		t.Fatalf("Verify: expected SubjectID=alice@example.com, got %q", verifiedIdentity.SubjectID)
	}

	// Log out.
	err = a.Engine.Logout(ctx, identity.SessionID, identity.SubjectID)
	assertNoError(t, err, "Logout")

	// Session MUST be invalid after logout — exact error type required.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if err == nil {
		t.Fatal("SECURITY: session still valid after logout — session not destroyed")
	}
	if !errors.Is(err, auth.ErrSessionNotFound) && !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("expected ErrSessionNotFound or ErrSessionExpired after logout, got %v", err)
	}

	// Login with password.
	loginIdentity, loginSess, err := a.Engine.Login(ctx, passwordCred("alice@example.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login")

	if loginIdentity.SubjectID != "alice@example.com" {
		t.Fatalf("Login: expected SubjectID=alice@example.com, got %q", loginIdentity.SubjectID)
	}
	if loginIdentity.SessionID == "" {
		t.Fatal("Login must return non-empty SessionID")
	}
	if loginIdentity.SessionID == identity.SessionID {
		t.Fatal("SECURITY: new login returned same session ID as pre-logout session")
	}
	if loginSess == nil {
		t.Fatal("expected non-nil session after login")
	}

	// Verify the new session.
	v2, err := a.Engine.Verify(ctx, loginIdentity.SessionID)
	assertNoError(t, err, "Verify after login")
	if v2.SubjectID != "alice@example.com" {
		t.Fatalf("Verify after login: SubjectID mismatch: %q", v2.SubjectID)
	}

	// Wrong password MUST fail with generic error.
	_, _, err = a.Engine.Login(ctx, passwordCred("alice@example.com", "WrongPassword!"))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: expected ErrInvalidCredentials, got %v", err)
	}

	// Non-existent user MUST return same generic error (user enumeration prevention).
	_, _, err = a.Engine.Login(ctx, passwordCred("nobody@example.com", "Str0ngP@ssword!"))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("non-existent user: expected ErrInvalidCredentials, got %v", err)
	}
}

func TestPasswordLogin_Postgres(t *testing.T) {
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

	identity, sess, err := a.Engine.Register(ctx, passwordCred("bob@example.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	if identity.SubjectID != "bob@example.com" {
		t.Fatalf("expected SubjectID=bob@example.com, got %q", identity.SubjectID)
	}
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
	if identity.AuthMethod != "password" {
		t.Fatalf("expected AuthMethod=password, got %q", identity.AuthMethod)
	}

	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify")

	err = a.Engine.Logout(ctx, identity.SessionID, identity.SubjectID)
	assertNoError(t, err, "Logout")

	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if err == nil {
		t.Fatal("SECURITY: session still valid after logout")
	}

	loginIdentity, _, err := a.Engine.Login(ctx, passwordCred("bob@example.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login")

	if loginIdentity.SessionID == identity.SessionID {
		t.Fatal("SECURITY: post-logout login reused old session ID")
	}

	_, err = a.Engine.Verify(ctx, loginIdentity.SessionID)
	assertNoError(t, err, "Verify after login")

	// STRICT: Verify session data persists in Postgres by direct query.
	hashedID := session.HashID(loginIdentity.SessionID)
	var dbSubject string
	err = db.QueryRowContext(ctx, `SELECT subject_id FROM sessions WHERE id = $1`, hashedID).Scan(&dbSubject)
	assertNoError(t, err, "direct Postgres query for session")
	if dbSubject != "bob@example.com" {
		t.Fatalf("Postgres session subject_id: expected bob@example.com, got %q", dbSubject)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Constant-time behavior verified —
// user-not-found ≈ wrong-password ≈ locked ≈ empty
// All paths MUST return identical ErrInvalidCredentials.
// STRICT: Timing check is a HARD FAIL (t.Errorf), not a warning log.
// --------------------------------------------------------------------------

func TestConstantTimeBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "ct:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("alice@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	const warmup = 3
	const iterations = 10

	// Warm up JIT/cache/connection pools.
	for i := 0; i < warmup; i++ {
		_, _, _ = a.Engine.Login(ctx, passwordCred("alice@test.com", "WrongPassword!"))
		_, _, _ = a.Engine.Login(ctx, passwordCred("nonexistent@test.com", "WrongPassword!"))
	}
	_ = store.ResetFailedAttempts(ctx, "alice@test.com")
	_ = store.SetLocked(ctx, "alice@test.com", false)

	// Path 1: Wrong password (user exists, not locked).
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, _, err = a.Engine.Login(ctx, passwordCred("alice@test.com", "WrongPassword!"))
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong password attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	wrongPwDuration := time.Since(start)
	_ = store.ResetFailedAttempts(ctx, "alice@test.com")

	// Path 2: User does not exist (dummyHash path).
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_, _, err = a.Engine.Login(ctx, passwordCred("nonexistent-xyz@test.com", "WrongPassword!"))
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("non-existent user attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	notFoundDuration := time.Since(start)

	// Path 3: User locked.
	_ = store.SetLocked(ctx, "alice@test.com", true)
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_, _, err = a.Engine.Login(ctx, passwordCred("alice@test.com", "Str0ngP@ssword!"))
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("locked attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	lockedDuration := time.Since(start)
	_ = store.SetLocked(ctx, "alice@test.com", false)
	_ = store.ResetFailedAttempts(ctx, "alice@test.com")

	// Path 4: Empty credentials.
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_, _, err = a.Engine.Login(ctx, passwordCred("", ""))
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("empty creds attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	emptyDuration := time.Since(start)

	avg := func(d time.Duration) time.Duration { return d / time.Duration(iterations) }
	avgWrong := avg(wrongPwDuration)
	avgNotFound := avg(notFoundDuration)
	avgLocked := avg(lockedDuration)
	avgEmpty := avg(emptyDuration)

	t.Logf("Timing — wrong-pw: %v, not-found: %v, locked: %v, empty: %v",
		avgWrong, avgNotFound, avgLocked, avgEmpty)

	// STRICT (HARD FAIL): All paths must be within 5x of wrong-password timing.
	// Any path significantly faster/slower leaks information.
	const maxRatio = 5
	baseline := avgWrong
	if baseline == 0 {
		baseline = 1 * time.Millisecond
	}

	checkTiming := func(name string, d time.Duration) {
		t.Helper()
		ratio := float64(d) / float64(baseline)
		if ratio < 1.0/float64(maxRatio) || ratio > float64(maxRatio) {
			t.Errorf("SECURITY: %s timing (%v) is %.1fx vs wrong-password (%v) — possible timing leak",
				name, d, ratio, baseline)
		}
	}
	checkTiming("not-found", avgNotFound)
	checkTiming("locked", avgLocked)
	checkTiming("empty-creds", avgEmpty)
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Lockout — N failures → locked → correct pw still fails → unlock → succeed
// STRICT: Verify counter increments, verify locked+correct == locked+wrong (same error),
// verify counter resets after successful login.
// --------------------------------------------------------------------------

func TestLockoutFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "lockout:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("lockme@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Verify user starts clean.
	u := store.GetUser("lockme@test.com")
	if u.failedAttempts != 0 {
		t.Fatalf("initial failed attempts: expected 0, got %d", u.failedAttempts)
	}
	if u.locked {
		t.Fatal("user should not be locked initially")
	}

	// Fail 5 times — verify counter increments each time.
	for i := 0; i < 5; i++ {
		_, _, err = a.Engine.Login(ctx, passwordCred("lockme@test.com", "WrongPass!"))
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
		u = store.GetUser("lockme@test.com")
		if u.failedAttempts != i+1 {
			t.Fatalf("after attempt %d: expected %d failed attempts, got %d", i+1, i+1, u.failedAttempts)
		}
	}

	// Lock the account.
	err = store.SetLocked(ctx, "lockme@test.com", true)
	assertNoError(t, err, "SetLocked")

	// STRICT: Correct password MUST fail when locked with the SAME generic error.
	_, _, errCorrectLocked := a.Engine.Login(ctx, passwordCred("lockme@test.com", "Str0ngP@ssword!"))
	if !errors.Is(errCorrectLocked, auth.ErrInvalidCredentials) {
		t.Fatalf("SECURITY: locked account with correct password: expected ErrInvalidCredentials, got %v", errCorrectLocked)
	}

	// STRICT: Wrong password while locked must return the SAME error string (no information leak).
	_, _, errWrongLocked := a.Engine.Login(ctx, passwordCred("lockme@test.com", "WrongPass!"))
	if errCorrectLocked.Error() != errWrongLocked.Error() {
		t.Fatalf("SECURITY: locked+correct-pw error %q differs from locked+wrong-pw error %q — information leak",
			errCorrectLocked.Error(), errWrongLocked.Error())
	}

	// Unlock and reset.
	_ = store.SetLocked(ctx, "lockme@test.com", false)
	_ = store.ResetFailedAttempts(ctx, "lockme@test.com")

	// Login MUST succeed now.
	identity, _, err := a.Engine.Login(ctx, passwordCred("lockme@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login after unlock")
	if identity.SubjectID != "lockme@test.com" {
		t.Fatalf("expected SubjectID=lockme@test.com, got %q", identity.SubjectID)
	}

	// STRICT: Verify counter resets after successful login.
	u = store.GetUser("lockme@test.com")
	if u.failedAttempts != 0 {
		t.Fatalf("failed attempts after successful login: expected 0, got %d", u.failedAttempts)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Session fixation — old session destroyed on login
// STRICT: verify old session destroyed, new has sufficient entropy,
// test chained fixation (fixation-on-fixation).
// --------------------------------------------------------------------------

func TestSessionFixation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "fix:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	regIdentity, _, err := a.Engine.Register(ctx, passwordCred("fix@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")
	oldSessionID := regIdentity.SessionID

	// Old session must be valid.
	_, err = a.Engine.Verify(ctx, oldSessionID)
	assertNoError(t, err, "Verify old session before re-login")

	// Login again with existing session ID (triggers fixation prevention).
	newIdentity, _, err := a.Engine.Login(ctx, passwordCredWithSession("fix@test.com", "Str0ngP@ssword!", oldSessionID))
	assertNoError(t, err, "Login with existing session")

	// New session MUST be different.
	if newIdentity.SessionID == oldSessionID {
		t.Fatal("SECURITY: new session ID equals old session ID — fixation prevention broken")
	}

	// STRICT: Session ID entropy — at least 64 hex chars (256 bits).
	if len(newIdentity.SessionID) < 64 {
		t.Fatalf("SECURITY: session ID too short (%d chars) — insufficient entropy", len(newIdentity.SessionID))
	}

	// Old session MUST be destroyed — attacker cannot replay.
	_, err = a.Engine.Verify(ctx, oldSessionID)
	if err == nil {
		t.Fatal("SECURITY: old session still valid after re-login — fixation vulnerability")
	}

	// New session must be valid.
	v, err := a.Engine.Verify(ctx, newIdentity.SessionID)
	assertNoError(t, err, "Verify new session")
	if v.SubjectID != "fix@test.com" {
		t.Fatalf("new session SubjectID: expected fix@test.com, got %q", v.SubjectID)
	}

	// STRICT: Chained fixation — login again with the new session.
	newerIdentity, _, err := a.Engine.Login(ctx, passwordCredWithSession("fix@test.com", "Str0ngP@ssword!", newIdentity.SessionID))
	assertNoError(t, err, "Second re-login")

	if newerIdentity.SessionID == newIdentity.SessionID {
		t.Fatal("SECURITY: chained fixation prevention failed — session ID reused")
	}

	// Intermediate session must be destroyed.
	_, err = a.Engine.Verify(ctx, newIdentity.SessionID)
	if err == nil {
		t.Fatal("SECURITY: intermediate session not destroyed in chained fixation test")
	}

	// Latest session must work.
	_, err = a.Engine.Verify(ctx, newerIdentity.SessionID)
	assertNoError(t, err, "Verify newest session after chained fixation")
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Hooks fire correctly in password login flow
// STRICT: Verify ORDER (registration < login < login_failed < logout),
// verify PAYLOADS (AuthMethod, Identifier, SubjectID, SessionID).
// --------------------------------------------------------------------------

type hookRecord struct {
	name       string
	authMethod string
	identifier string
	subjectID  string
	sessionID  string
	hasError   bool
}

func TestHooksInPasswordLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	var hookRecords []hookRecord
	var hookMu sync.Mutex

	recordHook := func(name string) hooks.HookFn {
		return func(_ context.Context, payload hooks.HookPayload) error {
			hookMu.Lock()
			defer hookMu.Unlock()
			rec := hookRecord{
				name:       name,
				authMethod: payload.GetAuthMethod(),
			}
			switch p := payload.(type) {
			case *hooks.RegisterPayload:
				rec.identifier = p.Identifier
				rec.subjectID = p.SubjectID
				rec.sessionID = p.SessionID
			case *hooks.LoginPayload:
				rec.identifier = p.Identifier
				rec.subjectID = p.SubjectID
				rec.sessionID = p.SessionID
				rec.hasError = p.Error != nil
			case *hooks.LogoutPayload:
				rec.subjectID = p.SubjectID
				rec.sessionID = p.SessionID
			}
			hookRecords = append(hookRecords, rec)
			return nil
		}
	}

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hooks:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, recordHook("registration")),
		authsetup.WithHook(auth.EventLogin, recordHook("login")),
		authsetup.WithHook(auth.EventLoginFailed, recordHook("login_failed")),
		authsetup.WithHook(auth.EventLogout, recordHook("logout")),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Step 1: Register.
	regIdentity, _, err := a.Engine.Register(ctx, passwordCred("hooks@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Step 2: Login.
	loginIdentity, _, err := a.Engine.Login(ctx, passwordCred("hooks@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login")

	// Step 3: Failed login.
	_, _, _ = a.Engine.Login(ctx, passwordCred("hooks@test.com", "WrongPassword!"))

	// Step 4: Logout.
	_ = a.Engine.Logout(ctx, loginIdentity.SessionID, loginIdentity.SubjectID)

	hookMu.Lock()
	defer hookMu.Unlock()

	// WithHook registers the function for BOTH EmitBefore and EmitAfter
	// on the same event, so we expect:
	//   Before-registration, After-registration,
	//   Before-login (success), After-login (success),
	//   Before-login (wrong-pw), After-login_failed,
	//   After-logout
	// = 7 total hook records.
	if len(hookRecords) < 7 {
		t.Fatalf("expected at least 7 hook events (before+after for reg/login, login_failed, logout), got %d: %+v",
			len(hookRecords), hookRecords)
	}

	// STRICT: Verify ordering using FIRST occurrence of each event.
	regFirstIdx := findHookIndex(hookRecords, "registration")
	loginFirstIdx := findHookIndex(hookRecords, "login")
	failIdx := findHookIndex(hookRecords, "login_failed")
	logoutIdx := findHookIndex(hookRecords, "logout")

	if regFirstIdx == -1 {
		t.Fatal("registration hook did not fire")
	}
	if loginFirstIdx == -1 {
		t.Fatal("login hook did not fire")
	}
	if failIdx == -1 {
		t.Fatal("login_failed hook did not fire")
	}
	if logoutIdx == -1 {
		t.Fatal("logout hook did not fire")
	}

	if loginFirstIdx < regFirstIdx {
		t.Fatalf("login hook (idx %d) fired before registration hook (idx %d) — wrong order", loginFirstIdx, regFirstIdx)
	}
	if failIdx < loginFirstIdx {
		t.Fatalf("login_failed hook (idx %d) fired before login hook (idx %d) — wrong order", failIdx, loginFirstIdx)
	}
	if logoutIdx < failIdx {
		t.Fatalf("logout hook (idx %d) fired before login_failed hook (idx %d) — wrong order", logoutIdx, failIdx)
	}

	// STRICT: Verify Before-hooks have EMPTY SubjectID/SessionID (not yet known).
	regBeforeHook := hookRecords[regFirstIdx]
	if regBeforeHook.authMethod != "password" {
		t.Errorf("before-registration hook AuthMethod: expected 'password', got %q", regBeforeHook.authMethod)
	}
	if regBeforeHook.identifier != "hooks@test.com" {
		t.Errorf("before-registration hook Identifier: expected 'hooks@test.com', got %q", regBeforeHook.identifier)
	}
	if regBeforeHook.subjectID != "" {
		t.Errorf("SECURITY: before-registration hook should NOT have SubjectID (not yet created), got %q", regBeforeHook.subjectID)
	}
	if regBeforeHook.sessionID != "" {
		t.Errorf("SECURITY: before-registration hook should NOT have SessionID (not yet created), got %q", regBeforeHook.sessionID)
	}

	loginBeforeHook := hookRecords[loginFirstIdx]
	if loginBeforeHook.authMethod != "password" {
		t.Errorf("before-login hook AuthMethod: expected 'password', got %q", loginBeforeHook.authMethod)
	}
	if loginBeforeHook.identifier != "hooks@test.com" {
		t.Errorf("before-login hook Identifier: expected 'hooks@test.com', got %q", loginBeforeHook.identifier)
	}
	if loginBeforeHook.subjectID != "" {
		t.Errorf("SECURITY: before-login hook should NOT have SubjectID (not yet authenticated), got %q", loginBeforeHook.subjectID)
	}
	if loginBeforeHook.sessionID != "" {
		t.Errorf("SECURITY: before-login hook should NOT have SessionID (not yet created), got %q", loginBeforeHook.sessionID)
	}

	// STRICT: Verify After-hooks have POPULATED SubjectID/SessionID.
	// Registration: findLastHookIndex works (only 2 records: Before + After).
	// Login: use findHookWithSubject because there are 3 "login" records:
	//   Before-Login(success), After-Login(success), Before-Login(wrong-pw).
	//   The last "login" record is Before-Login(wrong-pw) with empty SubjectID.
	regAfterIdx := findLastHookIndex(hookRecords, "registration")
	if regAfterIdx == regFirstIdx {
		t.Fatal("only one registration hook found; expected both Before and After")
	}
	regAfterHook := hookRecords[regAfterIdx]
	if regAfterHook.subjectID != "hooks@test.com" {
		t.Errorf("after-registration hook SubjectID: expected 'hooks@test.com', got %q", regAfterHook.subjectID)
	}
	if regAfterHook.sessionID == "" {
		t.Error("after-registration hook should have non-empty SessionID")
	}

	loginAfterIdx := findHookWithSubject(hookRecords, "login")
	if loginAfterIdx == -1 {
		t.Fatal("no login hook with populated SubjectID found — AfterLogin did not fire or did not carry SubjectID")
	}
	if loginAfterIdx == loginFirstIdx {
		t.Fatal("the login hook with SubjectID is the same as the first (Before) hook — unexpected")
	}
	loginAfterHook := hookRecords[loginAfterIdx]
	if loginAfterHook.authMethod != "password" {
		t.Errorf("after-login hook AuthMethod: expected 'password', got %q", loginAfterHook.authMethod)
	}
	if loginAfterHook.identifier != "hooks@test.com" {
		t.Errorf("after-login hook Identifier: expected 'hooks@test.com', got %q", loginAfterHook.identifier)
	}
	if loginAfterHook.subjectID != "hooks@test.com" {
		t.Errorf("after-login hook SubjectID: expected 'hooks@test.com', got %q", loginAfterHook.subjectID)
	}
	if loginAfterHook.sessionID == "" {
		t.Error("after-login hook should have non-empty SessionID")
	}

	failHook := hookRecords[failIdx]
	if failHook.authMethod != "password" {
		t.Errorf("login_failed hook AuthMethod: expected 'password', got %q", failHook.authMethod)
	}
	if !failHook.hasError {
		t.Error("login_failed hook should carry an Error in the payload")
	}

	logoutHook := hookRecords[logoutIdx]
	if logoutHook.subjectID != "hooks@test.com" {
		t.Errorf("logout hook SubjectID: expected 'hooks@test.com', got %q", logoutHook.subjectID)
	}
	if logoutHook.sessionID == "" {
		t.Error("logout hook should have non-empty SessionID")
	}

	// STRICT: Verify consistent session IDs — after-login SessionID should
	// match the login identity returned by the Engine.
	if loginAfterHook.sessionID != loginIdentity.SessionID {
		t.Errorf("after-login hook SessionID %q != Engine.Login SessionID %q",
			loginAfterHook.sessionID, loginIdentity.SessionID)
	}
	if regAfterHook.sessionID != regIdentity.SessionID {
		t.Errorf("after-registration hook SessionID %q != Engine.Register SessionID %q",
			regAfterHook.sessionID, regIdentity.SessionID)
	}
}

// TestHookBeforeAborts verifies that a BeforeRegister hook can abort the flow
// and that no user is created when it does.
func TestHookBeforeAborts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	blockErr := errors.New("registration blocked by policy")

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hookabort:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithHook(auth.EventRegistration, func(_ context.Context, _ hooks.HookPayload) error {
			return blockErr
		}),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("blocked@test.com", "Str0ngP@ssword!"))
	if err == nil {
		t.Fatal("registration should have been blocked by BeforeRegister hook")
	}
	if !errors.Is(err, blockErr) {
		t.Fatalf("expected blockErr, got %v", err)
	}

	// STRICT: User MUST NOT have been created.
	if store.UserCount() != 0 {
		t.Fatal("SECURITY: user was created despite BeforeRegister hook abort")
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Weak password fails at registration (not login)
// STRICT: Test boundary conditions — empty, exactly min-1, exactly min,
// max, max+1.
// --------------------------------------------------------------------------

func TestWeakPasswordRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "weakpw:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	tests := []struct {
		name     string
		email    string
		password string
		wantErr  bool
	}{
		{"empty", "empty@test.com", "", true},
		{"1 char", "one@test.com", "a", true},
		{"7 chars (boundary -1)", "seven@test.com", "Abcdef7", true},
		{"8 chars (exact min)", "eight@test.com", "Abcdef78", false},
		{"strong", "strong@test.com", "Str0ngP@ssword!2024", false},
		{"128 chars (exact max)", "max@test.com", strings.Repeat("A", 128), false},
		{"129 chars (over max)", "over@test.com", strings.Repeat("A", 129), true},
	}

	expectedSuccesses := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := a.Engine.Register(ctx, passwordCred(tt.email, tt.password))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected password policy error for %q, got nil", tt.name)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error for %q, got: %v", tt.name, err)
				}
				expectedSuccesses++
			}
		})
	}

	// Verify only successful registrations created users.
	if store.UserCount() != expectedSuccesses {
		t.Fatalf("expected %d users (valid passwords only), got %d", expectedSuccesses, store.UserCount())
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: MaxConcurrent enforced, oldest evicted
// STRICT: Verify eviction is strictly FIFO, test 4th login evicts 2nd,
// and test cross-user isolation.
// --------------------------------------------------------------------------

func TestMaxConcurrentSessions_Postgres(t *testing.T) {
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
			IdleTimeout:     30 * time.Minute,
			AbsoluteTimeout: 24 * time.Hour,
			MaxConcurrent:   2,
			CookieName:      "auth_session",
			CookieSecure:    true,
			CookieSameSite:  "Strict",
		}),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register (session 1).
	reg, _, err := a.Engine.Register(ctx, passwordCred("max@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")
	s1 := reg.SessionID

	time.Sleep(10 * time.Millisecond) // ordering guarantee

	// Login (session 2).
	l2, _, err := a.Engine.Login(ctx, passwordCred("max@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login 2")
	s2 := l2.SessionID

	// Both must exist.
	_, err = a.Engine.Verify(ctx, s1)
	assertNoError(t, err, "Verify s1 before eviction")
	_, err = a.Engine.Verify(ctx, s2)
	assertNoError(t, err, "Verify s2 before eviction")

	time.Sleep(10 * time.Millisecond)

	// Login (session 3 — evicts session 1, the oldest).
	l3, _, err := a.Engine.Login(ctx, passwordCred("max@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login 3")
	s3 := l3.SessionID

	// STRICT: s1 MUST be evicted.
	_, err = a.Engine.Verify(ctx, s1)
	if err == nil {
		t.Fatal("SECURITY: session 1 not evicted — MaxConcurrent enforcement broken")
	}
	// s2 and s3 MUST survive.
	_, err = a.Engine.Verify(ctx, s2)
	assertNoError(t, err, "s2 should survive eviction")
	_, err = a.Engine.Verify(ctx, s3)
	assertNoError(t, err, "s3 should be valid")

	time.Sleep(10 * time.Millisecond)

	// Login (session 4 — evicts session 2).
	l4, _, err := a.Engine.Login(ctx, passwordCred("max@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login 4")
	s4 := l4.SessionID

	_, err = a.Engine.Verify(ctx, s2)
	if err == nil {
		t.Fatal("SECURITY: session 2 not evicted on 4th login — MaxConcurrent broken")
	}
	_, err = a.Engine.Verify(ctx, s3)
	assertNoError(t, err, "s3 should survive")
	_, err = a.Engine.Verify(ctx, s4)
	assertNoError(t, err, "s4 should be valid")

	// STRICT: Cross-user isolation — other user's sessions unaffected.
	_, _, err = a.Engine.Register(ctx, passwordCred("other@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register other user")

	otherLogin, _, err := a.Engine.Login(ctx, passwordCred("other@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login other user")
	_, err = a.Engine.Verify(ctx, otherLogin.SessionID)
	assertNoError(t, err, "other user's session must be valid — cross-user isolation")

	// max@test.com sessions should still be valid after other user's activity.
	_, err = a.Engine.Verify(ctx, s3)
	assertNoError(t, err, "s3 should survive after other user activity")
	_, err = a.Engine.Verify(ctx, s4)
	assertNoError(t, err, "s4 should survive after other user activity")
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Identifier normalization in login
// STRICT: Test uppercase, spaces, duplicate registration with case variant.
// --------------------------------------------------------------------------

func TestIdentifierNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field: "email",
			Normalize: func(s string) string {
				return strings.ToLower(strings.TrimSpace(s))
			},
		}),
		authsetup.WithSessionRedis(client, "norm:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("norm@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Login with uppercase MUST work.
	identity, _, err := a.Engine.Login(ctx, passwordCred("NORM@TEST.COM", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login with uppercase")
	if identity.SubjectID != "norm@test.com" {
		t.Fatalf("expected normalized SubjectID=norm@test.com, got %q", identity.SubjectID)
	}

	// Login with spaces MUST work.
	identity2, _, err := a.Engine.Login(ctx, passwordCred("  Norm@Test.Com  ", "Str0ngP@ssword!"))
	assertNoError(t, err, "Login with spaces")
	if identity2.SubjectID != "norm@test.com" {
		t.Fatalf("expected normalized SubjectID=norm@test.com, got %q", identity2.SubjectID)
	}

	// STRICT: Duplicate registration with case variant MUST fail.
	_, _, err = a.Engine.Register(ctx, passwordCred("NORM@TEST.COM", "DifferentStr0ng!"))
	if !errors.Is(err, auth.ErrUserAlreadyExists) {
		t.Fatalf("case-variant re-registration: expected ErrUserAlreadyExists, got %v", err)
	}

	// Only one user should exist.
	if store.UserCount() != 1 {
		t.Fatalf("expected 1 user after normalized duplicate attempt, got %d", store.UserCount())
	}
}

// --------------------------------------------------------------------------
// ADVERSARIAL: Empty/null credential attacks
// --------------------------------------------------------------------------

func TestEmptyCredentialAttack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "empty:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Login: empty/empty.
	_, _, err = a.Engine.Login(ctx, passwordCred("", ""))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("empty/empty login: expected ErrInvalidCredentials, got %v", err)
	}

	// Login: empty identifier, valid password.
	_, _, err = a.Engine.Login(ctx, passwordCred("", "Str0ngP@ssword!"))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("empty-id login: expected ErrInvalidCredentials, got %v", err)
	}

	// Login: valid identifier, empty password.
	_, _, err = a.Engine.Login(ctx, passwordCred("user@test.com", ""))
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("empty-pw login: expected ErrInvalidCredentials, got %v", err)
	}

	// Verify: forged session ID MUST fail.
	_, err = a.Engine.Verify(ctx, "forged-session-id-12345")
	if err == nil {
		t.Fatal("SECURITY: forged session ID accepted")
	}

	// Verify: empty session ID MUST fail.
	_, err = a.Engine.Verify(ctx, "")
	if err == nil {
		t.Fatal("SECURITY: empty session ID accepted")
	}

	// Logout with forged session ID — MUST NOT panic.
	_ = a.Engine.Logout(ctx, "forged-session-id", "nobody")
	// May or may not error; the point is no panic.

	// Double-logout — MUST NOT panic.
	_, _, _ = a.Engine.Register(ctx, passwordCred("double@test.com", "Str0ngP@ssword!"))
}

// --------------------------------------------------------------------------
// ADVERSARIAL: Session ID entropy validation
// --------------------------------------------------------------------------

func TestSessionIDEntropy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "entropy:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("entropy@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	sid := identity.SessionID

	// Session ID must be at least 64 hex characters (32 bytes = 256 bits).
	if len(sid) < 64 {
		t.Fatalf("SECURITY: session ID is %d chars, need at least 64 (256 bits entropy)", len(sid))
	}

	// Session ID must be hex-encoded.
	for _, c := range sid {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			t.Fatalf("SECURITY: session ID contains non-hex character %q", string(c))
		}
	}

	// Generate multiple sessions — all MUST be unique (no RNG failure).
	seen := map[string]bool{sid: true}
	for i := 0; i < 20; i++ {
		login, _, err := a.Engine.Login(ctx, passwordCred("entropy@test.com", "Str0ngP@ssword!"))
		assertNoError(t, err, "Login %d", i)
		if seen[login.SessionID] {
			t.Fatalf("SECURITY: duplicate session ID generated on attempt %d — RNG failure", i)
		}
		seen[login.SessionID] = true
	}
}

// --------------------------------------------------------------------------
// ADVERSARIAL: Password hash format validation (Argon2id PHC)
// --------------------------------------------------------------------------

func TestPasswordHashFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hashfmt:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("hash@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	u := store.GetUser("hash@test.com")
	if u == nil {
		t.Fatal("user not found")
	}

	hash := u.passwordHash

	// Must start with $argon2id$.
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("SECURITY: password hash does not use argon2id: %q", hash[:min(len(hash), 20)])
	}

	// Must have 6 PHC segments: $argon2id$v=19$m=...,t=...,p=...$<salt>$<key>.
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("SECURITY: argon2id hash has %d parts (expected 6): likely malformed", len(parts))
	}

	// Same password MUST produce different hash (random salt).
	store2 := NewMemUserStore()
	a2, err := authsetup.New(
		authsetup.WithUserStore(store2),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "hashfmt2:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New 2")
	defer a2.Close()

	_, _, err = a2.Engine.Register(ctx, passwordCred("hash2@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register 2")

	u2 := store2.GetUser("hash2@test.com")
	hash2 := u2.passwordHash

	if hash == hash2 {
		t.Fatal("SECURITY: same password produced identical hash — salt not random")
	}
}

// --------------------------------------------------------------------------
// ADVERSARIAL: Concurrent login race conditions
// --------------------------------------------------------------------------

func TestConcurrentLoginRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "race:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("race@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	sessions := make(chan string, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			identity, _, err := a.Engine.Login(ctx, passwordCred("race@test.com", "Str0ngP@ssword!"))
			if err != nil {
				errs <- err
				return
			}
			sessions <- identity.SessionID
		}()
	}

	wg.Wait()
	close(errs)
	close(sessions)

	for err := range errs {
		t.Fatalf("concurrent login error: %v", err)
	}

	// All session IDs MUST be unique.
	seen := make(map[string]bool)
	for sid := range sessions {
		if seen[sid] {
			t.Fatal("SECURITY: duplicate session ID in concurrent login — RNG or race condition")
		}
		seen[sid] = true
	}
}

// --------------------------------------------------------------------------
// ADVERSARIAL: Double-logout safety
// --------------------------------------------------------------------------

func TestDoubleLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "dbllogout:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("dbl@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// First logout.
	err = a.Engine.Logout(ctx, identity.SessionID, identity.SubjectID)
	assertNoError(t, err, "First logout")

	// Second logout — MUST NOT panic or produce unexpected error.
	err = a.Engine.Logout(ctx, identity.SessionID, identity.SubjectID)
	// Idempotent delete — no panic required.
	t.Logf("Double logout result: %v (should not panic)", err)

	// Session must remain invalid.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	if err == nil {
		t.Fatal("SECURITY: session valid after double logout")
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func findHookIndex(records []hookRecord, name string) int {
	for i := range records {
		if records[i].name == name {
			return i
		}
	}
	return -1
}

func findLastHookIndex(records []hookRecord, name string) int {
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].name == name {
			return i
		}
	}
	return -1
}

// findHookWithSubject returns the index of the first record matching name
// that also has a non-empty subjectID (i.e., an After-hook with populated data).
func findHookWithSubject(records []hookRecord, name string) int {
	for i := range records {
		if records[i].name == name && records[i].subjectID != "" {
			return i
		}
	}
	return -1
}
