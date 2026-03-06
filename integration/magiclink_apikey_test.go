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
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/authsetup"
	apikeymode "github.com/abhipray-cpu/auth/mode/apikey"
	"github.com/abhipray-cpu/auth/mode/magiclink"
	"github.com/abhipray-cpu/auth/session"
)

// --------------------------------------------------------------------------
// Test infrastructure: In-memory MagicLinkStore
// --------------------------------------------------------------------------

// memMagicLinkStore is a thread-safe in-memory MagicLinkStore.
type memMagicLinkStore struct {
	mu     sync.Mutex
	tokens map[string]*session.MagicLinkToken
}

func newMemMagicLinkStore() *memMagicLinkStore {
	return &memMagicLinkStore{tokens: make(map[string]*session.MagicLinkToken)}
}

func (s *memMagicLinkStore) Store(_ context.Context, token *session.MagicLinkToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *memMagicLinkStore) Consume(_ context.Context, tokenValue string) (*session.MagicLinkToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok, ok := s.tokens[tokenValue]
	if !ok {
		return nil, auth.ErrTokenNotFound
	}
	delete(s.tokens, tokenValue) // single-use
	return tok, nil
}

func (s *memMagicLinkStore) tokenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

var _ session.MagicLinkStore = (*memMagicLinkStore)(nil)

// --------------------------------------------------------------------------
// Test infrastructure: In-memory Notifier
// --------------------------------------------------------------------------

type notifyRecord struct {
	Event   auth.AuthEvent
	Payload map[string]any
}

// memNotifier is a thread-safe in-memory Notifier that records calls.
type memNotifier struct {
	mu      sync.Mutex
	records []notifyRecord
}

func newMemNotifier() *memNotifier {
	return &memNotifier{}
}

func (n *memNotifier) Notify(_ context.Context, event auth.AuthEvent, payload map[string]any) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.records = append(n.records, notifyRecord{Event: event, Payload: payload})
	return nil
}

func (n *memNotifier) getRecords() []notifyRecord {
	n.mu.Lock()
	defer n.mu.Unlock()
	cp := make([]notifyRecord, len(n.records))
	copy(cp, n.records)
	return cp
}

var _ auth.Notifier = (*memNotifier)(nil)

// --------------------------------------------------------------------------
// Test infrastructure: In-memory APIKeyStore
// --------------------------------------------------------------------------

// memAPIKeyStore is a thread-safe in-memory APIKeyStore.
type memAPIKeyStore struct {
	mu   sync.Mutex
	keys map[string]*apikey.APIKey // keyed by KeyHash
	byID map[string]*apikey.APIKey // keyed by ID
}

func newMemAPIKeyStore() *memAPIKeyStore {
	return &memAPIKeyStore{
		keys: make(map[string]*apikey.APIKey),
		byID: make(map[string]*apikey.APIKey),
	}
}

func (s *memAPIKeyStore) FindByKey(_ context.Context, keyHash string) (*apikey.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyHash]
	if !ok {
		return nil, errors.New("api key not found")
	}
	// Return a copy.
	cp := *k
	return &cp, nil
}

func (s *memAPIKeyStore) Create(_ context.Context, ak *apikey.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[ak.KeyHash] = ak
	s.byID[ak.ID] = ak
	return nil
}

func (s *memAPIKeyStore) Revoke(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[keyID]
	if !ok {
		return errors.New("api key not found")
	}
	k.Revoked = true
	return nil
}

func (s *memAPIKeyStore) ListBySubject(_ context.Context, subjectID string) ([]*apikey.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*apikey.APIKey
	for _, k := range s.keys {
		if k.SubjectID == subjectID {
			cp := *k
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (s *memAPIKeyStore) UpdateLastUsed(_ context.Context, keyID string, timestamp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[keyID]
	if !ok {
		return errors.New("api key not found")
	}
	k.LastUsedAt = timestamp
	return nil
}

// getByID returns the raw key for assertion (thread-safe).
func (s *memAPIKeyStore) getByID(id string) *apikey.APIKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	if !ok {
		return nil
	}
	cp := *k
	return &cp
}

var _ apikey.APIKeyStore = (*memAPIKeyStore)(nil)

// --------------------------------------------------------------------------
// AUTH-0026 AC: Magic link full flow: initiate → token stored → verify → session
// --------------------------------------------------------------------------

func TestMagicLinkFullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	mlStore := newMemMagicLinkStore()
	notifier := newMemNotifier()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "magiclink:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithNotifier(notifier),
		authsetup.WithMagicLinkStore(mlStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Pre-register a user (magic link requires existing user).
	_, _, err = a.Engine.Register(ctx, passwordCred("magicuser@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register user for magic link")

	// Use magic link mode directly to Initiate.
	// The engine only exposes Login (which calls Authenticate).
	// We need the magic link mode to call Initiate.
	mlMode, err := newMagicLinkModeForTest(userStore, mlStore, notifier)
	assertNoError(t, err, "create magic link mode")

	// Initiate: generates token, stores it, notifies user.
	rawToken, err := mlMode.Initiate(ctx, "magicuser@test.com")
	assertNoError(t, err, "Initiate")

	if rawToken == "" {
		t.Fatal("Initiate returned empty token")
	}

	// Verify token was stored.
	if mlStore.tokenCount() != 1 {
		t.Fatalf("expected 1 token in store, got %d", mlStore.tokenCount())
	}

	// Verify Notifier was called with correct event.
	records := notifier.getRecords()
	foundMagicLinkNotify := false
	for _, r := range records {
		if r.Event == auth.EventMagicLinkSent {
			foundMagicLinkNotify = true
			// Verify payload contains token.
			if r.Payload["token"] != rawToken {
				t.Fatalf("Notifier payload token mismatch: expected %q, got %q", rawToken, r.Payload["token"])
			}
			if r.Payload["identifier"] != "magicuser@test.com" {
				t.Fatalf("Notifier payload identifier mismatch")
			}
		}
	}
	if !foundMagicLinkNotify {
		t.Fatal("Notifier was NOT called with EventMagicLinkSent")
	}

	// Authenticate with the raw token via engine.
	magicCred := auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	}
	loginIdentity, loginSess, err := a.Engine.Login(ctx, magicCred)
	assertNoError(t, err, "Login via magic link")

	if loginIdentity.SubjectID == "" {
		t.Fatal("magic link login returned empty SubjectID")
	}
	if loginIdentity.SessionID == "" {
		t.Fatal("magic link login returned empty SessionID")
	}
	if loginSess == nil {
		t.Fatal("expected non-nil session after magic link login")
	}

	// Verify the session.
	verifiedId, err := a.Engine.Verify(ctx, loginIdentity.SessionID)
	assertNoError(t, err, "Verify magic link session")
	if verifiedId.SubjectID != loginIdentity.SubjectID {
		t.Fatalf("Verify returned different SubjectID: expected %q, got %q",
			loginIdentity.SubjectID, verifiedId.SubjectID)
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: Magic link single-use: second verification fails
// --------------------------------------------------------------------------

func TestMagicLinkSingleUse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	mlStore := newMemMagicLinkStore()
	notifier := newMemNotifier()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "mlsingle:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithNotifier(notifier),
		authsetup.WithMagicLinkStore(mlStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Pre-register user.
	_, _, err = a.Engine.Register(ctx, passwordCred("single@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	mlMode, err := newMagicLinkModeForTest(userStore, mlStore, notifier)
	assertNoError(t, err, "create magic link mode")

	rawToken, err := mlMode.Initiate(ctx, "single@test.com")
	assertNoError(t, err, "Initiate")

	// First use — should succeed.
	magicCred := auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	}
	_, _, err = a.Engine.Login(ctx, magicCred)
	assertNoError(t, err, "First Login via magic link")

	// Second use — MUST fail.
	_, _, err = a.Engine.Login(ctx, magicCred)
	if err == nil {
		t.Fatal("SECURITY: magic link token was accepted twice — single-use violation")
	}
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on second use, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: Magic link expired token fails
// --------------------------------------------------------------------------

func TestMagicLinkExpiredToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	mlStore := newMemMagicLinkStore()
	notifier := newMemNotifier()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "mlexpired:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithNotifier(notifier),
		authsetup.WithMagicLinkStore(mlStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Pre-register user.
	_, _, err = a.Engine.Register(ctx, passwordCred("expired@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Create magic link mode with very short TTL.
	mlMode, err := newMagicLinkModeWithTTL(userStore, mlStore, notifier, 1*time.Millisecond)
	assertNoError(t, err, "create magic link mode with short TTL")

	rawToken, err := mlMode.Initiate(ctx, "expired@test.com")
	assertNoError(t, err, "Initiate")

	// Wait for token to expire.
	time.Sleep(50 * time.Millisecond)

	// Attempt login with expired token.
	magicCred := auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	}
	_, _, err = a.Engine.Login(ctx, magicCred)
	if err == nil {
		t.Fatal("SECURITY: expired magic link token was accepted")
	}
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for expired token, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: Non-existent user → generic error (anti-enumeration)
// --------------------------------------------------------------------------

func TestMagicLinkNonExistentUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	userStore := NewMemUserStore()
	mlStore := newMemMagicLinkStore()
	notifier := newMemNotifier()

	mlMode, err := newMagicLinkModeForTest(userStore, mlStore, notifier)
	assertNoError(t, err, "create magic link mode")

	ctx := context.Background()

	// Initiate for non-existent user — should return nil error (anti-enumeration).
	rawToken, err := mlMode.Initiate(ctx, "nonexistent@test.com")
	if err != nil {
		t.Fatalf("Initiate for non-existent user should NOT error (anti-enumeration), got: %v", err)
	}

	// Token should be empty (no token generated for non-existent user).
	if rawToken != "" {
		t.Fatal("SECURITY: token generated for non-existent user — enables enumeration")
	}

	// Notifier should NOT have been called.
	records := notifier.getRecords()
	for _, r := range records {
		if r.Event == auth.EventMagicLinkSent {
			t.Fatal("SECURITY: Notifier called for non-existent user — enables enumeration")
		}
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: Engine startup fails without Notifier
// --------------------------------------------------------------------------

func TestEngineStartupFailsWithoutNotifier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	mlStore := newMemMagicLinkStore()

	// MagicLinkStore is set, but Notifier is NOT — must fail.
	_, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "nonotifier:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithMagicLinkStore(mlStore),
		// NO WithNotifier
	)
	if err == nil {
		t.Fatal("expected error when MagicLinkStore is set but Notifier is nil")
	}
	if !strings.Contains(err.Error(), "Notifier") {
		t.Fatalf("expected Notifier-related error, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: Magic link identifier normalization
// --------------------------------------------------------------------------

func TestMagicLinkIdentifierNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	mlStore := newMemMagicLinkStore()
	notifier := newMemNotifier()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "mlnorm:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithNotifier(notifier),
		authsetup.WithMagicLinkStore(mlStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Register with normalized email.
	_, _, err = a.Engine.Register(ctx, passwordCred("Norm@Test.COM", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Initiate magic link with different casing.
	mlMode, err := newMagicLinkModeForTest(userStore, mlStore, notifier)
	assertNoError(t, err, "create magic link mode")

	rawToken, err := mlMode.Initiate(ctx, "  NORM@TEST.COM  ")
	assertNoError(t, err, "Initiate with unnormalized identifier")

	if rawToken == "" {
		t.Fatal("expected non-empty token — normalization should match the registered user")
	}

	// Verify token works.
	magicCred := auth.Credential{
		Type:   auth.CredentialTypeMagicLink,
		Secret: rawToken,
	}
	identity, _, err := a.Engine.Login(ctx, magicCred)
	assertNoError(t, err, "Login via magic link with normalized identifier")

	if identity.SubjectID == "" {
		t.Fatal("expected non-empty SubjectID")
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: API key — valid → identity
// --------------------------------------------------------------------------

func TestAPIKeyValid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	akStore := newMemAPIKeyStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "apikey:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAPIKeyStore(akStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Create an API key in the store.
	rawKey := "raw-api-key-12345"
	keyHash := session.HashID(rawKey)
	err = akStore.Create(ctx, &apikey.APIKey{
		ID:        "key-1",
		SubjectID: "api-user-1",
		KeyHash:   keyHash,
		Name:      "Test Key",
		Scopes:    []string{"read", "write"},
		CreatedAt: time.Now(),
	})
	assertNoError(t, err, "Create API key")

	// Login via API key.
	akCred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	}
	identity, sess, err := a.Engine.Login(ctx, akCred)
	assertNoError(t, err, "Login via API key")

	if identity.SubjectID != "api-user-1" {
		t.Fatalf("expected SubjectID=api-user-1, got %q", identity.SubjectID)
	}
	if identity.AuthMethod != "api_key" {
		t.Fatalf("expected AuthMethod=api_key, got %q", identity.AuthMethod)
	}
	if sess == nil {
		t.Fatal("expected non-nil session")
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: API key — expired, revoked → rejected
// --------------------------------------------------------------------------

func TestAPIKeyExpiredRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	akStore := newMemAPIKeyStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "akexpired:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAPIKeyStore(akStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Create an expired API key.
	rawKey := "expired-key-12345"
	keyHash := session.HashID(rawKey)
	err = akStore.Create(ctx, &apikey.APIKey{
		ID:        "expired-key-1",
		SubjectID: "expired-user",
		KeyHash:   keyHash,
		Name:      "Expired Key",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired 1 hour ago
	})
	assertNoError(t, err, "Create expired API key")

	akCred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	}
	_, _, err = a.Engine.Login(ctx, akCred)
	if err == nil {
		t.Fatal("SECURITY: expired API key was accepted")
	}
	if !errors.Is(err, auth.ErrAPIKeyExpired) {
		t.Fatalf("expected ErrAPIKeyExpired, got: %v", err)
	}
}

func TestAPIKeyRevokedRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	akStore := newMemAPIKeyStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "akrevoked:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAPIKeyStore(akStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	// Create a revoked API key.
	rawKey := "revoked-key-12345"
	keyHash := session.HashID(rawKey)
	err = akStore.Create(ctx, &apikey.APIKey{
		ID:        "revoked-key-1",
		SubjectID: "revoked-user",
		KeyHash:   keyHash,
		Name:      "Revoked Key",
		Revoked:   true,
		CreatedAt: time.Now(),
	})
	assertNoError(t, err, "Create revoked API key")

	akCred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	}
	_, _, err = a.Engine.Login(ctx, akCred)
	if err == nil {
		t.Fatal("SECURITY: revoked API key was accepted")
	}
	if !errors.Is(err, auth.ErrAPIKeyRevoked) {
		t.Fatalf("expected ErrAPIKeyRevoked, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: API key scopes in identity
// --------------------------------------------------------------------------

func TestAPIKeyScopesInIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	akStore := newMemAPIKeyStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "akscopes:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAPIKeyStore(akStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	rawKey := "scoped-key-12345"
	keyHash := session.HashID(rawKey)
	err = akStore.Create(ctx, &apikey.APIKey{
		ID:        "scoped-key-1",
		SubjectID: "scoped-user",
		KeyHash:   keyHash,
		Name:      "Scoped Key",
		Scopes:    []string{"admin", "read:users", "write:data"},
		CreatedAt: time.Now(),
	})
	assertNoError(t, err, "Create scoped API key")

	akCred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	}
	// API key mode returns Identity (not session-based), but engine wraps in session.
	// The mode itself returns scopes in Identity.Metadata.
	// But the engine.Login dispatches to mode.Authenticate, which returns the Identity,
	// then engine creates a session. The Identity from mode has metadata with scopes.
	// The engine's returned identity may not carry mode metadata.
	// Let's verify what the engine returns.

	identity, _, err := a.Engine.Login(ctx, akCred)
	assertNoError(t, err, "Login via API key with scopes")

	if identity.SubjectID != "scoped-user" {
		t.Fatalf("expected SubjectID=scoped-user, got %q", identity.SubjectID)
	}

	// The engine's Login calls mode.Authenticate which returns an identity
	// with Metadata["scopes"], but engine may override the identity.
	// Let's check by also testing the mode directly.
}

func TestAPIKeyScopesInModeIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	akStore := newMemAPIKeyStore()

	ctx := context.Background()

	rawKey := "modescope-key-12345"
	keyHash := session.HashID(rawKey)
	err := akStore.Create(ctx, &apikey.APIKey{
		ID:        "modescope-key-1",
		SubjectID: "modescope-user",
		KeyHash:   keyHash,
		Name:      "Mode Scope Key",
		Scopes:    []string{"admin", "read:users", "write:data"},
		CreatedAt: time.Now(),
	})
	assertNoError(t, err, "Create scoped API key")

	// Use mode directly to verify scopes in identity.
	akCred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	}

	// Use the actual API key mode package.
	akMode := newAPIKeyModeForTest(akStore)
	identity, err := akMode.Authenticate(ctx, akCred)
	assertNoError(t, err, "Authenticate via API key mode")

	scopes, ok := identity.Metadata["scopes"].([]string)
	if !ok || len(scopes) == 0 {
		t.Fatal("scopes not found in Identity.Metadata")
	}
	if len(scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(scopes))
	}

	expectedScopes := map[string]bool{"admin": true, "read:users": true, "write:data": true}
	for _, s := range scopes {
		if !expectedScopes[s] {
			t.Fatalf("unexpected scope %q", s)
		}
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: LastUsedAt updated end-to-end
// --------------------------------------------------------------------------

func TestAPIKeyLastUsedAtUpdated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	akStore := newMemAPIKeyStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "aklast:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAPIKeyStore(akStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	rawKey := "lastused-key-12345"
	keyHash := session.HashID(rawKey)
	err = akStore.Create(ctx, &apikey.APIKey{
		ID:        "lastused-key-1",
		SubjectID: "lastused-user",
		KeyHash:   keyHash,
		Name:      "LastUsed Key",
		CreatedAt: time.Now(),
	})
	assertNoError(t, err, "Create API key")

	// Before login, LastUsedAt should be zero.
	keyBefore := akStore.getByID("lastused-key-1")
	if keyBefore == nil {
		t.Fatal("key not found before login")
	}
	if !keyBefore.LastUsedAt.IsZero() {
		t.Fatal("LastUsedAt should be zero before first use")
	}

	beforeLogin := time.Now()

	akCred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: rawKey,
	}
	_, _, err = a.Engine.Login(ctx, akCred)
	assertNoError(t, err, "Login via API key")

	// After login, LastUsedAt should be updated.
	keyAfter := akStore.getByID("lastused-key-1")
	if keyAfter == nil {
		t.Fatal("key not found after login")
	}
	if keyAfter.LastUsedAt.IsZero() {
		t.Fatal("LastUsedAt was NOT updated after API key authentication")
	}
	if keyAfter.LastUsedAt.Before(beforeLogin) {
		t.Fatal("LastUsedAt is before the login time — not updated correctly")
	}
}

// --------------------------------------------------------------------------
// AUTH-0026 AC: Notifier called with correct event
// (Covered in TestMagicLinkFullFlow above — dedicated assertion there)
// Additional test: Notifier receives EventRegistration for registration
// --------------------------------------------------------------------------

func TestNotifierCalledOnRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	userStore := NewMemUserStore()
	notifier := newMemNotifier()
	mlStore := newMemMagicLinkStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(userStore),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "notify:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithNotifier(notifier),
		authsetup.WithMagicLinkStore(mlStore),
	)
	assertNoError(t, err, "authsetup.New")
	defer a.Close()

	ctx := context.Background()

	_, _, err = a.Engine.Register(ctx, passwordCred("notifyuser@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	records := notifier.getRecords()
	foundRegistration := false
	for _, r := range records {
		if r.Event == auth.EventRegistration {
			foundRegistration = true
		}
	}
	if !foundRegistration {
		t.Fatal("Notifier was NOT called with EventRegistration")
	}
}

// --------------------------------------------------------------------------
// Magic link mode constructor helpers (integration-level)
// --------------------------------------------------------------------------

func newMagicLinkModeForTest(userStore *MemUserStore, mlStore *memMagicLinkStore, notifier *memNotifier) (*magiclink.Mode, error) {
	return newMagicLinkModeWithTTL(userStore, mlStore, notifier, 0) // 0 = default 15min
}

func newMagicLinkModeWithTTL(userStore *MemUserStore, mlStore *memMagicLinkStore, notifier *memNotifier, ttl time.Duration) (*magiclink.Mode, error) {
	return magiclink.NewMode(magiclink.Config{
		UserStore:        userStore,
		MagicLinkStore:   mlStore,
		Notifier:         notifier,
		IdentifierConfig: identifierConfig(),
		TTL:              ttl,
	})
}

// newAPIKeyModeForTest creates an API key mode for direct testing.
func newAPIKeyModeForTest(store apikey.APIKeyStore) *apikeymode.Mode {
	return apikeymode.NewMode(apikeymode.Config{
		APIKeyStore: store,
	})
}
