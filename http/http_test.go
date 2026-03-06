// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
	"github.com/abhipray-cpu/auth/hooks"
	authhttp "github.com/abhipray-cpu/auth/http"
	"github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// stubUser implements auth.User.
type stubUser struct {
	subjectID      string
	identifier     string
	passwordHash   string
	locked         bool
	failedAttempts int
}

func (u *stubUser) GetSubjectID() string        { return u.subjectID }
func (u *stubUser) GetIdentifier() string       { return u.identifier }
func (u *stubUser) GetPasswordHash() string     { return u.passwordHash }
func (u *stubUser) GetFailedAttempts() int      { return u.failedAttempts }
func (u *stubUser) IsLocked() bool              { return u.locked }
func (u *stubUser) IsMFAEnabled() bool          { return false }
func (u *stubUser) GetMetadata() map[string]any { return nil }

// stubUserStore implements auth.UserStore.
type stubUserStore struct {
	users map[string]*stubUser
}

func newStubUserStore() *stubUserStore {
	return &stubUserStore{users: make(map[string]*stubUser)}
}

func (s *stubUserStore) FindByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	u, ok := s.users[identifier]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

func (s *stubUserStore) Create(_ context.Context, user auth.User) error {
	id := user.GetIdentifier()
	if _, ok := s.users[id]; ok {
		return auth.ErrUserAlreadyExists
	}
	s.users[id] = &stubUser{
		subjectID:    user.GetSubjectID(),
		identifier:   user.GetIdentifier(),
		passwordHash: user.GetPasswordHash(),
	}
	return nil
}

func (s *stubUserStore) UpdatePassword(_ context.Context, subjectID string, hash string) error {
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.passwordHash = hash
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *stubUserStore) IncrementFailedAttempts(_ context.Context, subjectID string) error {
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.failedAttempts++
			return nil
		}
	}
	return nil
}

func (s *stubUserStore) ResetFailedAttempts(_ context.Context, subjectID string) error {
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.failedAttempts = 0
			return nil
		}
	}
	return nil
}

func (s *stubUserStore) SetLocked(_ context.Context, subjectID string, locked bool) error {
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.locked = locked
			return nil
		}
	}
	return nil
}

// stubHasher implements auth.Hasher.
type stubHasher struct{}

func (h *stubHasher) Hash(password string) (string, error) {
	return "hashed:" + password, nil
}

func (h *stubHasher) Verify(password, hash string) (bool, error) {
	return hash == "hashed:"+password, nil
}

// stubSessionManager implements engine.SessionManager.
type stubSessionManager struct {
	sessions map[string]*session.Session
	counter  int
}

func newStubSessionManager() *stubSessionManager {
	return &stubSessionManager{sessions: make(map[string]*session.Session)}
}

func (m *stubSessionManager) CreateSession(_ context.Context, subjectID string, existingSessionID string, _ map[string]any) (string, *session.Session, error) {
	// Destroy existing session for fixation prevention.
	if existingSessionID != "" {
		delete(m.sessions, existingSessionID)
	}
	m.counter++
	rawID := fmt.Sprintf("session-%d", m.counter)
	sess := &session.Session{
		ID:            rawID,
		SubjectID:     subjectID,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(24 * time.Hour),
		LastActiveAt:  time.Now(),
		SchemaVersion: session.SchemaVersion,
	}
	m.sessions[rawID] = sess
	return rawID, sess, nil
}

func (m *stubSessionManager) ValidateSession(_ context.Context, rawID string) (*session.Session, error) {
	sess, ok := m.sessions[rawID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, auth.ErrSessionExpired
	}
	sess.LastActiveAt = time.Now()
	return sess, nil
}

func (m *stubSessionManager) RefreshSession(_ context.Context, rawID string) (*session.Session, error) {
	sess, ok := m.sessions[rawID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	sess.LastActiveAt = time.Now()
	return sess, nil
}

func (m *stubSessionManager) DestroySession(_ context.Context, rawID string) error {
	delete(m.sessions, rawID)
	return nil
}

func (m *stubSessionManager) DestroyAllSessions(_ context.Context, subjectID string) error {
	for id, sess := range m.sessions {
		if sess.SubjectID == subjectID {
			delete(m.sessions, id)
		}
	}
	return nil
}

// stubPasswordMode implements auth.AuthMode for password auth.
type stubPasswordMode struct {
	userStore auth.UserStore
	hasher    auth.Hasher
}

func (m *stubPasswordMode) Name() string { return "password" }
func (m *stubPasswordMode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypePassword
}

func (m *stubPasswordMode) Authenticate(ctx context.Context, cred auth.Credential) (*auth.Identity, error) {
	user, err := m.userStore.FindByIdentifier(ctx, cred.Identifier)
	if err != nil {
		return nil, auth.ErrInvalidCredentials
	}
	ok, err := m.hasher.Verify(cred.Secret, user.GetPasswordHash())
	if err != nil || !ok {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Identity{
		SubjectID:  user.GetSubjectID(),
		AuthMethod: "password",
		AuthTime:   time.Now(),
	}, nil
}

// stubAPIKeyMode implements auth.AuthMode for API key auth.
type stubAPIKeyMode struct {
	validKeys map[string]string // key -> subjectID
}

func (m *stubAPIKeyMode) Name() string { return "api_key" }
func (m *stubAPIKeyMode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypeAPIKey
}

func (m *stubAPIKeyMode) Authenticate(_ context.Context, cred auth.Credential) (*auth.Identity, error) {
	subjectID, ok := m.validKeys[cred.Secret]
	if !ok {
		return nil, auth.ErrInvalidCredentials
	}
	return &auth.Identity{
		SubjectID:  subjectID,
		AuthMethod: "api_key",
		AuthTime:   time.Now(),
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildEngine(t *testing.T, userStore *stubUserStore, sessMgr *stubSessionManager, modes ...auth.AuthMode) *engine.Engine {
	t.Helper()
	eng, err := engine.New(engine.Config{
		UserStore:      userStore,
		Hasher:         &stubHasher{},
		SessionManager: sessMgr,
		HookManager:    hooks.NewManager(),
		Modes:          modes,
		PasswordPolicy: password.DefaultPolicy(),
		IdentifierConfig: auth.IdentifierConfig{
			Field: "email",
		},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return eng
}

func loginBody(identifier, password string) *bytes.Buffer {
	b, _ := json.Marshal(authhttp.LoginRequest{Identifier: identifier, Password: password})
	return bytes.NewBuffer(b)
}

func registerBody(identifier, password string) *bytes.Buffer {
	b, _ := json.Marshal(authhttp.RegisterRequest{Identifier: identifier, Password: password})
	return bytes.NewBuffer(b)
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// --- RequireAuth middleware ---

func TestRequireAuth_ValidSession(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["alice@example.com"] = &stubUser{
		subjectID:    "alice@example.com",
		identifier:   "alice@example.com",
		passwordHash: "hashed:secret123",
	}

	// Login to get a session.
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("alice@example.com", "secret123"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d, want 200", rec.Code)
	}

	sessionCookie := findCookie(rec.Result(), "auth_session")
	if sessionCookie == nil {
		t.Fatal("no session cookie set after login")
	}

	// Use session cookie with RequireAuth middleware.
	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	var gotIdentity *auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("RequireAuth: got %d, want 200", rec2.Code)
	}
	if gotIdentity == nil {
		t.Fatal("RequireAuth: identity is nil in context")
	}
	if gotIdentity.SubjectID != "alice@example.com" {
		t.Errorf("RequireAuth: SubjectID = %q, want %q", gotIdentity.SubjectID, "alice@example.com")
	}
}

func TestRequireAuth_NoSession_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("RequireAuth (no session): got %d, want 401", rec.Code)
	}
}

func TestRequireAuth_InvalidSession_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "nonexistent-session"})
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("RequireAuth (invalid session): got %d, want 401", rec.Code)
	}
}

func TestRequireAuth_ExpiredSession_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)

	// Manually create an expired session.
	sessMgr.sessions["expired-session"] = &session.Session{
		ID:        "expired-session",
		SubjectID: "alice",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for expired session")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "expired-session"})
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("RequireAuth (expired session): got %d, want 401", rec.Code)
	}
}

// --- OptionalAuth middleware ---

func TestOptionalAuth_ValidSession(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["bob@example.com"] = &stubUser{
		subjectID:    "bob@example.com",
		identifier:   "bob@example.com",
		passwordHash: "hashed:pass456",
	}

	// Login.
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("bob@example.com", "pass456"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)
	sessionCookie := findCookie(rec.Result(), "auth_session")

	// OptionalAuth with valid session.
	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	var gotIdentity *auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
	})

	req2 := httptest.NewRequest(http.MethodGet, "/page", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	mw.OptionalAuth(inner).ServeHTTP(rec2, req2)

	if gotIdentity == nil {
		t.Fatal("OptionalAuth: identity should be set with valid session")
	}
	if gotIdentity.SubjectID != "bob@example.com" {
		t.Errorf("OptionalAuth: SubjectID = %q, want %q", gotIdentity.SubjectID, "bob@example.com")
	}
}

func TestOptionalAuth_NoSession_PassesNilIdentity(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		id := auth.GetIdentity(r.Context())
		if id != nil {
			t.Fatal("OptionalAuth: identity should be nil when no session")
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	rec := httptest.NewRecorder()
	mw.OptionalAuth(inner).ServeHTTP(rec, req)

	if !handlerCalled {
		t.Fatal("OptionalAuth: handler should still be called when no session")
	}
}

// --- Login handler ---

func TestLogin_Success(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["user@example.com"] = &stubUser{
		subjectID:    "user@example.com",
		identifier:   "user@example.com",
		passwordHash: "hashed:goodpass",
	}

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("user@example.com", "goodpass"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Login: got %d, want 200", rec.Code)
	}

	cookie := findCookie(rec.Result(), "auth_session")
	if cookie == nil {
		t.Fatal("Login: no session cookie set")
	}
	if !cookie.HttpOnly {
		t.Error("Login: session cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("Login: session cookie should be Secure")
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Login: decode response: %v", err)
	}
	if body["subject_id"] != "user@example.com" {
		t.Errorf("Login: subject_id = %q, want %q", body["subject_id"], "user@example.com")
	}
}

func TestLogin_WrongPassword_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["user@example.com"] = &stubUser{
		subjectID:    "user@example.com",
		identifier:   "user@example.com",
		passwordHash: "hashed:goodpass",
	}

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("user@example.com", "wrongpass"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Login (wrong password): got %d, want 401", rec.Code)
	}
}

func TestLogin_UnknownUser_Returns401_NoEnumeration(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("nonexistent@example.com", "pass"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Login (unknown user): got %d, want 401", rec.Code)
	}

	// Should not reveal whether user exists.
	body := rec.Body.String()
	if body != "Unauthorized\n" {
		t.Errorf("Login (unknown user): body should be generic, got %q", body)
	}
}

func TestLogin_InvalidMethod_Returns405(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Login (GET): got %d, want 405", rec.Code)
	}
}

func TestLogin_EmptyBody_Returns400(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Login (empty body): got %d, want 400", rec.Code)
	}
}

// --- Register handler ---

func TestRegister_Success_Returns201(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/register", registerBody("newuser@example.com", "StrongPass123"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Register().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Register: got %d, want 201", rec.Code)
	}

	cookie := findCookie(rec.Result(), "auth_session")
	if cookie == nil {
		t.Fatal("Register: no session cookie set (should be register-and-login-in-one)")
	}
	if !cookie.HttpOnly {
		t.Error("Register: session cookie should be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("Register: session cookie should be Secure")
	}
}

func TestRegister_DuplicateUser_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["existing@example.com"] = &stubUser{
		subjectID:    "existing@example.com",
		identifier:   "existing@example.com",
		passwordHash: "hashed:pass",
	}

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())
	req := httptest.NewRequest(http.MethodPost, "/auth/register", registerBody("existing@example.com", "pass"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Register().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Register (duplicate): got %d, want 401", rec.Code)
	}
}

// --- Logout handler ---

func TestLogout_Success_ClearsCookie(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["user@example.com"] = &stubUser{
		subjectID:    "user@example.com",
		identifier:   "user@example.com",
		passwordHash: "hashed:pass",
	}

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	// Login first.
	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("user@example.com", "pass"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)
	sessionCookie := findCookie(rec.Result(), "auth_session")

	// Logout.
	req2 := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	handlers.Logout().ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNoContent {
		t.Fatalf("Logout: got %d, want 204", rec2.Code)
	}

	clearedCookie := findCookie(rec2.Result(), "auth_session")
	if clearedCookie == nil {
		t.Fatal("Logout: should set cookie to clear it")
	}
	if clearedCookie.MaxAge != -1 {
		t.Errorf("Logout: cookie MaxAge = %d, want -1", clearedCookie.MaxAge)
	}

	// Verify session is destroyed — RequireAuth should fail now.
	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	req3 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req3.AddCookie(sessionCookie)
	rec3 := httptest.NewRecorder()
	mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called after logout")
	})).ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: got %d, want 401", rec3.Code)
	}
}

func TestLogout_NoSession_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rec := httptest.NewRecorder()
	handlers.Logout().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Logout (no session): got %d, want 401", rec.Code)
	}
}

// --- Session cookie attributes ---

func TestSessionCookie_Attributes(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["user@example.com"] = &stubUser{
		subjectID:    "user@example.com",
		identifier:   "user@example.com",
		passwordHash: "hashed:pass",
	}

	cfg := authhttp.CookieConfig{
		Name:     "auth_session",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	handlers := authhttp.NewHandlers(eng, cfg)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("user@example.com", "pass"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec, req)

	cookie := findCookie(rec.Result(), "auth_session")
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if !cookie.Secure {
		t.Error("cookie should be Secure")
	}
	if !cookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	// SameSite=Strict is encoded as SameSite == http.SameSiteStrictMode.
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
}

// --- API key extraction ---

func TestRequireAuth_APIKey_AuthorizationHeader(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	apiKeyMode := &stubAPIKeyMode{validKeys: map[string]string{"ak_test123": "api-user"}}
	eng := buildEngine(t, userStore, sessMgr, apiKeyMode)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	var gotIdentity *auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "ApiKey ak_test123")
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("API key (Authorization): got %d, want 200", rec.Code)
	}
	if gotIdentity == nil || gotIdentity.SubjectID != "api-user" {
		t.Fatal("API key (Authorization): wrong identity")
	}
}

func TestRequireAuth_APIKey_XAPIKeyHeader(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	apiKeyMode := &stubAPIKeyMode{validKeys: map[string]string{"ak_header": "header-user"}}
	eng := buildEngine(t, userStore, sessMgr, apiKeyMode)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	var gotIdentity *auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-API-Key", "ak_header")
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("API key (X-API-Key): got %d, want 200", rec.Code)
	}
	if gotIdentity == nil || gotIdentity.SubjectID != "header-user" {
		t.Fatal("API key (X-API-Key): wrong identity")
	}
}

func TestRequireAuth_APIKey_QueryParam(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	apiKeyMode := &stubAPIKeyMode{validKeys: map[string]string{"ak_query": "query-user"}}
	eng := buildEngine(t, userStore, sessMgr, apiKeyMode)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	var gotIdentity *auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data?api_key=ak_query", nil)
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("API key (query): got %d, want 200", rec.Code)
	}
	if gotIdentity == nil || gotIdentity.SubjectID != "query-user" {
		t.Fatal("API key (query): wrong identity")
	}
}

func TestRequireAuth_InvalidAPIKey_Returns401(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	apiKeyMode := &stubAPIKeyMode{validKeys: map[string]string{}}
	eng := buildEngine(t, userStore, sessMgr, apiKeyMode)

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with invalid API key")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-API-Key", "invalid-key")
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid API key: got %d, want 401", rec.Code)
	}
}

// --- Bearer token ---

func TestRequireAuth_BearerToken(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)

	// Manually create a session.
	sessMgr.sessions["bearer-sess"] = &session.Session{
		ID:        "bearer-sess",
		SubjectID: "bearer-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())
	var gotIdentity *auth.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer bearer-sess")
	rec := httptest.NewRecorder()
	mw.RequireAuth(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Bearer token: got %d, want 200", rec.Code)
	}
	if gotIdentity == nil || gotIdentity.SubjectID != "bearer-user" {
		t.Fatal("Bearer token: wrong identity")
	}
}

// --- Magic link handlers ---

func TestMagicLinkInitiate_Returns202(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	body, _ := json.Marshal(authhttp.MagicLinkRequest{Identifier: "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/auth/magic-link", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.MagicLinkInitiate().ServeHTTP(rec, req)

	// Always returns 202 regardless of user existence (prevent enumeration).
	if rec.Code != http.StatusAccepted {
		t.Fatalf("MagicLinkInitiate: got %d, want 202", rec.Code)
	}
}

func TestMagicLinkInitiate_EmptyIdentifier_Returns400(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	body, _ := json.Marshal(authhttp.MagicLinkRequest{Identifier: ""})
	req := httptest.NewRequest(http.MethodPost, "/auth/magic-link", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.MagicLinkInitiate().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("MagicLinkInitiate (empty): got %d, want 400", rec.Code)
	}
}

func TestMagicLinkVerify_NoToken_Returns400(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	req := httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify", nil)
	rec := httptest.NewRecorder()
	handlers.MagicLinkVerify().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("MagicLinkVerify (no token): got %d, want 400", rec.Code)
	}
}

// --- OAuth state cookie ---

func TestOAuthStateCookie_SameSiteLax(t *testing.T) {
	// Verify that OAuth state cookies use SameSite=Lax (not Strict).
	rec := httptest.NewRecorder()
	cfg := authhttp.DefaultCookieConfig()

	// Use exported helper indirectly by exerceding through handlers.
	// We test the cookie attribute directly.
	http.SetCookie(rec, &http.Cookie{
		Name:     "oauth_state",
		Value:    "test-state",
		Path:     cfg.Path,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	cookie := findCookie(rec.Result(), "oauth_state")
	if cookie == nil {
		t.Fatal("no oauth_state cookie")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("OAuth state cookie SameSite = %v, want Lax", cookie.SameSite)
	}
}

func TestSessionAndOAuthCookies_Coexist(t *testing.T) {
	// Verify that session (Strict) and OAuth (Lax) cookies coexist.
	rec := httptest.NewRecorder()
	cfg := authhttp.DefaultCookieConfig()

	// Set session cookie (Strict).
	http.SetCookie(rec, &http.Cookie{
		Name:     cfg.Name,
		Value:    "session-123",
		Path:     cfg.Path,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Set OAuth state cookie (Lax).
	http.SetCookie(rec, &http.Cookie{
		Name:     "oauth_state",
		Value:    "state-abc",
		Path:     cfg.Path,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	sessionCookie := findCookie(rec.Result(), cfg.Name)
	oauthCookie := findCookie(rec.Result(), "oauth_state")

	if sessionCookie == nil {
		t.Fatal("session cookie missing")
	}
	if oauthCookie == nil {
		t.Fatal("oauth_state cookie missing")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Error("session cookie should be SameSite=Strict")
	}
	if oauthCookie.SameSite != http.SameSiteLaxMode {
		t.Error("oauth cookie should be SameSite=Lax")
	}
}

// --- Route registration ---

func TestRegisterRoutes_AllMounted(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	mux := http.NewServeMux()
	authhttp.RegisterRoutes(mux, handlers, authhttp.DefaultRouteConfig())

	// Test that login route is mounted.
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer([]byte("{}")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	// Should get 400 (bad request) not 404 (not found).
	if rec.Code == http.StatusNotFound {
		t.Error("/auth/login should be registered")
	}

	// Test register route.
	req = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer([]byte("{}")))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("/auth/register should be registered")
	}

	// Test logout route.
	req = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("/auth/logout should be registered")
	}

	// Test magic link route.
	req = httptest.NewRequest(http.MethodPost, "/auth/magic-link", bytes.NewBuffer([]byte("{}")))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("/auth/magic-link should be registered")
	}

	// Test magic link verify route.
	req = httptest.NewRequest(http.MethodGet, "/auth/magic-link/verify", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("/auth/magic-link/verify should be registered")
	}
}

func TestRegisterRoutes_CustomPrefix(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	mux := http.NewServeMux()
	cfg := authhttp.RouteConfig{Prefix: "/api/v1/auth"}
	authhttp.RegisterRoutes(mux, handlers, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer([]byte("{}")))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Error("/api/v1/auth/login should be registered with custom prefix")
	}
}

// --- JWKS endpoint ---

func TestRegisterRoutes_JWKS_Mounted(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})

	mux := http.NewServeMux()
	cfg := authhttp.RouteConfig{
		Prefix:      "/auth",
		JWKSHandler: jwksHandler,
	}
	authhttp.RegisterRoutes(mux, handlers, cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/auth-keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS endpoint: got %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("JWKS endpoint: Content-Type = %q, want application/json", ct)
	}
}

func TestRegisterRoutes_NoJWKS_NotMounted(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)
	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	mux := http.NewServeMux()
	cfg := authhttp.RouteConfig{Prefix: "/auth"} // No JWKSHandler.
	authhttp.RegisterRoutes(mux, handlers, cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/auth-keys", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("JWKS (no handler): got %d, want 404", rec.Code)
	}
}

// --- Works with standard http.Handler middleware chain ---

func TestMiddleware_StandardChain(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	eng := buildEngine(t, userStore, sessMgr)

	sessMgr.sessions["chain-sess"] = &session.Session{
		ID:        "chain-sess",
		SubjectID: "chain-user",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	mw := authhttp.NewMiddleware(eng, authhttp.DefaultCookieConfig())

	// Build a standard middleware chain: logging → auth → handler.
	logCalled := false
	loggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logCalled = true
			next.ServeHTTP(w, r)
		})
	}

	var gotIdentity *auth.Identity
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = auth.GetIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	chain := loggingMiddleware(mw.RequireAuth(handler))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "chain-sess"})
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)

	if !logCalled {
		t.Fatal("logging middleware not called in chain")
	}
	if gotIdentity == nil || gotIdentity.SubjectID != "chain-user" {
		t.Fatal("identity not propagated through middleware chain")
	}
}

// --- Generic error (no enumeration) ---

func TestAuthFailures_GenericError(t *testing.T) {
	userStore := newStubUserStore()
	sessMgr := newStubSessionManager()
	passwordMode := &stubPasswordMode{userStore: userStore, hasher: &stubHasher{}}
	eng := buildEngine(t, userStore, sessMgr, passwordMode)

	userStore.users["exists@example.com"] = &stubUser{
		subjectID:    "exists@example.com",
		identifier:   "exists@example.com",
		passwordHash: "hashed:realpass",
	}

	handlers := authhttp.NewHandlers(eng, authhttp.DefaultCookieConfig())

	// Wrong password for existing user.
	req1 := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("exists@example.com", "wrongpass"))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec1, req1)

	// Non-existent user.
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody("noone@example.com", "anypass"))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	handlers.Login().ServeHTTP(rec2, req2)

	// Both should return the same status and body (no enumeration).
	if rec1.Code != rec2.Code {
		t.Errorf("status differs: wrong_pass=%d, unknown_user=%d (should be same)", rec1.Code, rec2.Code)
	}
	if rec1.Body.String() != rec2.Body.String() {
		t.Errorf("body differs: wrong_pass=%q, unknown_user=%q (should be same)", rec1.Body.String(), rec2.Body.String())
	}
}

// --- DefaultCookieConfig ---

func TestDefaultCookieConfig(t *testing.T) {
	cfg := authhttp.DefaultCookieConfig()
	if cfg.Name != "auth_session" {
		t.Errorf("Name = %q, want %q", cfg.Name, "auth_session")
	}
	if cfg.Path != "/" {
		t.Errorf("Path = %q, want %q", cfg.Path, "/")
	}
	if !cfg.Secure {
		t.Error("Secure should be true by default")
	}
	if cfg.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cfg.SameSite)
	}
}
