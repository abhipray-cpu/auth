// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example http-oauth demonstrates OAuth2/OIDC authentication with Google.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	authhttp "github.com/abhipray-cpu/auth/http"
	"github.com/abhipray-cpu/auth/mode/oauth"
	goredis "github.com/redis/go-redis/v9"
)

// memoryStateStore implements oauth.StateStore in-memory.
type memoryStateStore struct {
	mu     sync.Mutex
	states map[string]*oauth.OAuthState
}

func (s *memoryStateStore) Save(_ context.Context, state *oauth.OAuthState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *memoryStateStore) Load(_ context.Context, stateToken string) (*oauth.OAuthState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[stateToken]
	if !ok {
		return nil, fmt.Errorf("state not found")
	}
	delete(s.states, stateToken)
	return st, nil
}

// memoryUserStore — same as http-password example.
type memoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*memoryUser
}

type memoryUser struct {
	id, identifier, passwordHash string
	failedAttempts               int
	locked                       bool
}

func (u *memoryUser) GetSubjectID() string        { return u.id }
func (u *memoryUser) GetIdentifier() string       { return u.identifier }
func (u *memoryUser) GetPasswordHash() string     { return u.passwordHash }
func (u *memoryUser) GetFailedAttempts() int      { return u.failedAttempts }
func (u *memoryUser) IsLocked() bool              { return u.locked }
func (u *memoryUser) IsMFAEnabled() bool          { return false }
func (u *memoryUser) GetMetadata() map[string]any { return nil }

func (s *memoryUserStore) FindByIdentifier(_ context.Context, id string) (auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return nil, auth.ErrUserNotFound
}

func (s *memoryUserStore) Create(_ context.Context, user auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[user.GetIdentifier()]; ok {
		return auth.ErrUserAlreadyExists
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	s.users[user.GetIdentifier()] = &memoryUser{
		id: hex.EncodeToString(id), identifier: user.GetIdentifier(), passwordHash: user.GetPasswordHash(),
	}
	return nil
}

func (s *memoryUserStore) UpdatePassword(_ context.Context, subjectID, hash string) error { return nil }
func (s *memoryUserStore) IncrementFailedAttempts(_ context.Context, _ string) error      { return nil }
func (s *memoryUserStore) ResetFailedAttempts(_ context.Context, _ string) error          { return nil }
func (s *memoryUserStore) SetLocked(_ context.Context, _ string, _ bool) error            { return nil }

func main() {
	rdb := goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})

	a, err := authsetup.New(
		authsetup.WithUserStore(&memoryUserStore{users: make(map[string]*memoryUser)}),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field: "email", Normalize: strings.ToLower,
		}),
		authsetup.WithSessionRedis(rdb, "oauth-example:"),
		authsetup.WithSkipSchemaCheck(),

		// OAuth provider — Google
		authsetup.WithOAuthProvider(oauth.ProviderConfig{
			Name:         "google",
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			IssuerURL:    "https://accounts.google.com",
			Scopes:       []string{"openid", "email", "profile"},
			RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
		}),
		authsetup.WithOAuthStateStore(&memoryStateStore{states: make(map[string]*oauth.OAuthState)}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	mux := http.NewServeMux()
	handlers := authhttp.NewHandlers(a.Engine, authhttp.DefaultCookieConfig())
	authhttp.RegisterRoutes(mux, handlers, authhttp.DefaultRouteConfig())

	middleware := authhttp.NewMiddleware(a.Engine, authhttp.DefaultCookieConfig())
	mux.Handle("/api/me", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		_, _ = fmt.Fprintf(w, `{"subject_id": "%s", "auth_method": "%s"}`, identity.SubjectID, identity.AuthMethod)
	})))

	log.Println("http-oauth example listening on :8080")
	log.Println("Visit http://localhost:8080/auth/oauth/google to start OAuth flow")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
