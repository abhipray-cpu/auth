// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example http-magic-link demonstrates passwordless magic link authentication.
// The Notifier implementation prints the magic link to the console.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	authhttp "github.com/abhipray-cpu/auth/http"
	"github.com/abhipray-cpu/auth/session"
	goredis "github.com/redis/go-redis/v9"
)

// consoleNotifier prints magic links to the console.
type consoleNotifier struct{}

func (n *consoleNotifier) Notify(_ context.Context, event auth.AuthEvent, payload map[string]any) error {
	if event == auth.EventMagicLinkSent {
		fmt.Printf("\n🔗 Magic link for %s:\n   %s\n\n", payload["identifier"], payload["link"])
	}
	return nil
}

// memoryMagicLinkStore implements session.MagicLinkStore in-memory.
type memoryMagicLinkStore struct {
	mu     sync.Mutex
	tokens map[string]*session.MagicLinkToken
}

func (s *memoryMagicLinkStore) Store(_ context.Context, token *session.MagicLinkToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
	return nil
}

func (s *memoryMagicLinkStore) Consume(_ context.Context, token string) (*session.MagicLinkToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[token]
	if !ok {
		return nil, auth.ErrTokenNotFound
	}
	delete(s.tokens, token)
	if time.Now().After(t.ExpiresAt) {
		return nil, auth.ErrTokenNotFound
	}
	return t, nil
}

// memoryUserStore — minimal implementation.
type memoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*memoryUser
}
type memoryUser struct {
	id, identifier, passwordHash string
}

func (u *memoryUser) GetSubjectID() string        { return u.id }
func (u *memoryUser) GetIdentifier() string       { return u.identifier }
func (u *memoryUser) GetPasswordHash() string     { return u.passwordHash }
func (u *memoryUser) GetFailedAttempts() int      { return 0 }
func (u *memoryUser) IsLocked() bool              { return false }
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
func (s *memoryUserStore) UpdatePassword(_ context.Context, _, _ string) error       { return nil }
func (s *memoryUserStore) IncrementFailedAttempts(_ context.Context, _ string) error { return nil }
func (s *memoryUserStore) ResetFailedAttempts(_ context.Context, _ string) error     { return nil }
func (s *memoryUserStore) SetLocked(_ context.Context, _ string, _ bool) error       { return nil }

func main() {
	rdb := goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})

	a, err := authsetup.New(
		authsetup.WithUserStore(&memoryUserStore{users: make(map[string]*memoryUser)}),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field: "email", Normalize: strings.ToLower,
		}),
		authsetup.WithSessionRedis(rdb, "magic-example:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithNotifier(&consoleNotifier{}),
		authsetup.WithMagicLinkStore(&memoryMagicLinkStore{tokens: make(map[string]*session.MagicLinkToken)}),
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

	log.Println("http-magic-link example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
