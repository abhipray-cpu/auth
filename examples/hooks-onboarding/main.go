// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example hooks-onboarding demonstrates lifecycle hooks for user onboarding.
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

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	"github.com/abhipray-cpu/auth/hooks"
	authhttp "github.com/abhipray-cpu/auth/http"
	goredis "github.com/redis/go-redis/v9"
)

// --- Minimal UserStore ---
type memoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*memoryUser
}
type memoryUser struct{ id, identifier, passwordHash string }

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
		authsetup.WithSessionRedis(rdb, "hooks-example:"),
		authsetup.WithSkipSchemaCheck(),

		// Hook: AfterRegister — welcome email + default profile
		authsetup.WithHook(auth.EventRegistration, func(_ context.Context, payload hooks.HookPayload) error {
			p := payload.(*hooks.RegisterPayload)
			fmt.Printf("📧 [AfterRegister] Sending welcome email to %s (ID: %s)\n", p.Identifier, p.SubjectID)
			fmt.Printf("👤 [AfterRegister] Creating default profile for %s\n", p.SubjectID)
			return nil
		}),

		// Hook: AfterLogin — audit log
		authsetup.WithHook(auth.EventLogin, func(_ context.Context, payload hooks.HookPayload) error {
			p := payload.(*hooks.LoginPayload)
			fmt.Printf("🔐 [AfterLogin] User %s logged in via %s (session: %s)\n",
				p.SubjectID, p.AuthMethod, p.SessionID)
			return nil
		}),

		// Hook: AfterLoginFailed — track failed attempts
		authsetup.WithHook(auth.EventLoginFailed, func(_ context.Context, payload hooks.HookPayload) error {
			p := payload.(*hooks.LoginPayload)
			fmt.Printf("⚠️  [AfterLoginFailed] Failed login for %s: %v\n", p.Identifier, p.Error)
			return nil
		}),

		// Hook: AfterLogout — cleanup
		authsetup.WithHook(auth.EventLogout, func(_ context.Context, payload hooks.HookPayload) error {
			p := payload.(*hooks.LogoutPayload)
			fmt.Printf("👋 [AfterLogout] User %s logged out (session: %s)\n", p.SubjectID, p.SessionID)
			return nil
		}),
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
		_, _ = fmt.Fprintf(w, `{"subject_id": "%s"}`, identity.SubjectID)
	})))

	log.Println("hooks-onboarding example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
