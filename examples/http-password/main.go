// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example http-password demonstrates minimal HTTP password authentication.
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
	authhttp "github.com/abhipray-cpu/auth/http"
	goredis "github.com/redis/go-redis/v9"
)

// --- In-memory UserStore (replace with your database) ---

type memoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*memoryUser // keyed by identifier
}

type memoryUser struct {
	id             string
	identifier     string
	passwordHash   string
	failedAttempts int
	locked         bool
}

func (u *memoryUser) GetSubjectID() string        { return u.id }
func (u *memoryUser) GetIdentifier() string       { return u.identifier }
func (u *memoryUser) GetPasswordHash() string     { return u.passwordHash }
func (u *memoryUser) GetFailedAttempts() int      { return u.failedAttempts }
func (u *memoryUser) IsLocked() bool              { return u.locked }
func (u *memoryUser) IsMFAEnabled() bool          { return false }
func (u *memoryUser) GetMetadata() map[string]any { return nil }

func newMemoryUserStore() *memoryUserStore {
	return &memoryUserStore{users: make(map[string]*memoryUser)}
}

func (s *memoryUserStore) FindByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[identifier]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

func (s *memoryUserStore) Create(_ context.Context, user auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.GetIdentifier()]; exists {
		return auth.ErrUserAlreadyExists
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("generate id: %w", err)
	}
	s.users[user.GetIdentifier()] = &memoryUser{
		id:           hex.EncodeToString(id),
		identifier:   user.GetIdentifier(),
		passwordHash: user.GetPasswordHash(),
	}
	return nil
}

func (s *memoryUserStore) UpdatePassword(_ context.Context, subjectID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.id == subjectID {
			u.passwordHash = hash
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *memoryUserStore) IncrementFailedAttempts(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.id == subjectID {
			u.failedAttempts++
			return nil
		}
	}
	return nil
}

func (s *memoryUserStore) ResetFailedAttempts(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.id == subjectID {
			u.failedAttempts = 0
			return nil
		}
	}
	return nil
}

func (s *memoryUserStore) SetLocked(_ context.Context, subjectID string, locked bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.id == subjectID {
			u.locked = locked
			return nil
		}
	}
	return nil
}

func main() {
	rdb := goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})

	a, err := authsetup.New(
		authsetup.WithUserStore(newMemoryUserStore()),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field:     "email",
			Normalize: strings.ToLower,
		}),
		authsetup.WithSessionRedis(rdb, "example:"),
		authsetup.WithSkipSchemaCheck(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	mux := http.NewServeMux()

	// Register auth routes.
	handlers := authhttp.NewHandlers(a.Engine, authhttp.DefaultCookieConfig())
	authhttp.RegisterRoutes(mux, handlers, authhttp.DefaultRouteConfig())

	// Protected route.
	middleware := authhttp.NewMiddleware(a.Engine, authhttp.DefaultCookieConfig())
	mux.Handle("/api/me", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		_, _ = fmt.Fprintf(w, `{"subject_id": "%s", "auth_method": "%s"}`, identity.SubjectID, identity.AuthMethod)
	})))

	log.Println("http-password example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
