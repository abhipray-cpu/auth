// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example custom-session-store demonstrates implementing a custom session.SessionStore.
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
	"github.com/abhipray-cpu/auth/session"
)

// memorySessionStore implements session.SessionStore with a simple map.
type memorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session.Session
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{sessions: make(map[string]*session.Session)}
}

func (s *memorySessionStore) Create(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *memorySessionStore) Get(_ context.Context, sessionID string) (*session.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, auth.ErrSessionNotFound
	}
	return sess, nil
}

func (s *memorySessionStore) Update(_ context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *memorySessionStore) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *memorySessionStore) DeleteBySubject(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *memorySessionStore) CountBySubject(_ context.Context, subjectID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

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
	a, err := authsetup.New(
		authsetup.WithUserStore(&memoryUserStore{users: make(map[string]*memoryUser)}),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field: "email", Normalize: strings.ToLower,
		}),
		authsetup.WithCustomSessionStore(newMemorySessionStore()),
		authsetup.WithSkipSchemaCheck(),
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

	log.Println("custom-session-store example listening on :8080 (no Redis/Postgres needed!)")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
