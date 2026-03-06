// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example http-api-key demonstrates API key authentication.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/authsetup"
	authhttp "github.com/abhipray-cpu/auth/http"
	goredis "github.com/redis/go-redis/v9"
)

// memoryAPIKeyStore implements apikey.APIKeyStore in-memory.
type memoryAPIKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*apikey.APIKey // keyed by key hash
}

func (s *memoryAPIKeyStore) FindByKey(_ context.Context, keyHash string) (*apikey.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if k, ok := s.keys[keyHash]; ok {
		return k, nil
	}
	return nil, nil
}

func (s *memoryAPIKeyStore) Create(_ context.Context, key *apikey.APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KeyHash] = key
	return nil
}

func (s *memoryAPIKeyStore) Revoke(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.ID == keyID {
			k.Revoked = true
			return nil
		}
	}
	return nil
}

func (s *memoryAPIKeyStore) ListBySubject(_ context.Context, subjectID string) ([]*apikey.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*apikey.APIKey
	for _, k := range s.keys {
		if k.SubjectID == subjectID {
			result = append(result, k)
		}
	}
	return result, nil
}

func (s *memoryAPIKeyStore) UpdateLastUsed(_ context.Context, keyID string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if k.ID == keyID {
			k.LastUsedAt = t
			return nil
		}
	}
	return nil
}

// Minimal UserStore
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
	rdb := goredis.NewClient(&goredis.Options{Addr: "localhost:6379"})
	apiKeyStore := &memoryAPIKeyStore{keys: make(map[string]*apikey.APIKey)}

	a, err := authsetup.New(
		authsetup.WithUserStore(&memoryUserStore{users: make(map[string]*memoryUser)}),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field: "email", Normalize: strings.ToLower,
		}),
		authsetup.WithSessionRedis(rdb, "apikey-example:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithAPIKeyStore(apiKeyStore),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	// Create a test API key.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		log.Fatal(err)
	}
	rawKeyHex := hex.EncodeToString(rawKey)
	hash := sha256.Sum256([]byte(rawKeyHex))

	_ = apiKeyStore.Create(context.Background(), &apikey.APIKey{
		ID:        "test-key-1",
		SubjectID: "user-123",
		KeyHash:   hex.EncodeToString(hash[:]),
		Name:      "test-key",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	fmt.Printf("\n🔑 Test API key: %s\n\n", rawKeyHex)

	mux := http.NewServeMux()
	handlers := authhttp.NewHandlers(a.Engine, authhttp.DefaultCookieConfig())
	authhttp.RegisterRoutes(mux, handlers, authhttp.DefaultRouteConfig())

	middleware := authhttp.NewMiddleware(a.Engine, authhttp.DefaultCookieConfig())
	mux.Handle("/api/me", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		_, _ = fmt.Fprintf(w, `{"subject_id": "%s", "auth_method": "%s"}`, identity.SubjectID, identity.AuthMethod)
	})))

	log.Println("http-api-key example listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
