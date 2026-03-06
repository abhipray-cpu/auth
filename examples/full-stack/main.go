// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example full-stack demonstrates an HTTP gateway with gRPC backends,
// exercising all auth modes and cross-protocol identity propagation.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	authhttp "github.com/abhipray-cpu/auth/http"
	"github.com/abhipray-cpu/auth/propagator"
	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	// Create propagator for cross-service identity.
	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway.example.com",
		Audience: "backend.example.com",
		TTL:      30 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Wire up auth.
	a, err := authsetup.New(
		authsetup.WithUserStore(&memoryUserStore{users: make(map[string]*memoryUser)}),
		authsetup.WithIdentifierConfig(auth.IdentifierConfig{
			Field: "email", Normalize: strings.ToLower,
		}),
		authsetup.WithSessionRedis(rdb, "fullstack:"),
		authsetup.WithSkipSchemaCheck(),
		authsetup.WithIdentityPropagator(prop),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = a.Close() }()

	// --- Start gRPC backend (User Service) ---
	go func() {
		server := grpc.NewServer(
			grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
				Propagator:  prop,
				RequireAuth: true,
			})),
		)
		lis, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatalf("backend listen: %v", err)
		}
		log.Println("User Service (gRPC) listening on :50051")
		if err := server.Serve(lis); err != nil {
			log.Fatalf("backend serve: %v", err)
		}
	}()

	// --- Start gRPC backend (Order Service) ---
	go func() {
		server := grpc.NewServer(
			grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
				Propagator:  prop,
				RequireAuth: true,
			})),
		)
		lis, err := net.Listen("tcp", ":50052")
		if err != nil {
			log.Fatalf("order service listen: %v", err)
		}
		log.Println("Order Service (gRPC) listening on :50052")
		if err := server.Serve(lis); err != nil {
			log.Fatalf("order service serve: %v", err)
		}
	}()

	// --- Create gRPC client connections with propagation ---
	userConn, err := grpc.NewClient("localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
			Propagator: prop,
		})),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = userConn.Close() }()

	orderConn, err := grpc.NewClient("localhost:50052",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
			Propagator: prop,
		})),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = orderConn.Close() }()

	// --- HTTP Gateway ---
	mux := http.NewServeMux()
	handlers := authhttp.NewHandlers(a.Engine, authhttp.DefaultCookieConfig())
	authhttp.RegisterRoutes(mux, handlers, authhttp.RouteConfig{
		Prefix:      "/auth",
		JWKSHandler: a.JWKSHandler,
	})

	middleware := authhttp.NewMiddleware(a.Engine, authhttp.DefaultCookieConfig())

	mux.Handle("/api/me", middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		_, _ = fmt.Fprintf(w, `{"subject_id": "%s", "auth_method": "%s", "session_id": "%s"}`,
			identity.SubjectID, identity.AuthMethod, identity.SessionID)
	})))

	log.Println("HTTP Gateway listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
