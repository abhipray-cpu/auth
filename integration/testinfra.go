// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package integration provides integration test infrastructure using
// testcontainers for real Redis and Postgres instances.
//
// These tests exercise the auth library end-to-end against real storage
// backends, validating behavior that unit tests with mocks cannot cover.
//
// Requirements:
//   - Docker daemon running (Docker Desktop, colima, podman, etc.)
//   - Sufficient resources for Redis + Postgres containers
//
// Run with: go test -v -count=1 ./integration/...
// Skip with: go test -short ./integration/...
package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session/postgres"
	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// skipIfNoDocker skips the test if Docker is not available.
// It also ensures DOCKER_HOST is set for testcontainers when using
// non-default Docker socket paths (e.g., Colima, Rancher Desktop).
func skipIfNoDocker(t *testing.T) {
	t.Helper()
	// Check if Docker daemon is actually running (not just CLI installed).
	cmd := exec.Command("docker", "info")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("Docker daemon not available — skipping integration test: %v", err)
	}
	// Some setups have docker CLI but daemon is down.
	if strings.Contains(string(out), "Cannot connect") ||
		strings.Contains(string(out), "error during connect") {
		t.Skip("Docker daemon not reachable — skipping integration test")
	}

	// Ensure DOCKER_HOST is set for testcontainers.
	// Testcontainers panics if it can't find a Docker socket. When using
	// Colima or other non-default runtimes, the default /var/run/docker.sock
	// doesn't exist. Detect the host from `docker context inspect`.
	if os.Getenv("DOCKER_HOST") == "" {
		host := detectDockerHost()
		if host != "" {
			t.Setenv("DOCKER_HOST", host)
		}
	}
}

// detectDockerHost discovers the Docker socket from the active docker context.
// Returns an empty string if detection fails (testcontainers will use its defaults).
func detectDockerHost() string {
	cmd := exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	host := strings.TrimSpace(string(out))
	if host == "" || host == "<no value>" {
		return ""
	}
	return host
}

// ---------- Container helpers ----------

// startRedis starts a Redis container and returns a connected go-redis client.
// The container is terminated when the test completes.
func startRedis(t *testing.T) *goredis.Client {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	ctr, err := tcredis.Run(ctx,
		"redis:7-alpine",
		testcontainers.WithLogger(tclog.TestLogger(t)),
	)
	if err != nil {
		t.Fatalf("failed to start Redis container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	connStr, err := ctr.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("failed to get Redis connection string: %v", err)
	}

	opts, err := goredis.ParseURL(connStr)
	if err != nil {
		t.Fatalf("failed to parse Redis URL %q: %v", connStr, err)
	}

	client := goredis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("failed to ping Redis: %v", err)
	}

	return client
}

// startPostgres starts a Postgres container, runs session schema migration,
// and returns a connected *sql.DB. The container is terminated when the
// test completes.
func startPostgres(t *testing.T) *sql.DB {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("authtest"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
		testcontainers.WithLogger(tclog.TestLogger(t)),
	)
	if err != nil {
		t.Fatalf("failed to start Postgres container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get Postgres connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open Postgres connection: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("failed to ping Postgres: %v", err)
	}

	// Run session schema migration.
	if _, err := db.ExecContext(ctx, postgres.MigrationSQL()); err != nil {
		t.Fatalf("failed to run migration: %v", err)
	}

	return db
}

// ---------- In-memory UserStore ----------

// memUser is a simple in-memory User implementation for integration tests.
type memUser struct {
	subjectID      string
	identifier     string
	passwordHash   string
	failedAttempts int
	locked         bool
	metadata       map[string]any
}

func (u *memUser) GetSubjectID() string        { return u.subjectID }
func (u *memUser) GetIdentifier() string       { return u.identifier }
func (u *memUser) GetPasswordHash() string     { return u.passwordHash }
func (u *memUser) GetFailedAttempts() int      { return u.failedAttempts }
func (u *memUser) IsLocked() bool              { return u.locked }
func (u *memUser) IsMFAEnabled() bool          { return false }
func (u *memUser) GetMetadata() map[string]any { return u.metadata }

// MemUserStore is a thread-safe in-memory UserStore for integration tests.
type MemUserStore struct {
	mu    sync.RWMutex
	users map[string]*memUser // keyed by identifier
}

// NewMemUserStore creates a new in-memory UserStore.
func NewMemUserStore() *MemUserStore {
	return &MemUserStore{users: make(map[string]*memUser)}
}

// AddUser pre-populates a user (for login tests).
func (s *MemUserStore) AddUser(identifier, passwordHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[identifier] = &memUser{
		subjectID:    identifier,
		identifier:   identifier,
		passwordHash: passwordHash,
	}
}

// GetUser returns the raw memUser for assertions.
func (s *MemUserStore) GetUser(identifier string) *memUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[identifier]
}

// UserCount returns the number of users in the store.
func (s *MemUserStore) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

func (s *MemUserStore) FindByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[identifier]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	// Return a copy so mutations via IncrementFailedAttempts etc. don't race.
	cp := *u
	return &cp, nil
}

func (s *MemUserStore) Create(_ context.Context, user auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := user.GetIdentifier()
	if _, exists := s.users[id]; exists {
		return auth.ErrUserAlreadyExists
	}
	s.users[id] = &memUser{
		subjectID:    user.GetSubjectID(),
		identifier:   user.GetIdentifier(),
		passwordHash: user.GetPasswordHash(),
	}
	return nil
}

func (s *MemUserStore) UpdatePassword(_ context.Context, subjectID string, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.passwordHash = hash
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *MemUserStore) IncrementFailedAttempts(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.failedAttempts++
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *MemUserStore) ResetFailedAttempts(_ context.Context, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.failedAttempts = 0
			return nil
		}
	}
	return auth.ErrUserNotFound
}

func (s *MemUserStore) SetLocked(_ context.Context, subjectID string, locked bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.subjectID == subjectID {
			u.locked = locked
			return nil
		}
	}
	return auth.ErrUserNotFound
}

// Verify interface compliance.
var _ auth.UserStore = (*MemUserStore)(nil)

// ---------- Helpers ----------

// identifierConfig returns a standard email-based IdentifierConfig for tests.
func identifierConfig() auth.IdentifierConfig {
	return auth.IdentifierConfig{
		Field:         "email",
		CaseSensitive: false,
		Normalize:     func(s string) string { return strings.ToLower(strings.TrimSpace(s)) },
	}
}

// passwordCred builds a Credential for password login.
func passwordCred(identifier, password string) auth.Credential {
	return auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: identifier,
		Secret:     password,
	}
}

// passwordCredWithSession builds a Credential for password login with existing session (fixation test).
func passwordCredWithSession(identifier, password, existingSessionID string) auth.Credential {
	return auth.Credential{
		Type:       auth.CredentialTypePassword,
		Identifier: identifier,
		Secret:     password,
		Metadata: map[string]any{
			"existing_session_id": existingSessionID,
		},
	}
}

// assertNoError is a test helper that fails if err is non-nil.
func assertNoError(t *testing.T, err error, msg string, args ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf(fmt.Sprintf(msg, args...)+": %v", err)
	}
}

// assertError is a test helper that fails if err is nil.
func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error: %s", msg)
	}
}
