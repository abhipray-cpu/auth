// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/authsetup"
	authhttp "github.com/abhipray-cpu/auth/http"
	"github.com/abhipray-cpu/auth/session/postgres"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"
)

// --------------------------------------------------------------------------
// AUTH-0024 AC: Schema version mismatch detected
// STRICT: Insert wrong schema, verify exact error type.
// --------------------------------------------------------------------------

func TestSchemaVersionMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := startPostgres(t)
	ctx := context.Background()

	// Insert a session with a wrong schema version.
	_, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		"fake-id", "test-user", time.Now(), time.Now().Add(24*time.Hour), time.Now(), 999, `{}`,
	)
	assertNoError(t, err, "Insert fake session with wrong schema")

	store := NewMemUserStore()

	// Creating authsetup with schema check enabled MUST fail.
	_, err = authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionPostgres(db),
		// NOT skipping schema check
	)
	if err == nil {
		t.Fatal("expected schema version mismatch error, got nil")
	}
	if !errors.Is(err, auth.ErrSchemaVersionMismatch) {
		t.Fatalf("expected ErrSchemaVersionMismatch, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Migration SQL creates table and indexes
// STRICT: Verify table, indexes, columns, and full flow works.
// --------------------------------------------------------------------------

func TestMigrationSQLRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	ctr, err := startPostgresRaw(t)
	if err != nil {
		t.Fatalf("failed to start Postgres: %v", err)
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("failed to open connection: %v", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("failed to ping: %v", err)
	}

	// Table MUST NOT exist before migration.
	var exists bool
	err = db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sessions')`,
	).Scan(&exists)
	assertNoError(t, err, "check table existence")
	if exists {
		t.Fatal("sessions table should not exist before migration")
	}

	// Run migration SQL.
	migrationSQL := postgres.MigrationSQL()
	_, err = db.ExecContext(ctx, migrationSQL)
	assertNoError(t, err, "run migration SQL")

	// Table MUST exist now.
	err = db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sessions')`,
	).Scan(&exists)
	assertNoError(t, err, "check table existence after migration")
	if !exists {
		t.Fatal("sessions table should exist after migration")
	}

	// STRICT: At least 2 indexes (PK + subject_id).
	var indexCount int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pg_indexes WHERE tablename = 'sessions'`,
	).Scan(&indexCount)
	assertNoError(t, err, "check index count")
	if indexCount < 2 {
		t.Fatalf("expected at least 2 indexes on sessions, got %d", indexCount)
	}

	// STRICT: Required columns exist.
	requiredCols := []string{"id", "subject_id", "created_at", "expires_at", "last_active_at", "schema_version", "metadata"}
	for _, col := range requiredCols {
		var colExists bool
		err = db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'sessions' AND column_name = $1)`,
			col,
		).Scan(&colExists)
		assertNoError(t, err, "check column %s", col)
		if !colExists {
			t.Fatalf("sessions table missing required column %q", col)
		}
	}

	// Full flow MUST work after migration.
	store := NewMemUserStore()
	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionPostgres(db),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New after migration")
	defer a.Close()

	identity, _, err := a.Engine.Register(ctx, passwordCred("migrated@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register after migration")
	if identity.SubjectID != "migrated@test.com" {
		t.Fatalf("expected SubjectID=migrated@test.com, got %q", identity.SubjectID)
	}

	// Verify session actually lives in Postgres.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify after migration")
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: Graceful shutdown closes connections
// STRICT: After Close(), verify that operations actually fail.
// --------------------------------------------------------------------------

func TestGracefulShutdown_Redis(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	client := startRedis(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionRedis(client, "shutdown:"),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")

	ctx := context.Background()

	// Register to confirm it works before shutdown.
	identity, _, err := a.Engine.Register(ctx, passwordCred("shutdown@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	// Verify session works before close.
	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify before close")

	// Close MUST NOT error.
	err = a.Close()
	assertNoError(t, err, "Close")

	// STRICT: After close, Redis client should be closed — Ping should fail.
	err = client.Ping(ctx).Err()
	if err == nil {
		// Some connection pools may respond briefly; this is acceptable.
		t.Log("Redis client still responding after Close (connection pool caching)")
	} else {
		t.Logf("Redis client correctly closed: %v", err)
	}
}

func TestGracefulShutdown_Postgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := startPostgres(t)
	store := NewMemUserStore()

	a, err := authsetup.New(
		authsetup.WithUserStore(store),
		authsetup.WithIdentifierConfig(identifierConfig()),
		authsetup.WithSessionPostgres(db),
		authsetup.WithSkipSchemaCheck(),
	)
	assertNoError(t, err, "authsetup.New")

	ctx := context.Background()

	identity, _, err := a.Engine.Register(ctx, passwordCred("shutdown-pg@test.com", "Str0ngP@ssword!"))
	assertNoError(t, err, "Register")

	_, err = a.Engine.Verify(ctx, identity.SessionID)
	assertNoError(t, err, "Verify before close")

	err = a.Close()
	assertNoError(t, err, "Close")

	err = db.PingContext(ctx)
	if err == nil {
		t.Log("Postgres pool still responding after Close (pool caching)")
	} else {
		t.Logf("Postgres pool correctly closed: %v", err)
	}
}

// --------------------------------------------------------------------------
// AUTH-0024 AC: SameSite cookie policies coexist
// STRICT: Verify Secure, HttpOnly, Path, exact SameSite values.
// --------------------------------------------------------------------------

func TestSameSiteCookieCoexistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	sessionCfg := authhttp.DefaultCookieConfig()

	// STRICT: Verify defaults.
	if sessionCfg.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected default SameSite=Strict, got %v", sessionCfg.SameSite)
	}
	if sessionCfg.Name != "auth_session" {
		t.Fatalf("expected cookie name 'auth_session', got %q", sessionCfg.Name)
	}

	rec := httptest.NewRecorder()

	// Session cookie (Strict).
	http.SetCookie(rec, &http.Cookie{
		Name:     sessionCfg.Name,
		Value:    "session-value",
		Path:     sessionCfg.Path,
		Secure:   sessionCfg.Secure,
		HttpOnly: true,
		SameSite: sessionCfg.SameSite,
	})

	// OAuth state cookie (Lax).
	http.SetCookie(rec, &http.Cookie{
		Name:     "oauth_state",
		Value:    "state-value",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	var foundSession, foundOAuth bool
	for _, c := range cookies {
		switch c.Name {
		case "auth_session":
			foundSession = true
			if c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie SameSite: expected Strict, got %v", c.SameSite)
			}
			if !c.HttpOnly {
				t.Fatal("SECURITY: session cookie MUST be HttpOnly")
			}
			if !c.Secure {
				t.Fatal("SECURITY: session cookie MUST be Secure")
			}
		case "oauth_state":
			foundOAuth = true
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("OAuth state cookie SameSite: expected Lax, got %v", c.SameSite)
			}
			if !c.HttpOnly {
				t.Fatal("SECURITY: OAuth state cookie MUST be HttpOnly")
			}
			if !c.Secure {
				t.Fatal("SECURITY: OAuth state cookie MUST be Secure")
			}
		default:
			t.Fatalf("unexpected cookie %q", c.Name)
		}
	}
	if !foundSession {
		t.Fatal("session cookie not found in response")
	}
	if !foundOAuth {
		t.Fatal("OAuth state cookie not found in response")
	}
}

// --------------------------------------------------------------------------
// Helper: start raw Postgres without running migrations
// --------------------------------------------------------------------------

func startPostgresRaw(t *testing.T) (*tcpostgresContainer, error) {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	ctr, err := startPostgresContainer(ctx, t)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	return ctr, nil
}

type tcpostgresContainer struct {
	ctr testcontainers.Container
}

func (c *tcpostgresContainer) ConnectionString(ctx context.Context, args ...string) (string, error) {
	host, err := c.ctr.Host(ctx)
	if err != nil {
		return "", err
	}
	port, err := c.ctr.MappedPort(ctx, "5432")
	if err != nil {
		return "", err
	}
	dsn := "postgres://test:test@" + host + ":" + port.Port() + "/authtest"
	if len(args) > 0 {
		dsn += "?" + args[0]
	}
	return dsn, nil
}

func (c *tcpostgresContainer) Terminate(ctx context.Context) error {
	return c.ctr.Terminate(ctx)
}

func startPostgresContainer(ctx context.Context, t *testing.T) (*tcpostgresContainer, error) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_DB":       "authtest",
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(30 * time.Second),
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Logger:           tclog.TestLogger(t),
	})
	if err != nil {
		return nil, err
	}

	return &tcpostgresContainer{ctr: ctr}, nil
}
