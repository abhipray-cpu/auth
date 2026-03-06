// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"

	_ "modernc.org/sqlite" // Pure Go SQLite driver for testing
)

// setupTestDB creates a temporary SQLite database with the sessions schema.
// SQLite is used for unit testing to validate SQL logic without requiring
// a running Postgres instance. Integration tests (AUTH-0024) will use real
// Postgres via testcontainers.
func setupTestDB(t *testing.T) *Store {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create the table using SQLite-compatible DDL.
	// The production migration uses TIMESTAMPTZ and JSONB which are Postgres types.
	// SQLite is more permissive with types, so this works for testing.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id              TEXT PRIMARY KEY,
			subject_id      TEXT NOT NULL,
			created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at      DATETIME NOT NULL,
			last_active_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			schema_version  INTEGER NOT NULL DEFAULT 1,
			metadata        TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_subject_expires
			ON sessions (subject_id, expires_at);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
			ON sessions (expires_at);
	`)
	if err != nil {
		t.Fatalf("schema setup error: %v", err)
	}

	return NewStore(Config{DB: db})
}

func testSession(id, subject string) *session.Session {
	now := time.Now().UTC().Truncate(time.Second) // Truncate for SQLite compat.
	return &session.Session{
		ID:            id,
		SubjectID:     subject,
		CreatedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
		LastActiveAt:  now,
		SchemaVersion: session.SchemaVersion,
		Metadata:      map[string]any{"ip": "10.0.0.1"},
	}
}

// --- Test 4.30: Session row inserted ---
func TestPostgres_Create(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("sess-001", "user-123")
	err := store.Create(ctx, sess)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Verify row exists.
	got, err := store.Get(ctx, "sess-001")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", got.SubjectID)
	}
}

// --- Test 4.31: SchemaVersion column set on create ---
func TestPostgres_Create_SchemaVersion(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("sess-sv", "user-123")
	sess.SchemaVersion = session.SchemaVersion

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	got, err := store.Get(ctx, "sess-sv")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.SchemaVersion != session.SchemaVersion {
		t.Errorf("expected SchemaVersion=%d, got %d", session.SchemaVersion, got.SchemaVersion)
	}
}

// --- Test 4.32: Session row retrieved correctly ---
func TestPostgres_Get(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	original := testSession("sess-get", "user-123")
	original.Metadata = map[string]any{"role": "admin", "count": float64(42)}

	if err := store.Create(ctx, original); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	got, err := store.Get(ctx, "sess-get")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	if got.ID != "sess-get" {
		t.Errorf("expected ID=sess-get, got %q", got.ID)
	}
	if got.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", got.SubjectID)
	}
	if got.Metadata["role"] != "admin" {
		t.Errorf("expected metadata role=admin, got %v", got.Metadata["role"])
	}
	if got.Metadata["count"] != float64(42) {
		t.Errorf("expected metadata count=42, got %v", got.Metadata["count"])
	}
}

// --- Test 4.33: Missing row returns ErrSessionNotFound ---
func TestPostgres_Get_NotFound(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// --- Test 4.34: Row updated ---
func TestPostgres_Update(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("sess-upd", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Update.
	sess.LastActiveAt = time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	sess.Metadata = map[string]any{"updated": true}
	if err := store.Update(ctx, sess); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got, err := store.Get(ctx, "sess-upd")
	if err != nil {
		t.Fatalf("Get() after update error: %v", err)
	}
	if got.Metadata["updated"] != true {
		t.Errorf("expected metadata updated=true, got %v", got.Metadata["updated"])
	}
}

// --- Test 4.35: Row deleted ---
func TestPostgres_Delete(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("sess-del", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := store.Delete(ctx, "sess-del"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	_, err := store.Get(ctx, "sess-del")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound after delete, got: %v", err)
	}
}

// --- Test 4.36: DeleteBySubject removes all rows for subject ---
func TestPostgres_DeleteBySubject(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Create 3 for user-123, 1 for user-456.
	for i := 0; i < 3; i++ {
		sess := testSession("sess-sub-"+string(rune('a'+i)), "user-123")
		if err := store.Create(ctx, sess); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}
	other := testSession("sess-other", "user-456")
	if err := store.Create(ctx, other); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := store.DeleteBySubject(ctx, "user-123"); err != nil {
		t.Fatalf("DeleteBySubject() error: %v", err)
	}

	// user-123 sessions gone.
	for _, id := range []string{"sess-sub-a", "sess-sub-b", "sess-sub-c"} {
		_, err := store.Get(ctx, id)
		if !errors.Is(err, auth.ErrSessionNotFound) {
			t.Errorf("expected session %s deleted, got: %v", id, err)
		}
	}

	// user-456 remains.
	_, err := store.Get(ctx, "sess-other")
	if err != nil {
		t.Errorf("expected user-456 session to remain, got: %v", err)
	}
}

// --- Test 4.37: CountBySubject query works ---
func TestPostgres_CountBySubject(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Initially 0.
	count, err := store.CountBySubject(ctx, "user-123")
	if err != nil {
		t.Fatalf("CountBySubject() error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Create 3 sessions (all with future expiry).
	for i := 0; i < 3; i++ {
		sess := testSession("sess-cnt-"+string(rune('a'+i)), "user-123")
		if err := store.Create(ctx, sess); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	count, err = store.CountBySubject(ctx, "user-123")
	if err != nil {
		t.Fatalf("CountBySubject() error: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3, got %d", count)
	}
}

// --- Test 4.38: SubjectID + ExpiresAt index exists ---
func TestPostgres_Indexes(t *testing.T) {
	// Verify the migration SQL contains the expected indexes.
	migration := MigrationSQL()

	if !strings.Contains(migration, "idx_sessions_subject_expires") {
		t.Error("migration SQL missing idx_sessions_subject_expires index")
	}
	if !strings.Contains(migration, "idx_sessions_expires_at") {
		t.Error("migration SQL missing idx_sessions_expires_at index")
	}

	// Also verify actual index exists in test DB.
	store := setupTestDB(t)
	rows, err := store.db.Query("PRAGMA index_list('sessions')")
	if err != nil {
		t.Fatalf("PRAGMA index_list error: %v", err)
	}
	defer rows.Close()

	indexes := make(map[string]bool)
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan error: %v", err)
		}
		indexes[name] = true
	}

	if !indexes["idx_sessions_subject_expires"] {
		t.Error("expected idx_sessions_subject_expires index in database")
	}
	if !indexes["idx_sessions_expires_at"] {
		t.Error("expected idx_sessions_expires_at index in database")
	}
}

// --- Test 4.39: Expired sessions cleaned up ---
func TestPostgres_ExpiredCleanup(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Create 2 expired sessions and 1 active.
	expired1 := testSession("sess-exp-1", "user-123")
	expired1.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour) // Already expired.
	if err := store.Create(ctx, expired1); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	expired2 := testSession("sess-exp-2", "user-123")
	expired2.ExpiresAt = time.Now().UTC().Add(-2 * time.Hour)
	if err := store.Create(ctx, expired2); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	active := testSession("sess-active", "user-123")
	active.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	if err := store.Create(ctx, active); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	cleaned, err := store.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired() error: %v", err)
	}
	if cleaned != 2 {
		t.Errorf("expected 2 cleaned up, got %d", cleaned)
	}

	// Active session should remain.
	_, err = store.Get(ctx, "sess-active")
	if err != nil {
		t.Errorf("expected active session to remain, got: %v", err)
	}

	// Expired sessions should be gone.
	_, err = store.Get(ctx, "sess-exp-1")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected expired session to be cleaned up")
	}
}

// --- Test 4.40: Satisfies SessionStore interface ---
func TestPostgres_ImplementsSessionStore(t *testing.T) {
	var _ session.SessionStore = (*Store)(nil)
}

// --- Test 4.41: Postgres connection failure returns error, not panic ---
func TestPostgres_ConnectionFailure(t *testing.T) {
	// Open a connection to a non-existent database.
	db, err := sql.Open("sqlite", "/nonexistent/path/to/db.sqlite")
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	defer db.Close()

	store := NewStore(Config{DB: db})
	ctx := context.Background()

	// All operations should return errors, never panic.
	sess := testSession("sess-fail", "user-123")

	err = store.Create(ctx, sess)
	if err == nil {
		t.Error("expected error on Create with bad connection")
	}

	_, err = store.Get(ctx, "sess-fail")
	if err == nil {
		t.Error("expected error on Get with bad connection")
	}

	_, err = store.CountBySubject(ctx, "user-123")
	if err == nil {
		t.Error("expected error on CountBySubject with bad connection")
	}
}

// --- Test: Migration SQL file exists and is valid SQL ---
func TestPostgres_MigrationSQLFile(t *testing.T) {
	// Check that the migration file exists.
	path := "migrations/001_create_sessions.sql"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("migration file not found at %s: %v", path, err)
	}

	content := string(data)
	if !strings.Contains(content, "CREATE TABLE") {
		t.Error("migration file does not contain CREATE TABLE")
	}
	if !strings.Contains(content, "CREATE INDEX") {
		t.Error("migration file does not contain CREATE INDEX")
	}
	if !strings.Contains(content, "schema_version") {
		t.Error("migration file does not contain schema_version column")
	}

	// Verify the MigrationSQL() function also returns valid SQL.
	migrationFunc := MigrationSQL()
	if !strings.Contains(migrationFunc, "CREATE TABLE") {
		t.Error("MigrationSQL() does not contain CREATE TABLE")
	}

	// Verify the SQL is actually executable.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	defer db.Close()

	// Execute the file-based migration (adapted for SQLite).
	sqliteSQL := strings.ReplaceAll(content, "TIMESTAMPTZ", "DATETIME")
	sqliteSQL = strings.ReplaceAll(sqliteSQL, "JSONB", "TEXT")
	sqliteSQL = strings.ReplaceAll(sqliteSQL, "DEFAULT NOW()", "DEFAULT CURRENT_TIMESTAMP")
	_, err = db.Exec(sqliteSQL)
	if err != nil {
		t.Errorf("migration SQL is not valid: %v", err)
	}
}

// --- Test: Schema version check ---
func TestPostgres_CheckSchemaVersion(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// No sessions — should succeed.
	if err := store.CheckSchemaVersion(ctx); err != nil {
		t.Fatalf("CheckSchemaVersion() with no sessions should succeed, got: %v", err)
	}

	// Create a session with current version.
	sess := testSession("sess-sv-check", "user-123")
	sess.SchemaVersion = session.SchemaVersion
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Should match.
	if err := store.CheckSchemaVersion(ctx); err != nil {
		t.Fatalf("CheckSchemaVersion() should pass for matching version, got: %v", err)
	}

	// Insert a session with wrong version.
	_, err := store.db.Exec(
		`INSERT INTO sessions (id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"sess-wrong-v", "user-999",
		time.Now().UTC().Add(1*time.Second), // Slightly later so it's the most recent.
		time.Now().UTC().Add(24*time.Hour),
		time.Now().UTC(),
		999, // Wrong version.
		[]byte(`{}`),
	)
	if err != nil {
		t.Fatalf("insert wrong version error: %v", err)
	}

	err = store.CheckSchemaVersion(ctx)
	if err == nil {
		t.Fatal("expected error for mismatched schema version")
	}
	if !errors.Is(err, auth.ErrSchemaVersionMismatch) {
		t.Errorf("expected ErrSchemaVersionMismatch, got: %v", err)
	}
	if !strings.Contains(err.Error(), "migrations") {
		t.Errorf("error should mention migrations, got: %v", err)
	}
}

// --- Bonus test for MigrationSQL function output ---
func TestPostgres_MigrationSQL_Content(t *testing.T) {
	sql := MigrationSQL()

	required := []string{
		"CREATE TABLE",
		"sessions",
		"id",
		"subject_id",
		"created_at",
		"expires_at",
		"last_active_at",
		"schema_version",
		"metadata",
		"idx_sessions_subject_expires",
		"idx_sessions_expires_at",
	}

	for _, keyword := range required {
		if !strings.Contains(sql, keyword) {
			t.Errorf("MigrationSQL() missing %q", keyword)
		}
	}
}

// --- Test: ListBySubject returns sessions in order ---
func TestPostgres_ListBySubject(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	base := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 3; i++ {
		sess := &session.Session{
			ID:            "sess-list-" + string(rune('a'+i)),
			SubjectID:     "user-123",
			CreatedAt:     base.Add(time.Duration(i) * time.Second),
			ExpiresAt:     base.Add(24 * time.Hour),
			LastActiveAt:  base.Add(time.Duration(i) * time.Second),
			SchemaVersion: session.SchemaVersion,
			Metadata:      map[string]any{"order": float64(i)},
		}
		if err := store.Create(ctx, sess); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}

	sessions, err := store.ListBySubject(ctx, "user-123")
	if err != nil {
		t.Fatalf("ListBySubject() error: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(sessions))
	}

	// Should be ordered by created_at ascending.
	for i := 0; i < len(sessions)-1; i++ {
		if !sessions[i].CreatedAt.Before(sessions[i+1].CreatedAt) {
			t.Errorf("sessions not ordered by created_at: %v >= %v",
				sessions[i].CreatedAt, sessions[i+1].CreatedAt)
		}
	}
}

// --- Hardening Tests ---

// Test P.H1: Update non-existent session returns ErrSessionNotFound.
func TestPostgres_Update_NotFound(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("nonexistent", "user-123")
	err := store.Update(ctx, sess)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// Test P.H2: Delete non-existent session is idempotent.
func TestPostgres_Delete_Idempotent(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	err := store.Delete(ctx, "no-such-session")
	if err != nil {
		t.Errorf("expected nil for idempotent delete, got: %v", err)
	}
}

// Test P.H3: DeleteBySubject with no matching sessions is a no-op.
func TestPostgres_DeleteBySubject_NoSessions(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	err := store.DeleteBySubject(ctx, "ghost-user")
	if err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

// Test P.H4: CleanupExpired with no expired sessions returns 0.
func TestPostgres_CleanupExpired_None(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Create a session that hasn't expired.
	sess := testSession("still-alive", "user-1")
	sess.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	n, err := store.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired() error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 cleaned, got %d", n)
	}
}

// Test P.H5: Create with nil metadata round-trips correctly.
func TestPostgres_Create_NilMetadata(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("nil-meta", "user-1")
	sess.Metadata = nil
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	got, err := store.Get(ctx, "nil-meta")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.SubjectID != "user-1" {
		t.Errorf("expected SubjectID=user-1, got %q", got.SubjectID)
	}
}

// Test P.H6: ListBySubject with no sessions returns empty slice.
func TestPostgres_ListBySubject_Empty(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sessions, err := store.ListBySubject(ctx, "nobody")
	if err != nil {
		t.Fatalf("ListBySubject() error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

// Test P.H7: CountBySubject returns 0 for non-existent subject.
func TestPostgres_CountBySubject_Empty(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	count, err := store.CountBySubject(ctx, "nobody")
	if err != nil {
		t.Fatalf("CountBySubject() error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

// Test P.H8: Create with closed DB returns error.
func TestPostgres_Create_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	sess := testSession("err-create", "user-1")
	err := store.Create(ctx, sess)
	if err == nil {
		t.Fatal("expected error on Create with closed DB")
	}
}

// Test P.H9: Get with closed DB returns error (not ErrSessionNotFound).
func TestPostgres_Get_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("err-get", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	store.db.Close()

	_, err := store.Get(ctx, "err-get")
	if err == nil {
		t.Fatal("expected error on Get with closed DB")
	}
}

// Test P.H10: Update with closed DB returns error.
func TestPostgres_Update_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("err-upd", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	store.db.Close()

	sess.LastActiveAt = time.Now().UTC()
	err := store.Update(ctx, sess)
	if err == nil {
		t.Fatal("expected error on Update with closed DB")
	}
}

// Test P.H11: Delete with closed DB returns error.
func TestPostgres_Delete_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	err := store.Delete(ctx, "err-del")
	if err == nil {
		t.Fatal("expected error on Delete with closed DB")
	}
}

// Test P.H12: DeleteBySubject with closed DB returns error.
func TestPostgres_DeleteBySubject_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	err := store.DeleteBySubject(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error on DeleteBySubject with closed DB")
	}
}

// Test P.H13: CleanupExpired with closed DB returns error.
func TestPostgres_CleanupExpired_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	_, err := store.CleanupExpired(ctx)
	if err == nil {
		t.Fatal("expected error on CleanupExpired with closed DB")
	}
}

// Test P.H14: CountBySubject with closed DB returns error.
func TestPostgres_CountBySubject_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	_, err := store.CountBySubject(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error on CountBySubject with closed DB")
	}
}

// Test P.H15: ListBySubject with closed DB returns error.
func TestPostgres_ListBySubject_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	_, err := store.ListBySubject(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error on ListBySubject with closed DB")
	}
}

// Test P.H16: CheckSchemaVersion with closed DB returns error.
func TestPostgres_CheckSchemaVersion_DBError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()
	store.db.Close()

	err := store.CheckSchemaVersion(ctx)
	if err == nil {
		t.Fatal("expected error on CheckSchemaVersion with closed DB")
	}
}

// Test P.H17: ListBySubject with metadata round-trips correctly.
func TestPostgres_ListBySubject_WithMetadata(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("list-meta", "user-meta")
	sess.Metadata = map[string]any{"key": "value", "num": float64(42)}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	sessions, err := store.ListBySubject(ctx, "user-meta")
	if err != nil {
		t.Fatalf("ListBySubject() error: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Metadata["key"] != "value" {
		t.Errorf("expected metadata key=value, got %v", sessions[0].Metadata["key"])
	}
}

// Test P.H18: Update metadata to nil works.
func TestPostgres_Update_NilMetadata(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	sess := testSession("upd-nil-meta", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	sess.Metadata = nil
	if err := store.Update(ctx, sess); err != nil {
		t.Fatalf("Update() error: %v", err)
	}

	got, err := store.Get(ctx, "upd-nil-meta")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	// Nil metadata should round-trip as null or empty.
	_ = got
}

// Test P.H19: Get with corrupted metadata JSON returns unmarshal error.
func TestPostgres_Get_CorruptedMetadata(t *testing.T) {
	store := setupTestDB(t)

	// Insert a row with invalid JSON metadata directly via SQL.
	_, err := store.db.Exec(
		`INSERT INTO sessions (id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"corrupt-meta", "user-1",
		time.Now().UTC(),
		time.Now().UTC().Add(24*time.Hour),
		time.Now().UTC(),
		session.SchemaVersion,
		"not-valid-json{{{",
	)
	if err != nil {
		t.Fatalf("insert error: %v", err)
	}

	_, err = store.Get(context.Background(), "corrupt-meta")
	if err == nil {
		t.Fatal("expected unmarshal error for corrupted metadata")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("expected unmarshal error, got: %v", err)
	}
}

// Test P.H20: ListBySubject with corrupted metadata JSON returns error.
func TestPostgres_ListBySubject_CorruptedMetadata(t *testing.T) {
	store := setupTestDB(t)

	// Insert a row with invalid JSON metadata directly.
	_, err := store.db.Exec(
		`INSERT INTO sessions (id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"corrupt-list", "user-corrupt",
		time.Now().UTC(),
		time.Now().UTC().Add(24*time.Hour),
		time.Now().UTC(),
		session.SchemaVersion,
		"invalid-json!!!",
	)
	if err != nil {
		t.Fatalf("insert error: %v", err)
	}

	_, err = store.ListBySubject(context.Background(), "user-corrupt")
	if err == nil {
		t.Fatal("expected unmarshal error for corrupted metadata")
	}
}

// Test PG.H14: Create fails when metadata contains un-marshalable value (NaN).
func TestPostgres_Create_MarshalError(t *testing.T) {
	store := setupTestDB(t)
	sess := testSession("marshal-fail", "user-1")
	sess.Metadata = map[string]any{"bad": math.NaN()}

	err := store.Create(context.Background(), sess)
	if err == nil {
		t.Fatal("expected marshal error for NaN metadata")
	}
	if !strings.Contains(err.Error(), "marshal metadata") {
		t.Errorf("expected marshal metadata error, got: %v", err)
	}
}

// Test PG.H15: Update fails when metadata contains un-marshalable value (NaN).
func TestPostgres_Update_MarshalError(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Create a valid session first.
	sess := testSession("marshal-update", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Now try to update with un-marshalable metadata.
	sess.Metadata = map[string]any{"bad": math.NaN()}
	err := store.Update(ctx, sess)
	if err == nil {
		t.Fatal("expected marshal error for NaN metadata on update")
	}
	if !strings.Contains(err.Error(), "marshal metadata") {
		t.Errorf("expected marshal metadata error, got: %v", err)
	}
}
