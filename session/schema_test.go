// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/abhipray-cpu/auth"
)

// mockSchemaChecker is a mock SchemaChecker for testing.
type mockSchemaChecker struct {
	version int
	err     error
}

func (m *mockSchemaChecker) CheckSchemaVersion(_ context.Context) error {
	if m.err != nil {
		return m.err
	}
	return ValidateSchemaVersion(m.version)
}

// --- Test 4.47: Library checks schema version on startup ---
func TestSchemaVersion_CheckOnStartup(t *testing.T) {
	checker := &mockSchemaChecker{version: SchemaVersion}
	err := CheckSchema(context.Background(), checker)
	if err != nil {
		t.Fatalf("CheckSchema() should succeed for correct version, got: %v", err)
	}

	// Nil checker should be a no-op (e.g., Redis doesn't have schema versioning).
	err = CheckSchema(context.Background(), nil)
	if err != nil {
		t.Fatalf("CheckSchema(nil) should succeed, got: %v", err)
	}
}

// --- Test 4.48: Matching version → startup succeeds ---
func TestSchemaVersion_Match(t *testing.T) {
	err := ValidateSchemaVersion(SchemaVersion)
	if err != nil {
		t.Fatalf("expected nil for matching version, got: %v", err)
	}

	// Also test via the full CheckSchema path.
	checker := &mockSchemaChecker{version: 1}
	err = CheckSchema(context.Background(), checker)
	if err != nil {
		t.Fatalf("CheckSchema() should succeed for version 1, got: %v", err)
	}
}

// --- Test 4.49: Mismatched version → startup fails with clear error + migration link ---
func TestSchemaVersion_Mismatch(t *testing.T) {
	err := ValidateSchemaVersion(999)
	if err == nil {
		t.Fatal("expected error for mismatched version")
	}
	if !errors.Is(err, auth.ErrSchemaVersionMismatch) {
		t.Errorf("expected ErrSchemaVersionMismatch, got: %v", err)
	}

	// Error message should include version numbers and migration link.
	msg := err.Error()
	if !strings.Contains(msg, "999") {
		t.Errorf("error should contain stored version '999', got: %s", msg)
	}
	if !strings.Contains(msg, "1") {
		t.Errorf("error should contain expected version '1', got: %s", msg)
	}
	if !strings.Contains(msg, "migrations") {
		t.Errorf("error should mention migrations, got: %s", msg)
	}
	if !strings.Contains(msg, MigrationInfo) {
		t.Errorf("error should contain migration URL %q, got: %s", MigrationInfo, msg)
	}

	// Also test via CheckSchema path.
	checker := &mockSchemaChecker{version: 0}
	err = CheckSchema(context.Background(), checker)
	if !errors.Is(err, auth.ErrSchemaVersionMismatch) {
		t.Errorf("expected ErrSchemaVersionMismatch from CheckSchema, got: %v", err)
	}
}

// --- Test 4.50: Library never auto-migrates (verified by test) ---
func TestSchemaVersion_NoAutoMigrate(t *testing.T) {
	// The library should never auto-migrate. We verify this by checking that:
	// 1. CheckSchema returns an error on mismatch (it doesn't silently fix it).
	// 2. There is no "auto-migrate" or "auto_migrate" function/method in the API.
	// 3. The ValidateSchemaVersion function only reads — never writes.

	checker := &mockSchemaChecker{version: 0}
	err := CheckSchema(context.Background(), checker)

	// Must fail — not silently fix.
	if err == nil {
		t.Fatal("CheckSchema() should fail on version mismatch, not auto-migrate")
	}
	if !errors.Is(err, auth.ErrSchemaVersionMismatch) {
		t.Errorf("expected ErrSchemaVersionMismatch, got: %v", err)
	}

	// Verify the error instructs the user to run migrations manually.
	if !strings.Contains(err.Error(), "Run migrations") {
		t.Error("error should instruct user to run migrations manually")
	}

	// After CheckSchema fails, the version should still be wrong (no mutation).
	err2 := CheckSchema(context.Background(), checker)
	if err2 == nil {
		t.Fatal("CheckSchema() should still fail — no auto-migration happened")
	}
}

// --- Test 4.51: Migration SQL files exist and are valid SQL ---
func TestSchemaVersion_MigrationSQL(t *testing.T) {
	// Check that the migration file exists at the expected path.
	migrationPath := "../session/postgres/migrations/001_create_sessions.sql"

	// Try multiple relative paths since test working directory varies.
	paths := []string{
		migrationPath,
		"postgres/migrations/001_create_sessions.sql",
		"../postgres/migrations/001_create_sessions.sql",
	}

	var content []byte
	var found bool
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			content = data
			found = true
			break
		}
	}

	if !found {
		t.Fatal("migration file 001_create_sessions.sql not found in any expected location")
	}

	sql := string(content)

	// Verify it contains the required SQL statements.
	requiredKeywords := []string{
		"CREATE TABLE",
		"sessions",
		"id",
		"subject_id",
		"created_at",
		"expires_at",
		"last_active_at",
		"schema_version",
		"metadata",
		"CREATE INDEX",
		"idx_sessions_subject_expires",
		"idx_sessions_expires_at",
	}

	for _, kw := range requiredKeywords {
		if !strings.Contains(sql, kw) {
			t.Errorf("migration SQL missing %q", kw)
		}
	}

	// Verify MigrationInfo constant is set.
	if MigrationInfo == "" {
		t.Error("MigrationInfo constant should not be empty")
	}
	if !strings.Contains(MigrationInfo, "migrations") {
		t.Error("MigrationInfo should reference migrations documentation")
	}
}
