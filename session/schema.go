// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"

	"github.com/abhipray-cpu/auth"
)

// SchemaChecker verifies that the session store schema is compatible
// with the library's expected version. Implementations are provided
// by each store adapter (Postgres, Redis, etc.).
type SchemaChecker interface {
	// CheckSchemaVersion reads the schema version from the store and
	// compares it with the library's expected version. Returns
	// ErrSchemaVersionMismatch with a clear error message if they differ.
	CheckSchemaVersion(ctx context.Context) error
}

// MigrationInfo provides the migration link for schema version mismatches.
const MigrationInfo = "https://github.com/abhipray-cpu/auth/blob/main/docs/migrations.md"

// CheckSchema validates the schema version on startup. If the version
// doesn't match, it returns a clear error with migration instructions.
// The library NEVER auto-migrates — the team must run migrations explicitly.
func CheckSchema(ctx context.Context, checker SchemaChecker) error {
	if checker == nil {
		return nil
	}
	return checker.CheckSchemaVersion(ctx)
}

// ValidateSchemaVersion compares a stored version against the expected
// library version and returns a descriptive error if they don't match.
// This is a helper used by store adapters.
func ValidateSchemaVersion(storedVersion int) error {
	if storedVersion != SchemaVersion {
		return fmt.Errorf("%w: stored version %d, expected %d. "+
			"Run migrations: see %s",
			auth.ErrSchemaVersionMismatch, storedVersion, SchemaVersion, MigrationInfo)
	}
	return nil
}
