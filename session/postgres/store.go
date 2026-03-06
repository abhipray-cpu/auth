// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package postgres provides a PostgreSQL-backed session store implementation.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver registration
)

// Store implements session.SessionStore backed by PostgreSQL.
type Store struct {
	db *sql.DB
}

// Config holds Postgres session store configuration.
type Config struct {
	// DB is the *sql.DB connection pool. Required.
	DB *sql.DB
}

// NewStore creates a Postgres-backed SessionStore.
func NewStore(cfg Config) *Store {
	return &Store{db: cfg.DB}
}

// MigrationSQL returns the SQL statements for creating the sessions table
// and indexes. These are shipped as files and also available programmatically.
func MigrationSQL() string {
	return `
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    subject_id      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    schema_version  INTEGER NOT NULL DEFAULT 1,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS idx_sessions_subject_expires
    ON sessions (subject_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions (expires_at);
`
}

// Create persists a new session row.
func (s *Store) Create(ctx context.Context, sess *session.Session) error {
	metaJSON, err := json.Marshal(sess.Metadata)
	if err != nil {
		return fmt.Errorf("auth/session/postgres: marshal metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sess.ID, sess.SubjectID, sess.CreatedAt, sess.ExpiresAt,
		sess.LastActiveAt, sess.SchemaVersion, metaJSON,
	)
	if err != nil {
		return fmt.Errorf("auth/session/postgres: create failed: %w", err)
	}
	return nil
}

// Get retrieves a session by its hashed ID.
func (s *Store) Get(ctx context.Context, sessionID string) (*session.Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata
		 FROM sessions WHERE id = $1`, sessionID,
	)

	var sess session.Session
	var metaJSON []byte
	err := row.Scan(
		&sess.ID, &sess.SubjectID, &sess.CreatedAt, &sess.ExpiresAt,
		&sess.LastActiveAt, &sess.SchemaVersion, &metaJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, auth.ErrSessionNotFound
		}
		return nil, fmt.Errorf("auth/session/postgres: get failed: %w", err)
	}

	if metaJSON != nil {
		if err := json.Unmarshal(metaJSON, &sess.Metadata); err != nil {
			return nil, fmt.Errorf("auth/session/postgres: unmarshal metadata: %w", err)
		}
	}

	return &sess, nil
}

// Update persists changes to an existing session.
func (s *Store) Update(ctx context.Context, sess *session.Session) error {
	metaJSON, err := json.Marshal(sess.Metadata)
	if err != nil {
		return fmt.Errorf("auth/session/postgres: marshal metadata: %w", err)
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_active_at = $1, metadata = $2, expires_at = $3
		 WHERE id = $4`,
		sess.LastActiveAt, metaJSON, sess.ExpiresAt, sess.ID,
	)
	if err != nil {
		return fmt.Errorf("auth/session/postgres: update failed: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("auth/session/postgres: rows affected: %w", err)
	}
	if rows == 0 {
		return auth.ErrSessionNotFound
	}

	return nil
}

// Delete removes a single session by ID.
func (s *Store) Delete(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("auth/session/postgres: delete failed: %w", err)
	}
	return nil
}

// DeleteBySubject removes all sessions for a given subject.
func (s *Store) DeleteBySubject(ctx context.Context, subjectID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE subject_id = $1`, subjectID)
	if err != nil {
		return fmt.Errorf("auth/session/postgres: delete by subject failed: %w", err)
	}
	return nil
}

// CountBySubject returns the number of active sessions for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE subject_id = $1 AND expires_at > $2`,
		subjectID, time.Now().UTC(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("auth/session/postgres: count failed: %w", err)
	}
	return count, nil
}

// CleanupExpired deletes all sessions that have passed their expiry time.
// This can be called periodically by a background worker or cron.
func (s *Store) CleanupExpired(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < $1`, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("auth/session/postgres: cleanup failed: %w", err)
	}
	return result.RowsAffected()
}

// CheckSchemaVersion reads the schema version from the most recent session
// and compares it with the library's expected version. Returns an error
// with a clear message and migration link if they don't match.
func (s *Store) CheckSchemaVersion(ctx context.Context) error {
	var version int
	err := s.db.QueryRowContext(ctx,
		`SELECT schema_version FROM sessions ORDER BY created_at DESC LIMIT 1`,
	).Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			// No sessions yet — assume correct version.
			return nil
		}
		return fmt.Errorf("auth/session/postgres: schema version check failed: %w", err)
	}

	if version != session.SchemaVersion {
		return fmt.Errorf("%w: stored version %d, expected %d. "+
			"Run migrations: see https://github.com/abhipray-cpu/auth/blob/main/docs/migrations.md",
			auth.ErrSchemaVersionMismatch, version, session.SchemaVersion)
	}

	return nil
}

// ListBySubject returns all sessions for a subject, ordered by created_at.
// Used by SessionManager for concurrent session eviction.
func (s *Store) ListBySubject(ctx context.Context, subjectID string) ([]*session.Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, subject_id, created_at, expires_at, last_active_at, schema_version, metadata
		 FROM sessions WHERE subject_id = $1 ORDER BY created_at ASC`, subjectID,
	)
	if err != nil {
		return nil, fmt.Errorf("auth/session/postgres: list by subject failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []*session.Session
	for rows.Next() {
		var sess session.Session
		var metaJSON []byte
		err := rows.Scan(
			&sess.ID, &sess.SubjectID, &sess.CreatedAt, &sess.ExpiresAt,
			&sess.LastActiveAt, &sess.SchemaVersion, &metaJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("auth/session/postgres: scan row: %w", err)
		}
		if metaJSON != nil {
			if err := json.Unmarshal(metaJSON, &sess.Metadata); err != nil {
				return nil, fmt.Errorf("auth/session/postgres: unmarshal metadata: %w", err)
			}
		}
		sessions = append(sessions, &sess)
	}

	return sessions, rows.Err()
}

// Verify interface compliance at compile time.
var _ session.SessionStore = (*Store)(nil)
