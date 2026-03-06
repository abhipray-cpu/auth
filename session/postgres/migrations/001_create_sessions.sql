-- Migration: 001_create_sessions
-- Description: Create the sessions table with indexes for the auth library.
-- Schema Version: 1

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    subject_id      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    schema_version  INTEGER NOT NULL DEFAULT 1,
    metadata        JSONB
);

-- Index for fast lookup by subject + expiry (used by CountBySubject, DeleteBySubject)
CREATE INDEX IF NOT EXISTS idx_sessions_subject_expires
    ON sessions (subject_id, expires_at);

-- Index for expired session cleanup
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions (expires_at);
