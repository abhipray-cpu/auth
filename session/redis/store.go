// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package redis provides a Redis-backed session store implementation.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"
	goredis "github.com/redis/go-redis/v9"
)

// Store implements session.SessionStore backed by Redis.
type Store struct {
	client    *goredis.Client
	keyPrefix string
}

// Config holds Redis session store configuration.
type Config struct {
	// Client is the go-redis client. Required.
	Client *goredis.Client

	// KeyPrefix is the prefix for all session keys in Redis.
	// Default: "auth:session:"
	KeyPrefix string
}

// NewStore creates a Redis-backed SessionStore.
func NewStore(cfg Config) *Store {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "auth:session:"
	}
	return &Store{
		client:    cfg.Client,
		keyPrefix: prefix,
	}
}

func (s *Store) key(sessionID string) string {
	return s.keyPrefix + sessionID
}

// subjectKey returns the Redis SET key that tracks session IDs for a subject.
func (s *Store) subjectKey(subjectID string) string {
	return s.keyPrefix + "subject:" + subjectID
}

// sessionData is the JSON-serializable representation of a session in Redis.
type sessionData struct {
	ID            string         `json:"id"`
	SubjectID     string         `json:"subject_id"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	LastActiveAt  time.Time      `json:"last_active_at"`
	SchemaVersion int            `json:"schema_version"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

func toData(sess *session.Session) *sessionData {
	return &sessionData{
		ID:            sess.ID,
		SubjectID:     sess.SubjectID,
		CreatedAt:     sess.CreatedAt,
		ExpiresAt:     sess.ExpiresAt,
		LastActiveAt:  sess.LastActiveAt,
		SchemaVersion: sess.SchemaVersion,
		Metadata:      sess.Metadata,
	}
}

func fromData(d *sessionData) *session.Session {
	return &session.Session{
		ID:            d.ID,
		SubjectID:     d.SubjectID,
		CreatedAt:     d.CreatedAt,
		ExpiresAt:     d.ExpiresAt,
		LastActiveAt:  d.LastActiveAt,
		SchemaVersion: d.SchemaVersion,
		Metadata:      d.Metadata,
	}
}

// Create persists a new session in Redis with TTL set to ExpiresAt.
func (s *Store) Create(ctx context.Context, sess *session.Session) error {
	data, err := json.Marshal(toData(sess))
	if err != nil {
		return fmt.Errorf("auth/session/redis: marshal error: %w", err)
	}

	ttl := time.Until(sess.ExpiresAt)
	if ttl <= 0 {
		ttl = 1 * time.Second // Minimum TTL to avoid errors.
	}

	pipe := s.client.Pipeline()
	pipe.Set(ctx, s.key(sess.ID), data, ttl)
	pipe.SAdd(ctx, s.subjectKey(sess.SubjectID), sess.ID)
	pipe.Expire(ctx, s.subjectKey(sess.SubjectID), ttl)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("auth/session/redis: create failed: %w", err)
	}

	return nil
}

// Get retrieves a session by its hashed ID.
func (s *Store) Get(ctx context.Context, sessionID string) (*session.Session, error) {
	data, err := s.client.Get(ctx, s.key(sessionID)).Bytes()
	if err != nil {
		if err == goredis.Nil {
			return nil, auth.ErrSessionNotFound
		}
		return nil, fmt.Errorf("auth/session/redis: get failed: %w", err)
	}

	var sd sessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("auth/session/redis: unmarshal error: %w", err)
	}

	return fromData(&sd), nil
}

// Update persists changes to an existing session.
func (s *Store) Update(ctx context.Context, sess *session.Session) error {
	key := s.key(sess.ID)

	// Check existence first.
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("auth/session/redis: exists check failed: %w", err)
	}
	if exists == 0 {
		return auth.ErrSessionNotFound
	}

	data, err := json.Marshal(toData(sess))
	if err != nil {
		return fmt.Errorf("auth/session/redis: marshal error: %w", err)
	}

	// Preserve remaining TTL.
	ttl, err := s.client.TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		ttl = time.Until(sess.ExpiresAt)
	}

	if err := s.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("auth/session/redis: update failed: %w", err)
	}

	return nil
}

// Delete removes a single session.
func (s *Store) Delete(ctx context.Context, sessionID string) error {
	// Get the session first to find SubjectID for subject set cleanup.
	sess, err := s.Get(ctx, sessionID)
	if err != nil {
		// If session doesn't exist, that's fine — idempotent delete.
		if err == auth.ErrSessionNotFound {
			return nil
		}
		return err
	}

	pipe := s.client.Pipeline()
	pipe.Del(ctx, s.key(sessionID))
	pipe.SRem(ctx, s.subjectKey(sess.SubjectID), sessionID)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("auth/session/redis: delete failed: %w", err)
	}

	return nil
}

// DeleteBySubject removes all sessions for a given subject.
func (s *Store) DeleteBySubject(ctx context.Context, subjectID string) error {
	subKey := s.subjectKey(subjectID)
	members, err := s.client.SMembers(ctx, subKey).Result()
	if err != nil {
		return fmt.Errorf("auth/session/redis: list subject sessions failed: %w", err)
	}

	if len(members) == 0 {
		return nil
	}

	keys := make([]string, 0, len(members)+1)
	for _, id := range members {
		keys = append(keys, s.key(id))
	}
	keys = append(keys, subKey) // Delete the subject set too.

	if err := s.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("auth/session/redis: delete by subject failed: %w", err)
	}

	return nil
}

// CountBySubject returns the number of active sessions for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int, error) {
	count, err := s.client.SCard(ctx, s.subjectKey(subjectID)).Result()
	if err != nil {
		return 0, fmt.Errorf("auth/session/redis: count failed: %w", err)
	}
	return int(count), nil
}

// Verify interface compliance at compile time.
var _ session.SessionStore = (*Store)(nil)
