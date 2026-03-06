// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/session"
	goredis "github.com/redis/go-redis/v9"
)

func setupTest(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() error: %v", err)
	}
	t.Cleanup(mr.Close)

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	store := NewStore(Config{Client: client, KeyPrefix: "test:session:"})
	return store, mr
}

func testSession(id, subject string) *session.Session {
	now := time.Now()
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

// --- Test 4.19: Session stored in Redis with correct key prefix ---
func TestRedis_Create(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("sess-001", "user-123")
	err := store.Create(ctx, sess)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Verify key exists in Redis with correct prefix.
	if !mr.Exists("test:session:sess-001") {
		t.Error("expected key 'test:session:sess-001' in Redis")
	}
}

// --- Test 4.20: Redis EXPIRE set correctly ---
func TestRedis_Create_TTL(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("sess-ttl", "user-123")
	sess.ExpiresAt = time.Now().Add(1 * time.Hour)

	err := store.Create(ctx, sess)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	ttl := mr.TTL("test:session:sess-ttl")
	// TTL should be roughly 1 hour (allow some tolerance).
	if ttl < 59*time.Minute || ttl > 61*time.Minute {
		t.Errorf("expected TTL ~1h, got %v", ttl)
	}
}

// --- Test 4.21: Session retrieved and deserialized correctly ---
func TestRedis_Get(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	original := testSession("sess-get", "user-123")
	original.Metadata = map[string]any{"role": "admin", "ip": "10.0.0.1"}
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
	if got.SchemaVersion != session.SchemaVersion {
		t.Errorf("expected SchemaVersion=%d, got %d", session.SchemaVersion, got.SchemaVersion)
	}
	if got.Metadata["role"] != "admin" {
		t.Errorf("expected metadata role=admin, got %v", got.Metadata["role"])
	}
}

// --- Test 4.22: Missing key returns ErrSessionNotFound ---
func TestRedis_Get_NotFound(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// --- Test 4.23: Session updated in place ---
func TestRedis_Update(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	sess := testSession("sess-upd", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Update LastActiveAt.
	sess.LastActiveAt = time.Now().Add(5 * time.Minute)
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

// --- Test 4.24: Key removed on delete ---
func TestRedis_Delete(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("sess-del", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if !mr.Exists("test:session:sess-del") {
		t.Fatal("expected key to exist before delete")
	}

	if err := store.Delete(ctx, "sess-del"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	if mr.Exists("test:session:sess-del") {
		t.Error("expected key to be removed after delete")
	}
}

// --- Test 4.25: DeleteBySubject removes all sessions for a subject ---
func TestRedis_DeleteBySubject(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	// Create 3 sessions for user-123.
	for i := 0; i < 3; i++ {
		sess := testSession("sess-sub-"+string(rune('a'+i)), "user-123")
		if err := store.Create(ctx, sess); err != nil {
			t.Fatalf("Create() error: %v", err)
		}
	}
	// Create 1 session for user-456.
	other := testSession("sess-other", "user-456")
	if err := store.Create(ctx, other); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := store.DeleteBySubject(ctx, "user-123"); err != nil {
		t.Fatalf("DeleteBySubject() error: %v", err)
	}

	// All user-123 sessions should be gone.
	for _, id := range []string{"sess-sub-a", "sess-sub-b", "sess-sub-c"} {
		_, err := store.Get(ctx, id)
		if !errors.Is(err, auth.ErrSessionNotFound) {
			t.Errorf("expected session %s to be deleted, got: %v", id, err)
		}
	}

	// user-456 session should remain.
	_, err := store.Get(ctx, "sess-other")
	if err != nil {
		t.Errorf("expected user-456 session to remain, got: %v", err)
	}
}

// --- Test 4.26: CountBySubject returns correct count ---
func TestRedis_CountBySubject(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	// Initially 0.
	count, err := store.CountBySubject(ctx, "user-123")
	if err != nil {
		t.Fatalf("CountBySubject() error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}

	// Create 3 sessions.
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

// --- Test 4.27: Different key prefixes don't collide ---
func TestRedis_KeyIsolation(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() error: %v", err)
	}
	t.Cleanup(mr.Close)

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	storeA := NewStore(Config{Client: client, KeyPrefix: "app_a:session:"})
	storeB := NewStore(Config{Client: client, KeyPrefix: "app_b:session:"})

	ctx := context.Background()

	sessA := testSession("shared-id", "user-a")
	sessB := testSession("shared-id", "user-b")

	if err := storeA.Create(ctx, sessA); err != nil {
		t.Fatalf("storeA.Create() error: %v", err)
	}
	if err := storeB.Create(ctx, sessB); err != nil {
		t.Fatalf("storeB.Create() error: %v", err)
	}

	gotA, _ := storeA.Get(ctx, "shared-id")
	gotB, _ := storeB.Get(ctx, "shared-id")

	if gotA.SubjectID != "user-a" {
		t.Errorf("store A: expected SubjectID=user-a, got %q", gotA.SubjectID)
	}
	if gotB.SubjectID != "user-b" {
		t.Errorf("store B: expected SubjectID=user-b, got %q", gotB.SubjectID)
	}
}

// --- Test 4.28: Satisfies SessionStore interface ---
func TestRedis_ImplementsSessionStore(t *testing.T) {
	var _ session.SessionStore = (*Store)(nil)
}

// --- Test 4.29: Redis connection failure returns error, not panic ---
func TestRedis_ConnectionFailure(t *testing.T) {
	// Connect to a port that's not running Redis.
	client := goredis.NewClient(&goredis.Options{
		Addr:         "localhost:1",
		MaxRetries:   0,
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
	})
	store := NewStore(Config{Client: client})

	ctx := context.Background()

	// All operations should return errors, never panic.
	sess := testSession("sess-fail", "user-123")

	err := store.Create(ctx, sess)
	if err == nil {
		t.Error("expected error on Create with bad connection")
	}

	_, err = store.Get(ctx, "sess-fail")
	if err == nil {
		t.Error("expected error on Get with bad connection")
	}

	count, err := store.CountBySubject(ctx, "user-123")
	if err == nil {
		t.Error("expected error on CountBySubject with bad connection")
	}
	_ = count
}

// --- Hardening Tests ---

// Test R.H1: Update on non-existent session returns ErrSessionNotFound.
func TestRedis_Update_NotFound(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	sess := testSession("nonexistent", "user-123")
	err := store.Update(ctx, sess)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

// Test R.H2: Delete on non-existent session is idempotent (no error).
func TestRedis_Delete_Idempotent(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	err := store.Delete(ctx, "does-not-exist")
	if err != nil {
		t.Errorf("expected nil error for idempotent delete, got: %v", err)
	}
}

// Test R.H3: DeleteBySubject with no sessions for subject is a no-op.
func TestRedis_DeleteBySubject_NoSessions(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	err := store.DeleteBySubject(ctx, "no-such-user")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

// Test R.H4: Create with already-expired TTL still succeeds (minimum TTL).
func TestRedis_Create_ExpiredTTL(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	sess := testSession("expired-ttl", "user-123")
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // Already expired.

	err := store.Create(ctx, sess)
	if err != nil {
		t.Fatalf("Create() with past ExpiresAt should still succeed, got: %v", err)
	}
}

// Test R.H5: Default key prefix when empty.
func TestRedis_DefaultKeyPrefix(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() error: %v", err)
	}
	t.Cleanup(mr.Close)

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	store := NewStore(Config{Client: client, KeyPrefix: ""})

	ctx := context.Background()
	sess := testSession("prefix-test", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Should use default prefix "auth:session:"
	if !mr.Exists("auth:session:prefix-test") {
		t.Error("expected default key prefix auth:session:")
	}
}

// Test R.H6: Create with nil metadata round-trips correctly.
func TestRedis_Create_NilMetadata(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	sess := testSession("nil-meta", "user-123")
	sess.Metadata = nil

	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	got, err := store.Get(ctx, "nil-meta")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.SubjectID != "user-123" {
		t.Errorf("expected SubjectID=user-123, got %q", got.SubjectID)
	}
}

// Test R.H7: Concurrent Create does not panic.
func TestRedis_Create_Concurrent(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	const goroutines = 30
	done := make(chan struct{}, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer func() { done <- struct{}{} }()
			sess := testSession("concurrent-"+string(rune('a'+i)), "user-c")
			store.Create(ctx, sess)
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// Test R.H8: Update with TTL fallback (existing TTL expired or negative).
func TestRedis_Update_TTLFallback(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("ttl-fallback", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Fast-forward miniredis time so the key's TTL is effectively expired,
	// then set a very short TTL so the TTL read returns <= 0.
	mr.FastForward(25 * time.Hour)

	// The key should have expired, so re-create it without TTL to simulate
	// a key with no expiry (TTL returns -1).
	raw, _ := store.client.Get(ctx, store.key("ttl-fallback")).Bytes()
	if raw == nil {
		// Key expired, re-create it manually without TTL for test.
		data := []byte(`{"id":"ttl-fallback","subject_id":"user-123","created_at":"2024-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","last_active_at":"2024-01-01T00:00:00Z","schema_version":1}`)
		store.client.Set(ctx, store.key("ttl-fallback"), data, 0) // 0 = no expiry
	}

	sess.LastActiveAt = sess.LastActiveAt.Add(5 * time.Minute)
	err := store.Update(ctx, sess)
	if err != nil {
		t.Fatalf("Update() should fallback to ExpiresAt TTL, got: %v", err)
	}
}

// Test R.H9: Get with corrupted JSON in Redis returns unmarshal error.
func TestRedis_Get_CorruptedData(t *testing.T) {
	store, _ := setupTest(t)
	ctx := context.Background()

	// Write invalid JSON directly to Redis.
	store.client.Set(ctx, store.key("bad-json"), "not-valid-json{{{", 5*time.Minute)

	_, err := store.Get(ctx, "bad-json")
	if err == nil {
		t.Fatal("expected unmarshal error for corrupted data")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("expected unmarshal error, got: %v", err)
	}
}

// Test R.H10: Create with past ExpiresAt uses minimum TTL.
func TestRedis_Create_PastExpiry(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("past-expiry", "user-123")
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // Already expired.

	err := store.Create(ctx, sess)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Key should exist with the minimum 1s TTL.
	if !mr.Exists(store.key("past-expiry")) {
		t.Error("expected key to exist with minimum TTL")
	}
}

// Test R.H11: Get on closed connection returns error, not ErrSessionNotFound.
func TestRedis_Get_ConnectionError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	// Create a session first.
	sess := testSession("conn-err", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Close miniredis to simulate connection failure.
	mr.Close()

	_, err := store.Get(ctx, "conn-err")
	if err == nil {
		t.Fatal("expected error when Redis connection is closed")
	}
	// Should NOT be ErrSessionNotFound — it's a connection error.
	if errors.Is(err, auth.ErrSessionNotFound) {
		t.Error("connection error should not be ErrSessionNotFound")
	}
}

// Test R.H12: Update on closed connection returns error.
func TestRedis_Update_ConnectionError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("upd-conn-err", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mr.Close()

	sess.LastActiveAt = time.Now()
	err := store.Update(ctx, sess)
	if err == nil {
		t.Fatal("expected error when Redis connection is closed")
	}
}

// Test R.H13: Delete on closed connection returns error (not swallowed).
func TestRedis_Delete_ConnectionError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("del-conn-err", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mr.Close()

	err := store.Delete(ctx, "del-conn-err")
	if err == nil {
		t.Fatal("expected error when Redis connection is closed")
	}
}

// Test R.H14: DeleteBySubject on closed connection returns error.
func TestRedis_DeleteBySubject_ConnectionError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("delsub-conn-err", "user-123")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mr.Close()

	err := store.DeleteBySubject(ctx, "user-123")
	if err == nil {
		t.Fatal("expected error when Redis connection is closed")
	}
}

// Test R.H15: Create on closed connection returns error.
func TestRedis_Create_ConnectionError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	mr.Close()

	sess := testSession("create-conn-err", "user-123")
	err := store.Create(ctx, sess)
	if err == nil {
		t.Fatal("expected error when Redis connection is closed")
	}
}

// Test R.H16: CountBySubject on closed connection returns error.
func TestRedis_CountBySubject_ConnectionError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	mr.Close()

	_, err := store.CountBySubject(ctx, "user-123")
	if err == nil {
		t.Fatal("expected error when Redis connection is closed")
	}
}

// Test R.H17: Create fails when metadata contains un-marshalable value (NaN).
func TestRedis_Create_MarshalError(t *testing.T) {
	store, _ := setupTest(t)
	sess := testSession("marshal-fail", "user-1")
	sess.Metadata = map[string]any{"bad": math.NaN()}

	err := store.Create(context.Background(), sess)
	if err == nil {
		t.Fatal("expected marshal error for NaN metadata")
	}
	if !strings.Contains(err.Error(), "marshal error") {
		t.Errorf("expected marshal error, got: %v", err)
	}
}

// Test R.H18: Update fails when metadata contains un-marshalable value (NaN).
func TestRedis_Update_MarshalError(t *testing.T) {
	store, _ := setupTest(t)
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
	if !strings.Contains(err.Error(), "marshal error") {
		t.Errorf("expected marshal error, got: %v", err)
	}
}

// Test R.H19: Update fails when Redis connection is closed after existence check.
func TestRedis_Update_SetError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("update-set-err", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Close Redis so the SET command fails.
	mr.Close()

	sess.LastActiveAt = time.Now()
	err := store.Update(ctx, sess)
	if err == nil {
		t.Fatal("expected error when Redis connection is closed during update")
	}
}

// Test R.H20: Delete fails when Redis connection is closed.
func TestRedis_Delete_ConnectionError2(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("delete-conn-err", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mr.Close()

	err := store.Delete(ctx, sess.ID)
	if err == nil {
		t.Fatal("expected error when Redis connection is closed during delete")
	}
}

// Test R.H21: DeleteBySubject fails when Redis connection is closed.
func TestRedis_DeleteBySubject_DelError(t *testing.T) {
	store, mr := setupTest(t)
	ctx := context.Background()

	sess := testSession("delsub-conn-err", "user-1")
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mr.Close()

	err := store.DeleteBySubject(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error when Redis connection is closed during DeleteBySubject")
	}
}
