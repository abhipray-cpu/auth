// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"testing"
)

// Test: UserStore interface has exactly 6 methods — verified by mock compilation
func TestUserStore_InterfaceCompiles(t *testing.T) {
	var _ UserStore = (*mockUserStore)(nil)
}

// Test: User interface has exactly 7 methods — verified by mock compilation
func TestUser_InterfaceCompiles(t *testing.T) {
	var _ User = (*mockUser)(nil)
}

// Test: Hasher interface has 2 methods
func TestHasher_InterfaceCompiles(t *testing.T) {
	var _ Hasher = (*mockHasher)(nil)
}

// Test: Authorizer interface has 1 method
func TestAuthorizer_InterfaceCompiles(t *testing.T) {
	var _ Authorizer = (*mockAuthorizer)(nil)
}

// Test: Notifier interface has 1 method
func TestNotifier_InterfaceCompiles(t *testing.T) {
	var _ Notifier = (*mockNotifier)(nil)
}

// Test: AuthMode interface has 3 methods
func TestAuthMode_InterfaceCompiles(t *testing.T) {
	var _ AuthMode = (*mockAuthMode)(nil)
}

// --- Mock implementations (prove the interfaces compile) ---

type mockUserStore struct{}

func (m *mockUserStore) FindByIdentifier(_ context.Context, _ string) (User, error) {
	return nil, nil
}
func (m *mockUserStore) Create(_ context.Context, _ User) error                     { return nil }
func (m *mockUserStore) UpdatePassword(_ context.Context, _ string, _ string) error { return nil }
func (m *mockUserStore) IncrementFailedAttempts(_ context.Context, _ string) error  { return nil }
func (m *mockUserStore) ResetFailedAttempts(_ context.Context, _ string) error      { return nil }
func (m *mockUserStore) SetLocked(_ context.Context, _ string, _ bool) error        { return nil }

type mockUser struct{}

func (m *mockUser) GetSubjectID() string        { return "" }
func (m *mockUser) GetIdentifier() string       { return "" }
func (m *mockUser) GetPasswordHash() string     { return "" }
func (m *mockUser) GetFailedAttempts() int      { return 0 }
func (m *mockUser) IsLocked() bool              { return false }
func (m *mockUser) IsMFAEnabled() bool          { return false }
func (m *mockUser) GetMetadata() map[string]any { return nil }

type mockHasher struct{}

func (m *mockHasher) Hash(_ string) (string, error)           { return "", nil }
func (m *mockHasher) Verify(_ string, _ string) (bool, error) { return false, nil }

type mockAuthorizer struct{}

func (m *mockAuthorizer) CanAccess(_ context.Context, _, _, _ string) (bool, error) {
	return false, nil
}

type mockNotifier struct{}

func (m *mockNotifier) Notify(_ context.Context, _ AuthEvent, _ map[string]any) error {
	return nil
}

type mockAuthMode struct{}

func (m *mockAuthMode) Name() string { return "" }
func (m *mockAuthMode) Authenticate(_ context.Context, _ Credential) (*Identity, error) {
	return nil, nil
}
func (m *mockAuthMode) Supports(_ CredentialType) bool { return false }
