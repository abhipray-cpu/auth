// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package engine provides the core authentication orchestrator.
//
// The Engine dispatches to auth modes, manages sessions, emits hooks,
// and produces Identity values. It is the central coordination point
// that ties together all auth components.
package engine

import (
	"context"
	"fmt"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/session"
)

// Config configures the auth engine.
type Config struct {
	// UserStore is the team's user persistence (required).
	UserStore auth.UserStore

	// Hasher hashes and verifies passwords (required for password mode).
	Hasher auth.Hasher

	// SessionManager handles session lifecycle (required).
	SessionManager SessionManager

	// HookManager manages lifecycle event hooks (optional, created if nil).
	HookManager *hooks.Manager

	// Notifier sends notifications (optional, required for magic link mode).
	Notifier auth.Notifier

	// PasswordPolicy configures password validation rules.
	PasswordPolicy password.PasswordPolicy

	// IdentifierConfig tells the library what field identifies a user.
	IdentifierConfig auth.IdentifierConfig

	// Modes is the list of auth modes to enable.
	Modes []auth.AuthMode
}

// SessionManager abstracts the session.Manager for the engine.
// This allows the engine to be tested with mock session managers.
type SessionManager interface {
	CreateSession(ctx context.Context, subjectID string, existingSessionID string, metadata map[string]any) (string, *session.Session, error)
	ValidateSession(ctx context.Context, rawID string) (*session.Session, error)
	RefreshSession(ctx context.Context, rawID string) (*session.Session, error)
	DestroySession(ctx context.Context, rawID string) error
	DestroyAllSessions(ctx context.Context, subjectID string) error
}

// Engine is the core authentication orchestrator. It dispatches to auth modes,
// manages sessions, emits hooks, and produces identity.
type Engine struct {
	userStore      auth.UserStore
	hasher         auth.Hasher
	sessionMgr     SessionManager
	hookMgr        *hooks.Manager
	notifier       auth.Notifier
	passwordPolicy password.PasswordPolicy
	identifierCfg  auth.IdentifierConfig
	modes          map[auth.CredentialType]auth.AuthMode
}

// New creates a new auth engine. Returns an error if the configuration
// is invalid (e.g., magic link mode enabled but Notifier is nil).
func New(cfg Config) (*Engine, error) {
	if cfg.UserStore == nil {
		return nil, fmt.Errorf("auth: UserStore is required")
	}
	if cfg.SessionManager == nil {
		return nil, fmt.Errorf("auth: SessionManager is required")
	}

	hookMgr := cfg.HookManager
	if hookMgr == nil {
		hookMgr = hooks.NewManager()
	}

	e := &Engine{
		userStore:      cfg.UserStore,
		hasher:         cfg.Hasher,
		sessionMgr:     cfg.SessionManager,
		hookMgr:        hookMgr,
		notifier:       cfg.Notifier,
		passwordPolicy: cfg.PasswordPolicy,
		identifierCfg:  cfg.IdentifierConfig,
		modes:          make(map[auth.CredentialType]auth.AuthMode),
	}

	// Register modes.
	for _, mode := range cfg.Modes {
		for _, ct := range allCredentialTypes() {
			if mode.Supports(ct) {
				e.modes[ct] = mode
			}
		}

		// Validate: magic link mode requires Notifier.
		if mode.Supports(auth.CredentialTypeMagicLink) && cfg.Notifier == nil {
			return nil, fmt.Errorf("auth: Notifier is required when magic link mode is enabled")
		}
	}

	return e, nil
}

// allCredentialTypes returns all known credential types for mode registration.
func allCredentialTypes() []auth.CredentialType {
	return []auth.CredentialType{
		auth.CredentialTypePassword,
		auth.CredentialTypeOAuth,
		auth.CredentialTypeMagicLink,
		auth.CredentialTypeAPIKey,
		auth.CredentialTypeMTLS,
		auth.CredentialTypeSPIFFE,
	}
}

// hookEvent converts an AuthEvent to a hooks.Event.
func hookEvent(event auth.AuthEvent) hooks.Event {
	return hooks.Event(event)
}

// Register creates a new user account. It validates the password policy,
// hashes the password, creates the user, creates a session (register-and-login),
// and fires hooks.
func (e *Engine) Register(ctx context.Context, cred auth.Credential) (*auth.Identity, *session.Session, error) {
	identifier := e.normalizeIdentifier(cred.Identifier)

	// Fire BeforeRegister hook.
	beforePayload := &hooks.RegisterPayload{
		Identifier: identifier,
		AuthMethod: string(cred.Type),
	}
	if err := e.hookMgr.EmitBefore(ctx, hookEvent(auth.EventRegistration), beforePayload); err != nil {
		return nil, nil, err
	}

	// Validate password policy.
	if cred.Type == auth.CredentialTypePassword {
		if errs := password.Validate(cred.Secret, e.passwordPolicy); len(errs) > 0 {
			return nil, nil, auth.ErrPasswordPolicyViolation
		}
	}

	// Check if user already exists.
	existing, err := e.userStore.FindByIdentifier(ctx, identifier)
	if err == nil && existing != nil {
		return nil, nil, auth.ErrUserAlreadyExists
	}

	// Hash password.
	var passwordHash string
	if cred.Type == auth.CredentialTypePassword && e.hasher != nil {
		passwordHash, err = e.hasher.Hash(cred.Secret)
		if err != nil {
			return nil, nil, fmt.Errorf("auth: failed to hash password: %w", err)
		}
	}

	// Create user via the team's UserStore.
	newUser := &registrationUser{
		subjectID:    identifier,
		identifier:   identifier,
		passwordHash: passwordHash,
	}
	if err := e.userStore.Create(ctx, newUser); err != nil {
		return nil, nil, err
	}

	// Create session (register-and-login-in-one).
	rawSessionID, sess, err := e.sessionMgr.CreateSession(ctx, identifier, "", cred.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: failed to create session: %w", err)
	}

	identity := &auth.Identity{
		SubjectID:  identifier,
		AuthMethod: string(cred.Type),
		AuthTime:   sess.CreatedAt,
		SessionID:  rawSessionID,
	}

	// Fire AfterRegister hook.
	afterPayload := &hooks.RegisterPayload{
		Identifier: identifier,
		AuthMethod: string(cred.Type),
		SubjectID:  identifier,
		SessionID:  rawSessionID,
	}
	e.hookMgr.EmitAfter(ctx, hookEvent(auth.EventRegistration), afterPayload)

	// Optional notification.
	if e.notifier != nil {
		_ = e.notifier.Notify(ctx, auth.EventRegistration, map[string]any{
			"subject_id": identifier,
		})
	}

	return identity, sess, nil
}

// Login authenticates a user and creates a session. It dispatches to the
// correct AuthMode based on the credential type.
func (e *Engine) Login(ctx context.Context, cred auth.Credential) (*auth.Identity, *session.Session, error) {
	identifier := e.normalizeIdentifier(cred.Identifier)

	// Fire BeforeLogin hook.
	beforePayload := &hooks.LoginPayload{
		Identifier: identifier,
		AuthMethod: string(cred.Type),
	}
	if err := e.hookMgr.EmitBefore(ctx, hookEvent(auth.EventLogin), beforePayload); err != nil {
		return nil, nil, err
	}

	// Find the mode for this credential type.
	mode, ok := e.modes[cred.Type]
	if !ok {
		return nil, nil, fmt.Errorf("auth: unsupported credential type: %s", cred.Type)
	}

	// Dispatch to the auth mode.
	normalizedCred := cred
	normalizedCred.Identifier = identifier
	identity, err := mode.Authenticate(ctx, normalizedCred)
	if err != nil {
		// Fire AfterFailedLogin hook.
		failPayload := &hooks.LoginPayload{
			Identifier: identifier,
			AuthMethod: string(cred.Type),
			Error:      err,
		}
		e.hookMgr.EmitAfter(ctx, hookEvent(auth.EventLoginFailed), failPayload)
		return nil, nil, err
	}

	// Create session with fixation prevention.
	existingSessionID := ""
	if cred.Metadata != nil {
		if sid, ok := cred.Metadata["existing_session_id"].(string); ok {
			existingSessionID = sid
		}
	}

	rawSessionID, sess, err := e.sessionMgr.CreateSession(ctx, identity.SubjectID, existingSessionID, cred.Metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: failed to create session: %w", err)
	}

	identity.SessionID = rawSessionID
	identity.AuthTime = sess.CreatedAt

	// Fire AfterLogin hook.
	afterPayload := &hooks.LoginPayload{
		Identifier: identifier,
		AuthMethod: string(cred.Type),
		SubjectID:  identity.SubjectID,
		SessionID:  rawSessionID,
	}
	e.hookMgr.EmitAfter(ctx, hookEvent(auth.EventLogin), afterPayload)

	return identity, sess, nil
}

// Logout destroys the session and fires hooks.
func (e *Engine) Logout(ctx context.Context, sessionID string, subjectID string) error {
	if err := e.sessionMgr.DestroySession(ctx, sessionID); err != nil {
		return fmt.Errorf("auth: failed to destroy session: %w", err)
	}

	// Fire AfterLogout hook.
	payload := &hooks.LogoutPayload{
		SubjectID: subjectID,
		SessionID: sessionID,
	}
	e.hookMgr.EmitAfter(ctx, hookEvent(auth.EventLogout), payload)

	return nil
}

// Verify validates a session and returns the corresponding identity.
func (e *Engine) Verify(ctx context.Context, rawSessionID string) (*auth.Identity, error) {
	sess, err := e.sessionMgr.ValidateSession(ctx, rawSessionID)
	if err != nil {
		return nil, err
	}

	identity := &auth.Identity{
		SubjectID: sess.SubjectID,
		SessionID: rawSessionID,
	}

	return identity, nil
}

// Close performs graceful shutdown of the engine.
func (e *Engine) Close() error {
	return nil
}

// HookManager returns the engine's hook manager for registering hooks.
func (e *Engine) HookManager() *hooks.Manager {
	return e.hookMgr
}

// normalizeIdentifier applies the configured normalization to an identifier.
func (e *Engine) normalizeIdentifier(identifier string) string {
	if e.identifierCfg.Normalize != nil {
		return e.identifierCfg.Normalize(identifier)
	}
	return identifier
}

// registrationUser is a minimal User implementation for registration.
type registrationUser struct {
	subjectID    string
	identifier   string
	passwordHash string
}

func (u *registrationUser) GetSubjectID() string        { return u.subjectID }
func (u *registrationUser) GetIdentifier() string       { return u.identifier }
func (u *registrationUser) GetPasswordHash() string     { return u.passwordHash }
func (u *registrationUser) GetFailedAttempts() int      { return 0 }
func (u *registrationUser) IsLocked() bool              { return false }
func (u *registrationUser) IsMFAEnabled() bool          { return false }
func (u *registrationUser) GetMetadata() map[string]any { return nil }
