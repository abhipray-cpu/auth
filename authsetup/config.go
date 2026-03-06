// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authsetup

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/engine"
	"github.com/abhipray-cpu/auth/hash"
	"github.com/abhipray-cpu/auth/hooks"
	apikeymode "github.com/abhipray-cpu/auth/mode/apikey"
	"github.com/abhipray-cpu/auth/mode/magiclink"
	"github.com/abhipray-cpu/auth/mode/mtls"
	"github.com/abhipray-cpu/auth/mode/oauth"
	"github.com/abhipray-cpu/auth/mode/password"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
	"github.com/abhipray-cpu/auth/session/postgres"
	"github.com/abhipray-cpu/auth/session/redis"
	goredis "github.com/redis/go-redis/v9"
)

// config collects all values from functional options before validation.
type config struct {
	// Required.
	userStore        auth.UserStore
	identifierConfig auth.IdentifierConfig

	// Session store — exactly one required.
	redisClient        *goredis.Client
	redisKeyPrefix     string
	postgresDB         *sql.DB
	customSessionStore session.SessionStore

	// Session config override.
	sessionConfig *session.SessionConfig

	// Password.
	passwordPolicy *pw.PasswordPolicy
	hasher         auth.Hasher

	// OAuth.
	oauthProviders  []oauth.ProviderConfig
	oauthStateStore oauth.StateStore
	oauthHTTPClient *http.Client

	// Magic link.
	notifier       auth.Notifier
	magicLinkStore session.MagicLinkStore

	// API key.
	apiKeyStore apikey.APIKeyStore

	// mTLS.
	trustAnchors *x509.CertPool

	// Propagator.
	propagatorInstance propagator.IdentityPropagator
	propagatorConfig   *propagator.SignedJWTConfig

	// Hooks.
	hookRegistrations []hookRegistration

	// Authorizer.
	authorizer auth.Authorizer

	// Schema.
	skipSchemaCheck bool
}

// hookRegistration holds a deferred hook registration.
type hookRegistration struct {
	event auth.AuthEvent
	fn    hooks.HookFn
}

// Auth is the top-level configured auth instance returned by New().
// It holds the engine, propagator, and references to closeable resources.
type Auth struct {
	// Engine is the core authentication orchestrator.
	Engine *engine.Engine

	// Propagator is the identity propagator (nil if propagation is disabled).
	Propagator propagator.IdentityPropagator

	// JWKSHandler is the JWKS endpoint handler (nil if not using SignedJWTPropagator).
	JWKSHandler http.Handler

	// Authorizer is the team's authorization provider (nil if not configured).
	// Teams call Authorizer.CanAccess() in their business logic using the
	// Identity from context. The auth library defines the interface; teams
	// implement it with Casbin, OPA, Cedar, or custom logic.
	Authorizer auth.Authorizer

	// closeables are resources that need cleanup on Close().
	closeables []io.Closer
}

// Close performs graceful shutdown: closes Redis connections, Postgres
// connection pools, and stops JWKS refresh goroutines.
func (a *Auth) Close() error {
	var errs []error

	// Close the engine (future: stop background goroutines).
	if err := a.Engine.Close(); err != nil {
		errs = append(errs, err)
	}

	// Close all closeable resources.
	for _, c := range a.closeables {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// New creates and validates a fully wired auth instance using functional options.
//
// Required options:
//   - WithUserStore
//   - WithIdentifierConfig
//   - One of: WithSessionRedis, WithSessionPostgres, WithCustomSessionStore
//
// Defaults applied when not explicitly set:
//   - Hasher: Argon2id with OWASP parameters
//   - PasswordPolicy: NIST 800-63B
//   - Propagator: none (disabled unless explicitly configured)
func New(opts ...Option) (*Auth, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Build session store.
	sessionStore := cfg.buildSessionStore()

	// Check schema version.
	if err := cfg.checkSchema(context.Background(), sessionStore); err != nil {
		return nil, err
	}

	// Build session manager.
	sessionCfg := cfg.buildSessionConfig()
	sessionMgr := session.NewManager(sessionStore, sessionCfg)

	// Build hasher.
	hasher := cfg.buildHasher()

	// Build hook manager and register hooks.
	hookMgr := hooks.NewManager()
	for _, reg := range cfg.hookRegistrations {
		hookMgr.Register(hooks.Event(reg.event), reg.fn)
	}

	// Build auth modes.
	modes, err := cfg.buildModes(hasher)
	if err != nil {
		return nil, err
	}

	// Build engine.
	eng, err := engine.New(engine.Config{
		UserStore:        cfg.userStore,
		Hasher:           hasher,
		SessionManager:   sessionMgr,
		HookManager:      hookMgr,
		Notifier:         cfg.notifier,
		PasswordPolicy:   cfg.buildPasswordPolicy(),
		IdentifierConfig: cfg.identifierConfig,
		Modes:            modes,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: failed to create engine: %w", err)
	}

	// Build propagator.
	prop, err := cfg.buildPropagator()
	if err != nil {
		return nil, fmt.Errorf("auth: failed to create propagator: %w", err)
	}

	// Build JWKS handler if using SignedJWTPropagator.
	var jwksHandler http.Handler
	if sjp, ok := prop.(*propagator.SignedJWTPropagator); ok {
		jwksHandler = sjp.JWKSHandler()
	}

	return &Auth{
		Engine:      eng,
		Propagator:  prop,
		JWKSHandler: jwksHandler,
		Authorizer:  cfg.authorizer,
		closeables:  cfg.collectCloseables(),
	}, nil
}

// --- internal helpers ---

// validate checks that required options are set and mode-specific
// requirements are satisfied.
func (c *config) validate() error {
	if c.userStore == nil {
		return errors.New("auth: WithUserStore is required")
	}
	if c.identifierConfig.Field == "" {
		return errors.New("auth: WithIdentifierConfig is required (Field must be non-empty)")
	}
	if !c.hasSessionStore() {
		return errors.New("auth: a session store is required — use WithSessionRedis, WithSessionPostgres, or WithCustomSessionStore")
	}

	// Magic link requires Notifier.
	if c.magicLinkStore != nil && c.notifier == nil {
		return errors.New("auth: WithNotifier is required when magic link mode is enabled")
	}

	// OAuth requires StateStore.
	if len(c.oauthProviders) > 0 && c.oauthStateStore == nil {
		return errors.New("auth: WithOAuthStateStore is required when OAuth providers are configured")
	}

	return nil
}

func (c *config) hasSessionStore() bool {
	return c.redisClient != nil || c.postgresDB != nil || c.customSessionStore != nil
}

// buildSessionStore creates the session store from the configured backend.
func (c *config) buildSessionStore() session.SessionStore {
	switch {
	case c.customSessionStore != nil:
		return c.customSessionStore
	case c.redisClient != nil:
		return redis.NewStore(redis.Config{
			Client:    c.redisClient,
			KeyPrefix: c.redisKeyPrefix,
		})
	case c.postgresDB != nil:
		return postgres.NewStore(postgres.Config{
			DB: c.postgresDB,
		})
	default:
		panic("auth: no session store configured")
	}
}

// buildSessionConfig returns the configured session config or defaults.
func (c *config) buildSessionConfig() session.SessionConfig {
	if c.sessionConfig != nil {
		return *c.sessionConfig
	}
	return session.DefaultConfig()
}

// buildHasher returns the configured hasher or Argon2id default.
func (c *config) buildHasher() auth.Hasher {
	if c.hasher != nil {
		return c.hasher
	}
	return hash.NewArgon2idHasher(nil)
}

// buildPasswordPolicy returns the configured policy or NIST default.
func (c *config) buildPasswordPolicy() pw.PasswordPolicy {
	if c.passwordPolicy != nil {
		return *c.passwordPolicy
	}
	return pw.DefaultPolicy()
}

// buildModes creates all enabled auth modes from the configuration.
func (c *config) buildModes(hasher auth.Hasher) ([]auth.AuthMode, error) {
	var modes []auth.AuthMode

	// Password mode — always enabled.
	pwMode := password.NewMode(password.ModeConfig{
		UserStore:        c.userStore,
		Hasher:           hasher,
		IdentifierConfig: c.identifierConfig,
	})
	modes = append(modes, pwMode)

	// OAuth mode — enabled when providers are configured.
	if len(c.oauthProviders) > 0 {
		oauthMode, err := oauth.NewMode(oauth.Config{
			UserStore:  c.userStore,
			StateStore: c.oauthStateStore,
			HTTPClient: c.oauthHTTPClient,
			Providers:  c.oauthProviders,
		})
		if err != nil {
			return nil, fmt.Errorf("auth: failed to create OAuth mode: %w", err)
		}
		modes = append(modes, oauthMode)
	}

	// Magic link mode — enabled when notifier + store are configured.
	if c.notifier != nil && c.magicLinkStore != nil {
		mlMode, err := magiclink.NewMode(magiclink.Config{
			UserStore:        c.userStore,
			MagicLinkStore:   c.magicLinkStore,
			Notifier:         c.notifier,
			IdentifierConfig: c.identifierConfig,
		})
		if err != nil {
			return nil, fmt.Errorf("auth: failed to create magic link mode: %w", err)
		}
		modes = append(modes, mlMode)
	}

	// API key mode — enabled when APIKeyStore is configured.
	if c.apiKeyStore != nil {
		modes = append(modes, apikeymode.NewMode(apikeymode.Config{
			APIKeyStore: c.apiKeyStore,
		}))
	}

	// mTLS mode — enabled when trust anchors are configured.
	if c.trustAnchors != nil {
		mtlsMode, err := mtls.NewMode(mtls.Config{
			TrustAnchors: c.trustAnchors,
		})
		if err != nil {
			return nil, fmt.Errorf("auth: failed to create mTLS mode: %w", err)
		}
		modes = append(modes, mtlsMode)
	}

	return modes, nil
}

// buildPropagator creates the identity propagator.
func (c *config) buildPropagator() (propagator.IdentityPropagator, error) {
	if c.propagatorInstance != nil {
		return c.propagatorInstance, nil
	}
	if c.propagatorConfig != nil {
		return propagator.NewSignedJWTPropagator(*c.propagatorConfig)
	}
	return nil, nil
}

// checkSchema validates the session store schema version if applicable.
func (c *config) checkSchema(ctx context.Context, store session.SessionStore) error {
	if c.skipSchemaCheck {
		return nil
	}
	if checker, ok := store.(session.SchemaChecker); ok {
		return session.CheckSchema(ctx, checker)
	}
	return nil
}

// collectCloseables gathers all resources that need cleanup on Close().
func (c *config) collectCloseables() []io.Closer {
	var closeables []io.Closer

	if c.redisClient != nil {
		closeables = append(closeables, c.redisClient)
	}
	if c.postgresDB != nil {
		closeables = append(closeables, c.postgresDB)
	}

	return closeables
}
