// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authsetup provides the constructor and functional options for
// wiring the auth library. This is the only package adopters import
// during application startup.
//
// Usage:
//
//	eng, err := authsetup.New(
//	    authsetup.WithUserStore(myUserStore),
//	    authsetup.WithIdentifierConfig(auth.IdentifierConfig{Field: "email"}),
//	    authsetup.WithSessionRedis(redisClient, ""),
//	)
//	if err != nil { log.Fatal(err) }
//	defer eng.Close()
package authsetup

import (
	"crypto/x509"
	"database/sql"
	"net/http"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/apikey"
	"github.com/abhipray-cpu/auth/hooks"
	"github.com/abhipray-cpu/auth/mode/oauth"
	pw "github.com/abhipray-cpu/auth/password"
	"github.com/abhipray-cpu/auth/propagator"
	"github.com/abhipray-cpu/auth/session"
	goredis "github.com/redis/go-redis/v9"
)

// Option configures the auth engine during construction.
type Option func(*config)

// WithUserStore sets the team's user persistence (required).
func WithUserStore(store auth.UserStore) Option {
	return func(c *config) { c.userStore = store }
}

// WithIdentifierConfig sets the identifier configuration (required).
func WithIdentifierConfig(cfg auth.IdentifierConfig) Option {
	return func(c *config) { c.identifierConfig = cfg }
}

// WithSessionRedis configures Redis as the session store.
// The keyPrefix defaults to "auth:session:" if empty.
func WithSessionRedis(client *goredis.Client, keyPrefix string) Option {
	return func(c *config) {
		c.redisClient = client
		c.redisKeyPrefix = keyPrefix
	}
}

// WithSessionPostgres configures PostgreSQL as the session store.
func WithSessionPostgres(db *sql.DB) Option {
	return func(c *config) { c.postgresDB = db }
}

// WithCustomSessionStore provides a custom session.SessionStore implementation.
func WithCustomSessionStore(store session.SessionStore) Option {
	return func(c *config) { c.customSessionStore = store }
}

// WithSessionConfig overrides the default session configuration
// (timeouts, concurrent session limits, cookie settings).
func WithSessionConfig(cfg session.SessionConfig) Option {
	return func(c *config) { c.sessionConfig = &cfg }
}

// WithPasswordPolicy overrides the default NIST 800-63B password policy.
func WithPasswordPolicy(policy pw.PasswordPolicy) Option {
	return func(c *config) { c.passwordPolicy = &policy }
}

// WithHasher overrides the default Argon2id hasher. Use this for legacy
// password schemes or testing.
func WithHasher(hasher auth.Hasher) Option {
	return func(c *config) { c.hasher = hasher }
}

// WithOAuthProvider registers an OAuth2/OIDC provider. Call multiple times
// to register multiple providers.
func WithOAuthProvider(provider oauth.ProviderConfig) Option {
	return func(c *config) {
		c.oauthProviders = append(c.oauthProviders, provider)
	}
}

// WithOAuthStateStore sets the server-side state store for OAuth flows.
// Required when any OAuth provider is configured.
func WithOAuthStateStore(store oauth.StateStore) Option {
	return func(c *config) { c.oauthStateStore = store }
}

// WithOAuthHTTPClient overrides the HTTP client used for OAuth discovery,
// JWKS fetching, and token exchange.
func WithOAuthHTTPClient(client *http.Client) Option {
	return func(c *config) { c.oauthHTTPClient = client }
}

// WithNotifier sets the notification sender. Required when magic link
// mode is enabled. Can also be used for registration/login notifications.
func WithNotifier(notifier auth.Notifier) Option {
	return func(c *config) { c.notifier = notifier }
}

// WithMagicLinkStore sets the magic link token store. When set together
// with WithNotifier, magic link mode is automatically enabled.
func WithMagicLinkStore(store session.MagicLinkStore) Option {
	return func(c *config) { c.magicLinkStore = store }
}

// WithAPIKeyStore sets the API key store. When set, API key mode is
// automatically enabled.
func WithAPIKeyStore(store apikey.APIKeyStore) Option {
	return func(c *config) { c.apiKeyStore = store }
}

// WithTrustAnchors sets the mTLS trust anchor certificates. When set,
// mTLS/SPIFFE mode is automatically enabled.
func WithTrustAnchors(pool *x509.CertPool) Option {
	return func(c *config) { c.trustAnchors = pool }
}

// WithIdentityPropagator sets a custom identity propagator. Overrides
// the default SignedJWTPropagator.
func WithIdentityPropagator(p propagator.IdentityPropagator) Option {
	return func(c *config) { c.propagatorInstance = p }
}

// WithSignedJWTPropagator configures the default SignedJWTPropagator
// with the given settings.
func WithSignedJWTPropagator(cfg propagator.SignedJWTConfig) Option {
	return func(c *config) { c.propagatorConfig = &cfg }
}

// WithHook registers a lifecycle hook for the given event. Call multiple
// times to register multiple hooks — they execute in registration order.
func WithHook(event auth.AuthEvent, fn hooks.HookFn) Option {
	return func(c *config) {
		c.hookRegistrations = append(c.hookRegistrations, hookRegistration{
			event: event,
			fn:    fn,
		})
	}
}

// WithAuthorizer sets the authorization provider.
func WithAuthorizer(authz auth.Authorizer) Option {
	return func(c *config) { c.authorizer = authz }
}

// WithSkipSchemaCheck disables schema version checking on startup.
// Useful in testing or when the team manages migrations separately.
func WithSkipSchemaCheck() Option {
	return func(c *config) { c.skipSchemaCheck = true }
}
