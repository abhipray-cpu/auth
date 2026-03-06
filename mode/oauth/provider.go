// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oauth implements the OAuth2/OIDC authentication mode.
//
// This mode is provider-agnostic — it programs against the OIDC protocol,
// not individual providers. Any identity provider that implements OpenID
// Connect Discovery works out of the box.
//
// Security features:
//   - PKCE mandatory for all flows (S256)
//   - State + nonce for CSRF and replay prevention
//   - id_token signature verification via JWKS
//   - JWKS caching with rotation support
//   - Auto-registration on first OAuth login
//   - SameSite=Lax on state cookies
package oauth

import (
	"errors"
	"net/url"
)

// ProviderConfig configures an OAuth2/OIDC provider.
type ProviderConfig struct {
	// Name is an arbitrary identifier for the provider (e.g., "google", "entra-id").
	Name string

	// IssuerURL is the OIDC issuer URL used for discovery.
	// e.g., "https://accounts.google.com" or "https://login.microsoftonline.com/{tenant}/v2.0"
	IssuerURL string

	// ClientID is the OAuth2 client ID registered with the provider.
	ClientID string

	// ClientSecret is the OAuth2 client secret.
	ClientSecret string

	// RedirectURL is the callback URL for this provider.
	RedirectURL string

	// Scopes are the OAuth2 scopes to request. Defaults to ["openid", "profile", "email"].
	Scopes []string
}

// Validate checks that required fields are set.
func (c *ProviderConfig) Validate() error {
	if c.Name == "" {
		return errors.New("auth/oauth: provider Name is required")
	}
	if c.IssuerURL == "" {
		return errors.New("auth/oauth: provider IssuerURL is required")
	}
	if c.ClientID == "" {
		return errors.New("auth/oauth: provider ClientID is required")
	}

	// Validate that IssuerURL is a valid URL.
	if _, err := url.ParseRequestURI(c.IssuerURL); err != nil {
		return errors.New("auth/oauth: invalid IssuerURL: " + err.Error())
	}

	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	return nil
}

// ProviderRegistry manages multiple OAuth providers.
type ProviderRegistry struct {
	providers map[string]*ProviderConfig
}

// NewProviderRegistry creates an empty provider registry.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]*ProviderConfig),
	}
}

// Register adds a provider to the registry. Returns an error if validation fails.
func (r *ProviderRegistry) Register(cfg ProviderConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	r.providers[cfg.Name] = &cfg
	return nil
}

// Get retrieves a provider by name. Returns nil if not found.
func (r *ProviderRegistry) Get(name string) *ProviderConfig {
	return r.providers[name]
}

// Names returns all registered provider names.
func (r *ProviderRegistry) Names() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
