// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authhttp — routes.go provides route registration helpers.
//
// RegisterRoutes mounts all auth handlers on the given ServeMux with
// a configurable prefix. The JWKS endpoint is auto-registered at
// /.well-known/auth-keys when a JWKSHandler is provided.
package authhttp

import "net/http"

// RouteConfig configures route registration.
type RouteConfig struct {
	// Prefix is the URL prefix for auth routes. Default: "/auth".
	Prefix string

	// JWKSHandler is the handler for the JWKS endpoint.
	// When set, it is registered at /.well-known/auth-keys.
	JWKSHandler http.Handler

	// LoginRedirectURL is where to redirect after successful OAuth/magic link login.
	// Default: "/".
	LoginRedirectURL string
}

// DefaultRouteConfig returns a RouteConfig with sensible defaults.
func DefaultRouteConfig() RouteConfig {
	return RouteConfig{
		Prefix:           "/auth",
		LoginRedirectURL: "/",
	}
}

// RegisterRoutes registers all auth routes on the given mux.
//
// Routes registered:
//
//	POST {prefix}/login           — password login
//	POST {prefix}/register        — user registration
//	POST {prefix}/logout          — session logout
//	GET  {prefix}/oauth/{provider}          — OAuth initiate
//	GET  {prefix}/oauth/{provider}/callback — OAuth callback
//	POST {prefix}/magic-link                — magic link initiate
//	GET  {prefix}/magic-link/verify         — magic link verify
//	GET  /.well-known/auth-keys             — JWKS (if JWKSHandler provided)
func RegisterRoutes(mux *http.ServeMux, handlers *Handlers, cfg RouteConfig) {
	if cfg.Prefix == "" {
		cfg.Prefix = "/auth"
	}

	prefix := cfg.Prefix

	mux.Handle(prefix+"/login", handlers.Login())
	mux.Handle(prefix+"/register", handlers.Register())
	mux.Handle(prefix+"/logout", handlers.Logout())

	// OAuth routes — using trailing slash to capture provider segment.
	mux.Handle(prefix+"/oauth/", handlers.oauthRouter())

	// Magic link routes.
	mux.Handle(prefix+"/magic-link", handlers.MagicLinkInitiate())
	mux.Handle(prefix+"/magic-link/verify", handlers.MagicLinkVerify())

	// JWKS endpoint — always at well-known path, independent of prefix.
	if cfg.JWKSHandler != nil {
		mux.Handle("/.well-known/auth-keys", cfg.JWKSHandler)
	}
}

// oauthRouter routes OAuth requests to initiate or callback handlers.
func (h *Handlers) oauthRouter() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Determine if this is a callback or initiate request.
		if isCallbackPath(r.URL.Path) {
			h.OAuthCallback().ServeHTTP(w, r)
		} else {
			h.OAuthInitiate().ServeHTTP(w, r)
		}
	})
}

// isCallbackPath returns true if the path ends with /callback.
func isCallbackPath(path string) bool {
	// Trim trailing slash.
	p := path
	if len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return len(p) >= 9 && p[len(p)-9:] == "/callback"
}
