// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authhttp — middleware.go provides RequireAuth and OptionalAuth middleware.
//
// RequireAuth returns 401 for unauthenticated requests. OptionalAuth passes nil
// identity when no credentials are present — the handler still executes.
package authhttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
)

// Middleware is the HTTP authentication middleware.
type Middleware struct {
	engine    *engine.Engine
	cookieCfg CookieConfig
}

// NewMiddleware creates a new HTTP auth middleware.
func NewMiddleware(eng *engine.Engine, cookieCfg CookieConfig) *Middleware {
	if cookieCfg.Name == "" {
		cookieCfg = DefaultCookieConfig()
	}
	return &Middleware{
		engine:    eng,
		cookieCfg: cookieCfg,
	}
}

// RequireAuth is middleware that requires a valid session or API key.
// If the request is unauthenticated, it returns 401 Unauthorized.
// On success, the Identity is available via auth.GetIdentity(ctx).
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := m.authenticate(r)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth is middleware that attempts authentication but does not
// require it. If credentials are absent or invalid, the handler is still
// called with a nil identity in context.
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, ok := m.authenticate(r)
		if !ok {
			// No valid auth — proceed with original context (nil identity).
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticate attempts to extract and validate credentials from the request.
// It checks (in order): session cookie, Authorization header (Bearer / API key),
// X-API-Key header, api_key query parameter.
// Returns the context with identity and true on success, or (nil, false) on failure.
func (m *Middleware) authenticate(r *http.Request) (context.Context, bool) {
	// 1. Try session cookie.
	rawSessionID := readSessionCookie(r, m.cookieCfg)
	if rawSessionID != "" {
		identity, err := m.engine.Verify(r.Context(), rawSessionID)
		if err == nil && identity != nil {
			return auth.SetIdentity(r.Context(), identity), true
		}
	}

	// 2. Try Authorization header.
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Bearer token (session token).
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token != "" {
				identity, err := m.engine.Verify(r.Context(), token)
				if err == nil && identity != nil {
					return auth.SetIdentity(r.Context(), identity), true
				}
			}
		}

		// API key in Authorization header.
		if strings.HasPrefix(authHeader, "ApiKey ") {
			apiKey := strings.TrimPrefix(authHeader, "ApiKey ")
			return m.tryAPIKey(r.Context(), apiKey)
		}
	}

	// 3. Try X-API-Key header.
	xAPIKey := r.Header.Get("X-API-Key")
	if xAPIKey != "" {
		return m.tryAPIKey(r.Context(), xAPIKey)
	}

	// 4. Try api_key query parameter.
	queryKey := r.URL.Query().Get("api_key")
	if queryKey != "" {
		return m.tryAPIKey(r.Context(), queryKey)
	}

	return nil, false
}

// tryAPIKey attempts API key authentication via the engine.
func (m *Middleware) tryAPIKey(ctx context.Context, apiKey string) (context.Context, bool) {
	cred := auth.Credential{
		Type:   auth.CredentialTypeAPIKey,
		Secret: apiKey,
	}
	identity, _, err := m.engine.Login(ctx, cred)
	if err != nil || identity == nil {
		return nil, false
	}
	return auth.SetIdentity(ctx, identity), true
}
