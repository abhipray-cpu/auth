// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authhttp provides HTTP middleware, handlers, and route registration
// for the auth library.
//
// The package extracts credentials from cookies, headers, forms, and query
// parameters, dispatches to the auth engine, injects Identity into
// context.Context, and manages session cookies.
package authhttp

import (
	"net/http"
	"time"
)

// CookieConfig configures session cookie behavior.
type CookieConfig struct {
	// Name is the session cookie name. Default: "auth_session".
	Name string

	// Domain is the cookie domain scope.
	Domain string

	// Path is the cookie path scope. Default: "/".
	Path string

	// Secure requires HTTPS. Default: true.
	Secure bool

	// SameSite controls the SameSite attribute. Default: http.SameSiteStrictMode.
	SameSite http.SameSite

	// MaxAge is the cookie max age in seconds. 0 means session cookie.
	MaxAge int
}

// DefaultCookieConfig returns a CookieConfig with secure defaults.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     "auth_session",
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// setSessionCookie sets the session cookie on the response.
func setSessionCookie(w http.ResponseWriter, rawSessionID string, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    rawSessionID,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: cfg.SameSite,
		MaxAge:   cfg.MaxAge,
	})
}

// clearSessionCookie clears the session cookie on the response.
func clearSessionCookie(w http.ResponseWriter, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: cfg.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// readSessionCookie reads the raw session ID from the request cookie.
// Returns empty string if the cookie is not present.
func readSessionCookie(r *http.Request, cfg CookieConfig) string {
	c, err := r.Cookie(cfg.Name)
	if err != nil {
		return ""
	}
	return c.Value
}

// setOAuthStateCookie sets the OAuth state cookie with SameSite=Lax
// (required for cross-origin redirects from the IdP).
func setOAuthStateCookie(w http.ResponseWriter, name string, value string, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // OAuth requires Lax for cross-origin redirect
		MaxAge:   600,                  // 10 minutes for OAuth flow
	})
}

// clearOAuthStateCookie clears the OAuth state cookie.
func clearOAuthStateCookie(w http.ResponseWriter, name string, cfg CookieConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Secure:   cfg.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// readOAuthStateCookie reads the OAuth state cookie value.
func readOAuthStateCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// ---------- Public wrappers for use in integration tests ----------

// SetSessionCookiePublic is an exported wrapper around setSessionCookie.
func SetSessionCookiePublic(w http.ResponseWriter, rawSessionID string, cfg CookieConfig) {
	setSessionCookie(w, rawSessionID, cfg)
}

// SetOAuthStateCookiePublic is an exported wrapper around setOAuthStateCookie.
func SetOAuthStateCookiePublic(w http.ResponseWriter, name string, value string, cfg CookieConfig) {
	setOAuthStateCookie(w, name, value, cfg)
}

// ReadOAuthStateCookiePublic is an exported wrapper around readOAuthStateCookie.
func ReadOAuthStateCookiePublic(r *http.Request, name string) string {
	return readOAuthStateCookie(r, name)
}

// ClearOAuthStateCookiePublic is an exported wrapper around clearOAuthStateCookie.
func ClearOAuthStateCookiePublic(w http.ResponseWriter, name string, cfg CookieConfig) {
	clearOAuthStateCookie(w, name, cfg)
}
