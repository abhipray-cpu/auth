// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authhttp — handlers.go provides HTTP handlers for auth flows.
//
// Handlers: Login, Logout, Register, OAuthInitiate, OAuthCallback,
// MagicLinkInitiate, MagicLinkVerify.
package authhttp

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/engine"
)

// Handlers provides HTTP handler functions for auth flows.
type Handlers struct {
	engine    *engine.Engine
	cookieCfg CookieConfig
}

// NewHandlers creates new auth HTTP handlers.
func NewHandlers(eng *engine.Engine, cookieCfg CookieConfig) *Handlers {
	if cookieCfg.Name == "" {
		cookieCfg = DefaultCookieConfig()
	}
	return &Handlers{
		engine:    eng,
		cookieCfg: cookieCfg,
	}
}

// LoginRequest is the expected JSON body for POST login.
type LoginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// Login handles POST login requests. Reads identifier and password from the
// request body, dispatches to the engine, and sets the session cookie.
func (h *Handlers) Login() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if req.Identifier == "" || req.Password == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cred := auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: req.Identifier,
			Secret:     req.Password,
		}

		identity, _, err := h.engine.Login(r.Context(), cred)
		if err != nil {
			// Generic error to prevent enumeration.
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		setSessionCookie(w, identity.SessionID, h.cookieCfg)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"subject_id": identity.SubjectID,
			"session_id": identity.SessionID,
		})
	})
}

// RegisterRequest is the expected JSON body for POST register.
type RegisterRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

// Register handles POST registration requests. Creates a new user,
// logs them in, and sets the session cookie (register-and-login-in-one).
func (h *Handlers) Register() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if req.Identifier == "" || req.Password == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cred := auth.Credential{
			Type:       auth.CredentialTypePassword,
			Identifier: req.Identifier,
			Secret:     req.Password,
		}

		identity, _, err := h.engine.Register(r.Context(), cred)
		if err != nil {
			// Generic error to prevent enumeration.
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		setSessionCookie(w, identity.SessionID, h.cookieCfg)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"subject_id": identity.SubjectID,
			"session_id": identity.SessionID,
		})
	})
}

// Logout handles POST logout requests. Reads the session cookie,
// destroys the session, and clears the cookie.
func (h *Handlers) Logout() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		rawSessionID := readSessionCookie(r, h.cookieCfg)
		if rawSessionID == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Verify session to get subject ID for the engine.
		identity, err := h.engine.Verify(r.Context(), rawSessionID)
		if err != nil {
			// Session invalid/expired — still clear the cookie.
			clearSessionCookie(w, h.cookieCfg)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := h.engine.Logout(r.Context(), rawSessionID, identity.SubjectID); err != nil {
			clearSessionCookie(w, h.cookieCfg)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		clearSessionCookie(w, h.cookieCfg)
		w.WriteHeader(http.StatusNoContent)
	})
}

// OAuthInitiate handles GET requests to start an OAuth flow.
// It stores the state in a cookie and redirects to the provider's authorization URL.
func (h *Handlers) OAuthInitiate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract provider from URL path — expects /auth/oauth/{provider}.
		provider := extractPathParam(r.URL.Path, "oauth")
		if provider == "" || provider == "callback" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cred := auth.Credential{
			Type: auth.CredentialTypeOAuth,
			Metadata: map[string]any{
				"provider": provider,
				"action":   "initiate",
			},
		}

		identity, _, err := h.engine.Login(r.Context(), cred)
		if err != nil {
			// The engine should return initiate data in the error or identity metadata.
			// For OAuth initiate, the mode returns redirect info.
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if identity == nil || identity.Metadata == nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		redirectURL, _ := identity.Metadata["redirect_url"].(string)
		state, _ := identity.Metadata["state"].(string)

		if redirectURL == "" {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Store state in cookie with SameSite=Lax for cross-origin redirect.
		if state != "" {
			setOAuthStateCookie(w, "oauth_state", state, h.cookieCfg)
		}

		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// OAuthCallback handles GET requests for OAuth callback.
// It validates state, exchanges the code, and creates a session.
func (h *Handlers) OAuthCallback() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Validate state against cookie.
		storedState := readOAuthStateCookie(r, "oauth_state")
		if state == "" || storedState == "" || state != storedState {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Clear state cookie after use.
		clearOAuthStateCookie(w, "oauth_state", h.cookieCfg)

		// Extract provider from URL path — expects /auth/oauth/{provider}/callback.
		provider := extractCallbackProvider(r.URL.Path, "oauth")

		cred := auth.Credential{
			Type: auth.CredentialTypeOAuth,
			Metadata: map[string]any{
				"provider": provider,
				"action":   "callback",
				"code":     code,
				"state":    state,
			},
		}

		identity, _, err := h.engine.Login(r.Context(), cred)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		setSessionCookie(w, identity.SessionID, h.cookieCfg)

		// Redirect to home or configured redirect URL.
		redirectTo := r.URL.Query().Get("redirect_uri")
		if redirectTo == "" {
			redirectTo = "/"
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
	})
}

// MagicLinkRequest is the expected JSON body for magic link initiate.
type MagicLinkRequest struct {
	Identifier string `json:"identifier"`
}

// MagicLinkInitiate handles POST requests to send a magic link.
// Returns 202 Accepted regardless of whether the user exists (prevent enumeration).
func (h *Handlers) MagicLinkInitiate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req MagicLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if req.Identifier == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cred := auth.Credential{
			Type:       auth.CredentialTypeMagicLink,
			Identifier: req.Identifier,
			Metadata: map[string]any{
				"action": "initiate",
			},
		}

		// Fire and forget — always return 202 to prevent enumeration.
		_, _, _ = h.engine.Login(r.Context(), cred)
		w.WriteHeader(http.StatusAccepted)
	})
}

// MagicLinkVerify handles GET requests to verify a magic link token.
// Creates a session on success and redirects.
func (h *Handlers) MagicLinkVerify() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cred := auth.Credential{
			Type:   auth.CredentialTypeMagicLink,
			Secret: token,
			Metadata: map[string]any{
				"action": "verify",
			},
		}

		identity, _, err := h.engine.Login(r.Context(), cred)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		setSessionCookie(w, identity.SessionID, h.cookieCfg)

		redirectTo := r.URL.Query().Get("redirect_uri")
		if redirectTo == "" {
			redirectTo = "/"
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
	})
}

// extractPathParam extracts the segment after the given keyword in a URL path.
// For path "/auth/oauth/google" with keyword "oauth", returns "google".
func extractPathParam(path string, keyword string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if p == keyword && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// extractCallbackProvider extracts the provider from a callback URL path.
// For path "/auth/oauth/google/callback" with keyword "oauth", returns "google".
func extractCallbackProvider(path string, keyword string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i, p := range parts {
		if p == keyword && i+1 < len(parts) && parts[i+1] != "callback" {
			return parts[i+1]
		}
	}
	return ""
}
