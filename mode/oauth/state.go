// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

const (
	stateLength     = 32 // 256 bits of entropy
	nonceLength     = 32
	defaultStateTTL = 10 * time.Minute
)

// OAuthState holds the state and nonce for an OAuth flow.
type OAuthState struct {
	// State is the random CSRF token.
	State string

	// Nonce is the random value bound to the id_token.
	Nonce string

	// Provider is the provider name this state belongs to.
	Provider string

	// PKCEVerifier is the PKCE code_verifier for this flow.
	PKCEVerifier string

	// CreatedAt is when the state was generated.
	CreatedAt time.Time
}

// StateStore abstracts server-side storage of OAuth state.
// This allows PKCE verifiers and nonces to be persisted securely
// without putting them in cookies.
type StateStore interface {
	// Save persists an OAuthState. The key is the state token.
	Save(ctx context.Context, state *OAuthState) error

	// Load retrieves and deletes an OAuthState by its state token (single-use).
	Load(ctx context.Context, stateToken string) (*OAuthState, error)
}

// GenerateState creates a new OAuthState with random state, nonce, and PKCE.
func GenerateState(provider string) (*OAuthState, *PKCEChallenge, error) {
	stateToken, err := randomHex(stateLength)
	if err != nil {
		return nil, nil, fmt.Errorf("auth/oauth: failed to generate state: %w", err)
	}

	nonce, err := randomHex(nonceLength)
	if err != nil {
		return nil, nil, fmt.Errorf("auth/oauth: failed to generate nonce: %w", err)
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, nil, fmt.Errorf("auth/oauth: failed to generate PKCE: %w", err)
	}

	oauthState := &OAuthState{
		State:        stateToken,
		Nonce:        nonce,
		Provider:     provider,
		PKCEVerifier: pkce.Verifier,
		CreatedAt:    time.Now(),
	}

	return oauthState, pkce, nil
}

// SetStateCookie writes the state token to a secure cookie with SameSite=Lax.
func SetStateCookie(w http.ResponseWriter, provider, stateToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state_" + provider,
		Value:    stateToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})
}

// ValidateStateCookie checks that the state parameter matches the cookie.
// Returns the state token or an error.
func ValidateStateCookie(r *http.Request, provider, stateParam string) error {
	cookie, err := r.Cookie("oauth_state_" + provider)
	if err != nil {
		return fmt.Errorf("auth/oauth: state cookie not found for provider %q", provider)
	}
	if cookie.Value != stateParam {
		return fmt.Errorf("auth/oauth: state mismatch")
	}
	return nil
}

// ClearStateCookie removes the state cookie after use.
func ClearStateCookie(w http.ResponseWriter, provider string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state_" + provider,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
