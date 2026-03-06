// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abhipray-cpu/auth"
)

const (
	// maxResponseBodySize limits how much data we read from IdP endpoints
	// to prevent memory exhaustion from malicious servers.
	maxResponseBodySize = 1 << 20 // 1 MiB
)

// Config configures the OAuth2/OIDC mode.
type Config struct {
	// UserStore is the team's user persistence (required for auto-registration).
	UserStore auth.UserStore

	// StateStore persists OAuth state server-side (required).
	StateStore StateStore

	// HTTPClient is used for discovery, JWKS, and token exchange.
	// If nil, a default client with 10s timeout is used.
	HTTPClient *http.Client

	// Providers is the list of OAuth providers to register.
	Providers []ProviderConfig
}

// Mode implements auth.AuthMode for OAuth2/OIDC authentication.
type Mode struct {
	userStore  auth.UserStore
	stateStore StateStore
	registry   *ProviderRegistry
	discovery  *DiscoveryClient
	jwks       *JWKSClient
	httpClient *http.Client
}

// NewMode creates a new OAuthMode.
func NewMode(cfg Config) (*Mode, error) {
	if cfg.UserStore == nil {
		return nil, errors.New("auth/oauth: UserStore is required")
	}
	if cfg.StateStore == nil {
		return nil, errors.New("auth/oauth: StateStore is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	registry := NewProviderRegistry()
	for _, p := range cfg.Providers {
		if err := registry.Register(p); err != nil {
			return nil, err
		}
	}

	return &Mode{
		userStore:  cfg.UserStore,
		stateStore: cfg.StateStore,
		registry:   registry,
		discovery:  NewDiscoveryClient(httpClient),
		jwks:       NewJWKSClient(httpClient),
		httpClient: httpClient,
	}, nil
}

// Name returns the mode identifier.
func (m *Mode) Name() string { return "oauth2" }

// Supports returns true only for CredentialTypeOAuth.
func (m *Mode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypeOAuth
}

// BuildAuthURL generates the authorization URL for the given provider.
// It generates state, nonce, and PKCE challenge, stores them server-side,
// and returns the redirect URL.
func (m *Mode) BuildAuthURL(ctx context.Context, providerName string) (redirectURL string, stateToken string, err error) {
	provider := m.registry.Get(providerName)
	if provider == nil {
		return "", "", fmt.Errorf("auth/oauth: unknown provider %q", providerName)
	}

	// Discover OIDC endpoints.
	oidcConfig, err := m.discovery.Discover(ctx, provider.IssuerURL)
	if err != nil {
		return "", "", err
	}

	// Generate state, nonce, and PKCE.
	oauthState, pkce, err := GenerateState(providerName)
	if err != nil {
		return "", "", err
	}

	// Persist state server-side.
	if err := m.stateStore.Save(ctx, oauthState); err != nil {
		return "", "", fmt.Errorf("auth/oauth: failed to save state: %w", err)
	}

	// Build the authorization URL.
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {provider.ClientID},
		"redirect_uri":          {provider.RedirectURL},
		"scope":                 {strings.Join(provider.Scopes, " ")},
		"state":                 {oauthState.State},
		"nonce":                 {oauthState.Nonce},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}

	authURL := oidcConfig.AuthorizationEndpoint + "?" + params.Encode()
	return authURL, oauthState.State, nil
}

// Authenticate handles the OAuth callback. It validates state, exchanges
// the authorization code for tokens, verifies the id_token, and returns
// an Identity. If the user doesn't exist, they are auto-registered.
//
// Expected credential fields:
//   - Metadata["code"]: the authorization code
//   - Metadata["state"]: the state parameter
//   - Metadata["provider"]: the provider name
func (m *Mode) Authenticate(ctx context.Context, cred auth.Credential) (*auth.Identity, error) {
	code, _ := cred.Metadata["code"].(string)
	stateParam, _ := cred.Metadata["state"].(string)
	providerName, _ := cred.Metadata["provider"].(string)

	if code == "" || stateParam == "" || providerName == "" {
		return nil, auth.ErrInvalidCredentials
	}

	// Load and validate state (single-use).
	oauthState, err := m.stateStore.Load(ctx, stateParam)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: invalid state: %w", err)
	}

	// Check state TTL — reject states older than the configured window.
	if time.Since(oauthState.CreatedAt) > defaultStateTTL {
		return nil, fmt.Errorf("auth/oauth: state expired")
	}

	// Verify provider matches.
	if oauthState.Provider != providerName {
		return nil, fmt.Errorf("auth/oauth: state provider mismatch")
	}

	provider := m.registry.Get(providerName)
	if provider == nil {
		return nil, fmt.Errorf("auth/oauth: unknown provider %q", providerName)
	}

	// Discover OIDC config.
	oidcConfig, err := m.discovery.Discover(ctx, provider.IssuerURL)
	if err != nil {
		return nil, err
	}

	// Exchange authorization code for tokens (with PKCE verifier).
	tokenResp, err := m.exchangeCode(ctx, oidcConfig.TokenEndpoint, provider, code, oauthState.PKCEVerifier)
	if err != nil {
		return nil, err
	}

	// Parse id_token header to get kid.
	header, err := ParseIDTokenHeader(tokenResp.IDToken)
	if err != nil {
		return nil, err
	}

	// Get the signing key from JWKS.
	publicKey, err := m.jwks.GetKey(ctx, oidcConfig.JWKSUri, header.Kid)
	if err != nil {
		return nil, err
	}

	// Verify id_token.
	claims, err := VerifyIDToken(tokenResp.IDToken, publicKey, provider.IssuerURL, provider.ClientID, oauthState.Nonce)
	if err != nil {
		return nil, err
	}

	// Auto-register or find existing user.
	identifier := claims.Email
	if identifier == "" {
		identifier = claims.Subject
	}

	user, err := m.userStore.FindByIdentifier(ctx, identifier)
	if err != nil {
		// User not found — auto-register.
		newUser := &oauthUser{
			subjectID:    claims.Subject,
			identifier:   identifier,
			passwordHash: "", // OAuth users have no password hash.
		}
		if err := m.userStore.Create(ctx, newUser); err != nil {
			return nil, fmt.Errorf("auth/oauth: auto-registration failed: %w", err)
		}
		user = newUser
	}

	identity := &auth.Identity{
		SubjectID:  user.GetSubjectID(),
		AuthMethod: "oauth2",
		AuthTime:   time.Now(),
		Metadata: map[string]any{
			"provider": providerName,
			"email":    claims.Email,
			"name":     claims.Name,
		},
	}

	return identity, nil
}

// GetProviderRegistry returns the provider registry for inspection.
func (m *Mode) GetProviderRegistry() *ProviderRegistry {
	return m.registry
}

// tokenResponse represents the response from the token endpoint.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// exchangeCode exchanges an authorization code for tokens.
func (m *Mode) exchangeCode(ctx context.Context, tokenEndpoint string, provider *ProviderConfig, code, pkceVerifier string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {provider.RedirectURL},
		"client_id":     {provider.ClientID},
		"client_secret": {provider.ClientSecret},
		"code_verifier": {pkceVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: token exchange failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth/oauth: token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to parse token response: %w", err)
	}

	if tokenResp.IDToken == "" {
		return nil, errors.New("auth/oauth: no id_token in token response")
	}

	return &tokenResp, nil
}

// oauthUser implements auth.User for auto-registered OAuth users.
type oauthUser struct {
	subjectID    string
	identifier   string
	passwordHash string
}

func (u *oauthUser) GetSubjectID() string        { return u.subjectID }
func (u *oauthUser) GetIdentifier() string       { return u.identifier }
func (u *oauthUser) GetPasswordHash() string     { return u.passwordHash }
func (u *oauthUser) GetFailedAttempts() int      { return 0 }
func (u *oauthUser) IsLocked() bool              { return false }
func (u *oauthUser) IsMFAEnabled() bool          { return false }
func (u *oauthUser) GetMetadata() map[string]any { return nil }

// Compile-time interface check.
var _ auth.AuthMode = (*Mode)(nil)
