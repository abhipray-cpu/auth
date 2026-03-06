// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OIDCConfig represents the parsed OIDC Discovery document.
type OIDCConfig struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// DiscoveryClient fetches and caches OIDC Discovery configuration.
type DiscoveryClient struct {
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*discoveryEntry
}

type discoveryEntry struct {
	config    *OIDCConfig
	fetchedAt time.Time
}

const (
	discoveryCacheTTL    = 1 * time.Hour
	maxDiscoveryBodySize = 1 << 20 // 1 MiB
)

// NewDiscoveryClient creates a new OIDC Discovery client.
func NewDiscoveryClient(httpClient *http.Client) *DiscoveryClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &DiscoveryClient{
		httpClient: httpClient,
		cache:      make(map[string]*discoveryEntry),
	}
}

// Discover fetches the OIDC configuration for the given issuer URL.
// Results are cached for 1 hour.
func (c *DiscoveryClient) Discover(ctx context.Context, issuerURL string) (*OIDCConfig, error) {
	// Check cache first.
	c.mu.RLock()
	entry, ok := c.cache[issuerURL]
	c.mu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < discoveryCacheTTL {
		return entry.config, nil
	}

	// Fetch the discovery document.
	wellKnownURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth/oauth: discovery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBodySize))
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to read discovery response: %w", err)
	}

	var config OIDCConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to parse discovery document: %w", err)
	}

	// Validate issuer matches.
	if config.Issuer != issuerURL {
		return nil, fmt.Errorf("auth/oauth: issuer mismatch: expected %q, got %q", issuerURL, config.Issuer)
	}

	// Cache the result.
	c.mu.Lock()
	c.cache[issuerURL] = &discoveryEntry{
		config:    &config,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()

	return &config, nil
}

// Invalidate removes a cached discovery config (used for forced refresh).
func (c *DiscoveryClient) Invalidate(issuerURL string) {
	c.mu.Lock()
	delete(c.cache, issuerURL)
	c.mu.Unlock()
}
