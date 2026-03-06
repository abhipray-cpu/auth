// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JSONWebKey represents a single key from a JWKS.
type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Crv string `json:"crv"` // EC curve
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

// JWKSClient fetches, caches, and manages JWKS for token verification.
type JWKSClient struct {
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*jwksEntry // keyed by JWKS URI
}

type jwksEntry struct {
	jwks      *JWKS
	fetchedAt time.Time
}

const (
	jwksCacheTTL    = 1 * time.Hour
	maxJWKSBodySize = 1 << 20 // 1 MiB
)

// NewJWKSClient creates a new JWKS client.
func NewJWKSClient(httpClient *http.Client) *JWKSClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWKSClient{
		httpClient: httpClient,
		cache:      make(map[string]*jwksEntry),
	}
}

// GetKey retrieves a public key by kid from the given JWKS URI.
// Caches the JWKS and refreshes on key miss (rotation detection).
func (c *JWKSClient) GetKey(ctx context.Context, jwksURI string, kid string) (interface{}, error) {
	// Try cache first.
	key, err := c.findKeyInCache(jwksURI, kid)
	if err == nil {
		return key, nil
	}

	// Key not in cache — fetch fresh JWKS (rotation detection).
	if err := c.fetchJWKS(ctx, jwksURI); err != nil {
		return nil, err
	}

	return c.findKeyInCache(jwksURI, kid)
}

func (c *JWKSClient) findKeyInCache(jwksURI, kid string) (interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[jwksURI]
	if !ok {
		return nil, fmt.Errorf("auth/oauth: JWKS not cached for %q", jwksURI)
	}

	// Treat expired cache as a miss — forces a refetch.
	if time.Since(entry.fetchedAt) >= jwksCacheTTL {
		return nil, fmt.Errorf("auth/oauth: JWKS cache expired for %q", jwksURI)
	}

	for _, k := range entry.jwks.Keys {
		if k.Kid == kid {
			return parseJWK(&k)
		}
	}

	return nil, fmt.Errorf("auth/oauth: key %q not found in JWKS", kid)
}

func (c *JWKSClient) fetchJWKS(ctx context.Context, jwksURI string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return fmt.Errorf("auth/oauth: failed to create JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth/oauth: failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth/oauth: JWKS returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodySize))
	if err != nil {
		return fmt.Errorf("auth/oauth: failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("auth/oauth: failed to parse JWKS: %w", err)
	}

	c.mu.Lock()
	c.cache[jwksURI] = &jwksEntry{
		jwks:      &jwks,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()

	return nil
}

// IsCached returns whether a valid (non-expired) JWKS is cached for the given URI.
func (c *JWKSClient) IsCached(jwksURI string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[jwksURI]
	return ok && time.Since(entry.fetchedAt) < jwksCacheTTL
}

// parseJWK converts a JSONWebKey to a Go crypto public key.
func parseJWK(jwk *JSONWebKey) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAKey(jwk)
	case "EC":
		return parseECKey(jwk)
	default:
		return nil, fmt.Errorf("auth/oauth: unsupported key type %q", jwk.Kty)
	}
}

func parseRSAKey(jwk *JSONWebKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode RSA modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECKey(jwk *JSONWebKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("auth/oauth: unsupported curve %q", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode EC x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode EC y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
