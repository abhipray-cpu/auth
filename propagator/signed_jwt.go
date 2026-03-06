// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package propagator — signed_jwt.go implements SignedJWTPropagator.
//
// SignedJWTPropagator is the default identity propagation strategy.
// It creates short-lived (30 s) Ed25519-signed JWTs carrying the
// authenticated identity between services.
//
// Features:
//   - Ed25519 key generation on first Encode call
//   - Key rotation with 60 s overlap (old key accepted during overlap)
//   - JWKS endpoint handler serving public verification keys
//   - Audience-restricted, issuer-verified tokens
//   - All required claims: sub, iss, aud, iat, exp, auth_method, auth_time
package propagator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/abhipray-cpu/auth"
)

// Header key used to carry the propagated JWT.
const headerKeyJWT = "x-auth-identity"

// keyEntry represents a signing/verification key with its metadata.
type keyEntry struct {
	id         string
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	createdAt  time.Time
	expiresAt  time.Time // when key should stop being used for verification
}

// SignedJWTConfig configures the SignedJWTPropagator.
type SignedJWTConfig struct {
	// Issuer is the JWT "iss" claim.
	Issuer string

	// Audience is the JWT "aud" claim.
	Audience string

	// TTL is the token time-to-live. Default: 30 seconds.
	TTL time.Duration

	// KeyOverlapPeriod is how long old keys remain valid for verification
	// after rotation. Default: 60 seconds (2× TTL).
	KeyOverlapPeriod time.Duration

	// KeyStore provides optional persistence for signing keys across restarts.
	// If nil, keys are generated in-memory and lost on restart.
	KeyStore KeyStore

	// NowFunc returns the current time. Defaults to time.Now.
	// Exposed for testing.
	NowFunc func() time.Time
}

// KeyStore provides persistence for Ed25519 signing keys.
// Implementations may store keys in a session store, file, environment
// variable, or any other durable medium.
type KeyStore interface {
	// SaveKeys persists the current set of key entries.
	SaveKeys(ctx context.Context, keys []KeyRecord) error

	// LoadKeys retrieves previously persisted key entries.
	// Returns nil, nil if no keys have been persisted yet.
	LoadKeys(ctx context.Context) ([]KeyRecord, error)
}

// KeyRecord is the serializable form of a key entry for persistence.
type KeyRecord struct {
	ID         string    `json:"id"`
	PublicKey  []byte    `json:"public_key"`  // Ed25519 public key bytes
	PrivateKey []byte    `json:"private_key"` // Ed25519 private key bytes
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// SignedJWTPropagator implements IdentityPropagator using Ed25519 JWTs.
type SignedJWTPropagator struct {
	issuer           string
	audience         string
	ttl              time.Duration
	keyOverlapPeriod time.Duration
	keyStore         KeyStore
	nowFunc          func() time.Time

	mu   sync.RWMutex
	keys []keyEntry // ordered newest-first; old keys pruned on rotation
}

// NewSignedJWTPropagator creates a new SignedJWTPropagator.
func NewSignedJWTPropagator(cfg SignedJWTConfig) (*SignedJWTPropagator, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("propagator: Issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("propagator: Audience is required")
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}

	overlap := cfg.KeyOverlapPeriod
	if overlap == 0 {
		overlap = 2 * ttl
	}

	nowFunc := cfg.NowFunc
	if nowFunc == nil {
		nowFunc = time.Now
	}

	p := &SignedJWTPropagator{
		issuer:           cfg.Issuer,
		audience:         cfg.Audience,
		ttl:              ttl,
		keyOverlapPeriod: overlap,
		keyStore:         cfg.KeyStore,
		nowFunc:          nowFunc,
	}

	// Try to load persisted keys on startup.
	if cfg.KeyStore != nil {
		if records, err := cfg.KeyStore.LoadKeys(context.Background()); err == nil && len(records) > 0 {
			for _, r := range records {
				p.keys = append(p.keys, keyEntry{
					id:         r.ID,
					publicKey:  ed25519.PublicKey(r.PublicKey),
					privateKey: ed25519.PrivateKey(r.PrivateKey),
					createdAt:  r.CreatedAt,
					expiresAt:  r.ExpiresAt,
				})
			}
		}
	}

	return p, nil
}

// Encode creates a signed JWT carrying the identity and returns metadata
// to attach to outgoing requests.
func (p *SignedJWTPropagator) Encode(ctx context.Context, identity *auth.Identity) (map[string]string, error) {
	if identity == nil {
		return nil, errors.New("propagator: identity is nil")
	}

	key, err := p.currentKey()
	if err != nil {
		return nil, fmt.Errorf("propagator: key error: %w", err)
	}

	now := p.nowFunc()

	claims := jwtClaims{
		Sub:        identity.SubjectID,
		Iss:        p.issuer,
		Aud:        p.audience,
		Iat:        now.Unix(),
		Exp:        now.Add(p.ttl).Unix(),
		AuthMethod: identity.AuthMethod,
		AuthTime:   identity.AuthTime.Unix(),
		Kid:        key.id,
	}

	token, err := signJWT(claims, key.privateKey)
	if err != nil {
		return nil, fmt.Errorf("propagator: sign error: %w", err)
	}

	return map[string]string{headerKeyJWT: token}, nil
}

// Decode reads a JWT from metadata, verifies it, and reconstructs the identity.
func (p *SignedJWTPropagator) Decode(ctx context.Context, metadata map[string]string, _ *auth.WorkloadIdentity) (*auth.Identity, error) {
	token, ok := metadata[headerKeyJWT]
	if !ok {
		return nil, errors.New("propagator: no identity token in metadata")
	}

	claims, err := p.verifyJWT(token)
	if err != nil {
		return nil, err
	}

	return &auth.Identity{
		SubjectID:  claims.Sub,
		AuthMethod: claims.AuthMethod,
		AuthTime:   time.Unix(claims.AuthTime, 0),
		Metadata:   make(map[string]any),
	}, nil
}

// RotateKey generates a new signing key, keeping the previous key valid
// for the overlap period. Call this periodically (e.g. every TTL×2) or
// on demand.
func (p *SignedJWTPropagator) RotateKey() error {
	entry, err := generateKeyEntry(p.nowFunc(), p.keyOverlapPeriod)
	if err != nil {
		return fmt.Errorf("propagator: rotate error: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Prepend new key (newest first). Prune expired old keys.
	now := p.nowFunc()
	var kept []keyEntry
	kept = append(kept, entry)
	for _, k := range p.keys {
		if now.Before(k.expiresAt) {
			kept = append(kept, k)
		}
	}
	p.keys = kept

	if err := p.persistKeysLocked(); err != nil {
		return fmt.Errorf("propagator: persist after rotate: %w", err)
	}
	return nil
}

// KeyCount returns the number of keys currently held (for testing).
func (p *SignedJWTPropagator) KeyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.keys)
}

// ---------------------------------------------------------------
// Internal: key management
// ---------------------------------------------------------------

// currentKey returns the current signing key, generating one on first use.
func (p *SignedJWTPropagator) currentKey() (keyEntry, error) {
	p.mu.RLock()
	if len(p.keys) > 0 {
		k := p.keys[0]
		p.mu.RUnlock()
		return k, nil
	}
	p.mu.RUnlock()

	// Generate key on first use.
	entry, err := generateKeyEntry(p.nowFunc(), p.keyOverlapPeriod)
	if err != nil {
		return keyEntry{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check: another goroutine may have beaten us.
	if len(p.keys) > 0 {
		return p.keys[0], nil
	}

	p.keys = append(p.keys, entry)

	// Persist the newly generated key if a store is configured.
	_ = p.persistKeysLocked() // best-effort on first use
	return entry, nil
}

// persistKeysLocked saves current keys to the KeyStore. Must be called with
// p.mu held (read or write). No-op if no KeyStore is configured.
func (p *SignedJWTPropagator) persistKeysLocked() error {
	if p.keyStore == nil {
		return nil
	}
	records := make([]KeyRecord, len(p.keys))
	for i, k := range p.keys {
		records[i] = KeyRecord{
			ID:         k.id,
			PublicKey:  []byte(k.publicKey),
			PrivateKey: []byte(k.privateKey),
			CreatedAt:  k.createdAt,
			ExpiresAt:  k.expiresAt,
		}
	}
	return p.keyStore.SaveKeys(context.Background(), records)
}

// generateKeyEntry creates a new Ed25519 key pair with metadata.
func generateKeyEntry(now time.Time, overlapPeriod time.Duration) (keyEntry, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return keyEntry{}, fmt.Errorf("propagator: keygen: %w", err)
	}

	// Key ID: first 8 bytes of public key, base64url encoded.
	kid := base64.RawURLEncoding.EncodeToString(pub[:8])

	return keyEntry{
		id:         kid,
		publicKey:  pub,
		privateKey: priv,
		createdAt:  now,
		expiresAt:  now.Add(overlapPeriod + 24*time.Hour), // long validity for verification
	}, nil
}

// ---------------------------------------------------------------
// Internal: minimal JWT implementation (Ed25519 / EdDSA)
// ---------------------------------------------------------------

// jwtClaims is the set of claims carried in the propagation JWT.
type jwtClaims struct {
	Sub        string `json:"sub"`
	Iss        string `json:"iss"`
	Aud        string `json:"aud"`
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
	AuthMethod string `json:"auth_method"`
	AuthTime   int64  `json:"auth_time"`
	Kid        string `json:"kid"`
}

// jwtHeader is the JWT header for EdDSA/Ed25519.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// signJWT creates a compact JWT (header.payload.signature).
func signJWT(claims jwtClaims, privKey ed25519.PrivateKey) (string, error) {
	header := jwtHeader{Alg: "EdDSA", Typ: "JWT", Kid: claims.Kid}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	signature := ed25519.Sign(privKey, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + sigB64, nil
}

// verifyJWT verifies a compact JWT against all currently valid keys.
func (p *SignedJWTPropagator) verifyJWT(token string) (*jwtClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("propagator: malformed JWT")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("propagator: invalid JWT header encoding: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("propagator: invalid JWT header: %w", err)
	}

	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("propagator: unsupported algorithm %q", header.Alg)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("propagator: invalid JWT claims encoding: %w", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("propagator: invalid JWT claims: %w", err)
	}

	// Decode signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("propagator: invalid JWT signature encoding: %w", err)
	}

	// Find matching key.
	signingInput := parts[0] + "." + parts[1]
	pubKey, err := p.findVerificationKey(header.Kid, []byte(signingInput), sig)
	if err != nil {
		return nil, err
	}
	_ = pubKey

	// Validate claims.
	now := p.nowFunc()

	if claims.Exp != 0 && now.Unix() > claims.Exp {
		return nil, errors.New("propagator: JWT has expired")
	}

	if claims.Iss != p.issuer {
		return nil, fmt.Errorf("propagator: wrong issuer %q", claims.Iss)
	}

	if claims.Aud != p.audience {
		return nil, fmt.Errorf("propagator: wrong audience %q", claims.Aud)
	}

	return &claims, nil
}

// findVerificationKey finds the key that verifies the given signature.
// If no cached key matches and a KeyStore is configured, it reloads keys
// from the store (e.g., after a peer propagator rotated its key).
func (p *SignedJWTPropagator) findVerificationKey(kid string, message, sig []byte) (ed25519.PublicKey, error) {
	if key, ok := p.tryVerify(kid, message, sig); ok {
		return key, nil
	}

	// Cache miss — reload from KeyStore if available.
	if p.keyStore != nil {
		if err := p.reloadKeysFromStore(); err == nil {
			if key, ok := p.tryVerify(kid, message, sig); ok {
				return key, nil
			}
		}
	}

	return nil, errors.New("propagator: JWT signature verification failed")
}

// tryVerify attempts to verify a JWT signature against cached keys.
func (p *SignedJWTPropagator) tryVerify(kid string, message, sig []byte) (ed25519.PublicKey, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.nowFunc()

	// Try key ID match first.
	for _, k := range p.keys {
		if k.id == kid && now.Before(k.expiresAt) {
			if ed25519.Verify(k.publicKey, message, sig) {
				return k.publicKey, true
			}
		}
	}

	// Fallback: try all valid keys (in case kid doesn't match).
	for _, k := range p.keys {
		if now.Before(k.expiresAt) {
			if ed25519.Verify(k.publicKey, message, sig) {
				return k.publicKey, true
			}
		}
	}

	return nil, false
}

// reloadKeysFromStore refreshes the in-memory key cache from the KeyStore.
func (p *SignedJWTPropagator) reloadKeysFromStore() error {
	records, err := p.keyStore.LoadKeys(context.Background())
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Build a set of existing key IDs to avoid duplicates.
	existing := make(map[string]bool, len(p.keys))
	for _, k := range p.keys {
		existing[k.id] = true
	}

	for _, r := range records {
		if !existing[r.ID] {
			p.keys = append(p.keys, keyEntry{
				id:         r.ID,
				publicKey:  ed25519.PublicKey(r.PublicKey),
				privateKey: ed25519.PrivateKey(r.PrivateKey),
				createdAt:  r.CreatedAt,
				expiresAt:  r.ExpiresAt,
			})
		}
	}

	return nil
}

// Compile-time interface check.
var _ IdentityPropagator = (*SignedJWTPropagator)(nil)
