// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package propagator — jwks.go provides the JWKS endpoint handler.
//
// JWKSHandler exposes Ed25519 public verification keys as a standard
// JSON Web Key Set (RFC 7517), allowing downstream consumers and
// service meshes to verify propagation JWTs.
package propagator

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// JWKSHandler returns an http.Handler that serves the JWKS (JSON Web Key Set)
// containing all currently valid public keys.
func (p *SignedJWTPropagator) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		defer p.mu.RUnlock()

		jwks := jwksDoc{Keys: make([]jwkEntry, 0, len(p.keys))}
		now := p.nowFunc()

		for _, k := range p.keys {
			if now.Before(k.expiresAt) {
				jwks.Keys = append(jwks.Keys, jwkEntry{
					Kty: "OKP",
					Crv: "Ed25519",
					Kid: k.id,
					X:   base64.RawURLEncoding.EncodeToString(k.publicKey),
					Use: "sig",
					Alg: "EdDSA",
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
}

// ---------------------------------------------------------------
// JWKS types (RFC 7517)
// ---------------------------------------------------------------

type jwksDoc struct {
	Keys []jwkEntry `json:"keys"`
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}
