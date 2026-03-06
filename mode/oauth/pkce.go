// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCEChallenge holds a PKCE verifier and its derived challenge.
type PKCEChallenge struct {
	// Verifier is the random string (43–128 chars, unreserved characters).
	Verifier string

	// Challenge is the S256 hash of the verifier.
	Challenge string

	// Method is always "S256".
	Method string
}

// GeneratePKCE generates a new PKCE verifier and S256 challenge per RFC 7636.
// The verifier is 43 characters of base64url-encoded random bytes (32 bytes of entropy).
func GeneratePKCE() (*PKCEChallenge, error) {
	// 32 bytes of entropy → 43 base64url chars (no padding).
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	verifier := base64.RawURLEncoding.EncodeToString(b)
	challenge := computeS256Challenge(verifier)

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

// computeS256Challenge computes the S256 PKCE challenge:
// BASE64URL(SHA256(verifier))
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
