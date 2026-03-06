// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const rawIDLength = 32 // 256 bits of entropy

// GenerateID produces a cryptographically random session ID (hex-encoded).
// The raw ID is placed in the cookie; the hashed version is stored in the
// session store.
func GenerateID() (string, error) {
	b := make([]byte, rawIDLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth/session: failed to generate session ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashID returns the SHA-256 hex digest of the raw session ID.
// This is what gets stored in the session store — never the raw ID.
func HashID(rawID string) string {
	h := sha256.Sum256([]byte(rawID))
	return hex.EncodeToString(h[:])
}
