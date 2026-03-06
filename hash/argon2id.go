// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package hash provides password hashing implementations.
//
// The default implementation is Argon2id, the winner of the Password Hashing
// Competition and recommended by OWASP. Teams can override with a custom
// Hasher implementation for legacy password schemes.
package hash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams configures the Argon2id hashing parameters.
type Argon2idParams struct {
	// Time is the number of iterations (passes over the memory).
	Time uint32

	// Memory is the amount of memory in KiB (1024 = 1 MiB).
	Memory uint32

	// Parallelism is the number of threads.
	Parallelism uint8

	// SaltLength is the length of the random salt in bytes.
	SaltLength uint32

	// KeyLength is the length of the derived key in bytes.
	KeyLength uint32
}

// DefaultParams returns the default Argon2id parameters.
// time=1, memory=64MiB (65536 KiB), parallelism=4, salt=16, key=32.
func DefaultParams() Argon2idParams {
	return Argon2idParams{
		Time:        1,
		Memory:      64 * 1024, // 64 MiB
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Argon2idHasher implements the Hasher interface using the Argon2id algorithm.
type Argon2idHasher struct {
	params Argon2idParams
}

// NewArgon2idHasher creates a new Argon2idHasher with the given parameters.
// If params is nil or zero-value, DefaultParams() is used.
func NewArgon2idHasher(params *Argon2idParams) *Argon2idHasher {
	p := DefaultParams()
	if params != nil {
		if params.Time > 0 {
			p.Time = params.Time
		}
		if params.Memory > 0 {
			p.Memory = params.Memory
		}
		if params.Parallelism > 0 {
			p.Parallelism = params.Parallelism
		}
		if params.SaltLength > 0 {
			p.SaltLength = params.SaltLength
		}
		if params.KeyLength > 0 {
			p.KeyLength = params.KeyLength
		}
	}
	return &Argon2idHasher{params: p}
}

// Hash takes a plain-text password and returns a PHC-format hash string.
// Format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<key>
// Each call produces a different hash due to a random salt.
func (h *Argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth/hash: failed to generate salt: %w", err)
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		h.params.Time,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	hash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.Memory,
		h.params.Time,
		h.params.Parallelism,
		b64Salt,
		b64Key,
	)

	return hash, nil
}

// Verify checks a plain-text password against a PHC-format hash string.
// Uses constant-time comparison to prevent timing attacks.
func (h *Argon2idHasher) Verify(password string, encodedHash string) (bool, error) {
	params, salt, key, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherKey := argon2.IDKey(
		[]byte(password),
		salt,
		params.Time,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Constant-time comparison
	return subtle.ConstantTimeCompare(key, otherKey) == 1, nil
}

// decodeHash parses a PHC-format Argon2id hash string.
func decodeHash(encodedHash string) (params Argon2idParams, salt, key []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return params, nil, nil, errors.New("auth/hash: invalid hash format")
	}

	if parts[1] != "argon2id" {
		return params, nil, nil, fmt.Errorf("auth/hash: unsupported algorithm: %s", parts[1])
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return params, nil, nil, fmt.Errorf("auth/hash: failed to parse version: %w", err)
	}
	if version != argon2.Version {
		return params, nil, nil, fmt.Errorf("auth/hash: unsupported version: %d", version)
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Time, &params.Parallelism)
	if err != nil {
		return params, nil, nil, fmt.Errorf("auth/hash: failed to parse parameters: %w", err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return params, nil, nil, fmt.Errorf("auth/hash: failed to decode salt: %w", err)
	}
	params.SaltLength = uint32(len(salt))

	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, fmt.Errorf("auth/hash: failed to decode key: %w", err)
	}
	params.KeyLength = uint32(len(key))

	return params, salt, key, nil
}
