// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// IDTokenClaims represents the claims in an OIDC id_token.
type IDTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  Audience `json:"aud"`
	Nonce     string   `json:"nonce"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
}

// Audience handles the "aud" claim which can be a string or array.
type Audience []string

// UnmarshalJSON handles both string and []string for the aud claim.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = Audience(arr)
	return nil
}

// Contains checks if the audience includes the given value.
func (a Audience) Contains(clientID string) bool {
	for _, v := range a {
		if v == clientID {
			return true
		}
	}
	return false
}

// IDTokenHeader represents the JWT header.
type IDTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// VerifyIDToken verifies an id_token's signature and claims.
// Returns the parsed claims on success.
func VerifyIDToken(rawToken string, publicKey interface{}, expectedIssuer, expectedClientID, expectedNonce string) (*IDTokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth/oauth: invalid JWT format")
	}

	// Parse header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode JWT header: %w", err)
	}

	var header IDTokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to parse JWT header: %w", err)
	}

	// Reject "none" algorithm — alg=none is a well-known JWT attack vector.
	if strings.EqualFold(header.Alg, "none") {
		return nil, errors.New("auth/oauth: algorithm \"none\" is not allowed")
	}

	// Verify signature.
	signingInput := parts[0] + "." + parts[1]
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode JWT signature: %w", err)
	}

	if err := verifySignature(header.Alg, signingInput, signatureBytes, publicKey); err != nil {
		return nil, fmt.Errorf("auth/oauth: signature verification failed: %w", err)
	}

	// Parse claims.
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode JWT claims: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to parse JWT claims: %w", err)
	}

	// Verify issuer.
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("auth/oauth: issuer mismatch: expected %q, got %q", expectedIssuer, claims.Issuer)
	}

	// Verify audience.
	if !claims.Audience.Contains(expectedClientID) {
		return nil, fmt.Errorf("auth/oauth: audience mismatch: expected %q", expectedClientID)
	}

	// Verify nonce.
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("auth/oauth: nonce mismatch")
	}

	now := time.Now()

	// Verify expiry with clock skew tolerance.
	const clockSkew = 1 * time.Minute
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(clockSkew)) {
		return nil, errors.New("auth/oauth: id_token has expired")
	}

	// Verify issued-at — reject tokens issued far in the future.
	if claims.IssuedAt > 0 && time.Unix(claims.IssuedAt, 0).After(now.Add(clockSkew)) {
		return nil, errors.New("auth/oauth: id_token issued in the future")
	}

	return &claims, nil
}

// ParseIDTokenHeader extracts the header from a raw JWT without verifying.
func ParseIDTokenHeader(rawToken string) (*IDTokenHeader, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth/oauth: invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to decode JWT header: %w", err)
	}

	var header IDTokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("auth/oauth: failed to parse JWT header: %w", err)
	}

	return &header, nil
}

func verifySignature(alg string, signingInput string, signature []byte, publicKey interface{}) error {
	switch alg {
	case "RS256":
		return verifyRSA(crypto.SHA256, signingInput, signature, publicKey)
	case "RS384":
		return verifyRSA(crypto.SHA384, signingInput, signature, publicKey)
	case "RS512":
		return verifyRSA(crypto.SHA512, signingInput, signature, publicKey)
	case "ES256":
		return verifyEC(sha256.New, 32, signingInput, signature, publicKey)
	case "ES384":
		return verifyEC(sha512.New384, 48, signingInput, signature, publicKey)
	case "ES512":
		return verifyEC(sha512.New, 66, signingInput, signature, publicKey)
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}
}

func verifyRSA(hash crypto.Hash, signingInput string, signature []byte, publicKey interface{}) error {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("expected RSA public key")
	}

	h := hash.New()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, hash, digest, signature)
}

func verifyEC(hashFn func() hash.Hash, keySize int, signingInput string, signature []byte, publicKey interface{}) error {
	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("expected ECDSA public key")
	}

	h := hashFn()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	// ECDSA signature in JWS is R || S, each padded to key size.
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature length: expected %d, got %d", 2*keySize, len(signature))
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(ecKey, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}

// CreateTestJWT creates a signed JWT for testing. NOT for production use.
func CreateTestJWT(header IDTokenHeader, claims IDTokenClaims, signer func(input string) ([]byte, error)) (string, error) {
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

	sig, err := signer(signingInput)
	if err != nil {
		return "", err
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}
