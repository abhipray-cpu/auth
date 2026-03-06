// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package mtls — spiffe.go provides SPIFFE SVID parsing and trust domain extraction.
//
// This file handles the SPIFFE-specific parts of mTLS authentication:
//   - Extracting SPIFFE IDs from X.509 SAN URI extensions
//   - Trust domain parsing from SPIFFE IDs
//   - SVID validation (certificate chain = the SVID verification)
//
// SPIFFE SVID verification is done via the standard X.509 certificate
// chain verification in mode.go. A SVID is a certificate issued by a
// SPIRE CA. Verifying the cert chain against the SPIRE CA's trust bundle
// (configured as TrustAnchors) IS the SVID verification per the SPIFFE spec.
package mtls

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// extractSPIFFEID extracts the SPIFFE ID and trust domain from the
// certificate's SAN URI extension.
//
// A SPIFFE ID has the format: spiffe://<trust-domain>/<workload-path>
func extractSPIFFEID(cert *x509.Certificate) (spiffeID, trustDomain string, ok bool) {
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			trustDomain = uri.Host
			return uri.String(), trustDomain, true
		}
	}
	return "", "", false
}

// ParseSPIFFEID parses a raw SPIFFE ID string and returns the trust domain
// and workload path. Returns an error if the format is invalid.
//
// Format: spiffe://<trust-domain>/<workload-path>
func ParseSPIFFEID(rawID string) (trustDomain, workloadPath string, err error) {
	u, err := url.Parse(rawID)
	if err != nil {
		return "", "", fmt.Errorf("auth/mtls: invalid SPIFFE ID: %w", err)
	}

	if u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("auth/mtls: not a SPIFFE ID (scheme=%q)", u.Scheme)
	}

	if u.Host == "" {
		return "", "", errors.New("auth/mtls: SPIFFE ID missing trust domain")
	}

	path := strings.TrimPrefix(u.Path, "/")
	return u.Host, path, nil
}
