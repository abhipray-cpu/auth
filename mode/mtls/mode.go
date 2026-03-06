// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package mtls implements mutual TLS and SPIFFE SVID authentication.
//
// This mode verifies X.509 client certificates presented via mTLS
// and extracts workload identity from the certificate's Subject CN
// or SPIFFE ID in the SAN URI extension.
//
// It produces an Identity with WorkloadID and TrustDomain fields populated.
// For callers that only need the machine identity, AuthenticateWorkload
// returns a WorkloadIdentity directly.
//
// Security features:
//   - Certificate chain validation against configured trust anchors
//   - Expiry checking
//   - SPIFFE ID parsing with trust domain extraction
//   - CN extraction as fallback workload identifier
//   - No client cert → clear error
package mtls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/abhipray-cpu/auth"
)

// Config configures the mTLS authentication mode.
type Config struct {
	// TrustAnchors is the pool of trusted CA certificates used to verify
	// client certificates. Required.
	TrustAnchors *x509.CertPool
}

// Mode implements auth.AuthMode for mTLS/SPIFFE authentication.
type Mode struct {
	trustAnchors *x509.CertPool
}

// NewMode creates a new mTLS authentication mode.
// Returns an error if TrustAnchors is nil.
func NewMode(cfg Config) (*Mode, error) {
	if cfg.TrustAnchors == nil {
		return nil, errors.New("auth/mtls: TrustAnchors is required")
	}
	return &Mode{
		trustAnchors: cfg.TrustAnchors,
	}, nil
}

// Name returns the mode identifier.
func (m *Mode) Name() string { return "mtls" }

// Supports returns true for CredentialTypeMTLS and CredentialTypeSPIFFE.
func (m *Mode) Supports(ct auth.CredentialType) bool {
	return ct == auth.CredentialTypeMTLS || ct == auth.CredentialTypeSPIFFE
}

// Authenticate verifies a client certificate and returns an Identity
// with WorkloadID and TrustDomain populated.
//
// The credential's Metadata must contain a "peer_certificates" key with
// a value of type []*x509.Certificate (the TLS peer certificate chain).
//
// For mTLS: WorkloadID is the Subject CN.
// For SPIFFE: WorkloadID is the SPIFFE ID from the SAN URI, and
// TrustDomain is extracted from the SPIFFE ID.
func (m *Mode) Authenticate(ctx context.Context, cred auth.Credential) (*auth.Identity, error) {
	peerCerts, err := extractPeerCerts(cred)
	if err != nil {
		return nil, err
	}

	leaf := peerCerts[0]

	// Verify the certificate chain against trust anchors.
	if err := m.verifyCertChain(leaf, peerCerts[1:]); err != nil {
		return nil, err
	}

	// Extract workload identity.
	workloadID, trustDomain, authMethod := m.extractIdentity(leaf, cred.Type)

	identity := &auth.Identity{
		SubjectID:   "", // Machine identity — no user subject.
		AuthMethod:  authMethod,
		AuthTime:    time.Now(),
		WorkloadID:  workloadID,
		TrustDomain: trustDomain,
		Metadata:    make(map[string]any),
	}

	// Include SANs in metadata for downstream inspection.
	if sans := extractAllSANs(leaf); len(sans) > 0 {
		identity.Metadata["sans"] = sans
	}

	// Include CN in metadata.
	if leaf.Subject.CommonName != "" {
		identity.Metadata["cn"] = leaf.Subject.CommonName
	}

	return identity, nil
}

// AuthenticateWorkload verifies a client certificate and returns a
// WorkloadIdentity. This is a convenience for callers that only need
// the machine identity (not the full Identity struct).
func (m *Mode) AuthenticateWorkload(ctx context.Context, cred auth.Credential) (*auth.WorkloadIdentity, error) {
	identity, err := m.Authenticate(ctx, cred)
	if err != nil {
		return nil, err
	}

	return &auth.WorkloadIdentity{
		WorkloadID:  identity.WorkloadID,
		TrustDomain: identity.TrustDomain,
		Metadata:    identity.Metadata,
	}, nil
}

// verifyCertChain validates the leaf certificate against the configured
// trust anchors and any intermediate certificates.
func (m *Mode) verifyCertChain(leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	// Check expiry explicitly for a clearer error message.
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("auth/mtls: certificate not yet valid (notBefore: %s)", leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("auth/mtls: certificate has expired (notAfter: %s)", leaf.NotAfter.Format(time.RFC3339))
	}

	// Build intermediate pool.
	intermediatePool := x509.NewCertPool()
	for _, cert := range intermediates {
		intermediatePool.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         m.trustAnchors,
		Intermediates: intermediatePool,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("auth/mtls: certificate verification failed: %w", err)
	}

	return nil
}

// extractIdentity determines the workload ID and trust domain from the
// certificate. For SPIFFE credentials, it extracts the SPIFFE ID from
// the SAN URI. For mTLS, it uses the Subject CN.
func (m *Mode) extractIdentity(leaf *x509.Certificate, credType auth.CredentialType) (workloadID, trustDomain, authMethod string) {
	// Try SPIFFE ID extraction first for SPIFFE credential type.
	if credType == auth.CredentialTypeSPIFFE {
		if spiffeID, td, ok := extractSPIFFEID(leaf); ok {
			return spiffeID, td, "spiffe"
		}
	}

	// For mTLS or when no SPIFFE ID is found, use CN.
	cn := leaf.Subject.CommonName
	if cn == "" {
		cn = "unknown"
	}

	// Try to extract trust domain from SPIFFE SAN even for mTLS creds.
	if _, td, ok := extractSPIFFEID(leaf); ok {
		return cn, td, "mtls"
	}

	return cn, "", "mtls"
}

// extractPeerCerts extracts and validates the peer certificate chain
// from the credential metadata.
func extractPeerCerts(cred auth.Credential) ([]*x509.Certificate, error) {
	if cred.Metadata == nil {
		return nil, errors.New("auth/mtls: no client certificate presented")
	}

	certsRaw, ok := cred.Metadata["peer_certificates"]
	if !ok {
		return nil, errors.New("auth/mtls: no client certificate presented")
	}

	certs, ok := certsRaw.([]*x509.Certificate)
	if !ok {
		return nil, errors.New("auth/mtls: invalid peer certificate type")
	}

	if len(certs) == 0 {
		return nil, errors.New("auth/mtls: empty peer certificate chain")
	}

	return certs, nil
}

// extractAllSANs collects all Subject Alternative Names from a certificate.
func extractAllSANs(cert *x509.Certificate) []string {
	var sans []string

	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, "Email:"+email)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, "URI:"+uri.String())
	}

	return sans
}

// Compile-time interface check.
var _ auth.AuthMode = (*Mode)(nil)
