// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package mtls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/abhipray-cpu/auth"
	"github.com/abhipray-cpu/auth/mode/mtls"
)

// ---------------------------------------------------------------
// helpers: build test CA + leaf certs
// ---------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return testCA{cert: cert, key: key, pool: pool}
}

type leafOpts struct {
	cn        string
	spiffeID  string   // e.g. "spiffe://example.com/svc/api"
	dnsNames  []string // additional DNS SANs
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
	extUsage  []x509.ExtKeyUsage
}

func (ca testCA) issueLeaf(t *testing.T, opts leafOpts) []*x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(24 * time.Hour)
	}
	if opts.extUsage == nil {
		opts.extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: opts.cn},
		NotBefore:    opts.notBefore,
		NotAfter:     opts.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  opts.extUsage,
		DNSNames:     opts.dnsNames,
		IPAddresses:  opts.ips,
	}

	if opts.spiffeID != "" {
		u, err := url.Parse(opts.spiffeID)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// Return chain: [leaf, ca]
	return []*x509.Certificate{leaf, ca.cert}
}

// ---------------------------------------------------------------
// 1. NewMode validation
// ---------------------------------------------------------------

func TestNewMode_NilTrustAnchors(t *testing.T) {
	_, err := mtls.NewMode(mtls.Config{TrustAnchors: nil})
	if err == nil {
		t.Fatal("expected error for nil TrustAnchors")
	}
}

func TestNewMode_Valid(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, err := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil mode")
	}
}

// ---------------------------------------------------------------
// 2. Name and Supports
// ---------------------------------------------------------------

func TestMode_Name(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})
	if m.Name() != "mtls" {
		t.Fatalf("expected name %q, got %q", "mtls", m.Name())
	}
}

func TestMode_Supports(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	tests := []struct {
		ct   auth.CredentialType
		want bool
	}{
		{auth.CredentialTypeMTLS, true},
		{auth.CredentialTypeSPIFFE, true},
		{auth.CredentialTypePassword, false},
		{auth.CredentialTypeAPIKey, false},
		{auth.CredentialType("unknown"), false},
	}

	for _, tt := range tests {
		got := m.Supports(tt.ct)
		if got != tt.want {
			t.Errorf("Supports(%q) = %v, want %v", tt.ct, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------
// 3. Valid peer cert → Identity with WorkloadID (mTLS)
// ---------------------------------------------------------------

func TestAuthenticate_ValidMTLS(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{cn: "my-service"})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id.WorkloadID != "my-service" {
		t.Errorf("WorkloadID = %q, want %q", id.WorkloadID, "my-service")
	}
	if id.AuthMethod != "mtls" {
		t.Errorf("AuthMethod = %q, want %q", id.AuthMethod, "mtls")
	}
	if id.Metadata["cn"] != "my-service" {
		t.Errorf("Metadata[cn] = %q, want %q", id.Metadata["cn"], "my-service")
	}
}

// ---------------------------------------------------------------
// 4. Valid peer cert + SPIFFE SAN → Identity with SPIFFE ID
// ---------------------------------------------------------------

func TestAuthenticate_ValidSPIFFE(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{
		cn:       "api-server",
		spiffeID: "spiffe://example.com/svc/api",
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id.WorkloadID != "spiffe://example.com/svc/api" {
		t.Errorf("WorkloadID = %q, want SPIFFE ID", id.WorkloadID)
	}
	if id.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, "example.com")
	}
	if id.AuthMethod != "spiffe" {
		t.Errorf("AuthMethod = %q, want %q", id.AuthMethod, "spiffe")
	}
}

// ---------------------------------------------------------------
// 5. Expired cert → error
// ---------------------------------------------------------------

func TestAuthenticate_ExpiredCert(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{
		cn:        "old-service",
		notBefore: time.Now().Add(-48 * time.Hour),
		notAfter:  time.Now().Add(-1 * time.Hour),
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	_, err := m.Authenticate(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error for expired cert")
	}
	if got := err.Error(); !contains(got, "expired") {
		t.Errorf("error = %q, want 'expired'", got)
	}
}

// ---------------------------------------------------------------
// 6. Not-yet-valid cert → error
// ---------------------------------------------------------------

func TestAuthenticate_NotYetValidCert(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{
		cn:        "future-service",
		notBefore: time.Now().Add(24 * time.Hour),
		notAfter:  time.Now().Add(48 * time.Hour),
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	_, err := m.Authenticate(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error for not-yet-valid cert")
	}
	if got := err.Error(); !contains(got, "not yet valid") {
		t.Errorf("error = %q, want 'not yet valid'", got)
	}
}

// ---------------------------------------------------------------
// 7. Untrusted CA → error
// ---------------------------------------------------------------

func TestAuthenticate_UntrustedCA(t *testing.T) {
	trustedCA := newTestCA(t, "Trusted CA")
	untrustedCA := newTestCA(t, "Untrusted CA")

	// Mode trusts only trustedCA, but cert is from untrustedCA.
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: trustedCA.pool})

	chain := untrustedCA.issueLeaf(t, leafOpts{cn: "rogue-service"})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	_, err := m.Authenticate(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error for untrusted CA")
	}
	if got := err.Error(); !contains(got, "verification failed") {
		t.Errorf("error = %q, want 'verification failed'", got)
	}
}

// ---------------------------------------------------------------
// 8. No client cert → error
// ---------------------------------------------------------------

func TestAuthenticate_NoPeerCerts(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	tests := []struct {
		name string
		cred auth.Credential
	}{
		{
			name: "nil metadata",
			cred: auth.Credential{Type: auth.CredentialTypeMTLS},
		},
		{
			name: "missing key",
			cred: auth.Credential{
				Type:     auth.CredentialTypeMTLS,
				Metadata: map[string]any{},
			},
		},
		{
			name: "wrong type",
			cred: auth.Credential{
				Type:     auth.CredentialTypeMTLS,
				Metadata: map[string]any{"peer_certificates": "not certs"},
			},
		},
		{
			name: "empty chain",
			cred: auth.Credential{
				Type:     auth.CredentialTypeMTLS,
				Metadata: map[string]any{"peer_certificates": []*x509.Certificate{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Authenticate(context.Background(), tt.cred)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// ---------------------------------------------------------------
// 9. Subject CN extracted as workload ID
// ---------------------------------------------------------------

func TestAuthenticate_CNExtraction(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// CN with special characters.
	chain := ca.issueLeaf(t, leafOpts{cn: "payment-service.prod.internal"})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id.WorkloadID != "payment-service.prod.internal" {
		t.Errorf("WorkloadID = %q, want %q", id.WorkloadID, "payment-service.prod.internal")
	}
}

// ---------------------------------------------------------------
// 10. SPIFFE ID extracted from SAN URI
// ---------------------------------------------------------------

func TestAuthenticate_SPIFFEIDFromSAN(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{
		cn:       "svc",
		spiffeID: "spiffe://prod.example.com/ns/default/sa/frontend",
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id.WorkloadID != "spiffe://prod.example.com/ns/default/sa/frontend" {
		t.Errorf("WorkloadID = %q, want SPIFFE ID", id.WorkloadID)
	}
	if id.TrustDomain != "prod.example.com" {
		t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, "prod.example.com")
	}
}

// ---------------------------------------------------------------
// 11. Trust domain extracted from SPIFFE ID
// ---------------------------------------------------------------

func TestAuthenticate_TrustDomainExtraction(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	tests := []struct {
		spiffeID   string
		wantDomain string
	}{
		{"spiffe://example.com/svc/a", "example.com"},
		{"spiffe://staging.internal/ns/default", "staging.internal"},
		{"spiffe://corp.example.org/workload/db", "corp.example.org"},
	}

	for _, tt := range tests {
		t.Run(tt.wantDomain, func(t *testing.T) {
			chain := ca.issueLeaf(t, leafOpts{cn: "svc", spiffeID: tt.spiffeID})
			cred := auth.Credential{
				Type: auth.CredentialTypeSPIFFE,
				Metadata: map[string]any{
					"peer_certificates": chain,
				},
			}

			id, err := m.Authenticate(context.Background(), cred)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if id.TrustDomain != tt.wantDomain {
				t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, tt.wantDomain)
			}
		})
	}
}

// ---------------------------------------------------------------
// 12. Multiple SANs handled
// ---------------------------------------------------------------

func TestAuthenticate_MultipleSANs(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{
		cn:       "multi-san-svc",
		spiffeID: "spiffe://example.com/svc/multi",
		dnsNames: []string{"svc.local", "svc.example.com"},
		ips:      []net.IP{net.ParseIP("10.0.0.1")},
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sans, ok := id.Metadata["sans"].([]string)
	if !ok {
		t.Fatal("expected sans in metadata")
	}

	// Should contain DNS, IP, and URI SANs.
	wantPrefixes := []string{"DNS:", "IP:", "URI:"}
	for _, prefix := range wantPrefixes {
		found := false
		for _, san := range sans {
			if len(san) > len(prefix) && san[:len(prefix)] == prefix {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected SAN with prefix %q in %v", prefix, sans)
		}
	}
}

// ---------------------------------------------------------------
// 13. AuthenticateWorkload returns WorkloadIdentity
// ---------------------------------------------------------------

func TestAuthenticateWorkload(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	chain := ca.issueLeaf(t, leafOpts{
		cn:       "workload-svc",
		spiffeID: "spiffe://example.com/svc/worker",
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	wi, err := m.AuthenticateWorkload(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wi.WorkloadID != "spiffe://example.com/svc/worker" {
		t.Errorf("WorkloadID = %q, want SPIFFE ID", wi.WorkloadID)
	}
	if wi.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want %q", wi.TrustDomain, "example.com")
	}
	if wi.Metadata == nil {
		t.Fatal("expected non-nil Metadata")
	}
}

// ---------------------------------------------------------------
// 14. Trust anchors configurable — different CAs
// ---------------------------------------------------------------

func TestAuthenticate_TrustAnchorsConfigurable(t *testing.T) {
	ca1 := newTestCA(t, "CA One")
	ca2 := newTestCA(t, "CA Two")

	// Mode trusts only CA1.
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca1.pool})

	// Cert from CA1 — should succeed.
	chain1 := ca1.issueLeaf(t, leafOpts{cn: "svc-1"})
	cred1 := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain1,
		},
	}

	if _, err := m.Authenticate(context.Background(), cred1); err != nil {
		t.Fatalf("CA1 cert should pass: %v", err)
	}

	// Cert from CA2 — should fail.
	chain2 := ca2.issueLeaf(t, leafOpts{cn: "svc-2"})
	cred2 := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain2,
		},
	}

	if _, err := m.Authenticate(context.Background(), cred2); err == nil {
		t.Fatal("CA2 cert should fail with CA1-only trust anchors")
	}

	// Now trust both CAs.
	bothPool := x509.NewCertPool()
	bothPool.AddCert(ca1.cert)
	bothPool.AddCert(ca2.cert)

	m2, _ := mtls.NewMode(mtls.Config{TrustAnchors: bothPool})

	if _, err := m2.Authenticate(context.Background(), cred2); err != nil {
		t.Fatalf("CA2 cert should pass with both-CA trust: %v", err)
	}
}

// ---------------------------------------------------------------
// 15. ParseSPIFFEID helper
// ---------------------------------------------------------------

func TestParseSPIFFEID(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantDomain string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "valid",
			raw:        "spiffe://example.com/svc/api",
			wantDomain: "example.com",
			wantPath:   "svc/api",
		},
		{
			name:       "valid with nested path",
			raw:        "spiffe://prod.example.com/ns/default/sa/frontend",
			wantDomain: "prod.example.com",
			wantPath:   "ns/default/sa/frontend",
		},
		{
			name:    "wrong scheme",
			raw:     "https://example.com/svc",
			wantErr: true,
		},
		{
			name:    "missing trust domain",
			raw:     "spiffe:///svc/api",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, path, err := mtls.ParseSPIFFEID(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", domain, tt.wantDomain)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
		})
	}
}

// ---------------------------------------------------------------
// 16. SPIFFE type falls back to CN when no SPIFFE SAN
// ---------------------------------------------------------------

func TestAuthenticate_SPIFFEFallbackToCN(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// SPIFFE credential type but cert has no SPIFFE SAN URI.
	chain := ca.issueLeaf(t, leafOpts{cn: "legacy-svc"})

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fall back to CN.
	if id.WorkloadID != "legacy-svc" {
		t.Errorf("WorkloadID = %q, want %q", id.WorkloadID, "legacy-svc")
	}
	if id.AuthMethod != "mtls" {
		t.Errorf("AuthMethod = %q, want %q (fallback)", id.AuthMethod, "mtls")
	}
}

// ---------------------------------------------------------------
// 17. mTLS type still gets trust domain if SPIFFE SAN present
// ---------------------------------------------------------------

func TestAuthenticate_MTLSWithSPIFFESAN(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// mTLS credential type, but cert has a SPIFFE SAN.
	chain := ca.issueLeaf(t, leafOpts{
		cn:       "hybrid-svc",
		spiffeID: "spiffe://example.com/svc/hybrid",
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// mTLS type → CN as workload ID, but trust domain extracted.
	if id.WorkloadID != "hybrid-svc" {
		t.Errorf("WorkloadID = %q, want %q", id.WorkloadID, "hybrid-svc")
	}
	if id.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want %q", id.TrustDomain, "example.com")
	}
	if id.AuthMethod != "mtls" {
		t.Errorf("AuthMethod = %q, want %q", id.AuthMethod, "mtls")
	}
}

// ---------------------------------------------------------------
// 18. Compile-time interface check already in mode.go
// ---------------------------------------------------------------

func TestInterfaceCompliance(t *testing.T) {
	// Verify via type assertion at runtime too.
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	var _ auth.AuthMode = m // compile-time
}

// ---------------------------------------------------------------
// 19. AuthenticateWorkload error path
// ---------------------------------------------------------------

func TestAuthenticateWorkload_Error(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// No client cert → should propagate error.
	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
	}

	_, err := m.AuthenticateWorkload(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------
// 20. Empty CN fallback to "unknown"
// ---------------------------------------------------------------

func TestAuthenticate_EmptyCN(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// Issue leaf with empty CN.
	chain := ca.issueLeaf(t, leafOpts{cn: "", dnsNames: []string{"svc.local"}})

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if id.WorkloadID != "unknown" {
		t.Errorf("WorkloadID = %q, want %q", id.WorkloadID, "unknown")
	}
}

// ---------------------------------------------------------------
// 21. Email SANs in metadata
// ---------------------------------------------------------------

func TestAuthenticate_EmailSANs(t *testing.T) {
	ca := newTestCA(t, "Test CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// We need to manually create a cert with email SANs since
	// the helper doesn't support it directly.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(99),
		Subject:        pkix.Name{CommonName: "email-svc"},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: []string{"admin@example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	chain := []*x509.Certificate{leaf, ca.cert}

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sans, ok := id.Metadata["sans"].([]string)
	if !ok {
		t.Fatal("expected sans in metadata")
	}

	found := false
	for _, san := range sans {
		if san == "Email:admin@example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected Email SAN in %v", sans)
	}
}

// ---------------------------------------------------------------
// 22. ParseSPIFFEID with control chars (unparsable URL)
// ---------------------------------------------------------------

func TestParseSPIFFEID_InvalidURL(t *testing.T) {
	_, _, err := mtls.ParseSPIFFEID("spiffe://\x00invalid")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------
// 23. Testdata certs load and verify (AC: certs committed in testdata/)
// ---------------------------------------------------------------

func TestTestdataCerts_LoadAndVerify(t *testing.T) {
	// Load CA cert from testdata.
	caPEM, err := os.ReadFile("testdata/ca.pem")
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse ca.pem")
	}

	m, err := mtls.NewMode(mtls.Config{TrustAnchors: caPool})
	if err != nil {
		t.Fatal(err)
	}

	// Load valid client cert.
	clientPEM, err := os.ReadFile("testdata/client.pem")
	if err != nil {
		t.Fatalf("read client.pem: %v", err)
	}
	clientBlock, _ := pem.Decode(clientPEM)
	if clientBlock == nil {
		t.Fatal("failed to decode client.pem")
	}
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatalf("parse client.pem: %v", err)
	}

	// Also load the CA cert as a parsed cert for the chain.
	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": []*x509.Certificate{clientCert, caCert},
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("Authenticate with testdata cert: %v", err)
	}

	if id.WorkloadID != "spiffe://example.com/svc/test-service" {
		t.Errorf("WorkloadID = %q, want SPIFFE ID", id.WorkloadID)
	}
	if id.TrustDomain != "example.com" {
		t.Errorf("TrustDomain = %q, want example.com", id.TrustDomain)
	}
}

func TestTestdataCerts_ExpiredRejected(t *testing.T) {
	caPEM, err := os.ReadFile("testdata/ca.pem")
	if err != nil {
		t.Fatalf("read ca.pem: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: caPool})

	expiredPEM, err := os.ReadFile("testdata/expired.pem")
	if err != nil {
		t.Fatalf("read expired.pem: %v", err)
	}
	block, _ := pem.Decode(expiredPEM)
	expiredCert, _ := x509.ParseCertificate(block.Bytes)

	caBlock, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": []*x509.Certificate{expiredCert, caCert},
		},
	}

	_, err = m.Authenticate(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error for expired testdata cert")
	}
}

func TestTestdataCerts_UntrustedRejected(t *testing.T) {
	// Trust only the main CA.
	caPEM, _ := os.ReadFile("testdata/ca.pem")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)

	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: caPool})

	// Load cert signed by untrusted CA.
	untrustedPEM, _ := os.ReadFile("testdata/untrusted.pem")
	block, _ := pem.Decode(untrustedPEM)
	untrustedCert, _ := x509.ParseCertificate(block.Bytes)

	untrustedCAPEM, _ := os.ReadFile("testdata/untrusted-ca.pem")
	caBlock, _ := pem.Decode(untrustedCAPEM)
	untrustedCACert, _ := x509.ParseCertificate(caBlock.Bytes)

	cred := auth.Credential{
		Type: auth.CredentialTypeMTLS,
		Metadata: map[string]any{
			"peer_certificates": []*x509.Certificate{untrustedCert, untrustedCACert},
		},
	}

	_, err := m.Authenticate(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error for untrusted testdata cert")
	}
}

// ---------------------------------------------------------------
// 24. SVID verified against SPIRE trust bundle
//     (Trust anchors = SPIRE trust bundle. Cert chain verification IS SVID verification.)
// ---------------------------------------------------------------

func TestSVID_VerifiedAgainstTrustBundle(t *testing.T) {
	// The "trust bundle" is just the set of CA certs (TrustAnchors).
	// SPIFFE SVID = X.509 cert with spiffe:// SAN issued by a SPIRE CA.
	// Verifying the chain against TrustAnchors IS verifying the SVID.
	ca := newTestCA(t, "SPIRE CA")
	m, _ := mtls.NewMode(mtls.Config{TrustAnchors: ca.pool})

	// Issue a SVID (cert with SPIFFE SAN from our "SPIRE CA").
	chain := ca.issueLeaf(t, leafOpts{
		cn:       "spire-workload",
		spiffeID: "spiffe://prod.example.com/ns/default/sa/api",
	})

	cred := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": chain,
		},
	}

	id, err := m.Authenticate(context.Background(), cred)
	if err != nil {
		t.Fatalf("SVID verification against trust bundle failed: %v", err)
	}
	if id.WorkloadID != "spiffe://prod.example.com/ns/default/sa/api" {
		t.Errorf("WorkloadID = %q, want SPIFFE ID", id.WorkloadID)
	}
	if id.TrustDomain != "prod.example.com" {
		t.Errorf("TrustDomain = %q, want prod.example.com", id.TrustDomain)
	}

	// Different "SPIRE CA" (untrusted) → SVID rejected.
	otherCA := newTestCA(t, "Other SPIRE CA")
	otherChain := otherCA.issueLeaf(t, leafOpts{
		cn:       "rogue",
		spiffeID: "spiffe://evil.com/svc/rogue",
	})

	cred2 := auth.Credential{
		Type: auth.CredentialTypeSPIFFE,
		Metadata: map[string]any{
			"peer_certificates": otherChain,
		},
	}

	_, err = m.Authenticate(context.Background(), cred2)
	if err == nil {
		t.Fatal("expected error: SVID from untrusted SPIRE CA should be rejected")
	}
}

// ---------------------------------------------------------------
// helper
// ---------------------------------------------------------------

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstr(s, substr)
}

func searchSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
