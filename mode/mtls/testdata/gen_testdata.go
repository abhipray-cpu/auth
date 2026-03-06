// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command gen_testdata generates X.509 test certificates for the mTLS mode tests.package testdata

// Usage: go run gen_testdata.go
//
// Output files:
//
//	ca.pem          — Self-signed root CA certificate
//	ca-key.pem      — Root CA private key
//	client.pem      — Valid client cert signed by CA (CN=test-service, SPIFFE SAN)
//	client-key.pem  — Client private key
//	expired.pem     — Expired client cert signed by CA
//	expired-key.pem — Expired client private key
//	untrusted-ca.pem     — Untrusted CA certificate
//	untrusted-ca-key.pem — Untrusted CA private key
//	untrusted.pem        — Client cert signed by untrusted CA
//	untrusted-key.pem    — Untrusted client private key
package main

import (
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
	"time"
)

func main() {
	// --- Root CA ---
	caKey := genKey()
	caCert := selfSign(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, caKey)
	writePEM("ca.pem", "CERTIFICATE", caCert)
	writeKey("ca-key.pem", caKey)

	// --- Valid client cert with SPIFFE SAN ---
	clientKey := genKey()
	spiffeURI, _ := url.Parse("spiffe://example.com/svc/test-service")
	clientCert := issueCert(caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-service"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"test-service.local"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1")},
		URIs:         []*url.URL{spiffeURI},
	}, clientKey)
	writePEM("client.pem", "CERTIFICATE", clientCert)
	writeKey("client-key.pem", clientKey)

	// --- Expired client cert ---
	expiredKey := genKey()
	expiredCert := issueCert(caCert, caKey, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "expired-service"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, expiredKey)
	writePEM("expired.pem", "CERTIFICATE", expiredCert)
	writeKey("expired-key.pem", expiredKey)

	// --- Untrusted CA ---
	untrustedCAKey := genKey()
	untrustedCACert := selfSign(&x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Untrusted CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, untrustedCAKey)
	writePEM("untrusted-ca.pem", "CERTIFICATE", untrustedCACert)
	writeKey("untrusted-ca-key.pem", untrustedCAKey)

	// --- Client cert signed by untrusted CA ---
	untrustedKey := genKey()
	untrustedCert := issueCert(untrustedCACert, untrustedCAKey, &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "rogue-service"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, untrustedKey)
	writePEM("untrusted.pem", "CERTIFICATE", untrustedCert)
	writeKey("untrusted-key.pem", untrustedKey)
}

func genKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

func selfSign(tmpl *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return der
}

func issueCert(caCertDER []byte, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate, subjectKey *ecdsa.PrivateKey) []byte {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		panic(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &subjectKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	return der
}

func writePEM(filename, blockType string, der []byte) {
	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		panic(err)
	}
}

func writeKey(filename string, key *ecdsa.PrivateKey) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	writePEM(filename, "EC PRIVATE KEY", der)
}
