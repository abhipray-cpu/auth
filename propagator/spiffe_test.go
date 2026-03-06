// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package propagator

import (
	"context"
	"errors"
	"testing"

	"github.com/abhipray-cpu/auth"
)

// ---------------------------------------------------------------
// mock WorkloadAPIClient
// ---------------------------------------------------------------

type mockWorkloadAPI struct {
	fetchSVID   string
	fetchErr    error
	validateID  string
	validateErr error
}

func (m *mockWorkloadAPI) FetchJWTSVID(_ context.Context, _ string) (string, error) {
	return m.fetchSVID, m.fetchErr
}

func (m *mockWorkloadAPI) ValidateJWTSVID(_ context.Context, _ string, _ string) (string, error) {
	return m.validateID, m.validateErr
}

// ---------------------------------------------------------------
// 1. NewSPIFFEPropagator validation
// ---------------------------------------------------------------

func TestNewSPIFFEPropagator_NilClient(t *testing.T) {
	_, err := NewSPIFFEPropagator(SPIFFEPropagatorConfig{Audience: "aud"})
	if err == nil {
		t.Fatal("expected error for nil Client")
	}
}

func TestNewSPIFFEPropagator_EmptyAudience(t *testing.T) {
	_, err := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: &mockWorkloadAPI{},
	})
	if err == nil {
		t.Fatal("expected error for empty Audience")
	}
}

func TestNewSPIFFEPropagator_Valid(t *testing.T) {
	p, err := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client:   &mockWorkloadAPI{},
		Audience: "test-aud",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil propagator")
	}
}

// ---------------------------------------------------------------
// 2. Encode requests JWT-SVID from SPIRE, puts in metadata
// ---------------------------------------------------------------

func TestSPIFFEPropagator_Encode(t *testing.T) {
	client := &mockWorkloadAPI{fetchSVID: "svid-token-123"}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client:   client,
		Audience: "backend",
	})

	id := &auth.Identity{SubjectID: "user-1"}
	meta, err := p.Encode(context.Background(), id)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if meta[headerKeySPIFFE] != "svid-token-123" {
		t.Errorf("SVID = %q, want %q", meta[headerKeySPIFFE], "svid-token-123")
	}
}

// ---------------------------------------------------------------
// 3. Encode nil identity → error
// ---------------------------------------------------------------

func TestSPIFFEPropagator_EncodeNilIdentity(t *testing.T) {
	client := &mockWorkloadAPI{fetchSVID: "token"}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: client, Audience: "aud",
	})

	_, err := p.Encode(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

// ---------------------------------------------------------------
// 4. Decode verifies JWT-SVID via workload API
// ---------------------------------------------------------------

func TestSPIFFEPropagator_Decode(t *testing.T) {
	client := &mockWorkloadAPI{
		validateID: "spiffe://example.com/svc/api",
	}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: client, Audience: "backend",
	})

	meta := map[string]string{headerKeySPIFFE: "svid-token"}
	id, err := p.Decode(context.Background(), meta, nil)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if id.WorkloadID != "spiffe://example.com/svc/api" {
		t.Errorf("WorkloadID = %q, want SPIFFE ID", id.WorkloadID)
	}
	if id.AuthMethod != "spiffe" {
		t.Errorf("AuthMethod = %q, want spiffe", id.AuthMethod)
	}
}

// ---------------------------------------------------------------
// 5. Audience restriction checked (SPIRE agent unavailable → error)
// ---------------------------------------------------------------

func TestSPIFFEPropagator_SPIREUnavailable_Encode(t *testing.T) {
	client := &mockWorkloadAPI{
		fetchErr: errors.New("SPIRE agent unavailable"),
	}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: client, Audience: "backend",
	})

	_, err := p.Encode(context.Background(), &auth.Identity{SubjectID: "u"})
	if err == nil {
		t.Fatal("expected error when SPIRE unavailable")
	}
	if got := err.Error(); !containsStr(got, "SPIRE agent unavailable") {
		t.Errorf("error = %q, want SPIRE agent unavailable", got)
	}
}

func TestSPIFFEPropagator_SPIREUnavailable_Decode(t *testing.T) {
	client := &mockWorkloadAPI{
		validateErr: errors.New("SPIRE agent unavailable"),
	}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: client, Audience: "backend",
	})

	meta := map[string]string{headerKeySPIFFE: "some-token"}
	_, err := p.Decode(context.Background(), meta, nil)
	if err == nil {
		t.Fatal("expected error when SPIRE unavailable")
	}
}

// ---------------------------------------------------------------
// 6. No SVID in metadata → error
// ---------------------------------------------------------------

func TestSPIFFEPropagator_NoSVIDInMetadata(t *testing.T) {
	client := &mockWorkloadAPI{}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: client, Audience: "backend",
	})

	_, err := p.Decode(context.Background(), map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected error for missing SVID")
	}
}

// ---------------------------------------------------------------
// 7. Satisfies IdentityPropagator interface
// ---------------------------------------------------------------

func TestSPIFFEPropagator_ImplementsInterface(t *testing.T) {
	client := &mockWorkloadAPI{}
	p, _ := NewSPIFFEPropagator(SPIFFEPropagatorConfig{
		Client: client, Audience: "aud",
	})
	var _ IdentityPropagator = p
}
