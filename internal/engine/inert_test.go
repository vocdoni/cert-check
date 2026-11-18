// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine

import (
	"bytes"
	"crypto/x509"
	"log/slog"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// inertProfile is a minimal valid profile of provider under root.
func inertProfile(id, provider string, root *testpki.CA, policy string) profiles.Profile {
	return profiles.Profile{ID: id, ProviderID: provider, Name: id, HolderRole: profiles.RoleNaturalPerson,
		Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{policy},
		EKU: profiles.EKURequireClientAuth, Identity: tPlainAdapter(),
		Revocation: revocation.Policy{OCSPHosts: []string{cwOCSPHost}}}
}

func TestInertProvider(t *testing.T) {
	t.Parallel()
	now := tNow()
	root := testpki.NewRoot(t, "Expired Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "inert-root", testpki.ECDSAP256),
		NotBefore: now.Add(-30 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
	decl := profiles.Provider{ID: "inert", Name: "Inert", Description: "Inert provider", Beta: true,
		Profiles: []profiles.Profile{inertProfile("inert-a", "inert", root, cwPolicyA)}}
	leaf := root.Leaf(t, testpki.CertSpec{Now: now.Add(-48 * time.Hour), Subject: tPerson("IDCES-"+cwDNI, cwGiven, cwSurnames),
		KeyPair: tKey(t, "leaf", testpki.ECDSAP256), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}).Cert

	var logs bytes.Buffer
	p, err := New(Config{Provider: decl, Revocation: tRevocation(t, testpki.NewNet(), now), Now: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(&logs, nil)), Version: "v-inert"})
	if err != nil {
		t.Fatalf("New error = %v, want an inert provider", err)
	}

	if got, want := p.Info(), (certcheck.ProviderInfo{ID: "inert", Name: "Inert", Description: "Inert provider", Beta: true}); got != want {
		t.Errorf("Info() = %+v, want %+v", got, want)
	}
	if got := len(p.CAs()); got != 0 {
		t.Errorf("CAs() has %d certificates, want 0", got)
	}
	if got := len(p.EnabledProfiles()); got != 0 {
		t.Errorf("EnabledProfiles() has %d profiles, want 0", got)
	}
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
	}{
		{"no chain", nil},
		{"leaf", []*x509.Certificate{leaf}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := p.Verify(t.Context(), tc.chain)
			e := tErr(t, err)
			if res != nil || e.Code != CodeProviderMismatch || e.Diagnostics.FailedStep != StepBounds || e.Diagnostics.Code != CodeProviderMismatch {
				t.Errorf("got (%v, %s at %s), want (nil, %s at %s)", res, e.Code, e.Diagnostics.FailedStep, CodeProviderMismatch, StepBounds)
			}
			if got, want := e.Detail, "provider has no enabled profile"; got != want {
				t.Errorf("detail = %q, want %q", got, want)
			}
			if got, want := e.Diagnostics.Provider, "inert"; got != want {
				t.Errorf("Diagnostics.Provider = %q, want %q", got, want)
			}
			if got, want := e.Diagnostics.ServerVersion, "v-inert"; got != want {
				t.Errorf("Diagnostics.ServerVersion = %q, want %q", got, want)
			}
		})
	}
	for _, want := range []string{"anchor outside validity", "profile disabled: no valid anchor", "provider hidden"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %q:\n%s", want, logs.String())
		}
	}
}

// A standalone Provider knows only its own CAs: a leaf of another provider is
// untrusted_issuer (Handler.VerifyAs is what tells provider_mismatch apart).
func TestStandaloneVerifyUntrustedIssuer(t *testing.T) {
	t.Parallel()
	now := tNow()
	rootA := testpki.NewRoot(t, "Standalone Alpha Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "sa-rootA", testpki.ECDSAP256)})
	rootB := testpki.NewRoot(t, "Standalone Beta Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "sa-rootB", testpki.ECDSAP256)})
	rc := tRevocation(t, testpki.NewNet(), now)
	clock := func() time.Time { return now }
	if _, err := New(Config{Provider: profiles.Provider{ID: "alpha", Name: "Alpha",
		Profiles: []profiles.Profile{inertProfile("alpha-a", "alpha", rootA, cwPolicyA)}}, Revocation: rc, Now: clock, Logger: tDiscard}); err != nil {
		t.Fatalf("New(alpha) error = %v", err)
	}
	beta, err := New(Config{Provider: profiles.Provider{ID: "beta", Name: "Beta",
		Profiles: []profiles.Profile{inertProfile("beta-a", "beta", rootB, cwPolicyC)}}, Revocation: rc, Now: clock, Logger: tDiscard})
	if err != nil {
		t.Fatalf("New(beta) error = %v", err)
	}
	leaf := rootA.Leaf(t, testpki.CertSpec{Now: now, Subject: tPerson("IDCES-"+cwDNI, cwGiven, cwSurnames),
		KeyPair: tKey(t, "leaf", testpki.ECDSAP256), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}).Cert

	res, err := beta.Verify(t.Context(), []*x509.Certificate{leaf})
	e := tErr(t, err)
	if res != nil || e.Code != CodeUntrustedIssuer || e.Diagnostics.FailedStep != StepPath {
		t.Errorf("got (%v, %s at %s), want (nil, %s at %s)", res, e.Code, e.Diagnostics.FailedStep, CodeUntrustedIssuer, StepPath)
	}
	if got := e.Diagnostics.ProfileCandidates; len(got) != 1 || got[0].ProfileID != "beta-a" {
		t.Errorf("ProfileCandidates = %+v, want beta-a only", got)
	}
}

// keyAlgorithm is a copy of the one behind certcheck.DescribeCertificate;
// both must name every allowed key the same way.
func TestKeyAlgorithmMatchesDescribe(t *testing.T) {
	t.Parallel()
	now := tNow()
	root := testpki.NewRoot(t, "Key Algorithm Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "ka-root", testpki.ECDSAP256)})
	for _, tc := range []struct {
		key  testpki.KeySpec
		want string
	}{
		{testpki.RSA2048, "RSA-2048"},
		{testpki.RSA3072, "RSA-3072"},
		{testpki.ECDSAP256, "ECDSA-P-256"},
		{testpki.ECDSAP384, "ECDSA-P-384"},
		{testpki.ECDSAP521, "ECDSA-P-521"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			leaf := root.Leaf(t, testpki.CertSpec{Now: now, Subject: tPerson("IDCES-"+cwDNI, cwGiven, cwSurnames),
				KeyPair: tKey(t, "ka-leaf", tc.key)}).Cert
			got, described := keyAlgorithm(leaf), certcheck.DescribeCertificate(leaf).KeyAlgorithm
			if got != tc.want || described != tc.want {
				t.Errorf("keyAlgorithm = %q, DescribeCertificate KeyAlgorithm = %q, want %q for both", got, described, tc.want)
			}
		})
	}
}
