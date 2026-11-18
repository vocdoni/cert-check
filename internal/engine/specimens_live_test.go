// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build live

package engine_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// specLiveProviders maps a withheld specimen file prefix to its provider.
var specLiveProviders = map[string]string{"bewor-": "bewor", "sectigo-": "sectigo"}

// TestWithheldSpecimensRejectedTwice runs the TestSpecimensRejectedTwice
// double-rejection check on the specimens withheld from the repository
// (ruling R30), read from $CERTCHECK_LIVE_SPECIMENS_DIR: the expected codes
// are the MANIFEST.md ones (test_certificate twice for Bewor ×2 and the
// Sectigo citizen, unsupported_profile for the Sectigo employee).
func TestWithheldSpecimensRejectedTwice(t *testing.T) {
	dir := os.Getenv("CERTCHECK_LIVE_SPECIMENS_DIR")
	if dir == "" {
		t.Fatal("CERTCHECK_LIVE_SPECIMENS_DIR must name the directory with the withheld specimens (outside the repository)")
	}
	logger := slog.New(slog.DiscardHandler)
	withheld := 0
	for _, r := range readSpecimenManifest(t) {
		if r.Status != specimenWithheld {
			continue
		}
		withheld++
		t.Run(r.File, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, r.File))
			if err != nil {
				t.Fatal(err)
			}
			blk, _ := pem.Decode(raw)
			if blk == nil || blk.Type != "CERTIFICATE" {
				t.Fatal("no PEM certificate")
			}
			sum := sha256.Sum256(blk.Bytes)
			if got := hex.EncodeToString(sum[:]); got != r.SHA256 {
				t.Fatalf("DER SHA-256 %s, want the manifest's %s", got, r.SHA256)
			}
			leaf, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			provider := ""
			for prefix, p := range specLiveProviders {
				if strings.HasPrefix(r.File, prefix) {
					provider = p
				}
			}
			if provider == "" {
				t.Fatalf("no provider for %s", r.File)
			}
			clock := leaf.NotBefore.Add(30 * time.Minute)
			now := func() time.Time { return clock }
			run1, run2, ok := strings.Cut(r.Expected, " / ")
			if !ok {
				t.Fatalf("expected result %q lacks the run 2 half", r.Expected)
			}
			for _, run := range []struct {
				name    string
				markers bool
				half    string
			}{
				{"run 1 production markers", true, run1},
				{"run 2 markers emptied", false, run2},
			} {
				t.Run(run.name, func(t *testing.T) {
					providers := profiles.All()
					if !run.markers {
						for i := range providers {
							for j := range providers[i].Profiles {
								providers[i].Profiles[j].TestMarkers = nil
							}
						}
					}
					rc, err := revocation.NewChecker(revocation.Options{DialContext: specPipeNoNetwork, Now: now, Logger: logger})
					if err != nil {
						t.Fatalf("revocation.NewChecker: %v", err)
					}
					res, err := specHandler(t, providers, now, rc).VerifyAs(t.Context(), provider, []*x509.Certificate{leaf})
					e, isErr := errors.AsType[*certcheck.Error](err)
					if !isErr || res != nil {
						t.Fatalf("Check = (%v, %v), want a *certcheck.Error", res, err)
					}
					wantCode, wantDetail := specPipeWant(t, run.half)
					if e.Code != wantCode {
						t.Errorf("code = %s at %s (%q), want %s", e.Code, e.Diagnostics.FailedStep, e.Detail, wantCode)
					}
					if wantDetail != "" && (e.Detail != wantDetail || e.Diagnostics.FailedStep != certcheck.StepTestMarker) {
						t.Errorf("detail = %q at %s, want %q at %s", e.Detail, e.Diagnostics.FailedStep, wantDetail, certcheck.StepTestMarker)
					}
					if n := len(e.Diagnostics.RevocationAttempts); n != 0 {
						t.Errorf("%d revocation attempts, want none", n)
					}
					t.Logf("%s: %s at %s (%s)", r.File, e.Code, e.Diagnostics.FailedStep, e.Detail)
				})
			}
		})
	}
	if withheld != 4 {
		t.Errorf("%d withheld specimens in the manifest, want 4", withheld)
	}
}
