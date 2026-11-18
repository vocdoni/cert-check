// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// specPipeProviders maps a specimen file prefix to the provider it is
// presented to.
var specPipeProviders = []struct{ prefix, provider string }{
	{"fnmt-", "fnmt"}, {"dnie-", "dnie"}, {"digitel-", "digitel"}, {"idcat-", "idcat"},
}

// specPipeNoNetwork fails every dial: no specimen may reach revocation.
func specPipeNoNetwork(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("specimen pipeline: no network")
}

// specPipeWant parses one half of the manifest's expected result, e.g.
// "`test_certificate` (test_marker: fingerprint)", into the code and, for
// test_certificate, the Error.Detail the pipeline must give.
func specPipeWant(t *testing.T, half string) (certcheck.ErrorCode, string) {
	t.Helper()
	half = strings.ReplaceAll(strings.TrimSpace(half), "`", "")
	code, rest, _ := strings.Cut(half, " ")
	if certcheck.ErrorCode(code) != certcheck.CodeTestCertificate {
		return certcheck.ErrorCode(code), ""
	}
	marker, ok := strings.CutPrefix(strings.Trim(rest, "()"), "test_marker: ")
	if !ok {
		t.Fatalf("expected result %q: test_certificate without a test_marker kind", half)
	}
	if marker == "fingerprint" {
		return certcheck.CodeTestCertificate, "known specimen fingerprint"
	}
	return certcheck.CodeTestCertificate, "reserved identity: " + marker
}

// specHandler builds every declaration with engine.New at the clock (the
// production reserved identities) and a Handler over the enabled ones.
func specHandler(t *testing.T, providers []profiles.Provider, now func() time.Time, rc *revocation.Checker) *certcheck.Handler {
	t.Helper()
	var ps []certcheck.Provider
	for _, d := range providers {
		p, err := engine.New(engine.Config{Provider: d, Revocation: rc, Now: now, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatalf("engine.New(%s): %v", d.ID, err)
		}
		if len(p.CAs()) > 0 {
			ps = append(ps, p)
		}
	}
	h, err := certcheck.NewHandler(ps, certcheck.WithClock(now))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func TestSpecimensRejectedTwice(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	committed := 0
	for _, r := range readSpecimenManifest(t) {
		if r.Status != specimenCommitted {
			continue
		}
		committed++
		t.Run(r.File, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(specimenDir, r.File))
			if err != nil {
				t.Fatal(err)
			}
			blk, _ := pem.Decode(raw)
			if blk == nil {
				t.Fatal("no PEM block")
			}
			leaf, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			provider := ""
			for _, p := range specPipeProviders {
				if strings.HasPrefix(r.File, p.prefix) {
					provider = p.provider
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
				})
			}
		})
	}
	if committed != 29 {
		t.Errorf("%d committed specimens, want 29", committed)
	}
}
