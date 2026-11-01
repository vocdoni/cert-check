package certauth_test

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

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/internal/identity"
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
func specPipeWant(t *testing.T, half string) (certauth.ErrorCode, string) {
	t.Helper()
	half = strings.ReplaceAll(strings.TrimSpace(half), "`", "")
	code, rest, _ := strings.Cut(half, " ")
	if certauth.ErrorCode(code) != certauth.CodeTestCertificate {
		return certauth.ErrorCode(code), ""
	}
	marker, ok := strings.CutPrefix(strings.Trim(rest, "()"), "test_marker: ")
	if !ok {
		t.Fatalf("expected result %q: test_certificate without a test_marker kind", half)
	}
	if marker == "fingerprint" {
		return certauth.CodeTestCertificate, "known specimen fingerprint"
	}
	return certauth.CodeTestCertificate, "reserved identity: " + marker
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
					reg, err := profiles.New(profiles.Config{Providers: providers, Reserved: identity.DefaultReserved(), Now: clock, Logger: logger})
					if err != nil {
						t.Fatalf("profiles.New: %v", err)
					}
					rc, err := revocation.NewChecker(revocation.Options{DialContext: specPipeNoNetwork, Now: now, Logger: logger})
					if err != nil {
						t.Fatalf("revocation.NewChecker: %v", err)
					}
					chk, err := certauth.NewChecker(certauth.Options{Registry: reg, Revocation: rc, Now: now})
					if err != nil {
						t.Fatalf("NewChecker: %v", err)
					}
					res, err := chk.Check(t.Context(), provider, []*x509.Certificate{leaf})
					e, isErr := errors.AsType[*certauth.Error](err)
					if !isErr || res != nil {
						t.Fatalf("Check = (%v, %v), want a *certauth.Error", res, err)
					}
					wantCode, wantDetail := specPipeWant(t, run.half)
					if e.Code != wantCode {
						t.Errorf("code = %s at %s (%q), want %s", e.Code, e.Diagnostics.FailedStep, e.Detail, wantCode)
					}
					if wantDetail != "" && (e.Detail != wantDetail || e.Diagnostics.FailedStep != certauth.StepTestMarker) {
						t.Errorf("detail = %q at %s, want %q at %s", e.Detail, e.Diagnostics.FailedStep, wantDetail, certauth.StepTestMarker)
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
