// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build live

package server_test

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/providers"
)

// beworSpecimenSHA256 is the official Bewor test identity
// (testdata/specimens/MANIFEST.md, withheld per ruling R30).
const beworSpecimenSHA256 = "da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab"

// TestLiveBeworCredential (AC8) authenticates over loopback mTLS with the
// official Bewor test credential against the production providers and a
// real revocation checker (live OCSP). Run 1 empties the test markers and
// the reserved identities: success. Run 2 is the production registry:
// test_certificate.
func TestLiveBeworCredential(t *testing.T) {
	certFile, keyFile := os.Getenv("CERTCHECK_LIVE_BEWOR_CERT"), os.Getenv("CERTCHECK_LIVE_BEWOR_KEY")
	if certFile == "" || keyFile == "" {
		t.Fatal("CERTCHECK_LIVE_BEWOR_CERT and CERTCHECK_LIVE_BEWOR_KEY must name the Bewor test credential PEM files (outside the repository)")
	}
	cred, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load the Bewor credential: %v", err)
	}
	sum := sha256.Sum256(cred.Certificate[0])
	if got := hex.EncodeToString(sum[:]); got != beworSpecimenSHA256 {
		t.Fatalf("credential leaf SHA-256 %s, want the Bewor specimen %s", got, beworSpecimenSHA256)
	}

	t.Run("markers emptied: success", func(t *testing.T) {
		logs := &e2eLogs{}
		rc, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/live-test", Logger: logs.logger()})
		if err != nil {
			t.Fatalf("revocation.NewChecker: %v", err)
		}
		var provs []certcheck.Provider
		for _, d := range profiles.All() {
			for j := range d.Profiles {
				d.Profiles[j].TestMarkers = nil
			}
			p, err := engine.New(engine.Config{Provider: d, Revocation: rc, Logger: logs.logger(), Version: e2eVersion, Reserved: &identity.Reserved{}})
			if err != nil {
				t.Fatalf("engine.New(%s): %v", d.ID, err)
			}
			if len(p.CAs()) > 0 { // keep the non-inert ones, as providers.All does
				provs = append(provs, p)
			}
		}
		got := liveBeworRedeem(t, provs, logs, &cred)
		if got.Status != "success" || got.Result == nil {
			t.Fatalf("redeem = %+v (error %+v, diagnostics %+v), want success", got, got.Error, got.Diagnostics)
		}
		r := got.Result
		id := r.Identity
		if id.Document.Number != "99949999A" || id.GivenNames != "NOMNUEVE" || id.Surnames != "ESPECIMENNUEVE ESPECIMENNUEVE" {
			t.Errorf("identity = %s / %s / %s, want 99949999A / NOMNUEVE / ESPECIMENNUEVE ESPECIMENNUEVE",
				id.Document.Number, id.GivenNames, id.Surnames)
		}
		if r.Provider.ID != "bewor" || r.Profile.ID != "bewor-natural-person-sw" {
			t.Errorf("provider/profile = %s/%s, want bewor/bewor-natural-person-sw", r.Provider.ID, r.Profile.ID)
		}
		rv := r.Revocation
		if rv.Status != revocation.StatusGood || rv.Method != revocation.MethodOCSP ||
			!slices.Contains([]string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, rv.Source) {
			t.Errorf("revocation = %+v, want good via OCSP from ocsp1/ocsp2.uanataca.com", rv)
		}
		attempts := r.Diagnostics.RevocationAttempts
		if n := len(attempts); n == 0 || !attempts[n-1].NonceSent || !attempts[n-1].NonceEchoed {
			t.Errorf("revocation attempts = %+v, want the deciding OCSP attempt with its nonce echoed", attempts)
		}
		for _, a := range attempts {
			t.Logf("revocation attempt: %s %s http=%d %dms outcome=%s responder=%q nonceSent=%v nonceEchoed=%v thisUpdate=%v nextUpdate=%v",
				a.Method, a.URL, a.HTTPStatus, a.DurationMS, a.Outcome, a.ResponderSubject, a.NonceSent, a.NonceEchoed,
				liveStamp(a.ThisUpdate), liveStamp(a.NextUpdate))
		}
		t.Logf("result: provider %s, profile %s, revocation %s via %s from %s", r.Provider.ID, r.Profile.ID, rv.Status, rv.Method, rv.Source)
		liveNoIdentityInLogs(t, logs)
	})

	t.Run("production registry: test_certificate", func(t *testing.T) {
		logs := &e2eLogs{}
		rev, err := certcheck.NewRevocation(certcheck.RevocationOptions{UserAgent: "cert-check/live-test", Logger: logs.logger()})
		if err != nil {
			t.Fatalf("certcheck.NewRevocation: %v", err)
		}
		provs := providers.All(certcheck.WithRevocation(rev), certcheck.WithLogger(logs.logger()), certcheck.WithVersion(e2eVersion))
		got := liveBeworRedeem(t, provs, logs, &cred)
		if got.Status != "error" || got.Error == nil || got.Error.Code != string(certcheck.CodeTestCertificate) || got.Diagnostics == nil {
			t.Fatalf("redeem = %+v (error %+v), want test_certificate", got, got.Error)
		}
		if d := got.Diagnostics; d.FailedStep != certcheck.StepTestMarker || len(d.RevocationAttempts) != 0 {
			t.Errorf("diagnostics: failedStep %s with %d revocation attempts, want test_marker before any revocation check",
				d.FailedStep, len(d.RevocationAttempts))
		}
		t.Logf("result: %s at %s (%s)", got.Error.Code, got.Diagnostics.FailedStep, got.Diagnostics.TechnicalDetail)
		liveNoIdentityInLogs(t, logs)
	})
}

// liveBeworRedeem serves providers (built with a live revocation checker),
// runs create → mTLS GET on bewor.<auth domain> → redeem, and returns the
// redeem body.
func liveBeworRedeem(t *testing.T, providers []certcheck.Provider, logs *e2eLogs, cred *tls.Certificate) redeemResponse {
	t.Helper()
	s := startE2E(t, providers, logs, &e2eClock{t: time.Now()})
	authURL, cookie := s.create(t, "bewor")
	code := s.authenticate(t, s.authClient(t, "bewor."+e2eAuthDomain, cred), authURL)
	return s.redeemOK(t, code, cookie)
}

// liveNoIdentityInLogs fails when the specimen's identity reached the log.
func liveNoIdentityInLogs(t *testing.T, logs *e2eLogs) {
	t.Helper()
	out := logs.String()
	for _, v := range []string{"99949999A", "NOMNUEVE", "ESPECIMENNUEVE", "state="} {
		if strings.Contains(out, v) {
			t.Errorf("the log contains %q", v)
		}
	}
}

func liveStamp(p *time.Time) string {
	if p == nil {
		return "-"
	}
	return p.UTC().Format(time.RFC3339)
}
