// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// probeNow is the fake-network clock.
var probeNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

// probeFakeWorld is a CA with OCSP responders and CRLs on a fake network.
type probeFakeWorld struct {
	ca        *testpki.CA
	responder *testpki.Responder
	servers   map[string]*testpki.OCSPServer // by host
	net       *testpki.Net
	policy    revocation.Policy // every fake host allowlisted, nonce required
}

// probeOCSPHosts are the fake responders and the answer each gives.
var probeOCSPHosts = map[string]func(testpki.Request) testpki.OCSPSpec{
	"ocsp-good.test": func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: probeNow, NextUpdate: probeNow.Add(time.Hour)}
	},
	// A never-issued serial: revoked, certificateHold, 1970 (FNMT style).
	"ocsp-revoked.test": func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: probeNow, NextUpdate: probeNow.Add(time.Hour), Status: testpki.Revoked,
			Reason: 6, RevokedAt: time.Unix(0, 0).UTC()}
	},
	"ocsp-unknown.test": func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: probeNow, NextUpdate: probeNow.Add(time.Hour), Status: testpki.Unknown}
	},
	"ocsp-badsig.test": func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: probeNow, NextUpdate: probeNow.Add(time.Hour), CorruptSignature: true}
	},
	"ocsp-nononce.test": func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: probeNow, NextUpdate: probeNow.Add(time.Hour), Nonce: testpki.NonceOmit}
	},
	// Refuses a request without a nonce (unauthorized), answers one with a nonce.
	"ocsp-needs-nonce.test": func(r testpki.Request) testpki.OCSPSpec {
		if r.Nonce == nil {
			return testpki.OCSPSpec{ResponseStatus: 6}
		}
		return testpki.OCSPSpec{Now: probeNow, NextUpdate: probeNow.Add(time.Hour)}
	},
}

// probeCRLURL is the URL of a CRL served by the fake world at path.
func probeCRLURL(path string) string { return "http://crl.test" + path }

func newProbeFakeWorld(t *testing.T) *probeFakeWorld {
	t.Helper()
	w := &probeFakeWorld{servers: map[string]*testpki.OCSPServer{}, net: testpki.NewNet()}
	w.ca = testpki.NewRoot(t, "Probe CA", testpki.CertSpec{Now: probeNow})
	w.responder = w.ca.OCSPResponder(t, testpki.CertSpec{Now: probeNow})
	other := testpki.NewRoot(t, "Other CA", testpki.CertSpec{Now: probeNow})
	for host, answer := range probeOCSPHosts {
		s := testpki.NewOCSPServer(w.ca, w.responder)
		s.SetAnswer(answer)
		w.net.Serve(t, host, s.Handler(t))
		w.servers[host] = s
		w.policy.OCSPHosts = append(w.policy.OCSPHosts, host)
	}
	w.policy.OCSPHosts = append(w.policy.OCSPHosts, "ocsp-down.test") // never served: the dial fails
	slices.Sort(w.policy.OCSPHosts)
	w.policy.CRLHosts, w.policy.AllowCRL, w.policy.OCSPNonce = []string{"crl.test"}, true, true

	crl := func(spec testpki.CRLSpec) http.Handler {
		return testpki.Bytes("application/pkix-crl", w.ca.CRL(t, spec))
	}
	mux := http.NewServeMux()
	mux.Handle("/fresh.crl", crl(testpki.CRLSpec{Now: probeNow, Number: 1,
		Entries: []testpki.CRLEntry{{Serial: big.NewInt(7), RevokedAt: probeNow.Add(-time.Hour)}}}))
	mux.Handle("/stale.crl", crl(testpki.CRLSpec{Now: probeNow, Number: 2,
		ThisUpdate: probeNow.Add(-48 * time.Hour), NextUpdate: probeNow.Add(-24 * time.Hour)}))
	mux.Handle("/badsig.crl", crl(testpki.CRLSpec{Now: probeNow, Number: 3, Signer: other}))
	// CRLs the checker rejects although they are signed, fresh and not expired.
	idp := func(path string, spec testpki.IDPSpec) {
		if spec.URIs == nil {
			spec.URIs = []string{probeCRLURL(path)}
		}
		mux.Handle(path, crl(testpki.CRLSpec{Now: probeNow, Number: 4, IDP: &spec}))
	}
	idp("/idp-match.crl", testpki.IDPSpec{})
	idp("/idp-reasons.crl", testpki.IDPSpec{OnlySomeReasons: true})
	idp("/idp-other.crl", testpki.IDPSpec{URIs: []string{probeCRLURL("/other.crl")}})
	idp("/idp-onlyca.crl", testpki.IDPSpec{OnlyCA: true})
	idp("/idp-onlyuser.crl", testpki.IDPSpec{OnlyUser: true})
	mux.Handle("/next-before-this.crl", crl(testpki.CRLSpec{Now: probeNow, Number: 5,
		ThisUpdate: probeNow.Add(2 * time.Minute), NextUpdate: probeNow.Add(time.Minute)})) // inside the clock skew
	w.net.Serve(t, "crl.test", mux) // any other path: 404
	return w
}

// specimen issues a leaf whose AIA OCSP URL is responder.
func (w *probeFakeWorld) specimen(t *testing.T, responder string) *x509.Certificate {
	t.Helper()
	return w.ca.Leaf(t, testpki.CertSpec{
		Now:         probeNow,
		Subject:     testpki.Name{testpki.UTF8(testpki.OIDCommonName, "probe specimen")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		OCSPServers: []string{responder},
	}).Cert
}

func (w *probeFakeWorld) checker(t *testing.T) *revocation.Checker {
	t.Helper()
	rc, err := revocation.NewChecker(revocation.Options{DialContext: w.net.DialContext,
		Now: func() time.Time { return probeNow }, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	return rc
}

// prober probes on the fake network at probeNow with the production CRL
// cost limit; rc may be nil.
func (w *probeFakeWorld) prober(rc *revocation.Checker) prober {
	return prober{rc: rc, fetcher: revocation.NewFetcher(revocation.FetcherOptions{DialContext: w.net.DialContext}),
		now: func() time.Time { return probeNow }, crlLimit: revocation.DefaultCRLCacheBytes}
}

func TestProbeAgainstFakeNetwork(t *testing.T) {
	w := newProbeFakeWorld(t)
	optional := w.policy
	optional.OCSPNonce = false
	respSubject := w.responder.Cert.Subject.String()
	caSubject := w.ca.Cert.Subject.String()
	cases := []struct {
		name    string
		target  Target
		verdict Verdict
		want    []string // substrings of the line
	}{
		{"ocsp good, nonce required",
			Target{Profile: "p-good", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictOK, []string{"p-good ocsp ocsp-good.test/ http=200 ", "outcome=good", `responder="` + respSubject + `"`,
				"nonce=required/echoed", "thisUpdate=" + probeNow.Add(-time.Minute).Format(time.RFC3339),
				"nextUpdate=" + probeNow.Add(time.Hour).Format(time.RFC3339)}},
		{"ocsp good, nonce optional (none sent)",
			Target{Profile: "p-opt", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: optional},
			VerdictOK, []string{"outcome=good", "nonce=- "}},
		{"ocsp revoked (never-issued serial)",
			Target{Profile: "p-rev", Kind: KindOCSP, URL: "http://ocsp-revoked.test/", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictOK, []string{"outcome=revoked", "nonce=required/echoed", `detail="revoked (reason 6)"`}},
		{"ocsp unknown",
			Target{Profile: "p-unk", Kind: KindOCSP, URL: "http://ocsp-unknown.test/", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictOK, []string{"outcome=unknown"}},
		{"ocsp bad signature",
			Target{Profile: "p-badsig", Kind: KindOCSP, URL: "http://ocsp-badsig.test/", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictFail, []string{"http=200", "outcome=invalid_evidence", "signature"}},
		{"ocsp nonce required, not echoed",
			Target{Profile: "p-nonce", Kind: KindOCSP, URL: "http://ocsp-nononce.test/", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictFail, []string{"outcome=invalid_evidence", "nonce=required/absent", "nonce sent but not echoed"}},
		{"ocsp nonce optional, none sent",
			Target{Profile: "p-nonce-opt", Kind: KindOCSP, URL: "http://ocsp-nononce.test/", Issuer: w.ca.Cert, Policy: optional},
			VerdictOK, []string{"outcome=good", "nonce=- "}},
		{"ocsp endpoint down",
			Target{Profile: "p-down", Kind: KindOCSP, URL: "http://ocsp-down.test/", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictWarn, []string{"p-down ocsp ocsp-down.test/ http=0 ", "outcome=unavailable"}},
		{"crl fresh",
			Target{Profile: "p-crl", Kind: KindCRL, URL: "http://crl.test/fresh.crl", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictOK, []string{"p-crl crl crl.test/fresh.crl http=200 ", "outcome=good", `issuer="` + caSubject + `"`,
				"nonce=-", "thisUpdate=" + probeNow.Add(-time.Minute).Format(time.RFC3339), `detail="1 entries"`, "bytes="}},
		{"crl stale",
			Target{Profile: "p-crl-stale", Kind: KindCRL, URL: "http://crl.test/stale.crl", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictFail, []string{"outcome=stale", "nextUpdate in the past"}},
		{"crl signed by another CA",
			Target{Profile: "p-crl-bad", Kind: KindCRL, URL: "http://crl.test/badsig.crl", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictFail, []string{"outcome=invalid_evidence"}},
		{"crl not found",
			Target{Profile: "p-crl-404", Kind: KindCRL, URL: "http://crl.test/missing.crl", Issuer: w.ca.Cert, Policy: w.policy},
			VerdictWarn, []string{"http=404", "outcome=unavailable"}},
		{"specimen good",
			Target{Profile: "p-spec", Kind: KindSpecimen, Issuer: w.ca.Cert, Specimen: w.specimen(t, "http://ocsp-good.test/"), Policy: w.policy},
			VerdictOK, []string{"p-spec specimen ocsp-good.test/ http=200 ", "outcome=good", "nonce=required/echoed"}},
		{"specimen revoked",
			Target{Profile: "p-spec-rev", Kind: KindSpecimen, Issuer: w.ca.Cert, Specimen: w.specimen(t, "http://ocsp-revoked.test/"), Policy: w.policy},
			VerdictFail, []string{"outcome=revoked"}},
	}
	targets := make([]Target, 0, len(cases))
	var want Summary
	for _, c := range cases {
		targets = append(targets, c.target)
		want.add(c.verdict)
	}

	var out bytes.Buffer
	got, err := w.prober(w.checker(t)).run(t.Context(), targets, &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if got != want {
		t.Errorf("summary = %+v, want %+v\n%s", got, want, out.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != len(cases)+1 {
		t.Fatalf("got %d lines, want %d (one per target and a summary):\n%s", len(lines), len(cases)+1, out.String())
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := lines[i]
			if v, _, _ := strings.Cut(line, " "); Verdict(v) != c.verdict {
				t.Errorf("verdict = %q, want %q; line %q", v, c.verdict, line)
			}
			for _, s := range c.want {
				if !strings.Contains(line, s) {
					t.Errorf("line %q lacks %q", line, s)
				}
			}
		})
	}
	wantSummary := "summary: " + strconv.Itoa(want.OK) + " ok, " + strconv.Itoa(want.Warn) + " warn, " + strconv.Itoa(want.Fail) + " fail"
	if last := lines[len(lines)-1]; last != wantSummary {
		t.Errorf("summary line = %q, want %q", last, wantSummary)
	}
	if want != (Summary{OK: 7, Warn: 2, Fail: 5}) {
		t.Errorf("case table summary = %+v, want 7 ok, 2 warn, 5 fail", want)
	}
	if !got.Failed() {
		t.Error("Failed() = false with FAIL lines")
	}

	// Every OCSP request carries a fresh random 16-byte serial; a nonce only
	// when the profile requires one (TestProbeOCSPNonceMirrorsChecker).
	serials := map[string]bool{}
	for host, s := range w.servers {
		for _, r := range s.Requests() {
			if n := len(r.Serial.Bytes()); n != 16 {
				t.Errorf("%s: serial is %d bytes, want 16", host, n)
			}
			if serials[r.Serial.String()] {
				t.Errorf("%s: serial %x reused", host, r.Serial)
			}
			serials[r.Serial.String()] = true
		}
	}
	if len(serials) == 0 {
		t.Error("no OCSP request reached the fake responders")
	}
}

func TestRunRejectsInvalidTargets(t *testing.T) {
	w := newProbeFakeWorld(t)
	good := Target{Profile: "p", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: w.policy}
	specimen := w.specimen(t, "http://ocsp-good.test/")
	foreign := testpki.NewRoot(t, "Foreign CA", testpki.CertSpec{Now: probeNow, CDP: []testpki.DistributionPoint{{URIs: []string{probeCRLURL("/fresh.crl")}}}}).Cert
	otherDP := w.ca.Intermediate(t, "Probe CA other DP", testpki.CertSpec{Now: probeNow, CDP: []testpki.DistributionPoint{{URIs: []string{probeCRLURL("/other.crl")}}}}).Cert
	cases := []struct {
		name   string
		mutate func(*Target)
		rc     *revocation.Checker
	}{
		{"unknown kind", func(t *Target) { t.Kind = "dns" }, nil},
		{"no issuer", func(t *Target) { t.Issuer = nil }, nil},
		{"no profile", func(t *Target) { t.Profile = "" }, nil},
		{"ocsp without URL", func(t *Target) { t.URL = "" }, nil},
		{"invalid policy", func(t *Target) { t.Policy.OCSPHosts = []string{"UPPER.test"} }, nil},
		{"specimen without certificate", func(t *Target) { t.Kind, t.URL = KindSpecimen, "" }, w.checker(t)},
		{"specimen without checker", func(t *Target) {
			t.Kind, t.URL, t.Specimen = KindSpecimen, "", specimen
		}, nil},
		{"crl covering a certificate of another issuer", func(t *Target) {
			t.Kind, t.URL, t.Covers = KindCRL, probeCRLURL("/fresh.crl"), []*x509.Certificate{foreign}
		}, nil},
		{"crl covering a certificate whose CDP does not name it", func(t *Target) {
			t.Kind, t.URL, t.Covers = KindCRL, probeCRLURL("/fresh.crl"), []*x509.Certificate{otherDP}
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg := good
			c.mutate(&tg)
			var out bytes.Buffer
			sum, err := w.prober(c.rc).run(t.Context(), []Target{good, tg}, &out)
			if err == nil {
				t.Fatalf("run = %+v, nil; want an error", sum)
			}
			if out.Len() != 0 {
				t.Errorf("output before validation finished: %q", out.String())
			}
		})
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	w := newProbeFakeWorld(t)
	tg := Target{Profile: "p", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: w.policy}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	if _, err := w.prober(nil).run(ctx, []Target{tg}, &out); !errors.Is(err, context.Canceled) {
		t.Errorf("run with a cancelled context = %v, want context.Canceled", err)
	}
}

// runLines runs targets on the fake network and returns the report lines.
func (w *probeFakeWorld) runLines(t *testing.T, targets []Target) (Summary, []string) {
	t.Helper()
	var out bytes.Buffer
	sum, err := w.prober(w.checker(t)).run(t.Context(), targets, &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != len(targets)+1 {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(targets)+1, out.String())
	}
	return sum, lines
}

// TestProbeOCSPNonceMirrorsChecker: the probe sends a nonce only when the
// profile requires one, as the checker does (U13-FABLE-2). A responder that
// refuses nonce-less requests is a WARN for a nonce-less profile, as the
// checker's verdict on a certificate of that profile is unavailable.
func TestProbeOCSPNonceMirrorsChecker(t *testing.T) {
	w := newProbeFakeWorld(t)
	optional := w.policy
	optional.OCSPNonce = false
	const responder = "http://ocsp-needs-nonce.test/"
	_, lines := w.runLines(t, []Target{
		{Profile: "p-req", Kind: KindOCSP, URL: responder, Issuer: w.ca.Cert, Policy: w.policy},
		{Profile: "p-opt", Kind: KindOCSP, URL: responder, Issuer: w.ca.Cert, Policy: optional},
		{Profile: "p-spec", Kind: KindSpecimen, Issuer: w.ca.Cert, Specimen: w.specimen(t, responder), Policy: optional},
	})
	want := []struct {
		verdict Verdict
		parts   []string
	}{
		{VerdictOK, []string{"outcome=good", "nonce=required/echoed"}},
		{VerdictWarn, []string{"outcome=unavailable", "nonce=- ", "responseStatus 6"}},
		{VerdictWarn, []string{"outcome=unavailable", "responseStatus 6"}},
	}
	for i, wl := range want {
		if v, _, _ := strings.Cut(lines[i], " "); Verdict(v) != wl.verdict {
			t.Errorf("line %d verdict = %q, want %q; line %q", i, v, wl.verdict, lines[i])
		}
		for _, s := range wl.parts {
			if !strings.Contains(lines[i], s) {
				t.Errorf("line %q lacks %q", lines[i], s)
			}
		}
	}
	reqs := w.servers["ocsp-needs-nonce.test"].Requests()
	if len(reqs) != 3 || reqs[0].Nonce == nil || reqs[1].Nonce != nil || reqs[2].Nonce != nil {
		t.Errorf("requests = %+v, want three: a nonce for the required profile only", reqs)
	}
}

// TestProbeCRLMatchesChecker: CRL rows are judged by revocation.EvaluateCRL
// (freshness, IDP name and scope flags), so a CRL the checker rejects is
// never OK in the probe (U13-FABLE-3).
func TestProbeCRLMatchesChecker(t *testing.T) {
	w := newProbeFakeWorld(t)
	cases := []struct {
		path    string
		scope   revocation.Scope
		verdict Verdict
		detail  string
	}{
		{"/fresh.crl", 0, VerdictOK, "1 entries"}, // zero scope: leaf
		{"/idp-match.crl", revocation.ScopeLeaf, VerdictOK, "0 entries"},
		{"/idp-reasons.crl", revocation.ScopeLeaf, VerdictFail, "idp scope flag unsupported"},
		{"/idp-other.crl", revocation.ScopeLeaf, VerdictFail, "idp distributionPoint does not match"},
		{"/next-before-this.crl", revocation.ScopeLeaf, VerdictFail, "crl nextUpdate before thisUpdate"},
		{"/idp-onlyca.crl", revocation.ScopeLeaf, VerdictFail, "idp onlyContainsCACerts for a leaf"},
		{"/idp-onlyca.crl", revocation.ScopeCA, VerdictOK, "0 entries"},
		{"/idp-onlyuser.crl", revocation.ScopeCA, VerdictFail, "idp onlyContainsUserCerts for a CA"},
	}
	targets := make([]Target, 0, len(cases))
	for _, c := range cases {
		targets = append(targets, Target{Profile: "p", Kind: KindCRL, URL: probeCRLURL(c.path), Issuer: w.ca.Cert, Policy: w.policy, Scope: c.scope})
	}
	_, lines := w.runLines(t, targets)
	rc := w.checker(t)
	for i, c := range cases {
		line := lines[i]
		if v, _, _ := strings.Cut(line, " "); Verdict(v) != c.verdict {
			t.Errorf("%s scope %d: verdict = %q, want %q; line %q", c.path, c.scope, v, c.verdict, line)
		}
		if !strings.Contains(line, `detail="`+c.detail) {
			t.Errorf("%s scope %d: line %q lacks detail %q", c.path, c.scope, line, c.detail)
		}
		// The checker on a certificate of that scope (a leaf or an
		// intermediate) whose only revocation source is this CRL agrees.
		cdp := []testpki.DistributionPoint{{URIs: []string{probeCRLURL(c.path)}}}
		var cert *x509.Certificate
		if c.scope == revocation.ScopeCA {
			cert = w.ca.Intermediate(t, "probe crl ca", testpki.CertSpec{Now: probeNow, CDP: cdp}).Cert
		} else {
			cert = w.ca.Leaf(t, testpki.CertSpec{Now: probeNow, Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "probe crl leaf")},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CDP: cdp}).Cert
		}
		res, err := rc.Check(t.Context(), cert, w.ca.Cert, w.policy)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if ok := res.Status == revocation.StatusGood; ok != (c.verdict == VerdictOK) {
			t.Errorf("%s: checker status %s (%s), probe verdict %s", c.path, res.Status, res.Detail, c.verdict)
		}
	}
}

// TestRunNothingVerifiedFails: a run whose lines are all WARN verified
// nothing and fails (U13-FABLE-4).
func TestRunNothingVerifiedFails(t *testing.T) {
	w := newProbeFakeWorld(t)
	sum, lines := w.runLines(t, []Target{
		{Profile: "p-down", Kind: KindOCSP, URL: "http://ocsp-down.test/", Issuer: w.ca.Cert, Policy: w.policy},
		{Profile: "p-404", Kind: KindCRL, URL: probeCRLURL("/missing.crl"), Issuer: w.ca.Cert, Policy: w.policy},
	})
	if sum != (Summary{Warn: 2}) || !sum.Failed() {
		t.Errorf("summary = %+v, Failed() = %v; want 2 warn and failed", sum, sum.Failed())
	}
	if got, want := lines[len(lines)-1], "summary: 0 ok, 2 warn, 0 fail (no endpoint verified)"; got != want {
		t.Errorf("summary line = %q, want %q", got, want)
	}
	for _, c := range []struct {
		sum  Summary
		want bool
	}{
		{Summary{}, true},
		{Summary{OK: 1}, false},
		{Summary{OK: 1, Warn: 5}, false},
		{Summary{Warn: 1}, true},
		{Summary{OK: 3, Fail: 1}, true},
	} {
		if got := c.sum.Failed(); got != c.want {
			t.Errorf("%+v.Failed() = %v, want %v", c.sum, got, c.want)
		}
	}
}

// TestRunRejectsEmptyTargets: a run without targets verified nothing and
// fails (U13-ASTRA-5).
func TestRunRejectsEmptyTargets(t *testing.T) {
	w := newProbeFakeWorld(t)
	var out bytes.Buffer
	sum, err := w.prober(nil).run(t.Context(), nil, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum != (Summary{}) || !sum.Failed() {
		t.Errorf("summary = %+v, Failed() = %v; want empty and failed", sum, sum.Failed())
	}
	if got, want := out.String(), "summary: 0 ok, 0 warn, 0 fail (no endpoint verified)\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

// TestRunCanceledDuringLastTarget: a cancellation while the last target is
// probed fails the run, as it does during any earlier target (U13-ASTRA-4).
func TestRunCanceledDuringLastTarget(t *testing.T) {
	w := newProbeFakeWorld(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := testpki.NewOCSPServer(w.ca, w.responder)
	s.SetAnswer(probeOCSPHosts["ocsp-good.test"])
	h := s.Handler(t)
	w.net.Serve(t, "ocsp-cancel.test", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		cancel() // SIGINT while the last target is probed
		h.ServeHTTP(rw, r)
	}))
	policy := w.policy
	policy.OCSPHosts = append(slices.Clone(policy.OCSPHosts), "ocsp-cancel.test")
	var out bytes.Buffer
	sum, err := w.prober(nil).run(ctx, []Target{
		{Profile: "p-good", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: policy},
		{Profile: "p-cancel", Kind: KindOCSP, URL: "http://ocsp-cancel.test/", Issuer: w.ca.Cert, Policy: policy},
	}, &out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run = %+v, %v; want context.Canceled\n%s", sum, err, out.String())
	}
	if strings.Contains(out.String(), "summary:") {
		t.Errorf("a cancelled run printed a summary:\n%s", out.String())
	}
}

// TestProbeUsesPerTargetClock: every OCSP and CRL target reads the clock
// once, when it is probed, so evidence that expires during a long run is
// judged at the time it is fetched (U13-ASTRA-3).
func TestProbeUsesPerTargetClock(t *testing.T) {
	w := newProbeFakeWorld(t)
	crl := Target{Profile: "p-crl", Kind: KindCRL, URL: probeCRLURL("/fresh.crl"), Issuer: w.ca.Cert, Policy: w.policy}
	ocsp := Target{Profile: "p-ocsp", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: w.policy}
	// fresh.crl is valid until probeNow+23h59m, the OCSP answer until probeNow+1h.
	times := []time.Time{probeNow, probeNow.Add(24 * time.Hour), probeNow, probeNow.Add(2 * time.Hour)}
	reads := 0
	p := w.prober(nil)
	p.now = func() time.Time {
		reads++
		return times[min(reads, len(times))-1]
	}
	var out bytes.Buffer
	if _, err := p.run(t.Context(), []Target{crl, crl, ocsp, ocsp}, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	lines := strings.Split(out.String(), "\n")
	want := []struct {
		verdict Verdict
		part    string
	}{
		{VerdictOK, "outcome=good"},
		{VerdictFail, "crl nextUpdate in the past"},
		{VerdictOK, "outcome=good"},
		{VerdictFail, "outcome=stale"},
	}
	for i, wl := range want {
		if v, _, _ := strings.Cut(lines[i], " "); Verdict(v) != wl.verdict || !strings.Contains(lines[i], wl.part) {
			t.Errorf("line %d = %q, want %s with %q", i, lines[i], wl.verdict, wl.part)
		}
	}
	if reads != len(times) {
		t.Errorf("clock read %d times, want %d (once per target)", reads, len(times))
	}
}

// TestProbeCRLCostLimitMatchesChecker: the probe parses a CRL through the
// checker's cost bound, so a CRL too dense for the checker's CRL cache is a
// FAIL, as the checker refuses it (U13-ASTRA-2).
func TestProbeCRLCostLimitMatchesChecker(t *testing.T) {
	w := newProbeFakeWorld(t)
	const small = 8 << 10 // fresh.crl (one entry) fits, dense.crl (64 entries) does not
	entries := make([]testpki.CRLEntry, 64)
	for i := range entries {
		entries[i] = testpki.CRLEntry{Serial: big.NewInt(int64(1000 + i)), RevokedAt: probeNow.Add(-time.Hour)}
	}
	w.net.Serve(t, "dense.test", testpki.Bytes("application/pkix-crl", w.ca.CRL(t, testpki.CRLSpec{Now: probeNow, Number: 1, Entries: entries})))
	policy := w.policy
	policy.CRLHosts = []string{"crl.test", "dense.test"}
	cases := []struct {
		url     string
		limit   int64
		verdict Verdict
		detail  string
	}{
		{probeCRLURL("/fresh.crl"), small, VerdictOK, "1 entries"},
		{"http://dense.test/dense.crl", small, VerdictFail, "crl too large"},
		{"http://dense.test/dense.crl", revocation.DefaultCRLCacheBytes, VerdictOK, "64 entries"},
	}
	for _, c := range cases {
		p := w.prober(nil)
		p.crlLimit = c.limit
		var out bytes.Buffer
		if _, err := p.run(t.Context(), []Target{{Profile: "p", Kind: KindCRL, URL: c.url, Issuer: w.ca.Cert, Policy: policy}}, &out); err != nil {
			t.Fatalf("run: %v", err)
		}
		line, _, _ := strings.Cut(out.String(), "\n")
		if v, _, _ := strings.Cut(line, " "); Verdict(v) != c.verdict || !strings.Contains(line, `detail="`+c.detail+`"`) {
			t.Errorf("%s limit %d: line %q, want %s with detail %q", c.url, c.limit, line, c.verdict, c.detail)
		}
		// The checker with the same CRL cache limit agrees on a leaf whose
		// only revocation source is this CRL.
		rc, err := revocation.NewChecker(revocation.Options{DialContext: w.net.DialContext, CRLCacheBytes: c.limit,
			Now: func() time.Time { return probeNow }, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		leaf := w.ca.Leaf(t, testpki.CertSpec{Now: probeNow, Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "probe crl leaf")},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CDP: []testpki.DistributionPoint{{URIs: []string{c.url}}}}).Cert
		res, err := rc.Check(t.Context(), leaf, w.ca.Cert, policy)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if ok := res.Status == revocation.StatusGood; ok != (c.verdict == VerdictOK) {
			t.Errorf("%s limit %d: checker status %s (%s), probe verdict %s", c.url, c.limit, res.Status, res.Detail, c.verdict)
		}
	}
}

// TestProbeCRLRequiresIDPForDNIePartitions: a CRL row judged for a CA whose
// DPs name several CRLs (AC DNIE 005 and 006) needs the CRL to name its DP
// in an IDP, as the checker does; a CA with one DP (AC DNIE 004) does not
// (U13-ASTRA-1).
func TestProbeCRLRequiresIDPForDNIePartitions(t *testing.T) {
	w := newProbeFakeWorld(t)
	const unnamed = "crl without an idp name for a CA with several DPs"
	cases := []struct {
		name    string
		oneDP   bool                          // the CA's only DP names ARL.crl
		idp     func(string) *testpki.IDPSpec // the IDP of the CRL at a URL; nil: none
		verdict Verdict
		detail  string
	}{
		{"no idp", false, nil, VerdictFail, unnamed},
		{"idp without a name", false, func(string) *testpki.IDPSpec { return &testpki.IDPSpec{OnlyCA: true} }, VerdictFail, unnamed},
		{"idp naming its dp", false, func(u string) *testpki.IDPSpec { return &testpki.IDPSpec{URIs: []string{u}} }, VerdictOK, "0 entries"},
		{"one dp, no idp", true, nil, VerdictOK, "0 entries"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host := "dnie" + strconv.Itoa(i) + ".test"
			urls := []string{"http://" + host + "/CRL.crl", "http://" + host + "/ARL.crl"}
			mux := http.NewServeMux()
			for _, u := range urls {
				spec := testpki.CRLSpec{Now: probeNow, Number: 1}
				if c.idp != nil {
					spec.IDP = c.idp(u)
				}
				mux.Handle(strings.TrimPrefix(u, "http://"+host), testpki.Bytes("application/pkix-crl", w.ca.CRL(t, spec)))
			}
			w.net.Serve(t, host, mux)
			if c.oneDP {
				urls = urls[1:]
			}
			var cdp []testpki.DistributionPoint
			for _, u := range urls {
				cdp = append(cdp, testpki.DistributionPoint{URIs: []string{u}})
			}
			ca := w.ca.Intermediate(t, "probe AC DNIE", testpki.CertSpec{Now: probeNow, CDP: cdp}).Cert
			policy := w.policy
			policy.CRLHosts = []string{host}
			var targets []Target
			for _, u := range urls {
				targets = append(targets, Target{Profile: "p-dnie", Kind: KindCRL, URL: u, Issuer: w.ca.Cert, Policy: policy,
					Scope: revocation.ScopeCA, Covers: []*x509.Certificate{ca}})
			}
			_, lines := w.runLines(t, targets)
			for _, line := range lines[:len(targets)] {
				if v, _, _ := strings.Cut(line, " "); Verdict(v) != c.verdict || !strings.Contains(line, c.detail) {
					t.Errorf("line %q, want %s with %q", line, c.verdict, c.detail)
				}
			}
			res, err := w.checker(t).Check(t.Context(), ca, w.ca.Cert, policy)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if ok := res.Status == revocation.StatusGood; ok != (c.verdict == VerdictOK) {
				t.Errorf("checker status %s (%s), probe verdict %s", res.Status, res.Detail, c.verdict)
			}
		})
	}
}

// probeAllowed mirrors the fetcher's allowlist rule: http/https, lowercase
// host, default port stripped, exact match.
func probeAllowed(raw string, hosts []string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return slices.Contains(hosts, host)
}

func TestTargetsAllowlisted(t *testing.T) {
	targets, err := DefaultTargets()
	if err != nil {
		t.Fatalf("DefaultTargets: %v", err)
	}
	for _, tg := range targets {
		hosts := tg.Policy.OCSPHosts
		if tg.Kind == KindCRL {
			hosts = tg.Policy.CRLHosts
			if !tg.Policy.AllowCRL {
				t.Errorf("%s %s: CRL target for a profile without the CRL fallback", tg.Profile, tg.URL)
			}
		}
		if !probeAllowed(tg.URL, hosts) {
			t.Errorf("%s %s %s: host not in the profile's allowlist %q", tg.Profile, tg.Kind, tg.URL, hosts)
		}
	}
}

func TestDefaultTargets(t *testing.T) {
	targets, err := DefaultTargets()
	if err != nil {
		t.Fatalf("DefaultTargets: %v", err)
	}
	// Endpoint counts per profile, from the Task 12 URL table: one OCSP
	// target per (responder, issuing CA) pair, one CRL target per URL.
	type counts struct{ ocsp, crl int }
	want := map[string]counts{
		"fnmt-citizen-rsa": {1, 1}, "fnmt-citizen-g2": {1, 1},
		"aoc-idcat-g2": {1, 1}, "aoc-idcat-g3": {1, 1},
		"accv-citizen-software-current": {2, 2},
		"digitel-citizen-sw-g1":         {1, 1},
		"bewor-natural-person-sw":       {1, 1},
		"sectigo-citizen-local":         {2, 2},
		"fnmt-representative-rsa":       {1, 0}, "fnmt-representative-g2": {1, 0},
		"fnmt-employee-rsa": {1, 0}, "fnmt-employee-g2": {1, 0},
		"firmaprofesional-personal-sw": {2, 0},
		"anf-asociacion-class2-sw":     {1, 0}, "anf-sl-class2-sw": {1, 0},
		"uanataca-citizen-sw":               {4, 4},
		"signe-personal-otros-dispositivos": {0, 2},
		"lleidanet-natural-person-sw":       {0, 1},
		"dnie-auth":                         {3, 2},
	}
	got := map[string]counts{}
	pinned := map[string][]string{} // profile -> SHA-256 of its anchors and pinned intermediates
	for _, p := range profiles.All() {
		for _, pr := range p.Profiles {
			for _, a := range slices.Concat(pr.Anchors, pr.Intermediates) {
				pinned[pr.ID] = append(pinned[pr.ID], a.SHA256)
			}
		}
	}
	for _, tg := range targets {
		c := got[tg.Profile]
		switch tg.Kind {
		case KindOCSP:
			c.ocsp++
		case KindCRL:
			c.crl++
		default:
			t.Errorf("%s: default target of kind %q, want ocsp or crl", tg.Profile, tg.Kind)
		}
		got[tg.Profile] = c
		sum := sha256.Sum256(tg.Issuer.Raw)
		if !slices.Contains(pinned[tg.Profile], hex.EncodeToString(sum[:])) {
			t.Errorf("%s %s: issuer %q is not one of the profile's pinned CAs", tg.Profile, tg.URL, tg.Issuer.Subject)
		}
		if !tg.Issuer.IsCA {
			t.Errorf("%s %s: issuer %q is not a CA", tg.Profile, tg.URL, tg.Issuer.Subject)
		}
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: %d OCSP and %d CRL targets, want %d and %d", id, got[id].ocsp, got[id].crl, w.ocsp, w.crl)
		}
	}
	for id := range pinned {
		if _, ok := want[id]; !ok {
			t.Errorf("profile %s has no probe targets", id)
		}
	}

	// DNIe: OCSP per pinned intermediate, the root CRL and ARL against the
	// root at CA scope (they cover the intermediates); every other CRL at leaf scope.
	enabled, err := enabledProfiles()
	if err != nil {
		t.Fatal(err)
	}
	covered := 0
	for _, tg := range targets {
		wantScope := revocation.ScopeLeaf
		if tg.Profile == "dnie-auth" {
			wantScope = revocation.ScopeCA
		}
		if tg.Kind == KindCRL && tg.Scope != wantScope {
			t.Errorf("%s %s: scope %d, want %d", tg.Profile, tg.URL, tg.Scope, wantScope)
		}
		// A CRL is judged for exactly the pinned intermediates of its issuer
		// whose CDP names it, as the checker judges it for each of them.
		var wantCovers []*x509.Certificate
		for _, c := range enabled[tg.Profile].Intermediates {
			dps, err := revocation.UsableDistributionPoints(c, tg.Issuer)
			if err != nil {
				t.Fatalf("%s: %v", c.Subject, err)
			}
			names := slices.ContainsFunc(dps, func(dp revocation.DistributionPoint) bool {
				return slices.ContainsFunc(dp.FullName, func(gn revocation.GeneralName) bool { u, ok := gn.URI(); return ok && u == tg.URL })
			})
			if tg.Kind == KindCRL && names && bytes.Equal(c.RawIssuer, tg.Issuer.RawSubject) {
				wantCovers = append(wantCovers, c)
			}
		}
		if !slices.EqualFunc(tg.Covers, wantCovers, func(a, b *x509.Certificate) bool { return bytes.Equal(a.Raw, b.Raw) }) {
			t.Errorf("%s %s %s: covers %d certificates, want the %d pinned intermediates naming it", tg.Profile, tg.Kind, tg.URL, len(tg.Covers), len(wantCovers))
		}
		covered += len(tg.Covers)
		if tg.Profile != "dnie-auth" {
			continue
		}
		selfSigned := bytes.Equal(tg.Issuer.RawIssuer, tg.Issuer.RawSubject)
		if (tg.Kind == KindCRL) != selfSigned {
			t.Errorf("dnie %s %s: issuer %q self-signed=%v, want the root only for the CRLs", tg.Kind, tg.URL, tg.Issuer.Subject, selfSigned)
		}
	}
	if covered != 5 { // CRL.crl: AC DNIE 005 and 006; ARL.crl: AC DNIE 004, 005 and 006
		t.Errorf("CRL targets cover %d certificates, want 5", covered)
	}
}

func TestLoadSpecimens(t *testing.T) {
	targets, err := LoadSpecimens(os.DirFS("../../../testdata/specimens"))
	if err != nil {
		t.Fatalf("LoadSpecimens: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d specimen targets, want 1 (the committed DIGITEL specimen)", len(targets))
	}
	tg := targets[0]
	sum := sha256.Sum256(tg.Specimen.Raw)
	if tg.Kind != KindSpecimen || tg.Profile != "digitel-citizen-sw-g1" ||
		hex.EncodeToString(sum[:]) != "fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8" {
		t.Errorf("target = %s %s %x, want the digitel specimen fed45259", tg.Profile, tg.Kind, sum)
	}
	if tg.Specimen.CheckSignatureFrom(tg.Issuer) != nil {
		t.Errorf("issuer %q did not sign the specimen", tg.Issuer.Subject)
	}
	if !tg.Policy.OCSPNonce || !slices.Contains(tg.Policy.OCSPHosts, "ocsp.digitelts.es") {
		t.Errorf("policy = %+v, want the digitel profile policy", tg.Policy)
	}

	if _, err := LoadSpecimens(fstest.MapFS{"bad.pem": {Data: []byte("not a certificate")}}); err == nil {
		t.Error("LoadSpecimens accepted a .pem file without a certificate")
	}
}

// TestLoadSpecimensUnreadableDir: a specimen directory that does not exist,
// is not a directory or cannot be read is an error, not an empty list
// (U13-FABLE-1: fs.Glob ignores I/O errors).
func TestLoadSpecimensUnreadableDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.pem")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub, err := fs.Sub(fstest.MapFS{"a.pem": {Data: []byte("x")}}, "a.pem")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]fs.FS{
		"missing directory": os.DirFS(filepath.Join(dir, "missing")),
		"a file":            os.DirFS(file),
		"empty root":        os.DirFS(""),
		"a MapFS file":      sub,
	}
	if os.Geteuid() != 0 { // root reads a mode-0 directory
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) // let TempDir remove it
		cases["unreadable directory"] = os.DirFS(locked)
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := LoadSpecimens(fsys); err == nil {
				t.Errorf("LoadSpecimens = %d targets, nil; want an error", len(got))
			}
		})
	}
}

// countingFS serves a MapFS through Open and Stat only (no ReadFile),
// counting the files opened and the bytes read.
type countingFS struct {
	m      fstest.MapFS
	opened []string
	read   int
}

func (c *countingFS) Open(name string) (fs.File, error) {
	f, err := c.m.Open(name)
	if err != nil || name == "." {
		return f, err
	}
	c.opened = append(c.opened, name)
	return countingFile{File: f, n: &c.read}, nil
}

func (c *countingFS) Stat(name string) (fs.FileInfo, error) { return c.m.Stat(name) }

type countingFile struct {
	fs.File
	n *int
}

func (f countingFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	*f.n += n
	return n, err
}

// TestLoadSpecimensBounded: a specimen read stops at maxSpecimenBytes and
// a non-regular *.pem (a FIFO would block) is rejected unopened (U13-FABLE-10).
func TestLoadSpecimensBounded(t *testing.T) {
	large := &countingFS{m: fstest.MapFS{"big.pem": {Data: bytes.Repeat([]byte("A"), 1<<20)}}}
	if _, err := LoadSpecimens(large); err == nil {
		t.Error("LoadSpecimens accepted a 1 MiB .pem file")
	}
	if large.read > maxSpecimenBytes+1 {
		t.Errorf("read %d bytes of a 1 MiB file, want at most %d", large.read, maxSpecimenBytes+1)
	}
	fifo := &countingFS{m: fstest.MapFS{"fifo.pem": {Data: []byte("x"), Mode: fs.ModeNamedPipe}}}
	if _, err := LoadSpecimens(fifo); err == nil {
		t.Error("LoadSpecimens accepted a named pipe")
	}
	if len(fifo.opened) != 0 {
		t.Errorf("opened %q, want the named pipe left unopened", fifo.opened)
	}
}

// TestLoadSpecimensEntryLimit: LoadSpecimens considers at most
// maxSpecimenEntries directory entries; a larger directory is an error
// before any file is read (U13-ASTRA-6).
func TestLoadSpecimensEntryLimit(t *testing.T) {
	digitel, err := os.ReadFile("../../../testdata/specimens/digitel-ciudadanosw-99949996T.pem")
	if err != nil {
		t.Fatal(err)
	}
	dir := func(n int) *countingFS { // the DIGITEL specimen and n-1 other files
		m := fstest.MapFS{"digitel.pem": {Data: digitel}}
		for i := range n - 1 {
			m["other-"+strconv.Itoa(i)+".txt"] = &fstest.MapFile{Data: []byte("x")}
		}
		return &countingFS{m: m}
	}
	if got, err := LoadSpecimens(dir(maxSpecimenEntries)); err != nil || len(got) != 1 {
		t.Errorf("LoadSpecimens(%d entries) = %d targets, %v; want the specimen", maxSpecimenEntries, len(got), err)
	}
	over := dir(maxSpecimenEntries + 1)
	if got, err := LoadSpecimens(over); err == nil {
		t.Errorf("LoadSpecimens(%d entries) = %d targets, nil; want an error", maxSpecimenEntries+1, len(got))
	}
	if len(over.opened) != 0 {
		t.Errorf("opened %q in a directory over the entry limit, want nothing", over.opened)
	}
}

// TestLoadSpecimensDeduplicatesKnownCertificates: copies of a known specimen
// under several names are one target (U13-ASTRA-6).
func TestLoadSpecimensDeduplicatesKnownCertificates(t *testing.T) {
	digitel, err := os.ReadFile("../../../testdata/specimens/digitel-ciudadanosw-99949996T.pem")
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadSpecimens(fstest.MapFS{"a.pem": {Data: digitel}, "b.pem": {Data: digitel}, "c.pem": {Data: digitel}})
	if err != nil || len(got) != 1 {
		t.Errorf("LoadSpecimens(3 copies) = %d targets, %v; want 1", len(got), err)
	}
}
