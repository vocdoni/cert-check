package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
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
}

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

func (w *probeFakeWorld) fetcher() *revocation.Fetcher {
	return revocation.NewFetcher(revocation.FetcherOptions{DialContext: w.net.DialContext})
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
		{"ocsp good, nonce optional but echoed",
			Target{Profile: "p-opt", Kind: KindOCSP, URL: "http://ocsp-good.test/", Issuer: w.ca.Cert, Policy: optional},
			VerdictOK, []string{"outcome=good", "nonce=optional/echoed"}},
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
		{"ocsp nonce optional, not echoed",
			Target{Profile: "p-nonce-opt", Kind: KindOCSP, URL: "http://ocsp-nononce.test/", Issuer: w.ca.Cert, Policy: optional},
			VerdictOK, []string{"outcome=good", "nonce=optional/absent"}},
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
	got, err := run(t.Context(), w.checker(t), w.fetcher(), targets, probeNow, &out)
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

	// Every OCSP request carries a nonce and a fresh random 16-byte serial.
	serials := map[string]bool{}
	for host, s := range w.servers {
		for _, r := range s.Requests() {
			if r.Nonce == nil {
				t.Errorf("%s: request without a nonce", host)
			}
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tg := good
			c.mutate(&tg)
			var out bytes.Buffer
			sum, err := run(t.Context(), c.rc, w.fetcher(), []Target{good, tg}, probeNow, &out)
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
	if _, err := run(ctx, nil, w.fetcher(), []Target{tg}, probeNow, &out); !errors.Is(err, context.Canceled) {
		t.Errorf("run with a cancelled context = %v, want context.Canceled", err)
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

	// DNIe: OCSP per pinned intermediate, the root CRL and ARL against the root.
	for _, tg := range targets {
		if tg.Profile != "dnie-auth" {
			continue
		}
		selfSigned := bytes.Equal(tg.Issuer.RawIssuer, tg.Issuer.RawSubject)
		if (tg.Kind == KindCRL) != selfSigned {
			t.Errorf("dnie %s %s: issuer %q self-signed=%v, want the root only for the CRLs", tg.Kind, tg.URL, tg.Issuer.Subject, selfSigned)
		}
	}
}

func TestLoadSpecimens(t *testing.T) {
	targets, err := LoadSpecimens(os.DirFS("../../testdata/specimens"))
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
