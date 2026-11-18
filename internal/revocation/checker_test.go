// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// Default URLs of the chkT fixture. Every host is reached through testpki.Net.
const (
	chkTOCSPHost = "ocsp.test"
	chkTCRLHost  = "crl.test"
	chkTOCSPURL  = "http://ocsp.test/"
	chkTCRLURL   = "http://crl.test/a.crl"
)

// chkTClock is a settable clock for Options.Now.
type chkTClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *chkTClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *chkTClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// chkTLogs is a slog.Handler that keeps every record.
type chkTLogs struct {
	mu      sync.Mutex
	records []slog.Record
}

func (l *chkTLogs) Enabled(context.Context, slog.Level) bool { return true }

func (l *chkTLogs) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, r.Clone())
	return nil
}

func (l *chkTLogs) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *chkTLogs) WithGroup(string) slog.Handler      { return l }

// warnings returns the records at warn level or above.
func (l *chkTLogs) warnings() []slog.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []slog.Record
	for _, r := range l.records {
		if r.Level >= slog.LevelWarn {
			out = append(out, r)
		}
	}
	return out
}

// chkTAttrs returns the attributes of r as a key -> value map.
func chkTAttrs(r slog.Record) map[string]string {
	m := make(map[string]string)
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.String()
		return true
	})
	return m
}

// chkTFixture is an issuing CA with a delegated OCSP responder, a fake
// network and a settable clock.
type chkTFixture struct {
	net   *testpki.Net
	ca    *testpki.CA
	ocsp  *testpki.OCSPServer
	clock *chkTClock
	logs  *chkTLogs
	base  time.Time
}

func chkTNewFixture(t *testing.T) *chkTFixture {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Second)
	ca := testpki.NewRoot(t, "chkT issuing CA", testpki.CertSpec{Now: base})
	f := &chkTFixture{
		net:   testpki.NewNet(),
		ca:    ca,
		ocsp:  testpki.NewOCSPServer(ca, ca.OCSPResponder(t, testpki.CertSpec{Now: base})),
		clock: &chkTClock{now: base},
		logs:  &chkTLogs{},
		base:  base,
	}
	f.answer(chkTGood)
	return f
}

// chkTGood is a fresh good answer at now.
func chkTGood(now time.Time) testpki.OCSPSpec {
	return testpki.OCSPSpec{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
}

// chkTWith returns chkTGood modified by edit.
func chkTWith(edit func(now time.Time, s *testpki.OCSPSpec)) func(time.Time) testpki.OCSPSpec {
	return func(now time.Time) testpki.OCSPSpec {
		s := chkTGood(now)
		edit(now, &s)
		return s
	}
}

// answer makes the OCSP server answer spec(now), now read from the fixture
// clock when the request arrives.
func (f *chkTFixture) answer(spec func(now time.Time) testpki.OCSPSpec) {
	f.ocsp.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
		now := f.clock.Now()
		s := spec(now)
		s.Now = now
		return s
	})
}

// serve registers h for host and returns its request counter.
func (f *chkTFixture) serve(t *testing.T, host string, h http.Handler) *atomic.Int64 {
	t.Helper()
	hits := new(atomic.Int64)
	f.net.Serve(t, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h.ServeHTTP(w, r)
	}))
	return hits
}

// crl returns a handler serving a CRL signed by the fixture CA.
func (f *chkTFixture) crl(t *testing.T, spec testpki.CRLSpec) http.Handler {
	t.Helper()
	if spec.Now.IsZero() {
		spec.Now = f.base
	}
	return testpki.Bytes("application/pkix-crl", f.ca.CRL(t, spec))
}

// leaf issues a leaf with the given AIA OCSP URLs and CDP URLs (one
// DistributionPoint).
func (f *chkTFixture) leaf(t *testing.T, ocspURLs, crlURLs []string) *x509.Certificate {
	t.Helper()
	spec := testpki.CertSpec{
		Subject:     testpki.Name{testpki.UTF8(testpki.OIDCommonName, "chkT leaf")},
		Now:         f.base,
		OCSPServers: ocspURLs,
	}
	if len(crlURLs) > 0 {
		spec.CDP = []testpki.DistributionPoint{{URIs: crlURLs}}
	}
	return f.ca.Leaf(t, spec).Cert
}

// checker returns a Checker on the fixture network, clock and log capture
// unless o sets them.
func (f *chkTFixture) checker(t *testing.T, o Options) *Checker {
	t.Helper()
	if o.DialContext == nil {
		o.DialContext = f.net.DialContext
	}
	if o.Now == nil {
		o.Now = f.clock.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(f.logs)
	}
	c, err := NewChecker(o)
	if err != nil {
		t.Fatalf("NewChecker(%+v) error = %v, want nil", o, err)
	}
	return c
}

func chkTPolicy() Policy {
	return Policy{OCSPHosts: []string{chkTOCSPHost}, CRLHosts: []string{chkTCRLHost}, AllowCRL: true, OCSPNonce: true}
}

// chkTStatus answers every request with an HTTP error status.
func chkTStatus(code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, http.StatusText(code), code)
	})
}

func chkTCheck(t *testing.T, c *Checker, cert, issuer *x509.Certificate, p Policy) Result {
	t.Helper()
	res, err := c.Check(t.Context(), cert, issuer, p)
	if err != nil {
		t.Fatalf("Check error = %v, want nil", err)
	}
	return res
}

// chkTTrace summarises attempts for failure messages.
func chkTTrace(as []Attempt) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, fmt.Sprintf("%s:%s(http %d, cache %v, %q)", a.Method, a.Outcome, a.HTTPStatus, a.FromCache, a.Detail))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func TestCheckOCSPStatuses(t *testing.T) {
	cases := []struct {
		name       string
		spec       func(time.Time) testpki.OCSPSpec
		want       Status
		wantReason int
	}{
		{"good", chkTGood, StatusGood, -1},
		{"revoked", chkTWith(func(now time.Time, s *testpki.OCSPSpec) {
			s.Status, s.RevokedAt, s.Reason = testpki.Revoked, now.Add(-48*time.Hour), 1
		}), StatusRevoked, 1},
		{"revoked without reason", chkTWith(func(now time.Time, s *testpki.OCSPSpec) {
			s.Status, s.RevokedAt, s.OmitReason = testpki.Revoked, now.Add(-48*time.Hour), true
		}), StatusRevoked, -1},
		// Revocation is final: a stale revoked answer must not fall back to the CRL's good.
		{"revoked with nextUpdate in the past", chkTWith(func(now time.Time, s *testpki.OCSPSpec) {
			s.Status, s.RevokedAt, s.Reason = testpki.Revoked, now.Add(-48*time.Hour), 1
			s.ThisUpdate, s.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour)
		}), StatusRevoked, 1},
		{"unknown", chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.Status = testpki.Unknown }), StatusUnknown, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			f.answer(tc.spec)
			ocspHits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
			crlHits := f.serve(t, chkTCRLHost, f.crl(t, testpki.CRLSpec{}))
			leaf := f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL})
			res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, chkTPolicy())

			want := tc.spec(f.base)
			if res.Status != tc.want || res.Method != MethodOCSP {
				t.Fatalf("Check = %s via %q %s, want %s via ocsp", res.Status, res.Method, chkTTrace(res.Attempts), tc.want)
			}
			if !res.ThisUpdate.Equal(want.ThisUpdate) || !res.NextUpdate.Equal(want.NextUpdate) ||
				res.Source != chkTOCSPHost || !res.CheckedAt.Equal(f.base) {
				t.Errorf("Check = thisUpdate %v nextUpdate %v source %q checkedAt %v, want %v %v %q %v",
					res.ThisUpdate, res.NextUpdate, res.Source, res.CheckedAt, want.ThisUpdate, want.NextUpdate, chkTOCSPHost, f.base)
			}
			wantRevokedAt := time.Time{}
			if tc.want == StatusRevoked {
				wantRevokedAt = want.RevokedAt
			}
			if res.Reason != tc.wantReason || !res.RevokedAt.Equal(wantRevokedAt) {
				t.Errorf("Check = reason %d revokedAt %v, want %d %v", res.Reason, res.RevokedAt, tc.wantReason, wantRevokedAt)
			}
			if got := len(res.Attempts); got != 1 {
				t.Errorf("attempts = %d %s, want 1", got, chkTTrace(res.Attempts))
			}
			if got := ocspHits.Load(); got != 1 {
				t.Errorf("OCSP requests = %d, want 1", got)
			}
			if got := crlHits.Load(); got != 0 {
				t.Errorf("CRL requests = %d, want 0 (no fallback after an OCSP answer)", got)
			}
			if w := f.logs.warnings(); len(w) != 0 {
				t.Errorf("warn records = %d, want 0", len(w))
			}
		})
	}
}

func TestCheckFallback(t *testing.T) {
	const (
		otherHost   = "ocsp.other.test"
		crlDownHost = "crl-down.test"
	)
	ocspDown := func(*testing.T, *chkTFixture) http.Handler { return chkTStatus(http.StatusServiceUnavailable) }
	cases := []struct {
		name            string
		ocspURLs        []string
		ocsp            func(t *testing.T, f *chkTFixture) http.Handler
		crlURLs         []string // nil: [chkTCRLURL]
		wantOutcome     Status
		wantHTTP        int
		wantRequests    int64
		wantCRLOutcomes []Status // nil: [good]
	}{
		{
			name:        "ocsp http 503",
			ocspURLs:    []string{chkTOCSPURL},
			ocsp:        ocspDown,
			wantOutcome: StatusUnavailable, wantHTTP: http.StatusServiceUnavailable, wantRequests: 1,
		},
		{
			name:     "ocsp responseStatus tryLater",
			ocspURLs: []string{chkTOCSPURL},
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler {
				f.answer(func(time.Time) testpki.OCSPSpec { return testpki.OCSPSpec{ResponseStatus: 3} })
				return f.ocsp.Handler(t)
			},
			wantOutcome: StatusUnavailable, wantHTTP: http.StatusOK, wantRequests: 1,
		},
		{
			name:     "ocsp invalid signature",
			ocspURLs: []string{chkTOCSPURL},
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler {
				f.answer(chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.CorruptSignature = true }))
				return f.ocsp.Handler(t)
			},
			wantOutcome: StatusInvalidEvidence, wantHTTP: http.StatusOK, wantRequests: 1,
		},
		{
			name:     "ocsp nonce missing",
			ocspURLs: []string{chkTOCSPURL},
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler {
				f.answer(chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.Nonce = testpki.NonceOmit }))
				return f.ocsp.Handler(t)
			},
			wantOutcome: StatusInvalidEvidence, wantHTTP: http.StatusOK, wantRequests: 1,
		},
		{
			name:     "ocsp stale",
			ocspURLs: []string{chkTOCSPURL},
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler {
				f.answer(chkTWith(func(now time.Time, s *testpki.OCSPSpec) {
					s.ThisUpdate, s.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour)
				}))
				return f.ocsp.Handler(t)
			},
			wantOutcome: StatusStale, wantHTTP: http.StatusOK, wantRequests: 1,
		},
		{
			name:     "ocsp wrong CertID",
			ocspURLs: []string{chkTOCSPURL},
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler {
				f.answer(chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.SerialOverride = big.NewInt(4242) }))
				return f.ocsp.Handler(t)
			},
			wantOutcome: StatusInvalidEvidence, wantHTTP: http.StatusOK, wantRequests: 1,
		},
		{
			name:        "no OCSP URL in AIA",
			ocspURLs:    nil,
			ocsp:        func(t *testing.T, f *chkTFixture) http.Handler { return f.ocsp.Handler(t) },
			wantOutcome: StatusUnsupportedMethod, wantRequests: 0,
		},
		{
			name:        "AIA host not allowlisted",
			ocspURLs:    []string{"http://" + otherHost + "/"},
			ocsp:        func(t *testing.T, f *chkTFixture) http.Handler { return f.ocsp.Handler(t) },
			wantOutcome: StatusUnsupportedMethod, wantRequests: 0,
		},
		{
			name:     "ldap CDP URI skipped",
			ocspURLs: []string{chkTOCSPURL}, ocsp: ocspDown,
			crlURLs:     []string{"ldap://crl.test/cn=chkT%20CRL?certificateRevocationList", chkTCRLURL},
			wantOutcome: StatusUnavailable, wantHTTP: http.StatusServiceUnavailable, wantRequests: 1,
		},
		{
			name:     "first CDP URL down",
			ocspURLs: []string{chkTOCSPURL}, ocsp: ocspDown,
			crlURLs:     []string{"http://" + crlDownHost + "/a.crl", chkTCRLURL},
			wantOutcome: StatusUnavailable, wantHTTP: http.StatusServiceUnavailable, wantRequests: 1,
			wantCRLOutcomes: []Status{StatusUnavailable, StatusGood},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			h := tc.ocsp(t, f)
			ocspHits := f.serve(t, chkTOCSPHost, h)
			otherHits := f.serve(t, otherHost, h)
			crlHits := f.serve(t, chkTCRLHost, f.crl(t, testpki.CRLSpec{}))
			f.serve(t, crlDownHost, chkTStatus(http.StatusServiceUnavailable))
			crlURLs := tc.crlURLs
			if crlURLs == nil {
				crlURLs = []string{chkTCRLURL}
			}
			wantCRL := tc.wantCRLOutcomes
			if wantCRL == nil {
				wantCRL = []Status{StatusGood}
			}
			leaf := f.leaf(t, tc.ocspURLs, crlURLs)
			p := chkTPolicy()
			p.CRLHosts = append(p.CRLHosts, crlDownHost)
			res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, p)

			if res.Status != StatusGood || res.Method != MethodCRL || res.Source != chkTCRLHost {
				t.Fatalf("Check = %s via %q from %q %s, want good via crl from %q",
					res.Status, res.Method, res.Source, chkTTrace(res.Attempts), chkTCRLHost)
			}
			if len(res.Attempts) != 1+len(wantCRL) {
				t.Fatalf("attempts = %s, want one OCSP and %d CRL attempts", chkTTrace(res.Attempts), len(wantCRL))
			}
			o := res.Attempts[0]
			if o.Method != MethodOCSP || o.Outcome != tc.wantOutcome || o.HTTPStatus != tc.wantHTTP {
				t.Errorf("OCSP attempt = %s %s http %d, want ocsp %s http %d", o.Method, o.Outcome, o.HTTPStatus, tc.wantOutcome, tc.wantHTTP)
			}
			for i, want := range wantCRL {
				if c := res.Attempts[1+i]; c.Method != MethodCRL || c.Outcome != want {
					t.Errorf("CRL attempt %d = %s %s %q, want crl %s", i, c.Method, c.Outcome, c.URL, want)
				}
			}
			if c := res.Attempts[len(res.Attempts)-1]; c.URL != chkTCRLURL {
				t.Errorf("last CRL attempt URL = %q, want %q", c.URL, chkTCRLURL)
			}
			if got := ocspHits.Load() + otherHits.Load(); got != tc.wantRequests {
				t.Errorf("OCSP requests = %d, want %d", got, tc.wantRequests)
			}
			if got := crlHits.Load(); got != 1 {
				t.Errorf("CRL requests = %d, want 1", got)
			}
		})
	}
}

func TestCheckFailures(t *testing.T) {
	stale := func(now time.Time, s *testpki.OCSPSpec) {
		s.ThisUpdate, s.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	staleCRL := func(f *chkTFixture) testpki.CRLSpec {
		return testpki.CRLSpec{ThisUpdate: f.base.Add(-48 * time.Hour), NextUpdate: f.base.Add(-24 * time.Hour)}
	}
	ocspDown := func(*testing.T, *chkTFixture) http.Handler { return chkTStatus(http.StatusServiceUnavailable) }
	ocspAnswer := func(edit func(time.Time, *testpki.OCSPSpec)) func(*testing.T, *chkTFixture) http.Handler {
		return func(t *testing.T, f *chkTFixture) http.Handler {
			f.answer(chkTWith(edit))
			return f.ocsp.Handler(t)
		}
	}
	crlDown := func(*testing.T, *chkTFixture, *x509.Certificate) http.Handler {
		return chkTStatus(http.StatusServiceUnavailable)
	}
	crlGood := func(t *testing.T, f *chkTFixture, _ *x509.Certificate) http.Handler {
		return f.crl(t, testpki.CRLSpec{})
	}
	revokedAt := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name         string
		noURLs       bool     // leaf without AIA and CDP
		crlURLs      []string // nil: [chkTCRLURL]
		policy       func(*Policy)
		ocsp         func(*testing.T, *chkTFixture) http.Handler
		crl          func(*testing.T, *chkTFixture, *x509.Certificate) http.Handler
		want         Status
		wantMethod   Method
		wantCRLHits  int64
		wantWarn     Method // the method whose rejected evidence is logged; "" for none
		wantRevoked  bool
		wantAttempts int
	}{
		{
			name:   "ocsp down and crl not allowed",
			policy: func(p *Policy) { p.AllowCRL = false },
			ocsp:   ocspDown, crl: crlGood,
			want: StatusUnavailable, wantCRLHits: 0, wantAttempts: 1,
		},
		{
			name: "ocsp invalid and crl down",
			ocsp: ocspAnswer(func(_ time.Time, s *testpki.OCSPSpec) { s.CorruptSignature = true }), crl: crlDown,
			want: StatusInvalidEvidence, wantCRLHits: 1, wantWarn: MethodOCSP, wantAttempts: 2,
		},
		{
			name: "ocsp down and crl stale",
			ocsp: ocspDown,
			crl:  func(t *testing.T, f *chkTFixture, _ *x509.Certificate) http.Handler { return f.crl(t, staleCRL(f)) },
			want: StatusStale, wantCRLHits: 1, wantAttempts: 2,
		},
		{
			name: "ocsp stale and crl down",
			ocsp: ocspAnswer(stale), crl: crlDown,
			want: StatusStale, wantCRLHits: 1, wantAttempts: 2,
		},
		{
			name: "ocsp stale and crl signature invalid",
			ocsp: ocspAnswer(stale),
			crl: func(t *testing.T, f *chkTFixture, _ *x509.Certificate) http.Handler {
				return f.crl(t, testpki.CRLSpec{CorruptSig: true})
			},
			want: StatusInvalidEvidence, wantCRLHits: 1, wantWarn: MethodCRL, wantAttempts: 2,
		},
		{
			name:   "leaf without AIA or CDP",
			noURLs: true,
			ocsp:   func(t *testing.T, f *chkTFixture) http.Handler { return f.ocsp.Handler(t) }, crl: crlGood,
			want: StatusUnavailable, wantCRLHits: 0, wantAttempts: 2,
		},
		{
			name: "crl lists the serial",
			ocsp: ocspDown,
			crl: func(t *testing.T, f *chkTFixture, leaf *x509.Certificate) http.Handler {
				return f.crl(t, testpki.CRLSpec{Entries: []testpki.CRLEntry{{Serial: leaf.SerialNumber, RevokedAt: revokedAt, Reason: 1}}})
			},
			want: StatusRevoked, wantMethod: MethodCRL, wantCRLHits: 1, wantRevoked: true, wantAttempts: 2,
		},
		{
			name:    "cdp hosts outside CRLHosts",
			crlURLs: []string{"http://" + chkTOCSPHost + "/a.crl", "http://unlisted.test/a.crl"},
			ocsp:    ocspDown, crl: crlGood,
			want: StatusUnavailable, wantCRLHits: 0, wantAttempts: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			var leaf *x509.Certificate
			switch {
			case tc.noURLs:
				leaf = f.leaf(t, nil, nil)
			case tc.crlURLs != nil:
				leaf = f.leaf(t, []string{chkTOCSPURL}, tc.crlURLs)
			default:
				leaf = f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL})
			}
			ocspHits := f.serve(t, chkTOCSPHost, tc.ocsp(t, f))
			crlHits := f.serve(t, chkTCRLHost, tc.crl(t, f, leaf))
			p := chkTPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}
			res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, p)

			if res.Status != tc.want || res.Method != tc.wantMethod {
				t.Fatalf("Check = %s via %q %s, want %s via %q", res.Status, res.Method, chkTTrace(res.Attempts), tc.want, tc.wantMethod)
			}
			if got := len(res.Attempts); got != tc.wantAttempts {
				t.Errorf("attempts = %s, want %d", chkTTrace(res.Attempts), tc.wantAttempts)
			}
			if got := crlHits.Load(); got != tc.wantCRLHits {
				t.Errorf("CRL requests = %d, want %d", got, tc.wantCRLHits)
			}
			wantOCSPHits := int64(1)
			if tc.noURLs {
				wantOCSPHits = 0
			}
			if got := ocspHits.Load(); got != wantOCSPHits {
				t.Errorf("OCSP host requests = %d, want %d", got, wantOCSPHits)
			}
			if tc.wantRevoked {
				if !res.RevokedAt.Equal(revokedAt) || res.Reason != 1 {
					t.Errorf("Check = revokedAt %v reason %d, want %v 1", res.RevokedAt, res.Reason, revokedAt)
				}
			} else if !res.RevokedAt.IsZero() || res.Reason != -1 {
				t.Errorf("Check = revokedAt %v reason %d, want zero and -1", res.RevokedAt, res.Reason)
			}
			if res.Detail == "" {
				t.Error("Check detail is empty, want the failing attempt's detail")
			}

			warns := f.logs.warnings()
			if tc.wantWarn == "" {
				if len(warns) != 0 {
					t.Errorf("warn records = %d, want 0", len(warns))
				}
				return
			}
			if len(warns) != 1 {
				t.Fatalf("warn records = %d, want 1", len(warns))
			}
			host := chkTOCSPHost
			if tc.wantWarn == MethodCRL {
				host = chkTCRLHost
			}
			want := map[string]string{"issuer": f.ca.Cert.Subject.String(), "method": string(tc.wantWarn), "outcome": string(StatusInvalidEvidence), "host": host}
			if got := chkTAttrs(warns[0]); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("warn attrs = %v, want exactly %v", got, want)
			}
		})
	}
}

// TestCheckRejectedEvidenceLog: the warning for rejected evidence names the
// method, outcome and host of each rejected attempt, and nothing from a URL
// path or query, a redirect target or an error text.
func TestCheckRejectedEvidenceLog(t *testing.T) {
	const (
		ocspURL = "http://" + chkTOCSPHost + "/SENTINEL-OCSP-PATH?q=SENTINEL-OCSP-QUERY"
		crlURL  = "http://" + chkTCRLHost + "/SENTINEL-CRL-PATH.crl?x=SENTINEL-CRL-QUERY"
	)
	ocspBad := func(t *testing.T, f *chkTFixture) http.Handler {
		f.answer(chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.CorruptSignature = true }))
		return f.ocsp.Handler(t)
	}
	ocspDown := func(*testing.T, *chkTFixture) http.Handler { return chkTStatus(http.StatusServiceUnavailable) }
	foreign := func(*testing.T, *chkTFixture) http.Handler {
		return testpki.Redirect("http://foreign.test/SENTINEL-REDIRECT-PATH?y=SENTINEL-REDIRECT-QUERY")
	}
	badCRL := func(t *testing.T, f *chkTFixture) http.Handler {
		mux := http.NewServeMux()
		mux.Handle("/SENTINEL-CRL-PATH.crl", testpki.Redirect("/SENTINEL-REDIRECT-PATH?y=SENTINEL-REDIRECT-QUERY"))
		mux.Handle("/SENTINEL-REDIRECT-PATH", f.crl(t, testpki.CRLSpec{CorruptSig: true}))
		return mux
	}
	cases := []struct {
		name      string
		ocsp, crl func(*testing.T, *chkTFixture) http.Handler
		want      []Method
	}{
		{"ocsp rejected, crl redirect blocked", ocspBad, foreign, []Method{MethodOCSP}},
		{"ocsp down, crl rejected after a redirect", ocspDown, badCRL, []Method{MethodCRL}},
		{"both rejected", ocspBad, badCRL, []Method{MethodOCSP, MethodCRL}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			f.serve(t, chkTOCSPHost, tc.ocsp(t, f))
			f.serve(t, chkTCRLHost, tc.crl(t, f))
			f.serve(t, "foreign.test", f.crl(t, testpki.CRLSpec{}))
			leaf := f.leaf(t, []string{ocspURL}, []string{crlURL})
			res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, chkTPolicy())
			if res.Status != StatusInvalidEvidence {
				t.Fatalf("Check = %s %s, want invalid_evidence", res.Status, chkTTrace(res.Attempts))
			}
			warns := f.logs.warnings()
			if len(warns) != len(tc.want) {
				t.Fatalf("warn records = %d, want %d", len(warns), len(tc.want))
			}
			for i, w := range warns {
				host := chkTOCSPHost
				if tc.want[i] == MethodCRL {
					host = chkTCRLHost
				}
				want := map[string]string{"issuer": f.ca.Cert.Subject.String(), "method": string(tc.want[i]), "outcome": string(StatusInvalidEvidence), "host": host}
				got := chkTAttrs(w)
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("warn %d attrs = %v, want exactly %v", i, got, want)
				}
				if line := w.Message + fmt.Sprint(got); strings.Contains(line, "SENTINEL") {
					t.Errorf("warn %d = %q, want no URL path, query or redirect target", i, line)
				}
			}
		})
	}
}

func TestCheckTimeouts(t *testing.T) {
	t.Run("ocsp deadline falls back to crl", func(t *testing.T) {
		f := chkTNewFixture(t)
		f.serve(t, chkTOCSPHost, testpki.Slow(time.Second, f.ocsp.Handler(t)))
		f.serve(t, chkTCRLHost, f.crl(t, testpki.CRLSpec{}))
		leaf := f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL})
		res := chkTCheck(t, f.checker(t, Options{OCSPTimeout: 100 * time.Millisecond}), leaf, f.ca.Cert, chkTPolicy())
		if res.Status != StatusGood || res.Method != MethodCRL || len(res.Attempts) != 2 {
			t.Fatalf("Check = %s via %q %s, want good via crl after one OCSP attempt", res.Status, res.Method, chkTTrace(res.Attempts))
		}
		o := res.Attempts[0]
		if o.Outcome != StatusUnavailable || !strings.Contains(o.Detail, "deadline") {
			t.Errorf("OCSP attempt = %s %q, want unavailable mentioning the deadline", o.Outcome, o.Detail)
		}
		if o.Duration < 100*time.Millisecond || o.Duration >= time.Second {
			t.Errorf("OCSP attempt duration = %v, want in [100ms, 1s)", o.Duration)
		}
	})
	t.Run("crl deadline", func(t *testing.T) {
		f := chkTNewFixture(t)
		f.serve(t, chkTOCSPHost, chkTStatus(http.StatusServiceUnavailable))
		f.serve(t, chkTCRLHost, testpki.Slow(time.Second, f.crl(t, testpki.CRLSpec{})))
		leaf := f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL})
		res := chkTCheck(t, f.checker(t, Options{CRLTimeout: 100 * time.Millisecond}), leaf, f.ca.Cert, chkTPolicy())
		if res.Status != StatusUnavailable || len(res.Attempts) != 2 {
			t.Fatalf("Check = %s %s, want unavailable after one OCSP and one CRL attempt", res.Status, chkTTrace(res.Attempts))
		}
		if c := res.Attempts[1]; c.Outcome != StatusUnavailable || !strings.Contains(c.Detail, "deadline") {
			t.Errorf("CRL attempt = %s %q, want unavailable mentioning the deadline", c.Outcome, c.Detail)
		}
	})
}

// TestCheckCRLFetchesLeaveOCSPSlots: CRL fetches that hang for their whole
// timeout hold at most half the fetch slots, so an OCSP check on another
// host still answers within its own timeout.
func TestCheckCRLFetchesLeaveOCSPSlots(t *testing.T) {
	f := chkTNewFixture(t)
	release := make(chan struct{})
	var hung atomic.Int64
	hang := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hung.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		http.Error(w, "released", http.StatusServiceUnavailable)
	})
	p := Policy{OCSPHosts: []string{chkTOCSPHost}, AllowCRL: true}
	var leaves []*x509.Certificate
	for i := range MaxConcurrent { // one host each: the transport also caps connections per host
		host := fmt.Sprintf("crl-hung-%d.test", i)
		f.serve(t, host, hang)
		p.CRLHosts = append(p.CRLHosts, host)
		leaves = append(leaves, f.leaf(t, nil, []string{"http://" + host + "/a.crl"}))
	}
	f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
	ocspLeaf := f.leaf(t, []string{chkTOCSPURL}, nil)
	const ocspTimeout = 2 * time.Second
	c := f.checker(t, Options{OCSPTimeout: ocspTimeout, CRLTimeout: time.Minute})

	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(release)
	for _, leaf := range leaves {
		wg.Go(func() { c.Check(context.Background(), leaf, f.ca.Cert, p) })
	}
	crlTEventually(t, func() bool { return hung.Load() >= MaxConcurrent/2 })
	time.Sleep(100 * time.Millisecond) // let the other CRL checks queue
	start := time.Now()
	res := chkTCheck(t, c, ocspLeaf, f.ca.Cert, p)
	if res.Status != StatusGood || res.Method != MethodOCSP {
		t.Errorf("OCSP Check = %s via %q %s after %v, want good via ocsp", res.Status, res.Method, chkTTrace(res.Attempts), time.Since(start))
	}
	if d := time.Since(start); d >= ocspTimeout {
		t.Errorf("OCSP Check took %v, want under the %v OCSP timeout", d, ocspTimeout)
	}
	if got := hung.Load(); got != MaxConcurrent/2 {
		t.Errorf("CRL fetches in flight = %d, want %d", got, MaxConcurrent/2)
	}
}

func TestCheckOversizedOCSP(t *testing.T) {
	f := chkTNewFixture(t)
	f.ocsp.SetRawAnswer(func(testpki.Request) []byte { return bytes.Repeat([]byte{0x30}, 70<<10) })
	ocspHits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
	leaf := f.leaf(t, []string{chkTOCSPURL}, nil)
	p := Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true}
	res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, p)
	if res.Status != StatusUnavailable || res.Method != "" {
		t.Fatalf("Check = %s via %q %s, want unavailable", res.Status, res.Method, chkTTrace(res.Attempts))
	}
	if len(res.Attempts) < 1 || !strings.Contains(res.Attempts[0].Detail, ErrTooLarge.Error()) {
		t.Errorf("attempts = %s, want the first one to report %q", chkTTrace(res.Attempts), ErrTooLarge)
	}
	if got := ocspHits.Load(); got != 1 {
		t.Errorf("OCSP requests = %d, want 1", got)
	}
}

func TestCheckSecondOCSPURL(t *testing.T) {
	const (
		downURL = "http://ocsp1.test/"
		goodURL = "http://ocsp2.test/"
		evilURL = "http://evil.test/"
	)
	cases := []struct {
		name         string
		urls         []string
		wantOutcomes []Status
		wantDown     int64
		wantEvil     int64
	}{
		{"first 503 second good", []string{downURL, goodURL}, []Status{StatusUnavailable, StatusGood}, 1, 0},
		{"first good ends the step", []string{goodURL, downURL}, []Status{StatusGood}, 0, 0},
		{"unlisted URL skipped", []string{evilURL, goodURL}, []Status{StatusGood}, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			downHits := f.serve(t, "ocsp1.test", chkTStatus(http.StatusServiceUnavailable))
			goodHits := f.serve(t, "ocsp2.test", f.ocsp.Handler(t))
			evilHits := f.serve(t, "evil.test", f.ocsp.Handler(t))
			crlHits := f.serve(t, chkTCRLHost, f.crl(t, testpki.CRLSpec{}))
			leaf := f.leaf(t, tc.urls, []string{chkTCRLURL})
			p := chkTPolicy()
			p.OCSPHosts = []string{"ocsp1.test", "ocsp2.test"}
			res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, p)

			if res.Status != StatusGood || res.Method != MethodOCSP || res.Source != "ocsp2.test" {
				t.Fatalf("Check = %s via %q from %q %s, want good via ocsp from ocsp2.test",
					res.Status, res.Method, res.Source, chkTTrace(res.Attempts))
			}
			var got []Status
			for _, a := range res.Attempts {
				got = append(got, a.Outcome)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.wantOutcomes) {
				t.Errorf("attempt outcomes = %v, want %v", got, tc.wantOutcomes)
			}
			if last := res.Attempts[len(res.Attempts)-1]; last.URL != goodURL {
				t.Errorf("last attempt URL = %q, want %q", last.URL, goodURL)
			}
			if downHits.Load() != tc.wantDown || goodHits.Load() != 1 || evilHits.Load() != tc.wantEvil || crlHits.Load() != 0 {
				t.Errorf("requests = down %d good %d evil %d crl %d, want %d 1 %d 0",
					downHits.Load(), goodHits.Load(), evilHits.Load(), crlHits.Load(), tc.wantDown, tc.wantEvil)
			}
		})
	}
}

func TestCheckPrivateIPBlocked(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "must not be reached", http.StatusTeapot)
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	host := net.JoinHostPort("localhost", port)
	f := chkTNewFixture(t)
	leaf := f.leaf(t, []string{"http://" + host + "/"}, []string{"http://" + host + "/a.crl"})
	c, err := NewChecker(Options{Logger: slog.New(f.logs)}) // no DialContext: the address-checking dialer
	if err != nil {
		t.Fatalf("NewChecker error = %v, want nil", err)
	}
	p := Policy{OCSPHosts: []string{host}, CRLHosts: []string{host}, AllowCRL: true, OCSPNonce: true}
	res := chkTCheck(t, c, leaf, f.ca.Cert, p)

	if res.Status != StatusUnavailable || res.Method != "" {
		t.Fatalf("Check = %s via %q %s, want unavailable", res.Status, res.Method, chkTTrace(res.Attempts))
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("attempts = %s, want one OCSP and one CRL attempt", chkTTrace(res.Attempts))
	}
	for _, a := range res.Attempts {
		if a.Outcome != StatusUnavailable || !strings.Contains(a.Detail, ErrBlockedAddress.Error()) {
			t.Errorf("%s attempt = %s %q, want unavailable with %q", a.Method, a.Outcome, a.Detail, ErrBlockedAddress)
		}
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("loopback server saw %d requests, want 0", got)
	}
}

// chkTSwitch serves whatever CRL was last set.
type chkTSwitch struct{ body atomic.Pointer[[]byte] }

func (s *chkTSwitch) set(der []byte) { s.body.Store(&der) }

func (s *chkTSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	testpki.Bytes("application/pkix-crl", *s.body.Load()).ServeHTTP(w, r)
}

// TestCheckCRLCacheAdmission: a CRL that is not fresh or names another DP is
// rejected and not cached, so the right CRL is fetched on the next check.
func TestCheckCRLCacheAdmission(t *testing.T) {
	cases := []struct {
		name  string
		first func(f *chkTFixture) testpki.CRLSpec
		want  Status
	}{
		{"wrong partition", func(*chkTFixture) testpki.CRLSpec {
			return testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.test/b.crl"}, OnlyUser: true}}
		}, StatusInvalidEvidence},
		{"this update in the future", func(f *chkTFixture) testpki.CRLSpec {
			return testpki.CRLSpec{ThisUpdate: f.base.Add(10 * time.Minute)}
		}, StatusStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			sw := &chkTSwitch{}
			first := tc.first(f)
			first.Now = f.base
			sw.set(f.ca.CRL(t, first))
			hits := f.serve(t, chkTCRLHost, sw)
			leaf := f.leaf(t, nil, []string{chkTCRLURL})
			c := f.checker(t, Options{})
			if res := chkTCheck(t, c, leaf, f.ca.Cert, chkTPolicy()); res.Status != tc.want {
				t.Fatalf("first Check = %s %s, want %s", res.Status, chkTTrace(res.Attempts), tc.want)
			}
			sw.set(f.ca.CRL(t, testpki.CRLSpec{Now: f.base, IDP: &testpki.IDPSpec{URIs: []string{chkTCRLURL}, OnlyUser: true}}))
			if res := chkTCheck(t, c, leaf, f.ca.Cert, chkTPolicy()); res.Status != StatusGood || res.Method != MethodCRL {
				t.Fatalf("second Check = %s via %q %s, want good via crl", res.Status, res.Method, chkTTrace(res.Attempts))
			}
			if got := hits.Load(); got != 2 {
				t.Errorf("CRL requests = %d, want 2 (the first CRL not cached)", got)
			}
		})
	}
}

// TestCheckCRLOverCacheLimit: a CRL the cache could not keep is refused with
// a fixed detail instead of being parsed again on every check.
func TestCheckCRLOverCacheLimit(t *testing.T) {
	f := chkTNewFixture(t)
	var entries []testpki.CRLEntry
	for i := range 50 {
		entries = append(entries, testpki.CRLEntry{Serial: big.NewInt(int64(1000 + i)), RevokedAt: f.base.Add(-time.Hour), Reason: 1})
	}
	f.serve(t, chkTCRLHost, f.crl(t, testpki.CRLSpec{Entries: entries}))
	leaf := f.leaf(t, nil, []string{chkTCRLURL})
	c := f.checker(t, Options{CRLCacheBytes: crlCostBase + 10*crlCostEntry})
	res := chkTCheck(t, c, leaf, f.ca.Cert, chkTPolicy())
	if res.Status != StatusUnavailable || res.Method != "" {
		t.Fatalf("Check = %s via %q %s, want unavailable", res.Status, res.Method, chkTTrace(res.Attempts))
	}
	if a := res.Attempts[len(res.Attempts)-1]; a.Method != MethodCRL || a.Outcome != StatusUnsupportedMethod || a.Detail != "crl too large" {
		t.Errorf("CRL attempt = %s %s %q, want crl unsupported_method %q", a.Method, a.Outcome, a.Detail, "crl too large")
	}
}

// TestCRLRollbackRejected: once a CRL number is seen for an (issuer, URL), a
// lower one is invalid evidence, also after the cached CRL expired.
func TestCRLRollbackRejected(t *testing.T) {
	f := chkTNewFixture(t)
	sw := &chkTSwitch{}
	hits := f.serve(t, chkTCRLHost, sw)
	leaf := f.leaf(t, nil, []string{chkTCRLURL})
	c := f.checker(t, Options{})
	listed := []testpki.CRLEntry{{Serial: leaf.SerialNumber, RevokedAt: f.base.Add(-time.Hour), Reason: 1}}
	steps := []struct {
		name   string
		number int64
		listed bool
		want   Status
	}{
		{"crl 44 lists the leaf", 44, true, StatusRevoked},
		{"crl 43 replayed", 43, false, StatusInvalidEvidence},
		{"crl 44 again", 44, true, StatusRevoked},
		{"crl 45", 45, false, StatusGood},
		{"crl 44 replayed", 44, true, StatusInvalidEvidence},
	}
	for i, s := range steps {
		now := f.base.Add(time.Duration(i) * 61 * time.Minute) // past the cache's one hour
		f.clock.Set(now)
		spec := testpki.CRLSpec{Now: now, Number: s.number}
		if s.listed {
			spec.Entries = listed
		}
		sw.set(f.ca.CRL(t, spec))
		res := chkTCheck(t, c, leaf, f.ca.Cert, chkTPolicy())
		if res.Status != s.want {
			t.Fatalf("%s: Check = %s %s, want %s", s.name, res.Status, chkTTrace(res.Attempts), s.want)
		}
		if a := res.Attempts[len(res.Attempts)-1]; s.want == StatusInvalidEvidence && a.Detail != errCRLRollback.Error() {
			t.Errorf("%s: CRL attempt detail = %q, want %q", s.name, a.Detail, errCRLRollback)
		}
	}
	if got := hits.Load(); got != int64(len(steps)) {
		t.Errorf("CRL requests = %d, want %d", got, len(steps))
	}
}

func TestCheckRedirectToForeignHost(t *testing.T) {
	f := chkTNewFixture(t)
	crlHits := f.serve(t, chkTCRLHost, testpki.Redirect("http://foreign.test/a.crl"))
	foreignHits := f.serve(t, "foreign.test", f.crl(t, testpki.CRLSpec{}))
	leaf := f.leaf(t, nil, []string{chkTCRLURL})
	res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, chkTPolicy())

	if res.Status != StatusUnavailable || res.Method != "" {
		t.Fatalf("Check = %s via %q %s, want unavailable", res.Status, res.Method, chkTTrace(res.Attempts))
	}
	if len(res.Attempts) != 2 {
		t.Fatalf("attempts = %s, want one OCSP and one CRL attempt", chkTTrace(res.Attempts))
	}
	if c := res.Attempts[1]; c.Outcome != StatusUnavailable || !strings.Contains(c.Detail, ErrRedirectBlocked.Error()) {
		t.Errorf("CRL attempt = %s %q, want unavailable with %q", c.Outcome, c.Detail, ErrRedirectBlocked)
	}
	if crlHits.Load() != 1 || foreignHits.Load() != 0 {
		t.Errorf("requests = crl %d foreign %d, want 1 0", crlHits.Load(), foreignHits.Load())
	}
}

func TestCheckCAScope(t *testing.T) {
	const arlURL = "http://arl.test/arl.crl"
	cases := []struct {
		name       string
		ca         bool
		wantStatus Status
		wantMethod Method
	}{
		{"pinned intermediate accepts the ARL", true, StatusGood, MethodCRL},
		{"leaf rejects the ARL", false, StatusUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			root := f.ca
			mux := http.NewServeMux()
			mux.Handle("/arl.crl", testpki.Redirect("/current/arl.crl"))
			mux.Handle("/current/arl.crl", f.crl(t, testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{arlURL}, OnlyCA: true}}))
			arlHits := f.serve(t, "arl.test", mux)
			cdp := []testpki.DistributionPoint{{URIs: []string{arlURL}}}
			var cert *x509.Certificate
			if tc.ca {
				cert = root.Intermediate(t, "chkT AC DNIE", testpki.CertSpec{Now: f.base, CDP: cdp}).Cert
			} else {
				cert = root.Leaf(t, testpki.CertSpec{Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "chkT leaf")}, Now: f.base, CDP: cdp}).Cert
			}
			p := Policy{CRLHosts: []string{"arl.test"}, AllowCRL: true}
			res := chkTCheck(t, f.checker(t, Options{}), cert, root.Cert, p)

			if res.Status != tc.wantStatus || res.Method != tc.wantMethod {
				t.Fatalf("Check = %s via %q %s, want %s via %q", res.Status, res.Method, chkTTrace(res.Attempts), tc.wantStatus, tc.wantMethod)
			}
			if got := arlHits.Load(); got != 2 {
				t.Errorf("ARL host requests = %d, want 2 (302 then the ARL)", got)
			}
			if len(res.Attempts) != 2 || res.Attempts[1].URL != arlURL || res.Attempts[1].HTTPStatus != http.StatusOK {
				t.Errorf("attempts = %s, want the CRL attempt on %q with HTTP 200", chkTTrace(res.Attempts), arlURL)
			}
		})
	}

	// AC DNIE 005/006 shape: the CA names an empty, unscoped CRL first and
	// the ARL (the only list that carries CA revocations) second. A CA is
	// never good on the first list alone.
	const crlURL = "http://crl.test/CRL.crl"
	twoDP := []struct {
		name       string
		arl        func(t *testing.T, f *chkTFixture, cert *x509.Certificate) http.Handler
		wantStatus Status
		wantMethod Method
	}{
		{
			name: "ARL listing the CA wins over the empty CRL",
			arl: func(t *testing.T, f *chkTFixture, cert *x509.Certificate) http.Handler {
				return f.crl(t, testpki.CRLSpec{
					IDP:     &testpki.IDPSpec{URIs: []string{arlURL}, OnlyCA: true},
					Entries: []testpki.CRLEntry{{Serial: cert.SerialNumber, RevokedAt: f.base.Add(-time.Hour), Reason: 1}},
				})
			},
			wantStatus: StatusRevoked, wantMethod: MethodCRL,
		},
		{
			name: "ARL unavailable is never good on the CRL alone",
			arl: func(*testing.T, *chkTFixture, *x509.Certificate) http.Handler {
				return chkTStatus(http.StatusServiceUnavailable)
			},
			wantStatus: StatusUnavailable,
		},
	}
	for _, tc := range twoDP {
		t.Run("two DPs: "+tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			root := f.ca
			cdp := []testpki.DistributionPoint{{URIs: []string{crlURL}}, {URIs: []string{arlURL}}}
			cert := root.Intermediate(t, "chkT AC DNIE 005", testpki.CertSpec{Now: f.base, CDP: cdp}).Cert
			crlHits := f.serve(t, "crl.test", f.crl(t, testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURL}}}))
			arlHits := f.serve(t, "arl.test", tc.arl(t, f, cert))
			p := Policy{CRLHosts: []string{"crl.test", "arl.test"}, AllowCRL: true}
			res := chkTCheck(t, f.checker(t, Options{}), cert, root.Cert, p)

			if res.Status != tc.wantStatus || res.Method != tc.wantMethod {
				t.Fatalf("Check = %s via %q %s, want %s via %q", res.Status, res.Method, chkTTrace(res.Attempts), tc.wantStatus, tc.wantMethod)
			}
			if c, a := crlHits.Load(), arlHits.Load(); c != 1 || a != 1 {
				t.Errorf("requests: crl.test = %d, arl.test = %d, want 1 each", c, a)
			}
			if len(res.Attempts) != 3 || res.Attempts[1].URL != crlURL || res.Attempts[1].Outcome != StatusGood || res.Attempts[2].URL != arlURL {
				t.Errorf("attempts = %s, want OCSP unsupported, CRL good on %q, then %q", chkTTrace(res.Attempts), crlURL, arlURL)
			}
		})
	}
}

// TestCheckCAScopeUnsupportedARLCannotYieldGood: in the AC DNIE 005/006 shape
// the ARL URL must answer a CRL bound to it; anything the checker cannot use
// there keeps the CA from good even though CRL.crl answers good.
func TestCheckCAScopeUnsupportedARLCannotYieldGood(t *testing.T) {
	const (
		crlURL = "http://crl.test/CRL.crl"
		arlURL = "http://arl.test/ARL.crl"
	)
	arlIDP := func(s testpki.IDPSpec) *testpki.IDPSpec { s.URIs = []string{arlURL}; return &s }
	cases := []struct {
		name          string
		arl           testpki.CRLSpec
		crlNoIDP      bool // CRL.crl also served without an IDP
		arlNotAllowed bool // arl.test missing from CRLHosts: the ARL DP is never fetched
		wantStatus    Status
		wantARL       Status
	}{
		{"delta crl", testpki.CRLSpec{IDP: arlIDP(testpki.IDPSpec{OnlyCA: true}),
			ExtraExtensions: []pkix.Extension{{Id: oidExtDeltaCRLIndicator, Critical: true, Value: []byte{0x02, 0x01, 0x01}}}}, false, false, StatusUnavailable, StatusUnsupportedMethod},
		{"unknown critical extension", testpki.CRLSpec{IDP: arlIDP(testpki.IDPSpec{OnlyCA: true}),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 9}, Critical: true, Value: []byte{0x05, 0x00}}}}, false, false, StatusUnavailable, StatusUnsupportedMethod},
		{"user-only crl naming the arl", testpki.CRLSpec{IDP: arlIDP(testpki.IDPSpec{OnlyUser: true})}, false, false, StatusUnavailable, StatusUnsupportedMethod},
		{"user-only crl naming CRL.crl", testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURL}, OnlyUser: true}}, false, false, StatusInvalidEvidence, StatusInvalidEvidence},
		{"partial reasons", testpki.CRLSpec{IDP: arlIDP(testpki.IDPSpec{OnlyCA: true, OnlySomeReasons: true})}, false, false, StatusUnavailable, StatusUnsupportedMethod},
		{"empty crl without an idp", testpki.CRLSpec{}, false, false, StatusUnavailable, StatusUnsupportedMethod},
		{"idp without a name", testpki.CRLSpec{IDP: &testpki.IDPSpec{OnlyCA: true}}, false, false, StatusUnavailable, StatusUnsupportedMethod},
		{"unscoped crl at both urls", testpki.CRLSpec{}, true, false, StatusUnavailable, StatusUnsupportedMethod},
		{"arl host not allowlisted", testpki.CRLSpec{IDP: arlIDP(testpki.IDPSpec{OnlyCA: true})}, false, true, StatusUnavailable, StatusUnsupportedMethod},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			cdp := []testpki.DistributionPoint{{URIs: []string{crlURL}}, {URIs: []string{arlURL}}}
			cert := f.ca.Intermediate(t, "chkT AC DNIE 005", testpki.CertSpec{Now: f.base, CDP: cdp}).Cert
			crlSpec := testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURL}}}
			if tc.crlNoIDP {
				crlSpec = testpki.CRLSpec{}
			}
			f.serve(t, "crl.test", f.crl(t, crlSpec))
			arlHits := f.serve(t, "arl.test", f.crl(t, tc.arl))
			p := Policy{CRLHosts: []string{"crl.test", "arl.test"}, AllowCRL: true}
			wantURL, wantDetail := arlURL, ""
			if tc.arlNotAllowed {
				p.CRLHosts = []string{"crl.test"}
				wantURL, wantDetail = "", "no allowlisted CDP URL for a CA distribution point"
			}
			res := chkTCheck(t, f.checker(t, Options{}), cert, f.ca.Cert, p)

			if res.Status != tc.wantStatus || res.Method != "" {
				t.Fatalf("Check = %s via %q %s, want %s", res.Status, res.Method, chkTTrace(res.Attempts), tc.wantStatus)
			}
			a := res.Attempts[len(res.Attempts)-1]
			if a.URL != wantURL || a.Outcome != tc.wantARL || (wantDetail != "" && a.Detail != wantDetail) {
				t.Errorf("last attempt = %q %s %q, want %q %s", a.URL, a.Outcome, a.Detail, wantURL, tc.wantARL)
			}
			if tc.arlNotAllowed && arlHits.Load() != 0 {
				t.Errorf("arl.test requests = %d, want 0 (not allowlisted)", arlHits.Load())
			}
		})
	}

	// One DP (the AC DNIE 004 shape): a complete CRL without an IDP still
	// covers the CA.
	t.Run("single dp without an idp", func(t *testing.T) {
		f := chkTNewFixture(t)
		cert := f.ca.Intermediate(t, "chkT AC DNIE 004", testpki.CertSpec{Now: f.base, CDP: []testpki.DistributionPoint{{URIs: []string{arlURL}}}}).Cert
		f.serve(t, "arl.test", f.crl(t, testpki.CRLSpec{}))
		res := chkTCheck(t, f.checker(t, Options{}), cert, f.ca.Cert, Policy{CRLHosts: []string{"arl.test"}, AllowCRL: true})
		if res.Status != StatusGood || res.Method != MethodCRL {
			t.Fatalf("Check = %s via %q %s, want good via crl", res.Status, res.Method, chkTTrace(res.Attempts))
		}
	})
}

// TestCheckCAScopeMirrorDPs: DPs naming one CRL path on several hosts
// (UANATACA, BEWOR, inDenova, DIGITEL) are mirrors of one CRL, so a complete
// CRL without an IDP covers the CA; DPs naming different paths (the AC DNIE
// 005/006 shape) or queries still need a CRL bound to each.
func TestCheckCAScopeMirrorDPs(t *testing.T) {
	cases := []struct {
		name       string
		uris       []string // one DP each, served by the host of each URI
		revoked    bool     // the CRL lists the CA
		wantStatus Status
		wantMethod Method
	}{
		{"mirrors of one path", []string{"http://arl1.test/arl.crl", "http://arl2.test/arl.crl"}, false, StatusGood, MethodCRL},
		{"mirrors listing the CA", []string{"http://arl1.test/arl.crl", "http://arl2.test/arl.crl"}, true, StatusRevoked, MethodCRL},
		{"two paths stay strict", []string{"http://arl1.test/CRL.crl", "http://arl2.test/arl.crl"}, false, StatusUnavailable, ""},
		{"two paths on one host stay strict", []string{"http://arl1.test/CRL.crl", "http://arl1.test/arl.crl"}, false, StatusUnavailable, ""},
		{"two queries stay strict", []string{"http://arl1.test/get?crl=1", "http://arl2.test/get?crl=2"}, false, StatusUnavailable, ""},
		{"an ldap-only dp is another crl", []string{"ldap://arl1.test/cn=ARL?certificateRevocationList", "http://arl2.test/arl.crl"}, false, StatusUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			var cdp []testpki.DistributionPoint
			for _, u := range tc.uris {
				cdp = append(cdp, testpki.DistributionPoint{URIs: []string{u}})
			}
			cert := f.ca.Intermediate(t, "chkT UANATACA CA1", testpki.CertSpec{Now: f.base, CDP: cdp}).Cert
			var spec testpki.CRLSpec
			if tc.revoked {
				spec.Entries = []testpki.CRLEntry{{Serial: cert.SerialNumber, RevokedAt: f.base.Add(-time.Hour), Reason: 1}}
			}
			f.serve(t, "arl1.test", f.crl(t, spec))
			f.serve(t, "arl2.test", f.crl(t, spec))
			p := Policy{CRLHosts: []string{"arl1.test", "arl2.test"}, AllowCRL: true}
			res := chkTCheck(t, f.checker(t, Options{}), cert, f.ca.Cert, p)
			if res.Status != tc.wantStatus || res.Method != tc.wantMethod {
				t.Fatalf("Check = %s via %q %s, want %s via %q", res.Status, res.Method, chkTTrace(res.Attempts), tc.wantStatus, tc.wantMethod)
			}
			if tc.wantStatus == StatusGood && len(res.Attempts) != 3 {
				t.Errorf("attempts = %s, want OCSP unsupported then both mirrors good", chkTTrace(res.Attempts))
			}
		})
	}
}

// TestCheckRealDNIeCRLs runs the real AC RAIZ DNIE 2 CRL and ARL through the
// checker for AC DNIE 004 (ARL only) and 005 (CRL.crl then ARL.crl).
func TestCheckRealDNIeCRLs(t *testing.T) {
	n := testpki.NewNet()
	mux := http.NewServeMux()
	mux.Handle("/dnie/crls/CRL.crl", testpki.Bytes("application/pkix-crl", crlTReadFile(t, "dnie-crl.crl")))
	mux.Handle("/dnie/crls/ARL.crl", testpki.Bytes("application/pkix-crl", crlTReadFile(t, "dnie-arl.crl")))
	n.Serve(t, "pki.policia.es", mux)
	root := crlTReadCert(t, "ac-raiz-dnie-2.pem")
	c, err := NewChecker(Options{DialContext: n.DialContext, Now: func() time.Time { return crlTNow }, Logger: slog.New(&chkTLogs{})})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{CRLHosts: []string{"pki.policia.es"}, AllowCRL: true}
	for _, tc := range []struct {
		cert     string
		attempts int
	}{{"ac-dnie-004.pem", 2}, {"ac-dnie-005.pem", 3}} {
		t.Run(tc.cert, func(t *testing.T) {
			res := chkTCheck(t, c, crlTReadCert(t, tc.cert), root, p)
			if res.Status != StatusGood || res.Method != MethodCRL || len(res.Attempts) != tc.attempts {
				t.Errorf("Check = %s via %q %s, want good via crl after %d attempts", res.Status, res.Method, chkTTrace(res.Attempts), tc.attempts)
			}
		})
	}
}

func TestCheckAttempts(t *testing.T) {
	type wantAttempt struct {
		method      Method
		url         string
		http        int
		outcome     Status
		responder   bool // ResponderSubject is the delegated responder's subject
		nonceSent   bool
		nonceEchoed bool
		updates     bool // ThisUpdate/NextUpdate set to the evidence's values
	}
	cases := []struct {
		name  string
		nonce bool
		ocsp  func(*testing.T, *chkTFixture) http.Handler
		want  []wantAttempt
	}{
		{
			name: "ocsp good with nonce", nonce: true,
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler { return f.ocsp.Handler(t) },
			want: []wantAttempt{{MethodOCSP, chkTOCSPURL, 200, StatusGood, true, true, true, true}},
		},
		{
			name: "ocsp good without nonce", nonce: false,
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler { return f.ocsp.Handler(t) },
			want: []wantAttempt{{MethodOCSP, chkTOCSPURL, 200, StatusGood, true, false, false, true}},
		},
		{
			name: "ocsp nonce not echoed then crl", nonce: true,
			ocsp: func(t *testing.T, f *chkTFixture) http.Handler {
				f.answer(chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.Nonce = testpki.NonceOmit }))
				return f.ocsp.Handler(t)
			},
			want: []wantAttempt{
				{MethodOCSP, chkTOCSPURL, 200, StatusInvalidEvidence, true, true, false, true},
				{MethodCRL, chkTCRLURL, 200, StatusGood, false, false, false, true},
			},
		},
		{
			name: "ocsp 503 then crl", nonce: true,
			ocsp: func(*testing.T, *chkTFixture) http.Handler { return chkTStatus(http.StatusServiceUnavailable) },
			want: []wantAttempt{
				{MethodOCSP, chkTOCSPURL, 503, StatusUnavailable, false, true, false, false},
				{MethodCRL, chkTCRLURL, 200, StatusGood, false, false, false, true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			ocspSpec := chkTGood(f.base)
			crlSpec := testpki.CRLSpec{ThisUpdate: f.base.Add(-2 * time.Hour), NextUpdate: f.base.Add(6 * time.Hour)}
			f.serve(t, chkTOCSPHost, tc.ocsp(t, f))
			f.serve(t, chkTCRLHost, f.crl(t, crlSpec))
			leaf := f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL})
			p := chkTPolicy()
			p.OCSPNonce = tc.nonce
			res := chkTCheck(t, f.checker(t, Options{}), leaf, f.ca.Cert, p)

			if len(res.Attempts) != len(tc.want) {
				t.Fatalf("attempts = %s, want %d", chkTTrace(res.Attempts), len(tc.want))
			}
			for i, w := range tc.want {
				a := res.Attempts[i]
				if a.Method != w.method || a.URL != w.url || a.HTTPStatus != w.http || a.Outcome != w.outcome || a.FromCache {
					t.Errorf("attempt %d = %s %q http %d %s cache %v, want %s %q http %d %s cache false",
						i, a.Method, a.URL, a.HTTPStatus, a.Outcome, a.FromCache, w.method, w.url, w.http, w.outcome)
				}
				if a.Duration <= 0 {
					t.Errorf("attempt %d duration = %v, want > 0", i, a.Duration)
				}
				if a.Detail == "" {
					t.Errorf("attempt %d detail is empty", i)
				}
				wantResponder := ""
				if w.responder {
					wantResponder = f.ocsp.Responder.Cert.Subject.String()
				}
				if a.ResponderSubject != wantResponder {
					t.Errorf("attempt %d responder = %q, want %q", i, a.ResponderSubject, wantResponder)
				}
				if a.NonceSent != w.nonceSent || a.NonceEchoed != w.nonceEchoed {
					t.Errorf("attempt %d nonce sent/echoed = %v/%v, want %v/%v", i, a.NonceSent, a.NonceEchoed, w.nonceSent, w.nonceEchoed)
				}
				var wantThis, wantNext, wantProduced time.Time
				switch {
				case w.updates && w.method == MethodOCSP:
					wantThis, wantNext, wantProduced = ocspSpec.ThisUpdate, ocspSpec.NextUpdate, ocspSpec.ThisUpdate
				case w.updates:
					wantThis, wantNext = crlSpec.ThisUpdate, crlSpec.NextUpdate
				}
				if !a.ThisUpdate.Equal(wantThis) || !a.NextUpdate.Equal(wantNext) {
					t.Errorf("attempt %d thisUpdate/nextUpdate = %v/%v, want %v/%v", i, a.ThisUpdate, a.NextUpdate, wantThis, wantNext)
				}
				if w.method == MethodOCSP && w.http == http.StatusOK && !a.ProducedAt.Equal(wantProduced) {
					t.Errorf("attempt %d producedAt = %v, want %v", i, a.ProducedAt, wantProduced)
				}
			}
			// The 503 case never reaches the OCSP server.
			if reqs := f.ocsp.Requests(); len(reqs) > 0 {
				r := reqs[0]
				switch {
				case tc.nonce && len(r.Nonce) != 2+NonceLength:
					t.Errorf("request nonce extnValue = %d bytes, want OCTET STRING of %d", len(r.Nonce), NonceLength)
				case !tc.nonce && r.Nonce != nil:
					t.Errorf("request nonce = %x, want none", r.Nonce)
				}
			}
		})
	}

	t.Run("fresh nonce per request", func(t *testing.T) {
		f := chkTNewFixture(t)
		f.answer(chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.Status = testpki.Unknown })) // never cached
		f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
		leaf := f.leaf(t, []string{chkTOCSPURL}, nil)
		c := f.checker(t, Options{})
		p := Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true}
		for range 3 {
			chkTCheck(t, c, leaf, f.ca.Cert, p)
		}
		seen := make(map[string]bool)
		for _, r := range f.ocsp.Requests() {
			if len(r.Nonce) != 2+NonceLength || seen[string(r.Nonce)] {
				t.Errorf("request nonce %x: want a fresh %d-byte nonce", r.Nonce, NonceLength)
			}
			seen[string(r.Nonce)] = true
		}
		if len(seen) != 3 {
			t.Errorf("distinct nonces = %d, want 3", len(seen))
		}
	})
}

func TestCheckMisuse(t *testing.T) {
	f := chkTNewFixture(t)
	ocspHits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
	leaf := f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL})
	noSerial, noRaw := *leaf, *f.ca.Cert
	noSerial.SerialNumber, noRaw.Raw = nil, nil
	c := f.checker(t, Options{})
	cases := []struct {
		name   string
		cert   *x509.Certificate
		issuer *x509.Certificate
		policy Policy
	}{
		{"nil cert", nil, f.ca.Cert, chkTPolicy()},
		{"nil issuer", leaf, nil, chkTPolicy()},
		{"empty policy", leaf, f.ca.Cert, Policy{}},
		{"uppercase host", leaf, f.ca.Cert, Policy{OCSPHosts: []string{"OCSP.test"}}},
		{"crl allowed without hosts", leaf, f.ca.Cert, Policy{OCSPHosts: []string{chkTOCSPHost}, AllowCRL: true}},
		{"cert without serial", &noSerial, f.ca.Cert, chkTPolicy()},
		{"issuer without raw DER", leaf, &noRaw, chkTPolicy()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := c.Check(t.Context(), tc.cert, tc.issuer, tc.policy)
			if err == nil {
				t.Fatalf("Check error = nil (result %s), want an error", res.Status)
			}
			if res.Status != "" || len(res.Attempts) != 0 {
				t.Errorf("Check result = %s with %d attempts, want the zero Result", res.Status, len(res.Attempts))
			}
		})
	}
	if got := ocspHits.Load(); got != 0 {
		t.Errorf("OCSP requests = %d, want 0", got)
	}
}

func TestNewCheckerOptions(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		wantErr string // "" = accepted
	}{
		{"zero values take the defaults", Options{}, ""},
		{"positive values", Options{CRLCacheBytes: 1, OCSPCacheEntries: 1, OCSPTimeout: time.Millisecond, CRLTimeout: time.Millisecond}, ""},
		{"negative CRLCacheBytes", Options{CRLCacheBytes: -1}, "CRLCacheBytes"},
		{"negative OCSPCacheEntries", Options{OCSPCacheEntries: -1}, "OCSPCacheEntries"},
		{"negative OCSPTimeout", Options{OCSPTimeout: -time.Second}, "OCSPTimeout"},
		{"negative CRLTimeout", Options{CRLTimeout: -time.Second}, "CRLTimeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewChecker(tc.opts)
			if tc.wantErr == "" {
				if err != nil || c == nil {
					t.Fatalf("NewChecker(%+v) = %v, %v, want a Checker and nil", tc.opts, c, err)
				}
				return
			}
			if err == nil || c != nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewChecker(%+v) = %v, %v, want nil and an error naming %s", tc.opts, c, err, tc.wantErr)
			}
		})
	}
}

func TestCheckConcurrent(t *testing.T) {
	f := chkTNewFixture(t)
	f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
	f.serve(t, "ocsp-down.test", chkTStatus(http.StatusServiceUnavailable))
	leaves := []*x509.Certificate{
		f.leaf(t, []string{chkTOCSPURL}, []string{chkTCRLURL}),
		f.leaf(t, []string{"http://ocsp-down.test/"}, []string{chkTCRLURL}),
		f.leaf(t, []string{"http://ocsp-down.test/"}, []string{chkTCRLURL}),
	}
	f.serve(t, chkTCRLHost, f.crl(t, testpki.CRLSpec{Entries: []testpki.CRLEntry{
		{Serial: leaves[2].SerialNumber, RevokedAt: f.base.Add(-time.Hour), Reason: 1},
	}}))
	want := []struct {
		status Status
		method Method
	}{{StatusGood, MethodOCSP}, {StatusGood, MethodCRL}, {StatusRevoked, MethodCRL}}
	p := chkTPolicy()
	p.OCSPHosts = []string{chkTOCSPHost, "ocsp-down.test"}
	c := f.checker(t, Options{})

	const n = 50
	results := make([]Result, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			results[i], errs[i] = c.Check(t.Context(), leaves[i%len(leaves)], f.ca.Cert, p)
		})
	}
	wg.Wait()
	for i := range n {
		w := want[i%len(leaves)]
		if errs[i] != nil || results[i].Status != w.status || results[i].Method != w.method {
			t.Errorf("Check %d = %s via %q, %v, want %s via %q", i, results[i].Status, results[i].Method, errs[i], w.status, w.method)
		}
	}
}
