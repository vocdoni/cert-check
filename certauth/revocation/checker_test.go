package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
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
		wantWarn     bool
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
			want: StatusInvalidEvidence, wantCRLHits: 1, wantWarn: true, wantAttempts: 2,
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
			want: StatusInvalidEvidence, wantCRLHits: 1, wantWarn: true, wantAttempts: 2,
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
			if !tc.wantWarn {
				if len(warns) != 0 {
					t.Errorf("warn records = %d, want 0", len(warns))
				}
				return
			}
			if len(warns) != 1 {
				t.Fatalf("warn records = %d, want 1", len(warns))
			}
			got := chkTAttrs(warns[0])
			want := map[string]string{"issuer": f.ca.Cert.Subject.String(), "detail": res.Detail}
			if len(got) != len(want) || got["issuer"] != want["issuer"] || got["detail"] != want["detail"] {
				t.Errorf("warn attrs = %v, want exactly %v", got, want)
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
