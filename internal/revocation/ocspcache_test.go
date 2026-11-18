package revocation

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// chkTReuseCase checks one leaf at the fixture base time and again at base+at,
// with the OCSP server answering spec(now) each time.
type chkTReuseCase struct {
	name    string
	spec    func(now time.Time) testpki.OCSPSpec
	at      time.Duration
	want    Status
	wantHit bool
}

func chkTRunReuse(t *testing.T, tc chkTReuseCase) {
	t.Helper()
	chkTRunReusePolicy(t, tc, Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true})
}

// chkTRunReusePolicy is chkTRunReuse under policy p.
func chkTRunReusePolicy(t *testing.T, tc chkTReuseCase, p Policy) {
	t.Helper()
	f := chkTNewFixture(t)
	f.answer(tc.spec)
	hits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
	leaf := f.leaf(t, []string{chkTOCSPURL}, nil)
	c := f.checker(t, Options{})

	first := chkTCheck(t, c, leaf, f.ca.Cert, p)
	if first.Status != tc.want || hits.Load() != 1 {
		t.Fatalf("first Check = %s after %d requests %s, want %s after 1", first.Status, hits.Load(), chkTTrace(first.Attempts), tc.want)
	}
	f.clock.Set(f.base.Add(tc.at))
	second := chkTCheck(t, c, leaf, f.ca.Cert, p)
	if second.Status != tc.want || second.Method != MethodOCSP {
		t.Fatalf("Check at +%v = %s via %q %s, want %s via ocsp", tc.at, second.Status, second.Method, chkTTrace(second.Attempts), tc.want)
	}
	wantHits := int64(2)
	if tc.wantHit {
		wantHits = 1
	}
	if got := hits.Load(); got != wantHits {
		t.Errorf("OCSP requests after the check at +%v = %d, want %d", tc.at, got, wantHits)
	}
	if len(second.Attempts) != 1 || second.Attempts[0].FromCache != tc.wantHit {
		t.Errorf("attempts at +%v = %s, want one with FromCache %v", tc.at, chkTTrace(second.Attempts), tc.wantHit)
	}
	if !second.CheckedAt.Equal(f.base.Add(tc.at)) {
		t.Errorf("CheckedAt = %v, want %v", second.CheckedAt, f.base.Add(tc.at))
	}
	if tc.wantHit {
		// A cache hit reports the cached evidence unchanged.
		if !second.ThisUpdate.Equal(first.ThisUpdate) || !second.NextUpdate.Equal(first.NextUpdate) ||
			!second.RevokedAt.Equal(first.RevokedAt) || second.Reason != first.Reason || second.Source != first.Source {
			t.Errorf("cached result = %v %v %v %d %q, want the first answer %v %v %v %d %q",
				second.ThisUpdate, second.NextUpdate, second.RevokedAt, second.Reason, second.Source,
				first.ThisUpdate, first.NextUpdate, first.RevokedAt, first.Reason, first.Source)
		}
		// It also reports the full URL, as a fresh attempt does.
		if got := second.Attempts[0].URL; got != chkTOCSPURL {
			t.Errorf("cached attempt URL = %q, want %q", got, chkTOCSPURL)
		}
	}
}

// chkTAnswer is an OCSP answer with thisUpdate and nextUpdate (0 = absent)
// relative to the time of the request.
func chkTAnswer(status testpki.CertStatus, thisUpdate, nextUpdate time.Duration) func(time.Time) testpki.OCSPSpec {
	return func(now time.Time) testpki.OCSPSpec {
		s := testpki.OCSPSpec{Status: status, ThisUpdate: now.Add(thisUpdate)}
		if nextUpdate != 0 {
			s.NextUpdate = now.Add(nextUpdate)
		}
		if status == testpki.Revoked {
			s.RevokedAt, s.Reason = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), 1
		}
		return s
	}
}

func TestOCSPCacheGood(t *testing.T) {
	good := func(thisUpdate, nextUpdate time.Duration) func(time.Time) testpki.OCSPSpec {
		return chkTAnswer(testpki.Good, thisUpdate, nextUpdate)
	}
	cases := []chkTReuseCase{
		{"reused at thisUpdate+4m", good(0, time.Hour), 4 * time.Minute, StatusGood, true},
		{"not reused at thisUpdate+5m", good(0, time.Hour), 5 * time.Minute, StatusGood, false},
		{"not reused at thisUpdate+6m", good(0, time.Hour), 6 * time.Minute, StatusGood, false},
		{"without nextUpdate reused at +4m", good(0, 0), 4 * time.Minute, StatusGood, true},
		{"without nextUpdate not reused at +6m", good(0, 0), 6 * time.Minute, StatusGood, false},
		{"near nextUpdate reused while age < nextUpdate-now", good(0, 3*time.Minute), time.Minute, StatusGood, true},
		{"near nextUpdate not reused once age >= nextUpdate-now", good(0, 3*time.Minute), 2 * time.Minute, StatusGood, false},
		{"not reused after nextUpdate", good(0, 3*time.Minute), 4 * time.Minute, StatusGood, false},
		{"old thisUpdate refetched", good(-10*time.Minute, time.Hour), time.Second, StatusGood, false},
		{"thisUpdate within the clock skew reused", good(2*time.Minute, time.Hour), time.Minute, StatusGood, true},
		{"clock moved back within the skew reused", good(0, time.Hour), -4 * time.Minute, StatusGood, true},
		{"clock moved back beyond the skew refetched", good(0, time.Hour), -6 * time.Minute, StatusGood, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { chkTRunReuse(t, tc) })
	}
}

func TestOCSPCacheHonoursPolicyMaxAge(t *testing.T) {
	p := Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true, MaxAgeWithoutNextUpdate: time.Minute}
	cases := []chkTReuseCase{
		{"without nextUpdate and MaxAge 1m reused at +30s", chkTAnswer(testpki.Good, 0, 0), 30 * time.Second, StatusGood, true},
		{"without nextUpdate and MaxAge 1m not reused at +2m", chkTAnswer(testpki.Good, 0, 0), 2 * time.Minute, StatusGood, false},
		{"with nextUpdate MaxAge does not apply at +2m", chkTAnswer(testpki.Good, 0, time.Hour), 2 * time.Minute, StatusGood, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { chkTRunReusePolicy(t, tc, p) })
	}
}

func TestOCSPCacheBoundedBySignerValidity(t *testing.T) {
	cases := []struct {
		name    string
		at      time.Duration
		want    Status
		wantHit bool
	}{
		{"reused just before the responder expires", 2*time.Minute - time.Second, StatusGood, true},
		{"not reused once the responder expired", 2*time.Minute + time.Second, StatusInvalidEvidence, false},
		{"not reused before the responder is valid", -2 * time.Minute, StatusInvalidEvidence, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			f.ocsp = testpki.NewOCSPServer(f.ca, f.ca.OCSPResponder(t, testpki.CertSpec{
				Now: f.base, NotBefore: f.base.Add(-time.Minute), NotAfter: f.base.Add(2 * time.Minute),
			}))
			f.answer(chkTAnswer(testpki.Good, 0, time.Hour))
			hits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
			leaf := f.leaf(t, []string{chkTOCSPURL}, nil)
			c := f.checker(t, Options{})
			p := Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true}
			if res := chkTCheck(t, c, leaf, f.ca.Cert, p); res.Status != StatusGood {
				t.Fatalf("first Check = %s %s, want good", res.Status, chkTTrace(res.Attempts))
			}
			f.clock.Set(f.base.Add(tc.at))
			res := chkTCheck(t, c, leaf, f.ca.Cert, p)
			wantHits := int64(2)
			if tc.wantHit {
				wantHits = 1
			}
			if res.Status != tc.want || len(res.Attempts) != 1 || res.Attempts[0].FromCache != tc.wantHit || hits.Load() != wantHits {
				t.Errorf("Check at %+v = %s %s after %d requests, want %s, FromCache %v, %d requests",
					tc.at, res.Status, chkTTrace(res.Attempts), hits.Load(), tc.want, tc.wantHit, wantHits)
			}
		})
	}
}

func TestOCSPCacheCrossPolicy(t *testing.T) {
	type step struct {
		name       string
		p          Policy
		wantCache  bool
		wantSource string
		wantEchoed bool
	}
	run := func(t *testing.T, f *chkTFixture, leaf *x509.Certificate, steps []step) {
		t.Helper()
		c := f.checker(t, Options{})
		for _, s := range steps {
			res := chkTCheck(t, c, leaf, f.ca.Cert, s.p)
			if res.Status != StatusGood || len(res.Attempts) != 1 || res.Attempts[0].FromCache != s.wantCache ||
				res.Attempts[0].NonceEchoed != s.wantEchoed || res.Source != s.wantSource {
				t.Errorf("%s: Check = %s from %q %s, NonceEchoed %v; want good from %q, FromCache %v, NonceEchoed %v",
					s.name, res.Status, res.Source, chkTTrace(res.Attempts), res.Attempts[0].NonceEchoed,
					s.wantSource, s.wantCache, s.wantEchoed)
			}
		}
	}

	t.Run("nonce required", func(t *testing.T) {
		f := chkTNewFixture(t)
		hits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
		leaf := f.leaf(t, []string{chkTOCSPURL}, nil)
		noNonce := Policy{OCSPHosts: []string{chkTOCSPHost}}
		nonce := Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true}
		run(t, f, leaf, []step{
			{"nonce-less policy fetches", noNonce, false, chkTOCSPHost, false},
			{"nonce policy does not reuse an answer without a nonce", nonce, false, chkTOCSPHost, true},
			{"nonce policy reuses the echoed answer", nonce, true, chkTOCSPHost, false},
			{"nonce-less policy reuses the echoed answer", noNonce, true, chkTOCSPHost, false},
		})
		if got := hits.Load(); got != 2 {
			t.Errorf("OCSP requests = %d, want 2", got)
		}
	})

	t.Run("source host not allowlisted", func(t *testing.T) {
		f := chkTNewFixture(t)
		hits1 := f.serve(t, "ocsp1.test", f.ocsp.Handler(t))
		hits2 := f.serve(t, "ocsp2.test", f.ocsp.Handler(t))
		leaf := f.leaf(t, []string{"http://ocsp1.test/", "http://ocsp2.test/"}, nil)
		both := Policy{OCSPHosts: []string{"ocsp1.test", "ocsp2.test"}}
		only2 := Policy{OCSPHosts: []string{"ocsp2.test"}}
		run(t, f, leaf, []step{
			{"both hosts allowed: fetched from ocsp1", both, false, "ocsp1.test", false},
			{"ocsp1 not allowed: answer from ocsp1 not reused", only2, false, "ocsp2.test", false},
			{"ocsp2 answer reused", only2, true, "ocsp2.test", false},
		})
		if hits1.Load() != 1 || hits2.Load() != 1 {
			t.Errorf("OCSP requests = %d and %d, want 1 and 1", hits1.Load(), hits2.Load())
		}
	})
}

// TestOCSPCacheEntryRetainsNoResponse pads the unsigned certs field of a
// valid response with a 60 KiB certificate, as an on-path attacker can: a
// cached entry must not keep the response (or any slice of it) alive.
func TestOCSPCacheEntryRetainsNoResponse(t *testing.T) {
	p := ocspTNewPKI(t)
	pad := testpki.NewRoot(t, "ocspT padding", testpki.CertSpec{
		Now: p.now, ExtraExtensions: []pkix.Extension{{Id: ocspTOIDExtA, Value: make([]byte, 60<<10)}},
	})
	der := p.build(t, p.req, func(s *testpki.OCSPSpec) { s.Certs = []*x509.Certificate{p.resp.Cert, pad.Cert} })
	if len(der) < 60<<10 || len(der) > MaxOCSPResponse {
		t.Fatalf("padded response = %d bytes, want 60 KiB..%d", len(der), MaxOCSPResponse)
	}
	const n = 128
	c := newOCSPCache(n)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range n {
		r, err := ParseResponse(bytes.Clone(der))
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		ev, st, detail := VerifyOCSP(OCSPInput{Response: r, Want: p.want, Issuer: p.ca.Cert, Now: p.now, MaxAge: ocspTMaxAge})
		if st != StatusGood {
			t.Fatalf("VerifyOCSP = %s (%s), want good", st, detail)
		}
		c.put(strconv.Itoa(i), newOCSPItem(chkTOCSPURL, st, ev))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if c.lru.Len() != n {
		t.Fatalf("entries = %d, want %d", c.lru.Len(), n)
	}
	if perEntry := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n; perEntry > 4<<10 {
		t.Errorf("retained heap per entry = %d bytes, want <= 4 KiB (the %d-byte response must not stay reachable)", perEntry, len(der))
	}
}

func TestOCSPCacheRevoked(t *testing.T) {
	revoked := func(nextUpdate time.Duration) func(time.Time) testpki.OCSPSpec {
		return chkTAnswer(testpki.Revoked, 0, nextUpdate)
	}
	cases := []chkTReuseCase{
		{"reused at +30m", revoked(time.Hour), 30 * time.Minute, StatusRevoked, true},
		{"reused just before nextUpdate", revoked(time.Hour), time.Hour - time.Second, StatusRevoked, true},
		{"not reused at nextUpdate", revoked(time.Hour), time.Hour, StatusRevoked, false},
		{"not cached without nextUpdate", revoked(0), time.Second, StatusRevoked, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { chkTRunReuse(t, tc) })
	}
}

func TestOCSPCacheNeverUnknownOrInvalid(t *testing.T) {
	cases := []struct {
		name string
		spec func(time.Time) testpki.OCSPSpec // nil: the server answers 503
		want Status
	}{
		{"unknown", chkTAnswer(testpki.Unknown, 0, time.Hour), StatusUnknown},
		{"invalid signature", chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.CorruptSignature = true }), StatusInvalidEvidence},
		{"nonce not echoed", chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.Nonce = testpki.NonceOmit }), StatusInvalidEvidence},
		{"wrong CertID", chkTWith(func(_ time.Time, s *testpki.OCSPSpec) { s.SerialOverride = big.NewInt(4242) }), StatusInvalidEvidence},
		{"stale", chkTWith(func(now time.Time, s *testpki.OCSPSpec) {
			s.ThisUpdate, s.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Hour)
		}), StatusStale},
		{"tryLater", func(time.Time) testpki.OCSPSpec { return testpki.OCSPSpec{ResponseStatus: 3} }, StatusUnavailable},
		{"http 503", nil, StatusUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := chkTNewFixture(t)
			h := chkTStatus(http.StatusServiceUnavailable)
			if tc.spec != nil {
				f.answer(tc.spec)
				h = f.ocsp.Handler(t)
			}
			hits := f.serve(t, chkTOCSPHost, h)
			leaf := f.leaf(t, []string{chkTOCSPURL}, nil)
			c := f.checker(t, Options{})
			p := Policy{OCSPHosts: []string{chkTOCSPHost}, OCSPNonce: true}
			for i := range 2 {
				res := chkTCheck(t, c, leaf, f.ca.Cert, p)
				if res.Status != tc.want || len(res.Attempts) != 1 || res.Attempts[0].FromCache {
					t.Errorf("Check %d = %s %s, want %s from one fetched attempt", i, res.Status, chkTTrace(res.Attempts), tc.want)
				}
			}
			if got := hits.Load(); got != 2 {
				t.Errorf("OCSP requests = %d, want 2 (nothing cached)", got)
			}
			c.ocsp.mu.Lock()
			n := len(c.ocsp.items)
			c.ocsp.mu.Unlock()
			if n != 0 {
				t.Errorf("OCSP cache entries = %d, want 0", n)
			}
		})
	}

	t.Run("put ignores non-final statuses", func(t *testing.T) {
		now := time.Now()
		c := newOCSPCache(DefaultOCSPCacheEntries)
		for _, st := range []Status{StatusUnknown, StatusUnavailable, StatusStale, StatusInvalidEvidence, StatusUnsupportedMethod} {
			c.put(string(st), chkTItem(st, now))
			if _, ok := c.get(string(st), now, chkTItemPolicy); ok {
				t.Errorf("get after put(%s) = hit, want miss", st)
			}
		}
		if n := len(c.items); n != 0 {
			t.Errorf("entries = %d, want 0", n)
		}
	})
}

// chkTItem is a cache entry with status st: thisUpdate now, nextUpdate
// now+1h, a signer valid around now, served from chkTOCSPURL.
func chkTItem(st Status, now time.Time) ocspItem {
	return ocspItem{
		status: st, thisUpdate: now, nextUpdate: now.Add(time.Hour), reason: -1,
		signerNotBefore: now.Add(-time.Hour), signerNotAfter: now.Add(time.Hour),
		url: chkTOCSPURL, source: chkTOCSPHost,
	}
}

// chkTItemPolicy accepts chkTItem entries.
var chkTItemPolicy = Policy{OCSPHosts: []string{chkTOCSPHost}}

func TestOCSPCacheKeyIncludesIssuer(t *testing.T) {
	f := chkTNewFixture(t)
	other := testpki.NewRoot(t, "chkT other CA", testpki.CertSpec{Now: f.base})
	otherOCSP := testpki.NewOCSPServer(other, other.OCSPResponder(t, testpki.CertSpec{Now: f.base}))
	otherOCSP.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
		return chkTAnswer(testpki.Revoked, -time.Minute, time.Hour)(f.base)
	})
	hits := f.serve(t, "ocsp1.test", f.ocsp.Handler(t))
	otherHits := f.serve(t, "ocsp2.test", otherOCSP.Handler(t))

	serial := big.NewInt(0x5ca1ab1e)
	subject := testpki.Name{testpki.UTF8(testpki.OIDCommonName, "chkT leaf")}
	leaf := f.ca.Leaf(t, testpki.CertSpec{Subject: subject, Serial: serial, Now: f.base, OCSPServers: []string{"http://ocsp1.test/"}}).Cert
	otherLeaf := other.Leaf(t, testpki.CertSpec{Subject: subject, Serial: serial, Now: f.base, OCSPServers: []string{"http://ocsp2.test/"}}).Cert
	c := f.checker(t, Options{})
	p := Policy{OCSPHosts: []string{"ocsp1.test", "ocsp2.test"}, OCSPNonce: true}

	if res := chkTCheck(t, c, leaf, f.ca.Cert, p); res.Status != StatusGood {
		t.Fatalf("Check(first issuer) = %s %s, want good", res.Status, chkTTrace(res.Attempts))
	}
	if res := chkTCheck(t, c, otherLeaf, other.Cert, p); res.Status != StatusRevoked || res.Attempts[0].FromCache {
		t.Fatalf("Check(second issuer, same serial) = %s %s, want revoked from a fetch", res.Status, chkTTrace(res.Attempts))
	}
	if res := chkTCheck(t, c, leaf, f.ca.Cert, p); res.Status != StatusGood || !res.Attempts[0].FromCache {
		t.Errorf("Check(first issuer) again = %s %s, want good from the cache", res.Status, chkTTrace(res.Attempts))
	}
	if hits.Load() != 1 || otherHits.Load() != 1 {
		t.Errorf("OCSP requests = %d and %d, want 1 and 1", hits.Load(), otherHits.Load())
	}
}

func TestOCSPCacheBound(t *testing.T) {
	t.Run("lru eviction at the entry limit", func(t *testing.T) {
		now := time.Now()
		good := chkTItem(StatusGood, now)
		c := newOCSPCache(2)
		c.put("a", good)
		c.put("b", good)
		if _, ok := c.get("a", now, chkTItemPolicy); !ok { // a becomes the most recently used
			t.Fatal("get(a) = miss, want hit")
		}
		c.put("c", good)
		for key, want := range map[string]bool{"a": true, "b": false, "c": true} {
			if _, ok := c.get(key, now, chkTItemPolicy); ok != want {
				t.Errorf("get(%s) hit = %v, want %v", key, ok, want)
			}
		}
		if n := c.lru.Len(); n != 2 || len(c.items) != 2 {
			t.Errorf("entries = %d list, %d map, want 2 and 2", n, len(c.items))
		}
		c.put("c", chkTItem(StatusRevoked, now)) // replacing keeps one entry per key
		if it, ok := c.get("c", now, chkTItemPolicy); !ok || it.status != StatusRevoked || c.lru.Len() != 2 {
			t.Errorf("get(c) after replace = %v %v with %d entries, want revoked with 2 entries", it.status, ok, c.lru.Len())
		}
	})

	t.Run("checker honours OCSPCacheEntries", func(t *testing.T) {
		f := chkTNewFixture(t)
		hits := f.serve(t, chkTOCSPHost, f.ocsp.Handler(t))
		a := f.leaf(t, []string{chkTOCSPURL}, nil)
		b := f.leaf(t, []string{chkTOCSPURL}, nil)
		c := f.checker(t, Options{OCSPCacheEntries: 1})
		p := Policy{OCSPHosts: []string{chkTOCSPHost}}
		steps := []struct {
			name      string
			leaf      *x509.Certificate
			wantCache bool
			wantHits  int64
		}{
			{"a fetched", a, false, 1},
			{"b fetched, evicts a", b, false, 2},
			{"a fetched again, evicts b", a, false, 3},
			{"a cached", a, true, 3},
		}
		for _, s := range steps {
			res := chkTCheck(t, c, s.leaf, f.ca.Cert, p)
			if res.Status != StatusGood || res.Attempts[0].FromCache != s.wantCache || hits.Load() != s.wantHits {
				t.Errorf("%s: Check = %s %s after %d requests, want good, FromCache %v, %d requests",
					s.name, res.Status, chkTTrace(res.Attempts), hits.Load(), s.wantCache, s.wantHits)
			}
		}
	})

	t.Run("defaults", func(t *testing.T) {
		c, err := NewChecker(Options{})
		if err != nil {
			t.Fatalf("NewChecker error = %v, want nil", err)
		}
		if c.ocsp.limit != DefaultOCSPCacheEntries || c.crls.limit != DefaultCRLCacheBytes ||
			c.ocspTO != OCSPTimeout || c.crlTO != CRLTimeout || c.now == nil || c.log == nil {
			t.Errorf("NewChecker(Options{}) = ocsp limit %d, crl limit %d, timeouts %v/%v, want %d, %d, %v/%v with a clock and logger",
				c.ocsp.limit, c.crls.limit, c.ocspTO, c.crlTO, DefaultOCSPCacheEntries, DefaultCRLCacheBytes, OCSPTimeout, CRLTimeout)
		}
	})
}
