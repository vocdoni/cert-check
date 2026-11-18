package revocation

import (
	"container/list"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// crlTKey composes a cache key the way the checker does.
func crlTKey(issuer *x509.Certificate, url string) string { return issuerKey(issuer) + " " + url }

// crlTParsed returns a ParsedCRL of the given cost and nextUpdate.
func crlTParsed(cost int64, nextUpdate time.Time) *ParsedCRL {
	return &ParsedCRL{
		ThisUpdate: crlTNow.Add(-time.Hour),
		NextUpdate: nextUpdate,
		Listed:     map[string]CRLRecord{},
		Cost:       cost,
		URL:        "http://crl.example.es/a.crl",
	}
}

// crlTFetcher counts fetches and returns p (or err) from each.
type crlTFetcher struct {
	calls atomic.Int64
	p     *ParsedCRL
	err   error
	gate  chan struct{} // when non-nil, each fetch waits for it to close
}

func (f *crlTFetcher) fetch(ctx context.Context) crlLoad {
	f.calls.Add(1)
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return crlLoad{status: StatusUnavailable, err: ctx.Err()}
		}
	}
	at := Attempt{Method: MethodCRL, URL: "http://crl.example.es/a.crl", HTTPStatus: 200}
	if f.err != nil {
		return crlLoad{status: StatusUnavailable, err: f.err, attempt: at}
	}
	return crlLoad{crl: f.p, status: StatusGood, attempt: at, admit: true}
}

func TestCRLCache(t *testing.T) {
	now := crlTNow
	far := now.Add(24 * time.Hour)
	const timeout = 5 * time.Second

	t.Run("singleflight", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		f := &crlTFetcher{p: crlTParsed(1000, far), gate: make(chan struct{})}
		var started atomic.Int64
		results := make([]crlLoad, 20)
		var wg sync.WaitGroup
		for i := range results {
			wg.Go(func() {
				started.Add(1)
				results[i] = c.load(t.Context(), "k", now, timeout, f.fetch)
			})
		}
		crlTEventually(t, func() bool { return started.Load() == 20 && f.calls.Load() >= 1 })
		time.Sleep(50 * time.Millisecond) // let every caller join the flight
		close(f.gate)
		wg.Wait()
		if got := f.calls.Load(); got != 1 {
			t.Errorf("fetches = %d, want 1", got)
		}
		for i, r := range results {
			if r.crl != f.p || r.err != nil || r.status != StatusGood {
				t.Errorf("load %d = %+v, want the shared CRL", i, r)
			}
		}
		r := c.load(t.Context(), "k", now.Add(time.Minute), timeout, f.fetch)
		if r.crl != f.p || !r.attempt.FromCache || r.attempt.Method != MethodCRL || r.attempt.URL != f.p.URL || r.status != StatusGood {
			t.Errorf("load after the flight = %+v, want a cache hit", r)
		}
		if got := f.calls.Load(); got != 1 {
			t.Errorf("fetches after a cache hit = %d, want 1", got)
		}
	})

	t.Run("expiry", func(t *testing.T) {
		cases := []struct {
			name       string
			nextUpdate time.Time
			hitAt      time.Time
			missAt     time.Time
		}{
			{"one hour cap", now.Add(2 * time.Hour), now.Add(59 * time.Minute), now.Add(time.Hour)},
			{"next update first", now.Add(10 * time.Minute), now.Add(10*time.Minute - time.Second), now.Add(10 * time.Minute)},
			{"dnie arl next update months away", now.Add(140 * 24 * time.Hour), now.Add(59 * time.Minute), now.Add(time.Hour)},
		}
		for _, cc := range cases {
			t.Run(cc.name, func(t *testing.T) {
				c := newCRLCache(DefaultCRLCacheBytes)
				f := &crlTFetcher{p: crlTParsed(100, cc.nextUpdate)}
				c.load(t.Context(), "k", now, timeout, f.fetch)
				if r := c.load(t.Context(), "k", cc.hitAt, timeout, f.fetch); !r.attempt.FromCache || f.calls.Load() != 1 {
					t.Errorf("load at %v = fromCache %v, fetches %d, want a hit", cc.hitAt, r.attempt.FromCache, f.calls.Load())
				}
				if r := c.load(t.Context(), "k", cc.missAt, timeout, f.fetch); r.attempt.FromCache || f.calls.Load() != 2 {
					t.Errorf("load at %v = fromCache %v, fetches %d, want a refetch", cc.missAt, r.attempt.FromCache, f.calls.Load())
				}
			})
		}
	})

	t.Run("expired entry removed", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		c.put("k", crlTParsed(100, far), now)
		if _, ok := c.get("k", now.Add(time.Hour)); ok {
			t.Fatal("get after expiry = hit, want miss")
		}
		if c.cost != 0 || len(c.items) != 0 || c.lru.Len() != 0 {
			t.Errorf("after expiry: cost %d, items %d, lru %d, want all 0", c.cost, len(c.items), c.lru.Len())
		}
	})

	t.Run("not cached when already past next update", func(t *testing.T) {
		for _, next := range []time.Time{now, now.Add(-time.Second)} {
			c := newCRLCache(DefaultCRLCacheBytes)
			c.put("k", crlTParsed(100, next), now)
			if _, ok := c.get("k", now.Add(-time.Minute)); ok || c.cost != 0 {
				t.Errorf("nextUpdate %v: cached (cost %d), want not cached", next, c.cost)
			}
		}
	})

	t.Run("lru eviction", func(t *testing.T) {
		c := newCRLCache(1000)
		a, b, d := crlTParsed(400, far), crlTParsed(400, far), crlTParsed(400, far)
		c.put("a", a, now)
		c.put("b", b, now)
		if c.cost != 800 {
			t.Fatalf("cost = %d, want 800", c.cost)
		}
		if _, ok := c.get("a", now); !ok {
			t.Fatal("get a = miss, want hit")
		}
		c.put("d", d, now) // 1200 > 1000: evict the least recently used (b)
		for _, k := range []struct {
			key  string
			want bool
		}{{"a", true}, {"b", false}, {"d", true}} {
			if _, ok := c.get(k.key, now); ok != k.want {
				t.Errorf("get %s = %v, want %v", k.key, ok, k.want)
			}
		}
		if c.cost != 800 {
			t.Errorf("cost = %d, want 800", c.cost)
		}
	})

	t.Run("bound is inclusive", func(t *testing.T) {
		c := newCRLCache(1000)
		c.put("a", crlTParsed(1000, far), now)
		if _, ok := c.get("a", now); !ok || c.cost != 1000 {
			t.Fatalf("entry of cost 1000 under limit 1000: cached %v, cost %d, want cached, 1000", ok, c.cost)
		}
		c.put("b", crlTParsed(2, far), now)
		if _, ok := c.get("a", now); ok {
			t.Error("get a after b = hit, want evicted")
		}
		if _, ok := c.get("b", now); !ok || c.cost != 2 {
			t.Errorf("get b: cached %v, cost %d, want cached, 2", ok, c.cost)
		}
	})

	t.Run("entry above the bound not cached", func(t *testing.T) {
		c := newCRLCache(1000)
		c.put("small", crlTParsed(200, far), now)
		f := &crlTFetcher{p: crlTParsed(1001, far)}
		r := c.load(t.Context(), "huge", now, timeout, f.fetch)
		if r.crl != f.p || r.err != nil {
			t.Fatalf("load huge = %+v, want the parsed CRL returned", r)
		}
		if _, ok := c.get("huge", now); ok {
			t.Error("huge entry cached, want not cached")
		}
		if _, ok := c.get("small", now); !ok || c.cost != 200 {
			t.Errorf("small entry: cached %v, cost %d, want cached, 200", ok, c.cost)
		}
	})

	t.Run("replace keeps the cost", func(t *testing.T) {
		c := newCRLCache(1000)
		c.put("a", crlTParsed(200, far), now)
		c.put("a", crlTParsed(300, far), now)
		if c.cost != 300 || len(c.items) != 1 || c.lru.Len() != 1 {
			t.Errorf("cost %d, items %d, lru %d, want 300, 1, 1", c.cost, len(c.items), c.lru.Len())
		}
	})

	t.Run("failures not cached", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		down := errors.New("crlT: responder down")
		f := &crlTFetcher{err: down}
		for i := range 2 {
			r := c.load(t.Context(), "k", now, timeout, f.fetch)
			if r.status != StatusUnavailable || !errors.Is(r.err, down) || r.crl != nil || r.attempt.FromCache {
				t.Errorf("load %d = %+v, want the fetch failure", i, r)
			}
		}
		if got := f.calls.Load(); got != 2 {
			t.Errorf("fetches = %d, want 2", got)
		}
		invalid := func(context.Context) crlLoad {
			f.calls.Add(1)
			return crlLoad{status: StatusInvalidEvidence, err: errors.New("crlT: bad signature")}
		}
		c.load(t.Context(), "bad", now, timeout, invalid)
		c.load(t.Context(), "bad", now, timeout, invalid)
		if got := f.calls.Load(); got != 4 {
			t.Errorf("fetches after two invalid CRLs = %d, want 4", got)
		}
		if c.cost != 0 || len(c.items) != 0 {
			t.Errorf("cache holds %d items (cost %d), want none", len(c.items), c.cost)
		}
	})

	t.Run("cancelled waiter", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		p := crlTParsed(100, far)
		gate := make(chan struct{})
		release := sync.OnceFunc(func() { close(gate) })
		t.Cleanup(release)
		var calls atomic.Int64
		fetchCtxErr := make(chan error, 1)
		fetch := func(ctx context.Context) crlLoad {
			calls.Add(1)
			select {
			case <-gate:
			case <-ctx.Done():
			}
			fetchCtxErr <- ctx.Err()
			return crlLoad{crl: p, status: StatusGood, admit: true}
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var got crlLoad
		var wg sync.WaitGroup
		wg.Go(func() { got = c.load(ctx, "k", now, timeout, fetch) })
		crlTEventually(t, func() bool { return calls.Load() == 1 })
		cancel()
		wg.Wait()
		if got.status != StatusUnavailable || !errors.Is(got.err, context.Canceled) || got.crl != nil ||
			got.attempt.Method != MethodCRL || got.attempt.Outcome != StatusUnavailable {
			t.Errorf("cancelled load = %+v, want unavailable with context.Canceled", got)
		}
		release()
		if err := <-fetchCtxErr; err != nil {
			t.Errorf("shared fetch context error = %v, want nil (detached from the waiter)", err)
		}
		crlTEventually(t, func() bool { _, ok := c.get("k", now); return ok })
		r := c.load(t.Context(), "k", now, timeout, fetch)
		if r.crl != p || !r.attempt.FromCache || calls.Load() != 1 {
			t.Errorf("next load = %+v (fetches %d), want the cached CRL and 1 fetch", r, calls.Load())
		}
	})

	t.Run("fetch context carries the timeout", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		var left time.Duration
		var hasDeadline bool
		c.load(t.Context(), "k", now, 2*time.Second, func(ctx context.Context) crlLoad {
			var dl time.Time
			dl, hasDeadline = ctx.Deadline()
			left = time.Until(dl)
			return crlLoad{status: StatusUnavailable, err: errors.New("crlT: probe")}
		})
		if !hasDeadline || left <= 0 || left > 2*time.Second {
			t.Errorf("fetch deadline in %v (set %v), want within 2s", left, hasDeadline)
		}
	})

	t.Run("key separates issuers", func(t *testing.T) {
		a := testpki.NewRoot(t, "crlT cache issuer", testpki.CertSpec{Now: now})
		b := testpki.NewRoot(t, "crlT cache issuer", testpki.CertSpec{Now: now}) // same DN, other key
		const url = "http://crl.example.es/shared.crl"
		ka, kb := crlTKey(a.Cert, url), crlTKey(b.Cert, url)
		if ka == kb {
			t.Fatalf("keys for two issuers are equal: %s", ka)
		}
		if crlTKey(a.Cert, url) != ka {
			t.Fatal("key is not deterministic")
		}
		c := newCRLCache(DefaultCRLCacheBytes)
		fa := &crlTFetcher{p: crlTParsed(100, far)}
		fb := &crlTFetcher{p: crlTParsed(100, far)}
		ra := c.load(t.Context(), ka, now, timeout, fa.fetch)
		rb := c.load(t.Context(), kb, now, timeout, fb.fetch)
		if ra.crl != fa.p || rb.crl != fb.p || fa.calls.Load() != 1 || fb.calls.Load() != 1 {
			t.Errorf("loads = %p, %p (fetches %d, %d), want each issuer's own CRL fetched once", ra.crl, rb.crl, fa.calls.Load(), fb.calls.Load())
		}
		if r := c.load(t.Context(), ka, now, timeout, fb.fetch); r.crl != fa.p || !r.attempt.FromCache {
			t.Errorf("load for issuer a = %p (fromCache %v), want issuer a's cached CRL", r.crl, r.attempt.FromCache)
		}
	})
}

// TestCRLCachePanickingFetch: singleflight re-raises a panic of the shared
// function in a new goroutine, which would end the process; load recovers it.
func TestCRLCachePanickingFetch(t *testing.T) {
	c := newCRLCache(DefaultCRLCacheBytes)
	var calls atomic.Int64
	fetch := func(context.Context) crlLoad {
		calls.Add(1)
		panic("crlT: SENTINEL panic value")
	}
	for i := range 2 {
		r := c.load(t.Context(), "k", crlTNow, time.Second, fetch)
		if r.status != StatusUnavailable || r.err == nil || r.crl != nil || r.attempt.Method != MethodCRL {
			t.Fatalf("load %d = %+v, want unavailable", i, r)
		}
		if strings.Contains(r.err.Error(), "SENTINEL") {
			t.Errorf("load %d error %q carries the panic value, want a fixed detail", i, r.err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("fetches = %d, want 2 (the panicked flight is not reused)", got)
	}
}

func TestCRLCacheCancelledBeforeFlight(t *testing.T) {
	c := newCRLCache(DefaultCRLCacheBytes)
	f := &crlTFetcher{p: crlTParsed(100, crlTNow.Add(time.Hour)), gate: make(chan struct{})}
	t.Cleanup(func() { close(f.gate) })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := c.load(ctx, "k", crlTNow, time.Second, f.fetch)
	if r.status != StatusUnavailable || !errors.Is(r.err, context.Canceled) || r.attempt.Method != MethodCRL || r.attempt.Outcome != StatusUnavailable {
		t.Errorf("load with a cancelled context = %+v, want unavailable with context.Canceled", r)
	}
	time.Sleep(100 * time.Millisecond) // a detached flight would have started by now
	if got := f.calls.Load(); got != 0 {
		t.Errorf("fetches = %d, want 0", got)
	}
}

func TestCRLCacheMarks(t *testing.T) {
	now := crlTNow
	numbered := func(n int64) *ParsedCRL {
		p := crlTParsed(100, now.Add(24*time.Hour))
		p.Number = big.NewInt(n)
		return p
	}
	fetchOf := func(p *ParsedCRL) func(context.Context) crlLoad {
		return func(context.Context) crlLoad { return crlLoad{crl: p, status: StatusGood, admit: true} }
	}

	t.Run("not admitted is not marked", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		c.load(t.Context(), "k", now, time.Second, func(context.Context) crlLoad {
			return crlLoad{crl: numbered(9), status: StatusGood}
		})
		if r := c.load(t.Context(), "k", now, time.Second, fetchOf(numbered(3))); r.err != nil {
			t.Errorf("load after an unadmitted CRL 9 = %v, want CRL 3 accepted", r.err)
		}
	})

	t.Run("without a number", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		c.load(t.Context(), "k", now, time.Second, fetchOf(numbered(5)))
		c.removeLocked(c.items["k"])
		if r := c.load(t.Context(), "k", now, time.Second, fetchOf(crlTParsed(100, now.Add(time.Hour)))); r.err != nil {
			t.Errorf("load of a CRL without a number = %v, want accepted", r.err)
		}
	})

	t.Run("bounded, oldest evicted", func(t *testing.T) {
		c := newCRLCache(DefaultCRLCacheBytes)
		for i := range crlMaxMarks + 1 {
			c.load(t.Context(), fmt.Sprint(i), now, time.Second, fetchOf(numbered(10)))
		}
		if len(c.marks) != crlMaxMarks || c.markList.Len() != crlMaxMarks {
			t.Fatalf("marks = %d (list %d), want %d", len(c.marks), c.markList.Len(), crlMaxMarks)
		}
		for _, k := range []struct {
			key  string
			want bool
		}{{"1", true}, {fmt.Sprint(crlMaxMarks), true}, {"0", false}} { // "0" last: marking it evicts "1"
			key, want := k.key, k.want
			c.mu.Lock()
			c.items = map[string]*list.Element{}
			c.lru.Init()
			c.cost = 0
			c.mu.Unlock()
			r := c.load(t.Context(), key, now, time.Second, fetchOf(numbered(9)))
			if rolledBack := errors.Is(r.err, errCRLRollback); rolledBack != want {
				t.Errorf("key %s: CRL 9 after CRL 10 rolled back = %v, want %v", key, rolledBack, want)
			}
		}
	})
}

// TestCRLCacheDenseEntryAccounting: the cache charges a parsed CRL at least
// the heap it retains once its DER is garbage.
func TestCRLCacheDenseEntryAccounting(t *testing.T) {
	ca := testpki.NewRoot(t, "crlT accounting ca", testpki.CertSpec{Now: crlTNow})
	cases := []struct{ entries, serialLen int }{{10_000, 16}, {200_000, 20}}
	for _, cc := range cases {
		t.Run(fmt.Sprintf("%d entries of %d bytes", cc.entries, cc.serialLen), func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			p := crlTParseDense(t, ca, cc.entries, cc.serialLen) // the DER is unreachable on return
			runtime.GC()
			runtime.ReadMemStats(&after)
			retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			c := newCRLCache(DefaultCRLCacheBytes)
			c.put("k", p, crlTNow)
			if c.cost < retained {
				t.Errorf("charged %d bytes, retained %d: want charged >= retained", c.cost, retained)
			}
			t.Logf("%d entries: charged %d, retained %d", len(p.Listed), c.cost, retained)
			runtime.KeepAlive(p)
		})
	}
}

// crlTParseDense parses a dense CRL from crlTDense; nothing but the result
// outlives the call.
func crlTParseDense(t *testing.T, ca *testpki.CA, entries, serialLen int) *ParsedCRL {
	t.Helper()
	p, st, err := ParseCRL(crlTDense(t, ca, entries, serialLen, true, false), ca.Cert)
	if st != StatusGood || err != nil || len(p.Listed) != entries {
		t.Fatalf("ParseCRL = %s, %v, want good with %d entries", st, err, entries)
	}
	return p
}

// crlTEventually polls cond until it holds or 10 s pass.
func crlTEventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 10s")
		}
		time.Sleep(time.Millisecond)
	}
}
