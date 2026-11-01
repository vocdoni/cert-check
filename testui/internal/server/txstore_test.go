package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth"
)

// fakeClock is a goroutine-safe settable clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// txSecrets is one transaction's raw secrets, as the browser and the auth listener see them.
type txSecrets struct {
	cookie, state, code Secret
}

// mustCreate creates a transaction or stops the test.
func mustCreate(t *testing.T, s *Store, provider string, prev Secret) txSecrets {
	t.Helper()
	cookie, state, _, err := s.Create(provider, prev)
	if err != nil {
		t.Fatalf("Create(%q): %v", provider, err)
	}
	return txSecrets{cookie: cookie, state: state}
}

// mustComplete creates a transaction, consumes its state and completes it with o.
func mustComplete(t *testing.T, s *Store, provider string, o Outcome) txSecrets {
	t.Helper()
	sec := mustCreate(t, s, provider, "")
	ref, err := s.ConsumeState(sec.state, provider)
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if sec.code, err = s.Complete(ref, o); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return sec
}

func successOutcome() Outcome {
	return Outcome{Result: &certauth.Result{Diagnostics: certauth.Diagnostics{DiagnosticID: "diag-ok"}}}
}

func TestStoreFlow(t *testing.T) {
	clk := newClock()
	s := NewStore(0, clk.Now)
	created := clk.Now()
	cookie, state, expiresAt, err := s.Create("alpha", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if want := created.Add(TxLifetime); !expiresAt.Equal(want) {
		t.Errorf("expiresAt = %v, want %v", expiresAt, want)
	}
	if cookie == state {
		t.Fatal("cookie == state, want independent secrets")
	}
	wantPending := Snapshot{Status: TxPending, Provider: "alpha", CreatedAt: created}
	if got := s.Current(cookie); got != wantPending {
		t.Errorf("Current after Create = %+v, want %+v", got, wantPending)
	}

	clk.Advance(time.Minute)
	ref, err := s.ConsumeState(state, "alpha")
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if got := s.Current(cookie); got != wantPending {
		t.Errorf("Current after ConsumeState = %+v, want %+v", got, wantPending)
	}

	want := successOutcome()
	code, err := s.Complete(ref, want)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if code == cookie || code == state {
		t.Fatal("code reuses another secret")
	}
	wantCompleted := Snapshot{Status: TxCompleted, Provider: "alpha", CreatedAt: created}
	if got := s.Current(cookie); got != wantCompleted {
		t.Errorf("Current after Complete = %+v, want %+v", got, wantCompleted)
	}

	got, err := s.Redeem(code, cookie)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if got.Result != want.Result || got.Err != nil {
		t.Errorf("Redeem = %+v, want %+v", got, want)
	}
	if got := s.Current(cookie); got != (Snapshot{Status: TxNone}) {
		t.Errorf("Current after Redeem = %+v, want none", got)
	}
	if n := s.Len(); n != 0 {
		t.Errorf("Len = %d, want 0", n)
	}
}

func TestStoreFlowErrorOutcome(t *testing.T) {
	s := NewStore(0, newClock().Now)
	want := Outcome{Err: &certauth.Error{Code: certauth.CodeRevoked}}
	sec := mustComplete(t, s, "alpha", want)
	got, err := s.Redeem(sec.code, sec.cookie)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if got.Err != want.Err || got.Result != nil {
		t.Errorf("Redeem = %+v, want %+v", got, want)
	}
}

func TestStateReplay(t *testing.T) {
	s := NewStore(0, newClock().Now)
	sec := mustCreate(t, s, "alpha", "")
	if _, err := s.ConsumeState(sec.state, "alpha"); err != nil {
		t.Fatalf("first ConsumeState: %v", err)
	}
	if _, err := s.ConsumeState(sec.state, "alpha"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("replayed ConsumeState = %v, want %v", err, ErrInvalidState)
	}
}

func TestStateWrongProvider(t *testing.T) {
	s := NewStore(0, newClock().Now)
	sec := mustCreate(t, s, "alpha", "")
	if _, err := s.ConsumeState(sec.state, "beta"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ConsumeState(beta) = %v, want %v", err, ErrInvalidState)
	}
	if _, err := s.ConsumeState(sec.state, "alpha"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("retry on the right provider = %v, want %v (state spent)", err, ErrInvalidState)
	}
	if got := s.Current(sec.cookie).Status; got != TxPending {
		t.Errorf("Current = %q, want %q (the transaction itself stays until it expires)", got, TxPending)
	}
}

func TestStateExpired(t *testing.T) {
	cases := []struct {
		name    string
		elapsed time.Duration
		want    error
	}{
		{"just before expiry", TxLifetime - time.Second, nil},
		{"at expiry", TxLifetime, ErrInvalidState},
		{"after expiry", TxLifetime + time.Second, ErrInvalidState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clk := newClock()
			s := NewStore(0, clk.Now)
			sec := mustCreate(t, s, "alpha", "")
			clk.Advance(c.elapsed)
			if _, err := s.ConsumeState(sec.state, "alpha"); !errors.Is(err, c.want) {
				t.Errorf("ConsumeState after %v = %v, want %v", c.elapsed, err, c.want)
			}
		})
	}
}

func TestCodeReplay(t *testing.T) {
	s := NewStore(0, newClock().Now)
	sec := mustComplete(t, s, "alpha", successOutcome())
	if _, err := s.Redeem(sec.code, sec.cookie); err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if _, err := s.Redeem(sec.code, sec.cookie); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("replayed Redeem = %v, want %v", err, ErrInvalidCode)
	}
}

func TestRedeemWrongCookie(t *testing.T) {
	cases := []struct {
		name  string
		other func(t *testing.T, s *Store) Secret
	}{
		{"another live transaction", func(t *testing.T, s *Store) Secret { return mustCreate(t, s, "alpha", "").cookie }},
		{"unknown cookie", func(*testing.T, *Store) Secret { return NewSecret() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewStore(0, newClock().Now)
			victim := mustComplete(t, s, "alpha", successOutcome())
			if _, err := s.Redeem(victim.code, c.other(t, s)); !errors.Is(err, ErrCookie) {
				t.Fatalf("Redeem with a foreign cookie = %v, want %v", err, ErrCookie)
			}
			if _, err := s.Redeem(victim.code, victim.cookie); !errors.Is(err, ErrInvalidCode) {
				t.Errorf("retry with the right cookie = %v, want %v (code spent)", err, ErrInvalidCode)
			}
			if got := s.Current(victim.cookie).Status; got != TxCompleted {
				t.Errorf("Current = %q, want %q (kept, without a code, until expiry)", got, TxCompleted)
			}
		})
	}
}

func TestRedeemMissingCookie(t *testing.T) {
	s := NewStore(0, newClock().Now)
	sec := mustComplete(t, s, "alpha", successOutcome())
	if _, err := s.Redeem(sec.code, ""); !errors.Is(err, ErrCookie) {
		t.Fatalf("Redeem without a cookie = %v, want %v", err, ErrCookie)
	}
	if _, err := s.Redeem(sec.code, sec.cookie); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("retry with the cookie = %v, want %v (code spent)", err, ErrInvalidCode)
	}
}

func TestRedeemExpired(t *testing.T) {
	clk := newClock()
	s := NewStore(0, clk.Now)
	sec := mustComplete(t, s, "alpha", successOutcome())
	clk.Advance(TxLifetime)
	if _, err := s.Redeem(sec.code, sec.cookie); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("Redeem after expiry = %v, want %v", err, ErrInvalidCode)
	}
	if n := s.Len(); n != 0 {
		t.Errorf("Len = %d, want 0 (expired transaction deleted)", n)
	}
}

func TestCompleteAfterExpiry(t *testing.T) {
	clk := newClock()
	s := NewStore(0, clk.Now)
	sec := mustCreate(t, s, "alpha", "")
	ref, err := s.ConsumeState(sec.state, "alpha")
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	clk.Advance(TxLifetime + time.Second)
	if _, err := s.Complete(ref, successOutcome()); !errors.Is(err, ErrExpired) {
		t.Errorf("Complete after expiry = %v, want %v", err, ErrExpired)
	}
}

func TestCompleteTwiceAndUnknownRef(t *testing.T) {
	s := NewStore(0, newClock().Now)
	sec := mustCreate(t, s, "alpha", "")
	ref, err := s.ConsumeState(sec.state, "alpha")
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if _, err := s.Complete(ref, successOutcome()); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, err := s.Complete(ref, successOutcome()); !errors.Is(err, ErrInvalidState) {
		t.Errorf("second Complete = %v, want %v", err, ErrInvalidState)
	}
	if _, err := s.Complete(TxRef{}, successOutcome()); !errors.Is(err, ErrExpired) {
		t.Errorf("Complete(zero ref) = %v, want %v", err, ErrExpired)
	}
}

func TestCapacity(t *testing.T) {
	clk := newClock()
	s := NewStore(TxCapacity, clk.Now)
	var last txSecrets
	for range TxCapacity {
		last = mustCreate(t, s, "alpha", "")
	}
	if _, _, _, err := s.Create("alpha", ""); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("Create beyond capacity = %v, want %v", err, ErrStoreFull)
	}
	// Replacing the request's own previous transaction frees its slot.
	if _, _, _, err := s.Create("alpha", last.cookie); err != nil {
		t.Errorf("Create replacing the previous transaction when full: %v", err)
	}
	if n := s.Len(); n != TxCapacity {
		t.Errorf("Len = %d, want %d", n, TxCapacity)
	}
	clk.Advance(TxLifetime)
	if _, _, _, err := s.Create("alpha", ""); err != nil {
		t.Fatalf("Create after expiry: %v", err)
	}
	if n := s.Len(); n != 1 {
		t.Errorf("Len after sweep = %d, want 1", n)
	}
}

func TestCreateReplacesPrevious(t *testing.T) {
	s := NewStore(0, newClock().Now)
	old := mustComplete(t, s, "alpha", successOutcome())
	pending := mustCreate(t, s, "alpha", "")
	next := mustCreate(t, s, "beta", old.cookie)
	if got := s.Current(old.cookie).Status; got != TxNone {
		t.Errorf("Current(previous cookie) = %q, want %q", got, TxNone)
	}
	if _, err := s.Redeem(old.code, old.cookie); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("Redeem of the replaced transaction = %v, want %v", err, ErrInvalidCode)
	}
	if got := s.Current(next.cookie); got.Status != TxPending || got.Provider != "beta" {
		t.Errorf("Current(new cookie) = %+v, want pending beta", got)
	}
	// Unknown or malformed previous cookies are ignored.
	mustCreate(t, s, "alpha", NewSecret())
	mustCreate(t, s, "alpha", "not-a-secret")
	if got := s.Current(pending.cookie).Status; got != TxPending {
		t.Errorf("unrelated transaction = %q, want %q", got, TxPending)
	}
	if n := s.Len(); n != 4 {
		t.Errorf("Len = %d, want 4", n)
	}

	// A replaced pending transaction loses its state too.
	s2 := NewStore(0, newClock().Now)
	first := mustCreate(t, s2, "alpha", "")
	mustCreate(t, s2, "alpha", first.cookie)
	if _, err := s2.ConsumeState(first.state, "alpha"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("ConsumeState of the replaced transaction = %v, want %v", err, ErrInvalidState)
	}
}

func TestJanitor(t *testing.T) {
	clk := newClock()
	s := NewStore(0, clk.Now)
	mustCreate(t, s, "alpha", "")
	mustComplete(t, s, "alpha", successOutcome())
	stale := mustComplete(t, s, "alpha", successOutcome())
	if _, err := s.Redeem(stale.code, NewSecret()); !errors.Is(err, ErrCookie) {
		t.Fatalf("Redeem with a foreign cookie = %v, want %v", err, ErrCookie)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() { s.RunJanitor(ctx, 5*time.Millisecond) })
	defer func() {
		cancel()
		wg.Wait()
	}()

	time.Sleep(30 * time.Millisecond)
	if n := s.Len(); n != 3 {
		t.Fatalf("Len before expiry = %d, want 3", n)
	}
	clk.Advance(TxLifetime)
	deadline := time.Now().Add(5 * time.Second)
	for s.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("janitor left %d transactions after expiry", s.Len())
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.byState) != 0 || len(s.byCode) != 0 {
		t.Errorf("indexes after sweep: %d states, %d codes, want 0", len(s.byState), len(s.byCode))
	}
}

func TestMalformedSecrets(t *testing.T) {
	valid := string(NewSecret())
	cases := []struct{ name, v string }{
		{"empty", ""},
		{"short", "abc"},
		{"42 chars", valid[:42]},
		{"44 chars", valid + "A"},
		{"two secrets", valid + valid},
		{"standard alphabet", "+" + valid[1:]},
		{"slash", "/" + valid[1:]},
		{"invalid character", "!" + valid[1:]},
		{"padded", valid + "="},
		{"padding inside", valid[:42] + "="},
		{"space", " " + valid[1:]},
		{"newline", valid[:21] + "\n" + valid[22:]},
		{"newline inserted", valid[:21] + "\n" + valid[21:]},
		{"CRLF inserted", valid[:21] + "\r\n" + valid[21:]},
		{"non-canonical trailing bits", nonCanonical(valid)},
		{"non-ascii", "é" + valid[2:]},
	}
	clk := newClock()
	s := NewStore(0, clk.Now)
	live := mustComplete(t, s, "alpha", successOutcome())
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sec := Secret(c.v)
			if _, ok := sec.hash(); ok {
				t.Errorf("hash(%q) ok = true, want false", c.v)
			}
			if _, err := s.ConsumeState(sec, "alpha"); !errors.Is(err, ErrInvalidState) {
				t.Errorf("ConsumeState = %v, want %v", err, ErrInvalidState)
			}
			if _, err := s.Redeem(sec, live.cookie); !errors.Is(err, ErrInvalidCode) {
				t.Errorf("Redeem(code %q) = %v, want %v", c.v, err, ErrInvalidCode)
			}
			if got := s.Current(sec).Status; got != TxNone {
				t.Errorf("Current = %q, want %q", got, TxNone)
			}
			if _, _, _, err := s.Create("alpha", sec); err != nil {
				t.Errorf("Create(prev %q): %v", c.v, err)
			}
		})
	}
	// A malformed cookie never matches a code (the code is spent).
	if _, err := s.Redeem(live.code, Secret(nonCanonical(string(live.cookie)))); !errors.Is(err, ErrCookie) {
		t.Errorf("Redeem with a non-canonical cookie = %v, want %v", err, ErrCookie)
	}
}

// nonCanonical returns v with the unused low bits of its last character set:
// a lenient decoder maps it to the same bytes.
func nonCanonical(v string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	i := strings.IndexByte(alphabet, v[len(v)-1])
	return v[:len(v)-1] + string(alphabet[i|1])
}

func TestSecretFormat(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	seen := map[Secret]bool{}
	for range 1000 {
		s := NewSecret()
		if !re.MatchString(string(s)) {
			t.Fatalf("NewSecret() = %q, want 43 base64url characters", s)
		}
		if b, err := base64.RawURLEncoding.Strict().DecodeString(string(s)); err != nil || len(b) != 32 {
			t.Fatalf("NewSecret() decodes to %d bytes (%v), want 32", len(b), err)
		}
		if _, ok := s.hash(); !ok {
			t.Fatalf("hash(NewSecret()) ok = false")
		}
		if seen[s] {
			t.Fatalf("NewSecret() repeated %q", s)
		}
		seen[s] = true
	}
}

func TestNoRawSecretsRetained(t *testing.T) {
	clk := newClock()
	s := NewStore(0, clk.Now)
	var raw []Secret
	keep := func(secs ...txSecrets) {
		for _, sec := range secs {
			for _, v := range []Secret{sec.cookie, sec.state, sec.code} {
				if v != "" {
					raw = append(raw, v)
				}
			}
		}
	}
	pending := mustCreate(t, s, "alpha", "")
	consumed := mustCreate(t, s, "alpha", "")
	if _, err := s.ConsumeState(consumed.state, "alpha"); err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	completed := mustComplete(t, s, "alpha", successOutcome())
	mismatched := mustComplete(t, s, "beta", Outcome{Err: &certauth.Error{Code: certauth.CodeExpired, Detail: "leaf expired"}})
	if _, err := s.Redeem(mismatched.code, pending.cookie); !errors.Is(err, ErrCookie) {
		t.Fatalf("Redeem with a foreign cookie = %v, want %v", err, ErrCookie)
	}
	keep(pending, consumed, completed, mismatched)

	var rawBytes [][]byte
	for _, v := range raw {
		b, err := base64.RawURLEncoding.DecodeString(string(v))
		if err != nil {
			t.Fatalf("decode %q: %v", v, err)
		}
		rawBytes = append(rawBytes, b)
	}
	var strs int
	var walk func(path string, v reflect.Value)
	seen := map[uintptr]bool{}
	walk = func(path string, v reflect.Value) {
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() || seen[v.Pointer()] {
				return
			}
			seen[v.Pointer()] = true
			walk(path, v.Elem())
		case reflect.Interface:
			if !v.IsNil() {
				walk(path, v.Elem())
			}
		case reflect.Struct:
			for i := range v.NumField() {
				walk(path+"."+v.Type().Field(i).Name, v.Field(i))
			}
		case reflect.Map:
			for it := v.MapRange(); it.Next(); {
				walk(path+"[key]", it.Key())
				walk(path+"[value]", it.Value())
			}
		case reflect.Slice, reflect.Array:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				b := make([]byte, v.Len())
				for i := range v.Len() {
					b[i] = byte(v.Index(i).Uint())
				}
				for _, r := range rawBytes {
					if bytes.Contains(b, r) {
						t.Errorf("%s holds the bytes of a raw secret", path)
					}
				}
				return
			}
			for i := range v.Len() {
				walk(path+"[]", v.Index(i))
			}
		case reflect.String:
			strs++
			for _, r := range raw {
				if strings.Contains(v.String(), string(r)) {
					t.Errorf("%s = %q contains a raw secret", path, v.String())
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The store's own indexes are keyed by [32]byte hashes.
	keyType := reflect.TypeFor[[32]byte]()
	var indexes int
	sv := reflect.ValueOf(s).Elem()
	for i := range sv.NumField() {
		if f := sv.Field(i); f.Kind() == reflect.Map {
			indexes++
			if f.Type().Key() != keyType {
				t.Errorf("Store.%s: key type %s, want [32]byte", sv.Type().Field(i).Name, f.Type().Key())
			}
			if f.Len() == 0 {
				t.Errorf("Store.%s is empty; the test must cover every index", sv.Type().Field(i).Name)
			}
		}
	}
	walk("Store", reflect.ValueOf(s))
	if indexes != 3 || strs == 0 {
		t.Errorf("found %d indexes and walked %d strings, want 3 indexes and the provider strings", indexes, strs)
	}
}

func TestStoreConcurrent(t *testing.T) {
	s := NewStore(0, newClock().Now)
	ctx, cancel := context.WithCancel(t.Context())
	var janitor sync.WaitGroup
	janitor.Go(func() { s.RunJanitor(ctx, time.Millisecond) })
	defer func() {
		cancel()
		janitor.Wait()
	}()

	// Independent flows.
	var wg sync.WaitGroup
	var failures atomic.Int64
	for g := range 16 {
		wg.Go(func() {
			provider := []string{"alpha", "beta"}[g%2]
			for range 50 {
				cookie, state, _, err := s.Create(provider, "")
				if err != nil {
					failures.Add(1)
					continue
				}
				ref, err := s.ConsumeState(state, provider)
				if err != nil {
					failures.Add(1)
					continue
				}
				_ = s.Current(cookie)
				code, err := s.Complete(ref, successOutcome())
				if err != nil {
					failures.Add(1)
					continue
				}
				if _, err := s.Redeem(code, cookie); err != nil {
					failures.Add(1)
				}
				_ = s.Len()
			}
		})
	}
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d independent flows failed", n)
	}

	// Racing consumers of one state and one code: exactly one wins each.
	for range 20 {
		sec := mustCreate(t, s, "alpha", "")
		var states, codes atomic.Int64
		var refs sync.Map
		for range 8 {
			wg.Go(func() {
				if ref, err := s.ConsumeState(sec.state, "alpha"); err == nil {
					states.Add(1)
					refs.Store(ref, true)
				}
			})
		}
		wg.Wait()
		if n := states.Load(); n != 1 {
			t.Fatalf("%d racing ConsumeState calls succeeded, want 1", n)
		}
		refs.Range(func(k, _ any) bool {
			code, err := s.Complete(k.(TxRef), successOutcome())
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			for range 8 {
				wg.Go(func() {
					if _, err := s.Redeem(code, sec.cookie); err == nil {
						codes.Add(1)
					}
				})
			}
			return false
		})
		wg.Wait()
		if n := codes.Load(); n != 1 {
			t.Fatalf("%d racing Redeem calls succeeded, want 1", n)
		}
	}
	if n := s.Len(); n != 0 {
		t.Errorf("Len = %d, want 0", n)
	}
}
