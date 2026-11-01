package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTxCookie(t *testing.T) {
	v := NewSecret()
	set := httptest.NewRecorder()
	setTxCookie(set, v)
	want := []string{"__Host-certcheck_tx=" + string(v) + "; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax"}
	if got := set.Header().Values("Set-Cookie"); !slices.Equal(got, want) {
		t.Errorf("set: Set-Cookie = %q, want %q", got, want)
	}

	clear := httptest.NewRecorder()
	clearTxCookie(clear)
	want = []string{"__Host-certcheck_tx=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"}
	if got := clear.Header().Values("Set-Cookie"); !slices.Equal(got, want) {
		t.Errorf("clear: Set-Cookie = %q, want %q", got, want)
	}

	cases := []struct {
		name   string
		header string
		want   Secret
		wantOK bool
	}{
		{"present", CookieName + "=" + string(v), v, true},
		{"among others", "a=b; " + CookieName + "=" + string(v) + "; c=d", v, true},
		{"absent", "other=" + string(v), "", false},
		{"empty", CookieName + "=", "", false},
		{"no header", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://cert-check.test/api/v1/transactions/current", nil)
			if c.header != "" {
				r.Header.Set("Cookie", c.header)
			}
			got, ok := txCookie(r)
			if got != c.want || ok != c.wantOK {
				t.Errorf("txCookie = (%q, %v), want (%q, %v)", got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestMainHeaders(t *testing.T) {
	const wantCSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	h := mainHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	cases := []struct {
		path    string
		noStore bool
	}{
		{"/", false},
		{"/static/app.js", false},
		{"/api", false},
		{"/apix/v1", false},
		{"/api/v1/transactions", true},
		{"/api/v1/transactions/current", true},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://cert-check.test"+c.path, nil))
			want := map[string]string{
				"Content-Security-Policy":   wantCSP,
				"Referrer-Policy":           "no-referrer",
				"X-Content-Type-Options":    "nosniff",
				"Strict-Transport-Security": "max-age=31536000",
				"Cache-Control":             "",
			}
			if c.noStore {
				want["Cache-Control"] = "no-store"
			}
			for k, v := range want {
				if got := rec.Header().Values(k); (v == "" && len(got) != 0) || (v != "" && !slices.Equal(got, []string{v})) {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

func TestAuthHeaders(t *testing.T) {
	want := map[string]string{
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":           "no-referrer",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
		"Cache-Control":             "no-store",
		"Content-Type":              "text/plain; charset=utf-8",
	}
	const target = "https://cert-check.test/#code=SECRETCODE"
	cases := []struct {
		name, method string
		write        func(w http.ResponseWriter, r *http.Request)
		status       int
		location     string
	}{
		{"redirect GET", http.MethodGet, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusSeeOther) }, http.StatusSeeOther, target},
		{"redirect HEAD", http.MethodHead, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target, http.StatusSeeOther) }, http.StatusSeeOther, target},
		{"not found", http.MethodGet, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, http.StatusNotFound, ""},
		{"misdirected", http.MethodGet, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMisdirectedRequest) }, http.StatusMisdirectedRequest, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(c.method, "https://alpha.auth.test/v1/authenticate?state=x", nil)
			authHeaders(rec)
			c.write(rec, r)
			for k, v := range want {
				if got := rec.Header().Values(k); !slices.Equal(got, []string{v}) {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			if rec.Code != c.status {
				t.Errorf("status = %d, want %d", rec.Code, c.status)
			}
			if got := rec.Header().Get("Location"); got != c.location {
				t.Errorf("Location = %q, want %q", got, c.location)
			}
			if rec.Body.Len() != 0 {
				t.Errorf("body = %q, want empty (the auth listener renders no HTML)", rec.Body.String())
			}
		})
	}
}

func TestPostGuard(t *testing.T) {
	const origin = "https://cert-check.test"
	cases := []struct {
		name       string
		header     map[string]string
		wantStatus int
		wantCode   string
	}{
		{"no content type", map[string]string{}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"text/plain", map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"form", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"malformed content type", map[string]string{"Content-Type": "application/json; ="}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"json", map[string]string{"Content-Type": "application/json"}, 0, ""},
		{"json with charset", map[string]string{"Content-Type": "application/json; charset=utf-8"}, 0, ""},
		{"json upper case", map[string]string{"Content-Type": "Application/JSON"}, 0, ""},
		{"cross-site", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden, "forbidden"},
		{"same-site", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-site"}, http.StatusForbidden, "forbidden"},
		{"same-origin", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, 0, ""},
		{"user initiated", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "none"}, 0, ""},
		{"origin mismatch", map[string]string{"Content-Type": "application/json", "Origin": "https://evil.test"}, http.StatusForbidden, "forbidden"},
		{"origin null", map[string]string{"Content-Type": "application/json", "Origin": "null"}, http.StatusForbidden, "forbidden"},
		{"origin other scheme", map[string]string{"Content-Type": "application/json", "Origin": "http://cert-check.test"}, http.StatusForbidden, "forbidden"},
		{"origin equal", map[string]string{"Content-Type": "application/json", "Origin": origin, "Sec-Fetch-Site": "same-origin"}, 0, ""},
		{"origin absent", map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"}, 0, ""},
		{"wrong type before origin", map[string]string{"Content-Type": "text/plain", "Origin": "https://evil.test"}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, origin+"/api/v1/transactions", strings.NewReader("{}"))
			for k, v := range c.header {
				r.Header.Set(k, v)
			}
			status, code := postGuard(r, origin)
			if status != c.wantStatus || code != c.wantCode {
				t.Errorf("postGuard = (%d, %q), want (%d, %q)", status, code, c.wantStatus, c.wantCode)
			}
		})
	}
}

func TestDecodeJSON(t *testing.T) {
	type body struct {
		Code string `json:"code"`
	}
	sized := func(n int) string { // a valid body of exactly n bytes
		return `{"code":"` + strings.Repeat("x", n-11) + `"}`
	}
	cases := []struct {
		name, body string
		want       bool
		wantCode   string
	}{
		{"valid", `{"code":"abc"}`, true, "abc"},
		{"trailing whitespace", "{\"code\":\"abc\"}\n ", true, "abc"},
		{"1024 bytes", sized(1024), true, strings.Repeat("x", 1013)},
		{"1025 bytes", sized(1025), false, ""},
		{"unknown field", `{"code":"abc","extra":1}`, false, ""},
		{"trailing value", `{"code":"abc"} {"code":"def"}`, false, ""},
		{"trailing garbage", `{"code":"abc"}x`, false, ""},
		{"trailing brace", `{"code":"abc"}}`, false, ""},
		{"trailing bracket", `{"code":"abc"}]`, false, ""},
		{"wrong type", `{"code":1}`, false, ""},
		{"array", `["abc"]`, false, ""},
		{"empty", ``, false, ""},
		{"truncated", `{"code":"abc"`, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://cert-check.test/api/v1/transactions/redeem", strings.NewReader(c.body))
			var dst body
			got := decodeJSON(httptest.NewRecorder(), r, &dst)
			if got != c.want {
				t.Fatalf("decodeJSON(%.40q) = %v, want %v", c.body, got, c.want)
			}
			if c.want && dst.Code != c.wantCode {
				t.Errorf("code = %.20q (%d bytes), want %.20q (%d bytes)", dst.Code, len(dst.Code), c.wantCode, len(c.wantCode))
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	const peer = "10.0.0.9:5555"
	cases := []struct {
		name   string
		remote string
		xff    []string
		hops   int
		want   string // "" = invalid address
	}{
		{"no header", peer, nil, 1, "10.0.0.9"},
		{"hops 1", peer, []string{"1.1.1.1, 2.2.2.2"}, 1, "2.2.2.2"},
		{"hops 1 single entry", peer, []string{"1.1.1.1"}, 1, "1.1.1.1"},
		{"spoofed leftmost ignored", peer, []string{"6.6.6.6, 1.1.1.1"}, 1, "1.1.1.1"},
		{"two headers", peer, []string{"1.1.1.1", "2.2.2.2"}, 1, "2.2.2.2"},
		{"two headers hops 2", peer, []string{"1.1.1.1", "2.2.2.2"}, 2, "1.1.1.1"},
		{"hops 2", peer, []string{"1.1.1.1, 2.2.2.2"}, 2, "1.1.1.1"},
		{"hops beyond entries", peer, []string{"1.1.1.1, 2.2.2.2"}, 3, "10.0.0.9"},
		{"invalid entry", peer, []string{"1.1.1.1, not-an-ip"}, 1, "10.0.0.9"},
		{"empty entry", peer, []string{"1.1.1.1, "}, 1, "10.0.0.9"},
		{"entry with port", peer, []string{"1.1.1.1:443"}, 1, "10.0.0.9"},
		{"whitespace", peer, []string{" 1.1.1.1 ,  2.2.2.2 "}, 1, "2.2.2.2"},
		{"hops 0", peer, []string{"1.1.1.1, 2.2.2.2"}, 0, "10.0.0.9"},
		// IPv6 clients are keyed by their /64 (one allocation), IPv4 by address.
		{"IPv6 entry", peer, []string{"1.1.1.1, 2001:db8::1"}, 1, "2001:db8::"},
		{"IPv6 entry same /64", peer, []string{"2001:db8::ffff:1234:5678:9abc"}, 1, "2001:db8::"},
		{"IPv6 entry other /64", peer, []string{"2001:db8:0:1::1"}, 1, "2001:db8:0:1::"},
		{"IPv4-mapped entry", peer, []string{"::ffff:1.2.3.4"}, 1, "1.2.3.4"},
		{"IPv6 peer", "[2001:db8::9]:443", nil, 1, "2001:db8::"},
		{"IPv6 peer other /64", "[2001:db8:0:2::9]:443", nil, 1, "2001:db8:0:2::"},
		{"IPv6 zoned peer", "[fe80::1%eth0]:443", nil, 1, "fe80::"},
		{"IPv4-mapped peer", "[::ffff:10.0.0.9]:443", nil, 1, "10.0.0.9"},
		{"bad peer", "garbage", nil, 1, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://cert-check.test/", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			got := clientIP(r, c.hops)
			var want netip.Addr
			if c.want != "" {
				want = netip.MustParseAddr(c.want)
			}
			if got != want {
				t.Errorf("clientIP(XFF %q, hops %d) = %v, want %v", c.xff, c.hops, got, want)
			}
		})
	}
}

func TestIPLimiter(t *testing.T) {
	const perMinute = 20
	t0 := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	l := newIPLimiter(perMinute)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	for i := range perMinute {
		if ok, _ := l.allow(a, t0); !ok {
			t.Fatalf("request %d refused, want the first %d allowed", i+1, perMinute)
		}
	}
	ok, retryAfter := l.allow(a, t0)
	if ok || retryAfter <= 0 || retryAfter > 3*time.Second {
		t.Fatalf("request %d = (%v, %v), want refused with retryAfter in (0, 3s]", perMinute+1, ok, retryAfter)
	}
	if ok, _ := l.allow(b, t0); !ok {
		t.Error("another IP refused, want an independent bucket")
	}
	if ok, _ := l.allow(a, t0.Add(time.Second)); ok {
		t.Error("allowed 1s later, want refused until a token refills")
	}
	if ok, _ := l.allow(a, t0.Add(3*time.Second)); !ok {
		t.Error("refused after 3s, want one more allowed")
	}
	if ok, _ := l.allow(a, t0.Add(3*time.Second)); ok {
		t.Error("second request after 3s allowed, want refused")
	}
}

func TestIPLimiterBounded(t *testing.T) {
	const perMinute = 20
	t0 := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	l := newIPLimiter(perMinute)
	addr := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	for i := range maxLimiterEntries {
		if ok, _ := l.allow(addr(i), t0); !ok {
			t.Fatalf("client %d refused while filling the table", i)
		}
	}
	size := func() int {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.entries)
	}
	// Full of recently active clients: a new client is refused and not stored.
	newcomer := netip.MustParseAddr("192.0.2.200")
	ok, retryAfter := l.allow(newcomer, t0.Add(time.Minute))
	if ok || retryAfter <= 0 || retryAfter > 3*time.Second {
		t.Errorf("new client on a full table = (%v, %v), want refused with retryAfter in (0, 3s]", ok, retryAfter)
	}
	if n := size(); n != maxLimiterEntries {
		t.Errorf("entries = %d, want %d", n, maxLimiterEntries)
	}
	// Known clients keep their buckets.
	if ok, _ := l.allow(addr(7), t0.Add(time.Minute)); !ok {
		t.Error("known client refused on a full table")
	}
	// Once the old entries are idle beyond the prune window, the newcomer gets in.
	later := t0.Add(time.Minute + 10*time.Minute + time.Second)
	if ok, _ := l.allow(newcomer, later); !ok {
		t.Error("new client refused after the idle entries expired")
	}
	if n := size(); n != 1 {
		t.Errorf("entries after pruning = %d, want 1", n)
	}
}

// TestIPLimiterFullTableSweepsOncePerInterval: on a full table a newcomer
// triggers at most one prune scan per limiterSweepInterval; in between,
// newcomers are refused without scanning (U11-ASTRA-1).
func TestIPLimiterFullTableSweepsOncePerInterval(t *testing.T) {
	const perMinute = 20
	t0 := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	l := newIPLimiter(perMinute)
	for i := range maxLimiterEntries {
		if ok, _ := l.allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), t0); !ok {
			t.Fatalf("client %d refused while filling the table", i)
		}
	}
	size := func() int {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.entries)
	}
	newcomer := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}) }

	// The entries are not idle beyond the prune window yet: this sweep frees nothing.
	sweep := t0.Add(10 * time.Minute)
	if ok, _ := l.allow(newcomer(1), sweep); ok {
		t.Fatal("newcomer allowed on a full table of active clients")
	}
	// Every entry is now prunable, but the next sweep is not due: refused, nothing scanned.
	if ok, _ := l.allow(newcomer(2), sweep.Add(limiterSweepInterval-time.Second)); ok {
		t.Error("newcomer allowed before the next sweep was due, want refused without a scan")
	}
	if n := size(); n != maxLimiterEntries {
		t.Errorf("entries before the next sweep = %d, want %d (no scan)", n, maxLimiterEntries)
	}
	// The next sweep is due: the idle entries go and the newcomer gets in.
	if ok, _ := l.allow(newcomer(3), sweep.Add(limiterSweepInterval)); !ok {
		t.Error("newcomer refused once the sweep was due and the table was idle")
	}
	if n := size(); n != 1 {
		t.Errorf("entries after the due sweep = %d, want 1", n)
	}
}
