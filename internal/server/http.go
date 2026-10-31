package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// CookieName is the transaction cookie (host-only, Secure, HttpOnly).
const CookieName = "__Host-certcheck_tx"

const (
	mainCSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	authCSP   = "default-src 'none'; frame-ancestors 'none'"
	maxBody   = 1 << 10
	hstsValue = "max-age=31536000"
)

// setTxCookie sets the transaction cookie: Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300.
func setTxCookie(w http.ResponseWriter, v Secret) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: string(v), Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(TxLifetime / time.Second)})
}

// clearTxCookie expires the cookie (Max-Age=0).
func clearTxCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func txCookie(r *http.Request) (Secret, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return Secret(c.Value), true
}

// mainHeaders sets the security headers on every main-listener response.
func mainHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", mainCSP)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", hstsValue)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// authHeaders sets the auth-listener headers (redirects and 404s alike). The
// Content-Type is fixed so that http.Redirect writes no HTML body: the auth
// listener never renders HTML (spec "Authentication flow" step 4).
func authHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", authCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", hstsValue)
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
}

// postGuard enforces Content-Type: application/json (415) and, when present,
// Sec-Fetch-Site in {same-origin, none} and Origin == publicOrigin (403).
func postGuard(r *http.Request, publicOrigin string) (status int, code string) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return http.StatusUnsupportedMediaType, "unsupported_media_type"
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return http.StatusForbidden, "forbidden"
	}
	if o := r.Header.Get("Origin"); o != "" && o != publicOrigin {
		return http.StatusForbidden, "forbidden"
	}
	return 0, ""
}

// decodeJSON reads at most 1 KiB into dst, rejecting unknown fields and
// trailing data: only whitespace may follow the value (dec.More alone would
// accept a stray '}' or ']').
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return false
	}
	_, err := dec.Token()
	return errors.Is(err, io.EOF)
}

// clientIP returns the rightmost X-Forwarded-For entry selected by
// trustedHops (1 = the entry appended by the edge). The leftmost entry is
// never trusted. Without the header (or hops == 0) it is the TCP peer.
func clientIP(r *http.Request, trustedHops int) netip.Addr {
	remote := func() netip.Addr {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return netip.Addr{}
		}
		a, _ := netip.ParseAddr(host)
		return a.Unmap()
	}
	values := r.Header.Values("X-Forwarded-For")
	if trustedHops == 0 || len(values) == 0 {
		return remote()
	}
	var entries []string
	for _, v := range values {
		for e := range strings.SplitSeq(v, ",") {
			entries = append(entries, strings.TrimSpace(e))
		}
	}
	i := len(entries) - trustedHops
	if i < 0 {
		return remote()
	}
	a, err := netip.ParseAddr(entries[i])
	if err != nil {
		return remote()
	}
	return a.Unmap()
}

// ipLimiter is a per-IP token bucket with bounded memory.
type ipLimiter struct {
	mu      sync.Mutex
	perMin  int
	entries map[netip.Addr]*ipEntry
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

const maxLimiterEntries = 100_000

func newIPLimiter(perMinute int) *ipLimiter {
	return &ipLimiter{perMin: perMinute, entries: map[netip.Addr]*ipEntry{}}
}

// allow reports whether ip may proceed; when not, retryAfter is the wait.
func (l *ipLimiter) allow(ip netip.Addr, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, found := l.entries[ip]
	if !found {
		if len(l.entries) >= maxLimiterEntries {
			l.pruneLocked(now)
			if len(l.entries) >= maxLimiterEntries {
				return false, time.Minute / time.Duration(l.perMin) // table full: refuse new clients, memory stays bounded
			}
		}
		e = &ipEntry{lim: rate.NewLimiter(rate.Every(time.Minute/time.Duration(l.perMin)), l.perMin)}
		l.entries[ip] = e
	}
	e.seen = now
	res := e.lim.ReserveN(now, 1)
	if d := res.DelayFrom(now); d > 0 {
		res.CancelAt(now)
		return false, d
	}
	return true, 0
}

func (l *ipLimiter) pruneLocked(now time.Time) {
	for ip, e := range l.entries {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.entries, ip)
		}
	}
}
