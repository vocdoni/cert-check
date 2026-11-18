// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/vocdoni/cert-check/testui/web"
)

// CookieName is the transaction cookie (host-only, Secure, HttpOnly).
const CookieName = "__Host-certcheck_tx"

const (
	authCSP = "default-src 'none'; frame-ancestors 'none'"
	maxBody = 1 << 10
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

// mainHeaders sets the security headers on every main-listener response. Package web defines
// them, and the devserver serves through the same set.
func mainHeaders(next http.Handler) http.Handler {
	return web.SecurityHeaders(next)
}

// authHeaders sets the auth-listener headers (redirects and 404s alike). The
// Content-Type is fixed so that http.Redirect writes no HTML body: the auth
// listener never renders HTML (spec "Authentication flow" step 4). Every
// response is terminal (the browser leaves for the public origin), so the
// connection closes after it: one connection cannot pipeline a request flood.
func authHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Connection", "close")
	h.Set("Content-Security-Policy", authCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", web.HSTS)
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

// clientIP returns the rate-limit key of the client: the rightmost
// X-Forwarded-For entry selected by trustedHops (1 = the entry appended by
// the edge), bucketed by bucket. The leftmost entry is never trusted.
// Without the header (or hops == 0) it is the TCP peer.
func clientIP(r *http.Request, trustedHops int) netip.Addr {
	remote := func() netip.Addr {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return netip.Addr{}
		}
		a, _ := netip.ParseAddr(host)
		return bucket(a)
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
	return bucket(a)
}

// bucket keys IPv6 clients by their /56 (a residential subscriber's
// allocation: 256 /64s), IPv4 by address. One subscriber cannot spread its
// requests over many buckets or fill the limiter table.
func bucket(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 56).Masked().Addr()
	}
	return a
}

// ipLimiter is a per-IP token bucket with bounded memory.
type ipLimiter struct {
	mu        sync.Mutex
	perMin    int
	entries   map[netip.Addr]*ipEntry
	nextSweep time.Time // earliest prune scan of a full table
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

const maxLimiterEntries = 100_000

// limiterSweepInterval is the minimum time between prune scans of a full
// table; newcomers in between are refused without a scan.
const limiterSweepInterval = time.Minute

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
			if !now.Before(l.nextSweep) {
				l.nextSweep = now.Add(limiterSweepInterval)
				l.pruneLocked(now)
			}
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
