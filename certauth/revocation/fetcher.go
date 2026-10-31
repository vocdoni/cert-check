package revocation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Fetch limits (spec "Fetcher (SSRF controls)").
const (
	OCSPTimeout      = 5 * time.Second
	CRLTimeout       = 15 * time.Second
	MaxOCSPResponse  = 64 << 10
	MaxCRLResponse   = 32 << 20
	MaxRedirects     = 3
	MaxConcurrent    = 16
	maxHeaderBytes   = 16 << 10
	defaultUserAgent = "cert-check/dev"
)

// Fetch errors. All of them map to StatusUnavailable.
var (
	ErrHostNotAllowed  = errors.New("revocation: URL scheme or host not allowlisted")
	ErrBlockedAddress  = errors.New("revocation: destination address blocked")
	ErrRedirectBlocked = errors.New("revocation: redirect not allowed")
	ErrTooLarge        = errors.New("revocation: response exceeds size cap")
	ErrHTTPStatus      = errors.New("revocation: unexpected HTTP status")
)

// DialFunc dials a network connection.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// FetcherOptions configures a Fetcher.
type FetcherOptions struct {
	UserAgent     string // default "cert-check/dev"; production passes "cert-check/<version>"
	MaxConcurrent int    // default 16
	// DialContext replaces the address-checking dialer. Tests only (fake
	// network); production wiring never sets it.
	DialContext DialFunc
}

// Fetcher performs bounded HTTP fetches of revocation evidence.
type Fetcher struct {
	client *http.Client
	sem    chan struct{}
	ua     string
}

type allowKey struct{}

// NewFetcher returns a Fetcher. The default dialer rejects loopback, private,
// link-local, multicast, unspecified and other non-public addresses after DNS
// resolution; no proxy, no cookies, no transparent decompression.
func NewFetcher(o FetcherOptions) *Fetcher {
	dial := o.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: 5 * time.Second, Control: checkDialAddress}
		dial = d.DialContext
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      false,
	}
	n := o.MaxConcurrent
	if n <= 0 {
		n = MaxConcurrent
	}
	ua := o.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	return &Fetcher{
		client: &http.Client{Transport: tr, CheckRedirect: checkRedirect},
		sem:    make(chan struct{}, n),
		ua:     ua,
	}
}

// FetchRequest describes one fetch.
type FetchRequest struct {
	URL          string
	Body         []byte // POST when non-nil
	ContentType  string
	Accept       string
	MaxBytes     int64
	Timeout      time.Duration
	AllowedHosts []string // the union of the profile allowlists
}

// FetchResult is the outcome of a successful fetch (HTTP 200, within caps).
type FetchResult struct {
	Body       []byte
	StatusCode int
	FinalURL   string
	Duration   time.Duration
}

// Fetch performs the request. On error the returned result still carries the
// HTTP status (if any) and the duration for diagnostics.
func (f *Fetcher) Fetch(ctx context.Context, r FetchRequest) (FetchResult, error) {
	start := time.Now()
	res := FetchResult{}
	u, err := url.Parse(r.URL)
	if err != nil || !hostAllowed(u, r.AllowedHosts) {
		return res, ErrHostNotAllowed
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return res, ctx.Err()
	}
	ctx = context.WithValue(ctx, allowKey{}, r.AllowedHosts)
	method, body := http.MethodGet, io.Reader(nil)
	if r.Body != nil {
		method, body = http.MethodPost, bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", f.ua)
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	resp, err := f.client.Do(req)
	res.Duration = time.Since(start)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res.StatusCode, res.FinalURL = resp.StatusCode, resp.Request.URL.String()
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("%w %d", ErrHTTPStatus, resp.StatusCode)
	}
	if resp.ContentLength > r.MaxBytes {
		return res, ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, r.MaxBytes+1))
	res.Duration = time.Since(start)
	if err != nil {
		return res, err
	}
	if int64(len(b)) > r.MaxBytes {
		return res, ErrTooLarge
	}
	res.Body = b
	return res, nil
}

// hostAllowed: http/https only, no userinfo, host (and non-default port)
// exactly in the allowlist.
func hostAllowed(u *url.URL, allowed []string) bool {
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	key := host
	if port != "" {
		key = net.JoinHostPort(host, port)
	}
	return slices.Contains(allowed, key)
}

// checkRedirect: at most MaxRedirects, same scheme, and the target is the same
// host or another allowlisted host.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return fmt.Errorf("%w: too many redirects", ErrRedirectBlocked)
	}
	prev := via[len(via)-1].URL
	if req.URL.Scheme != prev.Scheme {
		return fmt.Errorf("%w: scheme change", ErrRedirectBlocked)
	}
	allowed, _ := req.Context().Value(allowKey{}).([]string)
	if !hostAllowed(req.URL, allowed) {
		return fmt.Errorf("%w: host not allowlisted", ErrRedirectBlocked)
	}
	return nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),   // TEST-NET-1
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), // IPv4-compatible (deprecated)
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),  // discard-only
	netip.MustParsePrefix("2001::/32"), // Teredo
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4
	netip.MustParsePrefix("fec0::/10"), // site-local (deprecated)
}

// AddressAllowed reports whether a resolved destination IP may be dialed.
func AddressAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// checkDialAddress is the net.Dialer Control hook: it runs after DNS
// resolution, on the literal IP being dialed.
func checkDialAddress(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedAddress
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !AddressAllowed(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, network)
	}
	return nil
}
