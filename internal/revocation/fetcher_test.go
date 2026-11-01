package revocation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/testpki"
)

func TestAddressAllowed(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", false},
		{"::1", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd12::1", false}, // Railway private network
		{"100.64.0.1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"255.255.255.255", false},
		{"::ffff:127.0.0.1", false},
		{"::ffff:10.0.0.1", false},
		{"::ffff:100.64.0.1", false}, // mapped CGNAT: only Unmap lets the prefix match
		{"::ffff:198.18.0.1", false}, // mapped benchmarking range
		{"::ffff:255.255.255.255", false},
		{"::ffff:8.8.8.8", true},
		{"64:ff9b::a00:1", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"2001:db8::1", false},
		// R51: documentation, 6to4, Teredo and legacy IPv6 ranges.
		{"192.0.2.1", false},    // TEST-NET-1
		{"198.51.100.1", false}, // TEST-NET-2
		{"203.0.113.1", false},  // TEST-NET-3
		{"192.88.99.1", false},  // 6to4 relay anycast
		{"::ffff:192.0.2.1", false},
		{"::ffff:198.51.100.1", false},
		{"::ffff:203.0.113.1", false},
		{"::ffff:192.88.99.1", false},
		{"2002:7f00:1::1", false},  // 6to4 embedding 127.0.0.1
		{"2002:808:808::1", false}, // 6to4 embedding a public IPv4: still blocked
		{"2001::1", false},         // Teredo
		{"2001:0:4136:e378:8000:63bf:3fff:fdd2", false},
		{"::7f00:1", false},  // IPv4-compatible 127.0.0.1
		{"::808:808", false}, // IPv4-compatible 8.8.8.8
		{"100::1", false},    // discard-only
		{"fec0::1", false},   // deprecated site-local
		{"feff::1", false},   // top of fec0::/10
		// A zone makes Prefix.Contains false: zoned addresses are never allowed.
		{"fec0::1%eth0", false},
		{"2001:db8::1%eth0", false},
		{"2001:4860:4860::8888%eth0", false},
		// Public controls, including neighbours of the new prefixes.
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"192.0.3.1", true},
		{"198.51.101.1", true},
		{"203.0.114.1", true},
		{"192.88.100.1", true},
		{"2001:4860:4860::8888", true},
		{"2606:4700::1111", true},
		{"2003::1", true},
		{"2a00:1450:4001::1", true},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			if got := AddressAllowed(netip.MustParseAddr(c.addr)); got != c.want {
				t.Errorf("AddressAllowed(%s) = %v, want %v", c.addr, got, c.want)
			}
		})
	}
	t.Run("zero address", func(t *testing.T) {
		if AddressAllowed(netip.Addr{}) {
			t.Error("AddressAllowed(zero) = true, want false")
		}
	})
}

func TestCheckDialAddress(t *testing.T) {
	cases := []struct {
		network, address string
		wantBlocked      bool
	}{
		{"tcp4", "127.0.0.1:80", true},
		{"tcp6", "[::1]:443", true},
		{"tcp6", "[fe80::1%eth0]:80", true},
		{"tcp6", "[::ffff:169.254.169.254]:80", true},
		{"tcp4", "10.0.0.1:80", true},
		{"tcp4", "no-port", true},
		{"tcp4", "example.es:80", true}, // never a name: Control sees resolved IPs only
		{"tcp4", "192.0.2.10:80", true},
		{"tcp4", "198.51.100.10:80", true},
		{"tcp4", "203.0.113.10:443", true},
		{"tcp4", "192.88.99.1:80", true},
		{"tcp6", "[::ffff:203.0.113.10]:80", true},
		{"tcp6", "[2002:c0a8:101::1]:80", true}, // 6to4 embedding 192.168.1.1
		{"tcp6", "[2001:0:4136:e378:8000:63bf:3fff:fdd2]:80", true},
		{"tcp6", "[::a00:1]:80", true}, // IPv4-compatible 10.0.0.1
		{"tcp6", "[100::5]:80", true},
		{"tcp6", "[fec0::1]:80", true},
		{"tcp6", "[fec0::1%eth0]:80", true},
		{"tcp6", "[2001:4860:4860::8888%eth0]:443", true},
		{"tcp4", "8.8.8.8:80", false},
		{"tcp6", "[2001:4860:4860::8888]:443", false},
		{"tcp6", "[2606:4700::1111]:443", false},
	}
	for _, c := range cases {
		t.Run(c.address, func(t *testing.T) {
			err := checkDialAddress(c.network, c.address, nil)
			if got := errors.Is(err, ErrBlockedAddress); got != c.wantBlocked {
				t.Errorf("checkDialAddress(%q, %q) = %v, want blocked %v", c.network, c.address, err, c.wantBlocked)
			}
			if !c.wantBlocked && err != nil {
				t.Errorf("checkDialAddress(%q, %q) = %v, want nil", c.network, c.address, err)
			}
		})
	}
}

func TestHostAllowed(t *testing.T) {
	allowed := []string{"crl.example.es", "ocsp.example.es:8080", "tls.example.es", "www.signe.es"}
	cases := []struct {
		url  string
		want bool
	}{
		{"http://WWW.SIGNE.ES/x.crl", true},
		// U+0130 lowercases to "i", but the transport dials the IDNA form.
		{"http://www.sİgne.es/x.crl", false},
		{"http://www.s%C4%B0gne.es/x.crl", false},
		{"http://www.s%c4%b0gne.es/x.crl", false},
		{"http://crl.example.es/a.crl", true},
		{"http://crl.example.es:80/a.crl", true},
		{"https://tls.example.es:443/a.crl", true},
		{"https://tls.example.es/a.crl", true},
		{"http://CRL.Example.ES/a.crl", true},
		{"http://ocsp.example.es:8080/", true},
		{"http://ocsp.example.es/", false},
		{"http://crl.example.es:8080/a.crl", false},
		{"https://crl.example.es:80/a.crl", false},
		{"http://crl.example.es./a.crl", false},
		{"http://other.example.es/a.crl", false},
		{"http://u@crl.example.es/a.crl", false},
		{"http://u:p@crl.example.es/a.crl", false},
		{"http:crl.example.es/a.crl", false},
		{"ftp://crl.example.es/a.crl", false},
		{"ldap://crl.example.es/cn=CRL", false},
		{"file:///etc/hosts", false},
		{"http:///a.crl", false},
		{"//crl.example.es/a.crl", false},
		{"http://[::1]/a.crl", false},
	}
	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			u, err := url.Parse(c.url)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", c.url, err)
			}
			if got := hostAllowed(u, allowed); got != c.want {
				t.Errorf("hostAllowed(%q) = %v, want %v", c.url, got, c.want)
			}
		})
	}
}

func TestFetchBlocksPrivateDestination(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("must not be served"))
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		host string
	}{
		{"localhost name", net.JoinHostPort("localhost", port)},
		{"ipv4 literal", net.JoinHostPort("127.0.0.1", port)},
	}
	f := NewFetcher(FetcherOptions{})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := f.Fetch(t.Context(), FetchRequest{
				URL:          "http://" + c.host + "/x",
				MaxBytes:     1 << 10,
				Timeout:      5 * time.Second,
				AllowedHosts: []string{c.host},
			})
			if !errors.Is(err, ErrBlockedAddress) {
				t.Errorf("Fetch(%s) error = %v, want %v", c.host, err, ErrBlockedAddress)
			}
			if res.Body != nil || res.StatusCode != 0 {
				t.Errorf("Fetch(%s) result = status %d, %d body bytes, want none", c.host, res.StatusCode, len(res.Body))
			}
		})
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("server saw %d requests, want 0", got)
	}
}

func TestFetchHostNotAllowlisted(t *testing.T) {
	var dials atomic.Int64
	f := NewFetcher(FetcherOptions{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("fetchT: unexpected dial")
	}})
	allowed := []string{"crl.example.es"}
	cases := []struct {
		name string
		url  string
	}{
		{"host not listed", "http://other.example.es/a.crl"},
		{"port not listed", "http://crl.example.es:8080/a.crl"},
		{"ftp", "ftp://crl.example.es/a.crl"},
		{"ldap", "ldap://crl.example.es/cn=CRL?certificateRevocationList"},
		{"file", "file:///etc/hosts"},
		{"userinfo", "http://u@crl.example.es/a.crl"},
		{"userinfo with password", "http://u:p@crl.example.es/a.crl"},
		{"opaque", "http:crl.example.es/a.crl"},
		{"unparsable", "http://crl.example.es:bad/a.crl"},
		{"empty", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.Fetch(t.Context(), FetchRequest{URL: c.url, MaxBytes: 1 << 10, Timeout: time.Second, AllowedHosts: allowed})
			if !errors.Is(err, ErrHostNotAllowed) {
				t.Errorf("Fetch(%q) error = %v, want %v", c.url, err, ErrHostNotAllowed)
			}
		})
	}
	if got := dials.Load(); got != 0 {
		t.Errorf("dialer called %d times, want 0", got)
	}
}

func TestFetchRedirects(t *testing.T) {
	body := []byte("fetchT crl bytes")
	n := testpki.NewNet()
	a := http.NewServeMux()
	a.Handle("/a", testpki.Redirect("/b"))
	a.Handle("/b", testpki.Redirect("/c"))
	a.Handle("/c", testpki.Redirect("/d"))
	a.Handle("/d", testpki.Bytes("application/pkix-crl", body))
	a.Handle("/r1", testpki.Redirect("/r2"))
	a.Handle("/r2", testpki.Redirect("/r3"))
	a.Handle("/r3", testpki.Redirect("/r4"))
	a.Handle("/r4", testpki.Redirect("/r5"))
	a.Handle("/r5", testpki.Bytes("application/pkix-crl", body))
	a.Handle("/to-b", testpki.Redirect("http://b.example.es/final.crl"))
	a.Handle("/to-c", testpki.Redirect("http://c.example.es/final.crl"))
	a.Handle("/to-https", testpki.Redirect("https://a.example.es/d"))
	n.Serve(t, "a.example.es", a)
	n.Serve(t, "b.example.es", testpki.Bytes("application/pkix-crl", body))
	var cHits atomic.Int64
	n.Serve(t, "c.example.es", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cHits.Add(1)
		_, _ = w.Write(body)
	}))
	var dialMu sync.Mutex
	var dialed []string
	f := NewFetcher(FetcherOptions{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialMu.Lock()
		dialed = append(dialed, addr)
		dialMu.Unlock()
		return n.DialContext(ctx, network, addr)
	}})
	allowed := []string{"a.example.es", "b.example.es"}

	cases := []struct {
		name      string
		url       string
		wantFinal string
		wantErr   error
	}{
		{"three redirects followed", "http://a.example.es/a", "http://a.example.es/d", nil},
		{"fourth redirect blocked", "http://a.example.es/r1", "", ErrRedirectBlocked},
		{"other allowlisted host", "http://a.example.es/to-b", "http://b.example.es/final.crl", nil},
		{"host not allowlisted", "http://a.example.es/to-c", "", ErrRedirectBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := f.Fetch(t.Context(), FetchRequest{URL: c.url, MaxBytes: 1 << 10, Timeout: 5 * time.Second, AllowedHosts: allowed})
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("Fetch(%s) error = %v, want %v", c.url, err, c.wantErr)
				}
				if res.Body != nil {
					t.Errorf("Fetch(%s) body = %q, want none", c.url, res.Body)
				}
				return
			}
			if err != nil {
				t.Fatalf("Fetch(%s) error = %v, want nil", c.url, err)
			}
			if res.FinalURL != c.wantFinal || !bytes.Equal(res.Body, body) || res.StatusCode != http.StatusOK {
				t.Errorf("Fetch(%s) = final %q status %d body %q, want final %q status 200 body %q",
					c.url, res.FinalURL, res.StatusCode, res.Body, c.wantFinal, body)
			}
		})
	}
	if got := cHits.Load(); got != 0 {
		t.Errorf("non-allowlisted host saw %d requests, want 0", got)
	}

	// An http -> https upgrade is followed. The fake network has no TLS
	// listener, so the fetch fails at the dial of port 443, after the
	// redirect check let it through.
	t.Run("upgrade to https followed", func(t *testing.T) {
		_, err := f.Fetch(t.Context(), FetchRequest{URL: "http://a.example.es/to-https", MaxBytes: 1 << 10, Timeout: 5 * time.Second, AllowedHosts: allowed})
		if err == nil || errors.Is(err, ErrRedirectBlocked) {
			t.Fatalf("Fetch error = %v, want a dial failure after the redirect", err)
		}
		dialMu.Lock()
		defer dialMu.Unlock()
		if !slices.Contains(dialed, "a.example.es:443") {
			t.Errorf("dialed %q, want a.example.es:443", dialed)
		}
	})
}

func TestCheckRedirectScheme(t *testing.T) {
	allowed := []string{"a.example.es", "b.example.es"}
	cases := []struct {
		name     string
		from, to string
		wantErr  error
	}{
		{"http to https to an allowlisted host", "http://a.example.es/x.crl", "https://b.example.es/x.crl", nil},
		{"http to https on the same host", "http://a.example.es/x.crl", "https://a.example.es/x.crl", nil},
		{"https to https", "https://a.example.es/x.crl", "https://b.example.es/x.crl", nil},
		{"https to http blocked", "https://a.example.es/x.crl", "http://a.example.es/x.crl", ErrRedirectBlocked},
		{"http to https to a host not allowlisted", "http://a.example.es/x.crl", "https://c.example.es/x.crl", ErrRedirectBlocked},
		{"http to ftp blocked", "http://a.example.es/x.crl", "ftp://a.example.es/x.crl", ErrRedirectBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), allowKey{}, allowed)
			prev, err := http.NewRequestWithContext(ctx, http.MethodGet, c.from, nil)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.to, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = checkRedirect(req, []*http.Request{prev})
			if (c.wantErr == nil && err != nil) || (c.wantErr != nil && !errors.Is(err, c.wantErr)) {
				t.Errorf("checkRedirect(%s -> %s) = %v, want %v", c.from, c.to, err, c.wantErr)
			}
		})
	}
}

// TestFetchRedirectNonASCIIHost: U+0130 lowercases to "i", so a Location on
// www.sİgne.es would compare equal to the allowlisted www.signe.es while the
// transport dials its IDNA form. Literal and percent-encoded, it is refused.
func TestFetchRedirectNonASCIIHost(t *testing.T) {
	n := testpki.NewNet()
	mux := http.NewServeMux()
	for path, loc := range map[string]string{
		"/literal": "http://www.sİgne.es/x.crl",
		"/encoded": "http://www.s%C4%B0gne.es/x.crl",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", loc) // verbatim: http.Redirect would escape it
			w.WriteHeader(http.StatusFound)
		})
	}
	n.Serve(t, "www.signe.es", mux)
	var conns fetchTConns
	f := NewFetcher(FetcherOptions{DialContext: conns.dial(n)})
	for _, path := range []string{"/literal", "/encoded"} {
		t.Run(path, func(t *testing.T) {
			_, err := f.Fetch(t.Context(), FetchRequest{URL: "http://www.signe.es" + path, MaxBytes: 1 << 10,
				Timeout: 5 * time.Second, AllowedHosts: []string{"www.signe.es"}})
			if !errors.Is(err, ErrRedirectBlocked) {
				t.Errorf("Fetch(%s) error = %v, want %v", path, err, ErrRedirectBlocked)
			}
		})
	}
	for _, addr := range conns.dialedAddrs() {
		if addr != "www.signe.es:80" {
			t.Errorf("dialed %q, want only www.signe.es:80", addr)
		}
	}
}

func TestFetchSizeCap(t *testing.T) {
	const limit = 1 << 10
	big := bytes.Repeat([]byte{0x30}, 4*limit)
	n := testpki.NewNet()
	mux := http.NewServeMux()
	mux.HandleFunc("/length", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(limit+1))
		_, _ = w.Write(big[:limit+1])
	})
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, _ *http.Request) {
		fl := w.(http.Flusher)
		for i := 0; i < len(big); i += 256 {
			_, _ = w.Write(big[i : i+256])
			fl.Flush()
		}
	})
	mux.HandleFunc("/exact", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(big[:limit])
	})
	n.Serve(t, "big.example.es", mux)
	f := NewFetcher(FetcherOptions{DialContext: n.DialContext})

	cases := []struct {
		path    string
		wantErr error
		wantLen int
	}{
		{"/length", ErrTooLarge, 0},
		{"/chunked", ErrTooLarge, 0},
		{"/exact", nil, limit},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			res, err := f.Fetch(t.Context(), FetchRequest{
				URL:          "http://big.example.es" + c.path,
				MaxBytes:     limit,
				Timeout:      5 * time.Second,
				AllowedHosts: []string{"big.example.es"},
			})
			if !errors.Is(err, c.wantErr) || (c.wantErr == nil && err != nil) {
				t.Fatalf("Fetch(%s) error = %v, want %v", c.path, err, c.wantErr)
			}
			if len(res.Body) != c.wantLen {
				t.Errorf("Fetch(%s) body length = %d, want %d", c.path, len(res.Body), c.wantLen)
			}
		})
	}
}

func TestFetchTimeout(t *testing.T) {
	n := testpki.NewNet()
	n.Serve(t, "slow.example.es", testpki.Slow(2*time.Second, testpki.Bytes("application/pkix-crl", []byte("late"))))
	f := NewFetcher(FetcherOptions{DialContext: n.DialContext})
	start := time.Now()
	res, err := f.Fetch(t.Context(), FetchRequest{
		URL:          "http://slow.example.es/x.crl",
		MaxBytes:     1 << 10,
		Timeout:      200 * time.Millisecond,
		AllowedHosts: []string{"slow.example.es"},
	})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Fetch error = %v, want %v", err, context.DeadlineExceeded)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("Fetch took %v, want about 200ms", elapsed)
	}
	if res.Duration <= 0 {
		t.Errorf("Fetch result Duration = %v, want > 0", res.Duration)
	}
}

func TestFetchConcurrency(t *testing.T) {
	cases := []struct {
		name     string
		max      int
		hosts    int
		wantPeak int64
		requests int
	}{
		{"default", 0, 8, MaxConcurrent, 40},
		{"custom", 4, 8, 4, 10},
		{"one host", 0, 1, maxConnsPerHost, 40},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var inflight, peak atomic.Int64
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			n := testpki.NewNet()
			var hosts []string
			for i := range c.hosts {
				hosts = append(hosts, "busy"+strconv.Itoa(i)+".example.es")
				n.Serve(t, hosts[i], http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer inflight.Add(-1)
					fetchTRaise(&peak, inflight.Add(1))
					select {
					case <-release:
						_, _ = w.Write([]byte("ok"))
					case <-r.Context().Done():
					}
				}))
			}
			t.Cleanup(unblock) // runs before the server cleanup (LIFO), also after a failure
			f := NewFetcher(FetcherOptions{DialContext: n.DialContext, MaxConcurrent: c.max})
			errs := make(chan error, c.requests)
			var wg sync.WaitGroup
			for i := range c.requests {
				wg.Go(func() {
					_, err := f.Fetch(t.Context(), FetchRequest{
						URL:          "http://" + hosts[i%len(hosts)] + "/x.crl",
						MaxBytes:     16,
						Timeout:      30 * time.Second,
						AllowedHosts: hosts,
					})
					errs <- err
				})
			}
			fetchTEventually(t, func() bool { return inflight.Load() >= c.wantPeak })
			time.Sleep(100 * time.Millisecond) // let any excess request reach the handler
			peakBeforeRelease := peak.Load()
			unblock()
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Errorf("Fetch error = %v, want nil", err)
				}
			}
			if peakBeforeRelease != c.wantPeak {
				t.Errorf("concurrent requests while blocked = %d, want %d", peakBeforeRelease, c.wantPeak)
			}
			if got := peak.Load(); got > c.wantPeak {
				t.Errorf("peak concurrent requests = %d, want <= %d", got, c.wantPeak)
			}
		})
	}
}

// TestFetchHungHostDoesNotStarveOthers: requests to a hung host beyond its
// connection cap wait for that host's permits, not holding global ones, so
// another host is still fetched within its timeout.
func TestFetchHungHostDoesNotStarveOthers(t *testing.T) {
	var hung atomic.Int64
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	n := testpki.NewNet()
	n.Serve(t, "hung.example.es", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hung.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	n.Serve(t, "fast.example.es", testpki.Bytes("application/pkix-crl", []byte("ok")))
	t.Cleanup(unblock) // runs before the server cleanup (LIFO), also after a failure
	var conns fetchTConns
	f := NewFetcher(FetcherOptions{DialContext: conns.dial(n)})
	hosts := []string{"hung.example.es", "fast.example.es"}
	var wg sync.WaitGroup
	for range MaxConcurrent {
		wg.Go(func() {
			_, _ = f.Fetch(t.Context(), FetchRequest{URL: "http://hung.example.es/x.crl", MaxBytes: 16,
				Timeout: 30 * time.Second, AllowedHosts: hosts})
		})
	}
	fetchTEventually(t, func() bool { return hung.Load() >= maxConnsPerHost })
	time.Sleep(100 * time.Millisecond) // let the excess requests queue

	res, err := f.Fetch(t.Context(), FetchRequest{URL: "http://fast.example.es/x.crl", MaxBytes: 16,
		Timeout: 2 * time.Second, AllowedHosts: hosts})
	if err != nil || string(res.Body) != "ok" {
		t.Errorf("Fetch(fast) = %q, %v while %d fetches hang on another host, want %q", res.Body, err, MaxConcurrent, "ok")
	}
	if !slices.Contains(conns.dialedAddrs(), "fast.example.es:80") {
		t.Errorf("dialed %q, want fast.example.es:80 among them", conns.dialedAddrs())
	}
	unblock()
	wg.Wait()
	if got := hung.Load(); got != MaxConcurrent {
		t.Errorf("hung host served %d requests, want %d", got, MaxConcurrent)
	}
}

// TestFetchCancelledDialsBounded: the transport detaches a dial from its
// request, so a Fetch cancelled while dialing releases its permit while the
// dial goes on. Round after round of such fetches must not pile up dials.
func TestFetchCancelledDialsBounded(t *testing.T) {
	var dialing, peak atomic.Int64
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := NewFetcher(FetcherOptions{DialContext: func(context.Context, string, string) (net.Conn, error) {
		defer dialing.Add(-1)
		fetchTRaise(&peak, dialing.Add(1))
		<-release // a destination that never answers the SYN
		return nil, errors.New("fetchT: dial released")
	}})
	for range 3 {
		var wg sync.WaitGroup
		for range MaxConcurrent {
			wg.Go(func() {
				_, err := f.Fetch(t.Context(), FetchRequest{URL: "http://hung.example.es/x.crl", MaxBytes: 16,
					Timeout: 50 * time.Millisecond, AllowedHosts: []string{"hung.example.es"}})
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("Fetch error = %v, want %v", err, context.DeadlineExceeded)
				}
			})
		}
		wg.Wait()
	}
	if got := peak.Load(); got < 1 || got > maxConnsPerHost {
		t.Errorf("outstanding dials peaked at %d, want 1..%d", got, maxConnsPerHost)
	}
}

// TestFetchHostCaseVariantsShareConns: every case variant of an allowlisted
// host, as the URL or as a redirect target, is requested under one lowercase
// host, so the variants share one idle pool instead of one pool each.
func TestFetchHostCaseVariantsShareConns(t *testing.T) {
	body := []byte("fetchT crl bytes")
	n := testpki.NewNet()
	mux := http.NewServeMux()
	mux.Handle("/final.crl", testpki.Bytes("application/pkix-crl", body))
	mux.HandleFunc("/to/{host}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.PathValue("host")+"/final.crl", http.StatusFound)
	})
	n.Serve(t, "crl.example.es", mux)
	var conns fetchTConns
	f := NewFetcher(FetcherOptions{DialContext: conns.dial(n)})
	for i := range 2 * maxIdleConns {
		v := fetchTCaseVariant("crl.example.es", i)
		for _, u := range []string{"http://" + v + "/final.crl", "http://crl.example.es/to/" + v} {
			res, err := f.Fetch(t.Context(), FetchRequest{URL: u, MaxBytes: 1 << 10, Timeout: 5 * time.Second,
				AllowedHosts: []string{"crl.example.es"}})
			if err != nil || !bytes.Equal(res.Body, body) {
				t.Fatalf("Fetch(%s) = %q, %v, want %q", u, res.Body, err, body)
			}
		}
	}
	if got := conns.open.Load(); got > 2 {
		t.Errorf("open connections after %d case variants = %d, want <= 2", 2*maxIdleConns, got)
	}
	for _, addr := range conns.dialedAddrs() {
		if addr != "crl.example.es:80" {
			t.Errorf("dialed %q, want crl.example.es:80", addr)
		}
	}
}

// TestFetchIdleConnsBounded: one idle connection per allowlisted host, and
// more hosts than maxIdleConns; the transport closes the excess.
func TestFetchIdleConnsBounded(t *testing.T) {
	n := testpki.NewNet()
	var hosts []string
	for i := range maxIdleConns + 8 {
		hosts = append(hosts, "crl"+strconv.Itoa(i)+".example.es")
		n.Serve(t, hosts[i], testpki.Bytes("application/pkix-crl", []byte("ok")))
	}
	var conns fetchTConns
	f := NewFetcher(FetcherOptions{DialContext: conns.dial(n)})
	for _, h := range hosts {
		if _, err := f.Fetch(t.Context(), FetchRequest{URL: "http://" + h + "/x.crl", MaxBytes: 16,
			Timeout: 5 * time.Second, AllowedHosts: hosts}); err != nil {
			t.Fatalf("Fetch(%s) error = %v", h, err)
		}
	}
	if got := conns.open.Load(); got > maxIdleConns {
		t.Errorf("open connections after %d hosts = %d, want <= %d", len(hosts), got, maxIdleConns)
	}
}

// TestFetchErrorOmitsResponseStrings: a Fetch error never quotes a Location
// or any other response bytes; the only URL in it is the requested one.
func TestFetchErrorOmitsResponseStrings(t *testing.T) {
	const sentinel = "SENTINELPII"
	raw := func(resp string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			c, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = buf.WriteString(resp)
			_ = buf.Flush()
		}
	}
	n := testpki.NewNet()
	mux := http.NewServeMux()
	mux.Handle("/foreign", testpki.Redirect("http://foreign.example.es/"+sentinel+"/a.crl?dni="+sentinel))
	mux.Handle("/downgrade", testpki.Redirect("ftp://a.example.es/"+sentinel+"?q="+sentinel))
	mux.Handle("/loop/", testpki.Redirect("/loop/"+sentinel+"?q="+sentinel))
	mux.Handle("/unrouted", testpki.Redirect("http://b.example.es/"+sentinel+"?q="+sentinel))
	mux.Handle("/bad-location", testpki.Redirect("http://a.example.es/%zz"+sentinel))
	mux.Handle("/bad-status", raw("HTTP/1.1 "+sentinel+"\r\n\r\n"))
	mux.Handle("/bad-header", raw("HTTP/1.1 200 OK\r\n"+sentinel+"\r\n\r\n"))
	mux.Handle("/bad-trailer", raw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n"+sentinel+"\r\n\r\n"))
	n.Serve(t, "a.example.es", mux)
	f := NewFetcher(FetcherOptions{DialContext: n.DialContext})
	cases := []struct {
		path    string
		wantErr error
	}{
		{"/foreign", ErrRedirectBlocked},
		{"/downgrade", ErrRedirectBlocked},
		{"/loop/x", ErrRedirectBlocked},
		{"/unrouted", nil},
		{"/bad-location", nil},
		{"/bad-status", nil},
		{"/bad-header", nil},
		{"/bad-trailer", nil},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			u := "http://a.example.es" + c.path
			_, err := f.Fetch(t.Context(), FetchRequest{URL: u, MaxBytes: 1 << 10, Timeout: 5 * time.Second,
				AllowedHosts: []string{"a.example.es", "b.example.es"}})
			if err == nil || (c.wantErr != nil && !errors.Is(err, c.wantErr)) {
				t.Fatalf("Fetch(%s) error = %v, want %v", u, err, c.wantErr)
			}
			msg := err.Error()
			if strings.Contains(msg, sentinel) || strings.Contains(msg, "foreign.example.es") {
				t.Errorf("Fetch(%s) error = %q, want no response-supplied text", u, msg)
			}
			if !strings.Contains(msg, strconv.Quote(u)) {
				t.Errorf("Fetch(%s) error = %q, want it to name the requested URL", u, msg)
			}
		})
	}
}

// TestFetchDialErrorClassified: a dial error is reduced to a fixed category.
// Its own text can name the resolver, a resolved address or an OS error.
func TestFetchDialErrorClassified(t *testing.T) {
	const leak = "10.1.2.3"
	addr := &net.TCPAddr{IP: net.ParseIP(leak), Port: 80}
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"resolver failure", &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "server misbehaving",
			Name: "ocsp.example.es", Server: leak + ":53"}}, errDialDNS},
		{"no such host", &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host",
			Name: "ocsp.example.es", Server: leak + ":53", IsNotFound: true}}, errDialDNS},
		{"timeout", &net.OpError{Op: "dial", Net: "tcp", Addr: addr, Err: os.ErrDeadlineExceeded}, errDialTimeout},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Addr: addr,
			Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, errDialRefused},
		{"blocked address", &net.OpError{Op: "dial", Net: "tcp", Addr: addr,
			Err: fmt.Errorf("%w: tcp4 %s", ErrBlockedAddress, leak)}, ErrBlockedAddress},
		{"other", &net.OpError{Op: "dial", Net: "tcp", Addr: addr,
			Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, errDial},
		{"opaque", errors.New("fetchT: dialer says " + leak), errDial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := NewFetcher(FetcherOptions{DialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, c.err
			}})
			const u = "http://ocsp.example.es/ocsp"
			_, err := f.Fetch(t.Context(), FetchRequest{URL: u, Body: []byte{0x30, 0x00}, MaxBytes: 1 << 10,
				Timeout: 5 * time.Second, AllowedHosts: []string{"ocsp.example.es"}})
			if !errors.Is(err, c.want) {
				t.Fatalf("Fetch error = %v, want %v", err, c.want)
			}
			want := (&url.Error{Op: "Post", URL: u, Err: c.want}).Error()
			if msg := err.Error(); msg != want || strings.Contains(msg, leak) {
				t.Errorf("Fetch error = %q, want %q", msg, want)
			}
		})
	}
}

func TestFetchRequestHeaders(t *testing.T) {
	type fetchTSeen struct {
		method, userAgent, contentType, accept, cookie, acceptEncoding string
		body                                                           []byte
	}
	var (
		mu   sync.Mutex
		seen []fetchTSeen
	)
	n := testpki.NewNet()
	n.Serve(t, "hdr.example.es", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, fetchTSeen{
			method:         r.Method,
			userAgent:      r.Header.Get("User-Agent"),
			contentType:    r.Header.Get("Content-Type"),
			accept:         r.Header.Get("Accept"),
			cookie:         r.Header.Get("Cookie"),
			acceptEncoding: r.Header.Get("Accept-Encoding"),
			body:           b,
		})
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "fetchT", Value: "tracking", Path: "/"})
		_, _ = w.Write([]byte("ok"))
	}))
	allowed := []string{"hdr.example.es"}
	custom := NewFetcher(FetcherOptions{UserAgent: "cert-check/1.2.3", DialContext: n.DialContext})
	def := NewFetcher(FetcherOptions{DialContext: n.DialContext})
	reqBody := []byte{0x30, 0x03, 0x02, 0x01, 0x01}

	steps := []struct {
		name string
		f    *Fetcher
		req  FetchRequest
		want fetchTSeen
	}{
		{
			name: "get sets a cookie",
			f:    custom,
			req:  FetchRequest{URL: "http://hdr.example.es/a.crl", Accept: "application/pkix-crl"},
			want: fetchTSeen{method: http.MethodGet, userAgent: "cert-check/1.2.3", accept: "application/pkix-crl"},
		},
		{
			name: "post sends no cookie",
			f:    custom,
			req: FetchRequest{URL: "http://hdr.example.es/ocsp", Body: reqBody,
				ContentType: "application/ocsp-request", Accept: "application/ocsp-response"},
			want: fetchTSeen{method: http.MethodPost, userAgent: "cert-check/1.2.3", contentType: "application/ocsp-request",
				accept: "application/ocsp-response", body: reqBody},
		},
		{
			name: "default user agent",
			f:    def,
			req:  FetchRequest{URL: "http://hdr.example.es/a.crl"},
			want: fetchTSeen{method: http.MethodGet, userAgent: "cert-check/dev"},
		},
	}
	for i, s := range steps {
		s.req.MaxBytes, s.req.Timeout, s.req.AllowedHosts = 1<<10, 5*time.Second, allowed
		res, err := s.f.Fetch(t.Context(), s.req)
		if err != nil {
			t.Fatalf("%s: Fetch error = %v", s.name, err)
		}
		if string(res.Body) != "ok" || res.StatusCode != http.StatusOK {
			t.Errorf("%s: result = status %d body %q, want 200 %q", s.name, res.StatusCode, res.Body, "ok")
		}
		mu.Lock()
		got := seen[i]
		mu.Unlock()
		if got.method != s.want.method || got.userAgent != s.want.userAgent || got.contentType != s.want.contentType ||
			got.accept != s.want.accept || got.cookie != "" || got.acceptEncoding != "" || !bytes.Equal(got.body, s.want.body) {
			t.Errorf("%s: server saw %+v, want %+v (no cookie, no Accept-Encoding)", s.name, got, s.want)
		}
	}
}

func TestFetchHTTPStatus(t *testing.T) {
	n := testpki.NewNet()
	mux := http.NewServeMux()
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusNotFound, http.StatusNoContent} {
		mux.HandleFunc("/"+strconv.Itoa(code), func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		})
	}
	n.Serve(t, "status.example.es", mux)
	f := NewFetcher(FetcherOptions{DialContext: n.DialContext})
	for _, code := range []int{http.StatusServiceUnavailable, http.StatusNotFound, http.StatusNoContent} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			res, err := f.Fetch(t.Context(), FetchRequest{
				URL:          "http://status.example.es/" + strconv.Itoa(code),
				MaxBytes:     1 << 10,
				Timeout:      5 * time.Second,
				AllowedHosts: []string{"status.example.es"},
			})
			if !errors.Is(err, ErrHTTPStatus) {
				t.Errorf("Fetch error = %v, want %v", err, ErrHTTPStatus)
			}
			if res.StatusCode != code || res.Body != nil {
				t.Errorf("Fetch result = status %d, %d body bytes, want status %d and no body", res.StatusCode, len(res.Body), code)
			}
		})
	}
}

// fetchTRaise raises peak to v if v is higher.
func fetchTRaise(peak *atomic.Int64, v int64) {
	for p := peak.Load(); v > p && !peak.CompareAndSwap(p, v); p = peak.Load() {
	}
}

// fetchTConns wraps a fake network: it records each dialed address, routes
// on its lowercase form (DNS names are case-insensitive) and counts the
// connections still open.
type fetchTConns struct {
	open   atomic.Int64
	mu     sync.Mutex
	dialed []string
}

func (c *fetchTConns) dial(n *testpki.Net) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c.mu.Lock()
		c.dialed = append(c.dialed, addr)
		c.mu.Unlock()
		conn, err := n.DialContext(ctx, network, strings.ToLower(addr))
		if err != nil {
			return nil, err
		}
		c.open.Add(1)
		return &fetchTConn{Conn: conn, close: sync.OnceFunc(func() { c.open.Add(-1) })}, nil
	}
}

func (c *fetchTConns) dialedAddrs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.dialed)
}

type fetchTConn struct {
	net.Conn
	close func()
}

func (c *fetchTConn) Close() error {
	c.close()
	return c.Conn.Close()
}

// fetchTCaseVariant uppercases the letters of s selected by the bits of mask.
func fetchTCaseVariant(s string, mask int) string {
	b := []byte(s)
	for i, bit := 0, 0; i < len(b); i++ {
		if 'a' <= b[i] && b[i] <= 'z' {
			if mask>>bit&1 == 1 {
				b[i] -= 'a' - 'A'
			}
			bit++
		}
	}
	return string(b)
}

// fetchTEventually polls cond until it holds or 10 s pass.
func fetchTEventually(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
