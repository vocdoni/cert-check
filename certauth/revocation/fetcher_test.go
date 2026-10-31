package revocation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
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
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
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
		{"tcp4", "8.8.8.8:80", false},
		{"tcp6", "[2001:4860:4860::8888]:443", false},
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
	allowed := []string{"crl.example.es", "ocsp.example.es:8080", "tls.example.es"}
	cases := []struct {
		url  string
		want bool
	}{
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
	f := NewFetcher(FetcherOptions{DialContext: n.DialContext})
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
		{"scheme change", "http://a.example.es/to-https", "", ErrRedirectBlocked},
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
		wantPeak int64
		requests int
	}{
		{"default", 0, MaxConcurrent, 40},
		{"custom", 4, 4, 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var inflight, peak atomic.Int64
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			n := testpki.NewNet()
			n.Serve(t, "busy.example.es", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cur := inflight.Add(1)
				defer inflight.Add(-1)
				for {
					p := peak.Load()
					if cur <= p || peak.CompareAndSwap(p, cur) {
						break
					}
				}
				select {
				case <-release:
					_, _ = w.Write([]byte("ok"))
				case <-r.Context().Done():
				}
			}))
			t.Cleanup(unblock) // runs before the server cleanup (LIFO), also after a failure
			f := NewFetcher(FetcherOptions{DialContext: n.DialContext, MaxConcurrent: c.max})
			errs := make(chan error, c.requests)
			var wg sync.WaitGroup
			for range c.requests {
				wg.Go(func() {
					_, err := f.Fetch(t.Context(), FetchRequest{
						URL:          "http://busy.example.es/x.crl",
						MaxBytes:     16,
						Timeout:      30 * time.Second,
						AllowedHosts: []string{"busy.example.es"},
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
