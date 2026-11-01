package server

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth"
)

// authListenerHeaders are set on every auth-listener response.
var authListenerHeaders = map[string]string{
	"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
	"Referrer-Policy":           "no-referrer",
	"X-Content-Type-Options":    "nosniff",
	"Strict-Transport-Security": "max-age=31536000",
	"Cache-Control":             "no-store",
	"Content-Type":              "text/plain; charset=utf-8",
}

var (
	codeLocationRe    = regexp.MustCompile(`^https://check\.test/#code=([A-Za-z0-9_-]{43})$`)
	invalidLocationRe = regexp.MustCompile(`^https://check\.test/#error=invalid_state&diag=([0-9a-f]{32})$`)
)

// checkAuthResponse asserts the status, the auth-listener headers and an empty body (ruling R37).
func checkAuthResponse(t *testing.T, resp *http.Response, body []byte, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("status = %d, want %d", resp.StatusCode, status)
	}
	checkHeaders(t, resp.Header, authListenerHeaders)
	if len(body) != 0 {
		t.Errorf("body = %q, want empty (the auth listener renders nothing)", body)
	}
}

// authenticate follows authURL with cert and returns the code from the 303.
func (w *srvWorld) authenticate(t *testing.T, c *http.Client, authURL string) Secret {
	t.Helper()
	resp, body := authDo(t, c, http.MethodGet, authURL, "")
	checkAuthResponse(t, resp, body, http.StatusSeeOther)
	m := codeLocationRe.FindStringSubmatch(resp.Header.Get("Location"))
	if m == nil {
		t.Fatalf("Location = %q, want match %s", resp.Header.Get("Location"), codeLocationRe)
	}
	return Secret(m[1])
}

// storedOutcome redeems code with cookie directly in the store.
func (w *srvWorld) storedOutcome(t *testing.T, code, cookie Secret) Outcome {
	t.Helper()
	o, err := w.app.store.Redeem(code, cookie)
	if err != nil {
		t.Fatalf("store.Redeem: %v", err)
	}
	return o
}

func TestAuthNotFound(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	cases := []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodGet, "/favicon.ico"},
		{http.MethodPost, "/v1/authenticate"},
		{http.MethodHead, "/v1/authenticate"},
		{http.MethodGet, "/v1/authenticate/"},
		{http.MethodGet, "/api/v1/providers"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp, body := authDo(t, c, tc.method, "https://"+srvAlphaHost+":8443"+tc.path, "")
			checkAuthResponse(t, resp, body, http.StatusNotFound)
		})
	}
}

func TestAuthMisdirected(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	authURL, cookie := w.createTx(t, "alpha")
	for _, host := range []string{srvBetaHost + ":8443", srvBetaHost, "check.test", "alpha.auth.test.evil:8443"} {
		resp, body := authDo(t, c, http.MethodGet, authURL, host)
		checkAuthResponse(t, resp, body, http.StatusMisdirectedRequest)
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("Host %q: Location = %q, want none", host, loc)
		}
	}
	// The 421 is answered before the state is consumed.
	if got := w.app.store.Current(cookie).Status; got != TxPending {
		t.Fatalf("after 421s the transaction status = %q, want pending", got)
	}
	w.authenticate(t, c, authURL)
}

func TestAuthInvalidState(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	base := "https://" + srvAlphaHost + ":8443/v1/authenticate"
	cases := []struct {
		name  string
		setup func(t *testing.T) (rawURL string, state Secret)
	}{
		{"missing", func(*testing.T) (string, Secret) { return base, "" }},
		{"empty", func(*testing.T) (string, Secret) { return base + "?state=", "" }},
		{"unknown", func(*testing.T) (string, Secret) {
			s := NewSecret()
			return base + "?state=" + string(s), s
		}},
		{"malformed", func(*testing.T) (string, Secret) { return base + "?state=not-a-state", "not-a-state" }},
		{"duplicated", func(t *testing.T) (string, Secret) {
			authURL, _ := w.createTx(t, "alpha")
			s := stateOf(t, authURL)
			return authURL + "&state=" + string(s), s
		}},
		{"wrong provider", func(t *testing.T) (string, Secret) {
			authURL, _ := w.createTx(t, "beta")
			s := stateOf(t, authURL)
			return base + "?state=" + string(s), s
		}},
		{"used", func(t *testing.T) (string, Secret) {
			authURL, _ := w.createTx(t, "alpha")
			w.authenticate(t, c, authURL)
			return authURL, stateOf(t, authURL)
		}},
		{"expired", func(t *testing.T) (string, Secret) { // last: moves the clock
			authURL, _ := w.createTx(t, "alpha")
			w.clk.Advance(TxLifetime)
			return authURL, stateOf(t, authURL)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawURL, state := tc.setup(t)
			resp, body := authDo(t, c, http.MethodGet, rawURL, "")
			checkAuthResponse(t, resp, body, http.StatusSeeOther)
			m := invalidLocationRe.FindStringSubmatch(resp.Header.Get("Location"))
			if m == nil {
				t.Fatalf("Location = %q, want match %s", resp.Header.Get("Location"), invalidLocationRe)
			}
			diag := m[1]
			var found bool
			for _, r := range w.logs.withMsg(t, "auth state rejected") {
				if r["diagnosticId"] != diag {
					continue
				}
				found = true
				if r["level"] != "WARN" || r["sni"] != srvAlphaHost || r["reason"] == "" || r["reason"] == nil {
					t.Errorf("log line = %v, want level WARN, sni %q and a reason", r, srvAlphaHost)
				}
			}
			if !found {
				t.Errorf("no \"auth state rejected\" line with diagnosticId %s; logs:\n%s", diag, w.logs)
			}
			u, err := url.Parse(rawURL)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			w.logs.noLeak(t, string(state), u.RawQuery, "state=")
		})
	}
}

func TestAuthSuccessRedirect(t *testing.T) {
	w := newSrvWorld(t, srvOptions{logLevel: slog.LevelDebug})
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	authURL, cookie := w.createTx(t, "alpha")
	code := w.authenticate(t, c, authURL)
	if got := w.app.store.Current(cookie).Status; got != TxCompleted {
		t.Errorf("transaction status = %q, want completed", got)
	}

	rec := w.redeem(code, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"success"`) ||
		!strings.Contains(rec.Body.String(), "12345679S") {
		t.Errorf("redeem: status %d body %s, want 200 success with the identity", rec.Code, rec.Body)
	}

	recs := w.logs.withMsg(t, "authentication succeeded")
	if len(recs) != 1 {
		t.Fatalf("got %d \"authentication succeeded\" lines, want 1; logs:\n%s", len(recs), w.logs)
	}
	r := recs[0]
	id, _ := r["diagnosticId"].(string)
	if r["level"] != "INFO" || r["provider"] != "alpha" || r["profile"] != "alpha-a" || r["revocationMethod"] != "ocsp" ||
		!srvHex32.MatchString(id) {
		t.Errorf("log line = %v, want INFO with provider alpha, profile alpha-a, revocationMethod ocsp and a diagnostic ID", r)
	}
	w.logs.noLeak(t, append(srvIdentityValues, string(code), string(cookie), string(stateOf(t, authURL)))...)
}

func TestAuthNoCertificate(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	run := w.start(t)
	c := w.authClient(t, run.authAddr, nil)
	authURL, cookie := w.createTx(t, "alpha")
	o := w.storedOutcome(t, w.authenticate(t, c, authURL), cookie)
	if o.Err == nil || o.Err.Code != certauth.CodeNoCertificate {
		t.Fatalf("outcome = %+v, want no_certificate", o)
	}
	if tlsInfo := o.Err.Diagnostics.TLS; tlsInfo == nil || tlsInfo.SNI != srvAlphaHost || tlsInfo.ClientCertificatePresented {
		t.Errorf("diagnostics TLS = %+v, want SNI %s without a client certificate", tlsInfo, srvAlphaHost)
	}
	if recs := w.logs.withMsg(t, "authentication failed"); len(recs) != 1 || recs[0]["code"] != "no_certificate" {
		t.Errorf("\"authentication failed\" lines = %v, want one with code no_certificate", recs)
	}
}

func TestAuthSlotsExhausted(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	for range cap(w.app.auth.slots) {
		w.app.auth.slots <- struct{}{}
	}
	w.app.auth.slotWait = 10 * time.Millisecond
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	authURL, cookie := w.createTx(t, "alpha")
	w.clk.Advance(time.Second) // diagnostics time follows the injected clock (ruling R47)

	o := w.storedOutcome(t, w.authenticate(t, c, authURL), cookie)
	if o.Err == nil || o.Err.Code != certauth.CodeInternal || !o.Err.Retryable {
		t.Fatalf("outcome = %+v, want internal, retryable", o)
	}
	d := o.Err.Diagnostics
	if !srvHex32.MatchString(d.DiagnosticID) || !d.Time.Equal(w.clk.Now()) || d.ServerVersion != srvVersion ||
		d.Code != certauth.CodeInternal || d.Provider != "alpha" || d.TLS == nil || d.TechnicalDetail == "" {
		t.Errorf("diagnostics = %+v, want id, time %v, version %q, code internal, provider alpha, TLS info and a detail",
			d, w.clk.Now(), srvVersion)
	}
	if got := len(w.app.auth.slots); got != ValidationSlots {
		t.Errorf("slots held = %d, want %d (a missed slot takes nothing)", got, ValidationSlots)
	}
}

func TestAuthBudget(t *testing.T) {
	w := newSrvWorld(t, srvOptions{ocspDelay: time.Second})
	w.app.auth.budget = 100 * time.Millisecond
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	authURL, cookie := w.createTx(t, "alpha")

	start := time.Now()
	code := w.authenticate(t, c, authURL)
	if d := time.Since(start); d >= time.Second {
		t.Errorf("the 303 took %v, want less than the 1s OCSP delay", d)
	}
	o := w.storedOutcome(t, code, cookie)
	if o.Err == nil || o.Err.Code != certauth.CodeInternal || !o.Err.Retryable {
		t.Fatalf("outcome = %+v, want internal, retryable", o)
	}
	if got := o.Err.Diagnostics.TechnicalDetail; !strings.Contains(got, "deadline") {
		t.Errorf("technicalDetail = %q, want the validation deadline", got)
	}
}

// TestValidateWithoutTLS: Authenticate's error for a request without TLS
// state has no diagnostics; the handler stamps its own (ruling R60).
func TestValidateWithoutTLS(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	o := w.app.auth.validate(httptest.NewRequest(http.MethodGet, "http://"+srvAlphaHost+authenticatePath, nil))
	if o.Err == nil || o.Err.Code != certauth.CodeInternal || !o.Err.Retryable {
		t.Fatalf("outcome = %+v, want internal, retryable", o)
	}
	d := o.Err.Diagnostics
	if !srvHex32.MatchString(d.DiagnosticID) || !d.Time.Equal(w.clk.Now()) || d.ServerVersion != srvVersion ||
		d.Code != certauth.CodeInternal || d.TechnicalDetail == "" || d.TLS != nil {
		t.Errorf("diagnostics = %+v, want a diagnostic ID, time %v, version %q, code internal, a detail and no TLS info",
			d, w.clk.Now(), srvVersion)
	}
}

func TestLimitListener(t *testing.T) {
	ln := newLimitListener(srvListen(t), 2)
	accepted := make(chan net.Conn, 4)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	})
	t.Cleanup(func() {
		_ = ln.Close() // ends the accept loop
		wg.Wait()
		close(accepted)
		for c := range accepted {
			_ = c.Close() // test teardown
		}
	})
	dial := func(t *testing.T) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() }) // test teardown
		return c
	}
	waitAccepted := func(t *testing.T) net.Conn {
		t.Helper()
		select {
		case c := <-accepted:
			t.Cleanup(func() { _ = c.Close() }) // test teardown; a second Close is harmless
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("connection not accepted within 5s")
			return nil
		}
	}

	dial(t)
	first := waitAccepted(t)
	dial(t)
	waitAccepted(t)

	third := dial(t)
	if err := third.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := third.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("third connection: Read = (%d, %v), want (0, EOF or reset) before any byte", n, err)
	}
	select {
	case <-accepted:
		t.Fatal("the third connection reached Accept's caller")
	default:
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	dial(t)
	waitAccepted(t)
}

func TestAuthServerHTTP11Only(t *testing.T) {
	srv := newAuthServer(http.NotFoundHandler(), srvDiscard)
	if srv.TLSNextProto == nil || len(srv.TLSNextProto) != 0 {
		t.Errorf("TLSNextProto = %v, want a non-nil empty map", srv.TLSNextProto)
	}
	for name, c := range map[string]struct{ got, want time.Duration }{
		"ReadHeaderTimeout": {srv.ReadHeaderTimeout, 10 * time.Second},
		"ReadTimeout":       {srv.ReadTimeout, 30 * time.Second},
		"WriteTimeout":      {srv.WriteTimeout, 60 * time.Second},
		"IdleTimeout":       {srv.IdleTimeout, 30 * time.Second},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
	if srv.MaxHeaderBytes != 16<<10 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 16<<10)
	}

	w := newSrvWorld(t, srvOptions{})
	run := w.start(t)
	c := w.authClient(t, run.authAddr, w.leafCert())
	resp, body := authDo(t, c, http.MethodGet, "https://"+srvAlphaHost+":8443/", "")
	checkAuthResponse(t, resp, body, http.StatusNotFound)
	if resp.Proto != "HTTP/1.1" || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "http/1.1" {
		var alpn string
		if resp.TLS != nil {
			alpn = resp.TLS.NegotiatedProtocol
		}
		t.Errorf("proto = %s, ALPN = %q, want HTTP/1.1 and http/1.1 (the client offered h2)", resp.Proto, alpn)
	}
	if resp.TLS != nil && (resp.TLS.Version != tls.VersionTLS12 || resp.TLS.DidResume) {
		t.Errorf("TLS version %x resumed %v, want TLS 1.2 without resumption", resp.TLS.Version, resp.TLS.DidResume)
	}
}

func TestServerErrorLogLevels(t *testing.T) {
	cases := []struct {
		name  string
		build func(*slog.Logger) *http.Server
		level slog.Level
	}{
		{"auth listener at debug (ruling R61)", func(l *slog.Logger) *http.Server { return newAuthServer(http.NotFoundHandler(), l) }, slog.LevelDebug},
		{"main listener at warn", func(l *slog.Logger) *http.Server { return newMainServer(http.NotFoundHandler(), l) }, slog.LevelWarn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, lvl := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn} {
				sink := &logSink{}
				srv := c.build(slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: lvl})))
				srv.ErrorLog.Print("http: TLS handshake error from 192.0.2.1:1234: EOF")
				recs := sink.records(t)
				if want := c.level >= lvl; (len(recs) == 1) != want {
					t.Fatalf("logger level %v: got %d records, want logged=%v", lvl, len(recs), want)
				}
				if len(recs) == 1 && recs[0]["level"] != c.level.String() {
					t.Errorf("logger level %v: record level = %v, want %v", lvl, recs[0]["level"], c.level)
				}
			}
		})
	}
}
