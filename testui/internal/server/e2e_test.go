// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
	"github.com/vocdoni/cert-check/testui/internal/acme"
	"github.com/vocdoni/cert-check/testui/internal/config"
	"github.com/vocdoni/cert-check/testui/internal/server"
)

// The end-to-end world (spec AC6, AC7, AC13): the App served by Run on
// loopback listeners; a synthetic CA whose delegated responder answers on the
// fake host ocsp.test; the providers alpha and beta (one profile and one CA
// each, nonce on). Auth clients dial the auth listener whatever the URL host
// says, with the authUrl host as SNI. The main API is called with an explicit
// Cookie header: cookiejar does not send Secure cookies over http.
const (
	e2eAuthDomain = "auth.test"
	e2eAlphaHost  = "alpha." + e2eAuthDomain
	e2eBetaHost   = "beta." + e2eAuthDomain
	e2eOCSPHost   = "ocsp.test"
	e2eVersion    = "e2e-version"

	// The synthetic holder: none of these may reach a log line.
	e2eDNI       = "12345679S"
	e2eGivenName = "JUAN"
	e2eSurnames  = "GARCÍA LÓPEZ"
	e2eFullName  = "JUAN GARCÍA LÓPEZ"

	// Listener policies (spec "Security headers"); the server's constants are unexported.
	e2eMainCSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	e2eAuthCSP = "default-src 'none'; frame-ancestors 'none'"
)

var (
	e2ePolicyAlpha = asn1.ObjectIdentifier{1, 2, 3, 1}
	e2ePolicyBeta  = asn1.ObjectIdentifier{1, 2, 3, 2}
)

// e2eClock is the App clock (store, limiters, auth diagnostics).
type e2eClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *e2eClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *e2eClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// e2eLogs is a goroutine-safe JSON log buffer.
type e2eLogs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *e2eLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *e2eLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// logger logs everything (debug included) as JSON into l.
func (l *e2eLogs) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// withMsg decodes every log line and returns those whose msg is msg.
func (l *e2eLogs) withMsg(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(l.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// redeemResponse is every redeem body (ruling R41: a test-local error type).
type redeemResponse struct {
	Status      string                 `json:"status"`
	Result      *certcheck.Result      `json:"result"`
	Error       *redeemError           `json:"error"`
	Diagnostics *certcheck.Diagnostics `json:"diagnostics"`
}

type redeemError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// decodeRedeem decodes a redeem body strictly (unknown keys fail).
func decodeRedeem(t *testing.T, body []byte) redeemResponse {
	t.Helper()
	var r redeemResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("decode redeem body %s: %v", body, err)
	}
	return r
}

// e2eServer is an App served by Run on loopback listeners.
type e2eServer struct {
	mainURL  string // http://127.0.0.1:<port>: the public origin
	mainAddr string
	authAddr string
	authPort string
	pool     *x509.CertPool // trusts the auth listener certificate
	clk      *e2eClock
	logs     *e2eLogs
	main     *http.Client
	stop     func() error // cancels Run and returns its error; idempotent

	// Values handed out during the test, for TestE2ELogsNoPII.
	secrets []string // states, codes and cookies
	diagIDs []string // diagnostic IDs of failures
}

// startE2E serves an App over providers on loopback listeners until the test
// ends; the cleanup asserts that Run returned nil.
func startE2E(t *testing.T, providers []certcheck.Provider, logs *e2eLogs, clk *e2eClock) *e2eServer {
	t.Helper()
	mainLn, authLn := e2eListen(t), e2eListen(t)
	s := &e2eServer{mainURL: "http://" + mainLn.Addr().String(), mainAddr: mainLn.Addr().String(),
		authAddr: authLn.Addr().String(), clk: clk, logs: logs}
	_, s.authPort, _ = net.SplitHostPort(s.authAddr)
	authPort, err := strconv.Atoi(s.authPort)
	if err != nil {
		t.Fatalf("auth port %q: %v", s.authPort, err)
	}
	public, err := url.Parse(s.mainURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s.mainURL, err)
	}
	serverCert, pool := testpki.ServerTLS(t, "*."+e2eAuthDomain)
	s.pool = pool
	app, err := server.New(server.Deps{
		Config:    config.Config{PublicURL: public, AuthDomain: e2eAuthDomain, AuthPublicPort: authPort, TrustedProxyHops: 1},
		Providers: providers, Certs: acme.NewStatic(serverCert), Logger: logs.logger(), Version: e2eVersion, Now: clk.Now,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var runErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		defer close(done)
		runErr = app.Run(ctx, mainLn, authLn)
	})
	s.stop = sync.OnceValue(func() error {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			return errors.New("Run did not return within 20s of the cancel")
		}
		wg.Wait()
		return runErr
	})
	t.Cleanup(func() {
		if err := s.stop(); err != nil {
			t.Errorf("Run = %v, want nil", err)
		}
	})
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections) // runs before the stop above
	s.main = &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.waitReady(t)
	return s
}

func e2eListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// waitReady polls /readyz until both listeners serve.
func (s *e2eServer) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, _ := s.do(t, s.request(t, http.MethodGet, "/readyz", "", ""))
		if resp.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz = %d after 5s, want 200", resp.StatusCode)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// request builds a main-listener request; a non-empty body is a same-origin
// JSON POST, a non-empty cookie is sent in an explicit Cookie header.
func (s *e2eServer) request(t *testing.T, method, path, body, cookie string) *http.Request {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequestWithContext(t.Context(), method, s.mainURL+path, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", s.mainURL)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if cookie != "" {
		r.Header.Set("Cookie", server.CookieName+"="+cookie)
	}
	return r
}

// do sends r with the main client and reads the whole body.
func (s *e2eServer) do(t *testing.T, r *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := s.main.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", r.Method, r.URL.Path, err)
	}
	return resp, readBody(t, resp)
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

// create runs POST /api/v1/transactions and returns the authUrl and the cookie.
func (s *e2eServer) create(t *testing.T, provider string) (authURL, cookie string) {
	t.Helper()
	resp, body := s.do(t, s.request(t, http.MethodPost, "/api/v1/transactions", `{"provider":"`+provider+`"}`, ""))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create %s: status %d, want 201; body %s", provider, resp.StatusCode, body)
	}
	var got struct {
		AuthURL   string `json:"authUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("create body %s: %v", body, err)
	}
	wantPrefix := "https://" + provider + "." + e2eAuthDomain + ":" + s.authPort + "/v1/authenticate?state="
	if !strings.HasPrefix(got.AuthURL, wantPrefix) {
		t.Fatalf("authUrl %q, want prefix %q", got.AuthURL, wantPrefix)
	}
	c := txCookie(resp)
	if c == nil || c.Value == "" {
		t.Fatalf("create %s: no %s cookie in %q", provider, server.CookieName, resp.Header.Values("Set-Cookie"))
	}
	s.secrets = append(s.secrets, strings.TrimPrefix(got.AuthURL, wantPrefix), c.Value)
	return got.AuthURL, c.Value
}

// redeem runs POST /api/v1/transactions/redeem; an empty cookie sends none.
func (s *e2eServer) redeem(t *testing.T, code, cookie string) (*http.Response, []byte) {
	t.Helper()
	return s.do(t, s.request(t, http.MethodPost, "/api/v1/transactions/redeem", `{"code":"`+code+`"}`, cookie))
}

// redeemOK redeems and expects 200 (a success or a validation error).
func (s *e2eServer) redeemOK(t *testing.T, code, cookie string) redeemResponse {
	t.Helper()
	resp, body := s.redeem(t, code, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem: status %d, want 200; body %s", resp.StatusCode, body)
	}
	got := decodeRedeem(t, body)
	if got.Diagnostics != nil {
		s.diagIDs = append(s.diagIDs, got.Diagnostics.DiagnosticID)
	}
	return got
}

// redeemRejected redeems and expects the 400 invalid_or_expired answer with
// minimal diagnostics carrying technical; it returns the body.
func (s *e2eServer) redeemRejected(t *testing.T, code, cookie, technical string) []byte {
	t.Helper()
	resp, body := s.redeem(t, code, cookie)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("redeem: status %d, want 400; body %s", resp.StatusCode, body)
	}
	got := decodeRedeem(t, body)
	if got.Status != "error" || got.Result != nil || got.Error == nil || got.Error.Code != "invalid_or_expired" ||
		got.Error.Retryable || got.Error.Message == "" || got.Diagnostics == nil {
		t.Fatalf("redeem body = %s, want status error, invalid_or_expired, not retryable, with diagnostics", body)
	}
	d := got.Diagnostics
	if !e2eHex32.MatchString(d.DiagnosticID) || d.Code != "invalid_or_expired" || d.TechnicalDetail != technical ||
		d.ServerVersion != e2eVersion || d.Time.IsZero() || d.Provider != "" || d.TLS != nil || d.Certificate != nil {
		t.Errorf("diagnostics = %+v, want only id, time, version, code invalid_or_expired and technicalDetail %q", d, technical)
	}
	s.diagIDs = append(s.diagIDs, d.DiagnosticID)
	return body
}

// txCookie returns the transaction cookie a response sets.
func txCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == server.CookieName {
			return c
		}
	}
	return nil
}

// authClient returns a client whose connections all reach the auth
// listener with SNI sni, presenting cert (nil: no certificate), offering h2
// and http/1.1 and a session cache, never following redirects.
func (s *e2eServer) authClient(t *testing.T, sni string, cert *tls.Certificate) *http.Client {
	t.Helper()
	cfg := &tls.Config{ServerName: sni, RootCAs: s.pool, NextProtos: []string{"h2", "http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(8)}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, s.authAddr)
		},
		TLSClientConfig:   cfg,
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// authGet sends GET rawURL with c; host overrides the Host header when set.
func authGet(t *testing.T, c *http.Client, rawURL, host string) (*http.Response, []byte) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if host != "" {
		r.Host = host
	}
	resp, err := c.Do(r)
	if err != nil {
		t.Fatalf("GET %s: %v", r.URL.Path, err)
	}
	return resp, readBody(t, resp)
}

var e2eHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

// rawOptionsAsterisk sends "OPTIONS * HTTP/1.1" on conn (an http.Client
// cannot) and returns the response with its body; conn is closed.
func rawOptionsAsterisk(t *testing.T, conn net.Conn, host string) (*http.Response, []byte) {
	t.Helper()
	defer func() { _ = conn.Close() }() // the response is fully read below
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, "OPTIONS * HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write OPTIONS *: %v", err)
	}
	req := &http.Request{Method: http.MethodOptions, URL: &url.URL{Path: "*"}, Host: host}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read OPTIONS * response: %v", err)
	}
	return resp, readBody(t, resp)
}

// checkAuthResponse asserts the status, the auth-listener headers and an
// empty body (ruling R37).
func checkAuthResponse(t *testing.T, resp *http.Response, body []byte, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Errorf("auth status = %d, want %d", resp.StatusCode, status)
	}
	checkSecurityHeaders(t, resp.Header, e2eAuthCSP, true)
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("auth Content-Type = %q, want text/plain; charset=utf-8", got)
	}
	if len(body) != 0 {
		t.Errorf("auth body = %q, want empty (the auth listener renders nothing)", body)
	}
}

// checkSecurityHeaders asserts the listener headers of spec AC7.
func checkSecurityHeaders(t *testing.T, h http.Header, csp string, noStore bool) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":   csp,
		"Referrer-Policy":           "no-referrer",
		"X-Content-Type-Options":    "nosniff",
		"Strict-Transport-Security": "max-age=31536000",
	}
	if noStore {
		want["Cache-Control"] = "no-store"
	}
	for k, v := range want {
		if got := h.Values(k); !slices.Equal(got, []string{v}) {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

// authenticate follows authURL with c and returns the code from the 303.
func (s *e2eServer) authenticate(t *testing.T, c *http.Client, authURL string) string {
	t.Helper()
	resp, body := authGet(t, c, authURL, "")
	checkAuthResponse(t, resp, body, http.StatusSeeOther)
	loc := resp.Header.Get("Location")
	code, ok := strings.CutPrefix(loc, s.mainURL+"/#code=")
	if !ok || len(code) != 43 {
		t.Fatalf("Location = %q, want %s/#code=<43 chars>", loc, s.mainURL)
	}
	s.secrets = append(s.secrets, code)
	return code
}

// invalidState GETs rawURL with c and expects the 303 to #error=invalid_state;
// it returns the diagnostic ID, which must be in an INFO log line.
func (s *e2eServer) invalidState(t *testing.T, c *http.Client, rawURL string) string {
	t.Helper()
	resp, body := authGet(t, c, rawURL, "")
	checkAuthResponse(t, resp, body, http.StatusSeeOther)
	loc := resp.Header.Get("Location")
	diag, ok := strings.CutPrefix(loc, s.mainURL+"/#error=invalid_state&diag=")
	if !ok || !e2eHex32.MatchString(diag) {
		t.Fatalf("Location = %q, want %s/#error=invalid_state&diag=<32 hex>", loc, s.mainURL)
	}
	var found bool
	for _, r := range s.logs.withMsg(t, "auth state rejected") {
		if r["diagnosticId"] == diag && r["level"] == "INFO" {
			found = true
		}
	}
	if !found {
		t.Errorf("no INFO \"auth state rejected\" line with diagnosticId %s", diag)
	}
	s.diagIDs = append(s.diagIDs, diag)
	return diag
}

// e2ePKI is the synthetic CA, its OCSP responder on the fake network and the
// alpha and beta providers.
type e2ePKI struct {
	now       time.Time
	ocsp      *testpki.OCSPServer
	leaf      *testpki.Leaf
	leafTLS   tls.Certificate
	providers []certcheck.Provider
}

func newE2EPKI(t *testing.T, logger *slog.Logger) *e2ePKI {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	ca := testpki.NewRoot(t, "E2E Test CA", testpki.CertSpec{Now: now})
	ocsp := testpki.NewOCSPServer(ca, ca.OCSPResponder(t, testpki.CertSpec{Now: now}))
	ocsp.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: now, NextUpdate: now.Add(time.Hour)}
	})
	n := testpki.NewNet()
	n.Serve(t, e2eOCSPHost, ocsp.Handler(t))
	rc, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/e2e", DialContext: n.DialContext, Now: clock, Logger: logger})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	betaCA := testpki.NewRoot(t, "E2E Beta Test CA", testpki.CertSpec{Now: now})
	var providers []certcheck.Provider
	for _, d := range e2eProviders(ca, betaCA) {
		p, err := engine.New(engine.Config{Provider: d, Revocation: rc, Now: clock, Logger: logger, Version: e2eVersion})
		if err != nil {
			t.Fatalf("engine.New(%s): %v", d.ID, err)
		}
		providers = append(providers, p)
	}
	leaf := ca.Leaf(t, testpki.CertSpec{
		Now: now,
		Subject: testpki.Name{
			testpki.Printable(testpki.OIDCountry, "ES"),
			testpki.Printable(testpki.OIDSerialNumber, "IDCES-"+e2eDNI),
			testpki.UTF8(testpki.OIDGivenName, e2eGivenName),
			testpki.UTF8(testpki.OIDSurname, e2eSurnames),
			testpki.UTF8(testpki.OIDCommonName, e2eFullName),
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:    []asn1.ObjectIdentifier{e2ePolicyAlpha},
		OCSPServers: []string{"http://" + e2eOCSPHost + "/"},
	})
	return &e2ePKI{now: now, ocsp: ocsp, leaf: leaf, leafTLS: leaf.TLSCertificate(), providers: providers}
}

// e2eProviders: alpha (under alphaCA) and beta (under betaCA), one profile
// each, policies 1.2.3.1 / 1.2.3.2; OCSP on ocsp.test with a nonce. Each has
// its own CA because a Handler rejects two providers that advertise one CA.
func e2eProviders(alphaCA, betaCA *testpki.CA) []profiles.Provider {
	adapter := identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}}},
		Surnames:  identity.SurnamesFromSN, SAN: identity.SANCheck{Kind: identity.SANNone},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	profile := func(id, provider string, ca *testpki.CA, policy asn1.ObjectIdentifier) profiles.Profile {
		return profiles.Profile{ID: id, ProviderID: provider, Name: id, HolderRole: profiles.RoleNaturalPerson,
			Anchors: []profiles.Anchor{profiles.TestAnchor(ca.Cert)}, PolicyOIDs: []string{policy.String()},
			EKU: profiles.EKURequireClientAuth, Identity: adapter,
			Revocation: revocation.Policy{OCSPHosts: []string{e2eOCSPHost}, OCSPNonce: true}}
	}
	return []profiles.Provider{
		{ID: "alpha", Name: "Alpha - Test", Description: "Alpha test provider",
			Profiles: []profiles.Profile{profile("alpha-a", "alpha", alphaCA, e2ePolicyAlpha)}},
		{ID: "beta", Name: "Beta - Test", Description: "Beta test provider", Beta: true,
			Profiles: []profiles.Profile{profile("beta-a", "beta", betaCA, e2ePolicyBeta)}},
	}
}

// e2eWorld is the synthetic PKI served by a running App.
type e2eWorld struct {
	*e2eServer
	pki *e2ePKI
}

func newE2EWorld(t *testing.T) *e2eWorld {
	t.Helper()
	logs := &e2eLogs{}
	pki := newE2EPKI(t, logs.logger())
	return &e2eWorld{e2eServer: startE2E(t, pki.providers, logs, &e2eClock{t: pki.now}), pki: pki}
}

// client returns an auth client for provider's SNI presenting the test leaf.
func (w *e2eWorld) client(t *testing.T, provider string) *http.Client {
	t.Helper()
	return w.authClient(t, provider+"."+e2eAuthDomain, &w.pki.leafTLS)
}

// withHost returns rawURL with its hostname replaced (port kept).
func withHost(t *testing.T, rawURL, hostname string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	u.Host = net.JoinHostPort(hostname, u.Port())
	return u.String()
}

// flowSuccess: create, mTLS GET, 303 #code=, redeem with the cookie, 200
// success with the identity; the cookie is cleared. It returns the body.
func (w *e2eWorld) flowSuccess(t *testing.T) []byte {
	t.Helper()
	authURL, cookie := w.create(t, "alpha")
	code := w.authenticate(t, w.client(t, "alpha"), authURL)
	resp, body := w.redeem(t, code, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem: status %d, want 200; body %s", resp.StatusCode, body)
	}
	got := decodeRedeem(t, body)
	if got.Status != "success" || got.Result == nil || got.Error != nil || got.Diagnostics != nil {
		t.Fatalf("redeem body = %s, want status success with a result only", body)
	}
	r := got.Result
	id := r.Identity
	if id.Document.Type != identity.DocumentDNI || id.Document.Number != e2eDNI || id.GivenNames != e2eGivenName ||
		id.Surnames != e2eSurnames || id.FullName != e2eFullName {
		t.Errorf("identity = %+v, want DNI %s, %s / %s / %s", id, e2eDNI, e2eGivenName, e2eSurnames, e2eFullName)
	}
	if r.Provider.ID != "alpha" || r.Profile.ID != "alpha-a" || r.Profile.HolderRole != profiles.RoleNaturalPerson {
		t.Errorf("provider/profile = %+v / %+v, want alpha / alpha-a natural_person", r.Provider, r.Profile)
	}
	if rv := r.Revocation; rv.Status != revocation.StatusGood || rv.Method != revocation.MethodOCSP || rv.Source != e2eOCSPHost {
		t.Errorf("revocation = %+v, want good via ocsp from %s", rv, e2eOCSPHost)
	}
	if ti := r.Diagnostics.TLS; ti == nil || ti.Version != "TLS 1.2" || ti.SNI != e2eAlphaHost ||
		!ti.ClientCertificatePresented || ti.ChainLength != 1 {
		t.Errorf("diagnostics TLS = %+v, want TLS 1.2, SNI %s, one presented certificate", ti, e2eAlphaHost)
	}
	if d := r.Diagnostics; d.FailedStep != "" || d.Code != "" || d.TechnicalDetail != "" || !e2eHex32.MatchString(d.DiagnosticID) {
		t.Errorf("success diagnostics = %+v, want an ID and empty failedStep/code/technicalDetail", d)
	}
	if c := txCookie(resp); c == nil || c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("redeem Set-Cookie = %q, want the cookie cleared", resp.Header.Values("Set-Cookie"))
	}
	return body
}

// flowNoClientCertificate: the handshake succeeds without a certificate;
// redeem gives no_certificate with diagnostics. It returns the body.
func (w *e2eWorld) flowNoClientCertificate(t *testing.T) []byte {
	t.Helper()
	authURL, cookie := w.create(t, "alpha")
	code := w.authenticate(t, w.authClient(t, e2eAlphaHost, nil), authURL)
	resp, body := w.redeem(t, code, cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeem: status %d, want 200; body %s", resp.StatusCode, body)
	}
	got := decodeRedeem(t, body)
	if got.Status != "error" || got.Result != nil || got.Error == nil || got.Diagnostics == nil {
		t.Fatalf("redeem body = %s, want status error with error and diagnostics", body)
	}
	if e := got.Error; e.Code != string(certcheck.CodeNoCertificate) || e.Retryable || e.Message == "" {
		t.Errorf("error = %+v, want no_certificate, not retryable, with a message", e)
	}
	d := got.Diagnostics
	if !e2eHex32.MatchString(d.DiagnosticID) || d.Code != certcheck.CodeNoCertificate || d.Provider != "alpha" ||
		d.ServerVersion != e2eVersion || d.TLS == nil || d.TLS.ClientCertificatePresented || d.TLS.SNI != e2eAlphaHost {
		t.Errorf("diagnostics = %+v (TLS %+v), want no_certificate for alpha with SNI %s and no certificate", d, d.TLS, e2eAlphaHost)
	}
	w.diagIDs = append(w.diagIDs, d.DiagnosticID)
	return body
}

// flowWrongSNIProvider: alpha's state on beta's SNI is invalid_state and is
// spent: retrying on alpha fails too.
func (w *e2eWorld) flowWrongSNIProvider(t *testing.T) {
	t.Helper()
	authURL, _ := w.create(t, "alpha")
	w.invalidState(t, w.client(t, "beta"), withHost(t, authURL, e2eBetaHost))
	w.invalidState(t, w.client(t, "alpha"), authURL)
}

func (w *e2eWorld) flowReplayedState(t *testing.T) {
	t.Helper()
	authURL, _ := w.create(t, "alpha")
	c := w.client(t, "alpha")
	w.authenticate(t, c, authURL)
	w.invalidState(t, c, authURL)
}

func (w *e2eWorld) flowReplayedCode(t *testing.T) []byte {
	t.Helper()
	authURL, cookie := w.create(t, "alpha")
	code := w.authenticate(t, w.client(t, "alpha"), authURL)
	if got := w.redeemOK(t, code, cookie); got.Status != "success" {
		t.Fatalf("first redeem status = %q, want success", got.Status)
	}
	return w.redeemRejected(t, code, cookie, "code_unknown_or_expired")
}

func (w *e2eWorld) flowRedeemWithoutCookie(t *testing.T) {
	t.Helper()
	authURL, cookie := w.create(t, "alpha")
	code := w.authenticate(t, w.client(t, "alpha"), authURL)
	w.redeemRejected(t, code, "", "cookie_missing")
	w.redeemRejected(t, code, cookie, "code_unknown_or_expired") // the cookie-less attempt spent the code
}

func (w *e2eWorld) flowRedeemOtherCookie(t *testing.T) {
	t.Helper()
	authURL, _ := w.create(t, "alpha")
	_, other := w.create(t, "alpha") // a second, independent transaction
	code := w.authenticate(t, w.client(t, "alpha"), authURL)
	w.redeemRejected(t, code, other, "cookie_mismatch")
}

func (w *e2eWorld) flowExpiredBeforeAuth(t *testing.T) {
	t.Helper()
	authURL, _ := w.create(t, "alpha")
	w.clk.Advance(server.TxLifetime + time.Second)
	w.invalidState(t, w.client(t, "alpha"), authURL)
}

func (w *e2eWorld) flowExpiredBeforeRedeem(t *testing.T) {
	t.Helper()
	authURL, cookie := w.create(t, "alpha")
	code := w.authenticate(t, w.client(t, "alpha"), authURL)
	w.clk.Advance(server.TxLifetime + time.Second)
	w.redeemRejected(t, code, cookie, "code_unknown_or_expired")
}

// flowUnknownSNI: the handshake fails with internal_error; the rejection is
// logged at debug with the SNI (ruling R59).
func (w *e2eWorld) flowUnknownSNI(t *testing.T) {
	t.Helper()
	const gamma = "gamma." + e2eAuthDomain
	c := w.authClient(t, gamma, &w.pki.leafTLS)
	resp, err := c.Get("https://" + net.JoinHostPort(gamma, w.authPort) + "/v1/authenticate")
	if err == nil {
		_ = resp.Body.Close() // unexpected success; reported below
		t.Fatalf("GET with SNI %s: status %d, want a handshake failure", gamma, resp.StatusCode)
	}
	if !strings.Contains(err.Error(), "internal error") {
		t.Errorf("handshake error = %v, want the internal_error alert", err)
	}
	var found bool
	for _, r := range w.logs.withMsg(t, "auth handshake rejected: unknown SNI") {
		if r["sni"] == gamma && r["level"] == "DEBUG" {
			found = true
		}
	}
	if !found {
		t.Errorf("no DEBUG \"auth handshake rejected: unknown SNI\" line with sni %s", gamma)
	}
}

// flowHostMismatch: a Host other than the SNI is 421, before the state is
// consumed: the link still works afterwards.
func (w *e2eWorld) flowHostMismatch(t *testing.T) {
	t.Helper()
	authURL, cookie := w.create(t, "alpha")
	c := w.client(t, "alpha")
	resp, body := authGet(t, c, authURL, net.JoinHostPort(e2eBetaHost, w.authPort))
	checkAuthResponse(t, resp, body, http.StatusMisdirectedRequest)
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("421 Location = %q, want none", loc)
	}
	code := w.authenticate(t, c, authURL)
	if got := w.redeemOK(t, code, cookie); got.Status != "success" {
		t.Errorf("redeem after the 421: status %q, want success", got.Status)
	}
}

// flows are every flow above, for TestE2ELogsNoPII.
func (w *e2eWorld) flows() []struct {
	name string
	run  func(*testing.T)
} {
	return []struct {
		name string
		run  func(*testing.T)
	}{
		{"success", func(t *testing.T) { w.flowSuccess(t) }},
		{"no client certificate", func(t *testing.T) { w.flowNoClientCertificate(t) }},
		{"wrong SNI provider", w.flowWrongSNIProvider},
		{"replayed state", w.flowReplayedState},
		{"replayed code", func(t *testing.T) { w.flowReplayedCode(t) }},
		{"redeem without cookie", w.flowRedeemWithoutCookie},
		{"redeem with another cookie", w.flowRedeemOtherCookie},
		{"expired before auth", w.flowExpiredBeforeAuth},
		{"expired before redeem", w.flowExpiredBeforeRedeem},
		{"unknown SNI", w.flowUnknownSNI},
		{"host mismatch", w.flowHostMismatch},
	}
}

func TestE2ESuccess(t *testing.T) {
	w := newE2EWorld(t)
	w.flowSuccess(t)
	reqs := w.pki.ocsp.Requests()
	if len(reqs) != 1 || reqs[0].Nonce == nil {
		t.Errorf("OCSP server saw %d requests (%+v), want one with a nonce", len(reqs), reqs)
	}
	if len(reqs) == 1 && reqs[0].Serial.Cmp(w.pki.leaf.Cert.SerialNumber) != 0 {
		t.Errorf("OCSP request serial %x, want the leaf's %x", reqs[0].Serial, w.pki.leaf.Cert.SerialNumber)
	}
}

func TestE2ENoClientCertificate(t *testing.T) {
	newE2EWorld(t).flowNoClientCertificate(t)
}

func TestE2EWrongSNIProvider(t *testing.T) {
	newE2EWorld(t).flowWrongSNIProvider(t)
}

func TestE2EReplayedState(t *testing.T) {
	newE2EWorld(t).flowReplayedState(t)
}

func TestE2EReplayedCode(t *testing.T) {
	newE2EWorld(t).flowReplayedCode(t)
}

func TestE2ERedeemWithoutCookie(t *testing.T) {
	newE2EWorld(t).flowRedeemWithoutCookie(t)
}

func TestE2ERedeemOtherCookie(t *testing.T) {
	newE2EWorld(t).flowRedeemOtherCookie(t)
}

func TestE2EExpiredTransaction(t *testing.T) {
	w := newE2EWorld(t)
	t.Run("before the auth GET", w.flowExpiredBeforeAuth)
	t.Run("before redeem", w.flowExpiredBeforeRedeem)
}

func TestE2EUnknownSNI(t *testing.T) {
	newE2EWorld(t).flowUnknownSNI(t)
}

func TestE2EHostMismatch(t *testing.T) {
	newE2EWorld(t).flowHostMismatch(t)
}

func TestE2EHTTP11NoResumption(t *testing.T) {
	w := newE2EWorld(t)
	c := w.client(t, "alpha")
	rawURL := "https://" + net.JoinHostPort(e2eAlphaHost, w.authPort) + "/"
	for i := range 2 {
		resp, body := authGet(t, c, rawURL, "")
		checkAuthResponse(t, resp, body, http.StatusNotFound)
		if resp.TLS == nil {
			t.Fatalf("connection %d: no TLS state", i)
		}
		if resp.Proto != "HTTP/1.1" || resp.TLS.NegotiatedProtocol != "http/1.1" {
			t.Errorf("connection %d: proto %s, ALPN %q, want HTTP/1.1 and http/1.1 (h2 was offered)", i, resp.Proto, resp.TLS.NegotiatedProtocol)
		}
		if resp.TLS.DidResume {
			t.Errorf("connection %d resumed a TLS session; session resumption must be off", i)
		}
		c.CloseIdleConnections() // the next request reconnects
	}
}

func TestE2ESecurityHeaders(t *testing.T) {
	w := newE2EWorld(t)
	type check struct {
		name   string
		resp   *http.Response
		body   []byte
		status int
		auth   bool
	}
	var checks []check
	mainCheck := func(name string, r *http.Request, status int) {
		resp, body := w.do(t, r)
		checks = append(checks, check{name: name, resp: resp, body: body, status: status})
	}
	authCheck := func(name string, resp *http.Response, body []byte, status int) {
		checks = append(checks, check{name: name, resp: resp, body: body, status: status, auth: true})
	}

	mainCheck("GET /", w.request(t, http.MethodGet, "/", "", ""), http.StatusOK)
	mainCheck("GET /app.js", w.request(t, http.MethodGet, "/app.js", "", ""), http.StatusOK)
	mainCheck("GET /missing.txt", w.request(t, http.MethodGet, "/missing.txt", "", ""), http.StatusNotFound)
	mainCheck("GET /healthz", w.request(t, http.MethodGet, "/healthz", "", ""), http.StatusOK)
	mainCheck("GET /readyz", w.request(t, http.MethodGet, "/readyz", "", ""), http.StatusOK)
	mainCheck("GET /api/v1/providers", w.request(t, http.MethodGet, "/api/v1/providers", "", ""), http.StatusOK)
	mainCheck("GET /api/v1/transactions/current", w.request(t, http.MethodGet, "/api/v1/transactions/current", "", ""), http.StatusOK)
	mainCheck("POST transactions unknown provider",
		w.request(t, http.MethodPost, "/api/v1/transactions", `{"provider":"gamma"}`, ""), http.StatusBadRequest)
	textPlain := w.request(t, http.MethodPost, "/api/v1/transactions", `{"provider":"alpha"}`, "")
	textPlain.Header.Set("Content-Type", "text/plain")
	mainCheck("POST transactions text/plain", textPlain, http.StatusUnsupportedMediaType)
	mainCheck("POST redeem unknown code",
		w.request(t, http.MethodPost, "/api/v1/transactions/redeem", `{"code":"unknown"}`, "x"), http.StatusBadRequest)
	mainCheck("POST transactions", w.request(t, http.MethodPost, "/api/v1/transactions", `{"provider":"alpha"}`, ""), http.StatusCreated)

	authURL, cookie := w.create(t, "alpha")
	c := w.client(t, "alpha")
	resp, body := authGet(t, c, authURL, "")
	authCheck("auth 303 code", resp, body, http.StatusSeeOther)
	code, _ := strings.CutPrefix(resp.Header.Get("Location"), w.mainURL+"/#code=")
	mainCheck("POST redeem success", w.request(t, http.MethodPost, "/api/v1/transactions/redeem", `{"code":"`+code+`"}`, cookie), http.StatusOK)
	resp, body = authGet(t, c, authURL, "")
	authCheck("auth 303 error", resp, body, http.StatusSeeOther)
	resp, body = authGet(t, c, "https://"+net.JoinHostPort(e2eAlphaHost, w.authPort)+"/favicon.ico", "")
	authCheck("auth 404", resp, body, http.StatusNotFound)
	resp, body = authGet(t, c, authURL, net.JoinHostPort(e2eBetaHost, w.authPort))
	authCheck("auth 421", resp, body, http.StatusMisdirectedRequest)

	// OPTIONS * is answered by net/http itself unless the server disables
	// its general OPTIONS handler; then it reaches the listener's handler.
	mainConn, err := net.DialTimeout("tcp", w.mainAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial main: %v", err)
	}
	resp, body = rawOptionsAsterisk(t, mainConn, w.mainAddr)
	checks = append(checks, check{name: "OPTIONS * main", resp: resp, body: body, status: http.StatusBadRequest})
	authConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", w.authAddr, &tls.Config{
		ServerName: e2eAlphaHost, RootCAs: w.pool, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{w.pki.leafTLS},
	})
	if err != nil {
		t.Fatalf("dial auth: %v", err)
	}
	resp, body = rawOptionsAsterisk(t, authConn, net.JoinHostPort(e2eAlphaHost, w.authPort))
	authCheck("OPTIONS * auth", resp, body, http.StatusNotFound)

	for _, ch := range checks {
		t.Run(ch.name, func(t *testing.T) {
			if ch.auth {
				checkAuthResponse(t, ch.resp, ch.body, ch.status)
				return
			}
			if ch.resp.StatusCode != ch.status {
				t.Errorf("status = %d, want %d; body %s", ch.resp.StatusCode, ch.status, ch.body)
			}
			checkSecurityHeaders(t, ch.resp.Header, e2eMainCSP, strings.HasPrefix(ch.resp.Request.URL.Path, "/api/"))
		})
	}
}

func TestE2ELogsNoPII(t *testing.T) {
	w := newE2EWorld(t)
	for _, f := range w.flows() {
		t.Run(f.name, f.run)
	}
	logs := w.logs.String()
	// Failures with a diagnostic ID: no certificate 1, wrong SNI 2, replayed
	// state 1, replayed code 1, no cookie 2, other cookie 1, expired 2.
	if len(w.diagIDs) != 10 {
		t.Errorf("%d failure diagnostic IDs collected, want 10", len(w.diagIDs))
	}
	for _, id := range w.diagIDs {
		if !strings.Contains(logs, id) {
			t.Errorf("diagnosticId %s of a failure is not in the log", id)
		}
	}
	leaf := w.pki.leaf.Cert
	sum := sha256.Sum256(leaf.Raw)
	forbidden := []string{
		e2eDNI, e2eGivenName, e2eSurnames, "GARC", "LÓPEZ", `L\u00d3PEZ`, e2eFullName,
		leaf.Subject.String(), fmt.Sprintf("%x", leaf.SerialNumber), hex.EncodeToString(sum[:]), "state=",
	}
	if len(w.secrets) < 20 {
		t.Errorf("only %d states/codes/cookies collected", len(w.secrets))
	}
	for _, v := range append(forbidden, w.secrets...) {
		if strings.Contains(logs, v) {
			t.Errorf("the log contains %q", v)
		}
	}
	if t.Failed() {
		t.Logf("logs:\n%s", logs)
	}
}

func TestE2EGracefulShutdown(t *testing.T) {
	w := newE2EWorld(t)
	if resp, _ := w.do(t, w.request(t, http.MethodGet, "/healthz", "", "")); resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", resp.StatusCode)
	}
	resp, body := authGet(t, w.client(t, "alpha"), "https://"+net.JoinHostPort(e2eAlphaHost, w.authPort)+"/", "")
	checkAuthResponse(t, resp, body, http.StatusNotFound)

	start := time.Now()
	if err := w.stop(); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	t.Logf("Run returned %v after the cancel", time.Since(start))
	for _, addr := range []string{w.mainAddr, w.authAddr} {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close() // the assertion below is what matters
			t.Errorf("%s still accepts connections after Run returned", addr)
		}
	}
}
