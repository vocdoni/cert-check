package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
	"github.com/vocdoni/cert-check/providers"
	"github.com/vocdoni/cert-check/testui/internal/config"
)

// The test world of api_test.go, auth_test.go and app_test.go: providers
// "alpha" (standard group) and "beta" (Beta group) under the auth domain
// "auth.test", one profile each with its own root; alpha's OCSP responder
// answers good on a fake network.
const (
	srvAuthDomain = "auth.test"
	srvAlphaHost  = "alpha.auth.test"
	srvBetaHost   = "beta.auth.test"
	srvOCSPHost   = "ocsp.alpha.test"
	srvPublicURL  = "https://check.test"
	srvAuthPort   = 8443
	srvVersion    = "test-version"
)

var (
	srvPolicyA = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	srvPolicyB = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1}
	// srvIdentityValues are the test leaf's identity values: they must never
	// appear in a log line or in a 400 body.
	srvIdentityValues = []string{"12345679S", "JUAN", "GARC", "LÓPEZ"}
	srvHex32          = regexp.MustCompile(`^[0-9a-f]{32}$`)
	srvDiscard        = slog.New(slog.DiscardHandler)
)

// srvOptions tunes newSrvWorld.
type srvOptions struct {
	ocspDelay time.Duration // delay before alpha's OCSP responder answers
	logLevel  slog.Level    // App logger level (zero = info)
	notReady  bool          // the auth certificate starts not ready
}

// srvWorld is the shared fixture: providers and a Handler over testpki
// declarations and an App built on them with a fake clock, a fake
// certificate source and a JSON log sink.
type srvWorld struct {
	now        time.Time  // provider and handler clock, certificate reference time
	clk        *fakeClock // App clock: store, limiters, auth diagnostics
	leaf       *testpki.Leaf
	providers  []certcheck.Provider // alpha and beta, clock fixed at now
	handler    *certcheck.Handler   // over providers, clock fixed at now
	certs      *fakeCerts
	serverPool *x509.CertPool // trusts the auth listener certificate
	logs       *logSink
	app        *App
	main       http.Handler
}

func newSrvWorld(t *testing.T, o srvOptions) *srvWorld {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	w := &srvWorld{now: now, clk: &fakeClock{t: now}, logs: &logSink{}}
	rootA := testpki.NewRoot(t, "Alpha Root", testpki.CertSpec{Now: now})
	rootB := testpki.NewRoot(t, "Beta Root", testpki.CertSpec{Now: now})

	ocsp := testpki.NewOCSPServer(rootA, rootA.OCSPResponder(t, testpki.CertSpec{Now: now}))
	ocsp.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: now, NextUpdate: now.Add(time.Hour)}
	})
	var ocspHandler http.Handler = ocsp.Handler(t)
	if o.ocspDelay > 0 {
		ocspHandler = testpki.Slow(o.ocspDelay, ocspHandler)
	}
	n := testpki.NewNet()
	n.Serve(t, srvOCSPHost, ocspHandler)
	rc, err := revocation.NewChecker(revocation.Options{
		UserAgent: "cert-check/test", DialContext: n.DialContext, Now: func() time.Time { return now },
		Logger: srvDiscard, OCSPTimeout: 5 * time.Second, CRLTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	adapter := identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}}},
		Surnames:  identity.SurnamesFromSN, SAN: identity.SANCheck{Kind: identity.SANNone},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	profile := func(id, provider string, root *testpki.CA, policy asn1.ObjectIdentifier) profiles.Profile {
		return profiles.Profile{ID: id, ProviderID: provider, Name: id, HolderRole: profiles.RoleNaturalPerson,
			Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{policy.String()},
			EKU: profiles.EKURequireClientAuth, Identity: adapter,
			Revocation: revocation.Policy{OCSPHosts: []string{srvOCSPHost}, OCSPNonce: true}} // no CRL fallback
	}
	clock := func() time.Time { return now }
	for _, d := range []profiles.Provider{
		{ID: "alpha", Name: "Alpha - Test", Description: "Alpha test provider",
			Profiles: []profiles.Profile{profile("alpha-a", "alpha", rootA, srvPolicyA)}},
		{ID: "beta", Name: "Beta - Test", Description: "Beta test provider", Beta: true,
			Profiles: []profiles.Profile{profile("beta-a", "beta", rootB, srvPolicyB)}},
	} {
		p, err := engine.New(engine.Config{Provider: d, Revocation: rc, Now: clock, Logger: srvDiscard, Version: srvVersion})
		if err != nil {
			t.Fatalf("engine.New(%s): %v", d.ID, err)
		}
		w.providers = append(w.providers, p)
	}
	w.handler, err = certcheck.NewHandler(w.providers, certcheck.WithClock(clock), certcheck.WithVersion(srvVersion))
	if err != nil {
		t.Fatalf("certcheck.NewHandler: %v", err)
	}
	w.leaf = rootA.Leaf(t, testpki.CertSpec{
		Now: now,
		Subject: testpki.Name{
			testpki.Printable(testpki.OIDCountry, "ES"),
			testpki.Printable(testpki.OIDSerialNumber, "IDCES-12345679S"),
			testpki.UTF8(testpki.OIDGivenName, "JUAN"),
			testpki.UTF8(testpki.OIDSurname, "GARCÍA LÓPEZ"),
			testpki.UTF8(testpki.OIDCommonName, "JUAN GARCÍA LÓPEZ"),
		},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:    []asn1.ObjectIdentifier{srvPolicyA},
		OCSPServers: []string{"http://" + srvOCSPHost + "/"},
	})
	serverCert, pool := testpki.ServerTLS(t, srvAlphaHost, srvBetaHost)
	w.serverPool = pool
	w.certs = &fakeCerts{cert: serverCert}
	w.certs.ready.Store(!o.notReady)

	logger := slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: o.logLevel}))
	w.app, err = New(Deps{Config: srvConfig(t), Providers: w.providers, Certs: w.certs, Logger: logger,
		Version: srvVersion, Now: w.clk.Now})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	w.main = w.app.MainHandler()
	return w
}

// srvConfig is the App configuration of the test world.
func srvConfig(t *testing.T) config.Config {
	t.Helper()
	u, err := url.Parse(srvPublicURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", srvPublicURL, err)
	}
	return config.Config{PublicURL: u, AuthDomain: srvAuthDomain, AuthPublicPort: srvAuthPort, TrustedProxyHops: 1}
}

// fakeCerts is a CertSource whose readiness the test toggles.
type fakeCerts struct {
	cert  tls.Certificate
	ready atomic.Bool
}

func (f *fakeCerts) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &f.cert, nil
}
func (f *fakeCerts) Ready() bool { return f.ready.Load() }

// logSink is a goroutine-safe JSON log buffer.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// records decodes every log line.
func (s *logSink) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(s.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// withMsg returns the records whose msg is msg.
func (s *logSink) withMsg(t *testing.T, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range s.records(t) {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// noLeak fails when the log output contains any of values.
func (s *logSink) noLeak(t *testing.T, values ...string) {
	t.Helper()
	logs := s.String()
	for _, v := range values {
		if v != "" && strings.Contains(logs, v) {
			t.Errorf("logs contain %q:\n%s", v, logs)
		}
	}
}

// jsonRequest is a same-origin JSON request to the main listener from 192.0.2.1.
func jsonRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, srvPublicURL+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", srvPublicURL)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// serve runs r against the main handler.
func (w *srvWorld) serve(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	w.main.ServeHTTP(rec, r)
	return rec
}

// createTx runs POST /api/v1/transactions and returns the auth URL and the cookie.
func (w *srvWorld) createTx(t *testing.T, provider string) (authURL string, cookie Secret) {
	t.Helper()
	rec := w.serve(jsonRequest(http.MethodPost, "/api/v1/transactions", `{"provider":"`+provider+`"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %s: status = %d, want 201; body %s", provider, rec.Code, rec.Body)
	}
	var body struct {
		AuthURL   string `json:"authUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	strictDecode(t, rec.Body.Bytes(), &body)
	c, ok := responseCookie(rec)
	if !ok {
		t.Fatalf("create %s: no %s cookie in %q", provider, CookieName, rec.Header().Values("Set-Cookie"))
	}
	return body.AuthURL, Secret(c.Value)
}

// stateOf returns the state parameter of an auth URL.
func stateOf(t *testing.T, authURL string) Secret {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("auth URL %q: %v", authURL, err)
	}
	return Secret(u.Query().Get("state"))
}

// completeTx creates a transaction over HTTP and completes it in the store
// with o, as the auth listener does; it returns the code and the cookie.
func (w *srvWorld) completeTx(t *testing.T, provider string, o Outcome) (code, cookie Secret) {
	t.Helper()
	authURL, cookie := w.createTx(t, provider)
	ref, err := w.app.store.ConsumeState(stateOf(t, authURL), provider)
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	code, err = w.app.store.Complete(ref, o)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return code, cookie
}

// redeem runs POST /api/v1/transactions/redeem; an empty cookie sends none.
func (w *srvWorld) redeem(code, cookie Secret) *httptest.ResponseRecorder {
	r := jsonRequest(http.MethodPost, "/api/v1/transactions/redeem", `{"code":"`+string(code)+`"}`)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: string(cookie)})
	}
	return w.serve(r)
}

// responseCookie returns the transaction cookie set by a response.
func responseCookie(rec *httptest.ResponseRecorder) (*http.Cookie, bool) {
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			return c, true
		}
	}
	return nil, false
}

// strictDecode decodes body into dst, failing on unknown fields.
func strictDecode(t *testing.T, body []byte, dst any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
}

// errorBody is the {"status":"error","error":{…}} envelope (no diagnostics).
type errorBody struct {
	Status string `json:"status"`
	Error  struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
}

// checkErrorBody asserts the error envelope and its message.
func checkErrorBody(t *testing.T, body []byte, code string, retryable bool) {
	t.Helper()
	var got errorBody
	strictDecode(t, body, &got)
	if got.Status != "error" || got.Error.Code != code || got.Error.Retryable != retryable {
		t.Errorf("body = %+v, want status error, code %q, retryable %v", got, code, retryable)
	}
	if got.Error.Message == "" || got.Error.Message != message(code) {
		t.Errorf("message = %q, want %q", got.Error.Message, message(code))
	}
}

// checkHeaders asserts exact header values.
func checkHeaders(t *testing.T, h http.Header, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := h.Values(k); !slices.Equal(got, []string{v}) {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

var mainAPIHeaders = map[string]string{
	"Content-Security-Policy":   mainCSP,
	"Referrer-Policy":           "no-referrer",
	"X-Content-Type-Options":    "nosniff",
	"Strict-Transport-Security": "max-age=31536000",
	"Cache-Control":             "no-store",
	"Content-Type":              "application/json; charset=utf-8",
}

func TestProvidersEndpoint(t *testing.T) {
	type provider struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Beta        bool   `json:"beta"`
	}
	get := func(t *testing.T, h http.Handler) []provider {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, srvPublicURL+"/api/v1/providers", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		checkHeaders(t, rec.Header(), mainAPIHeaders)
		var got []provider
		strictDecode(t, rec.Body.Bytes(), &got)
		return got
	}

	t.Run("test registry", func(t *testing.T) {
		w := newSrvWorld(t, srvOptions{})
		want := []provider{
			{ID: "alpha", Name: "Alpha - Test", Description: "Alpha test provider"},
			{ID: "beta", Name: "Beta - Test", Description: "Beta test provider", Beta: true},
		}
		if got := get(t, w.main); !slices.Equal(got, want) {
			t.Errorf("providers = %+v, want %+v", got, want)
		}
	})

	t.Run("production registry", func(t *testing.T) {
		// Display names per ruling R39 (preflight F5): spaced ASCII hyphen.
		want := []struct {
			id, name string
			beta     bool
		}{
			{"fnmt", "FNMT - Persona Física", false},
			{"idcat", "idCAT Certificat", false},
			{"accv", "ACCV - Ciudadano (software)", false},
			{"digitel", "DIGITEL ON - Ciudadano", false},
			{"bewor", "Bewor - Persona Física", false},
			{"sectigo", "Sectigo - Ciudadano", false},
			{"fnmt-representative", "FNMT - Representante", true},
			{"fnmt-employee", "FNMT - Empleado Público", true},
			{"firmaprofesional", "Firmaprofesional", true},
			{"anf", "ANF AC", true},
			{"uanataca", "Uanataca", true},
			{"signe", "SIGNE", true},
			{"lleidanet", "Lleidanet / inDenova", true},
			{"dnie", "DNIe (requires card reader)", true},
		}
		rev, err := certcheck.NewRevocation(certcheck.RevocationOptions{UserAgent: "cert-check/test", Logger: srvDiscard})
		if err != nil {
			t.Fatalf("certcheck.NewRevocation: %v", err)
		}
		provs := providers.All(certcheck.WithRevocation(rev), certcheck.WithLogger(srvDiscard), certcheck.WithVersion(srvVersion))
		cfg := srvConfig(t)
		cfg.AuthDomain = "auth.cert-check.vocdoni.dev"
		app, err := New(Deps{Config: cfg, Providers: provs, Certs: &fakeCerts{}, Logger: srvDiscard, Version: srvVersion})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		got := get(t, app.MainHandler())
		if len(got) != len(want) {
			t.Fatalf("got %d providers, want %d: %+v", len(got), len(want), got)
		}
		for i, wp := range want {
			g := got[i]
			if g.ID != wp.id || g.Name != wp.name || g.Beta != wp.beta || g.Description == "" {
				t.Errorf("provider %d = %+v, want {id %q name %q beta %v, non-empty description}", i, g, wp.id, wp.name, wp.beta)
			}
			if strings.ContainsAny(g.Name+g.Description, "\u2013\u2014") {
				t.Errorf("provider %s contains an en or em dash (ruling R39)", g.ID)
			}
		}
	})
}

func TestCreate(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	rec := w.serve(jsonRequest(http.MethodPost, "/api/v1/transactions", `{"provider":"alpha"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body)
	}
	checkHeaders(t, rec.Header(), mainAPIHeaders)
	var body struct {
		AuthURL   string `json:"authUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	strictDecode(t, rec.Body.Bytes(), &body)
	authRe := regexp.MustCompile(`^https://alpha\.auth\.test:8443/v1/authenticate\?state=([A-Za-z0-9_-]{43})$`)
	if !authRe.MatchString(body.AuthURL) {
		t.Errorf("authUrl = %q, want match %s", body.AuthURL, authRe)
	}
	if want := w.clk.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339); body.ExpiresAt != want {
		t.Errorf("expiresAt = %q, want %q", body.ExpiresAt, want)
	}
	setCookie := rec.Header().Values("Set-Cookie")
	cookieRe := regexp.MustCompile(`^__Host-certcheck_tx=[A-Za-z0-9_-]{43}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax$`)
	if len(setCookie) != 1 || !cookieRe.MatchString(setCookie[0]) {
		t.Errorf("Set-Cookie = %q, want one matching %s", setCookie, cookieRe)
	}
	if got := w.app.store.Len(); got != 1 {
		t.Errorf("store holds %d transactions, want 1", got)
	}
	if _, err := w.app.store.ConsumeState(stateOf(t, body.AuthURL), "alpha"); err != nil {
		t.Errorf("the authUrl state is not the transaction's alpha state: %v", err)
	}

	// A new creation with the old cookie replaces that transaction.
	c, _ := responseCookie(rec)
	again := jsonRequest(http.MethodPost, "/api/v1/transactions", `{"provider":"beta"}`)
	again.AddCookie(c)
	if rec := w.serve(again); rec.Code != http.StatusCreated {
		t.Fatalf("second create: status = %d, want 201", rec.Code)
	}
	if got := w.app.store.Len(); got != 1 {
		t.Errorf("after a create with the previous cookie the store holds %d transactions, want 1", got)
	}
}

func TestCreateErrors(t *testing.T) {
	create := func(body string, mod func(*http.Request)) func() *http.Request {
		return func() *http.Request {
			r := jsonRequest(http.MethodPost, "/api/v1/transactions", body)
			if mod != nil {
				mod(r)
			}
			return r
		}
	}
	const valid = `{"provider":"alpha"}`
	cases := []struct {
		name      string
		req       func() *http.Request
		status    int
		code      string
		retryable bool
	}{
		{"text content type", create(valid, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }), http.StatusUnsupportedMediaType, "unsupported_media_type", false},
		{"no content type", create(valid, func(r *http.Request) { r.Header.Del("Content-Type") }), http.StatusUnsupportedMediaType, "unsupported_media_type", false},
		{"cross-site", create(valid, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }), http.StatusForbidden, "forbidden", false},
		{"origin mismatch", create(valid, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }), http.StatusForbidden, "forbidden", false},
		{"unknown provider", create(`{"provider":"gamma"}`, nil), http.StatusBadRequest, "unknown_provider", false},
		{"empty provider", create(`{"provider":""}`, nil), http.StatusBadRequest, "unknown_provider", false},
		{"provider with a dot", create(`{"provider":"alpha.evil"}`, nil), http.StatusBadRequest, "unknown_provider", false},
		{"malformed", create(`{"provider":`, nil), http.StatusBadRequest, "bad_request", false},
		{"unknown field", create(`{"provider":"alpha","extra":1}`, nil), http.StatusBadRequest, "bad_request", false},
		{"trailing data", create(valid+`}`, nil), http.StatusBadRequest, "bad_request", false},
		{"over 1 KiB", create(strings.Repeat(" ", maxBody)+valid, nil), http.StatusBadRequest, "bad_request", false},
	}
	w := newSrvWorld(t, srvOptions{})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := w.serve(c.req())
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, c.status, rec.Body)
			}
			checkHeaders(t, rec.Header(), mainAPIHeaders)
			checkErrorBody(t, rec.Body.Bytes(), c.code, c.retryable)
			if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
				t.Errorf("Set-Cookie = %q, want none", got)
			}
		})
	}
	if got := w.app.store.Len(); got != 0 {
		t.Errorf("rejected creations left %d transactions, want 0", got)
	}

	t.Run("rate limited", func(t *testing.T) {
		w := newSrvWorld(t, srvOptions{})
		from := func(ip string) *http.Request {
			r := jsonRequest(http.MethodPost, "/api/v1/transactions", valid)
			r.Header.Set("X-Forwarded-For", ip)
			return r
		}
		for i := range 20 {
			if rec := w.serve(from("198.51.100.7")); rec.Code != http.StatusCreated {
				t.Fatalf("request %d: status = %d, want 201", i+1, rec.Code)
			}
		}
		rec := w.serve(from("198.51.100.7"))
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("request 21: status = %d, want 429", rec.Code)
		}
		checkErrorBody(t, rec.Body.Bytes(), "rate_limited", true)
		if s, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || s < 1 {
			t.Errorf("Retry-After = %q, want a positive number of seconds", rec.Header().Get("Retry-After"))
		}
		if rec := w.serve(from("198.51.100.8")); rec.Code != http.StatusCreated {
			t.Errorf("another IP: status = %d, want 201", rec.Code)
		}
	})

	t.Run("store full", func(t *testing.T) {
		w := newSrvWorld(t, srvOptions{})
		w.app.store = NewStore(1, w.clk.Now)
		w.app.auth.store = w.app.store
		if rec := w.serve(create(valid, nil)()); rec.Code != http.StatusCreated {
			t.Fatalf("first create: status = %d, want 201", rec.Code)
		}
		rec := w.serve(create(valid, nil)())
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("second create: status = %d, want 503", rec.Code)
		}
		checkErrorBody(t, rec.Body.Bytes(), "store_full", true)
	})
}

// redeemInvalidBody is the redeem 400 envelope.
type redeemInvalidBody struct {
	Status string `json:"status"`
	Error  struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
	Diagnostics certcheck.Diagnostics `json:"diagnostics"`
}

func TestRedeem(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	res, err := w.handler.VerifyAs(t.Context(), "alpha", []*x509.Certificate{w.leaf.Cert})
	if err != nil {
		t.Fatalf("VerifyAs: %v", err)
	}
	_, checkErr := w.handler.VerifyAs(t.Context(), "alpha", nil)
	valErr, ok := errors.AsType[*certcheck.Error](checkErr)
	if !ok || valErr.Code != certcheck.CodeNoCertificate {
		t.Fatalf("VerifyAs(no chain) = %v, want *certcheck.Error no_certificate", checkErr)
	}
	cleared := regexp.MustCompile(`^__Host-certcheck_tx=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax$`)

	// invalid asserts a 400 with minimal diagnostics and no identity value.
	invalid := func(t *testing.T, rec *httptest.ResponseRecorder, technical string) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
		}
		checkHeaders(t, rec.Header(), mainAPIHeaders)
		var got redeemInvalidBody
		strictDecode(t, rec.Body.Bytes(), &got)
		if got.Status != "error" || got.Error.Code != "invalid_or_expired" || got.Error.Retryable || got.Error.Message != message("invalid_or_expired") {
			t.Errorf("error = %+v, want invalid_or_expired, not retryable, with its message", got.Error)
		}
		d := got.Diagnostics
		if !srvHex32.MatchString(d.DiagnosticID) || !d.Time.Equal(w.clk.Now()) || d.ServerVersion != srvVersion ||
			d.Code != "invalid_or_expired" || d.TechnicalDetail != technical {
			t.Errorf("diagnostics = {id %q time %v version %q code %q detail %q}, want {32 hex, %v, %q, invalid_or_expired, %q}",
				d.DiagnosticID, d.Time, d.ServerVersion, d.Code, d.TechnicalDetail, w.clk.Now(), srvVersion, technical)
		}
		if d.Provider != "" || d.FailedStep != "" || d.TLS != nil || d.Certificate != nil || d.Chain != nil ||
			d.ProfileCandidates != nil || d.RevocationAttempts != nil {
			t.Errorf("diagnostics = %+v, want only id, time, version, code and technicalDetail", d)
		}
		for _, v := range srvIdentityValues {
			if bytes.Contains(rec.Body.Bytes(), []byte(v)) {
				t.Errorf("400 body contains identity value %q", v)
			}
		}
	}

	t.Run("success", func(t *testing.T) {
		code, cookie := w.completeTx(t, "alpha", Outcome{Result: res})
		rec := w.redeem(code, cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
		}
		checkHeaders(t, rec.Header(), mainAPIHeaders)
		var got struct {
			Status string            `json:"status"`
			Result *certcheck.Result `json:"result"`
		}
		strictDecode(t, rec.Body.Bytes(), &got)
		if got.Status != "success" || got.Result == nil {
			t.Fatalf("body = %s, want status success with a result", rec.Body)
		}
		if got.Result.Identity.Document.Number != "12345679S" || got.Result.Provider.ID != "alpha" || got.Result.Profile.ID != "alpha-a" {
			t.Errorf("result = {document %q provider %q profile %q}, want {12345679S alpha alpha-a}",
				got.Result.Identity.Document.Number, got.Result.Provider.ID, got.Result.Profile.ID)
		}
		if sc := rec.Header().Values("Set-Cookie"); len(sc) != 1 || !cleared.MatchString(sc[0]) {
			t.Errorf("Set-Cookie = %q, want the cookie cleared with Max-Age=0", sc)
		}
		if got := w.app.store.Current(cookie).Status; got != TxNone {
			t.Errorf("after redeem the transaction status = %q, want none", got)
		}

		t.Run("replayed", func(t *testing.T) {
			invalid(t, w.redeem(code, cookie), "code_unknown_or_expired")
		})
	})

	t.Run("validation error", func(t *testing.T) {
		code, cookie := w.completeTx(t, "alpha", Outcome{Err: valErr})
		rec := w.redeem(code, cookie)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
		}
		var got redeemInvalidBody
		strictDecode(t, rec.Body.Bytes(), &got)
		if got.Status != "error" || got.Error.Code != "no_certificate" || got.Error.Retryable || got.Error.Message != message("no_certificate") {
			t.Errorf("error = %+v, want no_certificate, not retryable, with its message", got.Error)
		}
		if got.Diagnostics.DiagnosticID != valErr.Diagnostics.DiagnosticID || got.Diagnostics.Code != certcheck.CodeNoCertificate {
			t.Errorf("diagnostics = {id %q code %q}, want {%q no_certificate}", got.Diagnostics.DiagnosticID, got.Diagnostics.Code, valErr.Diagnostics.DiagnosticID)
		}
		if sc := rec.Header().Values("Set-Cookie"); len(sc) != 1 || !cleared.MatchString(sc[0]) {
			t.Errorf("Set-Cookie = %q, want the cookie cleared with Max-Age=0", sc)
		}
	})

	t.Run("no cookie", func(t *testing.T) {
		code, cookie := w.completeTx(t, "alpha", Outcome{Result: res})
		invalid(t, w.redeem(code, ""), "cookie_missing")
		// The code was spent by the cookie-less attempt (U11-ASTRA-2).
		invalid(t, w.redeem(code, cookie), "code_unknown_or_expired")
	})

	t.Run("another valid cookie", func(t *testing.T) {
		code, cookie := w.completeTx(t, "alpha", Outcome{Result: res})
		_, other := w.createTx(t, "alpha")
		invalid(t, w.redeem(code, other), "cookie_mismatch")
		// The code was spent by the mismatched attempt.
		invalid(t, w.redeem(code, cookie), "code_unknown_or_expired")
	})

	t.Run("unknown code", func(t *testing.T) {
		_, cookie := w.completeTx(t, "alpha", Outcome{Result: res})
		invalid(t, w.redeem(NewSecret(), cookie), "code_unknown_or_expired")
		invalid(t, w.redeem("not-a-code", cookie), "code_unknown_or_expired")
	})

	t.Run("malformed body", func(t *testing.T) {
		r := jsonRequest(http.MethodPost, "/api/v1/transactions/redeem", `{"code":1}`)
		rec := w.serve(r)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		checkErrorBody(t, rec.Body.Bytes(), "bad_request", false)
	})

	t.Run("guards", func(t *testing.T) {
		r := jsonRequest(http.MethodPost, "/api/v1/transactions/redeem", `{"code":"x"}`)
		r.Header.Set("Content-Type", "text/plain")
		if rec := w.serve(r); rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("text/plain: status = %d, want 415", rec.Code)
		}
		r = jsonRequest(http.MethodPost, "/api/v1/transactions/redeem", `{"code":"x"}`)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		if rec := w.serve(r); rec.Code != http.StatusForbidden {
			t.Errorf("cross-site: status = %d, want 403", rec.Code)
		}
	})

	t.Run("rate limited", func(t *testing.T) {
		w := newSrvWorld(t, srvOptions{})
		for i := range 60 {
			if rec := w.redeem(NewSecret(), ""); rec.Code != http.StatusBadRequest {
				t.Fatalf("redeem %d: status = %d, want 400", i+1, rec.Code)
			}
		}
		rec := w.redeem(NewSecret(), "")
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("redeem 61: status = %d, want 429", rec.Code)
		}
		checkErrorBody(t, rec.Body.Bytes(), "rate_limited", true)
		if rec.Header().Get("Retry-After") == "" {
			t.Error("no Retry-After header")
		}
	})
}

func TestCurrent(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	type current struct {
		Status    string  `json:"status"`
		Provider  string  `json:"provider"`
		CreatedAt *string `json:"createdAt"`
		AuthHost  string  `json:"authHost"`
		AuthPort  int     `json:"authPort"`
	}
	get := func(t *testing.T, cookie Secret) current {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, srvPublicURL+"/api/v1/transactions/current", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: string(cookie)})
		}
		rec := w.serve(r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		checkHeaders(t, rec.Header(), mainAPIHeaders)
		var got current
		strictDecode(t, rec.Body.Bytes(), &got)
		return got
	}
	created := w.clk.Now().UTC().Format(time.RFC3339)
	none := current{Status: "none", AuthPort: srvAuthPort}

	if got := get(t, ""); got != none {
		t.Errorf("no cookie: %+v, want %+v", got, none)
	}
	if got := get(t, NewSecret()); got != none {
		t.Errorf("unknown cookie: %+v, want %+v", got, none)
	}
	authURL, cookie := w.createTx(t, "alpha")
	got := get(t, cookie)
	if got.Status != "pending" || got.Provider != "alpha" || got.CreatedAt == nil || *got.CreatedAt != created ||
		got.AuthHost != srvAlphaHost || got.AuthPort != srvAuthPort {
		t.Errorf("pending: %+v (createdAt %v), want {pending alpha %s %s %d}", got, got.CreatedAt, created, srvAlphaHost, srvAuthPort)
	}
	ref, err := w.app.store.ConsumeState(stateOf(t, authURL), "alpha")
	if err != nil {
		t.Fatalf("ConsumeState: %v", err)
	}
	if _, err := w.app.store.Complete(ref, Outcome{Err: &certcheck.Error{Code: certcheck.CodeInternal}}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := get(t, cookie); got.Status != "completed" || got.AuthHost != srvAlphaHost || got.AuthPort != srvAuthPort {
		t.Errorf("completed: %+v, want {completed alpha … %s %d}", got, srvAlphaHost, srvAuthPort)
	}
}

func TestHealthReady(t *testing.T) {
	w := newSrvWorld(t, srvOptions{notReady: true})
	status := func(t *testing.T, h http.Handler, path string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, srvPublicURL+path, nil))
		return rec.Code
	}
	if got := status(t, w.main, "/healthz"); got != http.StatusOK {
		t.Errorf("before Run: /healthz = %d, want 200", got)
	}
	if got := status(t, w.main, "/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("before Run: /readyz = %d, want 503", got)
	}

	run := w.start(t)
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	get := func(t *testing.T, path string) int {
		t.Helper()
		resp, err := client.Get("http://" + run.mainAddr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close() // read fully; nothing to report
		return resp.StatusCode
	}
	if got := get(t, "/healthz"); got != http.StatusOK {
		t.Errorf("running, cert not ready: /healthz = %d, want 200", got)
	}
	if got := get(t, "/readyz"); got != http.StatusServiceUnavailable {
		t.Errorf("running, cert not ready: /readyz = %d, want 503", got)
	}
	w.certs.ready.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for get(t, "/readyz") != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("/readyz did not turn 200 within 5s of the certificate becoming ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := get(t, "/healthz"); got != http.StatusOK {
		t.Errorf("ready: /healthz = %d, want 200", got)
	}
}

func TestStaticUI(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	cases := []struct {
		path   string
		status int
		ctype  string // prefix; "" = not checked
	}{
		{"/", http.StatusOK, "text/html"},
		{"/app.js", http.StatusOK, "text/javascript"},
		{"/fonts/", http.StatusNotFound, ""},
		{"/fonts", http.StatusNotFound, ""},
		{"/img/", http.StatusNotFound, ""},
		{"/missing.txt", http.StatusNotFound, ""},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec := w.serve(httptest.NewRequest(http.MethodGet, srvPublicURL+c.path, nil))
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d", rec.Code, c.status)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, c.ctype) {
				t.Errorf("Content-Type = %q, want prefix %q", got, c.ctype)
			}
			checkHeaders(t, rec.Header(), map[string]string{
				"Content-Security-Policy":   mainCSP,
				"Referrer-Policy":           "no-referrer",
				"X-Content-Type-Options":    "nosniff",
				"Strict-Transport-Security": "max-age=31536000",
			})
			if c.status == http.StatusNotFound && strings.Contains(rec.Body.String(), "href=") {
				t.Errorf("body lists files: %q", rec.Body)
			}
		})
	}
}

func TestMessagesCoverAllCodes(t *testing.T) {
	codes := []string{"invalid_or_expired", "unknown_provider", "unsupported_media_type", "rate_limited",
		"store_full", "forbidden", "bad_request", "invalid_state"}
	for _, c := range certcheck.Codes {
		codes = append(codes, string(c))
	}
	for _, c := range codes {
		m, ok := messages[c]
		if !ok || m == "" {
			t.Errorf("code %q has no message", c)
		}
		if strings.ContainsAny(m, "\u2013\u2014") {
			t.Errorf("message for %q contains an en or em dash: %q", c, m)
		}
	}
	if got, want := message("no-such-code"), messages[string(certcheck.CodeInternal)]; got != want {
		t.Errorf("message(unknown) = %q, want the internal message %q", got, want)
	}
}

func TestForwardedHeadersDebugLog(t *testing.T) {
	request := func() *http.Request {
		r := jsonRequest(http.MethodPost, "/api/v1/transactions", `{"provider":"alpha"}`)
		r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
		r.Header.Set("X-Real-IP", "203.0.113.10")
		r.Header.Set("Forwarded", "for=203.0.113.11")
		return r
	}
	ipValues := []string{"203.0.113", "198.51.100", "192.0.2"}

	t.Run("debug", func(t *testing.T) {
		w := newSrvWorld(t, srvOptions{logLevel: slog.LevelDebug})
		if rec := w.serve(request()); rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		recs := w.logs.withMsg(t, "forwarded headers")
		if len(recs) != 1 {
			t.Fatalf("got %d forwarded-headers lines, want 1; logs:\n%s", len(recs), w.logs)
		}
		present, _ := recs[0]["present"].([]any)
		var names []string
		for _, p := range present {
			s, _ := p.(string)
			names = append(names, s)
		}
		if want := []string{"X-Forwarded-For", "X-Real-IP", "Forwarded"}; !slices.Equal(names, want) {
			t.Errorf("present = %q, want %q", names, want)
		}
		if got := recs[0]["xffEntries"]; got != float64(2) {
			t.Errorf("xffEntries = %v, want 2", got)
		}
		w.logs.noLeak(t, ipValues...)
	})

	t.Run("info", func(t *testing.T) {
		w := newSrvWorld(t, srvOptions{logLevel: slog.LevelInfo})
		if rec := w.serve(request()); rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201", rec.Code)
		}
		if recs := w.logs.withMsg(t, "forwarded headers"); len(recs) != 0 {
			t.Errorf("got %d forwarded-headers lines at info level, want 0", len(recs))
		}
		w.logs.noLeak(t, ipValues...)
	})
}

// srvRunning is the world's App served by Run on loopback listeners.
type srvRunning struct {
	mainAddr, authAddr string
}

// srvListen opens a loopback TCP listener.
func srvListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// start serves the App until the test ends; cleanup asserts that Run returns nil.
func (w *srvWorld) start(t *testing.T) srvRunning {
	t.Helper()
	mainLn, authLn := srvListen(t), srvListen(t)
	run := srvRunning{mainAddr: mainLn.Addr().String(), authAddr: authLn.Addr().String()}
	ctx := t.Context() // cancelled before the cleanup below runs
	done := make(chan struct{})
	var runErr error
	var wg sync.WaitGroup
	wg.Go(func() {
		defer close(done)
		runErr = w.app.Run(ctx, mainLn, authLn)
	})
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return within 5s of the test context ending")
			return
		}
		wg.Wait()
		if runErr != nil {
			t.Errorf("Run = %v, want nil", runErr)
		}
	})
	return run
}

// authClient is an HTTPS client for the auth listener at addr that offers
// h2 and http/1.1, presents cert (nil: no certificate) and never follows
// redirects.
func (w *srvWorld) authClient(t *testing.T, addr string, cert *tls.Certificate) *http.Client {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: w.serverPool,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if cert == nil {
					return &tls.Certificate{}, nil
				}
				return cert, nil
			},
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{
		Transport:     tr,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// leafCert is the valid alpha client certificate.
func (w *srvWorld) leafCert() *tls.Certificate {
	return new(w.leaf.TLSCertificate())
}

// authDo sends one request to the auth listener and returns the response
// with its full body. host, when set, overrides the Host header.
func authDo(t *testing.T, c *http.Client, method, rawURL, host string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, rawURL, err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }() // body fully read below
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, body
}
