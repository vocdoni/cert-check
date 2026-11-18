package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
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
	"github.com/vocdoni/cert-check/testui/internal/server"
)

// The test world: providers "alpha" and "beta" under the auth domain
// "auth.test", one profile each with its own root; alpha's OCSP responder
// answers good on a fake network.
const (
	authDomain = "auth.test"
	alphaHost  = "alpha.auth.test"
	betaHost   = "beta.auth.test"
	gammaHost  = "gamma.auth.test"
	ocspHost   = "ocsp.alpha.test"
)

var (
	discard  = slog.New(slog.DiscardHandler)
	policyA  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	policyB  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2, 1}
	wantTLS  = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
	wantECs  = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	wantALPN = []string{"http/1.1"}
)

type world struct {
	now          time.Time
	rootA, rootB *testpki.CA
	providers    []certcheck.Provider // alpha, beta
	handler      *certcheck.Handler   // over providers
	serverCert   tls.Certificate
	serverPool   *x509.CertPool // trusts serverCert
}

func newWorld(t *testing.T) *world {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	w := &world{now: now}
	w.rootA = testpki.NewRoot(t, "Alpha Root", testpki.CertSpec{Now: now})
	w.rootB = testpki.NewRoot(t, "Beta Root", testpki.CertSpec{Now: now})

	ocsp := testpki.NewOCSPServer(w.rootA, w.rootA.OCSPResponder(t, testpki.CertSpec{Now: now}))
	ocsp.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: now, NextUpdate: now.Add(time.Hour)}
	})
	n := testpki.NewNet()
	n.Serve(t, ocspHost, ocsp.Handler(t))
	rc, err := revocation.NewChecker(revocation.Options{
		UserAgent: "cert-check/test", DialContext: n.DialContext, Now: func() time.Time { return now },
		Logger: discard, OCSPTimeout: 2 * time.Second, CRLTimeout: 2 * time.Second,
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
			Revocation: revocation.Policy{OCSPHosts: []string{ocspHost}, OCSPNonce: true}}
	}
	clock := func() time.Time { return now }
	for _, d := range []profiles.Provider{
		{ID: "alpha", Name: "Alpha", Profiles: []profiles.Profile{profile("alpha-a", "alpha", w.rootA, policyA)}},
		{ID: "beta", Name: "Beta", Profiles: []profiles.Profile{profile("beta-a", "beta", w.rootB, policyB)}},
	} {
		p, err := engine.New(engine.Config{Provider: d, Revocation: rc, Now: clock, Logger: discard, Version: "test"})
		if err != nil {
			t.Fatalf("engine.New(%s): %v", d.ID, err)
		}
		w.providers = append(w.providers, p)
	}
	w.handler, err = certcheck.NewHandler(w.providers, certcheck.WithClock(clock), certcheck.WithVersion("test"))
	if err != nil {
		t.Fatalf("certcheck.NewHandler: %v", err)
	}

	w.serverCert, w.serverPool = testpki.ServerTLS(t, alphaHost, betaHost, gammaHost)
	return w
}

// pool returns the CAs of provider id as a pool.
func (w *world) pool(t *testing.T, id string) *x509.CertPool {
	t.Helper()
	i := slices.IndexFunc(w.providers, func(p certcheck.Provider) bool { return p.Info().ID == id })
	if i < 0 {
		t.Fatalf("no provider %q", id)
	}
	pool := x509.NewCertPool()
	for _, c := range w.providers[i].CAs() {
		pool.AddCert(c)
	}
	return pool
}

// config returns the auth listener configuration of the world.
func (w *world) config(t *testing.T, allowTLS13 bool, log *slog.Logger) *tls.Config {
	t.Helper()
	cfg, err := server.ServerConfig(server.ConfigOptions{
		Providers:      w.providers,
		AuthDomain:     authDomain,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &w.serverCert, nil },
		AllowTLS13:     allowTLS13,
		Logger:         log,
	})
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	return cfg
}

// providerConfig resolves the per-SNI configuration as the handshake does.
func providerConfig(t *testing.T, cfg *tls.Config, sni string) *tls.Config {
	t.Helper()
	pc, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("GetConfigForClient(%q): %v", sni, err)
	}
	if pc == nil {
		t.Fatalf("GetConfigForClient(%q) = nil config", sni)
	}
	return pc
}

// pipeHandshake runs one TLS handshake over net.Pipe. After a successful
// handshake the server writes one byte that the client reads, so that
// post-handshake messages (TLS 1.3 session tickets) reach the client.
func pipeHandshake(t *testing.T, srvCfg, cliCfg *tls.Config) (state tls.ConnectionState, srvErr, cliErr error) {
	t.Helper()
	sc, cc := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	for _, c := range []net.Conn{sc, cc} {
		if err := c.SetDeadline(deadline); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}
	srv, cli := tls.Server(sc, srvCfg), tls.Client(cc, cliCfg)
	var wg sync.WaitGroup
	wg.Go(func() {
		srvErr = srv.HandshakeContext(t.Context())
		if srvErr == nil {
			_, srvErr = srv.Write([]byte{1})
		}
		if srvErr != nil {
			_ = sc.Close() // unblocks the client; the handshake error is what the test inspects
		}
	})
	cliErr = cli.HandshakeContext(t.Context())
	if cliErr == nil {
		_, cliErr = io.ReadFull(cli, make([]byte, 1))
	}
	if cliErr != nil {
		_ = cc.Close() // unblocks the server; the handshake error is what the test inspects
	}
	wg.Wait()
	state = cli.ConnectionState()
	_, _ = sc.Close(), cc.Close() // closing the raw pipe ends cannot fail in a way the test cares about
	return state, srvErr, cliErr
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestServerConfigRequiresOptions(t *testing.T) {
	w := newWorld(t)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &w.serverCert, nil }
	cases := []struct {
		name string
		opts server.ConfigOptions
	}{
		{"no providers", server.ConfigOptions{AuthDomain: authDomain, GetCertificate: getCert}},
		{"no domain", server.ConfigOptions{Providers: w.providers, GetCertificate: getCert}},
		{"no certificate source", server.ConfigOptions{Providers: w.providers, AuthDomain: authDomain}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := server.ServerConfig(c.opts)
			if err == nil || cfg != nil {
				t.Errorf("ServerConfig = (%v, %v), want (nil, error)", cfg, err)
			}
		})
	}
}

func TestServerConfigPerProvider(t *testing.T) {
	w := newWorld(t)
	cfg := w.config(t, false, discard)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("outer MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
	}
	if !slices.Equal(cfg.NextProtos, wantALPN) {
		t.Errorf("outer NextProtos = %q, want %q", cfg.NextProtos, wantALPN)
	}
	cases := []struct{ sni, provider string }{
		{alphaHost, "alpha"},
		{"ALPHA.Auth.Test", "alpha"},
		{betaHost, "beta"},
	}
	for _, c := range cases {
		t.Run(c.sni, func(t *testing.T) {
			pc := providerConfig(t, cfg, c.sni)
			if pc.ClientAuth != tls.RequestClientCert {
				t.Errorf("ClientAuth = %v, want RequestClientCert", pc.ClientAuth)
			}
			if want := w.pool(t, c.provider); pc.ClientCAs == nil || !pc.ClientCAs.Equal(want) {
				t.Errorf("ClientCAs differ from the CAs of provider %q", c.provider)
			}
			if pc.MinVersion != tls.VersionTLS12 || pc.MaxVersion != tls.VersionTLS12 {
				t.Errorf("versions = [%#x, %#x], want TLS 1.2 only", pc.MinVersion, pc.MaxVersion)
			}
			if !pc.SessionTicketsDisabled {
				t.Error("SessionTicketsDisabled = false, want true")
			}
			if !slices.Equal(pc.NextProtos, wantALPN) {
				t.Errorf("NextProtos = %q, want %q", pc.NextProtos, wantALPN)
			}
			if !slices.Equal(pc.CipherSuites, wantTLS) {
				t.Errorf("CipherSuites = %v, want %v", pc.CipherSuites, wantTLS)
			}
			if !slices.Equal(pc.CurvePreferences, wantECs) {
				t.Errorf("CurvePreferences = %v, want %v", pc.CurvePreferences, wantECs)
			}
			if pc.GetCertificate == nil {
				t.Error("GetCertificate = nil, want set")
			}
		})
	}
	alpha, beta := providerConfig(t, cfg, alphaHost), providerConfig(t, cfg, betaHost)
	if alpha.ClientCAs.Equal(beta.ClientCAs) {
		t.Error("alpha and beta advertise the same CA pool")
	}
}

func TestServerConfigTLS13(t *testing.T) {
	w := newWorld(t)
	cases := []struct {
		name       string
		allowTLS13 bool
		want       uint16
	}{
		{"default", false, tls.VersionTLS12},
		{"opt-in", true, tls.VersionTLS13},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := w.config(t, c.allowTLS13, discard)
			if got := providerConfig(t, cfg, alphaHost).MaxVersion; got != c.want {
				t.Errorf("MaxVersion = %#x, want %#x", got, c.want)
			}
			state, srvErr, cliErr := pipeHandshake(t, cfg, &tls.Config{ServerName: alphaHost, RootCAs: w.serverPool})
			if srvErr != nil || cliErr != nil {
				t.Fatalf("handshake: server %v, client %v", srvErr, cliErr)
			}
			if state.Version != c.want {
				t.Errorf("negotiated %s, want %s", tls.VersionName(state.Version), tls.VersionName(c.want))
			}
		})
	}
}

func TestUnknownSNIRejected(t *testing.T) {
	w := newWorld(t)
	long := strings.Repeat("x", 100) + "." + authDomain
	cases := []struct {
		name    string
		client  *tls.Config
		wantLog string // the sni attribute, truncated to 64 bytes
	}{
		{"unknown provider", &tls.Config{ServerName: gammaHost, RootCAs: w.serverPool}, "sni=" + gammaHost + "\n"},
		// crypto/tls sends no SNI extension when ServerName is an IP literal.
		{"no SNI", &tls.Config{ServerName: "127.0.0.1", RootCAs: w.serverPool}, `sni=""` + "\n"},
		{"long SNI", &tls.Config{ServerName: long, RootCAs: w.serverPool}, "sni=" + long[:64] + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var debug, info syncBuffer
			for _, l := range []struct {
				buf   *syncBuffer
				level slog.Level
			}{{&debug, slog.LevelDebug}, {&info, slog.LevelInfo}} {
				cfg := w.config(t, false, slog.New(slog.NewTextHandler(l.buf, &slog.HandlerOptions{Level: l.level})))
				_, srvErr, cliErr := pipeHandshake(t, cfg, c.client)
				if srvErr == nil {
					t.Errorf("%v logger: server handshake succeeded, want failure", l.level)
				}
				if cliErr == nil || !strings.Contains(cliErr.Error(), "internal error") {
					t.Errorf("%v logger: client error = %v, want an internal error alert", l.level, cliErr)
				}
			}
			if got := debug.String(); !strings.Contains(got, "level=DEBUG") || !strings.Contains(got, c.wantLog) {
				t.Errorf("debug log = %q, want a DEBUG line ending with %q", got, c.wantLog)
			}
			if got := info.String(); got != "" {
				t.Errorf("info log = %q, want nothing (scanners hit the port constantly)", got)
			}
		})
	}
}

func TestHandshakeAdvertisesProviderCAs(t *testing.T) {
	w := newWorld(t)
	cfg := w.config(t, false, discard)
	cases := []struct {
		sni  string
		want *testpki.CA
	}{
		{alphaHost, w.rootA},
		{betaHost, w.rootB},
	}
	for _, c := range cases {
		t.Run(c.sni, func(t *testing.T) {
			var got [][]byte
			cli := &tls.Config{ServerName: c.sni, RootCAs: w.serverPool,
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					got = slices.Clone(cri.AcceptableCAs)
					return &tls.Certificate{}, nil
				}}
			if _, srvErr, cliErr := pipeHandshake(t, cfg, cli); srvErr != nil || cliErr != nil {
				t.Fatalf("handshake: server %v, client %v", srvErr, cliErr)
			}
			want := [][]byte{c.want.Cert.RawSubject}
			if !slices.EqualFunc(got, want, bytes.Equal) {
				t.Errorf("AcceptableCAs = %d entries %x, want only %s's subject", len(got), got, c.want.Label)
			}
		})
	}
}

// recordingCache counts the sessions a server hands the client.
type recordingCache struct {
	tls.ClientSessionCache
	mu   sync.Mutex
	puts int
}

func (c *recordingCache) Put(key string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	if cs != nil {
		c.puts++
	}
	c.mu.Unlock()
	c.ClientSessionCache.Put(key, cs)
}

func TestNoResumptionNoH2(t *testing.T) {
	w := newWorld(t)
	for _, allowTLS13 := range []bool{false, true} {
		t.Run(map[bool]string{false: "tls12", true: "tls13"}[allowTLS13], func(t *testing.T) {
			cfg := w.config(t, allowTLS13, discard)
			cache := &recordingCache{ClientSessionCache: tls.NewLRUClientSessionCache(8)}
			cli := &tls.Config{ServerName: alphaHost, RootCAs: w.serverPool, NextProtos: []string{"h2", "http/1.1"}, ClientSessionCache: cache}
			for i := range 2 {
				state, srvErr, cliErr := pipeHandshake(t, cfg, cli)
				if srvErr != nil || cliErr != nil {
					t.Fatalf("handshake %d: server %v, client %v", i, srvErr, cliErr)
				}
				if state.NegotiatedProtocol != "http/1.1" {
					t.Errorf("handshake %d: NegotiatedProtocol = %q, want http/1.1", i, state.NegotiatedProtocol)
				}
				if state.DidResume {
					t.Errorf("handshake %d: DidResume = true, want false", i)
				}
			}
			cache.mu.Lock()
			defer cache.mu.Unlock()
			if cache.puts != 0 {
				t.Errorf("client received %d sessions, want 0", cache.puts)
			}
		})
	}
}

// authCall is what the test handler saw for one request.
type authCall struct {
	remote string
	res    *certcheck.Result
	err    error
}

// authServer is a real TLS server using the world's configuration whose
// handler calls certcheck.Handler.AuthAs with the provider of the SNI.
type authServer struct {
	addr  string
	mu    sync.Mutex
	calls []authCall
}

func (w *world) startServer(t *testing.T) *authServer {
	t.Helper()
	hosts := server.NewAuthHosts(authDomain)
	as := &authServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		id, _ := hosts.Provider(r.TLS.ServerName)
		res, err := w.handler.AuthAs(r, id)
		as.mu.Lock()
		as.calls = append(as.calls, authCall{remote: r.RemoteAddr, res: res, err: err})
		as.mu.Unlock()
		rw.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.TLS = w.config(t, false, discard)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	as.addr = srv.Listener.Addr().String()
	return as
}

// client returns an HTTP/1.1 client that dials the server for every host.
func (as *authServer) client(t *testing.T, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, as.addr)
		},
		TLSClientConfig: tlsCfg,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// get requests https://<host>/v1/authenticate and returns the handler's view.
func (as *authServer) get(t *testing.T, c *http.Client, host string) authCall {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+host+"/v1/authenticate", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", host, err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if len(as.calls) == 0 {
		t.Fatal("handler not called")
	}
	return as.calls[len(as.calls)-1]
}

// authError returns err as *certcheck.Error or stops the test.
func authError(t *testing.T, err error) *certcheck.Error {
	t.Helper()
	e, ok := errors.AsType[*certcheck.Error](err)
	if !ok {
		t.Fatalf("error = %v (%T), want *certcheck.Error", err, err)
	}
	return e
}

func TestRequestClientCertOptional(t *testing.T) {
	w := newWorld(t)
	as := w.startServer(t)
	call := as.get(t, as.client(t, &tls.Config{RootCAs: w.serverPool}), alphaHost)
	if call.res != nil {
		t.Fatalf("Authenticate result = %+v, want error", call.res)
	}
	e := authError(t, call.err)
	if e.Code != certcheck.CodeNoCertificate {
		t.Errorf("code = %q, want %q", e.Code, certcheck.CodeNoCertificate)
	}
	got := e.Diagnostics.TLS
	if got == nil {
		t.Fatal("Diagnostics.TLS = nil, want the handshake details")
	}
	if got.ClientCertificatePresented || got.ChainLength != 0 || got.SNI != alphaHost {
		t.Errorf("Diagnostics.TLS = %+v, want no certificate and SNI %s", got, alphaHost)
	}
}

func TestProvider(t *testing.T) {
	h := server.NewAuthHosts("Auth.Test")
	cases := []struct {
		serverName string
		want       string
		wantOK     bool
	}{
		{alphaHost, "alpha", true},
		{"ALPHA.Auth.TEST", "alpha", true},
		{"x.alpha.auth.test", "", false},
		{"auth.test", "", false},
		{".auth.test", "", false},
		{"alpha.auth.test.evil", "", false},
		{"alphaauth.test", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := h.Provider(c.serverName)
		if got != c.want || ok != c.wantOK {
			t.Errorf("Provider(%q) = (%q, %v), want (%q, %v)", c.serverName, got, ok, c.want, c.wantOK)
		}
	}
}

// TestHandshakeBudget: the server's handshake bound (the minimum of its
// timeouts, here a 300 ms ReadHeaderTimeout) closes silent and unknown-SNI
// connections, but a known provider SNI extends the handshake to the budget
// (2 s here, 90 s in production), so a slow certificate picker or PIN
// prompt still completes and the connection then serves a request.
func TestHandshakeBudget(t *testing.T) {
	const base, budget, picker = 300 * time.Millisecond, 2 * time.Second, time.Second
	server.SetHandshakeBudget(t, budget)
	w := newWorld(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.Config.ReadHeaderTimeout = base
	srv.TLS = w.config(t, false, discard)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()

	// closedWithin dials, lets start act on the connection and reports
	// whether the server closed it within limit.
	closedWithin := func(t *testing.T, start func(net.Conn), limit time.Duration) (time.Duration, bool) {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close()
		begin := time.Now()
		start(c)
		_ = c.SetReadDeadline(begin.Add(budget + time.Second))
		_, err = io.Copy(io.Discard, c) // returns at EOF/reset (closed) or at the read deadline
		took := time.Since(begin)
		var ne net.Error
		return took, !(errors.As(err, &ne) && ne.Timeout()) && took < limit
	}

	t.Run("silent", func(t *testing.T) {
		if took, ok := closedWithin(t, func(net.Conn) {}, budget/2); !ok {
			t.Errorf("silent connection open for %v, want closed at the %v base bound", took, base)
		}
	})
	t.Run("unknown SNI", func(t *testing.T) {
		took, ok := closedWithin(t, func(c net.Conn) {
			go func() { _ = tls.Client(c, &tls.Config{ServerName: gammaHost, RootCAs: w.serverPool}).Handshake() }()
		}, budget/2)
		if !ok {
			t.Errorf("unknown-SNI connection open for %v, want closed within the %v base bound", took, base)
		}
	})
	t.Run("known SNI, slow picker", func(t *testing.T) {
		c, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: alphaHost, RootCAs: w.serverPool, MaxVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				time.Sleep(picker) // longer than base, shorter than budget
				return &tls.Certificate{}, nil
			},
		})
		if err != nil {
			t.Fatalf("handshake with a %v picker: %v, want success within the %v budget", picker, err, budget)
		}
		defer c.Close()
		if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+alphaHost+"\r\n\r\n"); err != nil {
			t.Fatalf("write request: %v", err)
		}
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			t.Errorf("status = %d, want %d", res.StatusCode, http.StatusNoContent)
		}
	})
}
