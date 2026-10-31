package tlsauth_test

import (
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

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/certauth/tlsauth"
	"github.com/vocdoni/cert-check/internal/testpki"
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
	ocspURL    = "http://" + ocspHost + "/"
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
	leaf         *testpki.Leaf // valid alpha leaf
	checker      *certauth.Checker
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
	reg, err := profiles.New(profiles.Config{
		Providers: []profiles.Provider{
			{ID: "alpha", Name: "Alpha", Profiles: []profiles.Profile{profile("alpha-a", "alpha", w.rootA, policyA)}},
			{ID: "beta", Name: "Beta", Profiles: []profiles.Profile{profile("beta-a", "beta", w.rootB, policyB)}},
		},
		Reserved: identity.DefaultReserved(), Now: now, Logger: discard,
	})
	if err != nil {
		t.Fatalf("profiles.New: %v", err)
	}
	w.checker, err = certauth.NewChecker(certauth.Options{Registry: reg, Revocation: rc, Now: func() time.Time { return now }, Version: "test"})
	if err != nil {
		t.Fatalf("certauth.NewChecker: %v", err)
	}

	w.leaf = w.rootA.Leaf(t, testpki.CertSpec{
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
		Policies:    []asn1.ObjectIdentifier{policyA},
		OCSPServers: []string{ocspURL},
	})
	w.serverCert, w.serverPool = testpki.ServerTLS(t, alphaHost, betaHost, gammaHost)
	return w
}

// config returns the auth listener configuration of the world.
func (w *world) config(t *testing.T, allowTLS13 bool, log *slog.Logger) *tls.Config {
	t.Helper()
	cfg, err := tlsauth.ServerConfig(tlsauth.ConfigOptions{
		Checker:        w.checker,
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
		opts tlsauth.ConfigOptions
	}{
		{"no checker", tlsauth.ConfigOptions{AuthDomain: authDomain, GetCertificate: getCert}},
		{"no domain", tlsauth.ConfigOptions{Checker: w.checker, GetCertificate: getCert}},
		{"no certificate source", tlsauth.ConfigOptions{Checker: w.checker, AuthDomain: authDomain}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := tlsauth.ServerConfig(c.opts)
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
			want, err := w.checker.ClientCAs(c.provider)
			if err != nil {
				t.Fatalf("ClientCAs(%q): %v", c.provider, err)
			}
			if pc.ClientCAs == nil || !pc.ClientCAs.Equal(want) {
				t.Errorf("ClientCAs differ from checker.ClientCAs(%q)", c.provider)
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
	res    *certauth.Result
	err    error
}

// authServer is a real TLS server using the world's configuration whose
// handler calls Handler.Authenticate.
type authServer struct {
	addr  string
	mu    sync.Mutex
	calls []authCall
}

func (w *world) startServer(t *testing.T) *authServer {
	t.Helper()
	h := tlsauth.NewHandler(w.checker, authDomain)
	as := &authServer{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		res, err := h.Authenticate(r)
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

// authError returns err as *certauth.Error or stops the test.
func authError(t *testing.T, err error) *certauth.Error {
	t.Helper()
	e, ok := errors.AsType[*certauth.Error](err)
	if !ok {
		t.Fatalf("error = %v (%T), want *certauth.Error", err, err)
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
	if e.Code != certauth.CodeNoCertificate {
		t.Errorf("code = %q, want %q", e.Code, certauth.CodeNoCertificate)
	}
	got := e.Diagnostics.TLS
	if got == nil {
		t.Fatal("Diagnostics.TLS = nil, want the handshake details")
	}
	if got.ClientCertificatePresented || got.ChainLength != 0 || got.SNI != alphaHost {
		t.Errorf("Diagnostics.TLS = %+v, want no certificate and SNI %s", got, alphaHost)
	}
}

func TestAuthenticateSuccessAndTLSInfo(t *testing.T) {
	w := newWorld(t)
	as := w.startServer(t)
	call := as.get(t, as.client(t, &tls.Config{RootCAs: w.serverPool, Certificates: []tls.Certificate{w.leaf.TLSCertificate()}}), alphaHost)
	if call.err != nil {
		t.Fatalf("Authenticate: %v", call.err)
	}
	if call.res.Provider.ID != "alpha" {
		t.Errorf("provider = %q, want alpha", call.res.Provider.ID)
	}
	want := certauth.TLSInfo{Version: "TLS 1.2", SNI: alphaHost, ClientCertificatePresented: true, ChainLength: 1}
	got := call.res.Diagnostics.TLS
	if got == nil {
		t.Fatal("Diagnostics.TLS = nil, want the handshake details")
	}
	if got.Version != want.Version || got.SNI != want.SNI || got.ClientCertificatePresented != want.ClientCertificatePresented ||
		got.ChainLength != want.ChainLength || got.CipherSuite == "" {
		t.Errorf("Diagnostics.TLS = %+v, want %+v with a cipher suite", *got, want)
	}
}

func TestAuthenticateErrorCarriesTLS(t *testing.T) {
	w := newWorld(t)
	as := w.startServer(t)
	leaf := w.leaf.TLSCertificate()
	// beta advertises only its own root, so force the alpha leaf onto it.
	c := as.client(t, &tls.Config{RootCAs: w.serverPool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &leaf, nil }})
	call := as.get(t, c, betaHost)
	e := authError(t, call.err)
	if e.Code != certauth.CodeProviderMismatch {
		t.Errorf("code = %q, want %q", e.Code, certauth.CodeProviderMismatch)
	}
	if got := e.Diagnostics.TLS; got == nil || got.SNI != betaHost || !got.ClientCertificatePresented {
		t.Errorf("Diagnostics.TLS = %+v, want SNI %s with a certificate", got, betaHost)
	}
	if e.Diagnostics.Provider != "beta" {
		t.Errorf("Diagnostics.Provider = %q, want beta (from the SNI)", e.Diagnostics.Provider)
	}
}

func TestAuthenticateRunsEveryRequest(t *testing.T) {
	w := newWorld(t)
	as := w.startServer(t)
	c := as.client(t, &tls.Config{RootCAs: w.serverPool, Certificates: []tls.Certificate{w.leaf.TLSCertificate()}})
	first, second := as.get(t, c, alphaHost), as.get(t, c, alphaHost)
	if first.remote != second.remote {
		t.Fatalf("requests used connections %s and %s, want one keep-alive connection", first.remote, second.remote)
	}
	if first.err != nil || second.err != nil {
		t.Fatalf("Authenticate: %v, %v", first.err, second.err)
	}
	if a, b := first.res.Diagnostics.DiagnosticID, second.res.Diagnostics.DiagnosticID; a == "" || a == b {
		t.Errorf("DiagnosticIDs = %q, %q, want two distinct IDs", a, b)
	}
}

func TestAuthenticateWithoutTLS(t *testing.T) {
	w := newWorld(t)
	res, err := tlsauth.NewHandler(w.checker, authDomain).Authenticate(httptest.NewRequest(http.MethodGet, "http://"+alphaHost+"/v1/authenticate", nil))
	if res != nil {
		t.Fatalf("result = %+v, want nil", res)
	}
	e := authError(t, err)
	if e.Code != certauth.CodeInternal {
		t.Errorf("code = %q, want %q", e.Code, certauth.CodeInternal)
	}
	if e.Diagnostics.DiagnosticID != "" {
		t.Errorf("DiagnosticID = %q, want none (documented)", e.Diagnostics.DiagnosticID)
	}
}

func TestProvider(t *testing.T) {
	h := tlsauth.NewHandler(nil, "Auth.Test")
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

func TestCheckHost(t *testing.T) {
	cases := []struct {
		name, host, sni string
		noTLS           bool
		want            error
	}{
		{name: "host with port", host: "alpha.auth.test:8443", sni: alphaHost},
		{name: "host without port", host: alphaHost, sni: alphaHost},
		{name: "case-insensitive", host: "Alpha.AUTH.test", sni: alphaHost},
		{name: "other provider", host: betaHost, sni: alphaHost, want: tlsauth.ErrMisdirected},
		{name: "other provider with port", host: "beta.auth.test:443", sni: alphaHost, want: tlsauth.ErrMisdirected},
		{name: "trailing dot", host: "alpha.auth.test.", sni: alphaHost, want: tlsauth.ErrMisdirected},
		{name: "empty host", host: "", sni: alphaHost, want: tlsauth.ErrMisdirected},
		{name: "no SNI", host: alphaHost, sni: "", want: tlsauth.ErrMisdirected},
		{name: "empty host and no SNI", host: "", sni: "", want: tlsauth.ErrMisdirected},
		{name: "port only and no SNI", host: ":443", sni: "", want: tlsauth.ErrMisdirected},
		{name: "no TLS", host: alphaHost, noTLS: true, want: tlsauth.ErrMisdirected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://placeholder/v1/authenticate", nil)
			r.Host = c.host
			if !c.noTLS {
				r.TLS = &tls.ConnectionState{ServerName: c.sni}
			}
			if got := tlsauth.CheckHost(r); !errors.Is(got, c.want) {
				t.Errorf("CheckHost(Host %q, SNI %q) = %v, want %v", c.host, c.sni, got, c.want)
			}
		})
	}
}
