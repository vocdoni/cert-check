package certcheck_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// A real TLS server configured by Handler.TLSConfig whose handler calls
// AuthAs with the provider named by the first label of the SNI
// ("<id>.auth.test").
const (
	alphaHost = "alpha.auth.test"
	betaHost  = "beta.auth.test"
)

// authCall is what the test handler saw for one request.
type authCall struct {
	remote string
	res    *certcheck.Result
	err    error
}

type authServer struct {
	addr  string
	pool  *x509.CertPool // trusts the server certificate
	mu    sync.Mutex
	calls []authCall
}

func (w *hWorld) startServer(t *testing.T) *authServer {
	t.Helper()
	serverCert, serverPool := testpki.ServerTLS(t, alphaHost, betaHost)
	as := &authServer{pool: serverPool}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		id, _, _ := strings.Cut(r.TLS.ServerName, ".")
		res, err := w.h.AuthAs(r, id)
		as.mu.Lock()
		as.calls = append(as.calls, authCall{remote: r.RemoteAddr, res: res, err: err})
		as.mu.Unlock()
		rw.WriteHeader(http.StatusNoContent)
	}))
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.TLS = w.h.TLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil })
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

func TestAuthenticateSuccessAndTLSInfo(t *testing.T) {
	w := newHWorld(t)
	as := w.startServer(t)
	leaf := w.issue(t, w.rootA, hPolicyA, nil).TLSCertificate()
	call := as.get(t, as.client(t, &tls.Config{RootCAs: as.pool, Certificates: []tls.Certificate{leaf}}), alphaHost)
	if call.err != nil {
		t.Fatalf("AuthAs: %v", call.err)
	}
	if call.res.Provider.ID != "alpha" {
		t.Errorf("provider = %q, want alpha", call.res.Provider.ID)
	}
	want := certcheck.TLSInfo{Version: "TLS 1.2", SNI: alphaHost, ClientCertificatePresented: true, ChainLength: 1}
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
	w := newHWorld(t)
	as := w.startServer(t)
	leaf := w.issue(t, w.rootA, hPolicyA, nil).TLSCertificate()
	// The handler advertises both roots; force the alpha leaf onto beta's SNI.
	c := as.client(t, &tls.Config{RootCAs: as.pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &leaf, nil }})
	call := as.get(t, c, betaHost)
	e := hErr(t, call.err)
	if e.Code != certcheck.CodeProviderMismatch {
		t.Errorf("code = %q, want %q", e.Code, certcheck.CodeProviderMismatch)
	}
	if got := e.Diagnostics.TLS; got == nil || got.SNI != betaHost || !got.ClientCertificatePresented {
		t.Errorf("Diagnostics.TLS = %+v, want SNI %s with a certificate", got, betaHost)
	}
	if e.Diagnostics.Provider != "beta" {
		t.Errorf("Diagnostics.Provider = %q, want beta (from the SNI)", e.Diagnostics.Provider)
	}
}

func TestAuthenticateRunsEveryRequest(t *testing.T) {
	w := newHWorld(t)
	as := w.startServer(t)
	leaf := w.issue(t, w.rootA, hPolicyA, nil).TLSCertificate()
	c := as.client(t, &tls.Config{RootCAs: as.pool, Certificates: []tls.Certificate{leaf}})
	first, second := as.get(t, c, alphaHost), as.get(t, c, alphaHost)
	if first.remote != second.remote {
		t.Fatalf("requests used connections %s and %s, want one keep-alive connection", first.remote, second.remote)
	}
	if first.err != nil || second.err != nil {
		t.Fatalf("AuthAs: %v, %v", first.err, second.err)
	}
	if a, b := first.res.Diagnostics.DiagnosticID, second.res.Diagnostics.DiagnosticID; a == "" || a == b {
		t.Errorf("DiagnosticIDs = %q, %q, want two distinct IDs", a, b)
	}
}

// sharedProvider returns the same outcome to every call: a consumer Provider
// may hand out a package-level *Error or *Result.
type sharedProvider struct {
	ca  *x509.Certificate
	res *certcheck.Result
	err error
}

func (sharedProvider) Info() certcheck.ProviderInfo {
	return certcheck.ProviderInfo{ID: "shared", Name: "Shared"}
}
func (p sharedProvider) CAs() []*x509.Certificate { return []*x509.Certificate{p.ca} }
func (p sharedProvider) Verify(context.Context, []*x509.Certificate) (*certcheck.Result, error) {
	return p.res, p.err
}

// TestAuthSharedOutcome: Auth and AuthAs add the handshake details to a copy
// of the provider's outcome, never to the shared value (run with -race).
func TestAuthSharedOutcome(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	leaf := w.leaf(t, w.rootU, hPolicyA, nil)
	sharedErr := &certcheck.Error{Code: certcheck.CodeRevoked, Detail: "revoked",
		Diagnostics: certcheck.Diagnostics{Provider: "shared", FailedStep: certcheck.StepRevocation, Code: certcheck.CodeRevoked}}
	sharedRes := &certcheck.Result{Provider: certcheck.ProviderRef{ID: "shared", Name: "Shared"}}
	for _, tc := range []struct {
		name     string
		provider sharedProvider
		tlsOf    func() *certcheck.TLSInfo // the shared value's TLS details
	}{
		{"*Error", sharedProvider{ca: w.rootU.Cert, err: sharedErr}, func() *certcheck.TLSInfo { return sharedErr.Diagnostics.TLS }},
		{"wrapped *Error", sharedProvider{ca: w.rootU.Cert, err: fmt.Errorf("wrapped: %w", sharedErr)}, func() *certcheck.TLSInfo { return sharedErr.Diagnostics.TLS }},
		{"*Result", sharedProvider{ca: w.rootU.Cert, res: sharedRes}, func() *certcheck.TLSInfo { return sharedRes.Diagnostics.TLS }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := certcheck.NewHandler([]certcheck.Provider{tc.provider})
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Go(func() {
					sni := fmt.Sprintf("host%d.auth.test", i)
					r := httptest.NewRequest(http.MethodGet, "https://"+sni+"/login", nil)
					r.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, ServerName: sni, PeerCertificates: []*x509.Certificate{leaf}}
					var res *certcheck.Result
					var err error
					if i%2 == 0 {
						res, err = h.Auth(r)
					} else {
						res, err = h.AuthAs(r, "shared")
					}
					var got *certcheck.TLSInfo
					if e, ok := errors.AsType[*certcheck.Error](err); ok {
						got = e.Diagnostics.TLS
					} else if res != nil {
						got = res.Diagnostics.TLS
					}
					if got == nil || got.SNI != sni {
						t.Errorf("call %d: Diagnostics.TLS = %+v, want SNI %s", i, got, sni)
					}
				})
			}
			wg.Wait()
			if got := tc.tlsOf(); got != nil {
				t.Errorf("shared outcome's Diagnostics.TLS = %+v, want nil (untouched)", got)
			}
		})
	}
}

// TestTLSConfigALPN: TLSConfig offers http/1.1 only, but net/http adds h2
// unless http.Server.Protocols allows HTTP/1 only (the TLSConfig doc and the
// Handler.Auth example say so). If a Go release stops adding h2, the first
// case fails and the doc can be relaxed.
func TestTLSConfigALPN(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	serverCert, pool := testpki.ServerTLS(t, alphaHost)
	var http1 http.Protocols
	http1.SetHTTP1(true)
	for _, tc := range []struct {
		name      string
		protocols *http.Protocols
		h2        string // protocol an h2-only client negotiates; "" = the handshake fails
	}{
		{"Protocols unset", nil, "h2"},
		{"Protocols HTTP/1 only", &http1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			srv := &http.Server{Handler: http.NotFoundHandler(), Protocols: tc.protocols,
				ErrorLog:  slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
				TLSConfig: w.h.TLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil })}
			done := make(chan error, 1)
			go func() { done <- srv.ServeTLS(ln, "", "") }()
			t.Cleanup(func() {
				if err := srv.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
				if err := <-done; !errors.Is(err, http.ErrServerClosed) {
					t.Errorf("ServeTLS = %v, want %v", err, http.ErrServerClosed)
				}
			})
			dial := func(protos ...string) (string, error) {
				d := tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: alphaHost, NextProtos: protos}}
				conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
				if err != nil {
					return "", err
				}
				defer conn.Close()
				return conn.(*tls.Conn).ConnectionState().NegotiatedProtocol, nil
			}
			if got, err := dial("http/1.1"); err != nil || got != "http/1.1" {
				t.Errorf("http/1.1 client: (%q, %v), want http/1.1", got, err)
			}
			got, err := dial("h2")
			switch {
			case tc.h2 == "" && err == nil:
				t.Errorf("h2-only client negotiated %q, want a handshake failure", got)
			case tc.h2 != "" && (err != nil || got != tc.h2):
				t.Errorf("h2-only client: (%q, %v), want %q", got, err, tc.h2)
			}
		})
	}
}

func TestAuthenticateWithoutTLS(t *testing.T) {
	w := newHWorld(t)
	res, err := w.h.AuthAs(httptest.NewRequest(http.MethodGet, "http://"+alphaHost+"/v1/authenticate", nil), "alpha")
	if res != nil {
		t.Fatalf("result = %+v, want nil", res)
	}
	e := hErr(t, err)
	if e.Code != certcheck.CodeInternal {
		t.Errorf("code = %q, want %q", e.Code, certcheck.CodeInternal)
	}
	if e.Diagnostics.DiagnosticID != "" {
		t.Errorf("DiagnosticID = %q, want none (documented)", e.Diagnostics.DiagnosticID)
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
		{name: "other provider", host: betaHost, sni: alphaHost, want: certcheck.ErrMisdirected},
		{name: "other provider with port", host: "beta.auth.test:443", sni: alphaHost, want: certcheck.ErrMisdirected},
		{name: "trailing dot", host: "alpha.auth.test.", sni: alphaHost, want: certcheck.ErrMisdirected},
		{name: "empty host", host: "", sni: alphaHost, want: certcheck.ErrMisdirected},
		{name: "no SNI", host: alphaHost, sni: "", want: certcheck.ErrMisdirected},
		{name: "empty host and no SNI", host: "", sni: "", want: certcheck.ErrMisdirected},
		{name: "port only and no SNI", host: ":443", sni: "", want: certcheck.ErrMisdirected},
		{name: "no TLS", host: alphaHost, noTLS: true, want: certcheck.ErrMisdirected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://placeholder/v1/authenticate", nil)
			r.Host = c.host
			if !c.noTLS {
				r.TLS = &tls.ConnectionState{ServerName: c.sni}
			}
			if got := certcheck.CheckHost(r); !errors.Is(got, c.want) {
				t.Errorf("CheckHost(Host %q, SNI %q) = %v, want %v", c.host, c.sni, got, c.want)
			}
		})
	}
}
