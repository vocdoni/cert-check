package certcheck_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// nilResultProvider breaks the Provider contract: Verify returns neither a
// Result nor an error.
type nilResultProvider struct{ ca *x509.Certificate }

func (nilResultProvider) Info() certcheck.ProviderInfo {
	return certcheck.ProviderInfo{ID: "nil", Name: "Nil"}
}
func (p nilResultProvider) CAs() []*x509.Certificate { return []*x509.Certificate{p.ca} }
func (nilResultProvider) Verify(context.Context, []*x509.Certificate) (*certcheck.Result, error) {
	return nil, nil
}

func TestHandlerNilResult(t *testing.T) {
	t.Parallel()
	root := testpki.NewRoot(t, "Nil Result Root", testpki.CertSpec{})
	chain := []*x509.Certificate{root.Leaf(t, testpki.CertSpec{Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "Leaf")}}).Cert}
	h, err := certcheck.NewHandler([]certcheck.Provider{nilResultProvider{ca: root.Cert}}, certcheck.WithVersion("v-nil"))
	if err != nil {
		t.Fatalf("NewHandler error = %v", err)
	}
	for _, tc := range []struct {
		name   string
		verify func(context.Context) (*certcheck.Result, error)
	}{
		{"Verify", func(ctx context.Context) (*certcheck.Result, error) { return h.Verify(ctx, chain) }},
		{"VerifyAs", func(ctx context.Context) (*certcheck.Result, error) { return h.VerifyAs(ctx, "nil", chain) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.verify(t.Context())
			e, ok := errors.AsType[*certcheck.Error](err)
			if !ok || res != nil {
				t.Fatalf("got (%v, %v), want (nil, *certcheck.Error)", res, err)
			}
			if e.Code != certcheck.CodeInternal || e.Diagnostics.Code != certcheck.CodeInternal || !e.Retryable {
				t.Errorf("got (%s, diagnostics %s, retryable %v), want (%s, %s, true)", e.Code, e.Diagnostics.Code, e.Retryable,
					certcheck.CodeInternal, certcheck.CodeInternal)
			}
			if got, want := e.Detail, "provider returned no result"; got != want {
				t.Errorf("detail = %q, want %q", got, want)
			}
			if d := e.Diagnostics; d.Provider != "nil" || d.ServerVersion != "v-nil" || len(d.Chain) != 1 || d.Certificate == nil {
				t.Errorf("diagnostics = provider %q, version %q, %d chain entries, certificate %v; want nil, v-nil, 1, set",
					d.Provider, d.ServerVersion, len(d.Chain), d.Certificate != nil)
			}
		})
	}
}

func TestNewHandlerRejects(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	now := w.now
	rc, err := revocation.NewChecker(revocation.Options{Logger: hDiscard})
	if err != nil {
		t.Fatal(err)
	}
	// Same key as rootA, another subject: its own CA name, alpha's anchor key.
	sameKey := testpki.NewRoot(t, "Handler Gamma Root", testpki.CertSpec{Now: now, KeyPair: w.rootA.Key})
	expired := testpki.NewRoot(t, "Handler Expired Root", testpki.CertSpec{Now: now,
		NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
	for _, tc := range []struct {
		name      string
		providers []certcheck.Provider
		want      string
	}{
		{"no providers", nil, "at least one provider"},
		{"nil provider", []certcheck.Provider{w.alpha, nil}, "provider 1 is nil"},
		{"duplicate ID", []certcheck.Provider{w.alpha, fakeProvider{id: "alpha", cas: []*x509.Certificate{w.rootU.Cert}}}, `duplicate provider "alpha"`},
		{"inert provider", []certcheck.Provider{w.alpha, hProvider(t, hDecl("delta", expired, hPolicyB), now, rc)}, `provider "delta" has no enabled profile`},
		{"inert test double", []certcheck.Provider{fakeProvider{id: "empty"}}, `provider "empty" has no enabled profile`},
		{"shared CA subject", []certcheck.Provider{w.alpha, fakeProvider{id: "copy", cas: []*x509.Certificate{w.rootA.Cert}}}, "both advertise the CA"},
		{"shared anchor key and policy", []certcheck.Provider{w.alpha, hProvider(t, hDecl("gamma", sameKey, hPolicyA), now, rc)}, "share an anchor and policy " + hPolicyA.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := certcheck.NewHandler(tc.providers)
			if err == nil || h != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewHandler = (%v, %v), want an error containing %q", h, err, tc.want)
			}
			if msg := err.Error(); !strings.HasPrefix(msg, "certcheck: ") || strings.Contains(msg, "profiles: ") {
				t.Errorf("error %q, want the %q prefix only", msg, "certcheck: ")
			}
		})
	}
	if _, err := certcheck.NewHandler([]certcheck.Provider{w.alpha, hProvider(t, hDecl("gamma", sameKey, hPolicyB), now, rc)}); err != nil {
		t.Errorf("anchor key shared under another policy: NewHandler = %v, want nil", err)
	}
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("none") }
	suites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
	curves := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	for _, tc := range []struct {
		name string
		opts []certcheck.TLSOption
		max  uint16
	}{
		{"default TLS 1.2", nil, tls.VersionTLS12},
		{"WithTLS13", []certcheck.TLSOption{certcheck.WithTLS13()}, tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := w.h.TLSConfig(getCert, tc.opts...)
			if cfg.MinVersion != tls.VersionTLS12 || cfg.MaxVersion != tc.max {
				t.Errorf("versions [%#x, %#x], want [%#x, %#x]", cfg.MinVersion, cfg.MaxVersion, tls.VersionTLS12, tc.max)
			}
			if cfg.ClientAuth != tls.RequestClientCert || !cfg.SessionTicketsDisabled || !slices.Equal(cfg.NextProtos, []string{"http/1.1"}) {
				t.Errorf("ClientAuth %v, tickets disabled %v, ALPN %q; want %v, true, [http/1.1]",
					cfg.ClientAuth, cfg.SessionTicketsDisabled, cfg.NextProtos, tls.RequestClientCert)
			}
			if !slices.Equal(cfg.CipherSuites, suites) || !slices.Equal(cfg.CurvePreferences, curves) {
				t.Errorf("suites %v, curves %v; want %v, %v", cfg.CipherSuites, cfg.CurvePreferences, suites, curves)
			}
			if cfg.ClientCAs == nil || !cfg.ClientCAs.Equal(w.h.ClientCAs()) || cfg.GetCertificate == nil {
				t.Error("ClientCAs or GetCertificate not set from the handler")
			}
		})
	}
	// Each call returns its own configuration.
	a, b := w.h.TLSConfig(getCert), w.h.TLSConfig(getCert)
	a.CipherSuites[0] = 0
	if b.CipherSuites[0] != suites[0] {
		t.Error("TLSConfig shares its cipher suite slice between calls")
	}
}

// wrapProvider returns a revoked *certcheck.Error wrapped in another error.
type wrapProvider struct{ ca *x509.Certificate }

func (wrapProvider) Info() certcheck.ProviderInfo {
	return certcheck.ProviderInfo{ID: "wrap", Name: "Wrap"}
}
func (p wrapProvider) CAs() []*x509.Certificate { return []*x509.Certificate{p.ca} }
func (wrapProvider) Verify(context.Context, []*x509.Certificate) (*certcheck.Result, error) {
	e := &certcheck.Error{Code: certcheck.CodeRevoked, Detail: "revoked", Diagnostics: certcheck.Diagnostics{
		Provider: "wrap", FailedStep: certcheck.StepRevocation, Code: certcheck.CodeRevoked, TechnicalDetail: "revoked"}}
	return nil, fmt.Errorf("wrapped: %w", e)
}

// TestHandlerProviderErrors: whatever a consumer Provider returns on
// failure, every entry point answers a *certcheck.Error, and Auth/AuthAs add
// the handshake details to it.
func TestHandlerProviderErrors(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	leaf := w.leaf(t, w.rootU, hPolicyA, nil)
	state := &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		ServerName: "u.auth.test", PeerCertificates: []*x509.Certificate{leaf}}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://u.auth.test/login", nil)
		r.TLS = state
		return r
	}
	type call func(h *certcheck.Handler, id string) (*certcheck.Result, error)
	calls := []struct {
		name string
		tls  bool
		call call
	}{
		{"Verify", false, func(h *certcheck.Handler, _ string) (*certcheck.Result, error) {
			return h.Verify(t.Context(), []*x509.Certificate{leaf})
		}},
		{"VerifyAs", false, func(h *certcheck.Handler, id string) (*certcheck.Result, error) {
			return h.VerifyAs(t.Context(), id, []*x509.Certificate{leaf})
		}},
		{"Auth", true, func(h *certcheck.Handler, _ string) (*certcheck.Result, error) { return h.Auth(request()) }},
		{"AuthAs", true, func(h *certcheck.Handler, id string) (*certcheck.Result, error) { return h.AuthAs(request(), id) }},
	}
	for _, pc := range []struct {
		name     string
		provider certcheck.Provider
		code     certcheck.ErrorCode
		step     certcheck.Step
		detail   string
	}{
		{"no result", nilResultProvider{ca: w.rootU.Cert}, certcheck.CodeInternal, "", "provider returned no result"},
		{"plain error", fakeProvider{id: "fake", cas: []*x509.Certificate{w.rootU.Cert}}, certcheck.CodeInternal, "",
			"provider returned an error that is not *certcheck.Error"},
		{"wrapped *Error", wrapProvider{ca: w.rootU.Cert}, certcheck.CodeRevoked, certcheck.StepRevocation, "revoked"},
	} {
		id := pc.provider.Info().ID
		h, err := certcheck.NewHandler([]certcheck.Provider{pc.provider},
			certcheck.WithClock(func() time.Time { return w.now }), certcheck.WithVersion(hVersion))
		if err != nil {
			t.Fatalf("%s: NewHandler: %v", pc.name, err)
		}
		for _, c := range calls {
			t.Run(pc.name+"/"+c.name, func(t *testing.T) {
				res, err := c.call(h, id)
				e, ok := err.(*certcheck.Error)
				if !ok || res != nil {
					t.Fatalf("got (%v, %v (%T)), want (nil, *certcheck.Error)", res, err, err)
				}
				d := e.Diagnostics
				if e.Code != pc.code || d.Code != pc.code || e.Retryable != pc.code.Retryable() || d.FailedStep != pc.step {
					t.Errorf("got %s (diagnostics %s, retryable %v) at %q, want %s (retryable %v) at %q",
						e.Code, d.Code, e.Retryable, d.FailedStep, pc.code, pc.code.Retryable(), pc.step)
				}
				if e.Detail != pc.detail || d.TechnicalDetail != pc.detail || d.Provider != id {
					t.Errorf("detail %q (technical %q), provider %q; want %q and %q", e.Detail, d.TechnicalDetail, d.Provider, pc.detail, id)
				}
				if pc.code == certcheck.CodeInternal {
					if !hDiagIDRe.MatchString(d.DiagnosticID) || !d.Time.Equal(w.now) || d.ServerVersion != hVersion {
						t.Errorf("diagnostics id %q, time %v, version %q; want 32 hex, %v, %q", d.DiagnosticID, d.Time, d.ServerVersion, w.now, hVersion)
					}
					if len(d.Chain) != 1 || d.Certificate == nil || d.Certificate.SHA256 != testpki.SHA256Hex(leaf.Raw) {
						t.Errorf("chain %d entries, certificate %+v; want 1 and the leaf described", len(d.Chain), d.Certificate)
					}
				}
				switch want := certcheck.DescribeTLS(state); {
				case c.tls && (d.TLS == nil || *d.TLS != *want):
					t.Errorf("Diagnostics.TLS = %+v, want %+v", d.TLS, want)
				case !c.tls && d.TLS != nil:
					t.Errorf("Diagnostics.TLS = %+v, want nil", d.TLS)
				}
			})
		}
	}
}

func TestHandlerAuthWithoutTLS(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	for _, tc := range []struct {
		name string
		auth func(*http.Request) (*certcheck.Result, error)
	}{
		{"Auth", w.h.Auth},
		{"AuthAs", func(r *http.Request) (*certcheck.Result, error) { return w.h.AuthAs(r, "alpha") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.auth(httptest.NewRequest(http.MethodGet, "http://alpha.auth.test/login", nil))
			e := hErr(t, err)
			if res != nil || e.Code != certcheck.CodeInternal || !e.Retryable || e.Detail != "request without TLS state" {
				t.Errorf("got (%v, %s, retryable %v, %q), want (nil, %s, true, %q)", res, e.Code, e.Retryable, e.Detail,
					certcheck.CodeInternal, "request without TLS state")
			}
			if !reflect.ValueOf(e.Diagnostics).IsZero() {
				t.Errorf("Diagnostics = %+v, want empty", e.Diagnostics)
			}
		})
	}
}
