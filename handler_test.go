package certcheck_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
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
		{"nil CA", []certcheck.Provider{fakeProvider{id: "nilca", cas: []*x509.Certificate{nil}}}, "advertises a nil certificate"},
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

func TestHandlerVerifySelectsByIssuer(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	res, err := w.h.Verify(t.Context(), []*x509.Certificate{w.leaf(t, w.rootA, hPolicyA, nil)})
	if err != nil {
		t.Fatalf("Verify(alpha leaf) = %v, want success", err)
	}
	if want := (certcheck.ProviderRef{ID: "alpha", Name: "ALPHA"}); res.Provider != want {
		t.Errorf("Result.Provider = %+v, want %+v", res.Provider, want)
	}
	if doc := res.Identity.Document; doc.Type != certcheck.DocumentDNI || doc.Number != "12345679S" {
		t.Errorf("Result.Identity.Document = %s %q, want %s %q", doc.Type, doc.Number, certcheck.DocumentDNI, "12345679S")
	}
	// beta's leaf goes to beta, whose OCSP host has no responder for rootB.
	_, err = w.h.Verify(t.Context(), []*x509.Certificate{w.leaf(t, w.rootB, hPolicyB, nil)})
	e := hErr(t, err)
	if e.Code != certcheck.CodeRevocationUnavailable || e.Diagnostics.Provider != "beta" || e.Diagnostics.FailedStep != certcheck.StepRevocation {
		t.Errorf("Verify(beta leaf) = %s at %q by %q, want %s at %q by beta", e.Code, e.Diagnostics.FailedStep, e.Diagnostics.Provider,
			certcheck.CodeRevocationUnavailable, certcheck.StepRevocation)
	}
}

func TestHandlerVerifyNoCandidate(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	leaf := w.leaf(t, w.rootU, hPolicyA, nil)
	res, err := w.h.Verify(t.Context(), []*x509.Certificate{leaf, w.rootU.Cert})
	e := hErr(t, err)
	d := e.Diagnostics
	if res != nil || e.Code != certcheck.CodeUntrustedIssuer || e.Retryable || d.FailedStep != certcheck.StepPath {
		t.Fatalf("got (%v, %s, retryable %v) at %q, want (nil, %s, false) at %q", res, e.Code, e.Retryable, d.FailedStep,
			certcheck.CodeUntrustedIssuer, certcheck.StepPath)
	}
	if want := "no provider advertises the leaf's issuer"; e.Detail != want {
		t.Errorf("Detail = %q, want %q", e.Detail, want)
	}
	if d.Code != e.Code || d.TechnicalDetail != e.Detail {
		t.Errorf("Diagnostics code %s, technical detail %q; want %s and %q", d.Code, d.TechnicalDetail, e.Code, e.Detail)
	}
	if !hDiagIDRe.MatchString(d.DiagnosticID) || !d.Time.Equal(w.now) || d.ServerVersion != hVersion || d.Provider != "" {
		t.Errorf("diagnostics id %q, time %v, version %q, provider %q; want 32 hex, %v, %q, empty",
			d.DiagnosticID, d.Time, d.ServerVersion, d.Provider, w.now, hVersion)
	}
	if len(d.Chain) != 2 || d.Certificate == nil || d.Certificate.SHA256 != testpki.SHA256Hex(leaf.Raw) {
		t.Errorf("chain %d entries, certificate %+v; want 2 and the leaf described", len(d.Chain), d.Certificate)
	}
	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
	}{
		{"nil chain", nil},
		{"nil leaf", []*x509.Certificate{nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := w.h.Verify(t.Context(), tc.chain)
			e := hErr(t, err)
			if res != nil || e.Code != certcheck.CodeNoCertificate || e.Diagnostics.FailedStep != certcheck.StepBounds || e.Detail != "no client certificate" {
				t.Errorf("got (%v, %s at %q, %q), want (nil, %s at %q, %q)", res, e.Code, e.Diagnostics.FailedStep, e.Detail,
					certcheck.CodeNoCertificate, certcheck.StepBounds, "no client certificate")
			}
		})
	}
}

// TestHandlerBoundsBeforeDiagnostics: the handler's own failures describe a
// chain within the bounds, as a provider does: at most DefaultMaxChainLen+1
// entries, and no description of a leaf over MaxCertificateDER.
func TestHandlerBoundsBeforeDiagnostics(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	value, err := asn1.Marshal(make([]byte, 17<<10))
	if err != nil {
		t.Fatal(err)
	}
	oversized := w.leaf(t, w.rootU, hPolicyA, func(s *testpki.CertSpec) {
		s.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 2}, Value: value}}
	})
	leaf := w.leaf(t, w.rootU, hPolicyA, nil)
	long := []*x509.Certificate{leaf}
	for range 4 * certcheck.DefaultMaxChainLen {
		long = append(long, w.rootU.Cert)
	}
	for _, tc := range []struct {
		name         string
		verify       func(context.Context, []*x509.Certificate) (*certcheck.Result, error)
		chain        []*x509.Certificate
		entries      int
		describeLeaf bool
	}{
		{"Verify long chain", w.h.Verify, long, certcheck.DefaultMaxChainLen + 1, true},
		{"Verify oversized leaf", w.h.Verify, []*x509.Certificate{oversized}, 1, false},
		{"VerifyAs unknown provider, oversized leaf", func(ctx context.Context, chain []*x509.Certificate) (*certcheck.Result, error) {
			return w.h.VerifyAs(ctx, "nope", chain)
		}, []*x509.Certificate{oversized, w.rootU.Cert}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := tc.verify(t.Context(), tc.chain)
			d := hErr(t, err).Diagnostics
			if res != nil || len(d.Chain) != tc.entries {
				t.Errorf("result %v, %d chain entries; want nil and %d", res, len(d.Chain), tc.entries)
			}
			if described := d.Certificate != nil; described != tc.describeLeaf {
				t.Errorf("leaf described %v, want %v", described, tc.describeLeaf)
			}
		})
	}
}

// TestLogAttrsOmitsClientIssuer: the issuer DN of a presented certificate is
// client text. A self-signed personal certificate (issuer == subject) must
// not put the holder's names or document number in the log line.
func TestLogAttrsOmitsClientIssuer(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	personal := testpki.NewRoot(t, "personal", testpki.CertSpec{Now: w.now, Subject: testpki.Name{
		testpki.Printable(testpki.OIDCountry, "ES"), testpki.Printable(testpki.OIDSerialNumber, "IDCES-12345678Z"),
		testpki.UTF8(testpki.OIDGivenName, "JUAN"), testpki.UTF8(testpki.OIDSurname, "GARCÍA LÓPEZ"),
		testpki.UTF8(testpki.OIDCommonName, "JUAN GARCÍA LÓPEZ - 12345678Z")}}).Cert
	chain := []*x509.Certificate{personal}
	for _, tc := range []struct {
		name   string
		verify func() (*certcheck.Result, error)
	}{
		{"Verify", func() (*certcheck.Result, error) { return w.h.Verify(t.Context(), chain) }},
		{"VerifyAs", func() (*certcheck.Result, error) { return w.h.VerifyAs(t.Context(), "alpha", chain) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.verify()
			e := hErr(t, err)
			if e.Code != certcheck.CodeUntrustedIssuer || e.Diagnostics.Certificate == nil {
				t.Fatalf("code %s, certificate %v; want %s with the leaf described", e.Code, e.Diagnostics.Certificate, certcheck.CodeUntrustedIssuer)
			}
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "rejected", e.Diagnostics.LogAttrs()...)
			slog.New(slog.NewJSONHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "rejected", e.Diagnostics.LogAttrs()...)
			for _, pii := range []string{"JUAN", "GARC", "PEZ", "12345678Z"} {
				if strings.Contains(buf.String(), pii) {
					t.Errorf("log lines contain %q:\n%s", pii, buf.String())
				}
			}
			if !strings.Contains(buf.String(), e.Diagnostics.DiagnosticID) {
				t.Errorf("log lines lack the diagnostic ID:\n%s", buf.String())
			}
		})
	}
}

func TestHandlerVerifyAs(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	alphaLeaf := w.leaf(t, w.rootA, hPolicyA, nil)
	unknownCritical := func(s *testpki.CertSpec) {
		s.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1}, Critical: true, Value: asn1.NullBytes}}
	}
	const unknownAuthority = "x509: certificate signed by unknown authority"
	for _, tc := range []struct {
		name     string
		provider string
		leaf     *x509.Certificate
		code     certcheck.ErrorCode
		step     certcheck.Step
		detail   string
	}{
		{"unknown provider", "nope", alphaLeaf, certcheck.CodeProviderMismatch, certcheck.StepBounds, "unknown provider"},
		{"another provider's leaf", "beta", alphaLeaf, certcheck.CodeProviderMismatch, certcheck.StepPath, unknownAuthority},
		{"unhandled critical extension under another provider", "beta", w.leaf(t, w.rootA, hPolicyA, unknownCritical), certcheck.CodeProviderMismatch, certcheck.StepPath, unknownAuthority},
		{"unknown CA", "beta", w.leaf(t, w.rootU, hPolicyB, nil), certcheck.CodeUntrustedIssuer, certcheck.StepPath, unknownAuthority},
		// The re-classification clears critical extensions only to build a path.
		{"unknown CA with an unhandled critical extension", "beta", w.leaf(t, w.rootU, hPolicyB, unknownCritical), certcheck.CodeUntrustedIssuer, certcheck.StepPath, unknownAuthority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := w.h.VerifyAs(t.Context(), tc.provider, []*x509.Certificate{tc.leaf})
			e := hErr(t, err)
			d := e.Diagnostics
			if res != nil || e.Code != tc.code || d.Code != tc.code || d.FailedStep != tc.step || e.Retryable {
				t.Errorf("got (%v, %s, diagnostics %s, retryable %v) at %q; want (nil, %s, %s, false) at %q",
					res, e.Code, d.Code, e.Retryable, d.FailedStep, tc.code, tc.code, tc.step)
			}
			if e.Detail != tc.detail || d.TechnicalDetail != tc.detail {
				t.Errorf("detail %q, technical detail %q; want %q", e.Detail, d.TechnicalDetail, tc.detail)
			}
			if d.Provider != tc.provider || !hDiagIDRe.MatchString(d.DiagnosticID) || d.ServerVersion != hVersion {
				t.Errorf("diagnostics provider %q, id %q, version %q; want %q, 32 hex, %q", d.Provider, d.DiagnosticID, d.ServerVersion, tc.provider, hVersion)
			}
			if tc.step == certcheck.StepPath && (len(d.ProfileCandidates) != 1 || d.ProfileCandidates[0].ProfileID != tc.provider+"-a") {
				t.Errorf("profile candidates %+v, want the single profile %s-a of the named provider", d.ProfileCandidates, tc.provider)
			}
		})
	}
	// A standalone Provider knows no other provider: the same leaf is untrusted_issuer.
	_, err := w.beta.Verify(t.Context(), []*x509.Certificate{alphaLeaf})
	if e := hErr(t, err); e.Code != certcheck.CodeUntrustedIssuer || e.Diagnostics.FailedStep != certcheck.StepPath {
		t.Errorf("beta.Verify(alpha leaf) = %s at %q, want %s at %q", e.Code, e.Diagnostics.FailedStep, certcheck.CodeUntrustedIssuer, certcheck.StepPath)
	}
}

// TestHandlerAuthAs covers Auth and AuthAs on real providers. A request
// without TLS state is TestHandlerAuthWithoutTLS; providers that break the
// Provider contract are TestHandlerProviderErrors.
func TestHandlerAuthAs(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	request := func(state *tls.ConnectionState) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://alpha.auth.test/login", nil)
		r.TLS = state
		return r
	}
	handshake := func(leaf *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			ServerName: "alpha.auth.test", PeerCertificates: []*x509.Certificate{leaf}}
	}
	good, bad := handshake(w.leaf(t, w.rootA, hPolicyA, nil)), handshake(w.leaf(t, w.rootU, hPolicyA, nil))
	for _, tc := range []struct {
		name        string
		auth        func(*http.Request) (*certcheck.Result, error)
		badProvider string // Diagnostics.Provider of the rootU failure
	}{
		{"Auth", w.h.Auth, ""},
		{"AuthAs", func(r *http.Request) (*certcheck.Result, error) { return w.h.AuthAs(r, "alpha") }, "alpha"},
	} {
		t.Run(tc.name+"/success", func(t *testing.T) {
			res, err := tc.auth(request(good))
			if err != nil {
				t.Fatalf("error = %v, want success", err)
			}
			if want := certcheck.DescribeTLS(good); res.Provider.ID != "alpha" || res.Diagnostics.TLS == nil || *res.Diagnostics.TLS != *want {
				t.Errorf("provider %q, Diagnostics.TLS = %+v; want alpha and %+v", res.Provider.ID, res.Diagnostics.TLS, want)
			}
		})
		t.Run(tc.name+"/failure", func(t *testing.T) {
			res, err := tc.auth(request(bad))
			e := hErr(t, err)
			if res != nil || e.Code != certcheck.CodeUntrustedIssuer || e.Diagnostics.Provider != tc.badProvider {
				t.Errorf("got (%v, %s by %q), want (nil, %s by %q)", res, e.Code, e.Diagnostics.Provider, certcheck.CodeUntrustedIssuer, tc.badProvider)
			}
			if want := certcheck.DescribeTLS(bad); e.Diagnostics.TLS == nil || *e.Diagnostics.TLS != *want {
				t.Errorf("Diagnostics.TLS = %+v, want %+v", e.Diagnostics.TLS, want)
			}
		})
	}
}

func TestHandlerCAs(t *testing.T) {
	t.Parallel()
	w := newHWorld(t)
	check := func(t *testing.T, h *certcheck.Handler, want []*x509.Certificate) {
		t.Helper()
		got := h.Certificates()
		if !slices.EqualFunc(got, want, func(der []byte, c *x509.Certificate) bool { return bytes.Equal(der, c.Raw) }) {
			t.Errorf("Certificates() = %d entries, want the DER of %d CAs in provider order", len(got), len(want))
		}
		pool := x509.NewCertPool()
		for _, c := range want {
			if !h.CertificateCheck(c.RawSubject) {
				t.Errorf("CertificateCheck(%s) = false, want true", c.Subject)
			}
			pool.AddCert(c)
		}
		if !h.ClientCAs().Equal(pool) {
			t.Error("ClientCAs() differs from the pool of the advertised CAs")
		}
	}
	check(t, w.h, []*x509.Certificate{w.rootA.Cert, w.rootB.Cert})
	if w.h.CertificateCheck(w.rootU.Cert.RawSubject) {
		t.Error("CertificateCheck(unpinned root) = true, want false")
	}
	// A CA advertised twice by one provider is listed once.
	dup, err := certcheck.NewHandler([]certcheck.Provider{w.alpha, fakeProvider{id: "dup", cas: []*x509.Certificate{w.rootU.Cert, w.rootU.Cert}}})
	if err != nil {
		t.Fatalf("NewHandler(alpha, dup) = %v", err)
	}
	check(t, dup, []*x509.Certificate{w.rootA.Cert, w.rootU.Cert})

	// Returned slices are copies.
	want := [][]byte{bytes.Clone(w.rootA.Cert.Raw), bytes.Clone(w.rootB.Cert.Raw)}
	certs := w.h.Certificates()
	certs[0][0] ^= 0xff
	certs[1] = nil
	if got := w.h.Certificates(); !slices.EqualFunc(got, want, bytes.Equal) {
		t.Error("mutating the Certificates() result changed the handler")
	}
	ps := w.h.Providers()
	if len(ps) != 2 || ps[0] != w.alpha || ps[1] != w.beta {
		t.Fatalf("Providers() = %v, want [alpha beta]", ps)
	}
	ps[0] = nil
	if got := w.h.Providers(); got[0] != w.alpha {
		t.Error("mutating the Providers() result changed the handler")
	}
	if w.h.Name() != "certcheck" || !w.h.RequireCertificate() {
		t.Errorf("Name() = %q, RequireCertificate() = %v; want certcheck, true", w.h.Name(), w.h.RequireCertificate())
	}
}
