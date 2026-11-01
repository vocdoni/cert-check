package certcheck_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	certcheck "github.com/vocdoni/cert-check"
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
