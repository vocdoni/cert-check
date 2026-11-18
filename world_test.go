package certcheck_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// The handler world: providers alpha (rootA, policy hPolicyA) and beta
// (rootB, policy hPolicyB), one profile each; alpha's OCSP responder answers
// good on a fake network. rootU is pinned by nobody.
const (
	hOCSPHost = "ocsp.alpha.test"
	hVersion  = "handler-test"
)

var (
	hPolicyA   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 5, 1}
	hPolicyB   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 5, 2}
	hDiscard   = slog.New(slog.DiscardHandler)
	hDiagIDRe  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hClientEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
)

type hWorld struct {
	now                 time.Time
	rootA, rootB, rootU *testpki.CA
	alpha, beta         certcheck.Provider
	h                   *certcheck.Handler
}

// hAdapter reads IDCES-<DNI> from serialNumber and the surnames from SN.
func hAdapter() identity.Adapter {
	return identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{identity.DocumentDNI}}},
		Surnames:  identity.SurnamesFromSN, SAN: identity.SANCheck{Kind: identity.SANNone},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
}

// hDecl declares provider id with one profile "<id>-a" anchored at root
// under policy, revocation by OCSP at hOCSPHost.
func hDecl(id string, root *testpki.CA, policy asn1.ObjectIdentifier) profiles.Provider {
	return profiles.Provider{ID: id, Name: strings.ToUpper(id), Profiles: []profiles.Profile{{
		ID: id + "-a", ProviderID: id, Name: id + "-a", HolderRole: profiles.RoleNaturalPerson,
		Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{policy.String()},
		EKU: profiles.EKURequireClientAuth, Identity: hAdapter(),
		Revocation: revocation.Policy{OCSPHosts: []string{hOCSPHost}},
	}}}
}

// hProvider builds d with engine.New, loaded and clocked at now.
func hProvider(t *testing.T, d profiles.Provider, now time.Time, rc *revocation.Checker) certcheck.Provider {
	t.Helper()
	p, err := engine.New(engine.Config{Provider: d, Revocation: rc, Now: func() time.Time { return now }, Logger: hDiscard, Version: hVersion})
	if err != nil {
		t.Fatalf("engine.New(%s): %v", d.ID, err)
	}
	return p
}

func newHWorld(t *testing.T) *hWorld {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	w := &hWorld{now: now}
	w.rootA = testpki.NewRoot(t, "Handler Alpha Root", testpki.CertSpec{Now: now})
	w.rootB = testpki.NewRoot(t, "Handler Beta Root", testpki.CertSpec{Now: now})
	w.rootU = testpki.NewRoot(t, "Handler Unknown Root", testpki.CertSpec{Now: now})
	ocsp := testpki.NewOCSPServer(w.rootA, w.rootA.OCSPResponder(t, testpki.CertSpec{Now: now}))
	ocsp.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
		return testpki.OCSPSpec{Now: now, NextUpdate: now.Add(time.Hour)}
	})
	n := testpki.NewNet()
	n.Serve(t, hOCSPHost, ocsp.Handler(t))
	rc, err := revocation.NewChecker(revocation.Options{DialContext: n.DialContext, Now: func() time.Time { return now }, Logger: hDiscard})
	if err != nil {
		t.Fatal(err)
	}
	w.alpha = hProvider(t, hDecl("alpha", w.rootA, hPolicyA), now, rc)
	w.beta = hProvider(t, hDecl("beta", w.rootB, hPolicyB), now, rc)
	w.h, err = certcheck.NewHandler([]certcheck.Provider{w.alpha, w.beta},
		certcheck.WithClock(func() time.Time { return now }), certcheck.WithVersion(hVersion))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return w
}

// leaf issues a leaf under ca asserting policy, with alpha's OCSP URL.
func (w *hWorld) leaf(t *testing.T, ca *testpki.CA, policy asn1.ObjectIdentifier, edit func(*testpki.CertSpec)) *x509.Certificate {
	t.Helper()
	return w.issue(t, ca, policy, edit).Cert
}

// issue is leaf with the private key (for TLS clients).
func (w *hWorld) issue(t *testing.T, ca *testpki.CA, policy asn1.ObjectIdentifier, edit func(*testpki.CertSpec)) *testpki.Leaf {
	t.Helper()
	spec := testpki.CertSpec{Now: w.now, Subject: testpki.Name{
		testpki.Printable(testpki.OIDCountry, "ES"), testpki.Printable(testpki.OIDSerialNumber, "IDCES-12345679S"),
		testpki.UTF8(testpki.OIDGivenName, "JUAN"), testpki.UTF8(testpki.OIDSurname, "GARCÍA LÓPEZ"),
		testpki.UTF8(testpki.OIDCommonName, "JUAN GARCÍA LÓPEZ")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: hClientEKU,
		Policies: []asn1.ObjectIdentifier{policy}, OCSPServers: []string{"http://" + hOCSPHost + "/"}}
	if edit != nil {
		edit(&spec)
	}
	return ca.Leaf(t, spec)
}

// hErr returns err as *certcheck.Error or stops the test.
func hErr(t *testing.T, err error) *certcheck.Error {
	t.Helper()
	e, ok := errors.AsType[*certcheck.Error](err)
	if !ok {
		t.Fatalf("error = %v (%T), want *certcheck.Error", err, err)
	}
	return e
}

// fakeProvider is a consumer test double: it advertises cas and never
// verifies (its Verify error is not a *certcheck.Error).
type fakeProvider struct {
	id  string
	cas []*x509.Certificate
}

func (f fakeProvider) Info() certcheck.ProviderInfo {
	return certcheck.ProviderInfo{ID: f.id, Name: f.id}
}
func (f fakeProvider) CAs() []*x509.Certificate { return f.cas }
func (f fakeProvider) Verify(context.Context, []*x509.Certificate) (*certcheck.Result, error) {
	return nil, errors.New("fake")
}
