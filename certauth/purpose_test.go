package certauth

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/testpki"
)

func TestPurposeRules(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)
	requireCA := profiles.Profile{EKU: profiles.EKURequireClientAuth}
	allowAbsent := profiles.Profile{EKU: profiles.EKUAllowAbsent} // DNIe
	leaf := func(edit func(*testpki.CertSpec)) *x509.Certificate { return w.leaf(t, w.rootA, edit) }
	ekus := func(e ...x509.ExtKeyUsage) func(*testpki.CertSpec) {
		return func(s *testpki.CertSpec) { s.ExtKeyUsage = e }
	}
	caLeaf := w.rootA.Intermediate(t, "CA as leaf", testpki.CertSpec{Now: w.now, KeyPair: tKey(t, "leaf", testpki.ECDSAP256),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []asn1.ObjectIdentifier{tOID(t, cwPolicyA)}, OCSPServers: []string{cwOCSPURL}}).Cert

	for _, tc := range []struct {
		name    string
		leaf    *x509.Certificate
		profile profiles.Profile
		ok      bool
		detail  string
	}{
		{"KU absent", leaf(func(s *testpki.CertSpec) { s.NoKeyUsage = true }), requireCA, false, "KeyUsage extension absent"},
		{"KU absent under DNIe", leaf(func(s *testpki.CertSpec) { s.NoKeyUsage, s.ExtKeyUsage = true, nil }), allowAbsent, false, "KeyUsage extension absent"},
		{"KU without digitalSignature", leaf(func(s *testpki.CertSpec) { s.KeyUsage = x509.KeyUsageContentCommitment }), requireCA, false, "KeyUsage lacks digitalSignature"},
		{"EKU absent with RequireClientAuth", leaf(ekus()), requireCA, false, "ExtendedKeyUsage must be present and list clientAuth"},
		{"EKU absent with AllowAbsent", leaf(ekus()), allowAbsent, true, ""},
		{"EKU clientAuth with AllowAbsent", leaf(nil), allowAbsent, true, ""},
		{"EKU emailProtection with AllowAbsent", leaf(ekus(x509.ExtKeyUsageEmailProtection)), allowAbsent, false, "ExtendedKeyUsage present without clientAuth"},
		{"EKU only anyExtendedKeyUsage", leaf(ekus(x509.ExtKeyUsageAny)), requireCA, false, "ExtendedKeyUsage must be present and list clientAuth"},
		{"EKU only anyExtendedKeyUsage with AllowAbsent", leaf(ekus(x509.ExtKeyUsageAny)), allowAbsent, false, "ExtendedKeyUsage present without clientAuth"},
		{"anyEKU plus clientAuth (FNMT 2016 kit)", leaf(ekus(x509.ExtKeyUsageAny, x509.ExtKeyUsageClientAuth)), requireCA, true, ""},
		{"clientAuth and emailProtection", leaf(ekus(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection)), requireCA, true, ""},
		{"CA:TRUE leaf", caLeaf, requireCA, false, "leaf is a CA certificate"},
		{"EKU rule unset", leaf(nil), profiles.Profile{}, false, "profile EKU rule unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			detail, ok := purposeOK(tc.leaf, tc.profile)
			if ok != tc.ok || detail != tc.detail {
				t.Errorf("purposeOK = (%q, %v), want (%q, %v)", detail, ok, tc.detail, tc.ok)
			}
		})
	}

	t.Run("CA:TRUE leaf through the pipeline", func(t *testing.T) {
		res, err := w.chk.Check(t.Context(), "alpha", []*x509.Certificate{caLeaf})
		e := tErr(t, err)
		if res != nil || e.Code != CodeUnsupportedPurpose || e.Diagnostics.FailedStep != StepPurpose {
			t.Errorf("got (%s at %s), want (%s at %s)", e.Code, e.Diagnostics.FailedStep, CodeUnsupportedPurpose, StepPurpose)
		}
	})
}
