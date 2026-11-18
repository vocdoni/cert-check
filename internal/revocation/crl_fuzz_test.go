package revocation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// crlTRealCerts are the certificates whose CDP values seed FuzzParseCDP.
var crlTRealCerts = []string{"ac-raiz-dnie-2.pem", "ac-dnie-004.pem", "aoc-g3-root-a.pem", "aoc-subca-ciutadania-g3-a2.pem"}

// crlTExtension returns the value of the extension id, or nil.
func crlTExtension(exts []pkix.Extension, id asn1.ObjectIdentifier) []byte {
	for _, e := range exts {
		if e.Id.Equal(id) {
			return e.Value
		}
	}
	return nil
}

// crlTCheckGeneralName fails unless g is one complete context-specific TLV.
func crlTCheckGeneralName(t *testing.T, g GeneralName) {
	t.Helper()
	s := cryptobyte.String(g)
	var el cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1Element(&el, &tag) || !s.Empty() || tag&0xc0 != 0x80 {
		t.Fatalf("GeneralName %x is not one context-specific element", []byte(g))
	}
	g.URI()
}

func FuzzParseIDP(f *testing.F) {
	rl, err := x509.ParseRevocationList(crlTReadFile(f, "dnie-arl.crl"))
	if err != nil {
		f.Fatal(err)
	}
	arl := crlTExtension(rl.Extensions, oidExtIssuingDistPoint)
	if arl == nil {
		f.Fatal("dnie-arl.crl has no IDP")
	}
	f.Add(arl)
	for _, c := range crlTIDPCases() {
		f.Add(c.der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		idp, err := ParseIDP(der)
		if err != nil {
			return
		}
		if idp.RelativeName && idp.FullName != nil {
			t.Fatalf("IDP %x has both a relative name and a full name", der)
		}
		for _, g := range idp.FullName {
			crlTCheckGeneralName(t, g)
		}
	})
}

// crlTTBS returns the tbsCertList element of a CertificateList.
func crlTTBS(der []byte) ([]byte, bool) {
	in := cryptobyte.String(der)
	var crl, tbs cryptobyte.String
	if !in.ReadASN1(&crl, cbasn1.SEQUENCE) || !crl.ReadASN1Element(&tbs, cbasn1.SEQUENCE) {
		return nil, false
	}
	return tbs, true
}

// crlTReissue returns der with its signature algorithm and issuer replaced
// by ca's, signed by ca: a real CRL's structure under a test issuer.
func crlTReissue(t testing.TB, der []byte, ca *testpki.CA) []byte {
	t.Helper()
	tbs, ok := crlTTBS(der)
	in := cryptobyte.String(tbs)
	var body, version cryptobyte.String
	if !ok || !in.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1Element(&version, cbasn1.INTEGER) ||
		!body.SkipASN1(cbasn1.SEQUENCE) || !body.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("crlTReissue: malformed CRL")
	}
	return crlTSign(t, ca.Key, crlTSeq(version, crlTECDSAAlgID, ca.Cert.RawSubject, body), false)
}

// FuzzParseCRL runs ParseCRL and EvaluateCRL on each input as received and
// re-signed by the test issuer, so that mutations reach the parser.
func FuzzParseCRL(f *testing.F) {
	ca := testpki.NewRoot(f, "crlT fuzz crl issuer", testpki.CertSpec{Now: crlTNow})
	cdp := []testpki.DistributionPoint{{URIs: []string{"http://crl.example.es/root.crl"}}}
	leaf := ca.Leaf(f, testpki.CertSpec{Now: crlTNow, Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "crlT fuzz leaf")}, CDP: cdp}).Cert
	sub := ca.Intermediate(f, "crlT fuzz sub", testpki.CertSpec{Now: crlTNow, CDP: cdp}).Cert
	dps, err := ParseCRLDistributionPoints(leaf)
	if err != nil || len(dps) != 1 {
		f.Fatalf("ParseCRLDistributionPoints = %s, %v", crlTDPString(dps), err)
	}
	for _, name := range []string{"dnie-arl.crl", "dnie-crl.crl", "aoc-caroot-a.crl"} {
		f.Add(crlTReadFile(f, name))
		f.Add(crlTReissue(f, crlTReadFile(f, name), ca))
	}
	at := crlTNow.Add(-time.Hour)
	for _, s := range []testpki.CRLSpec{
		{},
		{Entries: []testpki.CRLEntry{{Serial: leaf.SerialNumber, RevokedAt: at, Reason: 1}, {Serial: sub.SerialNumber, RevokedAt: at, NoReason: true,
			Extensions: []pkix.Extension{testpki.InvalidityDate(at)}}}},
		{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/root.crl"}, OnlyUser: true}},
		{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, OnlyCA: true}},
		{IDP: &testpki.IDPSpec{RelativeName: testpki.RDN{{OID: testpki.OIDCommonName, Value: "CRL1"}}}},
		{ExtraExtensions: []pkix.Extension{{Id: oidExtDeltaCRLIndicator, Critical: true, Value: []byte{0x02, 0x01, 0x01}}}},
		{NoNextUpdate: true},
	} {
		s.Now = crlTNow
		f.Add(ca.CRL(f, s))
	}
	f.Add(crlTDense(f, ca, 4, 16, true, false))
	f.Fuzz(func(t *testing.T, der []byte) {
		crlTFuzzCheck(t, der, ca.Cert, leaf, sub, dps[0])
		if tbs, ok := crlTTBS(der); ok {
			crlTFuzzCheck(t, crlTSign(t, ca.Key, tbs, false), ca.Cert, leaf, sub, dps[0])
		}
	})
}

// crlTFuzzCheck checks the ParseCRL and EvaluateCRL invariants for der.
func crlTFuzzCheck(t *testing.T, der []byte, issuer, leaf, sub *x509.Certificate, dp DistributionPoint) {
	t.Helper()
	p, st, err := ParseCRL(der, issuer)
	if !st.Valid() {
		t.Fatalf("ParseCRL status %q is not a Status", st)
	}
	if err != nil {
		if p != nil || st == StatusGood {
			t.Fatalf("ParseCRL = %v, %s, %v: an error with a CRL or good", p, st, err)
		}
		return
	}
	if st != StatusGood || p == nil {
		t.Fatalf("ParseCRL = %v, %s, nil: want a CRL and good", p, st)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseCRL accepted what x509 rejects: %v", err)
	}
	if rl.CheckSignatureFrom(issuer) != nil {
		t.Fatal("ParseCRL accepted a CRL whose signature x509 rejects")
	}
	// A negative serial is listed under its unsigned reading too.
	if len(p.Listed) > 2*len(rl.RevokedCertificateEntries) || p.Cost < crlCostBase+int64(len(p.Listed))*crlCostEntry {
		t.Fatalf("Listed %d of %d entries, cost %d", len(p.Listed), len(rl.RevokedCertificateEntries), p.Cost)
	}
	// The pre-parse count behind the cache-limit check is x509's.
	if n, err := checkCRLSignature(der, issuer); err != nil || n != len(rl.RevokedCertificateEntries) {
		t.Fatalf("checkCRLSignature = %d, %v, want %d entries", n, err, len(rl.RevokedCertificateEntries))
	}
	for _, e := range rl.RevokedCertificateEntries {
		if _, ok := p.Listed[SerialKey(e.SerialNumber)]; !ok {
			t.Fatalf("serial %x is not in Listed", e.SerialNumber)
		}
	}
	for _, c := range []struct {
		cert  *x509.Certificate
		scope Scope
	}{{leaf, ScopeLeaf}, {sub, ScopeCA}} {
		got, _, detail := EvaluateCRL(p, c.cert, dp, c.scope, crlTNow)
		_, listed := p.Listed[SerialKey(c.cert.SerialNumber)]
		if !got.Valid() || detail == "" || (got == StatusRevoked && !listed) || (got == StatusGood && listed) {
			t.Fatalf("EvaluateCRL = %s (%q) with the serial listed %v", got, detail, listed)
		}
	}
}

func FuzzParseCDP(f *testing.F) {
	for _, name := range crlTRealCerts {
		if v := crlTExtension(crlTReadCert(f, name).Extensions, oidExtCRLDistributionPoints); v != nil {
			f.Add(v)
		}
	}
	issuer := testpki.NewRoot(f, "crlT fuzz issuer", testpki.CertSpec{Now: crlTNow})
	other := testpki.NewRoot(f, "crlT fuzz other", testpki.CertSpec{Now: crlTNow})
	for _, c := range crlTCDPCases(issuer.Cert, other.Cert) {
		f.Add(c.der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		dps, err := ParseCDP(der)
		if err != nil {
			return
		}
		for _, dp := range dps {
			if dp.RelativeName && dp.FullName != nil {
				t.Fatalf("CDP %x has a DP with both a relative name and a full name", der)
			}
			for _, g := range dp.FullName {
				crlTCheckGeneralName(t, g)
			}
			for _, g := range dp.CRLIssuer {
				crlTCheckGeneralName(t, g)
			}
		}
		for _, dp := range usableDistributionPoints(dps, issuer.Cert) {
			if dp.RelativeName || dp.HasReasons || len(dp.FullName) == 0 {
				t.Fatalf("usableDistributionPoints kept an unusable DP from %x", der)
			}
		}
	})
}
