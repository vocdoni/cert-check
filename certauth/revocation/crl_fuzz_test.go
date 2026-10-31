package revocation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

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
