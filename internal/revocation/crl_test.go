package revocation

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// crlTNow is the fixed clock of the CRL tests, inside the validity of the real
// CRLs in testdata/crl.
var crlTNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

const crlTDir = "testdata/crl"

// crlTDER returns one DER element: tag around the concatenated contents.
func crlTDER(tag cbasn1.Tag, contents ...[]byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(tag, func(b *cryptobyte.Builder) {
		for _, c := range contents {
			b.AddBytes(c)
		}
	})
	return b.BytesOrPanic()
}

func crlTSeq(contents ...[]byte) []byte { return crlTDER(cbasn1.SEQUENCE, contents...) }

// crlTURI is a uniformResourceIdentifier GeneralName.
func crlTURI(s string) []byte { return crlTDER(cbasn1.Tag(6).ContextSpecific(), []byte(s)) }

// crlTDirName is a directoryName GeneralName holding the Name DER.
func crlTDirName(nameDER []byte) []byte {
	return crlTDER(cbasn1.Tag(4).Constructed().ContextSpecific(), nameDER)
}

// crlTFullName is a distributionPoint [0] holding fullName [0] GeneralNames.
func crlTFullName(names ...[]byte) []byte {
	return crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(),
		crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(), names...))
}

// crlTRelativeName is a distributionPoint [0] holding nameRelativeToCRLIssuer [1].
func crlTRelativeName() []byte {
	var atv cryptobyte.Builder
	atv.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 3})
		b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte("CRL1")) })
	})
	return crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(),
		crlTDER(cbasn1.Tag(1).Constructed().ContextSpecific(), atv.BytesOrPanic()))
}

// crlTReasons is a DistributionPoint reasons [1] BIT STRING (keyCompromise).
func crlTReasons() []byte { return crlTDER(cbasn1.Tag(1).ContextSpecific(), []byte{0x07, 0x80}) }

// crlTIssuerNames is a DistributionPoint cRLIssuer [2] GeneralNames.
func crlTIssuerNames(names ...[]byte) []byte {
	return crlTDER(cbasn1.Tag(2).Constructed().ContextSpecific(), names...)
}

// crlTNames renders GeneralNames for got/want messages.
func crlTNames(names []GeneralName) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if u, ok := n.URI(); ok {
			out = append(out, "uri:"+u)
			continue
		}
		out = append(out, "tlv:"+hex.EncodeToString(n))
	}
	return out
}

func crlTDPString(dps []DistributionPoint) string {
	var sb strings.Builder
	for _, dp := range dps {
		fmt.Fprintf(&sb, "{full:%v rel:%v reasons:%v issuer:%v issuerSet:%v}", crlTNames(dp.FullName),
			dp.RelativeName, dp.HasReasons, crlTNames(dp.CRLIssuer), dp.CRLIssuer != nil)
	}
	return sb.String()
}

func crlTIDPString(idp IDP) string {
	return fmt.Sprintf("{full:%v rel:%v user:%v ca:%v reasons:%v indirect:%v attr:%v}", crlTNames(idp.FullName),
		idp.RelativeName, idp.OnlyUserCerts, idp.OnlyCACerts, idp.OnlySomeReasons, idp.IndirectCRL, idp.OnlyAttributeCert)
}

// crlTCDPCase is one ParseCDP input; usable counts the DPs usableDistributionPoints
// keeps for the issuer.
type crlTCDPCase struct {
	name    string
	der     []byte
	want    []DistributionPoint
	usable  int
	wantErr bool
}

func crlTCDPCases(issuer, other *x509.Certificate) []crlTCDPCase {
	uri1 := crlTURI("http://crl.example.es/a.crl")
	uri2 := crlTURI("http://crl2.example.es/b.crl")
	ldap := crlTURI("ldap://ldap.example.es/cn=CRL1?certificateRevocationList")
	dir := crlTDirName(testpki.Name{testpki.Printable(testpki.OIDCountry, "ES"), testpki.UTF8(testpki.OIDCommonName, "CRL1")}.DER())
	issuerDir := crlTDirName(issuer.RawSubject)
	otherDir := crlTDirName(other.RawSubject)
	gn := func(names ...[]byte) []GeneralName {
		out := make([]GeneralName, len(names))
		for i, n := range names {
			out[i] = GeneralName(n)
		}
		return out
	}
	return []crlTCDPCase{
		{name: "uris plus dirname", der: crlTSeq(crlTSeq(crlTFullName(uri1, ldap, dir))),
			want: []DistributionPoint{{FullName: gn(uri1, ldap, dir)}}, usable: 1},
		{name: "dirname first", der: crlTSeq(crlTSeq(crlTFullName(dir, uri1))),
			want: []DistributionPoint{{FullName: gn(dir, uri1)}}, usable: 1},
		{name: "two dps", der: crlTSeq(crlTSeq(crlTFullName(uri1)), crlTSeq(crlTFullName(uri2, dir))),
			want: []DistributionPoint{{FullName: gn(uri1)}, {FullName: gn(uri2, dir)}}, usable: 2},
		{name: "reasons", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTReasons())),
			want: []DistributionPoint{{FullName: gn(uri1), HasReasons: true}}, usable: 0},
		{name: "reasons beside a plain dp", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTReasons()), crlTSeq(crlTFullName(uri2))),
			want: []DistributionPoint{{FullName: gn(uri1), HasReasons: true}, {FullName: gn(uri2)}}, usable: 1},
		{name: "relative name", der: crlTSeq(crlTSeq(crlTRelativeName())),
			want: []DistributionPoint{{RelativeName: true}}, usable: 0},
		{name: "crl issuer is the issuer", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTIssuerNames(issuerDir))),
			want: []DistributionPoint{{FullName: gn(uri1), CRLIssuer: gn(issuerDir)}}, usable: 1},
		{name: "other crl issuer", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTIssuerNames(otherDir))),
			want: []DistributionPoint{{FullName: gn(uri1), CRLIssuer: gn(otherDir)}}, usable: 0},
		{name: "crl issuer is a uri", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTIssuerNames(uri2))),
			want: []DistributionPoint{{FullName: gn(uri1), CRLIssuer: gn(uri2)}}, usable: 0},
		{name: "crl issuer with two names", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTIssuerNames(issuerDir, otherDir))),
			want: []DistributionPoint{{FullName: gn(uri1), CRLIssuer: gn(issuerDir, otherDir)}}, usable: 0},
		{name: "crl issuer without a name", der: crlTSeq(crlTSeq(crlTIssuerNames(issuerDir))),
			want: []DistributionPoint{{CRLIssuer: gn(issuerDir)}}, usable: 0},
		{name: "reasons and crl issuer", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTReasons(), crlTIssuerNames(issuerDir))),
			want: []DistributionPoint{{FullName: gn(uri1), HasReasons: true, CRLIssuer: gn(issuerDir)}}, usable: 0},

		{name: "malformed: empty input", der: nil, wantErr: true},
		{name: "malformed: not a sequence", der: crlTDER(cbasn1.SET, crlTSeq(crlTFullName(uri1))), wantErr: true},
		{name: "malformed: trailing data", der: append(crlTSeq(crlTSeq(crlTFullName(uri1))), 0x00), wantErr: true},
		{name: "malformed: truncated", der: crlTSeq(crlTSeq(crlTFullName(uri1)))[:10], wantErr: true},
		{name: "malformed: dp not a sequence", der: crlTSeq(crlTDER(cbasn1.SET, crlTFullName(uri1))), wantErr: true},
		{name: "malformed: unknown dp field", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTDER(cbasn1.Tag(3).ContextSpecific(), []byte{0}))), wantErr: true},
		{name: "malformed: fields out of order", der: crlTSeq(crlTSeq(crlTIssuerNames(issuerDir), crlTFullName(uri1))), wantErr: true},
		{name: "malformed: empty fullName", der: crlTSeq(crlTSeq(crlTFullName())), wantErr: true},
		{name: "malformed: empty cRLIssuer", der: crlTSeq(crlTSeq(crlTFullName(uri1), crlTIssuerNames())), wantErr: true},
		{name: "malformed: universal GeneralName", der: crlTSeq(crlTSeq(crlTFullName(crlTDER(cbasn1.UTF8String, []byte("x"))))), wantErr: true},
		{name: "malformed: unknown DistributionPointName", der: crlTSeq(crlTSeq(crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(),
			crlTDER(cbasn1.Tag(2).Constructed().ContextSpecific())))), wantErr: true},
		{name: "malformed: data after fullName", der: crlTSeq(crlTSeq(crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(),
			crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(), uri1), crlTDER(cbasn1.Tag(1).Constructed().ContextSpecific())))), wantErr: true},
		{name: "malformed: primitive distributionPoint", der: crlTSeq(crlTSeq(crlTDER(cbasn1.Tag(0).ContextSpecific(), uri1))), wantErr: true},
	}
}

func TestParseCDP(t *testing.T) {
	issuer := testpki.NewRoot(t, "crlT cdp issuer", testpki.CertSpec{Now: crlTNow})
	other := testpki.NewRoot(t, "crlT cdp other", testpki.CertSpec{Now: crlTNow})
	for _, c := range crlTCDPCases(issuer.Cert, other.Cert) {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseCDP(c.der)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseCDP(%x) = %s, want error", c.der, crlTDPString(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCDP(%x) error = %v", c.der, err)
			}
			if g, w := crlTDPString(got), crlTDPString(c.want); g != w {
				t.Errorf("ParseCDP(%x)\n got %s\nwant %s", c.der, g, w)
			}
			if u := usableDistributionPoints(got, issuer.Cert); len(u) != c.usable {
				t.Errorf("usableDistributionPoints = %s, want %d entries", crlTDPString(u), c.usable)
			}
		})
	}

	t.Run("certificate extension", func(t *testing.T) {
		const uri = "http://crl.example.es/root.crl"
		dir := testpki.Name{testpki.UTF8(testpki.OIDCommonName, "CRL1")}
		leaf := issuer.Leaf(t, testpki.CertSpec{
			Now:     crlTNow,
			Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "crlT cdp leaf")},
			CDP:     []testpki.DistributionPoint{{URIs: []string{uri}, DirNames: []testpki.Name{dir}, DirNamesFirst: true}},
		})
		got, err := ParseCRLDistributionPoints(leaf.Cert)
		if err != nil {
			t.Fatalf("ParseCRLDistributionPoints error = %v", err)
		}
		want := []DistributionPoint{{FullName: []GeneralName{GeneralName(crlTDirName(dir.DER())), GeneralName(crlTURI(uri))}}}
		if g, w := crlTDPString(got), crlTDPString(want); g != w {
			t.Errorf("ParseCRLDistributionPoints\n got %s\nwant %s", g, w)
		}
	})

	t.Run("certificate without cdp", func(t *testing.T) {
		got, err := ParseCRLDistributionPoints(issuer.Cert)
		if err != nil || got != nil {
			t.Errorf("ParseCRLDistributionPoints = %s, %v, want nil, nil", crlTDPString(got), err)
		}
	})
}

type crlTIDPCase struct {
	name    string
	der     []byte
	want    IDP
	wantErr bool
}

func crlTIDPCases() []crlTIDPCase {
	const (
		uri1 = "http://crl.example.es/a.crl"
		uri2 = "ldap://ldap.example.es/cn=CRL1?certificateRevocationList"
	)
	dir := testpki.Name{testpki.Printable(testpki.OIDCountry, "ES"), testpki.UTF8(testpki.OIDCommonName, "CRL1")}
	ctxBool := func(tag uint8, v ...byte) []byte { return crlTDER(cbasn1.Tag(tag).ContextSpecific(), v) }
	return []crlTIDPCase{
		{name: "empty", der: testpki.EncodeIDP(testpki.IDPSpec{}), want: IDP{}},
		{name: "only user", der: testpki.EncodeIDP(testpki.IDPSpec{OnlyUser: true}), want: IDP{OnlyUserCerts: true}},
		{name: "only ca", der: testpki.EncodeIDP(testpki.IDPSpec{OnlyCA: true}), want: IDP{OnlyCACerts: true}},
		{name: "only some reasons", der: testpki.EncodeIDP(testpki.IDPSpec{OnlySomeReasons: true}), want: IDP{OnlySomeReasons: true}},
		{name: "indirect", der: testpki.EncodeIDP(testpki.IDPSpec{Indirect: true}), want: IDP{IndirectCRL: true}},
		{name: "only attribute certs", der: testpki.EncodeIDP(testpki.IDPSpec{OnlyAttr: true}), want: IDP{OnlyAttributeCert: true}},
		{name: "all flags", der: testpki.EncodeIDP(testpki.IDPSpec{OnlyUser: true, OnlyCA: true, OnlySomeReasons: true, Indirect: true, OnlyAttr: true}),
			want: IDP{OnlyUserCerts: true, OnlyCACerts: true, OnlySomeReasons: true, IndirectCRL: true, OnlyAttributeCert: true}},
		{name: "explicit false", der: crlTSeq(ctxBool(1, 0x00), ctxBool(2, 0x00)), want: IDP{}},
		{name: "full name uris plus dirname", der: testpki.EncodeIDP(testpki.IDPSpec{URIs: []string{uri1, uri2}, DirNames: []testpki.Name{dir}}),
			want: IDP{FullName: []GeneralName{GeneralName(crlTURI(uri1)), GeneralName(crlTURI(uri2)), GeneralName(crlTDirName(dir.DER()))}}},
		{name: "fnmt partition shape", der: testpki.EncodeIDP(testpki.IDPSpec{URIs: []string{uri1}, DirNames: []testpki.Name{dir}, DirNamesFirst: true, OnlyUser: true}),
			want: IDP{FullName: []GeneralName{GeneralName(crlTDirName(dir.DER())), GeneralName(crlTURI(uri1))}, OnlyUserCerts: true}},
		{name: "relative name", der: testpki.EncodeIDP(testpki.IDPSpec{RelativeName: testpki.RDN{{OID: testpki.OIDCommonName, Value: "CRL1"}}}),
			want: IDP{RelativeName: true}},

		{name: "bad boolean value", der: crlTSeq(ctxBool(1, 0x01)), wantErr: true},
		{name: "bad boolean length", der: crlTSeq(ctxBool(2, 0xff, 0xff)), wantErr: true},
		{name: "empty boolean", der: crlTSeq(ctxBool(4)), wantErr: true},
		{name: "bad boolean only attribute certs", der: crlTSeq(ctxBool(5, 0x7f)), wantErr: true},
		{name: "constructed boolean", der: crlTSeq(crlTDER(cbasn1.Tag(1).Constructed().ContextSpecific(), []byte{0x01, 0x01, 0xff})), wantErr: true},
		{name: "flags out of order", der: crlTSeq(ctxBool(2, 0xff), ctxBool(1, 0xff)), wantErr: true},
		{name: "trailing data inside", der: crlTSeq(ctxBool(1, 0xff), ctxBool(6, 0xff)), wantErr: true},
		{name: "trailing data after", der: append(testpki.EncodeIDP(testpki.IDPSpec{OnlyUser: true}), 0x00), wantErr: true},
		{name: "not a sequence", der: crlTDER(cbasn1.SET, ctxBool(1, 0xff)), wantErr: true},
		{name: "empty input", der: nil, wantErr: true},
		{name: "empty full name", der: crlTSeq(crlTFullName()), wantErr: true},
		{name: "unknown distribution point name", der: crlTSeq(crlTDER(cbasn1.Tag(0).Constructed().ContextSpecific(),
			crlTDER(cbasn1.Tag(3).Constructed().ContextSpecific()))), wantErr: true},
		{name: "universal general name", der: crlTSeq(crlTFullName(crlTDER(cbasn1.IA5String, []byte(uri1)))), wantErr: true},
	}
}

func TestParseIDP(t *testing.T) {
	for _, c := range crlTIDPCases() {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseIDP(c.der)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ParseIDP(%x) = %s, want error", c.der, crlTIDPString(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIDP(%x) error = %v", c.der, err)
			}
			if g, w := crlTIDPString(got), crlTIDPString(c.want); g != w {
				t.Errorf("ParseIDP(%x)\n got %s\nwant %s", c.der, g, w)
			}
		})
	}
}

func TestParseCRL(t *testing.T) {
	ca := testpki.NewRoot(t, "crlT parse ca", testpki.CertSpec{Now: crlTNow})
	other := testpki.NewRoot(t, "crlT parse other", testpki.CertSpec{Now: crlTNow})
	sameName := testpki.NewRoot(t, "crlT parse ca", testpki.CertSpec{Now: crlTNow}) // same DN, other key
	noCRLSign := testpki.NewRoot(t, "crlT parse no crlsign", testpki.CertSpec{Now: crlTNow, KeyUsage: x509.KeyUsageCertSign})
	unknown := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}
	null := []byte{0x05, 0x00}
	oidDelta := asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIDP := asn1.ObjectIdentifier{2, 5, 29, 28}
	certIssuer := crlTSeq(crlTDirName(other.Cert.RawSubject))
	entry := func(exts ...pkix.Extension) []testpki.CRLEntry {
		return []testpki.CRLEntry{{Serial: big.NewInt(7), RevokedAt: crlTNow.Add(-time.Hour), Reason: 1, Extensions: exts}}
	}
	spec := func(s testpki.CRLSpec) testpki.CRLSpec { s.Now = crlTNow; return s }

	cases := []struct {
		name   string
		der    []byte
		issuer *x509.Certificate
		want   Status
	}{
		{"valid", ca.CRL(t, spec(testpki.CRLSpec{})), ca.Cert, StatusGood},
		{"valid with idp", ca.CRL(t, spec(testpki.CRLSpec{IDP: &testpki.IDPSpec{OnlyUser: true}})), ca.Cert, StatusGood},
		{"malformed der", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, ca.Cert, StatusInvalidEvidence},
		{"issuer name differs", ca.CRL(t, spec(testpki.CRLSpec{IssuerDER: other.Cert.RawSubject})), ca.Cert, StatusInvalidEvidence},
		{"checked against another issuer", ca.CRL(t, spec(testpki.CRLSpec{})), other.Cert, StatusInvalidEvidence},
		{"signed by another ca", ca.CRL(t, spec(testpki.CRLSpec{Signer: other})), ca.Cert, StatusInvalidEvidence},
		{"same issuer name, other key", ca.CRL(t, spec(testpki.CRLSpec{})), sameName.Cert, StatusInvalidEvidence},
		{"corrupt signature", ca.CRL(t, spec(testpki.CRLSpec{CorruptSig: true})), ca.Cert, StatusInvalidEvidence},
		{"issuer without crlsign", noCRLSign.CRL(t, spec(testpki.CRLSpec{})), noCRLSign.Cert, StatusInvalidEvidence},
		{"malformed idp", ca.CRL(t, spec(testpki.CRLSpec{ExtraExtensions: []pkix.Extension{
			{Id: oidIDP, Critical: true, Value: crlTSeq(crlTDER(cbasn1.Tag(1).ContextSpecific(), []byte{0x01}))}}})), ca.Cert, StatusInvalidEvidence},
		{"critical unknown crl extension", ca.CRL(t, spec(testpki.CRLSpec{ExtraExtensions: []pkix.Extension{
			{Id: unknown, Critical: true, Value: null}}})), ca.Cert, StatusUnsupportedMethod},
		{"non-critical unknown crl extension", ca.CRL(t, spec(testpki.CRLSpec{ExtraExtensions: []pkix.Extension{
			{Id: unknown, Value: null}}})), ca.Cert, StatusGood},
		{"delta crl indicator", ca.CRL(t, spec(testpki.CRLSpec{ExtraExtensions: []pkix.Extension{
			{Id: oidDelta, Critical: true, Value: []byte{0x02, 0x01, 0x01}}}})), ca.Cert, StatusUnsupportedMethod},
		{"non-critical delta crl indicator", ca.CRL(t, spec(testpki.CRLSpec{ExtraExtensions: []pkix.Extension{
			{Id: oidDelta, Value: []byte{0x02, 0x01, 0x01}}}})), ca.Cert, StatusUnsupportedMethod},
		{"critical unknown entry extension", ca.CRL(t, spec(testpki.CRLSpec{Entries: entry(
			pkix.Extension{Id: unknown, Critical: true, Value: null})})), ca.Cert, StatusUnsupportedMethod},
		{"non-critical unknown entry extension", ca.CRL(t, spec(testpki.CRLSpec{Entries: entry(
			pkix.Extension{Id: unknown, Value: null})})), ca.Cert, StatusGood},
		{"certificateIssuer entry extension", ca.CRL(t, spec(testpki.CRLSpec{Entries: entry(
			pkix.Extension{Id: testpki.OIDEntryCertIssuer, Critical: true, Value: certIssuer})})), ca.Cert, StatusUnsupportedMethod},
		{"non-critical certificateIssuer entry extension", ca.CRL(t, spec(testpki.CRLSpec{Entries: entry(
			pkix.Extension{Id: testpki.OIDEntryCertIssuer, Value: certIssuer})})), ca.Cert, StatusUnsupportedMethod},
		{"invalidity date entry extension", ca.CRL(t, spec(testpki.CRLSpec{Entries: entry(
			testpki.InvalidityDate(crlTNow.Add(-2 * time.Hour)))})), ca.Cert, StatusGood},
		{"trailing data", append(ca.CRL(t, spec(testpki.CRLSpec{})), 0x00), ca.Cert, StatusInvalidEvidence},
		{"ecdsa with sha1", crlTSHA1(t, ca), ca.Cert, StatusInvalidEvidence},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, got, err := ParseCRL(c.der, c.issuer)
			if got != c.want {
				t.Fatalf("ParseCRL status = %s (err %v), want %s", got, err, c.want)
			}
			if c.want != StatusGood {
				if err == nil || p != nil {
					t.Errorf("ParseCRL = %v, %v, want nil and an error", p, err)
				}
				return
			}
			if err != nil || p == nil || p.Listed == nil {
				t.Fatalf("ParseCRL = %v, %v, want a parsed CRL", p, err)
			}
			rl, err := x509.ParseRevocationList(c.der)
			if err != nil {
				t.Fatal(err)
			}
			if !p.ThisUpdate.Equal(rl.ThisUpdate) || !p.NextUpdate.Equal(rl.NextUpdate) || p.Number == nil || p.Number.Cmp(rl.Number) != 0 {
				t.Errorf("ParseCRL = thisUpdate %v nextUpdate %v number %v, want %v %v %v", p.ThisUpdate, p.NextUpdate, p.Number, rl.ThisUpdate, rl.NextUpdate, rl.Number)
			}
			if p.Cost < crlCostBase {
				t.Errorf("Cost = %d, want at least %d", p.Cost, crlCostBase)
			}
		})
	}

	t.Run("idp kept", func(t *testing.T) {
		der := ca.CRL(t, spec(testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/a.crl"}, OnlyCA: true}}))
		p, st, err := ParseCRL(der, ca.Cert)
		if st != StatusGood || err != nil {
			t.Fatalf("ParseCRL = %s, %v, want good", st, err)
		}
		want := IDP{FullName: []GeneralName{GeneralName(crlTURI("http://crl.example.es/a.crl"))}, OnlyCACerts: true}
		if p.IDP == nil || crlTIDPString(*p.IDP) != crlTIDPString(want) {
			t.Errorf("IDP = %v, want %s", p.IDP, crlTIDPString(want))
		}
		plain, _, _ := ParseCRL(ca.CRL(t, spec(testpki.CRLSpec{})), ca.Cert)
		if plain == nil || plain.IDP != nil {
			t.Errorf("IDP of a CRL without the extension = %v, want nil", plain)
		}
	})

	t.Run("entry reasons", func(t *testing.T) {
		at := crlTNow.Add(-36 * time.Hour)
		der := ca.CRL(t, spec(testpki.CRLSpec{Entries: []testpki.CRLEntry{
			{Serial: big.NewInt(1), RevokedAt: at, Reason: 1},
			{Serial: big.NewInt(0x0102), RevokedAt: at, Reason: 6},
			{Serial: big.NewInt(3), RevokedAt: at, NoReason: true},
			{Serial: big.NewInt(4), RevokedAt: at, Reason: 0},
			{Serial: new(big.Int).SetBytes(bytes.Repeat([]byte{0x7f}, 20)), RevokedAt: at, Reason: 4},
		}}))
		p, st, err := ParseCRL(der, ca.Cert)
		if st != StatusGood || err != nil {
			t.Fatalf("ParseCRL = %s, %v, want good", st, err)
		}
		want := map[string]CRLRecord{
			"1":                      {RevokedAt: at, Reason: 1},
			"102":                    {RevokedAt: at, Reason: 6},
			"3":                      {RevokedAt: at, Reason: -1},
			"4":                      {RevokedAt: at, Reason: 0},
			strings.Repeat("7f", 20): {RevokedAt: at, Reason: 4},
		}
		if len(p.Listed) != len(want) {
			t.Errorf("Listed has %d entries, want %d", len(p.Listed), len(want))
		}
		wantCost := int64(crlCostBase)
		for k := range want {
			wantCost += crlCostEntry + int64(len(k))
		}
		if p.Cost != wantCost {
			t.Errorf("Cost = %d, want %d", p.Cost, wantCost)
		}
		for k, w := range want {
			g, ok := p.Listed[k]
			if !ok || !g.RevokedAt.Equal(w.RevokedAt) || g.Reason != w.Reason {
				t.Errorf("Listed[%s] = %+v (present %v), want %+v", k, g, ok, w)
			}
		}
	})
}

// crlTECDSAAlgID is the ecdsa-with-SHA256 AlgorithmIdentifier testpki uses
// for its (P-256) CA keys.
var crlTECDSAAlgID = crlTSeq(crlTDER(cbasn1.OBJECT_IDENTIFIER, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02}))

// crlTSign wraps tbs into a CertificateList signed with key (ECDSA P-256,
// SHA-256); corrupt flips the last signature byte.
func crlTSign(t testing.TB, key crypto.Signer, tbs []byte, corrupt bool) []byte {
	t.Helper()
	h := sha256.Sum256(tbs)
	sig, err := key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if corrupt {
		sig[len(sig)-1] ^= 0xff
	}
	return crlTSeq(tbs, crlTECDSAAlgID, crlTDER(cbasn1.BIT_STRING, append([]byte{0}, sig...)))
}

// crlTSHA1 returns an empty CRL issued by ca and signed with ecdsa-with-SHA1,
// which x509.RevocationList.CheckSignatureFrom accepts.
func crlTSHA1(t testing.TB, ca *testpki.CA) []byte {
	t.Helper()
	algID := crlTSeq(crlTDER(cbasn1.OBJECT_IDENTIFIER, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01}))
	utc := func(tm time.Time) []byte { return crlTDER(cbasn1.UTCTime, []byte(tm.UTC().Format("060102150405Z"))) }
	tbs := crlTSeq(crlTDER(cbasn1.INTEGER, []byte{1}), algID, ca.Cert.RawSubject, utc(crlTNow.Add(-time.Hour)), utc(crlTNow.Add(time.Hour)))
	h := sha1.Sum(tbs)
	sig, err := ca.Key.Sign(rand.Reader, h[:], crypto.SHA1)
	if err != nil {
		t.Fatal(err)
	}
	der := crlTSeq(tbs, algID, crlTDER(cbasn1.BIT_STRING, append([]byte{0}, sig...)))
	rl, err := x509.ParseRevocationList(der)
	if err != nil || rl.CheckSignatureFrom(ca.Cert) != nil {
		t.Fatalf("SHA-1 CRL: parse %v, want a CRL x509 accepts", err)
	}
	return der
}

// crlTDense returns a CRL issued by ca that lists n distinct serials of
// serialLen (>= 5) bytes, with a reasonCode when withReason, valid around
// crlTNow.
func crlTDense(t testing.TB, ca *testpki.CA, n, serialLen int, withReason, corrupt bool) []byte {
	t.Helper()
	utc := func(tm time.Time) []byte { return []byte(tm.UTC().Format("060102150405Z")) }
	reason := crlTSeq(crlTSeq(crlTDER(cbasn1.OBJECT_IDENTIFIER, []byte{0x55, 0x1d, 0x15}),
		crlTDER(cbasn1.OCTET_STRING, crlTDER(cbasn1.ENUM, []byte{1}))))
	number := crlTSeq(crlTDER(cbasn1.OBJECT_IDENTIFIER, []byte{0x55, 0x1d, 0x14}), crlTDER(cbasn1.OCTET_STRING, crlTDER(cbasn1.INTEGER, []byte{1})))
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddBytes(crlTECDSAAlgID)
		b.AddBytes(ca.Cert.RawSubject)
		b.AddASN1(cbasn1.UTCTime, func(b *cryptobyte.Builder) { b.AddBytes(utc(crlTNow.Add(-time.Hour))) })
		b.AddASN1(cbasn1.UTCTime, func(b *cryptobyte.Builder) { b.AddBytes(utc(crlTNow.Add(24 * time.Hour))) })
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			serial := make([]byte, serialLen)
			serial[0] = 0x40 // positive, minimal
			at := utc(crlTNow.Add(-48 * time.Hour))
			for i := range n {
				binary.BigEndian.PutUint32(serial[serialLen-4:], uint32(i))
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) { b.AddBytes(serial) })
					b.AddASN1(cbasn1.UTCTime, func(b *cryptobyte.Builder) { b.AddBytes(at) })
					if withReason {
						b.AddBytes(reason)
					}
				})
			}
		})
		b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(number) })
		})
	})
	return crlTSign(t, ca.Key, b.BytesOrPanic(), corrupt)
}

// TestParseCRLDenseBadSignature: an unauthenticated CRL near the size cap
// costs one signature check, not one allocation per entry.
func TestParseCRLDenseBadSignature(t *testing.T) {
	ca := testpki.NewRoot(t, "crlT dense ca", testpki.CertSpec{Now: crlTNow})
	der := crlTDense(t, ca, 1_000_000, 5, false, true)
	if len(der) > MaxCRLResponse {
		t.Fatalf("dense CRL is %d bytes, want within MaxCRLResponse", len(der))
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	p, st, err := ParseCRL(der, ca.Cert)
	runtime.ReadMemStats(&after)
	if st != StatusInvalidEvidence || err == nil || p != nil {
		t.Fatalf("ParseCRL = %v, %s, %v, want invalid_evidence", p, st, err)
	}
	got := after.TotalAlloc - before.TotalAlloc
	if got > 4<<20 {
		t.Errorf("ParseCRL of a %d-byte CRL with a bad signature allocated %d bytes, want at most 4 MiB", len(der), got)
	}
	t.Logf("%d-byte CRL with a bad signature: %d bytes allocated", len(der), got)
}

func TestSerialKey(t *testing.T) {
	cases := []struct {
		in   *big.Int
		want string
	}{
		{big.NewInt(0), "0"},
		{big.NewInt(1), "1"},
		{big.NewInt(0x0a0b), "a0b"},
		{new(big.Int).SetBytes([]byte{0x00, 0xff, 0x01}), "ff01"},
	}
	for _, c := range cases {
		if got := SerialKey(c.in); got != c.want {
			t.Errorf("SerialKey(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEvaluateCRL(t *testing.T) {
	now := crlTNow
	root := testpki.NewRoot(t, "crlT eval root", testpki.CertSpec{Now: now})
	const crlURI = "http://crl.example.es/root.crl"
	dirName := testpki.Name{testpki.Printable(testpki.OIDCountry, "ES"), testpki.UTF8(testpki.OIDCommonName, "CRL1")}
	otherDir := testpki.Name{testpki.Printable(testpki.OIDCountry, "ES"), testpki.UTF8(testpki.OIDCommonName, "CRL2")}
	cdp := []testpki.DistributionPoint{{URIs: []string{crlURI}, DirNames: []testpki.Name{dirName}}}
	leaf := root.Leaf(t, testpki.CertSpec{Now: now, Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "crlT eval leaf")}, CDP: cdp})
	sub := root.Intermediate(t, "crlT eval sub", testpki.CertSpec{Now: now, CDP: cdp})
	dpOf := func(c *x509.Certificate) DistributionPoint {
		dps, err := ParseCRLDistributionPoints(c)
		if err != nil || len(dps) != 1 {
			t.Fatalf("ParseCRLDistributionPoints = %s, %v, want one DP", crlTDPString(dps), err)
		}
		return dps[0]
	}
	leafDP, subDP := dpOf(leaf.Cert), dpOf(sub.Cert)
	revokedAt := now.Add(-48 * time.Hour)
	listed := func(c *x509.Certificate, reason int) []testpki.CRLEntry {
		return []testpki.CRLEntry{{Serial: c.SerialNumber, RevokedAt: revokedAt, Reason: reason}}
	}
	none := CRLRecord{}

	cases := []struct {
		name    string
		spec    testpki.CRLSpec
		ca      bool // check sub with ScopeCA instead of leaf with ScopeLeaf
		want    Status
		wantRec CRLRecord
	}{
		{name: "good", want: StatusGood},
		{name: "listed", spec: testpki.CRLSpec{Entries: listed(leaf.Cert, 1)}, want: StatusRevoked, wantRec: CRLRecord{RevokedAt: revokedAt, Reason: 1}},
		{name: "certificate hold", spec: testpki.CRLSpec{Entries: listed(leaf.Cert, 6)}, want: StatusRevoked, wantRec: CRLRecord{RevokedAt: revokedAt, Reason: 6}},
		{name: "listed without reason", spec: testpki.CRLSpec{Entries: []testpki.CRLEntry{{Serial: leaf.Cert.SerialNumber, RevokedAt: revokedAt, NoReason: true}}},
			want: StatusRevoked, wantRec: CRLRecord{RevokedAt: revokedAt, Reason: -1}},
		{name: "other serial listed", spec: testpki.CRLSpec{Entries: listed(sub.Cert, 1)}, want: StatusGood},
		{name: "next update past", spec: testpki.CRLSpec{ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Minute)}, want: StatusStale},
		{name: "next update past and listed", spec: testpki.CRLSpec{ThisUpdate: now.Add(-48 * time.Hour), NextUpdate: now.Add(-time.Minute), Entries: listed(leaf.Cert, 1)}, want: StatusStale},
		{name: "no next update", spec: testpki.CRLSpec{NoNextUpdate: true}, want: StatusStale},
		{name: "this update now+6m", spec: testpki.CRLSpec{ThisUpdate: now.Add(6 * time.Minute)}, want: StatusStale},
		{name: "this update now+4m", spec: testpki.CRLSpec{ThisUpdate: now.Add(4 * time.Minute)}, want: StatusGood},
		{name: "idp uri match", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}}}, want: StatusGood},
		{name: "idp uri match and listed", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}}, Entries: listed(leaf.Cert, 1)},
			want: StatusRevoked, wantRec: CRLRecord{RevokedAt: revokedAt, Reason: 1}},
		{name: "idp dirname match", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/elsewhere.crl"}, DirNames: []testpki.Name{dirName}}}, want: StatusGood},
		{name: "idp fnmt partition shape", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, DirNames: []testpki.Name{dirName}, DirNamesFirst: true, OnlyUser: true}}, want: StatusGood},
		{name: "idp mismatch", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, DirNames: []testpki.Name{otherDir}}}, want: StatusInvalidEvidence},
		{name: "idp mismatch and listed", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}}, Entries: listed(leaf.Cert, 1)}, want: StatusInvalidEvidence},
		{name: "idp uri differs only in case", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://CRL.example.es/root.crl"}}}, want: StatusInvalidEvidence},
		{name: "idp relative name", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{RelativeName: testpki.RDN{{OID: testpki.OIDCommonName, Value: "CRL1"}}}}, want: StatusUnsupportedMethod},
		{name: "idp flags without name", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{OnlyUser: true}}, want: StatusGood},
		{name: "leaf with only ca", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyCA: true}}, want: StatusUnsupportedMethod},
		{name: "leaf with only user", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyUser: true}}, want: StatusGood},
		{name: "ca with only ca", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyCA: true}}, ca: true, want: StatusGood},
		{name: "ca with only ca listed", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyCA: true}, Entries: listed(sub.Cert, 2)}, ca: true,
			want: StatusRevoked, wantRec: CRLRecord{RevokedAt: revokedAt, Reason: 2}},
		{name: "ca with only user", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyUser: true}}, ca: true, want: StatusUnsupportedMethod},
		{name: "ca without idp", ca: true, want: StatusGood},
		{name: "indirect", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, Indirect: true}}, want: StatusUnsupportedMethod},
		{name: "only some reasons", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlySomeReasons: true}}, want: StatusUnsupportedMethod},
		{name: "only attribute certs", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyAttr: true}}, want: StatusUnsupportedMethod},
		{name: "ca indirect", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyCA: true, Indirect: true}}, ca: true, want: StatusUnsupportedMethod},
		{name: "non-critical idp match", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, NonCritical: true}}, want: StatusGood},
		{name: "non-critical idp mismatch", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, NonCritical: true}}, want: StatusInvalidEvidence},
		{name: "non-critical idp only ca for a leaf", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{crlURI}, OnlyCA: true, NonCritical: true}}, want: StatusUnsupportedMethod},
		{name: "non-critical idp relative name", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{RelativeName: testpki.RDN{{OID: testpki.OIDCommonName, Value: "CRL1"}}, NonCritical: true}}, want: StatusUnsupportedMethod},
		// A CRL of another DP is invalid evidence whatever its scope flags.
		{name: "idp mismatch with only user for a ca", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, OnlyUser: true}}, ca: true, want: StatusInvalidEvidence},
		{name: "idp mismatch with only ca for a leaf", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, OnlyCA: true}}, want: StatusInvalidEvidence},
		{name: "idp mismatch with indirect", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, Indirect: true}}, want: StatusInvalidEvidence},
		{name: "idp mismatch with only some reasons for a ca", spec: testpki.CRLSpec{IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}, OnlySomeReasons: true}}, ca: true, want: StatusInvalidEvidence},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.spec.Now = now
			der := root.CRL(t, c.spec)
			p, st, err := ParseCRL(der, root.Cert)
			if st != StatusGood || err != nil {
				t.Fatalf("ParseCRL = %s, %v, want good", st, err)
			}
			cert, dp, scope := leaf.Cert, leafDP, ScopeLeaf
			if c.ca {
				cert, dp, scope = sub.Cert, subDP, ScopeCA
			}
			got, rec, detail := EvaluateCRL(p, cert, dp, scope, now)
			if got != c.want {
				t.Errorf("EvaluateCRL = %s (%s), want %s", got, detail, c.want)
			}
			if !rec.RevokedAt.Equal(c.wantRec.RevokedAt) || (c.want == StatusRevoked && rec.Reason != c.wantRec.Reason) ||
				(c.want != StatusRevoked && rec != none) {
				t.Errorf("EvaluateCRL record = %+v, want %+v", rec, c.wantRec)
			}
			if detail == "" {
				t.Error("EvaluateCRL detail is empty")
			}
		})
	}
}

// crlTEvalFixture is a root, a leaf it issued and the leaf's single DP.
func crlTEvalFixture(t *testing.T) (*testpki.CA, *x509.Certificate, DistributionPoint) {
	t.Helper()
	root := testpki.NewRoot(t, "crlT fixture root", testpki.CertSpec{Now: crlTNow})
	leaf := root.Leaf(t, testpki.CertSpec{Now: crlTNow, Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "crlT fixture leaf")},
		CDP: []testpki.DistributionPoint{{URIs: []string{"http://crl.example.es/root.crl"}}}})
	dps, err := ParseCRLDistributionPoints(leaf.Cert)
	if err != nil || len(dps) != 1 {
		t.Fatalf("ParseCRLDistributionPoints = %s, %v, want one DP", crlTDPString(dps), err)
	}
	return root, leaf.Cert, dps[0]
}

// crlTEvaluate parses der against root (want good) and evaluates it for leaf.
func crlTEvaluate(t *testing.T, der []byte, root *testpki.CA, leaf *x509.Certificate, dp DistributionPoint) (Status, CRLRecord, string) {
	t.Helper()
	p, st, err := ParseCRL(der, root.Cert)
	if st != StatusGood || err != nil {
		t.Fatalf("ParseCRL = %s, %v, want good", st, err)
	}
	return EvaluateCRL(p, leaf, dp, ScopeLeaf, crlTNow)
}

func TestEvaluateCRLZeroThisUpdate(t *testing.T) {
	root, leaf, dp := crlTEvalFixture(t)
	zero := crlTDER(cbasn1.GeneralizedTime, []byte("00010101000000Z"))
	next := crlTDER(cbasn1.UTCTime, []byte(crlTNow.Add(time.Hour).UTC().Format("060102150405Z")))
	der := crlTSign(t, root.Key, crlTSeq(crlTDER(cbasn1.INTEGER, []byte{1}), crlTECDSAAlgID, root.Cert.RawSubject, zero, next), false)
	if got, _, detail := crlTEvaluate(t, der, root, leaf, dp); got != StatusInvalidEvidence {
		t.Errorf("EvaluateCRL with thisUpdate 00010101000000Z = %s (%s), want invalid_evidence", got, detail)
	}
}

func TestEvaluateCRLInvertedUpdateInterval(t *testing.T) {
	root, leaf, dp := crlTEvalFixture(t)
	cases := []struct {
		name                   string
		thisUpdate, nextUpdate time.Time
		want                   Status
	}{
		{"next update before this update", crlTNow.Add(4 * time.Minute), crlTNow.Add(2 * time.Minute), StatusInvalidEvidence},
		{"next update equal to this update", crlTNow.Add(time.Minute), crlTNow.Add(time.Minute), StatusGood},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			der := root.CRL(t, testpki.CRLSpec{Now: crlTNow, ThisUpdate: c.thisUpdate, NextUpdate: c.nextUpdate})
			if got, _, detail := crlTEvaluate(t, der, root, leaf, dp); got != c.want {
				t.Errorf("EvaluateCRL = %s (%s), want %s", got, detail, c.want)
			}
		})
	}
}

func TestParseCRLDuplicateIDP(t *testing.T) {
	root, _, _ := crlTEvalFixture(t)
	idp := func(s testpki.IDPSpec) pkix.Extension {
		return pkix.Extension{Id: oidExtIssuingDistPoint, Critical: true, Value: testpki.EncodeIDP(s)}
	}
	cases := []struct {
		name  string
		extra []pkix.Extension
	}{
		{"second idp naming another dp", []pkix.Extension{idp(testpki.IDPSpec{URIs: []string{"http://crl.example.es/other.crl"}})}},
		{"second idp widening the scope", []pkix.Extension{idp(testpki.IDPSpec{})}},
		{"second crl number", []pkix.Extension{{Id: oidExtCRLNumber, Value: []byte{0x02, 0x01, 0x07}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			der := root.CRL(t, testpki.CRLSpec{Now: crlTNow, IDP: &testpki.IDPSpec{URIs: []string{"http://crl.example.es/root.crl"}, OnlyUser: true}, ExtraExtensions: c.extra})
			if p, st, err := ParseCRL(der, root.Cert); st != StatusInvalidEvidence || err == nil || p != nil {
				t.Errorf("ParseCRL = %v, %s, %v, want invalid_evidence", p, st, err)
			}
		})
	}
}

func TestParseCRLDuplicateSerial(t *testing.T) {
	root, leaf, dp := crlTEvalFixture(t)
	at := crlTNow.Add(-time.Hour)
	der := root.CRL(t, testpki.CRLSpec{Now: crlTNow, Entries: []testpki.CRLEntry{
		{Serial: leaf.SerialNumber, RevokedAt: at, Reason: 1},
		{Serial: big.NewInt(99), RevokedAt: at, Reason: 1},
		{Serial: leaf.SerialNumber, RevokedAt: at, Reason: 4},
	}})
	if got, rec, detail := crlTEvaluate(t, der, root, leaf, dp); got != StatusRevoked || !rec.RevokedAt.Equal(at) {
		t.Errorf("EvaluateCRL = %s %+v (%s), want revoked at %v", got, rec, detail, at)
	}
}

// TestParseCRLRemoveFromCRL pins today's behaviour: removeFromCRL (8) only
// has a meaning in a delta CRL, which is unsupported; in a complete CRL the
// serial is listed, so it is revoked.
func TestParseCRLRemoveFromCRL(t *testing.T) {
	root, leaf, dp := crlTEvalFixture(t)
	at := crlTNow.Add(-time.Hour)
	der := root.CRL(t, testpki.CRLSpec{Now: crlTNow, Entries: []testpki.CRLEntry{{Serial: leaf.SerialNumber, RevokedAt: at, Reason: 8}}})
	if got, rec, detail := crlTEvaluate(t, der, root, leaf, dp); got != StatusRevoked || rec.Reason != 8 {
		t.Errorf("EvaluateCRL = %s %+v (%s), want revoked with reason 8", got, rec, detail)
	}
}

func TestParseCRLCriticalEntryExtensions(t *testing.T) {
	root, leaf, _ := crlTEvalFixture(t)
	gt := func(s string) []byte { return crlTDER(cbasn1.GeneralizedTime, []byte(s)) }
	invalidity := func(critical bool, value []byte) pkix.Extension {
		return pkix.Extension{Id: oidEntryInvalidityDate, Critical: critical, Value: value}
	}
	cases := []struct {
		name string
		ext  pkix.Extension
		want Status
	}{
		{"unknown critical", pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 8}, Critical: true, Value: []byte{0x05, 0x00}}, StatusUnsupportedMethod},
		{"critical invalidity date", invalidity(true, gt("20261029120000Z")), StatusGood},
		{"critical invalidity date as UTCTime", invalidity(true, crlTDER(cbasn1.UTCTime, []byte("261029120000Z"))), StatusInvalidEvidence},
		{"critical invalidity date with trailing data", invalidity(true, append(gt("20261029120000Z"), 0x00)), StatusInvalidEvidence},
		{"critical invalidity date not a time", invalidity(true, []byte{0x05, 0x00}), StatusInvalidEvidence},
		{"critical invalidity date empty", invalidity(true, nil), StatusInvalidEvidence},
		{"non-critical malformed invalidity date ignored", invalidity(false, []byte{0x05, 0x00}), StatusGood},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			der := root.CRL(t, testpki.CRLSpec{Now: crlTNow, Entries: []testpki.CRLEntry{
				{Serial: leaf.SerialNumber, RevokedAt: crlTNow.Add(-time.Hour), Reason: 1, Extensions: []pkix.Extension{c.ext}}}})
			if p, st, err := ParseCRL(der, root.Cert); st != c.want || (st == StatusGood) != (err == nil && p != nil) {
				t.Errorf("ParseCRL = %v, %s, %v, want %s", p, st, err, c.want)
			}
		})
	}
}

func TestRealCRLs(t *testing.T) {
	cases := []struct {
		name, crl, cert, issuer, url string
		scope                        Scope
		want                         Status
	}{
		{"dnie arl", "dnie-arl.crl", "ac-dnie-004.pem", "ac-raiz-dnie-2.pem", "http://pki.policia.es/dnie/crls/ARL.crl", ScopeCA, StatusGood},
		{"dnie arl for a leaf scope", "dnie-arl.crl", "ac-dnie-004.pem", "ac-raiz-dnie-2.pem", "http://pki.policia.es/dnie/crls/ARL.crl", ScopeLeaf, StatusUnsupportedMethod},
		// Unscoped IDP, no entries: good for a CA, which is why a CA-scope
		// check also consults ARL.crl (Checker.checkCRL).
		{"dnie root crl for a CA", "dnie-crl.crl", "ac-dnie-005.pem", "ac-raiz-dnie-2.pem", "http://pki.policia.es/dnie/crls/CRL.crl", ScopeCA, StatusGood},
		{"aoc root crl", "aoc-caroot-a.crl", "aoc-subca-ciutadania-g3-a2.pem", "aoc-g3-root-a.pem", "http://epscd.aoc.cat/crl/caroot-a.crl", ScopeCA, StatusGood},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			der := crlTReadFile(t, c.crl)
			cert := crlTReadCert(t, c.cert)
			issuer := crlTReadCert(t, c.issuer)
			p, st, err := ParseCRL(der, issuer)
			if st != StatusGood || err != nil {
				t.Fatalf("ParseCRL(%s) = %s, %v, want good", c.crl, st, err)
			}
			dps, err := ParseCRLDistributionPoints(cert)
			if err != nil {
				t.Fatalf("ParseCRLDistributionPoints(%s) error = %v", c.cert, err)
			}
			usable := usableDistributionPoints(dps, issuer)
			i := slices.IndexFunc(usable, func(dp DistributionPoint) bool {
				return slices.ContainsFunc(dp.FullName, func(g GeneralName) bool { u, ok := g.URI(); return ok && u == c.url })
			})
			if i < 0 {
				t.Fatalf("no usable DP of %s names %s: %s", c.cert, c.url, crlTDPString(usable))
			}
			got, _, detail := EvaluateCRL(p, cert, usable[i], c.scope, crlTNow)
			if got != c.want {
				t.Errorf("EvaluateCRL(%s, %s) = %s (%s), want %s", c.crl, c.cert, got, detail, c.want)
			}
		})
	}

	t.Run("dnie arl idp", func(t *testing.T) {
		p, st, err := ParseCRL(crlTReadFile(t, "dnie-arl.crl"), crlTReadCert(t, "ac-raiz-dnie-2.pem"))
		if st != StatusGood || err != nil {
			t.Fatalf("ParseCRL = %s, %v", st, err)
		}
		if p.IDP == nil {
			t.Fatal("IDP = nil, want the critical ARL IDP")
		}
		want := "{full:[uri:http://pki.policia.es/dnie/crls/ARL.crl uri:ldap://ldap.dnie.es/CN=CRL,CN=AC%20RAIZ%20DNIE%202,OU=DNIE," +
			"O=DIRECCION%20GENERAL%20DE%20LA%20POLICIA,C=ES?authorityRevocationList?base?objectclass=cRLDistributionPoint] " +
			"rel:false user:false ca:true reasons:false indirect:false attr:false}"
		if got := crlTIDPString(*p.IDP); got != want {
			t.Errorf("IDP\n got %s\nwant %s", got, want)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		_, st, err := ParseCRL(crlTReadFile(t, "dnie-arl.crl"), crlTReadCert(t, "aoc-g3-root-a.pem"))
		if st != StatusInvalidEvidence || err == nil {
			t.Errorf("ParseCRL with another issuer = %s, %v, want invalid_evidence", st, err)
		}
	})

	t.Run("sources", crlTCheckSources)
}

// crlTReadFile reads a file under testdata/crl.
func crlTReadFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(crlTDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// crlTReadCert reads a one-block PEM certificate under testdata/crl/certs.
func crlTReadCert(t testing.TB, name string) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(crlTReadFile(t, filepath.Join("certs", name)))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s: want exactly one PEM CERTIFICATE block", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// crlTCheckSources recomputes the SHA-256 of every file under testdata/crl
// and compares it with SOURCES.md; every file must be listed.
func crlTCheckSources(t *testing.T) {
	f, err := os.Open(filepath.Join(crlTDir, "SOURCES.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	listed := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 3 {
			t.Fatalf("SOURCES.md row %q: want 3 cells", line)
		}
		name, sum := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[2])
		if name == "file" {
			continue
		}
		listed[name] = sum
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(listed) == 0 {
		t.Fatal("SOURCES.md lists no files")
	}
	for name, want := range listed {
		s := sha256.Sum256(crlTReadFile(t, name))
		if got := hex.EncodeToString(s[:]); got != want {
			t.Errorf("sha256(%s) = %s, want %s (SOURCES.md)", name, got, want)
		}
	}
	err = filepath.WalkDir(crlTDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(crlTDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, ok := listed[rel]; !ok && rel != "SOURCES.md" {
			t.Errorf("%s is not listed in SOURCES.md", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
