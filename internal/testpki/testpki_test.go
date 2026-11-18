package testpki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // recomputing the ResponderID byKey hash
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

// Universal tags checked by the decoders below.
const (
	decTagUTF8      = 12
	decTagPrintable = 19
	decTagTeletex   = 20
	decTagIA5       = 22
	decTagGenTime   = 24
	decTagBMP       = 30
)

var (
	decOIDSHA1         = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	decOIDSHA256       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	decOIDOCSPBasic    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	decOIDOCSPNonce    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	decOIDECDSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	decOIDRSASHA256    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	decOIDKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 15}
	decOIDIDP          = asn1.ObjectIdentifier{2, 5, 29, 28}
	decOIDUnknownCrit  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	decTestNow         = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	decLeafSubject     = Name{Printable(OIDCountry, "ES"), UTF8(OIDCommonName, "testpki leaf")}
	decDirName         = Name{Printable(OIDCountry, "ES"), UTF8(OIDCommonName, "dir name")}
	decCRLURI          = "http://crl.example.test/ca.crl"
	decCRLLDAP         = "ldap://ldap.example.test/cn=CRL1?certificateRevocationList;binary"
	decOCSPURL         = "http://ocsp.example.test/"
	decCAIssuersURL    = "http://ca.example.test/ca.crt"
	decRawSANDNSName   = "raw.example.test"
	decDateOfBirthText = "19800101120000Z"
)

// decElements splits concatenated DER elements.
func decElements(t *testing.T, b []byte) []asn1.RawValue {
	t.Helper()
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			t.Fatalf("decode element: %v", err)
		}
		out = append(out, v)
		b = rest
	}
	return out
}

// decOne decodes exactly one DER element.
func decOne(t *testing.T, b []byte) asn1.RawValue {
	t.Helper()
	els := decElements(t, b)
	if len(els) != 1 {
		t.Fatalf("got %d elements, want 1", len(els))
	}
	return els[0]
}

func decExtension(t *testing.T, c *x509.Certificate, oid asn1.ObjectIdentifier) pkix.Extension {
	t.Helper()
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e
		}
	}
	t.Fatalf("extension %v not found", oid)
	return pkix.Extension{}
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oid) })
}

type decGeneralName struct {
	tag   int
	value []byte
}

func decGeneralNames(t *testing.T, b []byte) []decGeneralName {
	t.Helper()
	var out []decGeneralName
	for _, el := range decElements(t, b) {
		if el.Class != asn1.ClassContextSpecific {
			t.Fatalf("GeneralName class %d, want context-specific", el.Class)
		}
		out = append(out, decGeneralName{tag: el.Tag, value: el.Bytes})
	}
	return out
}

func equalGeneralNames(a, b []decGeneralName) bool {
	return slices.EqualFunc(a, b, func(x, y decGeneralName) bool {
		return x.tag == y.tag && bytes.Equal(x.value, y.value)
	})
}

func TestNameDER(t *testing.T) {
	ca := NewRoot(t, "name root", CertSpec{})
	name := Name{
		Printable(OIDCountry, "ES"),
		UTF8(OIDOrganizationalUnit, "dup"),
		UTF8(OIDOrganizationalUnit, "dup"),
		{
			{OID: OIDSurname, Value: "Multi", Tag: TagUTF8},
			{OID: OIDGivenName, Value: "Valued", Tag: TagPrintable},
		},
		Tagged(OIDTitle, TagTeletex, "Teletex"),
		Tagged(OIDEmailAddress, TagIA5, "ia5@example.test"),
		Tagged(OIDCommonName, TagBMP, "ÑÜ"),
		{{OID: OIDDescription, Value: "default tag"}},
	}
	leaf := ca.Leaf(t, CertSpec{Subject: name})

	if got, want := leaf.Cert.RawSubject, name.DER(); !bytes.Equal(got, want) {
		t.Fatalf("RawSubject = %x, want Name.DER() = %x", got, want)
	}

	type wantATV struct {
		oid   asn1.ObjectIdentifier
		tag   int
		value []byte
		text  string
	}
	want := [][]wantATV{
		{{OIDCountry, decTagPrintable, []byte("ES"), "ES"}},
		{{OIDOrganizationalUnit, decTagUTF8, []byte("dup"), "dup"}},
		{{OIDOrganizationalUnit, decTagUTF8, []byte("dup"), "dup"}},
		{
			{OIDSurname, decTagUTF8, []byte("Multi"), "Multi"},
			{OIDGivenName, decTagPrintable, []byte("Valued"), "Valued"},
		},
		{{OIDTitle, decTagTeletex, []byte("Teletex"), "Teletex"}},
		{{OIDEmailAddress, decTagIA5, []byte("ia5@example.test"), "ia5@example.test"}},
		{{OIDCommonName, decTagBMP, []byte{0x00, 0xd1, 0x00, 0xdc}, "ÑÜ"}},
		{{OIDDescription, decTagUTF8, []byte("default tag"), "default tag"}},
	}

	type atv struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	type atvSET []atv
	var rdns []atvSET
	if rest, err := asn1.Unmarshal(leaf.Cert.RawSubject, &rdns); err != nil || len(rest) > 0 {
		t.Fatalf("decode RawSubject: err=%v rest=%d", err, len(rest))
	}
	if len(rdns) != len(want) {
		t.Fatalf("got %d RDNs, want %d", len(rdns), len(want))
	}
	var wantTexts []string
	for i, rdn := range rdns {
		if len(rdn) != len(want[i]) {
			t.Fatalf("RDN %d: got %d attributes, want %d", i, len(rdn), len(want[i]))
		}
		for j, a := range rdn {
			w := want[i][j]
			if !a.Type.Equal(w.oid) || a.Value.Tag != w.tag || !bytes.Equal(a.Value.Bytes, w.value) {
				t.Errorf("RDN %d attr %d: got (%v, tag %d, %x), want (%v, tag %d, %x)",
					i, j, a.Type, a.Value.Tag, a.Value.Bytes, w.oid, w.tag, w.value)
			}
			wantTexts = append(wantTexts, w.text)
		}
	}

	// x509 decodes every attribute, in order, duplicates included.
	var gotTexts []string
	for _, n := range leaf.Cert.Subject.Names {
		s, ok := n.Value.(string)
		if !ok {
			t.Fatalf("attribute %v decoded as %T, want string", n.Type, n.Value)
		}
		gotTexts = append(gotTexts, s)
	}
	if !slices.Equal(gotTexts, wantTexts) {
		t.Errorf("x509 attribute values = %q, want %q", gotTexts, wantTexts)
	}
	if got, want := leaf.Cert.Subject.CommonName, "ÑÜ"; got != want {
		t.Errorf("BMPString CommonName = %q, want %q", got, want)
	}
}

func TestLeafExtensions(t *testing.T) {
	ca := NewRoot(t, "extensions root", CertSpec{})

	t.Run("policies", func(t *testing.T) {
		want := []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 5734, 3, 10, 1}, {0, 4, 0, 194112, 1, 0}}
		leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject, Policies: want})
		if len(leaf.Cert.Policies) != len(want) {
			t.Fatalf("got %d policies, want %d", len(leaf.Cert.Policies), len(want))
		}
		for i, p := range leaf.Cert.Policies {
			if !p.EqualASN1OID(want[i]) {
				t.Errorf("policy %d = %v, want %v", i, p, want[i])
			}
		}
	})

	t.Run("aia", func(t *testing.T) {
		leaf := ca.Leaf(t, CertSpec{
			Subject:     decLeafSubject,
			OCSPServers: []string{decOCSPURL},
			CAIssuers:   []string{decCAIssuersURL},
		})
		if got, want := leaf.Cert.OCSPServer, []string{decOCSPURL}; !slices.Equal(got, want) {
			t.Errorf("OCSPServer = %q, want %q", got, want)
		}
		if got, want := leaf.Cert.IssuingCertificateURL, []string{decCAIssuersURL}; !slices.Equal(got, want) {
			t.Errorf("IssuingCertificateURL = %q, want %q", got, want)
		}
	})

	cdpCases := []struct {
		name     string
		dirFirst bool
		want     []decGeneralName
	}{
		{
			name: "cdp uris then dirname",
			want: []decGeneralName{{6, []byte(decCRLURI)}, {6, []byte(decCRLLDAP)}, {4, decDirName.DER()}},
		},
		{
			name:     "cdp dirnames first",
			dirFirst: true,
			want:     []decGeneralName{{4, decDirName.DER()}, {6, []byte(decCRLURI)}, {6, []byte(decCRLLDAP)}},
		},
	}
	for _, tc := range cdpCases {
		t.Run(tc.name, func(t *testing.T) {
			second := DistributionPoint{URIs: []string{"http://crl2.example.test/b.crl"}}
			leaf := ca.Leaf(t, CertSpec{
				Subject: decLeafSubject,
				CDP: []DistributionPoint{
					{URIs: []string{decCRLURI, decCRLLDAP}, DirNames: []Name{decDirName}, DirNamesFirst: tc.dirFirst},
					second,
				},
			})
			ext := decExtension(t, leaf.Cert, OIDExtCRLDistPoints)
			dps := decElements(t, decOne(t, ext.Value).Bytes)
			if len(dps) != 2 {
				t.Fatalf("got %d distribution points, want 2", len(dps))
			}
			var got [][]decGeneralName
			for _, dp := range dps {
				dpName := decOne(t, dp.Bytes)
				if dpName.Class != asn1.ClassContextSpecific || dpName.Tag != 0 || !dpName.IsCompound {
					t.Fatalf("distributionPoint tag = (%d,%d,%v), want [0] constructed", dpName.Class, dpName.Tag, dpName.IsCompound)
				}
				full := decOne(t, dpName.Bytes)
				if full.Class != asn1.ClassContextSpecific || full.Tag != 0 || !full.IsCompound {
					t.Fatalf("fullName tag = (%d,%d,%v), want [0] constructed", full.Class, full.Tag, full.IsCompound)
				}
				got = append(got, decGeneralNames(t, full.Bytes))
			}
			if !equalGeneralNames(got[0], tc.want) {
				t.Errorf("DP 1 names = %v, want %v", got[0], tc.want)
			}
			if want := []decGeneralName{{6, []byte(second.URIs[0])}}; !equalGeneralNames(got[1], want) {
				t.Errorf("DP 2 names = %v, want %v", got[1], want)
			}
			if !tc.dirFirst {
				want := []string{decCRLURI, decCRLLDAP, second.URIs[0]}
				if got := leaf.Cert.CRLDistributionPoints; !slices.Equal(got, want) {
					t.Errorf("CRLDistributionPoints = %q, want %q", got, want)
				}
			}
		})
	}

	t.Run("san rfc822 and dirname", func(t *testing.T) {
		email := "person@example.test"
		leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject, SANEmails: []string{email}, SANDirNames: []Name{decDirName}})
		if got, want := leaf.Cert.EmailAddresses, []string{email}; !slices.Equal(got, want) {
			t.Errorf("EmailAddresses = %q, want %q", got, want)
		}
		ext := decExtension(t, leaf.Cert, OIDExtSubjectAltName)
		got := decGeneralNames(t, decOne(t, ext.Value).Bytes)
		if want := []decGeneralName{{1, []byte(email)}, {4, decDirName.DER()}}; !equalGeneralNames(got, want) {
			t.Errorf("SAN names = %v, want %v", got, want)
		}
	})

	t.Run("sda dateOfBirth", func(t *testing.T) {
		leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject, DateOfBirth: decDateOfBirthText})
		ext := decExtension(t, leaf.Cert, OIDExtSubjectDirAttrs)
		if ext.Critical {
			t.Error("SDA critical = true, want false")
		}
		type attribute struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		var attrs []attribute
		if rest, err := asn1.Unmarshal(ext.Value, &attrs); err != nil || len(rest) > 0 {
			t.Fatalf("decode SDA: err=%v rest=%d", err, len(rest))
		}
		if len(attrs) != 1 || !attrs[0].Type.Equal(OIDAttrDateOfBirth) || len(attrs[0].Values) != 1 {
			t.Fatalf("SDA = %+v, want one dateOfBirth attribute with one value", attrs)
		}
		v := attrs[0].Values[0]
		if v.Tag != decTagGenTime || string(v.Bytes) != decDateOfBirthText {
			t.Errorf("dateOfBirth = (tag %d, %q), want (tag %d, %q)", v.Tag, v.Bytes, decTagGenTime, decDateOfBirthText)
		}
		if got, want := ext.Value, DateOfBirthSDA(decDateOfBirthText); !bytes.Equal(got, want) {
			t.Errorf("SDA value = %x, want DateOfBirthSDA = %x", got, want)
		}
	})

	t.Run("san raw override", func(t *testing.T) {
		raw, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(decRawSANDNSName)}})
		if err != nil {
			t.Fatal(err)
		}
		leaf := ca.Leaf(t, CertSpec{
			Subject:     decLeafSubject,
			SANRaw:      raw,
			SANEmails:   []string{"ignored@example.test"},
			SANDirNames: []Name{decDirName},
		})
		if got := decExtension(t, leaf.Cert, OIDExtSubjectAltName).Value; !bytes.Equal(got, raw) {
			t.Errorf("SAN value = %x, want SANRaw %x", got, raw)
		}
		if got, want := leaf.Cert.DNSNames, []string{decRawSANDNSName}; !slices.Equal(got, want) {
			t.Errorf("DNSNames = %q, want %q", got, want)
		}
		if len(leaf.Cert.EmailAddresses) != 0 {
			t.Errorf("EmailAddresses = %q, want none", leaf.Cert.EmailAddresses)
		}
	})

	t.Run("sda raw override", func(t *testing.T) {
		raw, err := asn1.Marshal([]struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}{{
			Type:   OIDAttrCountryOfResidence,
			Values: []asn1.RawValue{{Class: asn1.ClassUniversal, Tag: asn1.TagPrintableString, Bytes: []byte("ES")}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject, SDARaw: raw, DateOfBirth: decDateOfBirthText})
		if got := decExtension(t, leaf.Cert, OIDExtSubjectDirAttrs).Value; !bytes.Equal(got, raw) {
			t.Errorf("SDA value = %x, want SDARaw %x", got, raw)
		}
	})

	t.Run("extra extensions keep the critical bit", func(t *testing.T) {
		emptySeq := []byte{0x30, 0x00}
		leaf := ca.Leaf(t, CertSpec{
			Subject: decLeafSubject,
			ExtraExtensions: []pkix.Extension{
				{Id: OIDExtQCStatements, Critical: true, Value: emptySeq},
				{Id: decOIDUnknownCrit, Critical: true, Value: emptySeq},
			},
		})
		for _, oid := range []asn1.ObjectIdentifier{OIDExtQCStatements, decOIDUnknownCrit} {
			if !decExtension(t, leaf.Cert, oid).Critical {
				t.Errorf("extension %v critical = false, want true", oid)
			}
			if !slices.ContainsFunc(leaf.Cert.UnhandledCriticalExtensions, oid.Equal) {
				t.Errorf("UnhandledCriticalExtensions = %v, want it to list %v", leaf.Cert.UnhandledCriticalExtensions, oid)
			}
		}
	})

	pathLenCases := []struct {
		name     string
		pathLen  *int
		wantMax  int
		wantZero bool
	}{
		{"pathlen nil", nil, -1, false},
		{"pathlen 0", new(0), 0, true},
		{"pathlen 1", new(1), 1, false},
	}
	for _, tc := range pathLenCases {
		t.Run(tc.name, func(t *testing.T) {
			sub := ca.Intermediate(t, "sub "+tc.name, CertSpec{PathLen: tc.pathLen})
			if !sub.Cert.IsCA || !sub.Cert.BasicConstraintsValid {
				t.Fatalf("IsCA=%v BasicConstraintsValid=%v, want true, true", sub.Cert.IsCA, sub.Cert.BasicConstraintsValid)
			}
			if sub.Cert.MaxPathLen != tc.wantMax || sub.Cert.MaxPathLenZero != tc.wantZero {
				t.Errorf("MaxPathLen=%d MaxPathLenZero=%v, want %d, %v",
					sub.Cert.MaxPathLen, sub.Cert.MaxPathLenZero, tc.wantMax, tc.wantZero)
			}
		})
	}

	t.Run("key usage defaults and NoKeyUsage", func(t *testing.T) {
		if got, want := ca.Cert.KeyUsage, x509.KeyUsageCertSign|x509.KeyUsageCRLSign; got != want {
			t.Errorf("CA KeyUsage = %v, want %v", got, want)
		}
		leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject})
		if got, want := leaf.Cert.KeyUsage, x509.KeyUsageDigitalSignature; got != want {
			t.Errorf("leaf KeyUsage = %v, want %v", got, want)
		}
		bare := ca.Leaf(t, CertSpec{Subject: decLeafSubject, NoKeyUsage: true})
		if hasExtension(bare.Cert, decOIDKeyUsage) || bare.Cert.KeyUsage != 0 {
			t.Errorf("NoKeyUsage leaf: KeyUsage=%v, extension present=%v, want 0, false",
				bare.Cert.KeyUsage, hasExtension(bare.Cert, decOIDKeyUsage))
		}
	})
}

func TestWeakKeysAndSHA1(t *testing.T) {
	ecRoot := NewRoot(t, "weak ec root", CertSpec{})
	rsaRoot := NewRoot(t, "weak rsa root", CertSpec{Key: RSA2048})
	cases := []struct {
		name    string
		issuer  *CA
		spec    CertSpec
		wantRSA int            // RSA modulus bits, 0 for EC
		wantEC  elliptic.Curve // nil for RSA
		wantSig x509.SignatureAlgorithm
	}{
		{"rsa1024", ecRoot, CertSpec{Key: RSA1024}, 1024, nil, x509.ECDSAWithSHA256},
		{"rsa1920", ecRoot, CertSpec{Key: RSA1920}, 1920, nil, x509.ECDSAWithSHA256},
		{"ecdsa p224", ecRoot, CertSpec{Key: ECDSAP224}, 0, elliptic.P224(), x509.ECDSAWithSHA256},
		{"sha1 with rsa", rsaRoot, CertSpec{SignatureAlgorithm: x509.SHA1WithRSA}, 0, elliptic.P256(), x509.SHA1WithRSA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.spec.Subject = decLeafSubject
			leaf := tc.issuer.Leaf(t, tc.spec)
			reparsed, err := x509.ParseCertificate(leaf.Cert.Raw)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if reparsed.SignatureAlgorithm != tc.wantSig {
				t.Errorf("SignatureAlgorithm = %v, want %v", reparsed.SignatureAlgorithm, tc.wantSig)
			}
			switch pub := reparsed.PublicKey.(type) {
			case *rsa.PublicKey:
				if got := pub.N.BitLen(); got != tc.wantRSA {
					t.Errorf("RSA bits = %d, want %d", got, tc.wantRSA)
				}
			case *ecdsa.PublicKey:
				if pub.Curve != tc.wantEC {
					t.Errorf("curve = %s, want %v", pub.Curve.Params().Name, tc.wantEC)
				}
			default:
				t.Fatalf("public key type %T", pub)
			}
		})
	}
}

// Decoding structures for OCSP responses (RFC 6960), declared here so the
// test does not depend on any production parser.
type (
	decOCSPResponse struct {
		Status asn1.Enumerated
		Bytes  decResponseBytes `asn1:"explicit,tag:0,optional"`
	}
	decResponseBytes struct {
		Type     asn1.ObjectIdentifier
		Response []byte
	}
	decBasicResponse struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
		Certs     []asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}
	decResponseData struct {
		Version     int `asn1:"optional,default:0,explicit,tag:0"`
		ResponderID asn1.RawValue
		ProducedAt  time.Time `asn1:"generalized"`
		Responses   []decSingleResponse
		Extensions  []pkix.Extension `asn1:"explicit,tag:1,optional"`
	}
	decSingleResponse struct {
		CertID     decCertID
		CertStatus asn1.RawValue
		ThisUpdate time.Time        `asn1:"generalized"`
		NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
		Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
	}
	decCertID struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		NameHash      []byte
		KeyHash       []byte
		Serial        *big.Int
	}
	decOCSP struct {
		status asn1.Enumerated
		basic  decBasicResponse
		data   decResponseData
	}
)

func decodeOCSP(t *testing.T, der []byte) decOCSP {
	t.Helper()
	var out decOCSP
	var resp decOCSPResponse
	if rest, err := asn1.Unmarshal(der, &resp); err != nil || len(rest) > 0 {
		t.Fatalf("decode OCSPResponse: err=%v rest=%d", err, len(rest))
	}
	out.status = resp.Status
	if resp.Status != 0 {
		return out
	}
	if !resp.Bytes.Type.Equal(decOIDOCSPBasic) {
		t.Fatalf("responseType = %v, want %v", resp.Bytes.Type, decOIDOCSPBasic)
	}
	if rest, err := asn1.Unmarshal(resp.Bytes.Response, &out.basic); err != nil || len(rest) > 0 {
		t.Fatalf("decode BasicOCSPResponse: err=%v rest=%d", err, len(rest))
	}
	if rest, err := asn1.Unmarshal(out.basic.TBS.FullBytes, &out.data); err != nil || len(rest) > 0 {
		t.Fatalf("decode ResponseData: err=%v rest=%d", err, len(rest))
	}
	return out
}

func (d decOCSP) nonce() ([]byte, bool) {
	for _, e := range d.data.Extensions {
		if e.Id.Equal(decOIDOCSPNonce) {
			return e.Value, true
		}
	}
	return nil, false
}

// verify checks the BasicOCSPResponse signature with c's public key.
func (d decOCSP) verify(c *x509.Certificate) error {
	alg := x509.ECDSAWithSHA256
	if _, ok := c.PublicKey.(*rsa.PublicKey); ok {
		alg = x509.SHA256WithRSA
	}
	return c.CheckSignature(alg, d.basic.TBS.FullBytes, d.basic.Signature.RightAlign())
}

// decRevoked decodes RevokedInfo content: revocationTime and optional reason.
func decRevoked(t *testing.T, content []byte) (at time.Time, reason int, hasReason bool) {
	t.Helper()
	rest, err := asn1.UnmarshalWithParams(content, &at, "generalized")
	if err != nil {
		t.Fatalf("decode revocationTime: %v", err)
	}
	if len(rest) == 0 {
		return at, 0, false
	}
	var r asn1.Enumerated
	if rest, err = asn1.UnmarshalWithParams(rest, &r, "explicit,tag:0"); err != nil || len(rest) > 0 {
		t.Fatalf("decode revocationReason: err=%v rest=%d", err, len(rest))
	}
	return at, int(r), true
}

func TestOCSPResponseShapes(t *testing.T) {
	ca := NewRoot(t, "ocsp root", CertSpec{Now: decTestNow})
	rsaCA := NewRoot(t, "ocsp rsa root", CertSpec{Key: RSA2048, Now: decTestNow})
	leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject, Now: decTestNow})
	delegated := ca.OCSPResponder(t, CertSpec{Now: decTestNow})

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		t.Fatal(err)
	}
	nonce, err := asn1.Marshal(nonceBytes)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{HashAlgorithm: decOIDSHA1, Serial: leaf.Cert.SerialNumber, Nonce: nonce}
	reqNoNonce := Request{HashAlgorithm: decOIDSHA1, Serial: leaf.Cert.SerialNumber}
	reqSHA256 := Request{HashAlgorithm: decOIDSHA256, Serial: leaf.Cert.SerialNumber}
	thisUpdate := decTestNow.Add(-time.Minute)
	revokedAt := decTestNow.Add(-48 * time.Hour)
	wrongNonce := append([]byte{0x04, 0x20}, make([]byte, 32)...)

	cases := []struct {
		name   string
		issuer *CA
		req    Request
		spec   OCSPSpec
		check  func(t *testing.T, d decOCSP)
	}{
		{
			name: "good delegated defaults", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated},
			check: func(t *testing.T, d decOCSP) {
				s := d.data.Responses[0]
				if s.CertStatus.Class != asn1.ClassContextSpecific || s.CertStatus.Tag != 0 || s.CertStatus.IsCompound || len(s.CertStatus.Bytes) != 0 {
					t.Errorf("certStatus = %x, want [0] NULL (good)", s.CertStatus.FullBytes)
				}
				nameHash, keyHash := CertIDHashes(t, crypto.SHA1, ca.Cert)
				id := s.CertID
				if !id.HashAlgorithm.Algorithm.Equal(decOIDSHA1) || !bytes.Equal(id.NameHash, nameHash) ||
					!bytes.Equal(id.KeyHash, keyHash) || id.Serial.Cmp(leaf.Cert.SerialNumber) != 0 {
					t.Errorf("CertID = %+v, want SHA-1 hashes of the issuer and the leaf serial", id)
				}
				if !s.ThisUpdate.Equal(thisUpdate) || !d.data.ProducedAt.Equal(thisUpdate) {
					t.Errorf("thisUpdate=%v producedAt=%v, want both %v", s.ThisUpdate, d.data.ProducedAt, thisUpdate)
				}
				if !s.NextUpdate.IsZero() {
					t.Errorf("nextUpdate = %v, want absent", s.NextUpdate)
				}
				rid := d.data.ResponderID
				if rid.Tag != 1 || !rid.IsCompound || !bytes.Equal(rid.Bytes, delegated.Cert.RawSubject) {
					t.Errorf("ResponderID = %x, want byName [1] with the responder subject", rid.FullBytes)
				}
				if len(d.basic.Certs) != 1 || !bytes.Equal(d.basic.Certs[0].FullBytes, delegated.Cert.Raw) {
					t.Errorf("embedded certs = %d, want 1 (the delegated responder)", len(d.basic.Certs))
				}
				if !d.basic.Algorithm.Algorithm.Equal(decOIDECDSASHA256) {
					t.Errorf("signatureAlgorithm = %v, want %v", d.basic.Algorithm.Algorithm, decOIDECDSASHA256)
				}
				if err := d.verify(delegated.Cert); err != nil {
					t.Errorf("signature: %v", err)
				}
				if got, ok := d.nonce(); !ok || !bytes.Equal(got, nonce) {
					t.Errorf("nonce = %x (present %v), want echo %x", got, ok, nonce)
				}
			},
		},
		{
			name: "revoked reason 6", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, Status: Revoked, RevokedAt: revokedAt, Reason: 6},
			check: func(t *testing.T, d decOCSP) {
				cs := d.data.Responses[0].CertStatus
				if cs.Tag != 1 || !cs.IsCompound {
					t.Fatalf("certStatus tag = (%d, %v), want [1] constructed", cs.Tag, cs.IsCompound)
				}
				at, reason, has := decRevoked(t, cs.Bytes)
				if !at.Equal(revokedAt) || reason != 6 || !has {
					t.Errorf("revoked = (%v, %d, %v), want (%v, 6, true)", at, reason, has, revokedAt)
				}
			},
		},
		{
			name: "revoked OmitReason default time", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, Status: Revoked, Reason: 6, OmitReason: true},
			check: func(t *testing.T, d decOCSP) {
				at, _, has := decRevoked(t, d.data.Responses[0].CertStatus.Bytes)
				if want := thisUpdate.Add(-24 * time.Hour); !at.Equal(want) || has {
					t.Errorf("revoked = (%v, reason present %v), want (%v, false)", at, has, want)
				}
			},
		},
		{
			name: "unknown", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, Status: Unknown},
			check: func(t *testing.T, d decOCSP) {
				cs := d.data.Responses[0].CertStatus
				if cs.Class != asn1.ClassContextSpecific || cs.Tag != 2 || cs.IsCompound || len(cs.Bytes) != 0 {
					t.Errorf("certStatus = %x, want [2] NULL (unknown)", cs.FullBytes)
				}
			},
		},
		{
			name: "responder id byKey", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, ResponderID: ByKey},
			check: func(t *testing.T, d decOCSP) {
				var spki struct {
					Algorithm pkix.AlgorithmIdentifier
					PublicKey asn1.BitString
				}
				if _, err := asn1.Unmarshal(delegated.Cert.RawSubjectPublicKeyInfo, &spki); err != nil {
					t.Fatal(err)
				}
				sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // ResponderID byKey
				rid := d.data.ResponderID
				var keyHash []byte
				if rid.Tag != 2 || !rid.IsCompound {
					t.Fatalf("ResponderID tag = (%d, %v), want [2] constructed", rid.Tag, rid.IsCompound)
				}
				if _, err := asn1.Unmarshal(rid.Bytes, &keyHash); err != nil {
					t.Fatalf("decode byKey: %v", err)
				}
				if !bytes.Equal(keyHash, sum[:]) || !bytes.Equal(keyHash, SPKIKeyHash(t, delegated.Cert)) {
					t.Errorf("byKey = %x, want %x", keyHash, sum)
				}
			},
		},
		{
			name: "responder id byName of another cert", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, ResponderIDOf: ca.Cert},
			check: func(t *testing.T, d decOCSP) {
				if rid := d.data.ResponderID; rid.Tag != 1 || !bytes.Equal(rid.Bytes, ca.Cert.RawSubject) {
					t.Errorf("ResponderID = %x, want byName of the CA", rid.FullBytes)
				}
			},
		},
		{
			name: "nextUpdate present", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, NextUpdate: decTestNow.Add(time.Hour)},
			check: func(t *testing.T, d decOCSP) {
				if got, want := d.data.Responses[0].NextUpdate, decTestNow.Add(time.Hour); !got.Equal(want) {
					t.Errorf("nextUpdate = %v, want %v", got, want)
				}
			},
		},
		{
			name: "nonce omit", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, Nonce: NonceOmit},
			check: func(t *testing.T, d decOCSP) {
				if got, ok := d.nonce(); ok {
					t.Errorf("nonce = %x, want absent", got)
				}
			},
		},
		{
			name: "nonce echo without request nonce", issuer: ca, req: reqNoNonce,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated},
			check: func(t *testing.T, d decOCSP) {
				if got, ok := d.nonce(); ok {
					t.Errorf("nonce = %x, want absent", got)
				}
			},
		},
		{
			name: "nonce wrong", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, Nonce: NonceWrong},
			check: func(t *testing.T, d decOCSP) {
				if got, ok := d.nonce(); !ok || !bytes.Equal(got, wrongNonce) {
					t.Errorf("nonce = %x (present %v), want %x", got, ok, wrongNonce)
				}
			},
		},
		{
			name: "duplicate single", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, DuplicateSingle: true},
			check: func(t *testing.T, d decOCSP) {
				if n := len(d.data.Responses); n != 2 {
					t.Fatalf("got %d SingleResponses, want 2", n)
				}
				a, b := d.data.Responses[0], d.data.Responses[1]
				if !bytes.Equal(a.CertStatus.FullBytes, b.CertStatus.FullBytes) || a.CertID.Serial.Cmp(b.CertID.Serial) != 0 {
					t.Error("duplicate SingleResponse differs from the first")
				}
			},
		},
		{
			name: "sha256 certid from request", issuer: ca, req: reqSHA256,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated},
			check: func(t *testing.T, d decOCSP) {
				nameHash, keyHash := CertIDHashes(t, crypto.SHA256, ca.Cert)
				id := d.data.Responses[0].CertID
				if !id.HashAlgorithm.Algorithm.Equal(decOIDSHA256) || !bytes.Equal(id.NameHash, nameHash) || !bytes.Equal(id.KeyHash, keyHash) {
					t.Errorf("CertID = %+v, want SHA-256 hashes", id)
				}
			},
		},
		{
			name: "issuer signed ecdsa", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: ca.AsResponder()},
			check: func(t *testing.T, d decOCSP) {
				if len(d.basic.Certs) != 0 {
					t.Errorf("embedded certs = %d, want 0", len(d.basic.Certs))
				}
				if err := d.verify(ca.Cert); err != nil {
					t.Errorf("signature: %v", err)
				}
			},
		},
		{
			name: "issuer signed rsa", issuer: rsaCA, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: rsaCA.AsResponder()},
			check: func(t *testing.T, d decOCSP) {
				if !d.basic.Algorithm.Algorithm.Equal(decOIDRSASHA256) {
					t.Errorf("signatureAlgorithm = %v, want %v", d.basic.Algorithm.Algorithm, decOIDRSASHA256)
				}
				if len(d.basic.Certs) != 0 {
					t.Errorf("embedded certs = %d, want 0", len(d.basic.Certs))
				}
				if err := d.verify(rsaCA.Cert); err != nil {
					t.Errorf("signature: %v", err)
				}
			},
		},
		{
			name: "delegated NoCerts", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, NoCerts: true},
			check: func(t *testing.T, d decOCSP) {
				if len(d.basic.Certs) != 0 {
					t.Errorf("embedded certs = %d, want 0", len(d.basic.Certs))
				}
			},
		},
		{
			name: "corrupt signature", issuer: ca, req: req,
			spec: OCSPSpec{Now: decTestNow, Signer: delegated, CorruptSignature: true},
			check: func(t *testing.T, d decOCSP) {
				if err := d.verify(delegated.Cert); err == nil {
					t.Error("corrupt signature verified, want an error")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := decodeOCSP(t, BuildOCSPResponse(t, tc.issuer, tc.req, tc.spec))
			if d.status != 0 {
				t.Fatalf("responseStatus = %d, want 0", d.status)
			}
			if len(d.data.Responses) == 0 {
				t.Fatal("no SingleResponse")
			}
			tc.check(t, d)
		})
	}

	t.Run("response status 3", func(t *testing.T) {
		got := BuildOCSPResponse(t, ca, req, OCSPSpec{ResponseStatus: 3})
		if want := []byte{0x30, 0x03, 0x0a, 0x01, 0x03}; !bytes.Equal(got, want) {
			t.Errorf("response = % x, want % x", got, want)
		}
	})
}

// Encoding structures for a hand-built OCSP request (RFC 6960 4.1.1).
type (
	encCertID struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		NameHash      []byte
		KeyHash       []byte
		Serial        *big.Int
	}
	encRequest struct {
		Cert encCertID
	}
	encTBSRequest struct {
		RequestList []encRequest
		Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	encOCSPRequest struct {
		TBS encTBSRequest
	}
)

func encodeOCSPRequest(t *testing.T, issuer *x509.Certificate, serials []*big.Int, nonce []byte) []byte {
	t.Helper()
	nameHash, keyHash := CertIDHashes(t, crypto.SHA1, issuer)
	var r encOCSPRequest
	for _, s := range serials {
		r.TBS.RequestList = append(r.TBS.RequestList, encRequest{Cert: encCertID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: decOIDSHA1, Parameters: asn1.NullRawValue},
			NameHash:      nameHash,
			KeyHash:       keyHash,
			Serial:        s,
		}})
	}
	if nonce != nil {
		r.TBS.Extensions = []pkix.Extension{{Id: decOIDOCSPNonce, Value: nonce}}
	}
	der, err := asn1.Marshal(r)
	if err != nil {
		t.Fatalf("encode OCSP request: %v", err)
	}
	return der
}

func TestParseOCSPRequest(t *testing.T) {
	ca := NewRoot(t, "request root", CertSpec{})
	nameHash, keyHash := CertIDHashes(t, crypto.SHA1, ca.Cert)
	nonce := append([]byte{0x04, 0x20}, bytes.Repeat([]byte{0xab}, 32)...)
	serial := big.NewInt(0x1234567)

	t.Run("round trip", func(t *testing.T) {
		got, err := ParseOCSPRequest(encodeOCSPRequest(t, ca.Cert, []*big.Int{serial, big.NewInt(9)}, nonce))
		if err != nil {
			t.Fatalf("ParseOCSPRequest: %v", err)
		}
		if !got.HashAlgorithm.Equal(decOIDSHA1) || !bytes.Equal(got.IssuerNameHash, nameHash) ||
			!bytes.Equal(got.IssuerKeyHash, keyHash) || got.Serial.Cmp(serial) != 0 {
			t.Errorf("CertID = (%v, %x, %x, %v), want (%v, %x, %x, %v)", got.HashAlgorithm, got.IssuerNameHash,
				got.IssuerKeyHash, got.Serial, decOIDSHA1, nameHash, keyHash, serial)
		}
		if !bytes.Equal(got.Nonce, nonce) {
			t.Errorf("Nonce = %x, want %x", got.Nonce, nonce)
		}
		if got.Count != 2 {
			t.Errorf("Count = %d, want 2", got.Count)
		}
	})

	t.Run("no nonce", func(t *testing.T) {
		got, err := ParseOCSPRequest(encodeOCSPRequest(t, ca.Cert, []*big.Int{serial}, nil))
		if err != nil {
			t.Fatalf("ParseOCSPRequest: %v", err)
		}
		if got.Nonce != nil || got.Count != 1 {
			t.Errorf("Nonce=%x Count=%d, want nil, 1", got.Nonce, got.Count)
		}
	})

	bad := []struct {
		name string
		der  []byte
	}{
		{"trailing data", append(encodeOCSPRequest(t, ca.Cert, []*big.Int{serial}, nonce), 0x00)},
		{"empty request list", encodeOCSPRequest(t, ca.Cert, nil, nil)},
		{"garbage", []byte{0x30, 0x03, 0x02, 0x01}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseOCSPRequest(tc.der); err == nil {
				t.Errorf("ParseOCSPRequest = %+v, want an error", got)
			}
		})
	}
}

// decIDP decodes an IssuingDistributionPoint value into its elements by tag.
func decIDP(t *testing.T, value []byte) map[int]asn1.RawValue {
	t.Helper()
	out := make(map[int]asn1.RawValue)
	for _, el := range decElements(t, decOne(t, value).Bytes) {
		if el.Class != asn1.ClassContextSpecific {
			t.Fatalf("IDP element class %d, want context-specific", el.Class)
		}
		if _, dup := out[el.Tag]; dup {
			t.Fatalf("IDP element [%d] repeated", el.Tag)
		}
		out[el.Tag] = el
	}
	return out
}

func TestCRLShapes(t *testing.T) {
	ca := NewRoot(t, "crl root", CertSpec{Now: decTestNow})
	other := NewRoot(t, "other root", CertSpec{Now: decTestNow})
	rsaCA := NewRoot(t, "crl rsa root", CertSpec{Key: RSA2048, Now: decTestNow})
	thisUpdate := decTestNow.Add(-time.Minute)
	revokedAt := decTestNow.Add(-72 * time.Hour)
	overrideIssuer := Name{UTF8(OIDCommonName, "override issuer")}.DER()
	relName := RDN{{OID: OIDCommonName, Value: "CRL1"}}

	type variant struct {
		name    string
		ca      *CA
		spec    CRLSpec
		wantSig bool // CheckSignatureFrom(ca) passes
		check   func(t *testing.T, rl *x509.RevocationList)
	}
	idpCheck := func(spec IDPSpec, want func(t *testing.T, els map[int]asn1.RawValue)) func(t *testing.T, rl *x509.RevocationList) {
		return func(t *testing.T, rl *x509.RevocationList) {
			var ext *pkix.Extension
			for i := range rl.Extensions {
				if rl.Extensions[i].Id.Equal(decOIDIDP) {
					ext = &rl.Extensions[i]
				}
			}
			if ext == nil {
				t.Fatal("IDP extension missing")
			}
			if ext.Critical == spec.NonCritical {
				t.Errorf("IDP critical = %v, want %v", ext.Critical, !spec.NonCritical)
			}
			if !bytes.Equal(ext.Value, EncodeIDP(spec)) {
				t.Errorf("IDP value = %x, want EncodeIDP = %x", ext.Value, EncodeIDP(spec))
			}
			want(t, decIDP(t, ext.Value))
		}
	}
	fullNameCheck := func(want []decGeneralName) func(t *testing.T, els map[int]asn1.RawValue) {
		return func(t *testing.T, els map[int]asn1.RawValue) {
			dp, ok := els[0]
			if !ok || !dp.IsCompound {
				t.Fatal("IDP distributionPoint [0] missing")
			}
			full := decOne(t, dp.Bytes)
			if full.Tag != 0 || !full.IsCompound {
				t.Fatalf("distributionPoint name tag = (%d, %v), want fullName [0] constructed", full.Tag, full.IsCompound)
			}
			if got := decGeneralNames(t, full.Bytes); !equalGeneralNames(got, want) {
				t.Errorf("fullName = %v, want %v", got, want)
			}
		}
	}
	flagCheck := func(tag int, want []byte) func(t *testing.T, els map[int]asn1.RawValue) {
		return func(t *testing.T, els map[int]asn1.RawValue) {
			el, ok := els[tag]
			if !ok || el.IsCompound || !bytes.Equal(el.Bytes, want) {
				t.Errorf("IDP [%d] = %x (present %v), want primitive %x", tag, el.Bytes, ok, want)
			}
			if len(els) != 1 {
				t.Errorf("IDP has %d elements, want only [%d]", len(els), tag)
			}
		}
	}

	variants := []variant{
		{
			name: "defaults", ca: ca, spec: CRLSpec{Now: decTestNow, Number: 7}, wantSig: true,
			check: func(t *testing.T, rl *x509.RevocationList) {
				if !rl.ThisUpdate.Equal(thisUpdate) || !rl.NextUpdate.Equal(thisUpdate.Add(24*time.Hour)) {
					t.Errorf("thisUpdate=%v nextUpdate=%v, want %v and +24h", rl.ThisUpdate, rl.NextUpdate, thisUpdate)
				}
				if rl.Number == nil || rl.Number.Int64() != 7 {
					t.Errorf("Number = %v, want 7", rl.Number)
				}
				if !bytes.Equal(rl.RawIssuer, ca.Cert.RawSubject) {
					t.Errorf("RawIssuer = %x, want the CA subject", rl.RawIssuer)
				}
				if !bytes.Equal(rl.AuthorityKeyId, ca.Cert.SubjectKeyId) {
					t.Errorf("AuthorityKeyId = %x, want %x", rl.AuthorityKeyId, ca.Cert.SubjectKeyId)
				}
			},
		},
		{
			name: "rsa signer", ca: rsaCA, spec: CRLSpec{Now: decTestNow}, wantSig: true,
			check: func(t *testing.T, rl *x509.RevocationList) {
				if rl.SignatureAlgorithm != x509.SHA256WithRSA {
					t.Errorf("SignatureAlgorithm = %v, want %v", rl.SignatureAlgorithm, x509.SHA256WithRSA)
				}
			},
		},
		{
			name: "no next update", ca: ca, spec: CRLSpec{Now: decTestNow, NoNextUpdate: true}, wantSig: true,
			check: func(t *testing.T, rl *x509.RevocationList) {
				if !rl.NextUpdate.IsZero() {
					t.Errorf("NextUpdate = %v, want zero", rl.NextUpdate)
				}
			},
		},
		{
			name: "entries", ca: ca, wantSig: true,
			spec: CRLSpec{Now: decTestNow, Entries: []CRLEntry{
				{Serial: big.NewInt(10), RevokedAt: revokedAt, Reason: 1},
				{Serial: big.NewInt(11), RevokedAt: revokedAt, Reason: 6},
				{Serial: big.NewInt(12), RevokedAt: revokedAt, NoReason: true, Extensions: []pkix.Extension{InvalidityDate(revokedAt)}},
			}},
			check: func(t *testing.T, rl *x509.RevocationList) {
				want := []struct {
					serial int64
					reason int
					exts   int
				}{{10, 1, 1}, {11, 6, 1}, {12, 0, 1}}
				if len(rl.RevokedCertificateEntries) != len(want) {
					t.Fatalf("got %d entries, want %d", len(rl.RevokedCertificateEntries), len(want))
				}
				for i, e := range rl.RevokedCertificateEntries {
					w := want[i]
					if e.SerialNumber.Int64() != w.serial || e.ReasonCode != w.reason || !e.RevocationTime.Equal(revokedAt) || len(e.Extensions) != w.exts {
						t.Errorf("entry %d = (%v, reason %d, %v, %d exts), want (%d, reason %d, %v, %d exts)",
							i, e.SerialNumber, e.ReasonCode, e.RevocationTime, len(e.Extensions), w.serial, w.reason, revokedAt, w.exts)
					}
				}
			},
		},
		{
			name: "idp uris and dirnames", ca: ca, wantSig: true,
			spec: CRLSpec{Now: decTestNow, IDP: &IDPSpec{URIs: []string{decCRLURI}, DirNames: []Name{decDirName}}},
			check: idpCheck(IDPSpec{URIs: []string{decCRLURI}, DirNames: []Name{decDirName}},
				fullNameCheck([]decGeneralName{{6, []byte(decCRLURI)}, {4, decDirName.DER()}})),
		},
		{
			name: "idp dirnames first", ca: ca, wantSig: true,
			spec: CRLSpec{Now: decTestNow, IDP: &IDPSpec{URIs: []string{decCRLURI}, DirNames: []Name{decDirName}, DirNamesFirst: true}},
			check: idpCheck(IDPSpec{URIs: []string{decCRLURI}, DirNames: []Name{decDirName}, DirNamesFirst: true},
				fullNameCheck([]decGeneralName{{4, decDirName.DER()}, {6, []byte(decCRLURI)}})),
		},
		{
			name: "idp relative name", ca: ca, wantSig: true,
			spec: CRLSpec{Now: decTestNow, IDP: &IDPSpec{RelativeName: relName}},
			check: idpCheck(IDPSpec{RelativeName: relName}, func(t *testing.T, els map[int]asn1.RawValue) {
				rel := decOne(t, els[0].Bytes)
				if rel.Tag != 1 || !rel.IsCompound {
					t.Fatalf("distributionPoint name tag = (%d, %v), want nameRelativeToCRLIssuer [1]", rel.Tag, rel.IsCompound)
				}
				var a struct {
					Type  asn1.ObjectIdentifier
					Value string `asn1:"utf8"`
				}
				if rest, err := asn1.Unmarshal(rel.Bytes, &a); err != nil || len(rest) > 0 {
					t.Fatalf("decode relative name: err=%v rest=%d", err, len(rest))
				}
				if !a.Type.Equal(OIDCommonName) || a.Value != "CRL1" {
					t.Errorf("relative name = (%v, %q), want (%v, %q)", a.Type, a.Value, OIDCommonName, "CRL1")
				}
			}),
		},
		{
			name: "idp onlyContainsUserCerts", ca: ca, wantSig: true,
			spec:  CRLSpec{Now: decTestNow, IDP: &IDPSpec{OnlyUser: true}},
			check: idpCheck(IDPSpec{OnlyUser: true}, flagCheck(1, []byte{0xff})),
		},
		{
			name: "idp onlyContainsCACerts", ca: ca, wantSig: true,
			spec:  CRLSpec{Now: decTestNow, IDP: &IDPSpec{OnlyCA: true}},
			check: idpCheck(IDPSpec{OnlyCA: true}, flagCheck(2, []byte{0xff})),
		},
		{
			name: "idp onlySomeReasons", ca: ca, wantSig: true,
			spec:  CRLSpec{Now: decTestNow, IDP: &IDPSpec{OnlySomeReasons: true}},
			check: idpCheck(IDPSpec{OnlySomeReasons: true}, flagCheck(3, []byte{0x07, 0x80})),
		},
		{
			name: "idp indirectCRL", ca: ca, wantSig: true,
			spec:  CRLSpec{Now: decTestNow, IDP: &IDPSpec{Indirect: true}},
			check: idpCheck(IDPSpec{Indirect: true}, flagCheck(4, []byte{0xff})),
		},
		{
			name: "idp onlyContainsAttributeCerts", ca: ca, wantSig: true,
			spec:  CRLSpec{Now: decTestNow, IDP: &IDPSpec{OnlyAttr: true}},
			check: idpCheck(IDPSpec{OnlyAttr: true}, flagCheck(5, []byte{0xff})),
		},
		{
			name: "idp non-critical", ca: ca, wantSig: true,
			spec: CRLSpec{Now: decTestNow, IDP: &IDPSpec{URIs: []string{decCRLURI}, NonCritical: true}},
			check: idpCheck(IDPSpec{URIs: []string{decCRLURI}, NonCritical: true},
				fullNameCheck([]decGeneralName{{6, []byte(decCRLURI)}})),
		},
		{
			name: "issuer override", ca: ca, wantSig: true,
			spec: CRLSpec{Now: decTestNow, IssuerDER: overrideIssuer},
			check: func(t *testing.T, rl *x509.RevocationList) {
				if !bytes.Equal(rl.RawIssuer, overrideIssuer) {
					t.Errorf("RawIssuer = %x, want %x", rl.RawIssuer, overrideIssuer)
				}
			},
		},
		{
			name: "signed by another ca", ca: ca, wantSig: false,
			spec: CRLSpec{Now: decTestNow, Signer: other},
		},
		{
			name: "corrupt signature", ca: ca, wantSig: false,
			spec: CRLSpec{Now: decTestNow, CorruptSig: true},
		},
	}
	for _, tc := range variants {
		t.Run(tc.name, func(t *testing.T) {
			rl, err := x509.ParseRevocationList(tc.ca.CRL(t, tc.spec))
			if err != nil {
				t.Fatalf("ParseRevocationList: %v", err)
			}
			err = rl.CheckSignatureFrom(tc.ca.Cert)
			if got := err == nil; got != tc.wantSig {
				t.Errorf("CheckSignatureFrom(ca) ok = %v (err %v), want %v", got, err, tc.wantSig)
			}
			if tc.check != nil {
				tc.check(t, rl)
			}
		})
	}
}

func TestNetDial(t *testing.T) {
	ca := NewRoot(t, "net root", CertSpec{})
	leaf := ca.Leaf(t, CertSpec{Subject: decLeafSubject})
	ocspSrv := NewOCSPServer(ca, ca.OCSPResponder(t, CertSpec{}))
	crlBody := ca.CRL(t, CRLSpec{})

	n := NewNet()
	n.Serve(t, "ocsp.example.test", ocspSrv.Handler(t))
	n.Serve(t, "crl.example.test", Bytes("application/pkix-crl", crlBody))
	tr := &http.Transport{DialContext: n.DialContext, Proxy: nil}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}

	do := func(t *testing.T, method, url string, body []byte) (*http.Response, []byte, error) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/ocsp-request")
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return resp, b, err
	}

	t.Run("bytes handler", func(t *testing.T) {
		resp, body, err := do(t, http.MethodGet, "http://crl.example.test/ca.crl", nil)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		if got, want := resp.Header.Get("Content-Type"), "application/pkix-crl"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		if !bytes.Equal(body, crlBody) {
			t.Errorf("body = %d bytes, want the %d-byte CRL", len(body), len(crlBody))
		}
	})

	t.Run("ocsp server", func(t *testing.T) {
		reqDER := encodeOCSPRequest(t, ca.Cert, []*big.Int{leaf.Cert.SerialNumber}, nil)
		_, body, err := do(t, http.MethodPost, "http://ocsp.example.test/", reqDER)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		d := decodeOCSP(t, body)
		if d.status != 0 || len(d.data.Responses) != 1 || d.data.Responses[0].CertStatus.Tag != 0 {
			t.Fatalf("response status %d, %d singles, want successful good", d.status, len(d.data.Responses))
		}
		if d.data.Responses[0].NextUpdate.IsZero() {
			t.Error("default answer has no nextUpdate, want +1h")
		}
		reqs := ocspSrv.Requests()
		if len(reqs) != 1 || reqs[0].Serial.Cmp(leaf.Cert.SerialNumber) != 0 {
			t.Errorf("Requests() = %+v, want one request for the leaf serial", reqs)
		}
	})

	t.Run("unknown host", func(t *testing.T) {
		if resp, _, err := do(t, http.MethodGet, "http://unknown.example.test/", nil); err == nil {
			t.Errorf("GET unknown host: status %d, want a dial error", resp.StatusCode)
		}
	})

	t.Run("registered host on another port", func(t *testing.T) {
		if resp, _, err := do(t, http.MethodGet, "http://crl.example.test:8080/ca.crl", nil); err == nil {
			t.Errorf("GET host:8080: status %d, want a dial error", resp.StatusCode)
		}
	})
}

func TestServerTLS(t *testing.T) {
	const host = "auth.example.test"
	cert, pool := ServerTLS(t, host, "other.example.test")

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	var (
		wg        sync.WaitGroup
		serverErr error
	)
	wg.Go(func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()
		serverErr = conn.(*tls.Conn).HandshakeContext(t.Context())
	})
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})

	d := tls.Dialer{Config: &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("TLS dial: %v", err)
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()
	ln.Close()
	wg.Wait()
	if serverErr != nil {
		t.Errorf("server handshake: %v", serverErr)
	}
	if len(state.PeerCertificates) == 0 || !slices.Contains(state.PeerCertificates[0].DNSNames, host) {
		t.Errorf("peer certificate DNS names do not include %q", host)
	}
}
