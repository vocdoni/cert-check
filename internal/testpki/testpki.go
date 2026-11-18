// Package testpki builds synthetic PKIs for tests: CAs, intermediates and
// leaves with arbitrary raw subjects, SAN directoryName entries,
// SubjectDirectoryAttributes, policies, KU/EKU, critical extensions, AIA/CDP,
// weak keys and SHA-1 signatures; OCSP responders with configurable answers;
// CRL issuers with IssuingDistributionPoint variants; and an in-process fake
// network for HTTP fetches. It is imported only from _test.go files.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Common attribute and extension OIDs.
var (
	OIDCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	OIDSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
	OIDCountry                = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDLocality               = asn1.ObjectIdentifier{2, 5, 4, 7}
	OIDOrganization           = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDOrganizationalUnit     = asn1.ObjectIdentifier{2, 5, 4, 11}
	OIDTitle                  = asn1.ObjectIdentifier{2, 5, 4, 12}
	OIDDescription            = asn1.ObjectIdentifier{2, 5, 4, 13}
	OIDGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
	OIDOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	OIDUID                    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	OIDEmailAddress           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	OIDExtSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDExtSubjectDirAttrs     = asn1.ObjectIdentifier{2, 5, 29, 9}
	OIDExtCRLDistPoints       = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDExtQCStatements        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	OIDExtOCSPNoCheck         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	OIDAttrDateOfBirth        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
	OIDAttrCountryOfResidence = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 5}
)

// String tags accepted by Attr.Tag.
const (
	TagUTF8      = tagUTF8String
	TagPrintable = tagPrintableString
	TagTeletex   = tagT61String
	TagIA5       = tagIA5String
	TagBMP       = tagBMPString
)

// Attr is one AttributeTypeAndValue. Tag 0 means UTF8String.
type Attr struct {
	OID   asn1.ObjectIdentifier
	Value string
	Tag   int
}

// RDN is one RelativeDistinguishedName; more than one Attr makes it multi-valued.
// Attributes are encoded in the given order (tests may build non-DER SETs).
type RDN []Attr

// Name is an RDNSequence encoded verbatim: order and duplicates preserved.
type Name []RDN

// UTF8 returns a single-attribute RDN with a UTF8String value.
func UTF8(oid asn1.ObjectIdentifier, v string) RDN { return RDN{{OID: oid, Value: v, Tag: TagUTF8}} }

// Printable returns a single-attribute RDN with a PrintableString value.
func Printable(oid asn1.ObjectIdentifier, v string) RDN {
	return RDN{{OID: oid, Value: v, Tag: TagPrintable}}
}

// Tagged returns a single-attribute RDN with an explicit string tag.
func Tagged(oid asn1.ObjectIdentifier, tag int, v string) RDN {
	return RDN{{OID: oid, Value: v, Tag: tag}}
}

// DER encodes the name.
func (n Name) DER() []byte {
	var rdns [][]byte
	for _, rdn := range n {
		var atvs [][]byte
		for _, a := range rdn {
			tag := a.Tag
			if tag == 0 {
				tag = TagUTF8
			}
			atvs = append(atvs, seq(derOID(a.OID), encodeString(tag, a.Value)))
		}
		rdns = append(rdns, tlv(tagSet, atvs...))
	}
	return seq(rdns...)
}

// KeySpec selects a key algorithm and size.
type KeySpec int

// Key specs. Weak ones exist to test weak_algorithm.
const (
	ECDSAP256 KeySpec = iota + 1
	ECDSAP384
	ECDSAP521
	ECDSAP224
	RSA1024
	RSA1920
	RSA2048
	RSA3072
	RSA4096
)

// NewKey generates a fresh key. Every call returns a distinct key.
func NewKey(t testing.TB, k KeySpec) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch k {
	case ECDSAP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSAP521:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case ECDSAP224:
		key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case RSA1024:
		key, err = rsa.GenerateKey(rand.Reader, 1024)
	case RSA1920:
		key, err = rsa.GenerateKey(rand.Reader, 1920)
	case RSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		t.Fatalf("testpki: unknown key spec %d", k)
	}
	if err != nil {
		t.Fatalf("testpki: generate key: %v", err)
	}
	return key
}

// DistributionPoint is one CRL DistributionPoint (fullName form). Names are
// encoded URIs first, then directoryNames, unless DirNamesFirst is set.
type DistributionPoint struct {
	URIs          []string
	DirNames      []Name
	DirNamesFirst bool
}

// CertSpec describes a certificate. Zero fields take the defaults noted.
type CertSpec struct {
	Subject            Name               // leaf: required; CA: default CN=<label>,O=testpki,C=ES
	Key                KeySpec            // default ECDSAP256
	KeyPair            crypto.Signer      // overrides Key (reuse a key across certificates)
	Serial             *big.Int           // default random 128-bit positive
	NotBefore          time.Time          // default Now - 1h
	NotAfter           time.Time          // default Now + 365 days
	Now                time.Time          // reference time for defaults; default time.Now()
	KeyUsage           x509.KeyUsage      // default: leaf DigitalSignature; CA CertSign|CRLSign
	NoKeyUsage         bool               // omit the KeyUsage extension
	ExtKeyUsage        []x509.ExtKeyUsage // nil and UnknownEKU nil: extension omitted
	UnknownEKU         []asn1.ObjectIdentifier
	Policies           []asn1.ObjectIdentifier // certificatePolicies (no qualifiers)
	OCSPServers        []string                // AIA id-ad-ocsp
	CAIssuers          []string                // AIA id-ad-caIssuers
	CDP                []DistributionPoint     // cRLDistributionPoints
	SANDirNames        []Name                  // SAN directoryName entries
	SANEmails          []string                // SAN rfc822Name entries
	SANRaw             []byte                  // full SAN extension value (overrides SANDirNames/SANEmails)
	DateOfBirth        string                  // SDA dateOfBirth GeneralizedTime text, e.g. "19800101120000Z"
	SDARaw             []byte                  // full SDA extension value (overrides DateOfBirth)
	PathLen            *int                    // CA only; nil = no pathLenConstraint, new(0) = pathlen:0
	ExtraExtensions    []pkix.Extension        // e.g. critical qcStatements or an unknown critical OID
	SignatureAlgorithm x509.SignatureAlgorithm // e.g. x509.SHA1WithRSA; default per issuer key
}

// CA is a certificate authority that can issue certificates, OCSP responses and CRLs.
type CA struct {
	Cert  *x509.Certificate
	Key   crypto.Signer
	Label string
}

// Leaf is an end-entity certificate with its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// TLSCertificate returns the leaf as a tls.Certificate (leaf only in the chain).
func (l *Leaf) TLSCertificate(extra ...*x509.Certificate) tls.Certificate {
	chain := [][]byte{l.Cert.Raw}
	for _, c := range extra {
		chain = append(chain, c.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: l.Key, Leaf: l.Cert}
}

// NewRoot creates a self-signed CA.
func NewRoot(t testing.TB, label string, spec CertSpec) *CA {
	t.Helper()
	key := spec.KeyPair
	if key == nil {
		key = NewKey(t, orDefault(spec.Key, ECDSAP256))
	}
	if spec.Subject == nil {
		spec.Subject = defaultCAName(label)
	}
	tpl := template(t, spec, true)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("testpki: create root %s: %v", label, err)
	}
	return &CA{Cert: mustParse(t, der), Key: key, Label: label}
}

// Intermediate issues a CA certificate.
func (ca *CA) Intermediate(t testing.TB, label string, spec CertSpec) *CA {
	t.Helper()
	key := spec.KeyPair
	if key == nil {
		key = NewKey(t, orDefault(spec.Key, ECDSAP256))
	}
	if spec.Subject == nil {
		spec.Subject = defaultCAName(label)
	}
	der := ca.sign(t, template(t, spec, true), key.Public())
	return &CA{Cert: mustParse(t, der), Key: key, Label: label}
}

// Leaf issues an end-entity certificate.
func (ca *CA) Leaf(t testing.TB, spec CertSpec) *Leaf {
	t.Helper()
	if spec.Subject == nil {
		t.Fatal("testpki: leaf needs a Subject")
	}
	key := spec.KeyPair
	if key == nil {
		key = NewKey(t, orDefault(spec.Key, ECDSAP256))
	}
	der := ca.sign(t, template(t, spec, false), key.Public())
	return &Leaf{Cert: mustParse(t, der), Key: key}
}

// OCSPResponder issues a delegated responder certificate: EKU OCSPSigning,
// id-pkix-ocsp-nocheck, KU digitalSignature. spec may override any field.
func (ca *CA) OCSPResponder(t testing.TB, spec CertSpec) *Responder {
	t.Helper()
	if spec.Subject == nil {
		spec.Subject = Name{UTF8(OIDCommonName, ca.Label+" OCSP"), Printable(OIDCountry, "ES")}
	}
	if spec.ExtKeyUsage == nil && spec.UnknownEKU == nil {
		spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	spec.ExtraExtensions = append(spec.ExtraExtensions,
		pkix.Extension{Id: OIDExtOCSPNoCheck, Value: derNull()})
	l := ca.Leaf(t, spec)
	return &Responder{Cert: l.Cert, Key: l.Key}
}

// AsResponder returns a Responder that signs with the CA key itself.
func (ca *CA) AsResponder() *Responder { return &Responder{Cert: ca.Cert, Key: ca.Key} }

// SHA256Hex returns the hex SHA-256 of DER bytes.
func SHA256Hex(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// PEM encodes a certificate as PEM.
func PEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func (ca *CA) sign(t testing.TB, tpl *x509.Certificate, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatalf("testpki: issue under %s: %v", ca.Label, err)
	}
	return der
}

func defaultCAName(label string) Name {
	return Name{
		Printable(OIDCountry, "ES"),
		UTF8(OIDOrganization, "testpki"),
		UTF8(OIDCommonName, label),
	}
}

func orDefault(k, def KeySpec) KeySpec {
	if k == 0 {
		return def
	}
	return k
}

func template(t testing.TB, spec CertSpec, isCA bool) *x509.Certificate {
	t.Helper()
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	serial := spec.Serial
	if serial == nil {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		b[0] &= 0x7f
		b[0] |= 0x01
		serial = new(big.Int).SetBytes(b)
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            spec.Subject.DER(),
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtKeyUsage:           spec.ExtKeyUsage,
		UnknownExtKeyUsage:    spec.UnknownEKU,
		OCSPServer:            spec.OCSPServers,
		IssuingCertificateURL: spec.CAIssuers,
		SignatureAlgorithm:    spec.SignatureAlgorithm,
		ExtraExtensions:       append([]pkix.Extension(nil), spec.ExtraExtensions...),
	}
	if tpl.NotBefore.IsZero() {
		tpl.NotBefore = now.Add(-time.Hour)
	}
	if tpl.NotAfter.IsZero() {
		tpl.NotAfter = now.Add(365 * 24 * time.Hour)
	}
	switch {
	case spec.NoKeyUsage:
	case spec.KeyUsage != 0:
		tpl.KeyUsage = spec.KeyUsage
	case isCA:
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	default:
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	tpl.MaxPathLen = -1
	if isCA && spec.PathLen != nil {
		tpl.MaxPathLen = *spec.PathLen
		tpl.MaxPathLenZero = *spec.PathLen == 0
	}
	for _, p := range spec.Policies {
		oid, err := x509.OIDFromInts(oidInts(p))
		if err != nil {
			t.Fatalf("testpki: policy %v: %v", p, err)
		}
		tpl.Policies = append(tpl.Policies, oid)
	}
	if len(spec.CDP) > 0 {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtCRLDistPoints, Value: encodeCDP(spec.CDP)})
	}
	switch {
	case spec.SANRaw != nil:
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectAltName, Value: spec.SANRaw})
	case len(spec.SANDirNames) > 0 || len(spec.SANEmails) > 0:
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectAltName, Value: encodeSAN(spec.SANEmails, spec.SANDirNames)})
	}
	switch {
	case spec.SDARaw != nil:
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectDirAttrs, Value: spec.SDARaw})
	case spec.DateOfBirth != "":
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectDirAttrs, Value: DateOfBirthSDA(spec.DateOfBirth)})
	}
	return tpl
}

// DateOfBirthSDA encodes SubjectDirectoryAttributes holding one dateOfBirth
// attribute whose value is GeneralizedTime text gt (not validated).
func DateOfBirthSDA(gt string) []byte {
	return seq(seq(derOID(OIDAttrDateOfBirth), tlv(tagSet, tlv(tagGeneralizedTime, []byte(gt)))))
}

func encodeSAN(emails []string, dirs []Name) []byte {
	var names [][]byte
	for _, e := range emails {
		names = append(names, ctx(1, false, []byte(e)))
	}
	for _, d := range dirs {
		names = append(names, ctx(4, true, d.DER()))
	}
	return seq(names...)
}

func encodeGeneralNames(uris []string, dirs []Name, dirsFirst bool) []byte {
	var u, d []byte
	for _, name := range dirs {
		d = append(d, ctx(4, true, name.DER())...)
	}
	for _, uri := range uris {
		u = append(u, ctx(6, false, []byte(uri))...)
	}
	if dirsFirst {
		return append(d, u...)
	}
	return append(u, d...)
}

func encodeCDP(dps []DistributionPoint) []byte {
	var items [][]byte
	for _, dp := range dps {
		items = append(items, seq(ctx(0, true, ctx(0, true, encodeGeneralNames(dp.URIs, dp.DirNames, dp.DirNamesFirst)))))
	}
	return seq(items...)
}

func oidInts(oid asn1.ObjectIdentifier) []uint64 {
	out := make([]uint64, len(oid))
	for i, v := range oid {
		out[i] = uint64(v)
	}
	return out
}

func mustParse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testpki: parse: %v", err)
	}
	return c
}

// signDigest signs data with key using SHA-256 and returns the signature and
// the DER AlgorithmIdentifier.
func signDigest(key crypto.Signer, data []byte) (sig, algID []byte, err error) {
	h := sha256.Sum256(data)
	sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, algIDFor(key.Public()), nil
}

// algIDFor returns the SHA-256 signature AlgorithmIdentifier for a public key.
func algIDFor(pub crypto.PublicKey) []byte {
	if _, ok := pub.(*rsa.PublicKey); ok {
		return seq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), derNull())
	}
	return seq(derOID(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}))
}
