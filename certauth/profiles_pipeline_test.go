package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// Synthetic per-profile leaves (AC5): every production profile, with its
// anchors replaced by testpki CAs of the same key family, its real
// revocation hosts served by testpki.Net, and the non-reserved identity
// 12345679S / X1234567L, JUAN / GARCÍA LÓPEZ (accented on purpose).

const (
	ppGiven    = "JUAN"
	ppSurnames = "GARCÍA LÓPEZ"
	ppFirst    = "GARCÍA"
	ppSecond   = "LÓPEZ"
	ppDNI      = "12345679S"
	ppNIE      = "X1234567L"
	ppEmail    = "titular@example.test"
	ppCRLURL   = "http://pki.policia.es/dnie/crls/CRL.crl"
	ppCRLPath  = "/dnie/arls/CRL.crl"
	ppARLURL   = "http://pki.policia.es/dnie/crls/ARL.crl"
	ppARLPath  = "/dnie/arls/ARL.crl"
)

var (
	ppOIDAdobe   = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 5}
	ppOIDMSSign  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
	ppOIDMSLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	ppOIDQC      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	ppClientAuth = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	ppClientMail = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
)

const (
	ppDSNR   = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
	ppDSNRKE = ppDSNR | x509.KeyUsageKeyEncipherment
	ppDSNRKA = ppDSNR | x509.KeyUsageKeyAgreement
)

func ppFNMT(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 5734, 1, n} }
func ppAGE(n int) asn1.ObjectIdentifier  { return asn1.ObjectIdentifier{2, 16, 724, 1, 3, 5, 7, 2, n} }
func ppFP(n int) asn1.ObjectIdentifier   { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 13177, 0, n} }

// Subject attributes.
func ppC() testpki.RDN               { return testpki.Printable(testpki.OIDCountry, "ES") }
func ppSerialP(v string) testpki.RDN { return testpki.Printable(testpki.OIDSerialNumber, v) }
func ppSerial(v string) testpki.RDN  { return testpki.UTF8(testpki.OIDSerialNumber, v) }
func ppGN() testpki.RDN              { return testpki.UTF8(testpki.OIDGivenName, ppGiven) }
func ppSN() testpki.RDN              { return testpki.UTF8(testpki.OIDSurname, ppSurnames) }
func ppCN() testpki.RDN              { return testpki.UTF8(testpki.OIDCommonName, ppGiven+" "+ppSurnames) }
func ppU(oid asn1.ObjectIdentifier, v string) testpki.RDN {
	return testpki.UTF8(oid, v)
}

// ppQCStatements is a well-formed qcStatements value (QcCompliance).
func ppQCStatements(t testing.TB) []byte {
	t.Helper()
	der, err := asn1.Marshal([]struct{ ID asn1.ObjectIdentifier }{{ID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// ppWant is the expected Result of a shape.
type ppWant struct {
	docType       identity.DocumentType
	doc, raw      string
	given         string
	surnames      string
	first, second string // only where the profile provides them
	org           *identity.Organization
	birth         *identity.Date
	method        revocation.Method
}

// ppShape is one synthetic leaf of a profile (Task 7 shapes table).
type ppShape struct {
	name      string
	profile   string
	anchor    int // index of the issuing (replaced) anchor
	key       testpki.KeySpec
	subject   testpki.Name
	sanDirs   []testpki.Name
	sanEmails []string
	ku        x509.KeyUsage
	eku       []x509.ExtKeyUsage
	ekuOIDs   []asn1.ObjectIdentifier
	ocsp      []string
	cdp       []testpki.DistributionPoint
	redirects map[string]string // CDP URL -> path on the same host it answers 302 to
	extra     []pkix.Extension
	dob       string
	ocspEdit  func(now time.Time, s *testpki.OCSPSpec)
	want      ppWant
}

func ppDNIWant(raw string) ppWant {
	return ppWant{docType: identity.DocumentDNI, doc: ppDNI, raw: raw, given: ppGiven, surnames: ppSurnames, method: revocation.MethodOCSP}
}

func (w ppWant) split() ppWant { w.first, w.second = ppFirst, ppSecond; return w }

func ppCDP(urls ...string) []testpki.DistributionPoint {
	var dps []testpki.DistributionPoint
	for _, u := range urls {
		dps = append(dps, testpki.DistributionPoint{URIs: []string{u}})
	}
	return dps
}

// ppShapes returns the shapes of the 19 production profiles.
func ppShapes(t testing.TB) []ppShape {
	fnmtSANDesc := testpki.Name{ppU(ppFNMT(4), ppDNI), ppU(ppFNMT(3), ppSecond), ppU(ppFNMT(2), ppFirst), ppU(ppFNMT(1), ppGiven)}
	fnmtEKU := []asn1.ObjectIdentifier{ppOIDMSSign, ppOIDAdobe}
	const fnmtLDAP = "ldap://ldapusu.cert.fnmt.es/cn=CRLU1"
	idcatG2 := testpki.Name{ppC(), ppU(testpki.OIDOrganizationalUnit, "SERVEIS PUBLICS DE CERTIFICACIO"),
		ppU(testpki.OIDOrganizationalUnit, "VEGEU HTTPS://WWW.AOC.CAT/CATCERT/REGULACIO"), ppSN(), ppGN(), ppSerial("IDCES-" + ppDNI), ppCN()}
	accvSubject := testpki.Name{ppC(), ppSerial(ppDNI), ppGN(), ppSN(), ppU(testpki.OIDOrganizationalUnit, "CIUDADANOS"), ppU(testpki.OIDOrganization, "ACCV"), ppCN()}
	accvSAN := testpki.Name{ppU(testpki.OIDCommonName, ppGiven+"|"+ppFirst+"|"+ppSecond), ppU(testpki.OIDUID, ppDNI)}
	plainIDC := testpki.Name{ppC(), ppSerial("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN()}
	repSubject := testpki.Name{ppC(), ppSerialP("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN(),
		ppU(testpki.OIDOrganization, "EMPRESA DEMO SL"), ppU(testpki.OIDOrganizationIdentifier, "VATES-B00000000")}
	repSAN := testpki.Name{ppU(ppFNMT(4), "IDCES-"+ppDNI), ppU(ppFNMT(1), ppGiven), ppU(ppFNMT(2), ppFirst), ppU(ppFNMT(3), ppSecond)}
	repOrg := &identity.Organization{Name: "EMPRESA DEMO SL", Identifier: "VATES-B00000000"}
	empSubject := testpki.Name{ppC(), ppSerialP("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN(),
		ppU(testpki.OIDOrganizationalUnit, "SECRETARIA GENERAL"), ppU(testpki.OIDOrganization, "AYUNTAMIENTO DEMO")}
	empSAN := testpki.Name{ppU(ppAGE(4), ppDNI), ppU(ppAGE(6), ppGiven), ppU(ppAGE(7), ppFirst), ppU(ppAGE(8), ppSecond), ppU(ppAGE(3), "P0000000J")}
	empOrg := &identity.Organization{Name: "AYUNTAMIENTO DEMO"}
	empEKU := []asn1.ObjectIdentifier{ppOIDMSSign, ppOIDAdobe, ppOIDMSLogon}
	fpSAN := testpki.Name{ppU(ppFP(1), ppGiven), ppU(ppFP(2), ppFirst), ppU(ppFP(3), ppSecond)}
	anfSubject := testpki.Name{ppC(), ppSerial("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN(), ppU(testpki.OIDOrganizationalUnit, "CLASE 2 PERSONA FISICA")}
	nie := ppWant{docType: identity.DocumentNIE, doc: ppNIE, given: ppGiven, surnames: ppSurnames, method: revocation.MethodOCSP}

	shapes := []ppShape{
		{name: "fnmt-citizen-rsa", profile: "fnmt-citizen-rsa", key: testpki.RSA2048,
			subject: testpki.Name{ppC(), ppSerialP("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN()}, sanDirs: []testpki.Name{fnmtSANDesc},
			ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: fnmtEKU, ocsp: []string{"http://ocspusu.cert.fnmt.es/ocspusu/OcspResponder"},
			cdp:  []testpki.DistributionPoint{{URIs: []string{fnmtLDAP, "http://www.cert.fnmt.es/crlsacusu/CRLU1.crl"}}},
			want: ppDNIWant("IDCES-" + ppDNI).split()},
		{name: "fnmt-citizen-rsa-bare-2016", profile: "fnmt-citizen-rsa", key: testpki.RSA2048,
			subject: testpki.Name{ppC(), ppSerialP(ppDNI), ppSN(), ppGN(), ppCN()}, sanDirs: []testpki.Name{fnmtSANDesc},
			ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: fnmtEKU, ocsp: []string{"http://ocspusu.cert.fnmt.es/ocspusu/OcspResponder"},
			cdp:  []testpki.DistributionPoint{{URIs: []string{fnmtLDAP}}},
			want: ppDNIWant(ppDNI).split()},
		{name: "fnmt-citizen-g2", profile: "fnmt-citizen-g2", key: testpki.ECDSAP256,
			subject: testpki.Name{ppC(), ppSerialP("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN()},
			sanDirs: []testpki.Name{{ppU(ppFNMT(1), ppGiven), ppU(ppFNMT(2), ppFirst), ppU(ppFNMT(3), ppSecond), ppU(ppFNMT(4), ppDNI)}},
			ku:      ppDSNR, eku: ppClientAuth, ekuOIDs: fnmtEKU, ocsp: []string{"http://ocspusug2.cert.fnmt.es/ocspusuG2/OcspResponder"},
			cdp: ppCDP("http://www.cert.fnmt.es/crlacusuG2/CRL2.crl"), want: ppDNIWant("IDCES-" + ppDNI).split()},
		{name: "aoc-idcat-g2", profile: "aoc-idcat-g2", key: testpki.RSA2048, subject: idcatG2, sanEmails: []string{ppEmail},
			ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe}, ocsp: []string{"http://ocsp.catcert.cat"},
			cdp: ppCDP("http://epscd.catcert.net/crl/ec-ciutadania.crl"), want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "aoc-idcat-g2-qc", profile: "aoc-idcat-g2", key: testpki.RSA2048, subject: idcatG2, sanEmails: []string{ppEmail},
			ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe}, ocsp: []string{"http://ocsp.catcert.cat"},
			cdp:   ppCDP("http://epscd.catcert.net/crl/ec-ciutadania.crl"),
			extra: []pkix.Extension{{Id: ppOIDQC, Critical: true, Value: ppQCStatements(t)}}, want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "aoc-idcat-g3", profile: "aoc-idcat-g3", key: testpki.ECDSAP384,
			subject: testpki.Name{ppC(), ppSN(), ppGN(), ppSerial("IDCES-" + ppNIE), ppCN()},
			ku:      ppDSNR, eku: ppClientAuth, ocsp: []string{"http://ocsp.aoc.cat"}, cdp: ppCDP("http://epscd.aoc.cat/crl/casub-a2.crl"),
			want: func() ppWant { w := nie; w.raw = "IDCES-" + ppNIE; return w }()},
		{name: "aoc-idcat-g3-rsa-2048", profile: "aoc-idcat-g3", key: testpki.RSA2048,
			subject: testpki.Name{ppC(), ppSN(), ppGN(), ppSerial("IDCES-" + ppNIE), ppCN()},
			ku:      ppDSNR, eku: ppClientAuth, ocsp: []string{"http://ocsp.aoc.cat"}, cdp: ppCDP("http://epscd.aoc.cat/crl/casub-a2.crl"),
			want: func() ppWant { w := nie; w.raw = "IDCES-" + ppNIE; return w }()},
		{name: "accv-rsa", profile: "accv-citizen-software-current", anchor: 0, key: testpki.RSA3072,
			subject: accvSubject, sanDirs: []testpki.Name{accvSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			ocsp: []string{"http://ocsp.accv.es"}, cdp: ppCDP("http://www.accv.es/gestcert/accv_rsa1_cliente.crl"),
			redirects: map[string]string{"http://www.accv.es/gestcert/accv_rsa1_cliente.crl": "/fileadmin/Archivos/certificados/accv_rsa1_cliente.crl"},
			want:      ppDNIWant(ppDNI).split()},
		// RSA-2048 leaves pass on the global floor (R73: no 3072 override).
		{name: "accv-rsa-2048", profile: "accv-citizen-software-current", anchor: 0, key: testpki.RSA2048,
			subject: accvSubject, sanDirs: []testpki.Name{accvSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			ocsp: []string{"http://ocsp.accv.es"}, cdp: ppCDP("http://www.accv.es/gestcert/accv_rsa1_cliente.crl"),
			redirects: map[string]string{"http://www.accv.es/gestcert/accv_rsa1_cliente.crl": "/fileadmin/Archivos/certificados/accv_rsa1_cliente.crl"},
			want:      ppDNIWant(ppDNI).split()},
		{name: "accv-ecc", profile: "accv-citizen-software-current", anchor: 1, key: testpki.ECDSAP256,
			subject: accvSubject, sanDirs: []testpki.Name{accvSAN}, ku: ppDSNRKA, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			ocsp: []string{"http://ocsp.accv.es"}, cdp: ppCDP("http://www.accv.es/gestcert/accv_ecc1_cliente.crl"),
			redirects: map[string]string{"http://www.accv.es/gestcert/accv_ecc1_cliente.crl": "/fileadmin/Archivos/certificados/accv_ecc1_cliente.crl"},
			want:      ppDNIWant(ppDNI).split()},
		{name: "digitel-citizen-sw-g1", profile: "digitel-citizen-sw-g1", key: testpki.RSA3072,
			subject: testpki.Name{ppC(), ppSerial("IDCES-" + ppDNI), ppSN(), ppGN(), ppCN()}, sanEmails: []string{ppEmail},
			ku: ppDSNR, eku: ppClientMail, ocsp: []string{"http://ocsp.digitelts.es"},
			cdp:  ppCDP("http://crl1.pki.digitelts.es/digitelqualifiedcag1.crl", "http://crl2.pki.digitelts.es/digitelqualifiedcag1.crl"),
			want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "bewor-natural-person-sw", profile: "bewor-natural-person-sw", key: testpki.RSA2048,
			subject: testpki.Name{ppC(), ppSN(), ppGN(), ppSerial("IDCES-" + ppDNI), ppCN()}, sanEmails: []string{ppEmail},
			ku: ppDSNRKE, eku: ppClientMail,
			ocsp: []string{"http://ocsp1.uanataca.com/public/pki/ocsp/", "http://ocsp2.uanataca.com/public/pki/ocsp/"},
			cdp:  ppCDP("http://crl1.uanataca.com/public/pki/crl/bewor.crl", "http://crl2.uanataca.com/public/pki/crl/bewor.crl"),
			want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "sectigo-r35", profile: "sectigo-citizen-local", anchor: 0, key: testpki.RSA3072,
			subject: testpki.Name{ppC(), ppSerial("IDCES-" + ppDNI), ppSN(), ppGN(), ppCN()}, sanEmails: []string{ppEmail},
			ku: ppDSNR, eku: ppClientMail, ocsp: []string{"http://ocsp.sectigo.com"},
			ocspEdit: ppSectigoOCSP, cdp: ppCDP("http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAR35.crl"),
			want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "sectigo-e35", profile: "sectigo-citizen-local", anchor: 1, key: testpki.ECDSAP256,
			subject: testpki.Name{ppC(), ppSerial("IDCES-" + ppDNI), ppSN(), ppGN(), ppCN()}, sanEmails: []string{ppEmail},
			ku: ppDSNR, eku: ppClientMail, ocsp: []string{"http://ocsp.sectigo.com"},
			ocspEdit: ppSectigoOCSP, cdp: ppCDP("http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAE35.crl"),
			want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "fnmt-representative-rsa", profile: "fnmt-representative-rsa", key: testpki.RSA2048,
			subject: repSubject, sanDirs: []testpki.Name{repSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: fnmtEKU,
			ocsp: []string{"http://ocsprep.cert.fnmt.es/ocsprep/OcspResponder"}, cdp: ppCDP("http://www.cert.fnmt.es/crlsrep/CRL1.crl"),
			want: func() ppWant { w := ppDNIWant("IDCES-" + ppDNI).split(); w.org = repOrg; return w }()},
		{name: "fnmt-representative-g2", profile: "fnmt-representative-g2", key: testpki.ECDSAP256,
			subject: repSubject, sanDirs: []testpki.Name{repSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: fnmtEKU,
			ocsp: []string{"http://ocsprepg2.cert.fnmt.es/ocsprepG2/OcspResponder"}, cdp: ppCDP("http://www.cert.fnmt.es/crlsrepG2/CRL1.crl"),
			want: func() ppWant { w := ppDNIWant("IDCES-" + ppDNI).split(); w.org = repOrg; return w }()},
		{name: "fnmt-employee-rsa", profile: "fnmt-employee-rsa", key: testpki.RSA2048,
			subject: empSubject, sanDirs: []testpki.Name{empSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: empEKU,
			ocsp: []string{"http://ocspsp.cert.fnmt.es/ocspsp/OcspResponder"}, cdp: ppCDP("http://www.cert.fnmt.es/crlsp/CRL1.crl"),
			want: func() ppWant { w := ppDNIWant("IDCES-" + ppDNI).split(); w.org = empOrg; return w }()},
		{name: "fnmt-employee-g2", profile: "fnmt-employee-g2", key: testpki.ECDSAP256,
			subject: empSubject, sanDirs: []testpki.Name{empSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: empEKU,
			ocsp: []string{"http://ocspspg2.cert.fnmt.es/ocspspG2/OcspResponder"}, cdp: ppCDP("http://www.cert.fnmt.es/crlspG2/CRL1.crl"),
			want: func() ppWant { w := ppDNIWant("IDCES-" + ppDNI).split(); w.org = empOrg; return w }()},
		{name: "firmaprofesional-rsa", profile: "firmaprofesional-personal-sw", anchor: 0, key: testpki.RSA2048,
			subject: plainIDC, sanDirs: []testpki.Name{fpSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			ocsp: []string{"http://ocsp.firmaprofesional.com"}, cdp: ppCDP("http://crl.firmaprofesional.com/fpqualified.crl"),
			want: ppDNIWant("IDCES-" + ppDNI).split()},
		{name: "firmaprofesional-ecc", profile: "firmaprofesional-personal-sw", anchor: 1, key: testpki.ECDSAP384,
			subject: plainIDC, sanDirs: []testpki.Name{fpSAN}, ku: ppDSNRKE, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			ocsp: []string{"http://ocsp.firmaprofesional.com"}, cdp: ppCDP("http://crl.firmaprofesional.com/fpqualified.crl"),
			want: ppDNIWant("IDCES-" + ppDNI).split()},
		{name: "anf-asociacion-class2-sw", profile: "anf-asociacion-class2-sw", key: testpki.RSA2048,
			subject: anfSubject, ku: ppDSNR, eku: ppClientMail, ocsp: []string{"http://ocsp.anf.es/spain/AV"},
			cdp: ppCDP("http://crl.anf.es/crl/anf.crl"), want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "anf-sl-class2-sw", profile: "anf-sl-class2-sw", key: testpki.RSA2048,
			subject: anfSubject, ku: ppDSNR, eku: ppClientMail, ocsp: []string{"http://ocsp.anf.es/spain/AV"},
			cdp: ppCDP("http://crl.anf.es/crl/anf.crl"), want: ppDNIWant("IDCES-" + ppDNI)},
		{name: "signe-nie", profile: "signe-personal-otros-dispositivos", anchor: 0, key: testpki.RSA2048,
			subject: testpki.Name{ppC(), ppSerial("PNOES-" + ppNIE), ppGN(), ppSN(), ppCN()}, sanDirs: []testpki.Name{fpSAN},
			ku: ppDSNR, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			cdp:  ppCDP("http://www.signe.es/signe-ac/crl/signe-subca.crl"),
			want: func() ppWant { w := nie.split(); w.raw, w.method = "PNOES-"+ppNIE, revocation.MethodCRL; return w }()},
		{name: "signe-dni", profile: "signe-personal-otros-dispositivos", anchor: 1, key: testpki.RSA2048,
			subject: plainIDC, sanDirs: []testpki.Name{fpSAN}, ku: ppDSNR, eku: ppClientAuth, ekuOIDs: []asn1.ObjectIdentifier{ppOIDAdobe},
			cdp:  ppCDP("http://www.signe.es/signe-ac/crl/signe-subca.crl"),
			want: func() ppWant { w := ppDNIWant("IDCES-" + ppDNI).split(); w.method = revocation.MethodCRL; return w }()},
		{name: "lleidanet-natural-person-sw", profile: "lleidanet-natural-person-sw", key: testpki.RSA4096,
			subject: testpki.Name{ppC(), ppSerial("IDCES-" + ppDNI), ppGN(), ppSN(), ppCN(),
				ppU(testpki.OIDDescription, "PERSONA NATURAL"), testpki.Tagged(testpki.OIDEmailAddress, testpki.TagIA5, ppEmail)},
			ku: ppDSNR, eku: ppClientMail, ocsp: []string{"http://ocsp2.esigna.es"}, // AIA kept; the profile is CRL-only (R63)
			cdp:  ppCDP("http://crl1.esigna.es/sub/indenova_pki_003.crl"),
			want: func() ppWant { w := ppDNIWant("IDCES-" + ppDNI); w.method = revocation.MethodCRL; return w }()},
		{name: "dnie-auth", profile: "dnie-auth", key: testpki.RSA2048,
			subject: testpki.Name{ppC(), ppSerialP(ppDNI), ppU(testpki.OIDSurname, ppFirst), ppU(testpki.OIDGivenName, "JOSÉ"),
				ppU(testpki.OIDCommonName, ppSurnames+", JOSÉ (AUTENTICACIÓN)")},
			ku: x509.KeyUsageDigitalSignature, ocsp: []string{"http://ocsp.dnie.es"}, dob: "19800101120000Z",
			ocspEdit: func(_ time.Time, s *testpki.OCSPSpec) { s.NextUpdate = time.Time{} }, // good, no nextUpdate
			want: ppWant{docType: identity.DocumentDNI, doc: ppDNI, raw: ppDNI, given: "JOSÉ", surnames: ppSurnames,
				first: ppFirst, second: ppSecond, birth: &identity.Date{Year: 1980, Month: time.January, Day: 1}, method: revocation.MethodOCSP}},
	}
	for i := range 4 { // one run per Uanataca anchor
		shapes = append(shapes, ppShape{name: fmt.Sprintf("uanataca-citizen-sw-%d", i), profile: "uanataca-citizen-sw", anchor: i,
			key: testpki.RSA2048, subject: plainIDC, sanEmails: []string{ppEmail}, ku: ppDSNRKE, eku: ppClientMail,
			ocsp: []string{"http://ocsp1.uanataca.com/public/pki/ocsp/"}, cdp: ppCDP("http://crl1.uanataca.com/public/pki/crl/CA1subordinada.crl"),
			want: ppDNIWant("IDCES-" + ppDNI)})
	}
	return shapes
}

// ppSectigoOCSP: pre-generated responses, thisUpdate -3 d, nextUpdate +4 d.
func ppSectigoOCSP(now time.Time, s *testpki.OCSPSpec) {
	s.ThisUpdate, s.NextUpdate = now.Add(-72*time.Hour), now.Add(96*time.Hour)
}

func ppShapeNamed(t testing.TB, name string) ppShape {
	t.Helper()
	for _, s := range ppShapes(t) {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no shape %q", name)
	return ppShape{}
}

// ppPKI is DefaultProviders with every anchor replaced by a testpki CA of
// the same key family and the DNIe intermediates replaced by one testpki
// intermediate whose CDP names the root CRL and then the ARL (AC DNIE
// 005/006 shape).
type ppPKI struct {
	now        time.Time
	providers  []profiles.Provider
	profiles   map[string]profiles.Profile
	anchors    map[string][]*testpki.CA // profile ID -> replaced anchors, in declaration order
	dnieInter  *testpki.CA
	responders map[*testpki.CA]*testpki.Responder
	crls       map[*testpki.CA][]byte
	dnieCRL    []byte // empty root CRL of the DNIe anchor (IDP without scope flags)
	arl        []byte // good ARL of the DNIe anchor (IDP onlyContainsCACerts)
}

func newPPPKI(t testing.TB, now time.Time) *ppPKI {
	t.Helper()
	p := &ppPKI{now: now, providers: profiles.DefaultProviders(), profiles: map[string]profiles.Profile{},
		anchors: map[string][]*testpki.CA{}, responders: map[*testpki.CA]*testpki.Responder{}, crls: map[*testpki.CA][]byte{}}
	var cas []*testpki.CA
	for pi := range p.providers {
		for qi := range p.providers[pi].Profiles {
			prof := &p.providers[pi].Profiles[qi]
			anchors := make([]profiles.Anchor, 0, len(prof.Anchors))
			for ai, a := range prof.Anchors {
				label := fmt.Sprintf("%s anchor %d", prof.ID, ai)
				ca := testpki.NewRoot(t, label, testpki.CertSpec{Now: now, KeyPair: tKey(t, "pp-"+label, ppFamily(t, a))})
				p.anchors[prof.ID] = append(p.anchors[prof.ID], ca)
				anchors = append(anchors, profiles.TestAnchor(ca.Cert))
				cas = append(cas, ca)
			}
			prof.Anchors = anchors
			if prof.ID == "dnie-auth" {
				p.dnieInter = p.anchors[prof.ID][0].Intermediate(t, "dnie-auth intermediate", testpki.CertSpec{Now: now,
					KeyPair: tKey(t, "pp-dnie-intermediate", testpki.RSA2048),
					CDP:     []testpki.DistributionPoint{{URIs: []string{ppCRLURL}}, {URIs: []string{ppARLURL}}}})
				prof.Intermediates = []profiles.Anchor{profiles.TestAnchor(p.dnieInter.Cert)}
				cas = append(cas, p.dnieInter)
				p.dnieCRL = p.anchors[prof.ID][0].CRL(t, testpki.CRLSpec{Now: now, IDP: &testpki.IDPSpec{URIs: []string{ppCRLURL}}})
				p.arl = p.anchors[prof.ID][0].CRL(t, testpki.CRLSpec{Now: now, IDP: &testpki.IDPSpec{URIs: []string{ppARLURL}, OnlyCA: true}})
			}
			p.profiles[prof.ID] = *prof
		}
	}
	for _, ca := range cas {
		p.responders[ca] = ca.OCSPResponder(t, testpki.CertSpec{Now: now})
		p.crls[ca] = ca.CRL(t, testpki.CRLSpec{Now: now})
	}
	return p
}

// ppFamily returns a key spec of the same family as the real anchor: RSA
// (2048 bits, to keep the tests fast) or the anchor's ECDSA curve.
func ppFamily(t testing.TB, a profiles.Anchor) testpki.KeySpec {
	t.Helper()
	raw, err := fs.ReadFile(profiles.AnchorsFS(), a.File)
	if err != nil {
		t.Fatalf("read anchor %s: %v", a.File, err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		t.Fatalf("anchor %s: no PEM block", a.File)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("anchor %s: %v", a.File, err)
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return testpki.RSA2048
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return testpki.ECDSAP256
		case elliptic.P384():
			return testpki.ECDSAP384
		case elliptic.P521():
			return testpki.ECDSAP521
		}
	}
	t.Fatalf("anchor %s: unexpected key %T", a.File, c.PublicKey)
	return 0
}

// issuer returns the CA that issues the shape's leaf.
func (p *ppPKI) issuer(s ppShape) *testpki.CA {
	if s.profile == "dnie-auth" {
		return p.dnieInter
	}
	return p.anchors[s.profile][s.anchor]
}

// issue creates the shape's leaf.
func (p *ppPKI) issue(t testing.TB, s ppShape) *x509.Certificate {
	t.Helper()
	prof, ok := p.profiles[s.profile]
	if !ok {
		t.Fatalf("shape %s: unknown profile %s", s.name, s.profile)
	}
	return p.issuer(s).Leaf(t, testpki.CertSpec{
		Now: p.now, Subject: s.subject, KeyPair: tKey(t, "pp-leaf", s.key),
		KeyUsage: s.ku, ExtKeyUsage: s.eku, UnknownEKU: s.ekuOIDs,
		Policies:    []asn1.ObjectIdentifier{tOID(t, prof.PolicyOIDs[0])},
		OCSPServers: s.ocsp, CDP: s.cdp, SANDirNames: s.sanDirs, SANEmails: s.sanEmails,
		DateOfBirth: s.dob, ExtraExtensions: s.extra,
	}).Cert
}

// ppMode selects the OCSP side of a run.
type ppMode int

const (
	ppOCSPUp   ppMode = iota + 1 // OCSP answers good
	ppOCSPDown                   // OCSP answers 503: the CRL fallback decides
)

// check serves the shape's revocation endpoints on a fresh fake network and
// runs the pipeline on [leaf]. arl replaces the DNIe ARL handler when non-nil;
// the DNIe root CRL is always served.
func (p *ppPKI) check(t *testing.T, reg *profiles.Registry, s ppShape, leaf *x509.Certificate, mode ppMode, arl http.Handler) (*Result, error) {
	t.Helper()
	issuer := p.issuer(s)
	var sites tSites
	for _, u := range s.ocsp {
		h := http.Handler(tUnavailable)
		if mode == ppOCSPUp {
			srv := testpki.NewOCSPServer(issuer, p.responders[issuer])
			srv.SetAnswer(func(testpki.Request) testpki.OCSPSpec {
				spec := testpki.OCSPSpec{Now: p.now, NextUpdate: p.now.Add(time.Hour)}
				if s.ocspEdit != nil {
					s.ocspEdit(p.now, &spec)
				}
				return spec
			})
			h = srv.Handler(t)
		}
		sites.handle(t, u, h)
	}
	crl := testpki.Bytes("application/pkix-crl", p.crls[issuer])
	for _, dp := range s.cdp {
		for _, u := range dp.URIs {
			if !strings.HasPrefix(u, "http://") {
				continue
			}
			to, ok := s.redirects[u]
			if !ok {
				sites.handle(t, u, crl)
				continue
			}
			sites.handle(t, u, testpki.Redirect(to))
			sites.handle(t, ppSiteURL(t, u, to), crl)
		}
	}
	if s.profile == "dnie-auth" {
		if arl == nil {
			arl = testpki.Bytes("application/pkix-crl", p.arl)
		}
		sites.handle(t, ppCRLURL, testpki.Redirect(ppCRLPath))
		sites.handle(t, ppSiteURL(t, ppCRLURL, ppCRLPath), testpki.Bytes("application/pkix-crl", p.dnieCRL))
		sites.handle(t, ppARLURL, testpki.Redirect(ppARLPath))
		sites.handle(t, ppSiteURL(t, ppARLURL, ppARLPath), arl)
	}
	chk := tChecker(t, reg, p.now, tRevocation(t, sites.net(t), p.now))
	return chk.Check(t.Context(), p.profiles[s.profile].ProviderID, []*x509.Certificate{leaf})
}

// ppSiteURL returns path on the host of base.
func ppSiteURL(t testing.TB, base, path string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + u.Host + path
}

// hasHTTPCDP reports whether the shape's leaf has an http CDP URL.
func (s ppShape) hasHTTPCDP() bool {
	return slices.ContainsFunc(s.cdp, func(dp testpki.DistributionPoint) bool {
		return slices.ContainsFunc(dp.URIs, func(u string) bool { return strings.HasPrefix(u, "http://") })
	})
}

func TestProfilesPipeline(t *testing.T) {
	t.Parallel()
	now := tNow()
	p := newPPPKI(t, now)
	reg := tRegistry(t, p.providers, now)
	shapes := ppShapes(t)

	covered := map[string]bool{}
	for _, s := range shapes {
		covered[s.profile] = true
	}
	var all []string
	for _, prov := range p.providers {
		for _, prof := range prov.Profiles {
			all = append(all, prof.ID)
			if !covered[prof.ID] {
				t.Errorf("profile %s has no synthetic leaf", prof.ID)
			}
		}
	}
	if len(all) != 19 || len(covered) != len(all) {
		t.Errorf("%d production profiles, %d covered; want 19 and all", len(all), len(covered))
	}

	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			leaf := p.issue(t, s)
			prof := p.profiles[s.profile]

			res, err := p.check(t, reg, s, leaf, ppOCSPUp, nil)
			if err != nil {
				t.Fatalf("Check error = %v, want success", err)
			}
			ppAssertResult(t, res, prof, s.want, s.want.method)

			if len(s.ocsp) == 0 || len(prof.Revocation.OCSPHosts) == 0 {
				return // no OCSP to fall back from
			}
			// CRL fallback: OCSP 503, then the CRL decides (fail closed without one).
			res, err = p.check(t, reg, s, leaf, ppOCSPDown, nil)
			if !s.hasHTTPCDP() {
				e := tErr(t, err)
				if e.Code != CodeRevocationUnavailable || e.Diagnostics.FailedStep != StepRevocation {
					t.Fatalf("fallback without an http CDP: got (%s at %s), want (%s at %s)", e.Code, e.Diagnostics.FailedStep, CodeRevocationUnavailable, StepRevocation)
				}
				return
			}
			if err != nil {
				t.Fatalf("fallback Check error = %v, want success through the CRL", err)
			}
			ppAssertResult(t, res, prof, s.want, revocation.MethodCRL)
			if !slices.ContainsFunc(res.Diagnostics.RevocationAttempts, func(a RevocationAttempt) bool {
				return a.Method == revocation.MethodOCSP && a.HTTPStatus == http.StatusServiceUnavailable
			}) {
				t.Errorf("fallback attempts = %+v, want an OCSP attempt answered 503", res.Diagnostics.RevocationAttempts)
			}
		})
	}
}

func ppAssertResult(t *testing.T, res *Result, prof profiles.Profile, want ppWant, method revocation.Method) {
	t.Helper()
	if res.Provider.ID != prof.ProviderID || res.Profile.ID != prof.ID || res.Profile.HolderRole != prof.HolderRole {
		t.Errorf("provider/profile = %+v/%+v, want %s/%s (%s)", res.Provider, res.Profile, prof.ProviderID, prof.ID, prof.HolderRole)
	}
	id := res.Identity
	if id.Document.Type != want.docType || id.Document.Number != want.doc || id.Document.Raw != want.raw || id.Document.Country != "ES" {
		t.Errorf("document = %+v, want %s %s (raw %s)", id.Document, want.docType, want.doc, want.raw)
	}
	if id.GivenNames != want.given || id.Surnames != want.surnames || id.FullName != want.given+" "+want.surnames {
		t.Errorf("names = %q / %q / %q, want %q / %q", id.GivenNames, id.Surnames, id.FullName, want.given, want.surnames)
	}
	if id.FirstSurname != want.first || id.SecondSurname != want.second {
		t.Errorf("first/second surname = %q/%q, want %q/%q", id.FirstSurname, id.SecondSurname, want.first, want.second)
	}
	if !reflect.DeepEqual(res.Organization, want.org) {
		t.Errorf("organization = %+v, want %+v", res.Organization, want.org)
	}
	if !reflect.DeepEqual(id.BirthDate, want.birth) {
		t.Errorf("birth date = %v, want %v", id.BirthDate, want.birth)
	}
	if res.Revocation.Status != revocation.StatusGood || res.Revocation.Method != method {
		t.Errorf("revocation = %s via %s, want good via %s", res.Revocation.Status, res.Revocation.Method, method)
	}
	if len(res.Diagnostics.RevocationAttempts) == 0 {
		t.Error("diagnostics carry no revocation attempt")
	}
}
