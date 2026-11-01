package identity_test

import (
	"encoding/asn1"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// Adapter shapes, copied from the per-profile declarations of Task 6
// (internal/profiles). Keep them in sync.

func fnmt5734(n int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 5734, 1, n}
}

func fnmtEmployeeOID(n int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 724, 1, 3, 5, 7, 2, n}
}

func fp13177OID(n int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 13177, 0, n}
}

var noSAN = identity.SANCheck{Kind: identity.SANNone}

func sanAttrs(docOID asn1.ObjectIdentifier, docRules []identity.DocumentRule, given, first, second asn1.ObjectIdentifier) identity.SANCheck {
	return identity.SANCheck{Kind: identity.SANAttributes, DocumentOID: docOID, DocumentRules: docRules,
		GivenNameOID: given, FirstSurnameOID: first, SecondSurnameOID: second}
}

func fnmtSAN(doc []identity.DocumentRule) identity.SANCheck {
	return sanAttrs(fnmt5734(4), doc, fnmt5734(1), fnmt5734(2), fnmt5734(3))
}

func fp13177SAN() identity.SANCheck {
	return sanAttrs(nil, nil, fp13177OID(1), fp13177OID(2), fp13177OID(3))
}

// shapePlain: DIGITEL, Bewor, Sectigo, ANF, Uanataca, Lleidanet.
func shapePlain() identity.Adapter {
	return identity.Adapter{Documents: idcesRules, Surnames: identity.SurnamesFromSN, SAN: noSAN,
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone}
}

func shapeFNMTCitizenRSA() identity.Adapter {
	return identity.Adapter{
		Documents: append(append([]identity.DocumentRule{}, idcesRules...), bareRules...),
		Surnames:  identity.SurnamesFromSN, SAN: fnmtSAN(bareRules),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
}

func shapeFNMTCitizenG2() identity.Adapter {
	a := shapeFNMTCitizenRSA()
	a.Documents = idcesRules
	return a
}

func shapeFNMTRepresentative() identity.Adapter {
	return identity.Adapter{Documents: idcesRules, Surnames: identity.SurnamesFromSN, SAN: fnmtSAN(idcesRules),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationFromSubject}
}

func shapeFNMTEmployee() identity.Adapter {
	n := fnmtEmployeeOID
	return identity.Adapter{Documents: idcesRules, Surnames: identity.SurnamesFromSN,
		SAN:       sanAttrs(n(4), bareRules, n(6), n(7), n(8)),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationFromSubject}
}

func shapeIDCATG2() identity.Adapter {
	a := shapePlain()
	a.CountryMatchesPrefix, a.LegacyDNISuffix = true, true
	return a
}

func shapeIDCATG3() identity.Adapter {
	a := shapePlain()
	a.CountryMatchesPrefix = true
	return a
}

func shapeACCV() identity.Adapter {
	return identity.Adapter{
		Documents: bareRules, Surnames: identity.SurnamesFromSN,
		SAN:       identity.SANCheck{Kind: identity.SANPipeCN, DocumentOID: identity.OIDUID, DocumentRules: bareRules},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
}

func shapeFirmaprofesional() identity.Adapter {
	a := shapePlain()
	a.SAN = fp13177SAN()
	return a
}

func shapeSIGNE() identity.Adapter {
	a := shapePlain()
	a.Documents = signeRules
	a.SAN = fp13177SAN()
	return a
}

func shapeDNIe() identity.Adapter {
	return identity.Adapter{
		Documents: bareDNIRules,
		Surnames:  identity.SurnamesDNIeCN, SAN: noSAN,
		BirthDate: identity.BirthDateOptional, Organization: identity.OrganizationNone,
	}
}

// Subject and SAN builders.

func rdnC(v string) testpki.RDN      { return testpki.Printable(identity.OIDCountry, v) }
func rdnSerial(v string) testpki.RDN { return testpki.Printable(identity.OIDSerialNumber, v) }
func rdnGN(v string) testpki.RDN     { return testpki.UTF8(identity.OIDGivenName, v) }
func rdnSN(v string) testpki.RDN     { return testpki.UTF8(identity.OIDSurname, v) }
func rdnCN(v string) testpki.RDN     { return testpki.UTF8(identity.OIDCommonName, v) }
func rdnO(v string) testpki.RDN      { return testpki.UTF8(identity.OIDOrganization, v) }
func rdnOrgID(v string) testpki.RDN  { return testpki.UTF8(identity.OIDOrganizationIdentifier, v) }

// person returns C=ES, serialNumber, GN, SN and a CN in the FNMT style.
func person(serial, given, surnames string) testpki.Name {
	return testpki.Name{rdnC("ES"), rdnSerial(serial), rdnGN(given), rdnSN(surnames), rdnCN(surnames + " " + given)}
}

func with(n testpki.Name, extra ...testpki.RDN) testpki.Name {
	return append(append(testpki.Name{}, n...), extra...)
}

// without returns n minus every RDN that holds oid.
func without(n testpki.Name, oid asn1.ObjectIdentifier) testpki.Name {
	var out testpki.Name
	for _, rdn := range n {
		if !rdn[0].OID.Equal(oid) {
			out = append(out, rdn)
		}
	}
	return out
}

// fnmtDir is an FNMT SAN directoryName: .1.4 doc, .1.3 second, .1.2 first,
// .1.1 given (descending, as AC FNMT Usuarios writes it). Empty values are
// omitted.
func fnmtDir(doc, given, first, second string) testpki.Name {
	var n testpki.Name
	for _, f := range []struct {
		arc int
		v   string
	}{{4, doc}, {3, second}, {2, first}, {1, given}} {
		if f.v != "" {
			n = append(n, testpki.UTF8(fnmt5734(f.arc), f.v))
		}
	}
	return n
}

// ascending reverses an RDN order (AC USUARIOS G2 writes .1.1 first).
func ascending(n testpki.Name) testpki.Name {
	out := append(testpki.Name{}, n...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func accvDir(cn, uid string) testpki.Name {
	n := testpki.Name{rdnCN(cn)}
	if uid != "" {
		n = append(n, testpki.UTF8(identity.OIDUID, uid))
	}
	return n
}

// Expected values.

const (
	srcDocument   = "subject.2.5.4.5"
	srcGivenNames = "subject.2.5.4.42"
	srcSN         = "subject.2.5.4.4"
	srcDNIeCN     = "subject.2.5.4.3 (DNIe CN grammar)"
)

func dniDoc(number, raw string) identity.Document {
	return identity.Document{Type: identity.DocumentDNI, Country: "ES", Number: number, Raw: raw, Source: srcDocument}
}

func nieDoc(number, raw string) identity.Document {
	return identity.Document{Type: identity.DocumentNIE, Country: "ES", Number: number, Raw: raw, Source: srcDocument}
}

// plainIdentity is an identity whose surnames come from SN with no split.
func plainIdentity(doc identity.Document, given, surnames string) identity.Identity {
	return identity.Identity{Document: doc, GivenNames: given, Surnames: surnames, FullName: given + " " + surnames,
		Sources: map[string]string{"document": srcDocument, "givenNames": srcGivenNames, "surnames": srcSN}}
}

// splitIdentity adds a first/second surname split with their sources.
func splitIdentity(doc identity.Document, given, surnames, first, second, firstSrc, secondSrc string) identity.Identity {
	id := plainIdentity(doc, given, surnames)
	id.FirstSurname, id.SecondSurname = first, second
	id.Sources["firstSurname"] = firstSrc
	if second != "" {
		id.Sources["secondSurname"] = secondSrc
	}
	return id
}

func fnmtIdentity(doc identity.Document, given, surnames, first, second string) identity.Identity {
	return splitIdentity(doc, given, surnames, first, second,
		"san.dirName.1.3.6.1.4.1.5734.1.2", "san.dirName.1.3.6.1.4.1.5734.1.3")
}

func dnieIdentity(doc identity.Document, given, surnames, first, second string) identity.Identity {
	id := identity.Identity{Document: doc, GivenNames: given, Surnames: surnames, FirstSurname: first, SecondSurname: second,
		FullName: given + " " + surnames,
		Sources:  map[string]string{"document": srcDocument, "givenNames": srcGivenNames, "surnames": srcDNIeCN, "firstSurname": srcSN}}
	if second != "" {
		id.Sources["secondSurname"] = srcDNIeCN
	}
	return id
}

func ext(id identity.Identity) identity.Extracted { return identity.Extracted{Identity: id} }

// adapterCase is one Adapter.Extract call on a testpki leaf.
type adapterCase struct {
	name    string
	adapter identity.Adapter
	spec    testpki.CertSpec
	want    identity.Extracted
	wantErr error
}

func adapterCases(tb testing.TB) []adapterCase {
	const (
		num   = "12345678Z"
		other = "87654321X" // a different valid DNI
		gn    = "JUAN"
		sn    = "GARCIA LOPEZ"
		sn1   = "GARCIA"
		sn2   = "LOPEZ"
	)
	idces := "IDCES-" + num
	fnmtOK := fnmtIdentity(dniDoc(num, idces), gn, sn, sn1, sn2)
	rsa, g2 := shapeFNMTCitizenRSA(), shapeFNMTCitizenG2()
	san := func(names ...testpki.Name) []testpki.Name { return names }
	invalid, unsupported := identity.ErrInvalid, identity.ErrUnsupportedDocument

	org := &identity.Organization{Name: "EMPRESA EJEMPLO SL", Identifier: "VATES-B00000000"}
	withOrg := func(id identity.Identity, o *identity.Organization) identity.Extracted {
		id.Sources["organization"] = "subject.2.5.4.10"
		if o.Identifier != "" {
			id.Sources["organizationIdentifier"] = "subject.2.5.4.97"
		}
		return identity.Extracted{Identity: id, Organization: o}
	}

	dnieSubject := func(serial, cn string) testpki.Name {
		return testpki.Name{rdnC("ES"), rdnSerial(serial), rdnSN("GARCÍA"), rdnGN("JOSÉ"), rdnCN(cn)}
	}
	const dnieCN = "GARCÍA LÓPEZ, JOSÉ (AUTENTICACIÓN)"
	dnieOK := dnieIdentity(dniDoc(num, num), "JOSÉ", "GARCÍA LÓPEZ", "GARCÍA", "LÓPEZ")
	dnieBorn := dnieIdentity(dniDoc(num, num), "JOSÉ", "GARCÍA LÓPEZ", "GARCÍA", "LÓPEZ")
	dnieBorn.BirthDate = &identity.Date{Year: 1980, Month: time.January, Day: 1}
	dnieBorn.Sources["birthDate"] = "sda.1.3.6.1.5.5.7.9.1"

	idcatQuirk := plainIdentity(dniDoc(num, idces), gn, sn)
	idcatQuirk.Sources["surnamesQuirk"] = "legacy ' - DNI <id>' suffix removed"

	accvOK := splitIdentity(dniDoc(num, num), gn, sn, sn1, sn2, "san.dirName.2.5.4.3[1]", "san.dirName.2.5.4.3[2]")
	employee := splitIdentity(dniDoc(num, idces), gn, sn, sn1, sn2,
		"san.dirName.2.16.724.1.3.5.7.2.7", "san.dirName.2.16.724.1.3.5.7.2.8")
	fpOK := splitIdentity(dniDoc(num, idces), gn, sn, sn1, sn2,
		"san.dirName.1.3.6.1.4.1.13177.0.2", "san.dirName.1.3.6.1.4.1.13177.0.3")
	empDir := func(doc string) testpki.Name {
		n := fnmtEmployeeOID
		return testpki.Name{testpki.UTF8(n(4), doc), testpki.UTF8(n(6), gn), testpki.UTF8(n(7), sn1), testpki.UTF8(n(8), sn2)}
	}
	fpDir := testpki.Name{testpki.UTF8(fp13177OID(1), gn), testpki.UTF8(fp13177OID(2), sn1), testpki.UTF8(fp13177OID(3), sn2)}

	malformedNote := ext(plainIdentity(dniDoc(num, idces), gn, sn))
	malformedNote.Notes = []string{"malformed SubjectDirectoryAttributes ignored"}

	bmpKinds := shapePlain()
	bmpKinds.Kinds = identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP}

	cases := []adapterCase{
		// FNMT citizen, AC FNMT Usuarios (RSA): IDCES- or bare, SAN 5734.1.4 bare.
		{name: "fnmt-rsa IDCES, SAN descending", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))}, want: ext(fnmtOK)},
		{name: "fnmt-rsa IDCES, SAN ascending", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(ascending(fnmtDir(num, gn, sn1, sn2)))}, want: ext(fnmtOK)},
		{name: "fnmt-rsa bare (2016 kit), SAN descending", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))},
			want: ext(fnmtIdentity(dniDoc(num, num), gn, sn, sn1, sn2))},
		{name: "fnmt-rsa bare, SAN ascending", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(ascending(fnmtDir(num, gn, sn1, sn2)))},
			want: ext(fnmtIdentity(dniDoc(num, num), gn, sn, sn1, sn2))},
		{name: "fnmt-rsa NIE", adapter: rsa,
			spec: testpki.CertSpec{Subject: person("IDCES-X1234567L", gn, sn), SANDirNames: san(fnmtDir("X1234567L", gn, sn1, sn2))},
			want: ext(fnmtIdentity(nieDoc("X1234567L", "IDCES-X1234567L"), gn, sn, sn1, sn2))},
		{name: "fnmt-rsa single surname, SAN second surname absent", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn1), SANDirNames: san(fnmtDir(num, gn, sn1, ""))},
			want: ext(fnmtIdentity(dniDoc(num, idces), gn, sn1, sn1, ""))},
		{name: "fnmt-rsa single surname, SAN second surname empty", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn1), SANDirNames: san(with(fnmtDir(num, gn, sn1, ""), testpki.UTF8(fnmt5734(3), "")))},
			want: ext(fnmtIdentity(dniDoc(num, idces), gn, sn1, sn1, ""))},
		{name: "fnmt-rsa SAN split over two dirNames", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, "", "", ""), fnmtDir("", gn, sn1, sn2))}, want: ext(fnmtOK)},
		{name: "fnmt-rsa SAN repeated identically in two dirNames", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, sn1, sn2), fnmtDir(num, gn, sn1, sn2))}, want: ext(fnmtOK)},
		{name: "fnmt-rsa SAN differs from SN only in accents and case (R32)", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, "GARCIA DIEZ"), SANDirNames: san(fnmtDir(num, "Juan", sn1, "DÍEZ"))},
			want: ext(fnmtIdentity(dniDoc(num, idces), gn, "GARCIA DIEZ", sn1, "DÍEZ"))},
		{name: "fnmt-rsa SAN .1.4 disagrees", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(other, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN .1.4 IDCES-prefixed (bare rule)", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN .1.4 bad checksum", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir("12345678A", gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN .1.4 absent", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir("", gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN given name disagrees", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, "PEDRO", sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN given name absent", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, "", sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN second surname disagrees", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, sn1, "LOPES"))}, wantErr: invalid},
		{name: "fnmt-rsa SAN second surname absent but SN has two", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, sn1, ""))}, wantErr: invalid},
		{name: "fnmt-rsa SAN surnames swapped", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, sn2, sn1))}, wantErr: invalid},
		{name: "fnmt-rsa SAN first surname absent", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, "", sn2))}, wantErr: invalid},
		// The conflicting value comes first: a last-wins reader would see an
		// agreeing SAN, so only the duplicate rule rejects these.
		{name: "fnmt-rsa SAN conflicting surname across dirNames", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir("", "", "PEREZ", ""), fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN conflicting document across dirNames", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(other, "", "", ""), fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN conflicting given name across dirNames", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir("", "PEDRO", "", ""), fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "accv SAN conflicting UID across dirNames", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2, other), accvDir(gn+"|"+sn1+"|"+sn2, num))}, wantErr: invalid},
		{name: "fnmt-rsa SAN missing", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn)}, wantErr: invalid},
		{name: "fnmt-rsa SAN without a dirName", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANEmails: []string{"ca-mailbox@example.org"}}, wantErr: invalid},
		{name: "fnmt-rsa SAN malformed dirName", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANRaw: seqDER(tlv(0xa4, seqDER(setDER())))}, wantErr: invalid},
		{name: "fnmt-rsa serialNumber absent", adapter: rsa,
			spec: testpki.CertSpec{Subject: without(person(idces, gn, sn), identity.OIDSerialNumber), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa conflicting serialNumber duplicates", adapter: rsa,
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnSerial("IDCES-"+other)), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa GN absent", adapter: rsa,
			spec: testpki.CertSpec{Subject: without(person(idces, gn, sn), identity.OIDGivenName), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SN blank", adapter: rsa,
			spec: testpki.CertSpec{Subject: with(without(person(idces, gn, sn), identity.OIDSurname), rdnSN("   ")), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa GN as BMPString", adapter: rsa,
			spec: testpki.CertSpec{Subject: with(without(person(idces, gn, sn), identity.OIDGivenName), testpki.Tagged(identity.OIDGivenName, testpki.TagBMP, gn)),
				SANDirNames: san(fnmtDir(num, gn, sn1, sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN surname as BMPString", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn),
				SANDirNames: san(testpki.Name{testpki.UTF8(fnmt5734(4), num), testpki.UTF8(fnmt5734(1), gn), testpki.Tagged(fnmt5734(2), testpki.TagBMP, sn1), testpki.UTF8(fnmt5734(3), sn2)})},
			wantErr: invalid},
		{name: "fnmt-rsa passport", adapter: rsa,
			spec: testpki.CertSpec{Subject: person("PASES-AB123456", gn, sn), SANDirNames: san(fnmtDir("AB123456", gn, sn1, sn2))}, wantErr: unsupported},

		// FNMT citizen, AC USUARIOS G2: IDCES- only.
		{name: "fnmt-g2 IDCES, SAN ascending", adapter: g2,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(ascending(fnmtDir(num, gn, sn1, sn2)))}, want: ext(fnmtOK)},
		{name: "fnmt-g2 bare", adapter: g2,
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(ascending(fnmtDir(num, gn, sn1, sn2)))}, wantErr: invalid},

		// FNMT representative: SAN .1.4 = IDCES-<id>, organization from the subject.
		{name: "fnmt-representative", adapter: shapeFNMTRepresentative(),
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("EMPRESA  EJEMPLO SL"), rdnOrgID("VATES-B00000000")),
				SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))},
			want: withOrg(fnmtIdentity(dniDoc(num, idces), gn, sn, sn1, sn2), org)},
		{name: "fnmt-representative without organizationIdentifier", adapter: shapeFNMTRepresentative(),
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("EMPRESA EJEMPLO SL")), SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))},
			want: withOrg(fnmtIdentity(dniDoc(num, idces), gn, sn, sn1, sn2), &identity.Organization{Name: "EMPRESA EJEMPLO SL"})},
		// R5.5 (U7-FABLE-4): the identifier is normalised like every other
		// string, and a blank one records no source.
		{name: "fnmt-representative blank organizationIdentifier", adapter: shapeFNMTRepresentative(),
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("EMPRESA EJEMPLO SL"), rdnOrgID("   ")), SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))},
			want: withOrg(fnmtIdentity(dniDoc(num, idces), gn, sn, sn1, sn2), &identity.Organization{Name: "EMPRESA EJEMPLO SL"})},
		{name: "fnmt-representative organizationIdentifier inner spaces", adapter: shapeFNMTRepresentative(),
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("EMPRESA EJEMPLO SL"), rdnOrgID(" VATES-B00000000  X ")), SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))},
			want: withOrg(fnmtIdentity(dniDoc(num, idces), gn, sn, sn1, sn2), &identity.Organization{Name: "EMPRESA EJEMPLO SL", Identifier: "VATES-B00000000 X"})},
		{name: "fnmt-representative O missing", adapter: shapeFNMTRepresentative(),
			spec:    testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnOrgID("VATES-B00000000")), SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))},
			wantErr: invalid},
		{name: "fnmt-representative O blank", adapter: shapeFNMTRepresentative(),
			spec:    testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("  ")), SANDirNames: san(fnmtDir(idces, gn, sn1, sn2))},
			wantErr: invalid},
		{name: "fnmt-representative SAN .1.4 bare", adapter: shapeFNMTRepresentative(),
			spec:    testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("EMPRESA EJEMPLO SL")), SANDirNames: san(fnmtDir(num, gn, sn1, sn2))},
			wantErr: invalid},

		// FNMT public employee: SAN 2.16.724.1.3.5.7.2.{4,6,7,8}.
		{name: "fnmt-employee", adapter: shapeFNMTEmployee(),
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("AYUNTAMIENTO EJEMPLO"), rdnOrgID("VATES-P0000000J")), SANDirNames: san(empDir(num))},
			want: withOrg(employee, &identity.Organization{Name: "AYUNTAMIENTO EJEMPLO", Identifier: "VATES-P0000000J"})},
		{name: "fnmt-employee SAN document disagrees", adapter: shapeFNMTEmployee(),
			spec:    testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnO("AYUNTAMIENTO EJEMPLO")), SANDirNames: san(empDir(other))},
			wantErr: invalid},

		// idCAT: C must match the IDC country; G2 strips the legacy suffix.
		{name: "idcat-g2 IDCES, C=ES", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn)}, want: ext(plainIdentity(dniDoc(num, idces), gn, sn))},
		{name: "idcat-g2 C=FR", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: with(without(person(idces, gn, sn), identity.OIDCountry), rdnC("FR"))}, wantErr: invalid},
		{name: "idcat-g2 C absent", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: without(person(idces, gn, sn), identity.OIDCountry)}, wantErr: invalid},
		{name: "idcat-g2 IDCFR", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: with(without(person("IDCFR-123456789", gn, sn), identity.OIDCountry), rdnC("FR"))}, wantErr: unsupported},
		{name: "idcat-g2 legacy suffix with the document number", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn+" - DNI "+num)}, want: ext(idcatQuirk)},
		{name: "idcat-g2 legacy suffix with another number", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn+" - DNI "+other)},
			want: ext(plainIdentity(dniDoc(num, idces), gn, sn+" - DNI "+other))},
		{name: "idcat-g2 legacy suffix with the raw identifier", adapter: shapeIDCATG2(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn+" - DNI "+idces)},
			want: ext(plainIdentity(dniDoc(num, idces), gn, sn+" - DNI "+idces))},
		{name: "idcat-g3 legacy suffix kept (flag off)", adapter: shapeIDCATG3(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn+" - DNI "+num)},
			want: ext(plainIdentity(dniDoc(num, idces), gn, sn+" - DNI "+num))},

		// ACCV: bare document, SAN CN "GIVEN|SURNAME1|SURNAME2" plus UID.
		{name: "accv", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2, num))}, want: ext(accvOK)},
		{name: "accv empty second surname", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn1), SANDirNames: san(accvDir(gn+"|"+sn1+"|", num))},
			want: ext(splitIdentity(dniDoc(num, num), gn, sn1, sn1, "", "san.dirName.2.5.4.3[1]", ""))},
		{name: "accv two fields", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn1), SANDirNames: san(accvDir(gn+"|"+sn1, num))}, wantErr: invalid},
		{name: "accv four fields", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2+"|", num))}, wantErr: invalid},
		{name: "accv SAN given name differs", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir("PEDRO|"+sn1+"|"+sn2, num))}, wantErr: invalid},
		{name: "accv SAN surnames differ", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|PEREZ", num))}, wantErr: invalid},
		{name: "accv SAN empty first surname", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn2), SANDirNames: san(accvDir(gn+"||"+sn2, num))}, wantErr: invalid},
		{name: "accv UID differs from serialNumber", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2, other))}, wantErr: invalid},
		{name: "accv UID absent", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2, ""))}, wantErr: invalid},
		{name: "accv SAN CN absent", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn), SANDirNames: san(testpki.Name{testpki.UTF8(identity.OIDUID, num)})}, wantErr: invalid},
		{name: "accv IDCES subject", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2, num))}, wantErr: invalid},
		{name: "accv K NIF", adapter: shapeACCV(),
			spec: testpki.CertSpec{Subject: person("K1234567L", gn, sn), SANDirNames: san(accvDir(gn+"|"+sn1+"|"+sn2, "K1234567L"))}, wantErr: unsupported},

		// Firmaprofesional: SAN 13177.0.{1,2,3}, no SAN document.
		{name: "firmaprofesional", adapter: shapeFirmaprofesional(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fpDir)}, want: ext(fpOK)},
		{name: "firmaprofesional SAN first surname absent", adapter: shapeFirmaprofesional(),
			spec:    testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(testpki.Name{testpki.UTF8(fp13177OID(1), gn), testpki.UTF8(fp13177OID(3), sn2)})},
			wantErr: invalid},

		// SIGNE: IDCES-<DNI> or PNOES-<NIE>.
		{name: "signe PNOES NIE", adapter: shapeSIGNE(),
			spec: testpki.CertSpec{Subject: person("PNOES-X1234567L", gn, sn), SANDirNames: san(fpDir)},
			want: ext(splitIdentity(nieDoc("X1234567L", "PNOES-X1234567L"), gn, sn, sn1, sn2,
				"san.dirName.1.3.6.1.4.1.13177.0.2", "san.dirName.1.3.6.1.4.1.13177.0.3"))},
		{name: "signe IDCES DNI", adapter: shapeSIGNE(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fpDir)}, want: ext(fpOK)},
		{name: "signe IDCES NIE", adapter: shapeSIGNE(),
			spec: testpki.CertSpec{Subject: person("IDCES-X1234567L", gn, sn), SANDirNames: san(fpDir)}, wantErr: invalid},

		// DNIe: bare DNI, SN = first surname, complete surnames from the CN grammar.
		{name: "dnie accented suffix", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN)}, want: ext(dnieOK)},
		{name: "dnie unaccented suffix", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ, JOSÉ (AUTENTICACION)")}, want: ext(dnieOK)},
		{name: "dnie decomposed accents", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCI\u0301A LO\u0301PEZ, JOSE\u0301 (AUTENTICACIO\u0301N)")}, want: ext(dnieOK)},
		{name: "dnie single surname", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA, JOSÉ (AUTENTICACIÓN)")},
			want: ext(dnieIdentity(dniDoc(num, num), "JOSÉ", "GARCÍA", "GARCÍA", ""))},
		{name: "dnie birth date", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), DateOfBirth: "19800101120000Z"}, want: ext(dnieBorn)},
		{name: "dnie malformed birth date", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), DateOfBirth: "19800230120000Z"}, wantErr: invalid},
		// R10.2 (U6-FABLE-2): the birth date is from 1900 on and not after NotBefore.
		{name: "dnie birth date after the certificate validity start", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), DateOfBirth: "29990101000000Z"}, wantErr: invalid},
		{name: "dnie birth date before 1900", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), DateOfBirth: "18991231235959Z"}, wantErr: invalid},
		{name: "dnie birth date on the NotBefore day", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), DateOfBirth: "19800101120000Z",
				NotBefore: time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)}, want: ext(dnieBorn)},
		{name: "dnie birth date the day after NotBefore", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), DateOfBirth: "19800101120000Z",
				NotBefore: time.Date(1979, time.December, 31, 23, 59, 59, 0, time.UTC)}, wantErr: invalid},
		{name: "dnie SDA attribute with a trailing element", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), SDARaw: sdaTrailingDOB(tb, []byte{0x05, 0x00})}, wantErr: invalid},
		{name: "dnie SDA attribute with empty values", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, dnieCN), SDARaw: sdaEmptyResidence(tb)}, wantErr: invalid},
		{name: "dnie CN does not start with SN", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "LÓPEZ GARCÍA, JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "dnie CN surname only shares a prefix with SN", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍAS LÓPEZ, JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "dnie CN with another given name", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ, PEDRO (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "dnie CN without the comma separator", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ,JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		// R5.3 (U7-FABLE-1): the surnames are a plain word sequence.
		{name: "dnie CN space before comma", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ , JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "dnie CN surnames with an extra comma segment", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ, PEDRO, JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "dnie CN surnames with a parenthesised token", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ (FIRMA), JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "dnie CN without suffix", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ, JOSÉ")}, wantErr: invalid},
		{name: "dnie CN with FIRMA suffix", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ, JOSÉ (FIRMA)")}, wantErr: invalid},
		{name: "dnie CN with lower-case suffix", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA LÓPEZ, JOSÉ (autenticación)")}, wantErr: invalid},
		{name: "dnie CN absent", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: without(dnieSubject(num, dnieCN), identity.OIDCommonName)}, wantErr: invalid},
		{name: "dnie NIE", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject("X1234567L", dnieCN)}, wantErr: invalid},
		{name: "dnie IDCES", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(idces, dnieCN)}, wantErr: invalid},

		// Plain profiles (DIGITEL and others).
		{name: "plain", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn)}, want: ext(plainIdentity(dniDoc(num, idces), gn, sn))},
		{name: "plain names normalized", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, " JOSE\u0301  MARI\u0301A ", "  GARCIA   LOPEZ ")},
			want: ext(plainIdentity(dniDoc(num, idces), "JOS\u00c9 MAR\u00cdA", sn))},
		{name: "plain malformed SDA noted", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), DateOfBirth: "19800230120000Z"}, want: malformedNote},
		{name: "plain SDA attribute with a trailing element noted", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SDARaw: sdaTrailingDOB(tb, []byte{0x05, 0x00})}, want: malformedNote},
		{name: "plain SDA attribute with empty values noted", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SDARaw: sdaEmptyResidence(tb)}, want: malformedNote},
		{name: "plain valid SDA ignored", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), DateOfBirth: "19800101120000Z"}, want: ext(plainIdentity(dniDoc(num, idces), gn, sn))},
		{name: "plain BMPString GN rejected", adapter: shapePlain(),
			spec:    testpki.CertSpec{Subject: with(without(person(idces, gn, sn), identity.OIDGivenName), testpki.Tagged(identity.OIDGivenName, testpki.TagBMP, gn))},
			wantErr: invalid},
		{name: "plain BMPString GN with a Kinds override", adapter: bmpKinds,
			spec: testpki.CertSpec{Subject: with(without(person(idces, gn, sn), identity.OIDGivenName), testpki.Tagged(identity.OIDGivenName, testpki.TagBMP, gn))},
			want: ext(plainIdentity(dniDoc(num, idces), gn, sn))},
		{name: "plain bare rejected", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(num, gn, sn)}, wantErr: invalid},
		{name: "plain NIE", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person("IDCES-Z1234567R", gn, sn)}, want: ext(plainIdentity(nieDoc("Z1234567R", "IDCES-Z1234567R"), gn, sn))},
		{name: "plain conflicting GN duplicates", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: with(person(idces, gn, sn), rdnGN("PEDRO"))}, wantErr: invalid},
		{name: "plain multi-valued RDN", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: testpki.Name{rdnC("ES"), {
				{OID: identity.OIDSerialNumber, Value: idces, Tag: testpki.TagPrintable},
				{OID: identity.OIDGivenName, Value: gn},
				{OID: identity.OIDSurname, Value: sn},
			}}},
			want: ext(plainIdentity(dniDoc(num, idces), gn, sn))},

		// R53 control: Spanish and Catalan names pass on both paths.
		{name: "plain Spanish and Catalan names", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, "MARÍA ÀNGELS", "D'ARBÓS-GÜELL COL·L PEÑA ÇALÓ")},
			want: ext(plainIdentity(dniDoc(num, idces), "MARÍA ÀNGELS", "D'ARBÓS-GÜELL COL·L PEÑA ÇALÓ"))},
		{name: "fnmt-rsa Spanish and Catalan names", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, "MARÍA ÀNGELS", "D'ARBÓS-GÜELL COL·L PEÑA"),
				SANDirNames: san(fnmtDir(num, "MARÍA ÀNGELS", "D'ARBÓS-GÜELL", "COL·L PEÑA"))},
			want: ext(fnmtIdentity(dniDoc(num, idces), "MARÍA ÀNGELS", "D'ARBÓS-GÜELL COL·L PEÑA", "D'ARBÓS-GÜELL", "COL·L PEÑA"))},
		{name: "fnmt-rsa decomposed Catalan names in the SAN", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, "NÚRIA", "ÇALÓ COL·L"),
				SANDirNames: san(fnmtDir(num, "NU\u0301RIA", "C\u0327ALO\u0301", "COL·L"))},
			want: ext(fnmtIdentity(dniDoc(num, idces), "NÚRIA", "ÇALÓ COL·L", "ÇALÓ", "COL·L"))},

		// R5.1 (U6-ASTRA-1): a name needs a letter, and a long combining run
		// is rejected on both paths.
		{name: "plain subject GN invisible only", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, "\u034f", sn)}, wantErr: invalid},
		{name: "plain subject GN a lone combining mark", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, "\u0301", sn)}, wantErr: invalid},
		{name: "plain subject SN punctuation only", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, "- ·")}, wantErr: invalid},
		{name: "plain subject SN long combining run", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, gn, "GARCI"+strings.Repeat("\u0301", 5)+"A LOPEZ")}, wantErr: invalid},
		{name: "fnmt-rsa SAN first surname without a letter", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, "- "+sn2), SANDirNames: san(fnmtDir(num, gn, "-", sn2))}, wantErr: invalid},
		{name: "fnmt-rsa SAN second surname without a letter", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn1+" -"), SANDirNames: san(fnmtDir(num, gn, sn1, "-"))}, wantErr: invalid},
		{name: "dnie CN second surname without a letter", adapter: shapeDNIe(),
			spec: testpki.CertSpec{Subject: dnieSubject(num, "GARCÍA -, JOSÉ (AUTENTICACIÓN)")}, wantErr: invalid},
		{name: "fnmt-rsa SAN first surname long combining run", adapter: rsa,
			spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, gn, "GARCI"+strings.Repeat("\u0301", 5)+"A", sn2))}, wantErr: invalid},

		// R10.1 (U6-FABLE-1): a Cyrillic homoglyph in a Latin name is
		// rejected; a wholly Cyrillic name is not.
		{name: "plain subject GN with a Cyrillic A", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, "PRUEB\u0410S", sn)}, wantErr: invalid},
		{name: "plain wholly Cyrillic names", adapter: shapePlain(),
			spec: testpki.CertSpec{Subject: person(idces, "\u0418\u0412\u0410\u041d", "\u041f\u0415\u0422\u0420\u041e\u0412")}, want: ext(plainIdentity(dniDoc(num, idces), "\u0418\u0412\u0410\u041d", "\u041f\u0415\u0422\u0420\u041e\u0412"))},
	}
	// R53: each rejected class, in a subject attribute and in a SAN
	// dirName attribute. NBSP and the other spaces matter most here: before
	// R53, NormalizeName folded them into an agreeing value.
	for _, ic := range invisibleChars {
		bad := "JU" + string(ic.r) + "AN"
		cases = append(cases,
			adapterCase{name: "plain subject GN " + ic.name, adapter: shapePlain(),
				spec: testpki.CertSpec{Subject: person(idces, bad, sn)}, wantErr: invalid},
			adapterCase{name: "fnmt-rsa SAN given name " + ic.name, adapter: rsa,
				spec: testpki.CertSpec{Subject: person(idces, gn, sn), SANDirNames: san(fnmtDir(num, bad, sn1, sn2))}, wantErr: invalid},
		)
	}
	return cases
}

func TestAdapterExtract(t *testing.T) {
	ca := testpki.NewRoot(t, "identity-root", testpki.CertSpec{})
	for _, tc := range adapterCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			leaf := ca.Leaf(t, tc.spec)
			got, err := tc.adapter.Extract(leaf.Cert)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Extract err = %v, want %v", err, tc.wantErr)
				}
				other := identity.ErrInvalid
				if tc.wantErr == identity.ErrInvalid {
					other = identity.ErrUnsupportedDocument
				}
				if errors.Is(err, other) {
					t.Errorf("Extract err = %v also wraps %v", err, other)
				}
				if !reflect.DeepEqual(got, identity.Extracted{}) {
					t.Errorf("Extract returned %+v with an error, want zero", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract err = %v, want nil", err)
			}
			id := got.Identity
			if want := id.GivenNames + " " + id.Surnames; id.FullName != want {
				t.Errorf("FullName = %q, want GivenNames + \" \" + Surnames = %q", id.FullName, want)
			}
			for _, v := range []string{id.GivenNames, id.Surnames, id.FirstSurname, id.SecondSurname} {
				if v != identity.NormalizeName(v) {
					t.Errorf("name %q is not normalised", v)
				}
			}
			if !maps.Equal(id.Sources, tc.want.Identity.Sources) {
				t.Errorf("Sources:\n got %v\nwant %v", id.Sources, tc.want.Identity.Sources)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Extract:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestAdapterValidate(t *testing.T) {
	mutate := func(a identity.Adapter, f func(*identity.Adapter)) identity.Adapter {
		f(&a)
		return a
	}
	tests := []struct {
		name    string
		adapter identity.Adapter
		wantErr bool
	}{
		{"plain", shapePlain(), false},
		{"fnmt-rsa", shapeFNMTCitizenRSA(), false},
		{"fnmt-g2", shapeFNMTCitizenG2(), false},
		{"fnmt-representative", shapeFNMTRepresentative(), false},
		{"fnmt-employee", shapeFNMTEmployee(), false},
		{"idcat-g2", shapeIDCATG2(), false},
		{"idcat-g3", shapeIDCATG3(), false},
		{"accv", shapeACCV(), false},
		{"firmaprofesional", shapeFirmaprofesional(), false},
		{"signe", shapeSIGNE(), false},
		{"dnie", shapeDNIe(), false},
		{"zero value", identity.Adapter{}, true},
		{"no document rules", mutate(shapePlain(), func(a *identity.Adapter) { a.Documents = nil }), true},
		{"unset surname rule", mutate(shapePlain(), func(a *identity.Adapter) { a.Surnames = 0 }), true},
		{"unset SAN kind", mutate(shapePlain(), func(a *identity.Adapter) { a.SAN = identity.SANCheck{} }), true},
		{"unset birth date rule", mutate(shapePlain(), func(a *identity.Adapter) { a.BirthDate = 0 }), true},
		{"unset organization rule", mutate(shapePlain(), func(a *identity.Adapter) { a.Organization = 0 }), true},
		{"SANPipeCN without DocumentOID", mutate(shapeACCV(), func(a *identity.Adapter) { a.SAN.DocumentOID = nil }), true},
		{"SAN document without rules", mutate(shapeFNMTCitizenRSA(), func(a *identity.Adapter) { a.SAN.DocumentRules = nil }), true},

		// R5.4 (U7-FABLE-2): enums are bounded and Extract's inputs required.
		{"kinds override", mutate(shapePlain(), func(a *identity.Adapter) {
			a.Kinds = identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP}
		}), false},
		{"surname rule out of range", mutate(shapePlain(), func(a *identity.Adapter) { a.Surnames = 99 }), true},
		{"negative surname rule", mutate(shapePlain(), func(a *identity.Adapter) { a.Surnames = -1 }), true},
		{"SAN kind out of range", mutate(shapePlain(), func(a *identity.Adapter) { a.SAN.Kind = 99 }), true},
		{"birth date rule out of range", mutate(shapePlain(), func(a *identity.Adapter) { a.BirthDate = 99 }), true},
		{"organization rule out of range", mutate(shapePlain(), func(a *identity.Adapter) { a.Organization = 99 }), true},
		{"SANAttributes without FirstSurnameOID", mutate(shapeFNMTCitizenRSA(), func(a *identity.Adapter) { a.SAN.FirstSurnameOID = nil }), true},
		{"document rule without types", mutate(shapePlain(), func(a *identity.Adapter) {
			a.Documents = []identity.DocumentRule{{Encoding: identity.EncodingIDCES}}
		}), true},
		{"document rule with an unknown encoding", mutate(shapePlain(), func(a *identity.Adapter) {
			a.Documents = []identity.DocumentRule{{Encoding: "IDCFR", Types: dniNIE}}
		}), true},
		{"document rule with an unknown type", mutate(shapePlain(), func(a *identity.Adapter) {
			a.Documents = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{"PASSPORT"}}}
		}), true},
		{"SAN document rule without types", mutate(shapeFNMTCitizenRSA(), func(a *identity.Adapter) {
			a.SAN.DocumentRules = []identity.DocumentRule{{Encoding: identity.EncodingBare}}
		}), true},
		{"empty KindSet", mutate(shapePlain(), func(a *identity.Adapter) { a.Kinds = identity.KindSet{} }), true},
		{"KindOther in KindSet", mutate(shapePlain(), func(a *identity.Adapter) { a.Kinds = identity.KindSet{identity.KindUTF8, identity.KindOther} }), true},
		{"unset kind in KindSet", mutate(shapePlain(), func(a *identity.Adapter) { a.Kinds = identity.KindSet{identity.KindUTF8, 0} }), true},
	}
	ca := testpki.NewRoot(t, "validate-root", testpki.CertSpec{})
	leaf := ca.Leaf(t, testpki.CertSpec{Subject: person("IDCES-12345678Z", "JUAN", "GARCIA LOPEZ")})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.adapter.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate err = %v, want error %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}
			// R54: configuration errors wrap ErrInvalid like every other error.
			if !errors.Is(err, identity.ErrInvalid) || errors.Is(err, identity.ErrUnsupportedDocument) {
				t.Errorf("Validate err = %v, want ErrInvalid only", err)
			}
			_, xerr := tc.adapter.Extract(leaf.Cert)
			if xerr == nil || xerr.Error() != err.Error() {
				t.Errorf("Extract err = %v, want the Validate error %v", xerr, err)
			}
			if !errors.Is(xerr, identity.ErrInvalid) {
				t.Errorf("Extract err = %v, want ErrInvalid", xerr)
			}
		})
	}
}

// leakValues returns the inputs an error must not echo: every value of at
// least 4 bytes, and the part after a typed prefix's dash.
func leakValues(values ...string) []string {
	var out []string
	add := func(v string) {
		if len(strings.TrimSpace(v)) >= 4 {
			out = append(out, v)
		}
	}
	for _, v := range values {
		add(v)
		if _, after, ok := strings.Cut(v, "-"); ok {
			add(after)
		}
	}
	return out
}

func nameValues(names ...testpki.Name) []string {
	var out []string
	for _, n := range names {
		for _, rdn := range n {
			for _, a := range rdn {
				out = append(out, a.Value)
			}
		}
	}
	return out
}

func assertNoValues(t *testing.T, err error, values []string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, v := range leakValues(values...) {
		if strings.Contains(msg, v) {
			t.Errorf("error %q contains the input value %q", msg, v)
		}
	}
}

func TestErrorsCarryNoValues(t *testing.T) {
	t.Run("ParseDocument", func(t *testing.T) {
		for _, tc := range parseDocumentCases() {
			if tc.wantErr == nil {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				_, err := identity.ParseDocument(tc.value, "subject.2.5.4.5", tc.rules)
				assertNoValues(t, err, []string{tc.value, strings.TrimSpace(tc.value)})
			})
		}
	})

	t.Run("Name.Field", func(t *testing.T) {
		var cases []fieldCase
		cases = append(cases, nameFieldKindsCases(t)...)
		cases = append(cases, nameFieldTextCases(t)...)
		cases = append(cases, nameFieldDuplicateCases(t)...)
		for _, tc := range cases {
			if tc.wantErr == nil {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				kinds := tc.kinds
				if kinds == nil {
					kinds = identity.DefaultKinds
				}
				_, _, err := mustParseName(t, tc.der).Field(tc.oid, kinds)
				assertNoValues(t, err, tc.values)
			})
		}
	})

	t.Run("ParseDateOfBirth", func(t *testing.T) {
		for _, tc := range dateOfBirthCases(t) {
			if !tc.wantErr {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				_, _, err := identity.ParseDateOfBirth(tc.der)
				assertNoValues(t, err, tc.values)
			})
		}
	})

	t.Run("Adapter.Extract", func(t *testing.T) {
		ca := testpki.NewRoot(t, "leak-root", testpki.CertSpec{})
		for _, tc := range adapterCases(t) {
			if tc.wantErr == nil {
				continue
			}
			t.Run(tc.name, func(t *testing.T) {
				leaf := ca.Leaf(t, tc.spec)
				_, err := tc.adapter.Extract(leaf.Cert)
				values := nameValues(append([]testpki.Name{tc.spec.Subject}, tc.spec.SANDirNames...)...)
				assertNoValues(t, err, append(values, tc.spec.DateOfBirth))
			})
		}
	})
}
