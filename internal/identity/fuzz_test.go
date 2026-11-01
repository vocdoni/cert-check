package identity_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// allKinds accepts every string kind, so Field exercises the text checks.
var allKinds = identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP, identity.KindTeletex, identity.KindIA5}

// specimenExtension returns the value of extension oid, or nil.
func specimenExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e.Value
		}
	}
	return nil
}

func specimenCerts(f *testing.F) []*x509.Certificate {
	f.Helper()
	var certs []*x509.Certificate
	for _, file := range specimenFiles(f) {
		certs = append(certs, loadSpecimen(f, file))
	}
	return certs
}

// checkFieldsStable reads every attribute of n twice with each kind set and
// requires identical results.
func checkFieldsStable(t *testing.T, n identity.Name) {
	t.Helper()
	for _, a := range n.Attributes {
		for _, kinds := range []identity.KindSet{identity.DefaultKinds, allKinds} {
			v1, ok1, err1 := n.Field(a.OID, kinds)
			v2, ok2, err2 := n.Field(a.OID, kinds)
			if v1 != v2 || ok1 != ok2 || (err1 == nil) != (err2 == nil) {
				t.Fatalf("Field(%s) not stable: (%q, %v, %v) then (%q, %v, %v)", a.OID, v1, ok1, err1, v2, ok2, err2)
			}
			if !ok1 {
				t.Fatalf("Field(%s) found = false for a present attribute", a.OID)
			}
			if err1 != nil && !errors.Is(err1, identity.ErrInvalid) {
				t.Fatalf("Field(%s) err = %v, want ErrInvalid", a.OID, err1)
			}
		}
	}
}

func FuzzParseName(f *testing.F) {
	for _, c := range specimenCerts(f) {
		f.Add(c.RawSubject)
		f.Add(c.RawIssuer)
	}
	for _, tc := range nameFieldKindsCases(f) {
		f.Add(tc.der)
	}
	for _, tc := range nameFieldTextCases(f) {
		f.Add(tc.der)
	}
	for _, tc := range nameFieldDuplicateCases(f) {
		f.Add(tc.der)
	}
	for _, tc := range malformedNameCases(f) {
		f.Add(tc.der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		n, err := identity.ParseName(der)
		if err != nil {
			if !errors.Is(err, identity.ErrInvalid) {
				t.Fatalf("ParseName err = %v, want ErrInvalid", err)
			}
			return
		}
		if len(n.Attributes) > 64 {
			t.Fatalf("ParseName returned %d attributes, limit is 64", len(n.Attributes))
		}
		again, err := identity.ParseName(der)
		if err != nil || !reflect.DeepEqual(n, again) {
			t.Fatalf("ParseName not stable: %v", err)
		}
		checkFieldsStable(t, n)
	})
}

func FuzzParseSANDirectoryNames(f *testing.F) {
	oidSAN := asn1.ObjectIdentifier{2, 5, 29, 17}
	for _, c := range specimenCerts(f) {
		if v := specimenExtension(c, oidSAN); v != nil {
			f.Add(v)
		}
	}
	for _, tc := range nameFieldKindsCases(f) {
		f.Add(seqDER(generalName(4, true, tc.der)))
	}
	f.Add(seqDER())
	f.Add(seqDER(generalName(2, false, []byte("example.org"))))
	f.Add(seqDER(generalName(4, false, []byte{0x30, 0x00})))
	f.Fuzz(func(t *testing.T, der []byte) {
		names, err := identity.ParseSANDirectoryNames(der)
		if err != nil {
			if !errors.Is(err, identity.ErrInvalid) {
				t.Fatalf("ParseSANDirectoryNames err = %v, want ErrInvalid", err)
			}
			if names != nil {
				t.Fatalf("ParseSANDirectoryNames returned %d names with an error", len(names))
			}
			return
		}
		if len(names) > 64 {
			t.Fatalf("ParseSANDirectoryNames returned %d names, limit is 64", len(names))
		}
		again, err := identity.ParseSANDirectoryNames(der)
		if err != nil || !reflect.DeepEqual(names, again) {
			t.Fatalf("ParseSANDirectoryNames not stable: %v", err)
		}
		for _, n := range names {
			checkFieldsStable(t, n)
		}
	})
}

func FuzzParseDateOfBirth(f *testing.F) {
	oidSDA := asn1.ObjectIdentifier{2, 5, 29, 9}
	for _, c := range specimenCerts(f) {
		if v := specimenExtension(c, oidSDA); v != nil {
			f.Add(v)
		}
	}
	for _, tc := range dateOfBirthCases(f) {
		f.Add(tc.der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		d, found, err := identity.ParseDateOfBirth(der)
		if err != nil {
			if !errors.Is(err, identity.ErrInvalid) {
				t.Fatalf("ParseDateOfBirth err = %v, want ErrInvalid", err)
			}
			return
		}
		if !found {
			if d != (identity.Date{}) {
				t.Fatalf("ParseDateOfBirth = %v with found = false, want zero", d)
			}
			return
		}
		civil := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
		if civil.Year() != d.Year || civil.Month() != d.Month || civil.Day() != d.Day || d.Year < 1900 || d.Year > 9999 {
			t.Fatalf("ParseDateOfBirth = %v, not a valid civil date from 1900 on", d)
		}
		d2, found2, err2 := identity.ParseDateOfBirth(der)
		if d2 != d || !found2 || err2 != nil {
			t.Fatalf("ParseDateOfBirth not stable: (%v, %v, %v) then (%v, %v, %v)", d, found, err, d2, found2, err2)
		}
	})
}

// reportedNameOK reports whether a reported name is normalised, free of every
// code point class checkText rejects and does not mix Latin letters with
// Cyrillic or Greek ones.
func reportedNameOK(s string) bool {
	if s != identity.NormalizeName(s) {
		return false
	}
	var latin, other bool
	for _, r := range s {
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f, r == utf8.RuneError, r == 0x2800, r == 0xfffc,
			unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Co), r != ' ' && unicode.Is(unicode.Zs, r):
			return false
		}
		latin = latin || unicode.Is(unicode.Latin, r)
		other = other || unicode.In(r, unicode.Cyrillic, unicode.Greek)
	}
	return !latin || !other
}

// FuzzAdapterExtract runs Adapter.Extract, for each of the eleven profile
// shapes, on a certificate built directly from fuzzed subject, SAN and SDA
// bytes (R10.3): Extract reads only RawSubject, Extensions and NotBefore, so
// no signature is needed.
func FuzzAdapterExtract(f *testing.F) {
	oidSAN, oidSDA := asn1.ObjectIdentifier{2, 5, 29, 17}, asn1.ObjectIdentifier{2, 5, 29, 9}
	shapes := []identity.Adapter{shapePlain(), shapeFNMTCitizenRSA(), shapeFNMTCitizenG2(), shapeFNMTRepresentative(),
		shapeFNMTEmployee(), shapeIDCATG2(), shapeIDCATG3(), shapeACCV(), shapeFirmaprofesional(), shapeSIGNE(), shapeDNIe()}
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	add := func(c *x509.Certificate) {
		san, sda := specimenExtension(c, oidSAN), specimenExtension(c, oidSDA)
		var flags uint8
		if san != nil {
			flags |= 1
		}
		if sda != nil {
			flags |= 2
		}
		for i := range shapes {
			f.Add(c.RawSubject, san, sda, uint8(i), flags)
		}
	}
	ca := testpki.NewRoot(f, "fuzz-extract-root", testpki.CertSpec{})
	for _, tc := range adapterCases(f) {
		add(ca.Leaf(f, tc.spec).Cert)
	}
	for _, c := range specimenCerts(f) {
		add(c)
	}
	f.Fuzz(func(t *testing.T, subject, san, sda []byte, shape, flags uint8) {
		a := shapes[int(shape)%len(shapes)]
		cert := &x509.Certificate{RawSubject: subject, NotBefore: notBefore}
		if flags&1 != 0 {
			cert.Extensions = append(cert.Extensions, pkix.Extension{Id: oidSAN, Value: san})
		}
		if flags&2 != 0 {
			cert.Extensions = append(cert.Extensions, pkix.Extension{Id: oidSDA, Value: sda})
		}
		x, err := a.Extract(cert)
		if err != nil {
			if errors.Is(err, identity.ErrInvalid) == errors.Is(err, identity.ErrUnsupportedDocument) {
				t.Fatalf("Extract err = %v, want exactly one of ErrInvalid and ErrUnsupportedDocument", err)
			}
			if !reflect.DeepEqual(x, identity.Extracted{}) {
				t.Fatalf("Extract returned %+v with an error, want zero", x)
			}
			return
		}
		id := x.Identity
		switch id.Document.Type {
		case identity.DocumentDNI:
			if !identity.ValidDNI(id.Document.Number) {
				t.Fatalf("DNI %q fails ValidDNI", id.Document.Number)
			}
		case identity.DocumentNIE:
			if !identity.ValidNIE(id.Document.Number) {
				t.Fatalf("NIE %q fails ValidNIE", id.Document.Number)
			}
		default:
			t.Fatalf("unknown document type %q", id.Document.Type)
		}
		n, err := identity.ParseName(subject)
		if err != nil {
			t.Fatalf("subject accepted by Extract fails ParseName: %v", err)
		}
		serial, ok, err := n.Field(identity.OIDSerialNumber, identity.DefaultKinds)
		if err != nil || !ok || id.Document.Raw != strings.Trim(serial, " ") || id.Document.Country != "ES" ||
			id.Document.Source != "subject.2.5.4.5" || !strings.HasSuffix(id.Document.Raw, id.Document.Number) {
			t.Fatalf("Document %+v inconsistent with subject serialNumber %q (%v, %v)", id.Document, serial, ok, err)
		}
		if id.GivenNames == "" || id.Surnames == "" || id.FullName != id.GivenNames+" "+id.Surnames {
			t.Fatalf("names (%q, %q, %q) inconsistent", id.GivenNames, id.Surnames, id.FullName)
		}
		names := []string{id.GivenNames, id.Surnames, id.FirstSurname, id.SecondSurname}
		if x.Organization != nil {
			names = append(names, x.Organization.Name, x.Organization.Identifier)
		}
		for _, s := range names {
			if !reportedNameOK(s) {
				t.Fatalf("reported name %q is not normalised, carries a rejected code point or mixes scripts", s)
			}
		}
		if id.FirstSurname != "" {
			joined := id.FirstSurname
			if id.SecondSurname != "" {
				joined += " " + id.SecondSurname
			}
			if identity.ComparisonKey(joined) != identity.ComparisonKey(id.Surnames) {
				t.Fatalf("surname split (%q, %q) disagrees with %q", id.FirstSurname, id.SecondSurname, id.Surnames)
			}
		}
		if id.BirthDate != nil && a.BirthDate != identity.BirthDateOptional {
			t.Fatalf("birth date %v reported by a profile without one", *id.BirthDate)
		}
		if d := id.BirthDate; d != nil {
			civil := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
			if civil.Year() != d.Year || civil.Month() != d.Month || civil.Day() != d.Day || d.Year < 1900 || civil.After(notBefore) {
				t.Fatalf("birth date %v is not a civil date from 1900 to NotBefore", *d)
			}
		}
		if (x.Organization != nil) != (a.Organization == identity.OrganizationFromSubject) {
			t.Fatalf("Organization = %+v for organization rule %v", x.Organization, a.Organization)
		}
		for k := range id.Sources {
			switch k {
			case "document", "givenNames", "surnames", "firstSurname", "secondSurname", "birthDate",
				"organization", "organizationIdentifier", "surnamesQuirk":
			default:
				t.Fatalf("unknown source key %q", k)
			}
		}
		again, err := a.Extract(cert)
		if err != nil || !reflect.DeepEqual(x, again) {
			t.Fatalf("Extract not stable: %+v, %v", again, err)
		}
	})
}

func FuzzDateUnmarshalJSON(f *testing.F) {
	for _, s := range []string{`"1985-07-23"`, `"0987-03-04"`, `"2000-02-29"`, `"1999-02-29"`, `null`, `"2000-2-29"`, `20000229`, `"\u0032000-01-01"`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		var d identity.Date
		if err := d.UnmarshalJSON(in); err != nil {
			if !errors.Is(err, identity.ErrInvalid) {
				t.Fatalf("UnmarshalJSON(%q) err = %v, want ErrInvalid", in, err)
			}
			if d != (identity.Date{}) {
				t.Fatalf("UnmarshalJSON(%q) failed but set %v", in, d)
			}
			return
		}
		if string(in) == "null" {
			if d != (identity.Date{}) {
				t.Fatalf("UnmarshalJSON(null) set %v", d)
			}
			return
		}
		civil := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
		if civil.Year() != d.Year || civil.Month() != d.Month || civil.Day() != d.Day || d.Year < 0 || d.Year > 9999 {
			t.Fatalf("UnmarshalJSON(%q) = %v, not a valid civil date", in, d)
		}
		out, err := d.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var again identity.Date
		if err := again.UnmarshalJSON(out); err != nil || again != d {
			t.Fatalf("round trip of %q: %s -> (%v, %v), want %v", in, out, again, err, d)
		}
	})
}

func FuzzParseDocument(f *testing.F) {
	ruleSets := [][]identity.DocumentRule{bothRules, idcesRules, bareRules, signeRules, pnoesNIERules, bareDNIRules}
	for _, tc := range parseDocumentCases() {
		for i := range ruleSets {
			f.Add(tc.value, uint8(i))
		}
	}
	for _, c := range specimenCerts(f) {
		n, err := identity.ParseName(c.RawSubject)
		if err != nil {
			f.Fatalf("specimen subject: %v", err)
		}
		if v, ok, err := n.Field(identity.OIDSerialNumber, identity.DefaultKinds); err == nil && ok {
			f.Add(v, uint8(0))
		}
	}
	f.Fuzz(func(t *testing.T, value string, set uint8) {
		rules := ruleSets[int(set)%len(ruleSets)]
		doc, err := identity.ParseDocument(value, "fuzz", rules)
		if err != nil {
			inv, uns := errors.Is(err, identity.ErrInvalid), errors.Is(err, identity.ErrUnsupportedDocument)
			if inv == uns {
				t.Fatalf("ParseDocument err = %v, want exactly one of ErrInvalid and ErrUnsupportedDocument", err)
			}
			// No fixed message contains a digit, so a value with a digit can never be echoed.
			if v := strings.Trim(value, " "); len(v) >= 6 && strings.ContainsAny(v, "0123456789") && strings.Contains(err.Error(), v) {
				t.Fatalf("ParseDocument error %q echoes the value", err)
			}
			return
		}
		switch doc.Type {
		case identity.DocumentDNI:
			if !identity.ValidDNI(doc.Number) {
				t.Fatalf("DNI %q fails ValidDNI", doc.Number)
			}
		case identity.DocumentNIE:
			if !identity.ValidNIE(doc.Number) {
				t.Fatalf("NIE %q fails ValidNIE", doc.Number)
			}
		default:
			t.Fatalf("unknown document type %q", doc.Type)
		}
		if doc.Country != "ES" || doc.Source != "fuzz" || doc.Raw != strings.Trim(value, " ") || !strings.HasSuffix(doc.Raw, doc.Number) {
			t.Fatalf("Document %+v inconsistent with value %q", doc, value)
		}
		again, err := identity.ParseDocument(value, "fuzz", rules)
		if err != nil || again != doc {
			t.Fatalf("ParseDocument not stable: %+v, %v", again, err)
		}
	})
}
