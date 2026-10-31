package identity_test

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
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
		if civil.Year() != d.Year || civil.Month() != d.Month || civil.Day() != d.Day || d.Year < 0 || d.Year > 9999 {
			t.Fatalf("ParseDateOfBirth = %v, not a valid civil date", d)
		}
		d2, found2, err2 := identity.ParseDateOfBirth(der)
		if d2 != d || !found2 || err2 != nil {
			t.Fatalf("ParseDateOfBirth not stable: (%v, %v, %v) then (%v, %v, %v)", d, found, err, d2, found2, err2)
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
