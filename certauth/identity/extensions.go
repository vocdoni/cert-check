package identity

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var (
	oidExtSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtSubjectDirAttrs = asn1.ObjectIdentifier{2, 5, 29, 9}
	oidAttrDateOfBirth    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
)

// maxSANEntries bounds parsing work on hostile input.
const maxSANEntries = 64

// DirectoryNames returns the parsed directoryName entries of the SAN
// extension, in order. A certificate without SAN yields (nil, nil).
func DirectoryNames(cert *x509.Certificate) ([]Name, error) {
	ext, ok := findExtension(cert, oidExtSubjectAltName)
	if !ok {
		return nil, nil
	}
	return ParseSANDirectoryNames(ext)
}

// ParseSANDirectoryNames parses a SubjectAltName extension value and returns
// its directoryName entries.
func ParseSANDirectoryNames(der []byte) ([]Name, error) {
	var gns []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &gns)
	if err != nil || len(rest) != 0 {
		return nil, invalidf("san: malformed GeneralNames")
	}
	if len(gns) > maxSANEntries {
		return nil, invalidf("san: too many entries")
	}
	var out []Name
	for _, gn := range gns {
		if gn.Class != asn1.ClassContextSpecific {
			return nil, invalidf("san: GeneralName is not context-specific")
		}
		if gn.Tag != 4 {
			continue
		}
		if !gn.IsCompound {
			return nil, invalidf("san: directoryName is not constructed")
		}
		n, err := ParseName(gn.Bytes)
		if err != nil {
			return nil, fmt.Errorf("san: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}

// Date is a civil date.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// String formats the date as YYYY-MM-DD.
func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day) }

// MarshalJSON encodes the date as "YYYY-MM-DD".
func (d Date) MarshalJSON() ([]byte, error) { return []byte(`"` + d.String() + `"`), nil }

// UnmarshalJSON decodes a "YYYY-MM-DD" string holding a valid civil date;
// any other form is an ErrInvalid error. null leaves d unchanged (a *Date
// field becomes nil), as encoding/json does for its own types.
func (d *Date) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return invalidf("date: not a JSON string")
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return invalidf("date: %q is not YYYY-MM-DD", s)
	}
	*d = Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}
	return nil
}

// DateOfBirth reads SubjectDirectoryAttributes dateOfBirth. found is false
// when the extension or the attribute is absent. The value must be exactly one
// GeneralizedTime "YYYYMMDDHHMMSSZ"; the civil date is its first 8 digits.
func DateOfBirth(cert *x509.Certificate) (d Date, found bool, err error) {
	ext, ok := findExtension(cert, oidExtSubjectDirAttrs)
	if !ok {
		return Date{}, false, nil
	}
	return ParseDateOfBirth(ext)
}

// ParseDateOfBirth parses a SubjectDirectoryAttributes extension value.
// Every Attribute must be exactly SEQUENCE { type, values } with a non-empty
// values SET (ruling R52, extended to the SDA).
func ParseDateOfBirth(der []byte) (d Date, found bool, err error) {
	var attrs []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &attrs)
	if err != nil || len(rest) != 0 {
		return Date{}, false, invalidf("sda: malformed attributes")
	}
	for _, raw := range attrs {
		typ, values, ok := parseSDAAttribute(raw)
		if !ok {
			return Date{}, false, invalidf("sda: malformed attribute")
		}
		if !typ.Equal(oidAttrDateOfBirth) {
			continue
		}
		if found || len(values) != 1 {
			return Date{}, true, invalidf("sda: dateOfBirth must have exactly one value")
		}
		v := values[0]
		if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagGeneralizedTime || v.IsCompound {
			return Date{}, true, invalidf("sda: dateOfBirth is not GeneralizedTime")
		}
		t, perr := time.Parse("20060102150405Z", string(v.Bytes))
		if perr != nil || len(v.Bytes) != 15 {
			return Date{}, true, invalidf("sda: dateOfBirth is not YYYYMMDDHHMMSSZ")
		}
		d, found = Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}, true
	}
	return d, found, nil
}

// parseSDAAttribute reads Attribute ::= SEQUENCE { type OID, values SET SIZE
// (1..MAX) OF ANY } and rejects an empty values SET or any element after it;
// encoding/asn1 struct decoding would silently accept trailing elements.
func parseSDAAttribute(raw asn1.RawValue) (asn1.ObjectIdentifier, []asn1.RawValue, bool) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return nil, nil, false
	}
	var typ asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(raw.Bytes, &typ)
	if err != nil {
		return nil, nil, false
	}
	var set asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &set)
	if err != nil || len(rest) != 0 || set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet || !set.IsCompound || len(set.Bytes) == 0 {
		return nil, nil, false
	}
	var values []asn1.RawValue
	for inner := set.Bytes; len(inner) > 0; {
		var v asn1.RawValue
		if inner, err = asn1.Unmarshal(inner, &v); err != nil {
			return nil, nil, false
		}
		values = append(values, v)
	}
	return typ, values, true
}

func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

// NormalizeName applies NFC, collapses runs of white space to one ASCII
// space and trims. It never splits or reorders words.
func NormalizeName(s string) string {
	return strings.Join(strings.Fields(norm.NFC.String(s)), " ")
}

// ComparisonKey is the key used only for cross-field consistency checks:
// NormalizeName, then diacritics removed (NFD, drop Mn), upper-cased. FNMT's
// own specimen 99949990V certifies SN "ESPECIMEN-DIEZ" and SAN "ESPECIMEN-DÍEZ".
// Reported values always keep the certified spelling.
func ComparisonKey(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(NormalizeName(s)) {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(norm.NFC.String(b.String()))
}
