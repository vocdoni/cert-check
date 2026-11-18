// Package identity parses and validates the personal identity carried by a
// certificate: strict RDN parsing of the raw subject, SAN directoryName
// decoding, SubjectDirectoryAttributes dateOfBirth, DNI/NIE grammar and
// checksum, name normalisation, and declarative per-profile adapters.
//
// Errors never contain certificate values: they name fields and rules only.
package identity

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Sentinel errors. Every error returned by this package wraps exactly one.
var (
	// ErrInvalid: grammar, checksum, string type or cross-field disagreement.
	ErrInvalid = errors.New("identity invalid")
	// ErrUnsupportedDocument: a valid typed identifier that is not a Spanish DNI/NIE.
	ErrUnsupportedDocument = errors.New("identity document unsupported")
)

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// StringKind is the ASN.1 string type of an attribute value.
type StringKind int

// String kinds. Zero is unset.
const (
	KindUTF8 StringKind = iota + 1
	KindPrintable
	KindBMP
	KindTeletex
	KindIA5
	KindOther
)

// KindSet is a set of accepted string kinds for identity fields.
type KindSet []StringKind

// DefaultKinds are the kinds accepted for identity fields unless a profile
// allows more: UTF8String and PrintableString.
var DefaultKinds = KindSet{KindUTF8, KindPrintable}

func (s KindSet) has(k StringKind) bool {
	for _, x := range s {
		if x == k {
			return true
		}
	}
	return false
}

// Attribute is one AttributeTypeAndValue, in DER order.
type Attribute struct {
	OID  asn1.ObjectIdentifier
	Kind StringKind
	Tag  int    // universal tag number of the value
	Raw  []byte // value contents (no tag/length)
	Text string // decoded text; "" when Kind is KindOther or decoding failed
	Err  error  // decoding error, nil when Text is valid for Kind
	RDN  int    // index of the enclosing RDN; multi-valued RDNs share it
}

// Name is a parsed RDNSequence with order, duplicates and multi-valued RDNs preserved.
type Name struct {
	Attributes []Attribute
}

// maxNameAttributes bounds parsing work on hostile input.
const maxNameAttributes = 64

// ParseName strictly parses a DER RDNSequence (for example x509.Certificate.RawSubject).
func ParseName(der []byte) (Name, error) {
	var rdns []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &rdns)
	if err != nil {
		return Name{}, invalidf("name: malformed RDNSequence")
	}
	if len(rest) != 0 {
		return Name{}, invalidf("name: trailing data")
	}
	var out Name
	for i, rdn := range rdns {
		if rdn.Class != asn1.ClassUniversal || rdn.Tag != asn1.TagSet || !rdn.IsCompound {
			return Name{}, invalidf("name: RDN %d is not a SET", i)
		}
		inner := rdn.Bytes
		if len(inner) == 0 {
			return Name{}, invalidf("name: RDN %d is empty", i)
		}
		for len(inner) > 0 {
			var atv asn1.RawValue
			inner, err = asn1.Unmarshal(inner, &atv)
			if err != nil {
				return Name{}, invalidf("name: RDN %d: malformed attribute", i)
			}
			oid, value, ok := parseATV(atv)
			if !ok {
				return Name{}, invalidf("name: RDN %d: malformed attribute", i)
			}
			if len(out.Attributes) == maxNameAttributes {
				return Name{}, invalidf("name: too many attributes")
			}
			out.Attributes = append(out.Attributes, decodeAttribute(oid, value, i))
		}
	}
	return out, nil
}

// parseATV reads AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
// and rejects a missing value or any element after it (ruling R52);
// encoding/asn1 struct decoding would silently accept trailing elements.
func parseATV(atv asn1.RawValue) (asn1.ObjectIdentifier, asn1.RawValue, bool) {
	if atv.Class != asn1.ClassUniversal || atv.Tag != asn1.TagSequence || !atv.IsCompound {
		return nil, asn1.RawValue{}, false
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(atv.Bytes, &oid)
	if err != nil {
		return nil, asn1.RawValue{}, false
	}
	var value asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &value)
	if err != nil || len(rest) != 0 {
		return nil, asn1.RawValue{}, false
	}
	return oid, value, true
}

func decodeAttribute(oid asn1.ObjectIdentifier, v asn1.RawValue, rdn int) Attribute {
	a := Attribute{OID: oid, Tag: v.Tag, Raw: v.Bytes, RDN: rdn, Kind: KindOther}
	if v.Class != asn1.ClassUniversal || v.IsCompound {
		a.Err = errors.New("not a universal primitive string")
		return a
	}
	switch v.Tag {
	case asn1.TagUTF8String:
		a.Kind = KindUTF8
		if !utf8.Valid(v.Bytes) {
			a.Err = errors.New("invalid UTF-8")
			return a
		}
		a.Text = string(v.Bytes)
	case asn1.TagPrintableString:
		a.Kind = KindPrintable
		for _, b := range v.Bytes {
			if !isPrintable(b) {
				a.Err = errors.New("invalid PrintableString character")
				return a
			}
		}
		a.Text = string(v.Bytes)
	case asn1.TagIA5String:
		a.Kind = KindIA5
		for _, b := range v.Bytes {
			if b >= 0x80 {
				a.Err = errors.New("invalid IA5String character")
				return a
			}
		}
		a.Text = string(v.Bytes)
	case asn1.TagBMPString:
		a.Kind = KindBMP
		if len(v.Bytes)%2 != 0 {
			a.Err = errors.New("odd BMPString length")
			return a
		}
		u := make([]uint16, len(v.Bytes)/2)
		for i := range u {
			u[i] = uint16(v.Bytes[2*i])<<8 | uint16(v.Bytes[2*i+1])
		}
		for _, c := range u {
			if c >= 0xd800 && c <= 0xdfff {
				a.Err = errors.New("surrogate in BMPString")
				return a
			}
		}
		a.Text = string(utf16.Decode(u))
	case asn1.TagT61String:
		a.Kind = KindTeletex
		r := make([]rune, len(v.Bytes)) // decoded as ISO-8859-1, the common practice
		for i, b := range v.Bytes {
			r[i] = rune(b)
		}
		a.Text = string(r)
	}
	return a
}

// isPrintable reports whether b is in the X.680 PrintableString set.
func isPrintable(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	switch b {
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
		return true
	}
	return false
}

// Field returns the text of the attribute oid for identity use. found is false
// when the attribute is absent. Every occurrence must have an accepted kind and
// clean text; duplicates must be identical, otherwise ErrInvalid.
func (n Name) Field(oid asn1.ObjectIdentifier, kinds KindSet) (value string, found bool, err error) {
	for _, a := range n.Attributes {
		if !a.OID.Equal(oid) {
			continue
		}
		if !kinds.has(a.Kind) {
			return "", true, invalidf("attribute %s: string type not accepted", oid)
		}
		if a.Err != nil {
			return "", true, invalidf("attribute %s: %v", oid, a.Err)
		}
		if err := checkText(a.Text); err != nil {
			return "", true, invalidf("attribute %s: %v", oid, err)
		}
		if found && a.Text != value {
			return "", true, invalidf("attribute %s: conflicting duplicate values", oid)
		}
		value, found = a.Text, true
	}
	return value, found, nil
}

// maxCombiningRun bounds a run of consecutive combining marks (R5.1). A
// Spanish or Catalan letter needs at most two.
const maxCombiningRun = 4

// checkText rejects control characters, U+FFFD, bidi controls and, per
// ruling R53, every other invisible or ambiguous code point: format
// characters (Cf), line and paragraph separators, private-use code points,
// noncharacters and any space other than U+0020. Per R5.1 it also rejects
// the other default-ignorable code points (U+034F, the Hangul fillers),
// variation selectors and runs of more than maxCombiningRun combining marks.
// Per R10.1 it rejects the blank symbols U+2800 and U+FFFC and a value that
// mixes Latin letters with Cyrillic or Greek ones (the scripts whose capitals
// have Latin homoglyphs); a value wholly in one script passes. The errors name
// the rule, never the character.
func checkText(s string) error {
	run := 0
	var latin, cyrillicGreek bool
	for _, r := range s {
		if unicode.Is(unicode.M, r) {
			run++
		} else {
			run = 0
		}
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f:
			return errors.New("control character")
		case r == utf8.RuneError:
			return errors.New("replacement character")
		case r == 0x061c, r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return errors.New("bidi control")
		case unicode.Is(unicode.Cf, r):
			return errors.New("format character")
		case unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			return errors.New("default-ignorable character")
		case unicode.Is(unicode.Variation_Selector, r):
			return errors.New("variation selector")
		case unicode.In(r, unicode.Zl, unicode.Zp):
			return errors.New("line or paragraph separator")
		case unicode.Is(unicode.Co, r):
			return errors.New("private-use character")
		case r >= 0xfdd0 && r <= 0xfdef, r&0xfffe == 0xfffe:
			return errors.New("noncharacter")
		case r == 0x2800, r == 0xfffc:
			return errors.New("blank symbol")
		case r != ' ' && unicode.Is(unicode.Zs, r):
			return errors.New("space other than U+0020")
		case run > maxCombiningRun:
			return errors.New("too many combining marks")
		}
		latin = latin || unicode.Is(unicode.Latin, r)
		cyrillicGreek = cyrillicGreek || unicode.In(r, unicode.Cyrillic, unicode.Greek)
	}
	if latin && cyrillicGreek {
		return errors.New("mixed scripts")
	}
	return nil
}
