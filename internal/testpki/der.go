package testpki

import (
	"encoding/asn1"
	"math/big"
	"time"
	"unicode/utf16"
)

// DER tag bytes used by the hand-written encoders below.
const (
	tagBoolean         = 0x01
	tagInteger         = 0x02
	tagBitString       = 0x03
	tagOctetString     = 0x04
	tagNull            = 0x05
	tagEnumerated      = 0x0a
	tagUTF8String      = 0x0c
	tagPrintableString = 0x13
	tagT61String       = 0x14
	tagIA5String       = 0x16
	tagGeneralizedTime = 0x18
	tagBMPString       = 0x1e
	tagSequence        = 0x30
	tagSet             = 0x31
)

// tlv returns tag || DER length || concatenation of contents.
func tlv(tag byte, contents ...[]byte) []byte {
	var body []byte
	for _, c := range contents {
		body = append(body, c...)
	}
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func seq(contents ...[]byte) []byte { return tlv(tagSequence, contents...) }

// ctx returns a context-specific tag: constructed when explicit or when the
// implicitly tagged type is constructed.
func ctx(n byte, constructed bool, contents ...[]byte) []byte {
	tag := 0x80 | n
	if constructed {
		tag |= 0x20
	}
	return tlv(tag, contents...)
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func derOID(oid asn1.ObjectIdentifier) []byte { return mustMarshal(oid) }
func derInt(n *big.Int) []byte                { return mustMarshal(n) }
func derNull() []byte                         { return []byte{tagNull, 0x00} }
func derOctets(b []byte) []byte               { return tlv(tagOctetString, b) }
func derEnum(n int) []byte                    { return tlv(tagEnumerated, []byte{byte(n)}) }

// derGeneralizedTime encodes t (UTC, whole seconds) as GeneralizedTime.
func derGeneralizedTime(t time.Time) []byte {
	return tlv(tagGeneralizedTime, []byte(t.UTC().Format("20060102150405Z")))
}

// derTime encodes t as UTCTime before 2050 and GeneralizedTime after (RFC 5280).
func derTime(t time.Time) []byte {
	t = t.UTC()
	if t.Year() < 2050 && t.Year() >= 1950 {
		return tlv(0x17, []byte(t.Format("060102150405Z")))
	}
	return derGeneralizedTime(t)
}

func derBitString(b []byte) []byte { return tlv(tagBitString, append([]byte{0}, b...)) }

// encodeString encodes s with the given universal string tag.
func encodeString(tag int, s string) []byte {
	if tag == tagBMPString {
		var b []byte
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u>>8), byte(u))
		}
		return tlv(tagBMPString, b)
	}
	return tlv(byte(tag), []byte(s))
}

func derExtensions(exts []extension) []byte {
	var items [][]byte
	for _, e := range exts {
		parts := [][]byte{derOID(e.id)}
		if e.critical {
			parts = append(parts, []byte{tagBoolean, 0x01, 0xff})
		}
		parts = append(parts, derOctets(e.value))
		items = append(items, seq(parts...))
	}
	return seq(items...)
}

type extension struct {
	id       asn1.ObjectIdentifier
	critical bool
	value    []byte
}
