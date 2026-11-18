// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity

import (
	"fmt"
	"strings"
)

// DocumentType is the kind of Spanish identity document.
type DocumentType string

// Document types.
const (
	DocumentDNI DocumentType = "DNI"
	DocumentNIE DocumentType = "NIE"
)

// Encoding is how a profile writes the document number in its source field.
type Encoding string

// Encodings. Each is an exact grammar; nothing is stripped to force a match.
const (
	EncodingIDCES Encoding = "IDCES" // "IDCES-<number>" (ETSI EN 319 412-1)
	EncodingPNOES Encoding = "PNOES" // "PNOES-<number>" (SIGNE NIE only)
	EncodingBare  Encoding = "bare"  // "<number>" (only when the profile declares it)
)

// DocumentRule accepts one encoding with the listed document types.
type DocumentRule struct {
	Encoding Encoding
	Types    []DocumentType
}

// Document is a validated Spanish identity document.
type Document struct {
	Type    DocumentType `json:"type"`
	Country string       `json:"country"` // always "ES"
	Number  string       `json:"number"`  // 9 characters, uppercase, leading zeros kept
	Raw     string       `json:"raw"`     // the field value as certified (after trimming spaces)
	Source  string       `json:"source"`  // provenance, e.g. "subject.2.5.4.5"
}

const controlLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// ValidDNI reports whether s is exactly 8 digits plus the mod-23 letter.
func ValidDNI(s string) bool {
	if len(s) != 9 {
		return false
	}
	n := 0
	for i := range 8 {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return s[8] == controlLetters[n%23]
}

// ValidNIE reports whether s is X/Y/Z + 7 digits + the mod-23 letter
// (X/Y/Z read as 0/1/2).
func ValidNIE(s string) bool {
	if len(s) != 9 {
		return false
	}
	var lead byte
	switch s[0] {
	case 'X':
		lead = '0'
	case 'Y':
		lead = '1'
	case 'Z':
		lead = '2'
	default:
		return false
	}
	return ValidDNI(string(lead) + s[1:])
}

// typedPrefix reports whether v starts with an ETSI-style typed prefix
// ("XXXcc-" or "XX:cc-") and returns it without the dash.
func typedPrefix(v string) (string, bool) {
	isUpper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	if len(v) > 6 && v[5] == '-' && isUpper(v[0]) && isUpper(v[1]) && isUpper(v[2]) && isUpper(v[3]) && isUpper(v[4]) {
		return v[:5], true
	}
	if len(v) > 6 && v[5] == '-' && v[2] == ':' && isUpper(v[0]) && isUpper(v[1]) && isUpper(v[3]) && isUpper(v[4]) {
		return v[:5], true
	}
	return "", false
}

// otherSpanishNIF reports K/L/M personal NIFs and similar letter-led numbers
// that are valid identifiers but not a DNI/NIE.
func otherSpanishNIF(v string) bool {
	if len(v) != 9 || !strings.ContainsRune("KLM", rune(v[0])) {
		return false
	}
	for i := 1; i < 8; i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return v[8] >= 'A' && v[8] <= 'Z'
}

// ParseDocument validates value (the raw field text) against rules.
// Surrounding ASCII spaces are trimmed; anything else must match exactly.
// It returns ErrUnsupportedDocument for a well-formed identifier of another
// document kind, ErrInvalid otherwise.
func ParseDocument(value, source string, rules []DocumentRule) (Document, error) {
	v := strings.Trim(value, " ")
	if v == "" {
		return Document{}, invalidf("%s: empty document", source)
	}
	for i := range len(v) {
		c := v[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == ':') {
			return Document{}, invalidf("%s: document is not uppercase ASCII", source)
		}
	}
	enc, number := EncodingBare, v
	if p, ok := typedPrefix(v); ok {
		switch p {
		case "IDCES":
			enc, number = EncodingIDCES, v[6:]
		case "PNOES":
			enc, number = EncodingPNOES, v[6:]
		default:
			return Document{}, fmt.Errorf("%w: %s: typed identifier %s", ErrUnsupportedDocument, source, p)
		}
	}
	var rule *DocumentRule
	for i := range rules {
		if rules[i].Encoding == enc {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		if enc == EncodingPNOES {
			return Document{}, fmt.Errorf("%w: %s: typed identifier PNOES", ErrUnsupportedDocument, source)
		}
		return Document{}, invalidf("%s: encoding %s not accepted by this profile", source, enc)
	}
	allowed := func(t DocumentType) bool {
		for _, x := range rule.Types {
			if x == t {
				return true
			}
		}
		return false
	}
	switch {
	case ValidDNI(number) && allowed(DocumentDNI):
		return Document{Type: DocumentDNI, Country: "ES", Number: number, Raw: v, Source: source}, nil
	case ValidNIE(number) && allowed(DocumentNIE):
		return Document{Type: DocumentNIE, Country: "ES", Number: number, Raw: v, Source: source}, nil
	case otherSpanishNIF(number):
		return Document{}, fmt.Errorf("%w: %s: personal NIF that is not a DNI/NIE", ErrUnsupportedDocument, source)
	}
	return Document{}, invalidf("%s: number fails the %s grammar or checksum", source, enc)
}
