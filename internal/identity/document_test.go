package identity_test

import (
	"errors"
	"testing"

	"github.com/vocdoni/cert-check/internal/identity"
)

var (
	dniNIE  = []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}
	dniOnly = []identity.DocumentType{identity.DocumentDNI}
	nieOnly = []identity.DocumentType{identity.DocumentNIE}

	idcesRules = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: dniNIE}}
	bareRules  = []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniNIE}}
	bothRules  = []identity.DocumentRule{
		{Encoding: identity.EncodingIDCES, Types: dniNIE},
		{Encoding: identity.EncodingBare, Types: dniNIE},
	}
	// signeRules: IDCES-<DNI> and PNOES-<NIE> (SIGNE).
	signeRules = []identity.DocumentRule{
		{Encoding: identity.EncodingIDCES, Types: dniOnly},
		{Encoding: identity.EncodingPNOES, Types: nieOnly},
	}
	pnoesNIERules = []identity.DocumentRule{{Encoding: identity.EncodingPNOES, Types: nieOnly}}
	idcesDNIRules = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: dniOnly}}
	bareDNIRules  = []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniOnly}}
)

func TestValidDNI(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"00000000T", true},
		{"00012345V", true},
		{"12345678Z", true},
		{"99949992L", true},
		{"99999999R", true},
		{"12345679S", true},
		{"12345678A", false}, // checksum
		{"1234567Z", false},  // length
		{"123456789Z", false},
		{"12345678z", false}, // lower case
		{"1234567AZ", false},
		{"X1234567L", false}, // NIE, not DNI
		{"1234 678Z", false},
		{"+1234567Z", false},
		{"", false},
		{"１２３４５６７８Z", false}, // full-width digits
	}
	for _, tc := range tests {
		if got := identity.ValidDNI(tc.in); got != tc.want {
			t.Errorf("ValidDNI(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidNIE(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"X0000000T", true},
		{"X1234567L", true},
		{"Y1234567X", true},
		{"Y0000000Z", true},
		{"Z1234567R", true},
		{"Z0000000M", true},
		{"Y0000000R", false}, // digest A example, wrong letter
		{"Z0000000W", false}, // digest A example, wrong letter
		{"W1234567L", false}, // not an NIE lead letter
		{"x1234567L", false},
		{"X123456L", false},
		{"X12345678L", false},
		{"XX234567L", false},
		{"12345678Z", false}, // DNI, not NIE
		{"", false},
	}
	for _, tc := range tests {
		if got := identity.ValidNIE(tc.in); got != tc.want {
			t.Errorf("ValidNIE(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// documentCase is one ParseDocument call.
type documentCase struct {
	name    string
	value   string
	rules   []identity.DocumentRule
	want    identity.Document
	wantErr error
}

func parseDocumentCases() []documentCase {
	const src = "subject.2.5.4.5"
	dni := func(number, raw string) identity.Document {
		return identity.Document{Type: identity.DocumentDNI, Country: "ES", Number: number, Raw: raw, Source: src}
	}
	nie := func(number, raw string) identity.Document {
		return identity.Document{Type: identity.DocumentNIE, Country: "ES", Number: number, Raw: raw, Source: src}
	}
	return []documentCase{
		{name: "IDCES DNI", value: "IDCES-12345678Z", rules: idcesRules, want: dni("12345678Z", "IDCES-12345678Z")},
		{name: "IDCES NIE", value: "IDCES-X1234567L", rules: idcesRules, want: nie("X1234567L", "IDCES-X1234567L")},
		{name: "IDCES leading zeros", value: "IDCES-00012345V", rules: idcesRules, want: dni("00012345V", "IDCES-00012345V")},
		{name: "IDCES under IDCES and bare rules", value: "IDCES-12345678Z", rules: bothRules, want: dni("12345678Z", "IDCES-12345678Z")},
		{name: "bare with a bare rule", value: "12345678Z", rules: bareRules, want: dni("12345678Z", "12345678Z")},
		{name: "bare NIE with a bare rule", value: "Y1234567X", rules: bareRules, want: nie("Y1234567X", "Y1234567X")},
		{name: "bare under IDCES and bare rules", value: "00000000T", rules: bothRules, want: dni("00000000T", "00000000T")},
		{name: "bare without a bare rule", value: "12345678Z", rules: idcesRules, wantErr: identity.ErrInvalid},
		{name: "IDCES without an IDCES rule", value: "IDCES-12345678Z", rules: bareRules, wantErr: identity.ErrInvalid},
		{name: "no rules", value: "12345678Z", rules: nil, wantErr: identity.ErrInvalid},
		{name: "passport", value: "PASES-AB123456", rules: bothRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "French national ID", value: "IDCFR-123456789", rules: bothRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "tax identifier", value: "TINES-12345678Z", rules: bothRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "EX colon form", value: "EX:ES-12345678Z", rules: bothRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "JU colon form", value: "JU:ES-12345678Z", rules: bothRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "PNOES with a PNOES rule", value: "PNOES-X1234567L", rules: signeRules, want: nie("X1234567L", "PNOES-X1234567L")},
		{name: "PNOES without a PNOES rule", value: "PNOES-X1234567L", rules: bothRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "PNOES DNI under a NIE-only rule", value: "PNOES-12345678Z", rules: pnoesNIERules, wantErr: identity.ErrInvalid},
		{name: "IDCES DNI under SIGNE", value: "IDCES-12345678Z", rules: signeRules, want: dni("12345678Z", "IDCES-12345678Z")},
		{name: "IDCES NIE under a DNI-only rule (SIGNE)", value: "IDCES-X1234567L", rules: signeRules, wantErr: identity.ErrInvalid},
		{name: "IDCES NIE under IDCES DNI-only", value: "IDCES-X1234567L", rules: idcesDNIRules, wantErr: identity.ErrInvalid},
		{name: "bare NIE under a bare DNI-only rule", value: "X1234567L", rules: bareDNIRules, wantErr: identity.ErrInvalid},
		{name: "bare K NIF", value: "K1234567L", rules: bareRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "bare L NIF", value: "L1234567L", rules: bareRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "IDCES M NIF", value: "IDCES-M1234567L", rules: idcesRules, wantErr: identity.ErrUnsupportedDocument},
		{name: "surrounding spaces trimmed", value: "  12345678Z  ", rules: bareRules, want: dni("12345678Z", "12345678Z")},
		{name: "inner space", value: "1234 5678Z", rules: bareRules, wantErr: identity.ErrInvalid},
		{name: "space after prefix", value: "IDCES- 12345678Z", rules: idcesRules, wantErr: identity.ErrInvalid},
		{name: "tab", value: "\t12345678Z", rules: bareRules, wantErr: identity.ErrInvalid},
		{name: "lower-case prefix", value: "idces-12345678Z", rules: idcesRules, wantErr: identity.ErrInvalid},
		{name: "lower-case letter", value: "12345678z", rules: bareRules, wantErr: identity.ErrInvalid},
		{name: "9-digit number (EADTrust example)", value: "IDCES-012345678R", rules: idcesRules, wantErr: identity.ErrInvalid},
		{name: "checksum", value: "IDCES-12345678A", rules: idcesRules, wantErr: identity.ErrInvalid},
		{name: "doubled prefix", value: "IDCES-IDCES-12345678Z", rules: idcesRules, wantErr: identity.ErrInvalid},
		{name: "prefix without number", value: "IDCES-", rules: bothRules, wantErr: identity.ErrInvalid},
		{name: "dash in number", value: "12345678-Z", rules: bareRules, wantErr: identity.ErrInvalid},
		{name: "full-width digits", value: "１２３４５６７８Z", rules: bareRules, wantErr: identity.ErrInvalid},
		{name: "empty", value: "", rules: bothRules, wantErr: identity.ErrInvalid},
		{name: "spaces only", value: "   ", rules: bothRules, wantErr: identity.ErrInvalid},
	}
}

func TestParseDocument(t *testing.T) {
	for _, tc := range parseDocumentCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := identity.ParseDocument(tc.value, "subject.2.5.4.5", tc.rules)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseDocument(%q) err = %v, want %v", tc.value, err, tc.wantErr)
				}
				other := identity.ErrInvalid
				if tc.wantErr == identity.ErrInvalid {
					other = identity.ErrUnsupportedDocument
				}
				if errors.Is(err, other) {
					t.Errorf("ParseDocument(%q) err = %v also wraps %v", tc.value, err, other)
				}
				if got != (identity.Document{}) {
					t.Errorf("ParseDocument(%q) = %+v with an error, want zero Document", tc.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDocument(%q) err = %v, want nil", tc.value, err)
			}
			if got != tc.want {
				t.Errorf("ParseDocument(%q) = %+v, want %+v", tc.value, got, tc.want)
			}
		})
	}

	t.Run("source echoed", func(t *testing.T) {
		got, err := identity.ParseDocument("IDCES-12345678Z", "san.1.3.6.1.4.1.5734.1.4", idcesRules)
		if err != nil {
			t.Fatal(err)
		}
		if got.Source != "san.1.3.6.1.4.1.5734.1.4" || got.Raw != "IDCES-12345678Z" {
			t.Errorf("Source = %q, Raw = %q, want %q and %q", got.Source, got.Raw, "san.1.3.6.1.4.1.5734.1.4", "IDCES-12345678Z")
		}
	})
}
