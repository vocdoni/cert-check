package identity_test

import (
	"encoding/asn1"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// DER helpers for hand-built malformed inputs. testpki keeps its encoders
// unexported, and these tests need encodings testpki refuses to produce.

const (
	tagUTCTime         = 0x17
	tagGeneralizedTime = 0x18
	tagSequence        = 0x30
	tagSet             = 0x31
)

// tlv returns tag || DER length || contents.
func tlv(tag byte, contents ...[]byte) []byte {
	var body []byte
	for _, c := range contents {
		body = append(body, c...)
	}
	out := []byte{tag}
	switch n := len(body); {
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

func seqDER(contents ...[]byte) []byte { return tlv(tagSequence, contents...) }
func setDER(contents ...[]byte) []byte { return tlv(tagSet, contents...) }

func oidDER(tb testing.TB, oid asn1.ObjectIdentifier) []byte {
	tb.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		tb.Fatalf("marshal oid %v: %v", oid, err)
	}
	return b
}

// atvDER encodes one AttributeTypeAndValue whose value has the raw tag byte.
func atvDER(tb testing.TB, oid asn1.ObjectIdentifier, tag byte, value []byte) []byte {
	tb.Helper()
	return seqDER(oidDER(tb, oid), tlv(tag, value))
}

// nameDER encodes an RDNSequence with one ATV per RDN.
func nameDER(atvs ...[]byte) []byte {
	var rdns [][]byte
	for _, a := range atvs {
		rdns = append(rdns, setDER(a))
	}
	return seqDER(rdns...)
}

func mustParseName(tb testing.TB, der []byte) identity.Name {
	tb.Helper()
	n, err := identity.ParseName(der)
	if err != nil {
		tb.Fatalf("ParseName: %v", err)
	}
	return n
}

var (
	oidOU = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCN = identity.OIDCommonName
	oidSN = identity.OIDSurname
	oidGN = identity.OIDGivenName
)

func TestParseNamePreservesOrder(t *testing.T) {
	der := testpki.Name{
		testpki.Printable(identity.OIDCountry, "ES"),
		testpki.UTF8(oidOU, "B"),
		testpki.UTF8(oidOU, "A"),
		{{OID: oidSN, Value: "GARCIA", Tag: testpki.TagUTF8}, {OID: oidGN, Value: "JUAN", Tag: testpki.TagPrintable}},
		testpki.UTF8(oidOU, "B"),
		testpki.Tagged(oidCN, testpki.TagIA5, "X"),
	}.DER()
	got := mustParseName(t, der)

	type attr struct {
		OID  string
		Kind identity.StringKind
		Tag  int
		Text string
		RDN  int
	}
	want := []attr{
		{"2.5.4.6", identity.KindPrintable, asn1.TagPrintableString, "ES", 0},
		{"2.5.4.11", identity.KindUTF8, asn1.TagUTF8String, "B", 1},
		{"2.5.4.11", identity.KindUTF8, asn1.TagUTF8String, "A", 2},
		{"2.5.4.4", identity.KindUTF8, asn1.TagUTF8String, "GARCIA", 3},
		{"2.5.4.42", identity.KindPrintable, asn1.TagPrintableString, "JUAN", 3},
		{"2.5.4.11", identity.KindUTF8, asn1.TagUTF8String, "B", 4},
		{"2.5.4.3", identity.KindIA5, asn1.TagIA5String, "X", 5},
	}
	var gotAttrs []attr
	for _, a := range got.Attributes {
		if a.Err != nil {
			t.Errorf("attribute %s: Err = %v, want nil", a.OID, a.Err)
		}
		if string(a.Raw) != a.Text {
			t.Errorf("attribute %s: Raw = %q, want %q", a.OID, a.Raw, a.Text)
		}
		gotAttrs = append(gotAttrs, attr{a.OID.String(), a.Kind, a.Tag, a.Text, a.RDN})
	}
	if !reflect.DeepEqual(gotAttrs, want) {
		t.Errorf("attributes:\n got %+v\nwant %+v", gotAttrs, want)
	}

	// Two differing OUs are fine while the OU is never read for identity,
	// but reading it is a conflict.
	if _, _, err := got.Field(oidOU, identity.DefaultKinds); !errors.Is(err, identity.ErrInvalid) {
		t.Errorf("Field(OU) err = %v, want ErrInvalid (conflicting duplicates)", err)
	}

	empty := mustParseName(t, seqDER())
	if len(empty.Attributes) != 0 {
		t.Errorf("empty RDNSequence: got %d attributes, want 0", len(empty.Attributes))
	}
}

// fieldCase reads oid from a DER name with the given kinds.
type fieldCase struct {
	name    string
	der     []byte
	oid     asn1.ObjectIdentifier
	kinds   identity.KindSet
	want    string
	found   bool
	wantErr error
	rule    string   // when set, the error must name this rule
	values  []string // input values an error must not echo
}

func runFieldCases(t *testing.T, cases []fieldCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := mustParseName(t, tc.der)
			got, found, err := n.Field(tc.oid, tc.kinds)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("Field err = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				if tc.rule != "" && !strings.Contains(err.Error(), tc.rule) {
					t.Errorf("Field err = %q, want it to name the rule %q", err, tc.rule)
				}
				return
			}
			if got != tc.want || found != tc.found {
				t.Errorf("Field = (%q, %v), want (%q, %v)", got, found, tc.want, tc.found)
			}
			// Re-read: Field is a pure function of the parsed name.
			again, againFound, againErr := n.Field(tc.oid, tc.kinds)
			if again != got || againFound != found || againErr != nil {
				t.Errorf("second Field = (%q, %v, %v), want (%q, %v, nil)", again, againFound, againErr, got, found)
			}
		})
	}
}

func nameFieldKindsCases(tb testing.TB) []fieldCase {
	bmp := testpki.Name{testpki.Tagged(oidGN, testpki.TagBMP, "JOSÉ")}.DER()
	// Teletex bytes are read as ISO-8859-1: 0xD1 is Ñ.
	teletex := nameDER(atvDER(tb, oidSN, testpki.TagTeletex, []byte("MU\xd1OZ")))
	ia5 := testpki.Name{testpki.Tagged(oidGN, testpki.TagIA5, "JUAN")}.DER()
	utf8 := testpki.Name{testpki.UTF8(oidGN, "JOSÉ")}.DER()
	printable := testpki.Name{testpki.Printable(oidGN, "JUAN")}.DER()
	return []fieldCase{
		{name: "utf8 default", der: utf8, oid: oidGN, want: "JOSÉ", found: true},
		{name: "printable default", der: printable, oid: oidGN, want: "JUAN", found: true},
		{name: "nil kinds rejects everything", der: printable, oid: oidGN, kinds: identity.KindSet{}, wantErr: identity.ErrInvalid, values: []string{"JUAN"}},
		{name: "bmp rejected by default", der: bmp, oid: oidGN, kinds: identity.DefaultKinds, wantErr: identity.ErrInvalid, values: []string{"JOSÉ"}},
		{name: "bmp accepted explicitly", der: bmp, oid: oidGN, kinds: identity.KindSet{identity.KindBMP}, want: "JOSÉ", found: true},
		{name: "teletex rejected by default", der: teletex, oid: oidSN, kinds: identity.DefaultKinds, wantErr: identity.ErrInvalid, values: []string{"MUÑOZ"}},
		{name: "teletex accepted explicitly", der: teletex, oid: oidSN, kinds: identity.KindSet{identity.KindUTF8, identity.KindTeletex}, want: "MUÑOZ", found: true},
		{name: "ia5 rejected by default", der: ia5, oid: oidGN, kinds: identity.DefaultKinds, wantErr: identity.ErrInvalid, values: []string{"JUAN"}},
		{name: "ia5 accepted explicitly", der: ia5, oid: oidGN, kinds: identity.KindSet{identity.KindIA5}, want: "JUAN", found: true},
		{name: "absent", der: utf8, oid: oidSN, kinds: identity.DefaultKinds, want: "", found: false},
	}
}

func TestNameFieldKinds(t *testing.T) {
	cases := nameFieldKindsCases(t)
	// The utf8/printable default rows pass DefaultKinds explicitly.
	for i := range cases {
		if cases[i].kinds == nil {
			cases[i].kinds = identity.DefaultKinds
		}
	}
	runFieldCases(t, cases)
}

func nameFieldTextCases(tb testing.TB) []fieldCase {
	utf8 := func(v string) []byte { return nameDER(atvDER(tb, oidGN, asn1.TagUTF8String, []byte(v))) }
	printable := func(v string) []byte { return nameDER(atvDER(tb, oidGN, asn1.TagPrintableString, []byte(v))) }
	bmp := func(units ...uint16) []byte {
		var b []byte
		for _, u := range units {
			b = append(b, byte(u>>8), byte(u))
		}
		return nameDER(atvDER(tb, oidGN, asn1.TagBMPString, b))
	}
	k := identity.DefaultKinds
	all := identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP, identity.KindTeletex, identity.KindIA5}
	cases := []fieldCase{
		{name: "clean utf8", der: utf8("JOSÉ MARÍA"), oid: oidGN, kinds: k, want: "JOSÉ MARÍA", found: true},
		{name: "clean printable", der: printable("O'NEIL-SMITH (JR.)"), oid: oidGN, kinds: k, want: "O'NEIL-SMITH (JR.)", found: true},
		{name: "bell U+0007", der: utf8("JU\u0007AN"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JU\u0007AN"}},
		{name: "tab", der: utf8("JUAN\tPEDRO"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN\tPEDRO"}},
		{name: "DEL", der: utf8("JUAN\u007f"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN\u007f"}},
		{name: "NEL U+0085", der: utf8("JUAN\u0085PEDRO"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN\u0085PEDRO"}},
		{name: "replacement U+FFFD", der: utf8("JU\uFFFDAN"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JU\uFFFDAN"}},
		{name: "RLO U+202E", der: utf8("JUAN\u202ENAUJ"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN\u202ENAUJ"}},
		{name: "LRI U+2066", der: utf8("\u2066JUAN"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"\u2066JUAN"}},
		{name: "ALM U+061C", der: utf8("JUAN\u061C"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN\u061C"}},
		{name: "invalid utf8", der: utf8("JU\xffAN"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JU\xffAN"}},
		{name: "utf8 encoded surrogate", der: utf8("JU\xed\xa0\x80AN"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JU\xed\xa0\x80AN"}},
		{name: "printable asterisk", der: printable("JUAN*"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN*"}},
		{name: "printable ampersand", der: printable("JUAN&ANA"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN&ANA"}},
		{name: "printable high byte", der: printable("JOS\xc9"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JOS\xc9"}},
		{name: "bmp odd length", der: nameDER(atvDER(tb, oidGN, asn1.TagBMPString, []byte{0, 'J', 0})), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid},
		{name: "bmp surrogate", der: bmp('J', 0xd800, 'N'), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid},
		{name: "bmp control", der: bmp('J', 0x0007), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid},
		{name: "teletex C1 control", der: nameDER(atvDER(tb, oidGN, testpki.TagTeletex, []byte("JUAN\x85"))), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid},
		{name: "ia5 high byte", der: nameDER(atvDER(tb, oidGN, asn1.TagIA5String, []byte("JUAN\x80"))), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid, values: []string{"JUAN\x80"}},

		// R53 in the other string kinds.
		{name: "bmp soft hyphen", der: bmp('J', 0x00ad, 'N'), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid, rule: "format character"},
		{name: "bmp noncharacter U+FFFE", der: bmp('J', 0xfffe), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid, rule: "noncharacter"},
		{name: "bmp private use", der: bmp('J', 0xe000), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid, rule: "private-use character"},
		{name: "teletex NBSP", der: nameDER(atvDER(tb, oidGN, testpki.TagTeletex, []byte("JU\xa0AN"))), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid, rule: "space other than U+0020"},
		{name: "teletex soft hyphen", der: nameDER(atvDER(tb, oidGN, testpki.TagTeletex, []byte("JU\xadAN"))), oid: oidGN, kinds: all, wantErr: identity.ErrInvalid, rule: "format character"},

		// Spanish and Catalan names keep passing: Ñ, Ç, À, Ü, the Catalan
		// middle dot, apostrophe, hyphen, lower case and combining marks.
		{name: "Spanish and Catalan letters", der: utf8(spanishNames), oid: oidGN, kinds: k, want: spanishNames, found: true},
		{name: "Spanish lower case", der: utf8("Peña Çabrera Àlvarez Güell"), oid: oidGN, kinds: k, want: "Peña Çabrera Àlvarez Güell", found: true},
		{name: "decomposed accents", der: utf8("PEN\u0303A GU\u0308ELL"), oid: oidGN, kinds: k, want: "PEN\u0303A GU\u0308ELL", found: true},
		{name: "teletex Latin-1 letters", der: nameDER(atvDER(tb, oidGN, testpki.TagTeletex, []byte("PE\xd1A \xc7\xc0\xdc\xb7L'O-K"))), oid: oidGN, kinds: all, want: "PEÑA ÇÀÜ·L'O-K", found: true},
		{name: "bmp Spanish letters", der: bmp('P', 'E', 0x00d1, 'A', ' ', 0x00b7), oid: oidGN, kinds: all, want: "PEÑA ·", found: true},
		{name: "decomposed Catalan lower case", der: utf8(decomposedCatalan), oid: oidGN, kinds: k, want: decomposedCatalan, found: true},

		// R5.1: a run of more than 4 combining marks is rejected; x/text
		// itself inserts U+034F after 30 non-starters.
		{name: "four combining marks", der: utf8(combiningRun(4)), oid: oidGN, kinds: k, want: combiningRun(4), found: true},
		{name: "five combining marks", der: utf8(combiningRun(5)), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, rule: "too many combining marks", values: []string{combiningRun(5)}},
		{name: "31 combining marks", der: utf8(combiningRun(31)), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, rule: "too many combining marks", values: []string{combiningRun(31)}},
		{name: "five combining marks of mixed classes", der: utf8("JU\u0301\u0903\u0302\u20dd\u0303AN"), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, rule: "too many combining marks"},
		{name: "two runs of four combining marks", der: utf8("JU\u0301\u0302\u0303\u0308A\u0301\u0302\u0303\u0308N"), oid: oidGN, kinds: k,
			want: "JU\u0301\u0302\u0303\u0308A\u0301\u0302\u0303\u0308N", found: true},
	}
	for _, ic := range invisibleChars {
		v := "JU" + string(ic.r) + "AN"
		cases = append(cases, fieldCase{name: ic.name, der: utf8(v), oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, rule: ic.rule, values: []string{v}})
	}
	return cases
}

// spanishNames exercises every non-ASCII letter class a Spanish or Catalan
// name uses; ruling R53 must keep accepting it.
const spanishNames = "MARÍA ÀNGELS D'ARBÓS-GÜELL PEÑA COL·LEGI ÇALÓ"

// decomposedCatalan is lower-case Catalan and Spanish in NFD: ç, ó, l·l, ñ,
// ú, à and an apostrophe.
const decomposedCatalan = "c\u0327alo\u0301 col·l n\u0303u\u0301ria d'a\u0300ngels"

// combiningRun returns "JUA", n combining acute accents, then "N".
func combiningRun(n int) string { return "JUA" + strings.Repeat("\u0301", n) + "N" }

// invisibleChars has at least one code point per class rejected by ruling
// R53, with the rule its error must name.
var invisibleChars = []struct {
	name string
	r    rune
	rule string
}{
	{"Cf soft hyphen U+00AD", 0x00ad, "format character"},
	{"Cf zero width space U+200B", 0x200b, "format character"},
	{"Cf zero width non-joiner U+200C", 0x200c, "format character"},
	{"Cf zero width joiner U+200D", 0x200d, "format character"},
	{"Cf word joiner U+2060", 0x2060, "format character"},
	{"Cf invisible plus U+2064", 0x2064, "format character"},
	{"Cf byte order mark U+FEFF", 0xfeff, "format character"},
	{"Cf Arabic number sign U+0600", 0x0600, "format character"},
	{"Cf language tag U+E0001", 0xe0001, "format character"},
	{"Zl line separator U+2028", 0x2028, "line or paragraph separator"},
	{"Zp paragraph separator U+2029", 0x2029, "line or paragraph separator"},
	{"Co private use U+E000", 0xe000, "private-use character"},
	{"Co private use U+F8FF", 0xf8ff, "private-use character"},
	{"Co plane 15 U+F0000", 0xf0000, "private-use character"},
	{"Co plane 16 U+10FFFD", 0x10fffd, "private-use character"},
	{"noncharacter U+FDD0", 0xfdd0, "noncharacter"},
	{"noncharacter U+FDEF", 0xfdef, "noncharacter"},
	{"noncharacter U+FFFE", 0xfffe, "noncharacter"},
	{"noncharacter U+FFFF", 0xffff, "noncharacter"},
	{"noncharacter U+1FFFE", 0x1fffe, "noncharacter"},
	{"noncharacter U+10FFFF", 0x10ffff, "noncharacter"},
	{"Zs no-break space U+00A0", 0x00a0, "space other than U+0020"},
	{"Zs ogham space U+1680", 0x1680, "space other than U+0020"},
	{"Zs en quad U+2000", 0x2000, "space other than U+0020"},
	{"Zs hair space U+200A", 0x200a, "space other than U+0020"},
	{"Zs narrow no-break space U+202F", 0x202f, "space other than U+0020"},
	{"Zs medium math space U+205F", 0x205f, "space other than U+0020"},
	{"Zs ideographic space U+3000", 0x3000, "space other than U+0020"},
	// U6-ASTRA-1: invisible code points outside Cf. ComparisonKey drops the
	// Mn ones, so before R5.1 they also survived the SAN consistency check.
	{"Mn combining grapheme joiner U+034F", 0x034f, "default-ignorable character"},
	{"Lo Hangul choseong filler U+115F", 0x115f, "default-ignorable character"},
	{"Lo Hangul filler U+3164", 0x3164, "default-ignorable character"},
	{"Mn variation selector-16 U+FE0F", 0xfe0f, "variation selector"},
	{"Mn Mongolian free variation selector U+180B", 0x180b, "variation selector"},
	{"Mn variation selector-17 U+E0100", 0xe0100, "variation selector"},
}

func TestNameFieldText(t *testing.T) { runFieldCases(t, nameFieldTextCases(t)) }

func nameFieldDuplicateCases(tb testing.TB) []fieldCase {
	k := identity.DefaultKinds
	return []fieldCase{
		{
			name: "identical duplicates",
			der:  testpki.Name{testpki.UTF8(oidGN, "JUAN"), testpki.UTF8(oidSN, "GARCIA"), testpki.UTF8(oidGN, "JUAN")}.DER(),
			oid:  oidGN, kinds: k, want: "JUAN", found: true,
		},
		{
			name: "identical text in two string kinds",
			der:  testpki.Name{testpki.UTF8(oidGN, "JUAN"), testpki.Printable(oidGN, "JUAN")}.DER(),
			oid:  oidGN, kinds: k, want: "JUAN", found: true,
		},
		{
			name: "identical inside a multi-valued RDN",
			der:  testpki.Name{{{OID: oidGN, Value: "JUAN"}, {OID: oidGN, Value: "JUAN"}}}.DER(),
			oid:  oidGN, kinds: k, want: "JUAN", found: true,
		},
		{
			name: "conflicting duplicates", der: testpki.Name{testpki.UTF8(oidGN, "JUAN"), testpki.UTF8(oidGN, "PEDRO")}.DER(),
			oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN", "PEDRO"},
		},
		{
			name: "conflicting inside a multi-valued RDN", der: testpki.Name{{{OID: oidSN, Value: "GARCIA"}, {OID: oidSN, Value: "LOPEZ"}}}.DER(),
			oid: oidSN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"GARCIA", "LOPEZ"},
		},
		{
			name: "duplicates differing only in case", der: testpki.Name{testpki.UTF8(oidGN, "JUAN"), testpki.UTF8(oidGN, "Juan")}.DER(),
			oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN", "Juan"},
		},
		{
			name: "second occurrence has a rejected kind", der: testpki.Name{testpki.UTF8(oidGN, "JUAN"), testpki.Tagged(oidGN, testpki.TagBMP, "JUAN")}.DER(),
			oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN"},
		},
		{
			name: "second occurrence has a control character", der: nameDER(atvDER(tb, oidGN, asn1.TagUTF8String, []byte("JUAN")), atvDER(tb, oidGN, asn1.TagUTF8String, []byte("JUAN\n"))),
			oid: oidGN, kinds: k, wantErr: identity.ErrInvalid, values: []string{"JUAN"},
		},
	}
}

func TestNameFieldDuplicates(t *testing.T) { runFieldCases(t, nameFieldDuplicateCases(t)) }

// malformedNameCase is a DER input ParseName must reject.
type malformedNameCase struct {
	name string
	der  []byte
}

func malformedNameCases(tb testing.TB) []malformedNameCase {
	good := testpki.Name{testpki.Printable(identity.OIDCountry, "ES"), testpki.UTF8(oidGN, "JUAN")}.DER()
	gnATV := atvDER(tb, oidGN, asn1.TagUTF8String, []byte("JUAN"))
	many := func(n int) []byte {
		var atvs [][]byte
		for range n {
			atvs = append(atvs, gnATV)
		}
		return nameDER(atvs...)
	}
	return []malformedNameCase{
		{"empty input", nil},
		{"truncated", good[:len(good)-1]},
		{"truncated header", good[:1]},
		{"trailing bytes", append(append([]byte{}, good...), 0x00)},
		{"trailing second sequence", append(append([]byte{}, good...), seqDER()...)},
		{"outer SET instead of SEQUENCE", setDER(setDER(gnATV))},
		{"RDN is a SEQUENCE", seqDER(seqDER(gnATV))},
		{"RDN is a primitive", seqDER(tlv(asn1.TagUTF8String, []byte("JUAN")))},
		{"RDN is context-specific", seqDER(tlv(0xa1, gnATV))},
		{"empty SET", seqDER(setDER())},
		{"ATV is not a SEQUENCE", seqDER(setDER(setDER(oidDER(tb, oidGN), tlv(asn1.TagUTF8String, []byte("JUAN")))))},
		{"ATV without value", seqDER(setDER(seqDER(oidDER(tb, oidGN))))},
		{"ATV empty SEQUENCE", seqDER(setDER(seqDER()))},
		// R52: nothing may follow the value.
		{"ATV with a trailing extra element", seqDER(setDER(seqDER(oidDER(tb, oidGN), tlv(asn1.TagUTF8String, []byte("JUAN")), tlv(asn1.TagUTF8String, []byte("PEDRO")))))},
		{"ATV with a trailing NULL", seqDER(setDER(seqDER(oidDER(tb, oidGN), tlv(asn1.TagUTF8String, []byte("JUAN")), []byte{asn1.TagNull, 0x00})))},
		{"ATV with a trailing byte", seqDER(setDER(seqDER(oidDER(tb, oidGN), tlv(asn1.TagUTF8String, []byte("JUAN")), []byte{0x00})))},
		{"second ATV in an RDN with a trailing element", seqDER(setDER(gnATV, seqDER(oidDER(tb, oidSN), tlv(asn1.TagUTF8String, []byte("GARCIA")), tlv(asn1.TagUTF8String, []byte("LOPEZ")))))},
		{"ATV context-specific constructed", seqDER(setDER(tlv(0xb0, oidDER(tb, oidGN), tlv(asn1.TagUTF8String, []byte("JUAN")))))},
		{"ATV primitive with the SEQUENCE tag number", seqDER(setDER(tlv(0x10, oidDER(tb, oidGN), tlv(asn1.TagUTF8String, []byte("JUAN")))))},
		{"ATV type is not an OID", seqDER(setDER(seqDER(tlv(asn1.TagUTF8String, []byte("2.5.4.42")), tlv(asn1.TagUTF8String, []byte("JUAN")))))},
		{"ATV value truncated", seqDER(setDER(seqDER(oidDER(tb, oidGN), []byte{asn1.TagUTF8String, 0x05, 'J'})))},
		{"non-minimal length", append([]byte{tagSequence, 0x81, byte(len(good) - 2)}, good[2:]...)},
		{"indefinite length", append(append([]byte{tagSequence, 0x80}, good[2:]...), 0x00, 0x00)},
		{"65 attributes", many(65)},
		{"65 attributes in one RDN", seqDER(setDER(func() [][]byte {
			var a [][]byte
			for range 65 {
				a = append(a, gnATV)
			}
			return a
		}()...))},
	}
}

func TestParseNameMalformed(t *testing.T) {
	for _, tc := range malformedNameCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			n, err := identity.ParseName(tc.der)
			if !errors.Is(err, identity.ErrInvalid) {
				t.Fatalf("ParseName err = %v, want ErrInvalid", err)
			}
			if len(n.Attributes) != 0 {
				t.Errorf("ParseName returned %d attributes with an error, want 0", len(n.Attributes))
			}
		})
	}

	t.Run("64 attributes", func(t *testing.T) {
		gnATV := atvDER(t, oidGN, asn1.TagUTF8String, []byte("JUAN"))
		var atvs [][]byte
		for range 64 {
			atvs = append(atvs, gnATV)
		}
		n := mustParseName(t, nameDER(atvs...))
		if got, want := len(n.Attributes), 64; got != want {
			t.Errorf("attributes = %d, want %d", got, want)
		}
	})

	t.Run("constructed value kept as KindOther", func(t *testing.T) {
		der := nameDER(
			atvDER(t, identity.OIDCountry, asn1.TagPrintableString, []byte("ES")),
			seqDER(oidDER(t, oidGN), seqDER(tlv(asn1.TagUTF8String, []byte("JUAN")))),
		)
		n := mustParseName(t, der)
		if got, want := len(n.Attributes), 2; got != want {
			t.Fatalf("attributes = %d, want %d", got, want)
		}
		a := n.Attributes[1]
		if a.Kind != identity.KindOther || a.Err == nil || a.Text != "" {
			t.Errorf("constructed value: Kind=%v Err=%v Text=%q, want KindOther, non-nil Err, empty Text", a.Kind, a.Err, a.Text)
		}
		all := identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP, identity.KindTeletex, identity.KindIA5, identity.KindOther}
		if _, _, err := n.Field(oidGN, all); !errors.Is(err, identity.ErrInvalid) {
			t.Errorf("Field on constructed value err = %v, want ErrInvalid", err)
		}
		if v, ok, err := n.Field(identity.OIDCountry, identity.DefaultKinds); err != nil || !ok || v != "ES" {
			t.Errorf("Field(C) = (%q, %v, %v), want (\"ES\", true, nil)", v, ok, err)
		}
	})

	t.Run("non-universal and non-string values", func(t *testing.T) {
		der := nameDER(
			seqDER(oidDER(t, oidGN), tlv(0x80, []byte("JUAN"))),       // context-specific primitive
			seqDER(oidDER(t, oidSN), tlv(asn1.TagInteger, []byte{1})), // universal, not a string
		)
		n := mustParseName(t, der)
		for _, a := range n.Attributes {
			if a.Kind != identity.KindOther || a.Text != "" {
				t.Errorf("attribute %s: Kind=%v Text=%q, want KindOther and empty Text", a.OID, a.Kind, a.Text)
			}
			if _, _, err := n.Field(a.OID, identity.DefaultKinds); !errors.Is(err, identity.ErrInvalid) {
				t.Errorf("Field(%s) err = %v, want ErrInvalid", a.OID, err)
			}
		}
	})
}
