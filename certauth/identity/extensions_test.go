package identity_test

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// generalName encodes a context-specific GeneralName.
func generalName(n byte, constructed bool, contents []byte) []byte {
	tag := 0x80 | n
	if constructed {
		tag |= 0x20
	}
	return tlv(tag, contents)
}

func dirNameGN(n testpki.Name) []byte { return generalName(4, true, n.DER()) }

func TestParseSANDirectoryNames(t *testing.T) {
	first := testpki.Name{testpki.UTF8(identity.OIDGivenName, "JUAN"), testpki.UTF8(identity.OIDSurname, "GARCIA")}
	second := testpki.Name{testpki.UTF8(identity.OIDCommonName, "JUAN|GARCIA|LOPEZ"), testpki.UTF8(identity.OIDUID, "12345678Z")}
	email := generalName(1, false, []byte("ca-mailbox@example.org"))
	dns := generalName(2, false, []byte("example.org"))

	many := func(n int, gn []byte) []byte {
		var gns [][]byte
		for range n {
			gns = append(gns, gn)
		}
		return seqDER(gns...)
	}

	tests := []struct {
		name    string
		der     []byte
		want    [][]string // per dirName: attribute texts in order
		wantErr bool
	}{
		{name: "email and two dirNames", der: seqDER(email, dirNameGN(first), dns, dirNameGN(second)),
			want: [][]string{{"JUAN", "GARCIA"}, {"JUAN|GARCIA|LOPEZ", "12345678Z"}}},
		{name: "DNS only", der: seqDER(dns), want: nil},
		{name: "empty GeneralNames", der: seqDER(), want: nil},
		{name: "64 entries", der: many(64, dns), want: nil},
		{name: "65 entries", der: many(65, dns), wantErr: true},
		{name: "65 dirNames", der: many(65, dirNameGN(first)), wantErr: true},
		{name: "malformed: truncated", der: seqDER(email, dirNameGN(first))[:20], wantErr: true},
		{name: "malformed: trailing bytes", der: append(seqDER(dns), 0x00), wantErr: true},
		{name: "malformed: not a SEQUENCE", der: setDER(dns), wantErr: true},
		{name: "malformed: empty input", der: nil, wantErr: true},
		{name: "dirName not constructed", der: seqDER(generalName(4, false, first.DER())), wantErr: true},
		{name: "GeneralName not context-specific", der: seqDER(tlv(asn1.TagUTF8String, []byte("JUAN"))), wantErr: true},
		{name: "dirName holds a malformed Name", der: seqDER(generalName(4, true, seqDER(setDER()))), wantErr: true},
		{name: "dirName holds trailing bytes", der: seqDER(generalName(4, true, append(first.DER(), 0x00))), wantErr: true},
		{name: "dirName holds two Names", der: seqDER(generalName(4, true, append(first.DER(), second.DER()...))), wantErr: true},
		{name: "dirName ATV with a trailing extra element (R52)", der: seqDER(generalName(4, true, seqDER(setDER(seqDER(
			oidDER(t, identity.OIDGivenName), tlv(asn1.TagUTF8String, []byte("JUAN")), tlv(asn1.TagUTF8String, []byte("PEDRO"))))))), wantErr: true},
		{name: "dirName ATV without value (R52)", der: seqDER(generalName(4, true, seqDER(setDER(seqDER(oidDER(t, identity.OIDGivenName)))))), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := identity.ParseSANDirectoryNames(tc.der)
			if tc.wantErr {
				if !errors.Is(err, identity.ErrInvalid) {
					t.Fatalf("err = %v, want ErrInvalid", err)
				}
				if got != nil {
					t.Errorf("got %d names with an error, want nil", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			var texts [][]string
			for _, n := range got {
				var row []string
				for _, a := range n.Attributes {
					row = append(row, a.Text)
				}
				texts = append(texts, row)
			}
			if len(texts) != len(tc.want) {
				t.Fatalf("got %d dirNames %q, want %d %q", len(texts), texts, len(tc.want), tc.want)
			}
			for i := range texts {
				if len(texts[i]) != len(tc.want[i]) {
					t.Fatalf("dirName %d = %q, want %q", i, texts[i], tc.want[i])
				}
				for j := range texts[i] {
					if texts[i][j] != tc.want[i][j] {
						t.Errorf("dirName %d attribute %d = %q, want %q", i, j, texts[i][j], tc.want[i][j])
					}
				}
			}
		})
	}

	// R53 through the SAN path: the dirName parses, reading the attribute fails.
	t.Run("dirName attribute text", func(t *testing.T) {
		read := func(t *testing.T, v string) (string, error) {
			t.Helper()
			fnmtGiven := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 5734, 1, 1}
			names, err := identity.ParseSANDirectoryNames(seqDER(email, dirNameGN(testpki.Name{testpki.UTF8(fnmtGiven, v)})))
			if err != nil || len(names) != 1 {
				t.Fatalf("ParseSANDirectoryNames = %d names, %v; want 1, nil", len(names), err)
			}
			got, _, err := names[0].Field(fnmtGiven, identity.DefaultKinds)
			return got, err
		}
		for _, ic := range invisibleChars {
			t.Run(ic.name, func(t *testing.T) {
				v := "JU" + string(ic.r) + "AN"
				_, err := read(t, v)
				if !errors.Is(err, identity.ErrInvalid) || !strings.Contains(err.Error(), ic.rule) {
					t.Fatalf("Field err = %v, want ErrInvalid naming %q", err, ic.rule)
				}
				if strings.Contains(err.Error(), v) {
					t.Errorf("error %q echoes the value", err)
				}
			})
		}
		t.Run("Spanish and Catalan letters", func(t *testing.T) {
			if got, err := read(t, spanishNames); err != nil || got != spanishNames {
				t.Errorf("Field = (%q, %v), want (%q, nil)", got, err, spanishNames)
			}
		})
	})

	t.Run("certificate", func(t *testing.T) {
		ca := testpki.NewRoot(t, "san-root", testpki.CertSpec{})
		subj := testpki.Name{testpki.UTF8(identity.OIDCommonName, "LEAF")}
		with := ca.Leaf(t, testpki.CertSpec{Subject: subj, SANEmails: []string{"ca-mailbox@example.org"}, SANDirNames: []testpki.Name{first, second}})
		got, err := identity.DirectoryNames(with.Cert)
		if err != nil || len(got) != 2 {
			t.Fatalf("DirectoryNames = %d names, %v; want 2, nil", len(got), err)
		}
		if v, ok, err := got[1].Field(identity.OIDUID, identity.DefaultKinds); err != nil || !ok || v != "12345678Z" {
			t.Errorf("second dirName UID = (%q, %v, %v), want (\"12345678Z\", true, nil)", v, ok, err)
		}
		without := ca.Leaf(t, testpki.CertSpec{Subject: subj})
		got, err = identity.DirectoryNames(without.Cert)
		if err != nil || got != nil {
			t.Errorf("DirectoryNames without SAN = (%v, %v), want (nil, nil)", got, err)
		}
	})
}

// dobAttr encodes one SDA Attribute with the given raw values.
func dobAttr(tb testing.TB, oid asn1.ObjectIdentifier, values ...[]byte) []byte {
	tb.Helper()
	return seqDER(oidDER(tb, oid), setDER(values...))
}

// sdaCase is one ParseDateOfBirth call.
type sdaCase struct {
	name      string
	der       []byte
	want      identity.Date
	wantFound bool
	wantErr   bool
	values    []string // input values an error must not echo
}

func dateOfBirthCases(tb testing.TB) []sdaCase {
	gt := func(s string) []byte { return tlv(tagGeneralizedTime, []byte(s)) }
	dob := testpki.OIDAttrDateOfBirth
	residence := dobAttr(tb, testpki.OIDAttrCountryOfResidence, tlv(asn1.TagPrintableString, []byte("ES")))
	return []sdaCase{
		{name: "noon", der: testpki.DateOfBirthSDA("19800101120000Z"), want: identity.Date{Year: 1980, Month: time.January, Day: 1}, wantFound: true},
		{name: "midnight", der: testpki.DateOfBirthSDA("20000529000000Z"), want: identity.Date{Year: 2000, Month: time.May, Day: 29}, wantFound: true},
		{name: "leap day", der: testpki.DateOfBirthSDA("20000229235959Z"), want: identity.Date{Year: 2000, Month: time.February, Day: 29}, wantFound: true},
		{name: "countryOfResidence ignored (before)", der: seqDER(residence, dobAttr(tb, dob, gt("19800101120000Z"))), want: identity.Date{Year: 1980, Month: time.January, Day: 1}, wantFound: true},
		{name: "countryOfResidence ignored (after)", der: seqDER(dobAttr(tb, dob, gt("19800101120000Z")), residence), want: identity.Date{Year: 1980, Month: time.January, Day: 1}, wantFound: true},
		{name: "absent", der: seqDER(residence), wantFound: false},
		{name: "empty attributes", der: seqDER(), wantFound: false},
		{name: "UTCTime", der: seqDER(dobAttr(tb, dob, tlv(tagUTCTime, []byte("800101120000Z")))), wantErr: true, values: []string{"800101120000Z"}},
		{name: "two values", der: seqDER(dobAttr(tb, dob, gt("19800101120000Z"), gt("19800102120000Z"))), wantErr: true, values: []string{"19800101120000Z", "19800102120000Z"}},
		{name: "no values", der: seqDER(dobAttr(tb, dob)), wantErr: true},
		{name: "two dateOfBirth attributes", der: seqDER(dobAttr(tb, dob, gt("19800101120000Z")), dobAttr(tb, dob, gt("19800101120000Z"))), wantErr: true, values: []string{"19800101120000Z"}},
		{name: "February 30", der: testpki.DateOfBirthSDA("19800230120000Z"), wantErr: true, values: []string{"19800230120000Z"}},
		{name: "month 13", der: testpki.DateOfBirthSDA("19801301120000Z"), wantErr: true, values: []string{"19801301120000Z"}},
		{name: "hour 24", der: testpki.DateOfBirthSDA("19800101240000Z"), wantErr: true, values: []string{"19800101240000Z"}},
		{name: "no seconds", der: testpki.DateOfBirthSDA("198001011200Z"), wantErr: true, values: []string{"198001011200Z"}},
		{name: "fraction", der: testpki.DateOfBirthSDA("19800101120000.5Z"), wantErr: true, values: []string{"19800101120000.5Z"}},
		{name: "offset", der: testpki.DateOfBirthSDA("19800101120000+0100"), wantErr: true, values: []string{"19800101120000+0100"}},
		{name: "no zone", der: testpki.DateOfBirthSDA("19800101120000"), wantErr: true, values: []string{"19800101120000"}},
		{name: "signed year", der: testpki.DateOfBirthSDA("+9800101120000Z"), wantErr: true, values: []string{"+9800101120000Z"}},
		{name: "date only", der: testpki.DateOfBirthSDA("19800101"), wantErr: true, values: []string{"19800101"}},
		{name: "PrintableString value", der: seqDER(dobAttr(tb, dob, tlv(asn1.TagPrintableString, []byte("19800101120000Z")))), wantErr: true, values: []string{"19800101120000Z"}},
		{name: "constructed GeneralizedTime", der: seqDER(dobAttr(tb, dob, tlv(0x20|tagGeneralizedTime, gt("19800101120000Z")))), wantErr: true},
		{name: "values not a SET", der: seqDER(seqDER(oidDER(tb, dob), seqDER(gt("19800101120000Z")))), wantErr: true},
		{name: "truncated", der: testpki.DateOfBirthSDA("19800101120000Z")[:10], wantErr: true},
		{name: "trailing bytes", der: append(testpki.DateOfBirthSDA("19800101120000Z"), 0x00), wantErr: true},
		{name: "not a SEQUENCE", der: setDER(dobAttr(tb, dob, gt("19800101120000Z"))), wantErr: true},
		{name: "empty input", der: nil, wantErr: true},
	}
}

func TestDateOfBirth(t *testing.T) {
	for _, tc := range dateOfBirthCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			got, found, err := identity.ParseDateOfBirth(tc.der)
			if tc.wantErr {
				if !errors.Is(err, identity.ErrInvalid) {
					t.Fatalf("err = %v, want ErrInvalid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if got != tc.want || found != tc.wantFound {
				t.Errorf("ParseDateOfBirth = (%v, %v), want (%v, %v)", got, found, tc.want, tc.wantFound)
			}
		})
	}

	t.Run("certificate", func(t *testing.T) {
		ca := testpki.NewRoot(t, "sda-root", testpki.CertSpec{})
		subj := testpki.Name{testpki.UTF8(identity.OIDCommonName, "LEAF")}
		with := ca.Leaf(t, testpki.CertSpec{Subject: subj, DateOfBirth: "19800101120000Z"})
		d, found, err := identity.DateOfBirth(with.Cert)
		if err != nil || !found || d != (identity.Date{Year: 1980, Month: time.January, Day: 1}) {
			t.Errorf("DateOfBirth = (%v, %v, %v), want (1980-01-01, true, nil)", d, found, err)
		}
		without := ca.Leaf(t, testpki.CertSpec{Subject: subj})
		d, found, err = identity.DateOfBirth(without.Cert)
		if err != nil || found || d != (identity.Date{}) {
			t.Errorf("DateOfBirth without SDA = (%v, %v, %v), want (zero, false, nil)", d, found, err)
		}
		bad := ca.Leaf(t, testpki.CertSpec{Subject: subj, SDARaw: []byte{0x30, 0x05}})
		if _, _, err := identity.DateOfBirth(bad.Cert); !errors.Is(err, identity.ErrInvalid) {
			t.Errorf("DateOfBirth malformed SDA err = %v, want ErrInvalid", err)
		}
	})

	t.Run("format", func(t *testing.T) {
		d := identity.Date{Year: 987, Month: time.March, Day: 4}
		if got, want := d.String(), "0987-03-04"; got != want {
			t.Errorf("String = %q, want %q", got, want)
		}
		b, err := json.Marshal(struct {
			D  identity.Date  `json:"d"`
			P  *identity.Date `json:"p"`
			NP *identity.Date `json:"np"`
		}{D: d, P: &d})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(b), `{"d":"0987-03-04","p":"0987-03-04","np":null}`; got != want {
			t.Errorf("JSON = %s, want %s", got, want)
		}
	})
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"MUN\u0303OZ", "MU\u00d1OZ"}, // NFD → NFC
		{"MU\u00d1OZ", "MU\u00d1OZ"},
		{"\u00a0 MU\u00d1OZ\u00a0 GARCI\u0301A ", "MU\u00d1OZ GARC\u00cdA"}, // NBSP is white space; I+U+0301 → Í
		{"  GARCIA   LOPEZ  ", "GARCIA LOPEZ"},
		{"GARCIA\t\tLOPEZ", "GARCIA LOPEZ"},
		{"GARCIA \t  LOPEZ", "GARCIA LOPEZ"},
		{"DE LA PEÇA DE PROVES", "DE LA PEÇA DE PROVES"}, // never reorders or splits
		{"O'NEIL-SMITH", "O'NEIL-SMITH"},
		{"José", "José"}, // case is kept
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range tests {
		if got := identity.NormalizeName(tc.in); got != tc.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestComparisonKey(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"ESPECIMEN-DIEZ", "ESPECIMEN-DÍEZ", true},
		{"MUÑOZ", "MUNOZ", true},
		{"MUN\u0303OZ", "MUÑOZ", true},
		{"muñoz", "MUNOZ", true},
		{"GÜENOS", "GUENOS", true},
		{"  GARCIA  LOPEZ ", "GARCIA LOPEZ", true},
		{"PEÇA", "PECA", true},
		{"GARCIA", "GARCIAS", false},
		{"GARCIA LOPEZ", "GARCIALOPEZ", false},
		{"GARCIA LOPEZ", "LOPEZ GARCIA", false},
		{"O'NEIL", "ONEIL", false},
	}
	for _, tc := range tests {
		ka, kb := identity.ComparisonKey(tc.a), identity.ComparisonKey(tc.b)
		if got := ka == kb; got != tc.want {
			t.Errorf("ComparisonKey(%q) == ComparisonKey(%q): got %v (%q vs %q), want %v", tc.a, tc.b, got, ka, kb, tc.want)
		}
	}
	if got, want := identity.ComparisonKey("Especimen-Díez"), "ESPECIMEN-DIEZ"; got != want {
		t.Errorf("ComparisonKey = %q, want %q", got, want)
	}
}
