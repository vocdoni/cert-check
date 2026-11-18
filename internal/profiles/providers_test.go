package profiles_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// provTSourceRow is one row of anchors/SOURCES.md.
type provTSourceRow struct {
	file, fileSHA256, derSHA256, spkiSHA256 string
}

// provTSources parses the anchors/SOURCES.md table rows whose first cell
// names a .pem file. Columns: file | subject | source | file SHA-256 |
// DER SHA-256 | SPKI SHA-256 | TSL service status.
func provTSources(t *testing.T) map[string]provTSourceRow {
	t.Helper()
	raw, err := os.ReadFile(path.Join("anchors", "SOURCES.md"))
	if err != nil {
		t.Fatalf("read anchors/SOURCES.md: %v", err)
	}
	rows := map[string]provTSourceRow{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i, c := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(c, "`", ""))
		}
		if !strings.HasSuffix(cells[0], ".pem") {
			continue
		}
		if len(cells) != 7 {
			t.Fatalf("SOURCES.md row %q: got %d cells, want 7", cells[0], len(cells))
		}
		if _, dup := rows[cells[0]]; dup {
			t.Errorf("SOURCES.md lists %s twice", cells[0])
		}
		rows[cells[0]] = provTSourceRow{file: cells[0], fileSHA256: cells[3], derSHA256: cells[4], spkiSHA256: cells[5]}
	}
	if len(rows) == 0 {
		t.Fatal("anchors/SOURCES.md has no rows")
	}
	return rows
}

func provTHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestAnchorFiles (AC5) checks every embedded anchor file and every pin.
func TestAnchorFiles(t *testing.T) {
	refs := map[string]int{} // anchor file -> number of pins referencing it
	for _, p := range profiles.All() {
		for _, prof := range p.Profiles {
			for _, a := range slices.Concat(prof.Anchors, prof.Intermediates) {
				refs[a.File]++
				if want := "anchors/" + a.SHA256 + ".pem"; a.File != want || a.DER != nil {
					t.Errorf("%s: anchor File = %q (DER set %v), want %q from the embedded FS", prof.ID, a.File, a.DER != nil, want)
				}
				if _, err := fs.Stat(profiles.AnchorsFS(), a.File); err != nil {
					t.Errorf("%s: referenced file %s: %v", prof.ID, a.File, err)
				}
			}
		}
	}

	embedded, err := fs.Glob(profiles.AnchorsFS(), "anchors/*.pem")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(embedded) != 29 {
		t.Errorf("embedded %d anchor files, want 29", len(embedded))
	}
	onDisk, err := os.ReadDir("anchors")
	if err != nil {
		t.Fatalf("read anchors dir: %v", err)
	}
	for _, e := range onDisk {
		if e.Name() == "SOURCES.md" {
			continue
		}
		if !slices.Contains(embedded, "anchors/"+e.Name()) {
			t.Errorf("anchors/%s is not an embedded .pem anchor; remove it", e.Name())
		}
	}

	sources := provTSources(t)
	now := time.Now()
	for _, name := range embedded {
		t.Run(path.Base(name), func(t *testing.T) {
			if n := refs[name]; n != 1 {
				t.Errorf("referenced by %d pins, want exactly 1", n)
			}
			raw, err := fs.ReadFile(profiles.AnchorsFS(), name)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
				t.Error("file does not start with a PEM CERTIFICATE header")
			}
			blk, rest := pem.Decode(raw)
			if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
				t.Fatal("want one PEM CERTIFICATE block without headers")
			}
			if len(bytes.TrimSpace(rest)) != 0 {
				t.Errorf("%d bytes after the PEM block, want exactly one block", len(rest))
			}
			der := provTHex(blk.Bytes)
			if want := strings.TrimSuffix(path.Base(name), ".pem"); der != want {
				t.Errorf("DER SHA-256 = %s, want the file name %s", der, want)
			}
			row, ok := sources[path.Base(name)]
			if !ok {
				t.Fatal("no row in anchors/SOURCES.md")
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				t.Fatalf("ParseCertificate (Go 1.27): %v", err)
			}
			if got := provTHex(raw); got != row.fileSHA256 {
				t.Errorf("file SHA-256 = %s, SOURCES.md has %s", got, row.fileSHA256)
			}
			if row.derSHA256 != der {
				t.Errorf("SOURCES.md DER SHA-256 = %s, want %s", row.derSHA256, der)
			}
			if got := provTHex(c.RawSubjectPublicKeyInfo); got != row.spkiSHA256 {
				t.Errorf("SPKI SHA-256 = %s, SOURCES.md has %s", got, row.spkiSHA256)
			}
			if !c.BasicConstraintsValid || !c.IsCA {
				t.Error("not CA:TRUE")
			}
			if now.Before(c.NotBefore) || now.After(c.NotAfter) {
				t.Errorf("not valid now: %s..%s", c.NotBefore, c.NotAfter)
			}
			if len(c.UnhandledCriticalExtensions) != 0 {
				t.Errorf("unhandled critical extensions %v", c.UnhandledCriticalExtensions)
			}
			if len(c.ExtKeyUsage)+len(c.UnknownExtKeyUsage) > 0 &&
				!slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) && !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny) {
				t.Errorf("EKU %v %v does not allow clientAuth", c.ExtKeyUsage, c.UnknownExtKeyUsage)
			}
		})
	}
	for f := range sources {
		if !slices.Contains(embedded, "anchors/"+f) {
			t.Errorf("SOURCES.md lists %s, which is not an embedded anchor", f)
		}
	}
}

// Independent restatement of the Task 6 per-profile table. It is written from
// the plan and the research digests, not from providers.go.

func provTPins(pairs ...string) [][2]string {
	var out [][2]string
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, [2]string{pairs[i], pairs[i+1]})
	}
	return out
}

var (
	provTDNINIE   = []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}
	provTIDCES    = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: provTDNINIE}}
	provTBare     = []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: provTDNINIE}}
	provTSANNone  = identity.SANCheck{Kind: identity.SANNone}
	provTFNMT     = func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 5734, 1, n} }
	provTEmployee = func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{2, 16, 724, 1, 3, 5, 7, 2, n} }
	provT13177    = func(n int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 13177, 0, n} }
)

func provTPlain() identity.Adapter {
	return identity.Adapter{Documents: provTIDCES, Surnames: identity.SurnamesFromSN, SAN: provTSANNone,
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone}
}

func provTSAN(doc asn1.ObjectIdentifier, rules []identity.DocumentRule, given, first, second asn1.ObjectIdentifier) identity.SANCheck {
	return identity.SANCheck{Kind: identity.SANAttributes, DocumentOID: doc, DocumentRules: rules,
		GivenNameOID: given, FirstSurnameOID: first, SecondSurnameOID: second}
}

func provTFNMTCitizen(docs []identity.DocumentRule) identity.Adapter {
	a := provTPlain()
	a.Documents = docs
	a.SAN = provTSAN(provTFNMT(4), provTBare, provTFNMT(1), provTFNMT(2), provTFNMT(3))
	return a
}

func provTFNMTRepresentative() identity.Adapter {
	a := provTPlain()
	a.SAN = provTSAN(provTFNMT(4), provTIDCES, provTFNMT(1), provTFNMT(2), provTFNMT(3))
	a.Organization = identity.OrganizationFromSubject
	return a
}

func provTFNMTEmployee() identity.Adapter {
	a := provTPlain()
	a.SAN = provTSAN(provTEmployee(4), provTBare, provTEmployee(6), provTEmployee(7), provTEmployee(8))
	a.Organization = identity.OrganizationFromSubject
	return a
}

func provTIDCAT(legacy bool) identity.Adapter {
	a := provTPlain()
	a.CountryMatchesPrefix, a.LegacyDNISuffix = true, legacy
	return a
}

func provTACCV() identity.Adapter {
	a := provTPlain()
	a.Documents = provTBare
	a.SAN = identity.SANCheck{Kind: identity.SANPipeCN, DocumentOID: identity.OIDUID, DocumentRules: provTBare}
	return a
}

func provTFirmaprofesional() identity.Adapter {
	a := provTPlain()
	a.SAN = provTSAN(nil, nil, provT13177(1), provT13177(2), provT13177(3))
	return a
}

func provTSIGNE() identity.Adapter {
	a := provTFirmaprofesional()
	a.Documents = []identity.DocumentRule{
		{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{identity.DocumentDNI}},
		{Encoding: identity.EncodingPNOES, Types: []identity.DocumentType{identity.DocumentNIE}},
	}
	return a
}

func provTDNIe() identity.Adapter {
	return identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: []identity.DocumentType{identity.DocumentDNI}}},
		Surnames:  identity.SurnamesDNIeCN, SAN: provTSANNone,
		BirthDate: identity.BirthDateOptional, Organization: identity.OrganizationNone,
	}
}

// provTIdcatMarker is the AOC production test identity (DPC v7.4 §1.1.3).
var provTIdcatMarker = []profiles.AttributeMatch{
	{OID: identity.OIDGivenName, Value: "NOMDOS"},
	{OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"},
}

type provTRow struct {
	id, provider  string
	role          profiles.Role
	anchors       [][2]string // DER SHA-256, SPKI SHA-256
	intermediates [][2]string
	oids          []string
	eku           profiles.EKURule
	ocsp, crl     []string
	nonce         bool
	minRSA        int
	handled       []string
	adapter       identity.Adapter
	fingerprints  int
	subject       [][]profiles.AttributeMatch
}

var provTTable = []provTRow{
	{id: "fnmt-citizen-rsa", provider: "fnmt", role: profiles.RoleNaturalPerson,
		anchors: provTPins("601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869", "0b21720b91f0e45c43f2e7cb185f552eb7de7ed46b2ac172ee39b50841710a6f"),
		oids:    []string{"1.3.6.1.4.1.5734.3.10.1"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocspusu.cert.fnmt.es"}, crl: []string{"www.cert.fnmt.es"}, nonce: true,
		adapter: provTFNMTCitizen(slices.Concat(provTIDCES, provTBare)), fingerprints: 12},
	{id: "fnmt-citizen-g2", provider: "fnmt", role: profiles.RoleNaturalPerson,
		anchors: provTPins("283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89", "4a7bdf68ccebcdbfccfcdbe75ccb2d744e28be51a401fa34da558489696c807f"),
		oids:    []string{"1.3.6.1.4.1.5734.3.20.1.0"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocspusug2.cert.fnmt.es"}, crl: []string{"www.cert.fnmt.es"}, nonce: true,
		adapter: provTFNMTCitizen(provTIDCES), fingerprints: 2},
	{id: "aoc-idcat-g2", provider: "idcat", role: profiles.RoleNaturalPerson,
		anchors: provTPins("0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6", "3761345542c20b314a744a7c54a82152a283be9cdcda233f050000c2d0e5070d"),
		oids:    []string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.catcert.cat", "ocsp.aoc.cat"}, crl: []string{"epscd.catcert.net", "epscd.aoc.cat"}, nonce: true,
		handled: []string{"1.3.6.1.5.5.7.1.3"}, adapter: provTIDCAT(true), fingerprints: 1,
		subject: [][]profiles.AttributeMatch{provTIdcatMarker}},
	{id: "aoc-idcat-g3", provider: "idcat", role: profiles.RoleNaturalPerson,
		anchors: provTPins("e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735", "4da535844e847db014be7e842d7b243118f3d28ce487c32cb62e5a72c70b88c2"),
		oids:    []string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.catcert.cat", "ocsp.aoc.cat"}, crl: []string{"epscd.catcert.net", "epscd.aoc.cat"}, nonce: true,
		adapter: provTIDCAT(false), subject: [][]profiles.AttributeMatch{provTIdcatMarker}},
	{id: "accv-citizen-software-current", provider: "accv", role: profiles.RoleNaturalPerson,
		anchors: provTPins(
			"a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1", "03cd20b076b5b589a78efa46a09e6d1cc8ba5878088113749d16f7414cd9c1f1",
			"5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496", "73b39454c0f85a4f23e29e923073aa74f755934809e359f2ea87c9eebfa34b75"),
		oids: []string{"1.3.6.1.4.1.8149.3.7.8.0"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.accv.es"}, crl: []string{"www.accv.es"}, nonce: true, adapter: provTACCV()},
	{id: "digitel-citizen-sw-g1", provider: "digitel", role: profiles.RoleNaturalPerson,
		anchors: provTPins("86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61", "00600557c6552a65e2dd8dee34d7b674043fd1c5935562ded5f26e2e5777eabb"),
		oids:    []string{"1.3.6.1.4.1.54225.10.3.1"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.digitelts.es"}, crl: []string{"crl1.pki.digitelts.es", "crl2.pki.digitelts.es"}, nonce: true,
		adapter: provTPlain(), fingerprints: 1},
	{id: "bewor-natural-person-sw", provider: "bewor", role: profiles.RoleNaturalPerson,
		anchors: provTPins("8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d", "ba0331d2b536d13f5d8953475ae3b945764ed54b3788ba5bf4f4a7ee6e770003"),
		oids:    []string{"1.3.6.1.4.1.55693.1.1.2"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, crl: []string{"crl1.uanataca.com", "crl2.uanataca.com"}, nonce: true,
		adapter: provTPlain(), fingerprints: 2},
	{id: "sectigo-citizen-local", provider: "sectigo", role: profiles.RoleNaturalPerson,
		anchors: provTPins(
			"ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde", "eb9f35a491f478c19fc0cdc02a8a5d54df26ed3b248f587459539bc2a48f6a24",
			"53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9", "8e351d9cb41b50d077af2842b9faf748c4269ea6cf01e34d29f1f83c85edf983"),
		oids: []string{"1.3.6.1.4.1.6449.1.2.1.7.1"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.sectigo.com"}, crl: []string{"crl.sectigo.com"}, nonce: false,
		adapter: provTPlain(), fingerprints: 2},
	{id: "fnmt-representative-rsa", provider: "fnmt-representative", role: profiles.RoleRepresentative,
		anchors: provTPins("8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b", "da576c79f49f91353b1865dfcf889888f9ce50391b2a261d51a3c677676ef044"),
		oids:    []string{"1.3.6.1.4.1.5734.3.11.1", "1.3.6.1.4.1.5734.3.11.2", "1.3.6.1.4.1.5734.3.11.3"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsprep.cert.fnmt.es"}, crl: []string{"www.cert.fnmt.es"}, nonce: true, adapter: provTFNMTRepresentative()},
	{id: "fnmt-representative-g2", provider: "fnmt-representative", role: profiles.RoleRepresentative,
		anchors: provTPins("0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64", "66f3f2da778bf26070b42bc7accd97d9f188d25a15f1e2575603042618c13502"),
		oids:    []string{"1.3.6.1.4.1.5734.3.21.1.0", "1.3.6.1.4.1.5734.3.21.2.0", "1.3.6.1.4.1.5734.3.21.3.0"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsprepg2.cert.fnmt.es"}, crl: []string{"www.cert.fnmt.es"}, nonce: true, adapter: provTFNMTRepresentative()},
	{id: "fnmt-employee-rsa", provider: "fnmt-employee", role: profiles.RolePublicEmployee,
		anchors: provTPins("8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498", "68de305107cbd1889d7a9b039fdca503c1a88ad1f45d1752df8f50c72969d915"),
		oids:    []string{"1.3.6.1.4.1.5734.3.17.2"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocspsp.cert.fnmt.es"}, crl: []string{"www.cert.fnmt.es"}, nonce: true, adapter: provTFNMTEmployee()},
	{id: "fnmt-employee-g2", provider: "fnmt-employee", role: profiles.RolePublicEmployee,
		anchors: provTPins("983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe", "a1e3f004222a51998b97853b50fdbfbe9b3f932c3bd0b85737663bd19b33a906"),
		oids:    []string{"1.3.6.1.4.1.5734.3.23.1.0"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocspspg2.cert.fnmt.es"}, crl: []string{"www.cert.fnmt.es"}, nonce: true, adapter: provTFNMTEmployee()},
	{id: "firmaprofesional-personal-sw", provider: "firmaprofesional", role: profiles.RoleNaturalPerson,
		anchors: provTPins(
			"2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf", "c695bd5c40f753beb93f653202a3d6354ede0dd21295fd894a0869be366753e6",
			"4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1", "dab1f8803dcf0900d5810e5d9b598781a1f039b30bdf89ad241bfa3e358dd8f9"),
		oids: []string{"1.3.6.1.4.1.13177.10.1.40.2"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.firmaprofesional.com"}, crl: []string{"crl.firmaprofesional.com"}, adapter: provTFirmaprofesional()},
	{id: "anf-asociacion-class2-sw", provider: "anf", role: profiles.RoleNaturalPerson,
		anchors: provTPins("b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23", "d1b4c6d6b4f387bd50f89359a11c3a07673effb796cbcecfd32219594362988c"),
		oids:    []string{"1.3.6.1.4.1.18332.3.4.1.2.22"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.anf.es"}, crl: []string{"crl.anf.es"}, nonce: true, adapter: provTPlain()},
	{id: "anf-sl-class2-sw", provider: "anf", role: profiles.RoleNaturalPerson,
		anchors: provTPins("5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a", "9992ddc44e5b001f31044fd4723e424e3e2509799b084211f660d321a2fea436"),
		oids:    []string{"1.3.6.1.4.1.49201.3.4.1.2.22"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp.anf.es"}, crl: []string{"crl.anf.es"}, nonce: true, adapter: provTPlain()},
	{id: "uanataca-citizen-sw", provider: "uanataca", role: profiles.RoleNaturalPerson,
		anchors: provTPins(
			"35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f", "c886cd88edc69bffba28dcc5ba092fa5906742ce4712ddfc71e4e5851fa51f26",
			"00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909", "fac53d2ea5667fa530415045aa563d293ed0de542e26a0607f31a480c695fe75",
			"9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a", "12093d696c24875b59dbc44b2ac814961b8bc73b870310f6cecd5d21a4e6787a",
			"15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a", "5f78b32f4a4770c8676ac81b467005ce22dde8f2613c5acca3612bcf6029a9b6"),
		oids: []string{"1.3.6.1.4.1.47286.1.1.1.1"}, eku: profiles.EKURequireClientAuth,
		ocsp: []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, crl: []string{"crl1.uanataca.com", "crl2.uanataca.com"}, nonce: true,
		adapter: provTPlain()},
	{id: "signe-personal-otros-dispositivos", provider: "signe", role: profiles.RoleNaturalPerson,
		anchors: provTPins(
			"b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea", "7988bdc1ad8ebd8bf150d25ffe876fb05bb3444e1c064bd13f2a57d82bb5f66f",
			"244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35", "6a30d221e4acfdae38d34006418094fa8337da2f30b9a99c04cfe7d98317dd70"),
		oids: []string{"1.3.6.1.4.1.36035.1.3.2"}, eku: profiles.EKURequireClientAuth,
		ocsp: nil, crl: []string{"www.signe.es", "crl.firmaprofesional.com"}, adapter: provTSIGNE()},
	{id: "lleidanet-natural-person-sw", provider: "lleidanet", role: profiles.RoleNaturalPerson,
		anchors: provTPins("3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25", "e0f0a51ac007c5ea964344e785c4ac005d8db0e8cd7a33943f726a46c0532d3e"),
		oids:    []string{"1.3.6.1.4.1.49959.1.1.1.1.1"}, eku: profiles.EKURequireClientAuth,
		ocsp: nil, crl: []string{"crl1.esigna.es", "crl.esigna.es"}, adapter: provTPlain()},
	{id: "dnie-auth", provider: "dnie", role: profiles.RoleNaturalPerson,
		anchors: provTPins("c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11", "4a5dc6f078372f3497d01ba654c902357b54a1c53387f8b3cf3b92749cdeb44b"),
		intermediates: provTPins(
			"ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c", "1b5b9b72ed25bdab71a112d252c747f5961bfed9ad4bce77292af34b1146481f",
			"828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828", "1f6b84c54a1824bdc0f639487dfaa29c7b2bc7fefe69499651eb2036fcf859a2",
			"eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd", "60a9a73a0c25f1e14b44508554076c2c48ad32c503c9bc534c945a82a290cb97"),
		oids: []string{"2.16.724.1.2.2.2.4"}, eku: profiles.EKUAllowAbsent,
		ocsp: []string{"ocsp.dnie.es"}, crl: []string{"pki.policia.es"}, nonce: true, adapter: provTDNIe(), fingerprints: 13},
}

func provTAnchorPins(as []profiles.Anchor) [][2]string {
	var out [][2]string
	for _, a := range as {
		out = append(out, [2]string{a.SHA256, a.SPKISHA256})
	}
	return out
}

func TestProfilesTable(t *testing.T) {
	var got []profiles.Profile
	for _, p := range profiles.All() {
		for _, prof := range p.Profiles {
			if prof.ProviderID != p.ID {
				t.Errorf("%s: ProviderID %q inside provider %q", prof.ID, prof.ProviderID, p.ID)
			}
			got = append(got, prof)
		}
	}
	if len(got) != len(provTTable) {
		t.Fatalf("got %d profiles, want %d", len(got), len(provTTable))
	}
	for i, w := range provTTable {
		g := got[i]
		t.Run(w.id, func(t *testing.T) {
			check := func(field string, got, want any) {
				t.Helper()
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s:\n got %#v\nwant %#v", field, got, want)
				}
			}
			check("ID", g.ID, w.id)
			check("ProviderID", g.ProviderID, w.provider)
			check("HolderRole", g.HolderRole, w.role)
			check("Anchors", provTAnchorPins(g.Anchors), w.anchors)
			check("Intermediates", provTAnchorPins(g.Intermediates), w.intermediates)
			check("PolicyOIDs", g.PolicyOIDs, w.oids)
			check("EKU", g.EKU, w.eku)
			check("KeyUsage", g.KeyUsage, profiles.KURule{})
			check("Algorithms.MinRSABits", g.Algorithms.MinRSABits, w.minRSA)
			check("HandledCriticalExtensions", g.HandledCriticalExtensions, w.handled)
			check("Identity", g.Identity, w.adapter)
			check("Revocation", g.Revocation, revocation.Policy{
				OCSPHosts: w.ocsp, CRLHosts: w.crl, AllowCRL: len(w.crl) > 0, OCSPNonce: w.nonce})
			var fps int
			var subjects [][]profiles.AttributeMatch
			for _, m := range g.TestMarkers {
				if m.SHA256 != "" {
					fps++
				} else {
					subjects = append(subjects, m.Subject)
				}
				if m.Source == "" {
					t.Errorf("test marker %+v has no source", m)
				}
			}
			check("fingerprint markers", fps, w.fingerprints)
			check("subject markers", subjects, w.subject)
		})
	}
}

// TestExcludedOIDsAbsent: exclusions are by omission, so none of these
// policies may be allowlisted by any profile.
func TestExcludedOIDsAbsent(t *testing.T) {
	excluded := []string{
		// FNMT pseudonym / judicial lanes.
		"1.3.6.1.4.1.5734.3.17.3", "1.3.6.1.4.1.5734.3.17.4", "1.3.6.1.4.1.5734.3.17.5",
		"1.3.6.1.4.1.5734.3.17.6", "1.3.6.1.4.1.5734.3.17.8", "1.3.6.1.4.1.5734.3.17.10",
		"1.3.6.1.4.1.5734.3.23.2.0", "1.3.6.1.4.1.5734.3.23.3.0", "1.3.6.1.4.1.5734.3.23.1.1",
		"1.3.6.1.4.1.5734.3.23.3.1", "1.3.6.1.4.1.5734.3.23.4.1", "1.3.6.1.4.1.5734.3.23.1.3",
		// FNMT consular.
		"1.3.6.1.4.1.5734.3.26.1.0",
		// Bewor centralised HSM.
		"1.3.6.1.4.1.55693.1.1.1",
		// Sectigo citizen QSCD, employee, QWAC.
		"1.3.6.1.4.1.6449.1.2.1.7.2", "1.3.6.1.4.1.6449.1.2.1.7.3", "1.3.6.1.4.1.6449.1.2.1.7.4", "1.3.6.1.4.1.6449.1.2.1.7.5",
		// Firmaprofesional centralised DCCF.
		"1.3.6.1.4.1.13177.10.1.40.3",
		// ANF QSCD and centralised.
		"1.3.6.1.4.1.18332.3.4.1.4.22", "1.3.6.1.4.1.18332.3.4.1.5.22",
		"1.3.6.1.4.1.49201.3.4.1.4.22", "1.3.6.1.4.1.49201.3.4.1.5.22",
		// Uanataca HSM, QSCD, centralised QSCD and legacy OIDs.
		"1.3.6.1.4.1.47286.1.1.1.2", "1.3.6.1.4.1.47286.1.1.1.3", "1.3.6.1.4.1.47286.1.1.1.4",
		"1.3.6.1.4.1.47286.1.1.6", "1.3.6.1.4.1.47286.1.1.6.2",
		// SIGNE portable DCCF.
		"1.3.6.1.4.1.36035.1.3.1",
		// Lleidanet hardware.
		"1.3.6.1.4.1.49959.1.1.1.2.1",
		// DNIe signature and centralised signature.
		"2.16.724.1.2.2.2.3", "2.16.724.1.2.2.2.11",
		// ACCV legacy citizen software.
		"1.3.6.1.4.1.8149.3.7.6.0", "1.3.6.1.4.1.8149.3.7.7.0",
	}
	// Historical AOC policies 15096.1.3.1.* are excluded as a whole arc.
	const historicalAOC = "1.3.6.1.4.1.15096.1.3.1."
	for _, p := range profiles.All() {
		for _, prof := range p.Profiles {
			for _, o := range prof.PolicyOIDs {
				if slices.Contains(excluded, o) {
					t.Errorf("%s allowlists excluded policy %s", prof.ID, o)
				}
				if strings.HasPrefix(o, historicalAOC) {
					t.Errorf("%s allowlists historical AOC policy %s", prof.ID, o)
				}
			}
		}
	}
}

// TestSpecimenMarkers: every specimen of the manifest (committed or withheld
// under ruling R30) is a fingerprint marker of exactly one profile, and every
// fingerprint marker is a manifest specimen.
func TestSpecimenMarkers(t *testing.T) {
	rows := specTManifest(t)
	reg, err := profiles.Default(time.Now(), nil)
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	owners := map[string][]string{} // sha256 -> profile IDs
	sources := map[string]string{}  // sha256 -> marker source
	for _, p := range profiles.All() {
		for _, prof := range p.Profiles {
			for _, m := range prof.TestMarkers {
				if m.SHA256 == "" {
					continue
				}
				owners[m.SHA256] = append(owners[m.SHA256], prof.ID)
				sources[m.SHA256] = m.Source
			}
		}
	}
	enabled := map[string]*profiles.Enabled{}
	for _, p := range reg.Providers() {
		for _, e := range reg.Enabled(p.ID) {
			enabled[e.Profile.ID] = e
		}
	}
	listed := map[string]bool{}
	for _, r := range rows {
		listed[r.sha256] = true
		t.Run(r.file, func(t *testing.T) {
			ids := owners[r.sha256]
			if len(ids) != 1 {
				t.Fatalf("fingerprint %s is a marker of %v, want exactly one profile", r.sha256, ids)
			}
			if want := "testdata/specimens/" + r.file; sources[r.sha256] != want {
				t.Errorf("marker source = %q, want %q", sources[r.sha256], want)
			}
			if want, ok := specTExpected[r.file]; ok && ids[0] != want.profile {
				t.Errorf("marker of %s, want %s", ids[0], want.profile)
			}
			e, ok := enabled[ids[0]]
			if !ok {
				t.Fatalf("profile %s is not enabled", ids[0])
			}
			if !e.IsFingerprintMarker(r.sha256) {
				t.Errorf("Enabled(%s).IsFingerprintMarker = false, want true", ids[0])
			}
			for id, other := range enabled {
				if id != ids[0] && other.IsFingerprintMarker(r.sha256) {
					t.Errorf("also a fingerprint marker of %s", id)
				}
			}
		})
	}
	for sha, ids := range owners {
		if !listed[sha] {
			t.Errorf("fingerprint marker %s of %v is not in the specimen manifest", sha, ids)
		}
	}
	if len(owners) != len(rows) {
		t.Errorf("%d fingerprint markers, %d manifest rows", len(owners), len(rows))
	}
}

func TestAllAndByID(t *testing.T) {
	all := profiles.All()
	if len(all) == 0 {
		t.Fatal("All() returned no providers")
	}
	for _, want := range all {
		t.Run(want.ID, func(t *testing.T) {
			got, ok := profiles.ByID(want.ID)
			if !ok {
				t.Fatalf("ByID(%q) found = false, want true", want.ID)
			}
			if got.ID != want.ID {
				t.Errorf("ByID(%q).ID = %q", want.ID, got.ID)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("ByID(%q) differs from the All() entry", want.ID)
			}
		})
	}
	t.Run("unknown id", func(t *testing.T) {
		got, ok := profiles.ByID("nope")
		if ok {
			t.Errorf("ByID(%q) found = true, want false", "nope")
		}
		if got.ID != "" || len(got.Profiles) != 0 {
			t.Errorf("ByID(%q) = %+v, want the zero Provider", "nope", got)
		}
	})
}
