package profiles_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
)

// specTDir holds the CA-published specimen leaves and their MANIFEST.md.
const specTDir = "../testdata/specimens"

// specTRow is one MANIFEST.md row.
type specTRow struct {
	file, status, sha256 string
}

const specTCommitted = "committed"

// specTManifest parses MANIFEST.md rows (committed and withheld).
func specTManifest(t *testing.T) []specTRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specTDir, "MANIFEST.md"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var rows []specTRow
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i, c := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(c, "`", ""))
		}
		if len(cells) < 3 || !strings.HasSuffix(cells[0], ".pem") {
			continue
		}
		rows = append(rows, specTRow{file: cells[0], status: cells[1], sha256: cells[2]})
	}
	if len(rows) != 33 {
		t.Fatalf("manifest has %d specimen rows, want 33", len(rows))
	}
	return rows
}

func specTLoad(t *testing.T, file string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specTDir, file))
	if err != nil {
		t.Fatalf("read specimen: %v", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("%s: no PEM CERTIFICATE block", file)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("%s: parse: %v", file, err)
	}
	return c
}

// Expected identities: the values of Task 2's TestSpecimenIdentities, now
// through the real declarations.

const (
	specTSrcDocument = "subject.2.5.4.5"
	specTSrcGiven    = "subject.2.5.4.42"
	specTSrcSN       = "subject.2.5.4.4"
	specTSrcDNIeCN   = "subject.2.5.4.3 (DNIe CN grammar)"
	specTSrcFNMT2    = "san.dirName.1.3.6.1.4.1.5734.1.2"
	specTSrcFNMT3    = "san.dirName.1.3.6.1.4.1.5734.1.3"
)

func specTDNI(number, raw string) identity.Document {
	return identity.Document{Type: identity.DocumentDNI, Country: "ES", Number: number, Raw: raw, Source: specTSrcDocument}
}

func specTPlain(doc identity.Document, given, surnames string) identity.Identity {
	return identity.Identity{Document: doc, GivenNames: given, Surnames: surnames, FullName: given + " " + surnames,
		Sources: map[string]string{"document": specTSrcDocument, "givenNames": specTSrcGiven, "surnames": specTSrcSN}}
}

func specTFNMTSplit(doc identity.Document, given, surnames, first, second string) identity.Identity {
	id := specTPlain(doc, given, surnames)
	id.FirstSurname, id.SecondSurname = first, second
	id.Sources["firstSurname"] = specTSrcFNMT2
	if second != "" {
		id.Sources["secondSurname"] = specTSrcFNMT3
	}
	return id
}

func specTFNMT(number, raw, given, first, second string) identity.Identity {
	return specTFNMTSplit(specTDNI(number, raw), given, first+" "+second, first, second)
}

func specTDNIe(number, second string) identity.Identity {
	id := identity.Identity{Document: specTDNI(number, number), GivenNames: "Ciudadano", Surnames: "Ficticio " + second,
		FirstSurname: "Ficticio", SecondSurname: second, FullName: "Ciudadano Ficticio " + second,
		Sources: map[string]string{"document": specTSrcDocument, "givenNames": specTSrcGiven, "surnames": specTSrcDNIeCN, "firstSurname": specTSrcSN}}
	if second != "" {
		id.Sources["secondSurname"] = specTSrcDNIeCN
	}
	return id
}

// specTCase is the expected outcome of a specimen through the adapter of its
// profile. unpinnedIssuer marks leaves whose issuing CA is not pinned (AC DNIE
// 001): they are attributed to their profile by fingerprint only.
type specTCase struct {
	profile        string
	want           identity.Identity
	wantErr        error
	unpinnedIssuer bool
}

var specTExpected = func() map[string]specTCase {
	const (
		rsa, g2, dnie = "fnmt-citizen-rsa", "fnmt-citizen-g2", "dnie-auth"
		pruebas       = "PRUEBAS"
		eidas         = "EIDAS"
		cert          = "CERTIFICADO"
		uno           = "ESPECIMEN UÑO"
		guenos        = "ESPECIMEN DE LOS GÜENOS"
	)
	diez := specTFNMTSplit(specTDNI("99949990V", "IDCES-99949990V"), "NOM D'DIEZ", "ESPECIMENDIEZ ESPECIMEN-DIEZ", "ESPECIMENDIEZ", "ESPECIMEN-DÍEZ")
	invalid := func(profile string, unpinned bool) specTCase {
		return specTCase{profile: profile, wantErr: identity.ErrInvalid, unpinnedIssuer: unpinned}
	}
	return map[string]specTCase{
		// FNMT AC FNMT Usuarios (RSA): IDCES- and the May-2016 bare kit.
		"fnmt-rsa-nosmime-activo-99999999R-2024.pem":                {profile: rsa, want: specTFNMT("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		"fnmt-rsa-nosmime-revocado-99999999R-2024.pem":              {profile: rsa, want: specTFNMT("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		"fnmt-rsa-nosmime-activo-99999972C-2024.pem":                {profile: rsa, want: specTFNMT("99999972C", "IDCES-99999972C", pruebas, eidas, cert)},
		"fnmt-rsa-caducado-99999999R-2016.pem":                      {profile: rsa, want: specTFNMT("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		"fnmt-rsa-revocado-pruebasrev-99999999R-2016.pem":           {profile: rsa, want: specTFNMT("99999999R", "IDCES-99999999R", "PRUEBASREV", eidas, cert)},
		"fnmt-rsa-smime-revocado-99999999R-2020.pem":                {profile: rsa, want: specTFNMT("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		"fnmt-rsa-nosmime-espanol-espanol-juan-00000000T-2023.pem":  {profile: rsa, want: specTFNMT("00000000T", "IDCES-00000000T", "JUAN", "ESPAÑOL", "ESPAÑOL")},
		"fnmt-rsa-legacy2016-activo-apellidounopf-pruebaspf.pem":    {profile: rsa, want: specTFNMT("00000000T", "00000000T", "PRUEBASPF", "APELLIDOUNOPF", "APELLIDODOSPF")},
		"fnmt-rsa-legacy2016-revocado-apellidounorev-pruebaspf.pem": {profile: rsa, want: specTFNMT("00000000T", "00000000T", "PRUEBASPF", "APELLIDOUNOREVPF", "APELLIDODOSREVPF")},
		"fnmt-rsa-supervisor-especimen-99949990V-2025.pem":          {profile: rsa, want: diez},
		"fnmt-rsa-supervisor-especimen-99949991H-2025.pem":          {profile: rsa, want: specTFNMT("99949991H", "IDCES-99949991H", "NOM UN O", uno, guenos)},
		"fnmt-rsa-supervisor-especimen-99949999A-2025.pem":          {profile: rsa, want: specTFNMT("99949999A", "IDCES-99949999A", "NOMNUEVE", "ESPECIMENNUEVE", "ESPECIMENNUEVE")},
		// FNMT AC USUARIOS G2.
		"fnmt-ecc-g2-activo-especimen-99949991H-2025.pem":   {profile: g2, want: specTFNMT("99949991H", "IDCES-99949991H", "NOM UN O", uno, guenos)},
		"fnmt-ecc-g2-revocado-especimen-99949990V-2025.pem": {profile: g2, want: diez},
		// DNIe authentication certificates (AC DNIE 004 pinned, AC DNIE 001 not).
		"dnie-ac004-auth-activo.pem":   {profile: dnie, want: specTDNIe("00000000T", "Activo")},
		"dnie-ac004-auth-caducado.pem": {profile: dnie, want: specTDNIe("00000000T", "Caducado")},
		"dnie-ac004-auth-revocado.pem": {profile: dnie, want: specTDNIe("00000000T", "Revocado")},
		"dnie-ac001-auth-activo.pem":   {profile: dnie, want: specTDNIe("99999018D", "Activo"), unpinnedIssuer: true},
		"dnie-ac001-auth-revocado.pem": {profile: dnie, want: specTDNIe("99999018D", "Revocado"), unpinnedIssuer: true},
		// DNIe signature certificates fail the authentication CN grammar.
		"dnie-ac001-firma-activo.pem":               invalid(dnie, true),
		"dnie-ac001-firma-revocado.pem":             invalid(dnie, true),
		"dnie-ac004-firma-activo.pem":               invalid(dnie, false),
		"dnie-ac004-firma-caducado.pem":             invalid(dnie, false),
		"dnie-ac004-firma-revocado.pem":             invalid(dnie, false),
		"dnie-ac004-firmacentralizada-activo.pem":   invalid(dnie, false),
		"dnie-ac004-firmacentralizada-caducado.pem": invalid(dnie, false),
		"dnie-ac004-firmacentralizada-revocado.pem": invalid(dnie, false),
		// DIGITEL.
		"digitel-ciudadanosw-99949996T.pem": {profile: "digitel-citizen-sw-g1",
			want: specTPlain(specTDNI("99949996T", "IDCES-99949996T"), "NOMSEIS", "ESPECIMENSEIS ESPECIMENSEIS")},
		// idCAT 2015 leaf: bare serialNumber, rejected by the IDCES-only grammar.
		"idcat-g2-pf-peca-de-proves-00000000T.pem": invalid("aoc-idcat-g2", false),
		// Withheld (R30): attribution only, no file.
		"bewor-pfsoftbt-99949999A.pem":          {profile: "bewor-natural-person-sw"},
		"bewor-pfsoftbt-revocado-99999999R.pem": {profile: "bewor-natural-person-sw"},
		"sectigo-citizen-99949990V.pem":         {profile: "sectigo-citizen-local"},
		"sectigo-employee-99949993C.pem":        {profile: "sectigo-citizen-local"},
	}
}()

// specTIssuerProfile returns the enabled profile whose pinned anchor or
// intermediate is the leaf's issuer (same name and key identifier).
func specTIssuerProfile(reg *profiles.Registry, leaf *x509.Certificate) []string {
	var ids []string
	for _, p := range reg.Providers() {
		for _, e := range reg.Enabled(p.ID) {
			for _, c := range append(append([]*x509.Certificate{}, e.Anchors...), e.Intermediates...) {
				if bytes.Equal(leaf.RawIssuer, c.RawSubject) &&
					(len(leaf.AuthorityKeyId) == 0 || bytes.Equal(leaf.AuthorityKeyId, c.SubjectKeyId)) {
					ids = append(ids, e.Profile.ID)
				}
			}
		}
	}
	return ids
}

func TestProfileAdaptersOnSpecimens(t *testing.T) {
	reg, err := profiles.Default(time.Now(), nil)
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	byID := map[string]profiles.Profile{}
	for _, p := range reg.Providers() {
		for _, e := range reg.Enabled(p.ID) {
			byID[e.Profile.ID] = e.Profile
		}
	}
	rows := specTManifest(t)
	for _, r := range rows {
		tc, ok := specTExpected[r.file]
		if !ok {
			t.Errorf("specimen %s has no expected outcome", r.file)
			continue
		}
		if r.status != specTCommitted {
			continue
		}
		t.Run(r.file, func(t *testing.T) {
			leaf := specTLoad(t, r.file)
			issuers := specTIssuerProfile(reg, leaf)
			switch {
			case tc.unpinnedIssuer && len(issuers) != 0:
				t.Errorf("issuer pinned by %v, want unpinned", issuers)
			case !tc.unpinnedIssuer && (len(issuers) != 1 || issuers[0] != tc.profile):
				t.Errorf("issuer pinned by %v, want exactly [%s]", issuers, tc.profile)
			}
			prof, ok := byID[tc.profile]
			if !ok {
				t.Fatalf("profile %s not enabled", tc.profile)
			}
			got, err := prof.Identity.Extract(leaf)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Extract err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract err = %v, want nil", err)
			}
			if !reflect.DeepEqual(got.Identity, tc.want) {
				t.Errorf("Identity:\n got %+v\nwant %+v", got.Identity, tc.want)
			}
			if got.Organization != nil || len(got.Notes) != 0 {
				t.Errorf("Organization = %+v, Notes = %q; want nil and none", got.Organization, got.Notes)
			}
			if kind, hit := reg.Reserved().Match(got); !hit || kind != identity.MarkerDocument {
				t.Errorf("Reserved().Match = (%q, %v), want (%q, true)", kind, hit, identity.MarkerDocument)
			}
		})
	}
	if len(specTExpected) != len(rows) {
		t.Errorf("%d expected outcomes for %d manifest rows", len(specTExpected), len(rows))
	}
}
