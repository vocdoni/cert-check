package identity_test

import (
	"testing"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/testpki"
)

func extracted(doc, given, surnames string, org *identity.Organization) identity.Extracted {
	return identity.Extracted{
		Identity: identity.Identity{
			Document:   identity.Document{Type: identity.DocumentDNI, Country: "ES", Number: doc, Raw: doc, Source: srcDocument},
			GivenNames: given, Surnames: surnames, FullName: given + " " + surnames,
		},
		Organization: org,
	}
}

func TestReservedMatch(t *testing.T) {
	r := identity.DefaultReserved()

	type row struct {
		name     string
		x        identity.Extracted
		wantKind identity.MarkerKind
		wantHit  bool
	}
	var tests []row
	// The 16 reserved documents (spec "reserved identities").
	for _, doc := range []string{
		"00000000T", "99999999R", "99999972C", "99999018D", "X0000000T",
		"99949990V", "99949991H", "99949992L", "99949993C", "99949994K",
		"99949995E", "99949996T", "99949997R", "99949998W", "99949999A",
		"12345678Z",
	} {
		tests = append(tests, row{"document " + doc, extracted(doc, "JUAN", "GARCIA LOPEZ", nil), identity.MarkerDocument, true})
	}
	const doc = "12345679S" // valid, not reserved
	// split reports the given first and second surnames, as a SAN would.
	split := func(surnames, first, second string) identity.Extracted {
		x := extracted(doc, "JUAN", surnames, nil)
		x.Identity.FirstSurname, x.Identity.SecondSurname = first, second
		return x
	}
	tests = append(tests, []row{
		// R5.2: markers fold like the SAN consistency check (ComparisonKey),
		// and every surname spelling is screened.
		{"surname ESPÉCIMEN accented", extracted(doc, "JUAN", "ESPÉCIMEN DIEZ", nil), identity.MarkerSurname, true},
		{"surname ESPECÍMEN accented", extracted(doc, "JUAN", "ESPECÍMEN LOPEZ", nil), identity.MarkerSurname, true},
		{"surname PRÚEBAS accented", extracted(doc, "JUAN", "EIDAS PRÚEBAS", nil), identity.MarkerSurname, true},
		{"surname FICTÍCIO accented", extracted(doc, "JUAN", "FICTÍCIO", nil), identity.MarkerSurname, true},
		{"surname DE PRÒVES accented", extracted(doc, "JUAN", "DE PRÒVES", nil), identity.MarkerSurname, true},
		{"first surname only", split("GARCIA LOPEZ", "ESPECIMEN", "LOPEZ"), identity.MarkerSurname, true},
		{"second surname only", split("GARCIA LOPEZ", "GARCIA", "FICTÍCIO"), identity.MarkerSurname, true},
		{"given NÓMBRE accented", extracted(doc, "NÓMBRE", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given CIUDADÁNO accented", extracted(doc, "CIUDADÁNO", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOM DÓS pattern accented", extracted(doc, "NOM DÓS", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOM D\u2019DIEZ typographic apostrophe", extracted(doc, "NOM D\u2019DIEZ", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"organization accented", extracted(doc, "JUAN", "GARCIA LOPEZ", &identity.Organization{Name: "ENTIDAD DE PRÚEBAS"}), identity.MarkerOrganization, true},
		{"accented real names", split("PEÑA DÍEZ", "PEÑA", "DÍEZ"), "", false},

		{"surname mixed case", extracted(doc, "JUAN", "De La Peça De Proves", nil), identity.MarkerSurname, true},
		{"surname decomposed", extracted(doc, "JUAN", "de la Pec\u0327a de Proves", nil), identity.MarkerSurname, true},
		{"surname DE PROVES without cedilla", extracted(doc, "JUAN", "DE LA PECA DE PROVES", nil), identity.MarkerSurname, true},
		{"surname ESPECIMEN", extracted(doc, "JUAN", "ESPECIMENDIEZ ESPECIMEN-DIEZ", nil), identity.MarkerSurname, true},
		{"surname FICTICIO", extracted(doc, "JUAN", "FICTICIO", nil), identity.MarkerSurname, true},
		{"surname Ficticio Activo", extracted(doc, "JUAN", "Ficticio Activo", nil), identity.MarkerSurname, true},
		{"surname APELLIDO1", extracted(doc, "JUAN", "APELLIDO1 X", nil), identity.MarkerSurname, true},
		{"surname APELLIDOUNOPF", extracted(doc, "JUAN", "APELLIDOUNOPF APELLIDODOSPF", nil), identity.MarkerSurname, true},
		{"surname PRUEBAS", extracted(doc, "JUAN", "EIDAS PRUEBAS", nil), identity.MarkerSurname, true},
		{"given NOMBRE", extracted(doc, "NOMBRE", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given Ciudadano", extracted(doc, "Ciudadano", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given PRUEBAS", extracted(doc, "PRUEBAS", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given PRUEBASPF", extracted(doc, "PRUEBASPF", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given PRUEBASREV", extracted(doc, "pruebasrev", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOM UN O", extracted(doc, "NOM UN O", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOMDOS", extracted(doc, "NOMDOS", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOM D'DIEZ", extracted(doc, "NOM D'DIEZ", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NomSeis", extracted(doc, "NomSeis", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOMNUEVE", extracted(doc, "NOMNUEVE", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"given NOM DIEZ", extracted(doc, "NOM DIEZ", "GARCIA LOPEZ", nil), identity.MarkerGivenName, true},
		{"organization", extracted(doc, "JUAN", "GARCIA LOPEZ", &identity.Organization{Name: "Entidad de pruebas"}), identity.MarkerOrganization, true},
		{"organization upper case", extracted(doc, "JUAN", "GARCIA LOPEZ", &identity.Organization{Name: "ENTIDAD DE PRUEBAS", Identifier: "VATES-Q0000000J"}), identity.MarkerOrganization, true},
		{"document wins over name markers", extracted("99999999R", "PRUEBAS", "EIDAS CERTIFICADO", nil), identity.MarkerDocument, true},
		{"no match", extracted(doc, "JUAN", "GARCIA LOPEZ", nil), "", false},
		{"given name equality is exact", extracted(doc, "NOMBRES", "GARCIA LOPEZ", nil), "", false},
		{"given name contains a marker", extracted(doc, "JUAN NOMBRE", "GARCIA LOPEZ", nil), "", false},
		{"given pattern is anchored", extracted(doc, "NOMDOSA", "GARCIA LOPEZ", nil), "", false},
		{"other organization", extracted(doc, "JUAN", "GARCIA LOPEZ", &identity.Organization{Name: "EMPRESA EJEMPLO SL"}), "", false},
		{"organization equality is exact", extracted(doc, "JUAN", "GARCIA LOPEZ", &identity.Organization{Name: "ENTIDAD DE PRUEBAS SL"}), "", false},
		{"NIE not reserved", extracted("X1234567L", "JUAN", "GARCIA LOPEZ", nil), "", false},
	}...)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, hit := r.Match(tc.x)
			if kind != tc.wantKind || hit != tc.wantHit {
				t.Errorf("Match = (%q, %v), want (%q, %v)", kind, hit, tc.wantKind, tc.wantHit)
			}
		})
	}

	t.Run("empty registry", func(t *testing.T) {
		if kind, hit := (identity.Reserved{}).Match(extracted("00000000T", "NOMBRE", "FICTICIO", nil)); hit {
			t.Errorf("empty registry Match = (%q, true), want no match", kind)
		}
	})
}

// TestReservedMatchAcceptedSpellings: a certificate with a nonreserved
// document whose subject and SAN spell a marker differently, which the SAN
// consistency check accepts, still hits the marker; the reported identity
// keeps the certified spellings (R5.2, U7-ASTRA-1).
func TestReservedMatchAcceptedSpellings(t *testing.T) {
	const doc = "12345679S" // valid, not reserved
	ca := testpki.NewRoot(t, "reserved-root", testpki.CertSpec{})
	r := identity.DefaultReserved()
	tests := []struct {
		name                       string
		subjectGN, subjectSN       string
		sanGN, sanFirst, sanSecond string
		wantKind                   identity.MarkerKind
		wantHit                    bool
	}{
		{"subject ESPECÍMEN, SAN ESPECIMEN", "JUAN", "ESPECÍMEN LOPEZ", "JUAN", "ESPECIMEN", "LOPEZ", identity.MarkerSurname, true},
		{"subject ESPECIMEN, SAN ESPECÍMEN", "JUAN", "ESPECIMEN LOPEZ", "JUAN", "ESPECÍMEN", "LOPEZ", identity.MarkerSurname, true},
		{"subject NÓMBRE, SAN NOMBRE", "NÓMBRE", "GARCIA LOPEZ", "NOMBRE", "GARCIA", "LOPEZ", identity.MarkerGivenName, true},
		{"subject NOMBRE, SAN NÓMBRE", "NOMBRE", "GARCIA LOPEZ", "NÓMBRE", "GARCIA", "LOPEZ", identity.MarkerGivenName, true},
		{"real name with accents only in the SAN", "JOSE", "PENA DIEZ", "JOSÉ", "PEÑA", "DÍEZ", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := ca.Leaf(t, testpki.CertSpec{Subject: person("IDCES-"+doc, tc.subjectGN, tc.subjectSN),
				SANDirNames: []testpki.Name{fnmtDir(doc, tc.sanGN, tc.sanFirst, tc.sanSecond)}})
			x, err := shapeFNMTCitizenRSA().Extract(leaf.Cert)
			if err != nil {
				t.Fatalf("Extract err = %v, want nil", err)
			}
			id := x.Identity
			if id.GivenNames != tc.subjectGN || id.Surnames != tc.subjectSN || id.FirstSurname != tc.sanFirst || id.SecondSurname != tc.sanSecond {
				t.Errorf("Identity names = (%q, %q, %q, %q), want the certified spellings (%q, %q, %q, %q)",
					id.GivenNames, id.Surnames, id.FirstSurname, id.SecondSurname, tc.subjectGN, tc.subjectSN, tc.sanFirst, tc.sanSecond)
			}
			if kind, hit := r.Match(x); kind != tc.wantKind || hit != tc.wantHit {
				t.Errorf("Match = (%q, %v), want (%q, %v)", kind, hit, tc.wantKind, tc.wantHit)
			}
		})
	}
}

func TestDefaultReservedVersion(t *testing.T) {
	r := identity.DefaultReserved()
	if got, want := r.Version, "2026-10-31"; got != want {
		t.Errorf("Version = %q, want %q", got, want)
	}
	if got, want := len(r.Documents), 16; got != want {
		t.Errorf("len(Documents) = %d, want %d", got, want)
	}
	for _, d := range r.Documents {
		if !identity.ValidDNI(d) && !identity.ValidNIE(d) {
			t.Errorf("reserved document %q is neither a valid DNI nor a valid NIE", d)
		}
	}
	if got, want := len(r.SurnameContains), 7; got != want {
		t.Errorf("len(SurnameContains) = %d, want %d", got, want)
	}
	if got, want := len(r.GivenNameEquals), 5; got != want {
		t.Errorf("len(GivenNameEquals) = %d, want %d", got, want)
	}
	if r.GivenNamePattern == nil || len(r.OrganizationEquals) != 1 {
		t.Errorf("GivenNamePattern = %v, OrganizationEquals = %q; want a pattern and one organization", r.GivenNamePattern, r.OrganizationEquals)
	}
	// Each call returns an independent registry.
	r.Documents[0] = "MUTATED"
	if identity.DefaultReserved().Documents[0] == "MUTATED" {
		t.Error("DefaultReserved shares its Documents slice between calls")
	}
}
