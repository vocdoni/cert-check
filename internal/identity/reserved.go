package identity

import (
	"regexp"
	"slices"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// MarkerKind names which reserved-identity rule matched. It never carries a value.
type MarkerKind string

// Marker kinds.
const (
	MarkerDocument     MarkerKind = "reserved_document"
	MarkerSurname      MarkerKind = "surname_marker"
	MarkerGivenName    MarkerKind = "given_name_marker"
	MarkerOrganization MarkerKind = "organization_marker"
)

// Reserved is the versioned registry of test and specimen identities
// (spec "Identity extraction", reserved identities and name markers).
type Reserved struct {
	Version            string
	Documents          []string       // document numbers, exact
	SurnameContains    []string       // compared after NFC + upper-casing
	GivenNameEquals    []string       // compared after NFC + upper-casing
	GivenNamePattern   *regexp.Regexp // applied to the NFC + upper-cased given names
	OrganizationEquals []string       // compared after NFC + upper-casing
}

// DefaultReserved returns the production registry.
func DefaultReserved() Reserved {
	return Reserved{
		Version: "2026-10-31",
		Documents: []string{
			"00000000T", "99999999R", "99999972C", "99999018D", "X0000000T",
			"99949990V", "99949991H", "99949992L", "99949993C", "99949994K",
			"99949995E", "99949996T", "99949997R", "99949998W", "99949999A",
			"12345678Z",
		},
		SurnameContains: []string{
			"ESPECIMEN", "PRUEBAS", "FICTICIO", "APELLIDOUNO", "APELLIDO1",
			"DE LA PEÇA DE PROVES", "DE PROVES",
		},
		GivenNameEquals:    []string{"NOMBRE", "PRUEBAS", "PRUEBASPF", "PRUEBASREV", "CIUDADANO"},
		GivenNamePattern:   regexp.MustCompile(`^NOM ?(UN O|D'DIEZ|DOS|SEIS|NUEVE|DIEZ)$`),
		OrganizationEquals: []string{"ENTIDAD DE PRUEBAS"},
	}
}

func fold(s string) string { return strings.ToUpper(NormalizeName(norm.NFC.String(s))) }

// Match reports whether the extraction hits a reserved identity or a name
// marker. The returned kind never includes the matched value.
func (r Reserved) Match(x Extracted) (MarkerKind, bool) {
	if slices.Contains(r.Documents, x.Identity.Document.Number) {
		return MarkerDocument, true
	}
	sn := fold(x.Identity.Surnames)
	for _, m := range r.SurnameContains {
		if strings.Contains(sn, fold(m)) {
			return MarkerSurname, true
		}
	}
	gn := fold(x.Identity.GivenNames)
	for _, m := range r.GivenNameEquals {
		if gn == fold(m) {
			return MarkerGivenName, true
		}
	}
	if r.GivenNamePattern != nil && r.GivenNamePattern.MatchString(gn) {
		return MarkerGivenName, true
	}
	if x.Organization != nil {
		on := fold(x.Organization.Name)
		for _, m := range r.OrganizationEquals {
			if on == fold(m) {
				return MarkerOrganization, true
			}
		}
	}
	return "", false
}
