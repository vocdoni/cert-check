package identity

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"slices"
	"strings"
	"unicode"
)

// Subject attribute OIDs used by adapters.
var (
	OIDCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	OIDSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
	OIDCountry                = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDOrganization           = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
	OIDOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	OIDUID                    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
)

// SurnameRule says where the complete surnames come from.
type SurnameRule int

// Surname rules.
const (
	// SurnamesFromSN: 2.5.4.4 holds the complete surnames.
	SurnamesFromSN SurnameRule = iota + 1
	// SurnamesDNIeCN: 2.5.4.4 holds the first surname only; the complete
	// surnames come from CN "<SURNAMES>, <GIVEN> (AUTENTICACIÓN|AUTENTICACION)".
	SurnamesDNIeCN
)

// SANKind selects the SAN directoryName cross-check.
type SANKind int

// SAN cross-check kinds.
const (
	SANNone SANKind = iota + 1
	// SANAttributes: separate attributes for document, given name, first and
	// second surname (FNMT 5734.1.*, FNMT employee 2.16.724.1.3.5.7.2.*,
	// Firmaprofesional/SIGNE 13177.0.*).
	SANAttributes
	// SANPipeCN: ACCV, CN "GIVEN|SURNAME1|SURNAME2" plus UID = document.
	SANPipeCN
)

// SANCheck declares the SAN consistency fields that must agree with the subject.
// Absent OIDs (nil) are not checked. All present ones are required.
type SANCheck struct {
	Kind             SANKind
	DocumentOID      asn1.ObjectIdentifier // FNMT 5734.1.4; ACCV UID; nil = none
	DocumentRules    []DocumentRule        // grammar of the SAN document value
	GivenNameOID     asn1.ObjectIdentifier
	FirstSurnameOID  asn1.ObjectIdentifier
	SecondSurnameOID asn1.ObjectIdentifier // optional in the certificate (may be absent or empty)
}

// BirthDateRule says whether the profile declares a birth date.
type BirthDateRule int

// Birth date rules.
const (
	// BirthDateNone: SDA is ignored; a malformed SDA is noted, not an error.
	BirthDateNone BirthDateRule = iota + 1
	// BirthDateOptional: dateOfBirth from SDA when present; malformed → ErrInvalid.
	BirthDateOptional
)

// OrganizationRule says whether the profile reports an organization.
type OrganizationRule int

// Organization rules.
const (
	OrganizationNone OrganizationRule = iota + 1
	// OrganizationFromSubject: Name from O (required), Identifier from 2.5.4.97 (optional).
	OrganizationFromSubject
)

// Adapter declares a profile's identity grammar. The zero value is invalid;
// use Validate.
type Adapter struct {
	Documents            []DocumentRule // accepted encodings of subject 2.5.4.5
	Kinds                KindSet        // accepted string kinds; nil = DefaultKinds
	Surnames             SurnameRule
	SAN                  SANCheck
	CountryMatchesPrefix bool // idCAT: subject C must equal the IDC country (ES)
	LegacyDNISuffix      bool // idCAT G2: strip "<SN> - DNI <id>" only when <id> equals the document
	BirthDate            BirthDateRule
	Organization         OrganizationRule
}

// Validate checks the adapter declaration: every rule is set and known, and
// every field Extract relies on is present (R5.4). Every returned error
// wraps ErrInvalid (ruling R54).
func (a Adapter) Validate() error {
	var errs []error
	if len(a.Documents) == 0 {
		errs = append(errs, invalidf("adapter has no document rules"))
	}
	if a.Surnames < SurnamesFromSN || a.Surnames > SurnamesDNIeCN {
		errs = append(errs, invalidf("adapter surname rule unset or unknown"))
	}
	if a.SAN.Kind < SANNone || a.SAN.Kind > SANPipeCN {
		errs = append(errs, invalidf("adapter SAN kind unset or unknown"))
	}
	if a.BirthDate < BirthDateNone || a.BirthDate > BirthDateOptional {
		errs = append(errs, invalidf("adapter birth date rule unset or unknown"))
	}
	if a.Organization < OrganizationNone || a.Organization > OrganizationFromSubject {
		errs = append(errs, invalidf("adapter organization rule unset or unknown"))
	}
	if a.SAN.Kind == SANAttributes && a.SAN.FirstSurnameOID == nil {
		errs = append(errs, invalidf("adapter SANAttributes needs FirstSurnameOID"))
	}
	if a.SAN.Kind == SANPipeCN && a.SAN.DocumentOID == nil {
		errs = append(errs, invalidf("adapter SANPipeCN needs DocumentOID"))
	}
	if a.SAN.DocumentOID != nil && len(a.SAN.DocumentRules) == 0 {
		errs = append(errs, invalidf("adapter SAN document without rules"))
	}
	for _, r := range slices.Concat(a.Documents, a.SAN.DocumentRules) {
		if !validRule(r) {
			errs = append(errs, invalidf("adapter document rule has an unknown encoding or no known types"))
		}
	}
	if a.Kinds != nil && (len(a.Kinds) == 0 || slices.ContainsFunc(a.Kinds, func(k StringKind) bool { return k < KindUTF8 || k > KindIA5 })) {
		errs = append(errs, invalidf("adapter kinds empty or outside KindUTF8..KindIA5"))
	}
	return errors.Join(errs...)
}

// validRule reports whether r has a known encoding and at least one document
// type, all of them known.
func validRule(r DocumentRule) bool {
	switch r.Encoding {
	case EncodingIDCES, EncodingPNOES, EncodingBare:
	default:
		return false
	}
	return len(r.Types) > 0 && !slices.ContainsFunc(r.Types, func(t DocumentType) bool { return t != DocumentDNI && t != DocumentNIE })
}

// Identity is the typed identity extracted from validated fields.
type Identity struct {
	Document      Document          `json:"document"`
	GivenNames    string            `json:"givenNames"`
	Surnames      string            `json:"surnames"`
	FirstSurname  string            `json:"firstSurname"`
	SecondSurname string            `json:"secondSurname"`
	FullName      string            `json:"fullName"`
	BirthDate     *Date             `json:"birthDate"`
	Sources       map[string]string `json:"sources"`
}

// Organization is the entity a representative or employee acts for. It is
// never the person's identity.
type Organization struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
}

// Extracted is the output of Adapter.Extract.
type Extracted struct {
	Identity     Identity
	Organization *Organization
	// Notes are non-PII remarks for debug logging (e.g. "malformed SDA ignored").
	Notes []string
}

// Extract applies the adapter to a certificate whose chain and profile have
// already been validated.
func (a Adapter) Extract(cert *x509.Certificate) (Extracted, error) {
	if err := a.Validate(); err != nil {
		return Extracted{}, err
	}
	kinds := a.Kinds
	if kinds == nil {
		kinds = DefaultKinds
	}
	subj, err := ParseName(cert.RawSubject)
	if err != nil {
		return Extracted{}, err
	}
	src := map[string]string{}

	rawDoc, ok, err := subj.Field(OIDSerialNumber, kinds)
	if err != nil {
		return Extracted{}, err
	}
	if !ok {
		return Extracted{}, invalidf("subject serialNumber absent")
	}
	doc, err := ParseDocument(rawDoc, "subject.2.5.4.5", a.Documents)
	if err != nil {
		return Extracted{}, err
	}
	src["document"] = doc.Source

	if a.CountryMatchesPrefix && strings.HasPrefix(doc.Raw, "IDC") {
		c, ok, err := subj.Field(OIDCountry, kinds)
		if err != nil {
			return Extracted{}, err
		}
		if !ok || c != doc.Raw[3:5] {
			return Extracted{}, invalidf("subject C does not match the identifier country")
		}
	}

	given, err := requiredName(subj, OIDGivenName, kinds)
	if err != nil {
		return Extracted{}, err
	}
	src["givenNames"] = "subject.2.5.4.42"
	sn, err := requiredName(subj, OIDSurname, kinds)
	if err != nil {
		return Extracted{}, err
	}

	id := Identity{Document: doc, GivenNames: given, Sources: src}
	switch a.Surnames {
	case SurnamesFromSN:
		if a.LegacyDNISuffix {
			// Exact grammar ^(.+) - DNI ([0-9A-Z]+)$ with group 2 == document number.
			if i := strings.LastIndex(sn, " - DNI "); i > 0 && sn[i+len(" - DNI "):] == doc.Number {
				sn = sn[:i]
				src["surnamesQuirk"] = "legacy ' - DNI <id>' suffix removed"
			}
		}
		id.Surnames = sn
		src["surnames"] = "subject.2.5.4.4"
	case SurnamesDNIeCN:
		cn, err := requiredName(subj, OIDCommonName, kinds)
		if err != nil {
			return Extracted{}, err
		}
		full, err := dnieSurnames(cn, sn, given)
		if err != nil {
			return Extracted{}, err
		}
		id.Surnames, id.FirstSurname = full, sn
		id.SecondSurname = strings.TrimPrefix(strings.TrimPrefix(full, sn), " ")
		src["surnames"] = "subject.2.5.4.3 (DNIe CN grammar)"
		src["firstSurname"] = "subject.2.5.4.4"
		if id.SecondSurname != "" {
			src["secondSurname"] = "subject.2.5.4.3 (DNIe CN grammar)"
		}
	default:
		return Extracted{}, invalidf("unknown surname rule")
	}

	if err := a.crossCheckSAN(cert, &id, kinds); err != nil {
		return Extracted{}, err
	}
	for _, s := range []string{id.FirstSurname, id.SecondSurname} {
		if s != "" && !hasLetter(s) {
			return Extracted{}, invalidf("surname without a letter")
		}
	}

	out := Extracted{}
	switch a.BirthDate {
	case BirthDateOptional:
		d, found, err := DateOfBirth(cert)
		if err != nil {
			return Extracted{}, err
		}
		if found {
			id.BirthDate = &d
			src["birthDate"] = "sda.1.3.6.1.5.5.7.9.1"
		}
	case BirthDateNone:
		if _, _, err := DateOfBirth(cert); err != nil {
			out.Notes = append(out.Notes, "malformed SubjectDirectoryAttributes ignored")
		}
	}

	if a.Organization == OrganizationFromSubject {
		name, ok, err := subj.Field(OIDOrganization, kinds)
		if err != nil {
			return Extracted{}, err
		}
		if !ok || NormalizeName(name) == "" {
			return Extracted{}, invalidf("subject O absent for an organization profile")
		}
		ident, _, err := subj.Field(OIDOrganizationIdentifier, kinds)
		if err != nil {
			return Extracted{}, err
		}
		out.Organization = &Organization{Name: NormalizeName(name), Identifier: strings.TrimSpace(ident)}
		src["organization"] = "subject.2.5.4.10"
		if ident != "" {
			src["organizationIdentifier"] = "subject.2.5.4.97"
		}
	}

	id.FullName = id.GivenNames + " " + id.Surnames
	out.Identity = id
	return out, nil
}

func requiredName(n Name, oid asn1.ObjectIdentifier, kinds KindSet) (string, error) {
	v, ok, err := n.Field(oid, kinds)
	if err != nil {
		return "", err
	}
	v = NormalizeName(v)
	if !ok || !hasLetter(v) {
		return "", invalidf("subject %s absent, empty or without a letter", oid)
	}
	return v, nil
}

// hasLetter reports whether s holds a letter. checkText has already rejected
// the invisible ones (the Hangul fillers), so the letter is visible (R5.1).
func hasLetter(s string) bool { return strings.IndexFunc(s, unicode.IsLetter) >= 0 }

// dnieSurnames applies the DNIe CN grammar against the known SN and GN. The
// surnames must be a normalised word sequence without ',' or parentheses.
func dnieSurnames(cn, sn, given string) (string, error) {
	var rest string
	var ok bool
	for _, suffix := range []string{" (AUTENTICACIÓN)", " (AUTENTICACION)"} {
		if rest, ok = strings.CutSuffix(cn, suffix); ok {
			break
		}
	}
	if !ok {
		return "", invalidf("DNIe CN lacks the authentication suffix")
	}
	full, ok := strings.CutSuffix(rest, ", "+given)
	if !ok {
		return "", invalidf("DNIe CN given name does not match GN")
	}
	if full != NormalizeName(full) || strings.ContainsAny(full, ",()") {
		return "", invalidf("DNIe CN surnames are not a plain word sequence")
	}
	if full != sn && !strings.HasPrefix(full, sn+" ") {
		return "", invalidf("DNIe CN surnames do not start with SN")
	}
	return full, nil
}

func (a Adapter) crossCheckSAN(cert *x509.Certificate, id *Identity, kinds KindSet) error {
	if a.SAN.Kind == SANNone {
		return nil
	}
	dirs, err := DirectoryNames(cert)
	if err != nil {
		return err
	}
	field := func(oid asn1.ObjectIdentifier) (string, bool, error) {
		var val string
		var found bool
		for _, d := range dirs {
			v, ok, err := d.Field(oid, kinds)
			if err != nil {
				return "", true, err
			}
			if ok {
				if found && v != val {
					return "", true, invalidf("san %s: conflicting duplicate values", oid)
				}
				val, found = v, true
			}
		}
		return val, found, nil
	}
	if a.SAN.DocumentOID != nil {
		v, ok, err := field(a.SAN.DocumentOID)
		if err != nil {
			return err
		}
		if !ok {
			return invalidf("san document %s absent", a.SAN.DocumentOID)
		}
		sanDoc, err := ParseDocument(v, "san."+a.SAN.DocumentOID.String(), a.SAN.DocumentRules)
		if err != nil {
			return invalidf("san document %s: does not parse", a.SAN.DocumentOID)
		}
		if sanDoc.Number != id.Document.Number || sanDoc.Type != id.Document.Type {
			return invalidf("san document %s disagrees with subject serialNumber", a.SAN.DocumentOID)
		}
	}
	var given, first, second string
	switch a.SAN.Kind {
	case SANAttributes:
		var ok bool
		if a.SAN.GivenNameOID != nil {
			if given, ok, err = field(a.SAN.GivenNameOID); err != nil || !ok {
				return orInvalid(err, "san given name absent")
			}
		}
		if first, ok, err = field(a.SAN.FirstSurnameOID); err != nil || !ok {
			return orInvalid(err, "san first surname absent")
		}
		if a.SAN.SecondSurnameOID != nil {
			if second, _, err = field(a.SAN.SecondSurnameOID); err != nil {
				return err
			}
		}
	case SANPipeCN:
		cn, ok, err := field(OIDCommonName)
		if err != nil || !ok {
			return orInvalid(err, "san CN absent")
		}
		parts := strings.Split(cn, "|")
		if len(parts) != 3 {
			return invalidf("san CN is not GIVEN|SURNAME1|SURNAME2")
		}
		given, first, second = parts[0], parts[1], parts[2]
	}
	given, first, second = NormalizeName(given), NormalizeName(first), NormalizeName(second)
	if first == "" {
		return invalidf("san first surname empty")
	}
	if (a.SAN.GivenNameOID != nil || a.SAN.Kind == SANPipeCN) && ComparisonKey(given) != ComparisonKey(id.GivenNames) {
		return invalidf("san given name disagrees with subject GN")
	}
	joined := first
	if second != "" {
		joined += " " + second
	}
	if ComparisonKey(joined) != ComparisonKey(id.Surnames) {
		return invalidf("san surnames disagree with subject SN")
	}
	id.FirstSurname, id.SecondSurname = first, second
	if a.SAN.Kind == SANPipeCN {
		id.Sources["firstSurname"] = "san.dirName.2.5.4.3[1]"
		if second != "" {
			id.Sources["secondSurname"] = "san.dirName.2.5.4.3[2]"
		}
		return nil
	}
	id.Sources["firstSurname"] = "san.dirName." + a.SAN.FirstSurnameOID.String()
	if second != "" {
		id.Sources["secondSurname"] = "san.dirName." + a.SAN.SecondSurnameOID.String()
	}
	return nil
}

func orInvalid(err error, msg string) error {
	if err != nil {
		return err
	}
	return invalidf("%s", msg)
}
