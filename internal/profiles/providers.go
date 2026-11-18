package profiles

import (
	"encoding/asn1"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// Source digests (provider research, not kept in this repository): A = FNMT, DNIe and ACCV;
// B = idCAT, Izenpe and Camerfirma; C = the other providers.
// Specimen fingerprints: testdata/specimens/MANIFEST.md.

func anchor(sha, spki string) Anchor {
	return Anchor{File: "anchors/" + sha + ".pem", SHA256: sha, SPKISHA256: spki}
}

func fp(sha, file string) TestMarker {
	return TestMarker{SHA256: sha, Source: "testdata/specimens/" + file}
}

func oid(arcs ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(arcs) }

var (
	dniNIE  = []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}
	dniOnly = []identity.DocumentType{identity.DocumentDNI}
	nieOnly = []identity.DocumentType{identity.DocumentNIE}
	idces   = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: dniNIE}}
	bare    = []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniNIE}}
	noSAN   = identity.SANCheck{Kind: identity.SANNone}
)

// plain: IDCES-<DNI|NIE> in 2.5.4.5, GN 2.5.4.42, complete surnames in SN 2.5.4.4,
// no SAN check, no birth date, no organization.
func plain() identity.Adapter {
	return identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN, SAN: noSAN,
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone}
}

// sanAttrs declares SAN directoryName attributes that must agree with the subject.
func sanAttrs(docOID asn1.ObjectIdentifier, docRules []identity.DocumentRule, given, first, second asn1.ObjectIdentifier) identity.SANCheck {
	return identity.SANCheck{Kind: identity.SANAttributes, DocumentOID: docOID, DocumentRules: docRules,
		GivenNameOID: given, FirstSurnameOID: first, SecondSurnameOID: second}
}

// fp13177: Firmaprofesional SAN namespace, also used by SIGNE.
func fp13177() identity.SANCheck {
	n := func(i int) asn1.ObjectIdentifier { return oid(1, 3, 6, 1, 4, 1, 13177, 0, i) }
	return sanAttrs(nil, nil, n(1), n(2), n(3))
}

func policy(nonce bool, ocsp, crl []string) revocation.Policy {
	return revocation.Policy{OCSPHosts: ocsp, CRLHosts: crl, AllowCRL: len(crl) > 0, OCSPNonce: nonce}
}

func person(id, providerID, name string, anchors []Anchor, oids []string, a identity.Adapter, p revocation.Policy, markers ...TestMarker) Profile {
	return Profile{ID: id, ProviderID: providerID, Name: name, HolderRole: RoleNaturalPerson, Anchors: anchors,
		PolicyOIDs: oids, EKU: EKURequireClientAuth, Identity: a, Revocation: p, TestMarkers: markers}
}

// All returns the production providers in display order:
// standard first, then the Beta group. Each call builds new Provider and
// Profile values, but nested slices (document rules and types) are shared
// package-level values: callers must not modify them.
func All() []Provider {
	return []Provider{
		FNMT(), IDCAT(), ACCV(), Digitel(), Bewor(), Sectigo(),
		FNMTRepresentative(), FNMTEmployee(), Firmaprofesional(), ANF(), Uanataca(), SIGNE(), Lleidanet(), DNIe(),
	}
}

// ByID returns the production provider declaration with the given ID.
func ByID(id string) (Provider, bool) {
	for _, p := range All() {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}
