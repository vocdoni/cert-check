// Package profiles holds the provider/profile registry: pinned anchors
// (embedded PEM, SHA-256 and SPKI pins checked at load), exact policy OIDs,
// purpose and algorithm rules, identity adapters, revocation policies and
// test-certificate markers.
package profiles

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// Role is the holder role of a profile.
type Role string

// Roles (JSON values of profile.holderRole).
const (
	RoleNaturalPerson  Role = "natural_person"
	RoleRepresentative Role = "representative"
	RolePublicEmployee Role = "public_employee"
)

// Valid reports whether r is a defined role.
func (r Role) Valid() bool {
	return r == RoleNaturalPerson || r == RoleRepresentative || r == RolePublicEmployee
}

// Anchor is a pinned CA certificate: a trust anchor or a pinned intermediate.
type Anchor struct {
	File       string // path in the embedded FS, "anchors/<sha256>.pem"; empty when DER is set
	DER        []byte // tests only: the certificate itself
	SHA256     string // pinned SHA-256 of the DER, lowercase hex
	SPKISHA256 string // pinned SHA-256 of the SubjectPublicKeyInfo, lowercase hex
}

// TestAnchor builds an Anchor from a certificate with computed pins (tests).
func TestAnchor(c *x509.Certificate) Anchor {
	d, s := sha256.Sum256(c.Raw), sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return Anchor{DER: c.Raw, SHA256: hex.EncodeToString(d[:]), SPKISHA256: hex.EncodeToString(s[:])}
}

// KURule is the leaf KeyUsage rule. digitalSignature is always required when
// the extension is present.
type KURule struct {
	AllowAbsent bool // no enabled profile sets this
}

// EKURule is the leaf ExtendedKeyUsage rule.
type EKURule int

// EKU rules.
const (
	// EKURequireClientAuth: the extension is present and lists clientAuth.
	EKURequireClientAuth EKURule = iota + 1
	// EKUAllowAbsent: absent, or present and listing clientAuth (DNIe only).
	EKUAllowAbsent
)

// AlgPolicy tightens the global algorithm floor (RSA ≥ 2048, ECDSA
// P-256/P-384/P-521, SHA-256+ signatures) where a profile documents it.
type AlgPolicy struct {
	MinRSABits int // 0 = 2048
}

// AttributeMatch is one exact subject attribute value.
type AttributeMatch struct {
	OID   asn1.ObjectIdentifier
	Value string
}

// TestMarker identifies a known test or specimen certificate.
type TestMarker struct {
	SHA256  string           // leaf DER SHA-256 (lowercase hex); or
	Subject []AttributeMatch // an exact subject attribute combination documented by the issuer
	Source  string           // where it comes from (fixture file, CPS section)
}

// Profile is a versioned, exact allowlist entry.
type Profile struct {
	ID                        string
	ProviderID                string
	Name                      string
	HolderRole                Role
	Anchors                   []Anchor
	Intermediates             []Anchor // pinned CAs between anchor and leaf (DNIe only)
	PolicyOIDs                []string // exact dotted OIDs; the leaf asserts at least one
	KeyUsage                  KURule
	EKU                       EKURule
	Algorithms                AlgPolicy
	Identity                  identity.Adapter
	Revocation                revocation.Policy
	TestMarkers               []TestMarker
	HandledCriticalExtensions []string // dotted OIDs parsed by certauth itself (aoc-idcat-g2: qcStatements)
}

// Provider is a selectable UI entry and auth subdomain grouping profiles.
type Provider struct {
	ID          string // DNS label: [a-z][a-z0-9-]{0,62}
	Name        string
	Description string
	Beta        bool
	Profiles    []Profile
}

// ProfileInfo is the profile part of a result.
type ProfileInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	HolderRole Role   `json:"holderRole"`
}
