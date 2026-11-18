package testpki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

var (
	oidExtCRLNumber        = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtAKI              = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtIDP              = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidEntryReason         = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidEntryInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
	OIDEntryCertIssuer     = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// CRLEntry is one revoked certificate.
type CRLEntry struct {
	Serial     *big.Int
	RevokedAt  time.Time
	Reason     int  // CRLReason; ignored when NoReason
	NoReason   bool // omit the reasonCode entry extension
	Extensions []pkix.Extension
}

// IDPSpec describes an IssuingDistributionPoint extension.
type IDPSpec struct {
	URIs            []string // distributionPoint fullName URIs
	DirNames        []Name   // distributionPoint fullName directoryNames
	DirNamesFirst   bool     // encode directoryNames before URIs
	RelativeName    RDN      // nameRelativeToCRLIssuer (instead of fullName) when non-nil
	OnlyUser        bool
	OnlyCA          bool
	OnlySomeReasons bool
	Indirect        bool
	OnlyAttr        bool
	NonCritical     bool // RFC 5280 requires critical; some CAs (EC-ACC) do not
}

// CRLSpec describes a CRL signed by a CA.
type CRLSpec struct {
	Number          int64
	ThisUpdate      time.Time // default Now - 1m
	NextUpdate      time.Time // default ThisUpdate + 24h
	NoNextUpdate    bool
	Now             time.Time
	Entries         []CRLEntry
	IDP             *IDPSpec
	ExtraExtensions []pkix.Extension
	Signer          *CA    // default: the receiver CA (wrong-signer tests set another CA)
	IssuerDER       []byte // override the issuer Name (default: receiver's RawSubject)
	CorruptSig      bool
}

// CRL encodes and signs a CRL for ca.
func (ca *CA) CRL(t testing.TB, spec CRLSpec) []byte {
	t.Helper()
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	if spec.ThisUpdate.IsZero() {
		spec.ThisUpdate = now.Add(-time.Minute)
	}
	if spec.NextUpdate.IsZero() {
		spec.NextUpdate = spec.ThisUpdate.Add(24 * time.Hour)
	}
	signer := spec.Signer
	if signer == nil {
		signer = ca
	}
	issuer := spec.IssuerDER
	if issuer == nil {
		issuer = ca.Cert.RawSubject
	}
	tbs := [][]byte{derInt(big.NewInt(1)), algIDFor(signer.Key.Public()), issuer, derTime(spec.ThisUpdate)}
	if !spec.NoNextUpdate {
		tbs = append(tbs, derTime(spec.NextUpdate))
	}
	if len(spec.Entries) > 0 {
		var entries [][]byte
		for _, e := range spec.Entries {
			var exts []extension
			if !e.NoReason {
				exts = append(exts, extension{id: oidEntryReason, value: derEnum(e.Reason)})
			}
			exts = append(exts, toExts(e.Extensions)...)
			parts := [][]byte{derInt(e.Serial), derTime(e.RevokedAt)}
			if len(exts) > 0 {
				parts = append(parts, derExtensions(exts))
			}
			entries = append(entries, seq(parts...))
		}
		tbs = append(tbs, seq(entries...))
	}
	exts := []extension{{id: oidExtCRLNumber, value: derInt(big.NewInt(spec.Number))}}
	if len(ca.Cert.SubjectKeyId) > 0 {
		exts = append(exts, extension{id: oidExtAKI, value: seq(ctx(0, false, ca.Cert.SubjectKeyId))})
	}
	if spec.IDP != nil {
		exts = append(exts, extension{id: oidExtIDP, critical: !spec.IDP.NonCritical, value: EncodeIDP(*spec.IDP)})
	}
	exts = append(exts, toExts(spec.ExtraExtensions)...)
	tbs = append(tbs, ctx(0, true, derExtensions(exts)))
	tbsDER := seq(tbs...)
	sig, algID, err := signDigest(signer.Key, tbsDER)
	if err != nil {
		t.Fatalf("testpki: sign CRL: %v", err)
	}
	if spec.CorruptSig {
		sig[len(sig)-1] ^= 0xff
	}
	return seq(tbsDER, algID, derBitString(sig))
}

// EncodeIDP encodes an IssuingDistributionPoint extension value.
func EncodeIDP(s IDPSpec) []byte {
	var parts [][]byte
	switch {
	case s.RelativeName != nil:
		var atvs [][]byte
		for _, a := range s.RelativeName {
			tag := a.Tag
			if tag == 0 {
				tag = TagUTF8
			}
			atvs = append(atvs, seq(derOID(a.OID), encodeString(tag, a.Value)))
		}
		parts = append(parts, ctx(0, true, ctx(1, true, atvs...)))
	case len(s.URIs) > 0 || len(s.DirNames) > 0:
		parts = append(parts, ctx(0, true, ctx(0, true, encodeGeneralNames(s.URIs, s.DirNames, s.DirNamesFirst))))
	}
	boolTrue := []byte{0xff}
	if s.OnlyUser {
		parts = append(parts, ctx(1, false, boolTrue))
	}
	if s.OnlyCA {
		parts = append(parts, ctx(2, false, boolTrue))
	}
	if s.OnlySomeReasons {
		parts = append(parts, ctx(3, false, []byte{0x07, 0x80})) // unused=7, keyCompromise
	}
	if s.Indirect {
		parts = append(parts, ctx(4, false, boolTrue))
	}
	if s.OnlyAttr {
		parts = append(parts, ctx(5, false, boolTrue))
	}
	return seq(parts...)
}

// InvalidityDate returns an invalidityDate CRL entry extension.
func InvalidityDate(t time.Time) pkix.Extension {
	return pkix.Extension{Id: oidEntryInvalidityDate, Value: derGeneralizedTime(t)}
}
