package revocation

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidExtCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtIssuingDistPoint      = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidExtCRLNumber             = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtAuthorityKeyID        = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtDeltaCRLIndicator     = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidEntryReasonCode          = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidEntryInvalidityDate      = asn1.ObjectIdentifier{2, 5, 29, 24}
	oidEntryCertificateIssuer   = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// GeneralName is one GeneralName kept as its full DER TLV, compared byte for byte.
type GeneralName []byte

// URI returns the uniformResourceIdentifier ([6]) value, if it is one.
func (g GeneralName) URI() (string, bool) {
	s := cryptobyte.String(g)
	var v cryptobyte.String
	if !s.ReadASN1(&v, cbasn1.Tag(6).ContextSpecific()) || !s.Empty() {
		return "", false
	}
	return string(v), true
}

// DistributionPoint is one entry of a certificate's CRLDistributionPoints.
type DistributionPoint struct {
	FullName     []GeneralName
	RelativeName bool          // nameRelativeToCRLIssuer present (unsupported)
	HasReasons   bool          // reasons present (partial DP, unsupported)
	CRLIssuer    []GeneralName // cRLIssuer, nil when absent
}

// ParseCRLDistributionPoints parses the certificate's CDP extension itself:
// x509.Certificate.CRLDistributionPoints stops at the first non-URI name and
// loses the names needed for the IDP comparison.
func ParseCRLDistributionPoints(cert *x509.Certificate) ([]DistributionPoint, error) {
	var raw []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtCRLDistributionPoints) {
			raw = e.Value
		}
	}
	if raw == nil {
		return nil, nil
	}
	return ParseCDP(raw)
}

// ParseCDP parses a CRLDistributionPoints extension value.
func ParseCDP(raw []byte) ([]DistributionPoint, error) {
	in := cryptobyte.String(raw)
	var dps cryptobyte.String
	if !in.ReadASN1(&dps, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errors.New("cdp: malformed")
	}
	var out []DistributionPoint
	for !dps.Empty() {
		var dpDER cryptobyte.String
		if !dps.ReadASN1(&dpDER, cbasn1.SEQUENCE) {
			return nil, errors.New("cdp: malformed DistributionPoint")
		}
		var dp DistributionPoint
		var name cryptobyte.String
		var has bool
		if !dpDER.ReadOptionalASN1(&name, &has, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("cdp: malformed distributionPoint")
		}
		if has {
			full, rel, err := parseDistributionPointName(name)
			if err != nil {
				return nil, fmt.Errorf("cdp: %w", err)
			}
			dp.FullName, dp.RelativeName = full, rel
		}
		var skip cryptobyte.String
		if !dpDER.ReadOptionalASN1(&skip, &dp.HasReasons, cbasn1.Tag(1).ContextSpecific()) {
			return nil, errors.New("cdp: malformed reasons")
		}
		var issuer cryptobyte.String
		var hasIssuer bool
		if !dpDER.ReadOptionalASN1(&issuer, &hasIssuer, cbasn1.Tag(2).Constructed().ContextSpecific()) {
			return nil, errors.New("cdp: malformed cRLIssuer")
		}
		if hasIssuer {
			names, err := readGeneralNames(issuer)
			if err != nil {
				return nil, fmt.Errorf("cdp: cRLIssuer: %w", err)
			}
			dp.CRLIssuer = names
		}
		if !dpDER.Empty() {
			return nil, errors.New("cdp: trailing data")
		}
		out = append(out, dp)
	}
	return out, nil
}

// parseDistributionPointName parses the content of a [0] DistributionPointName.
func parseDistributionPointName(s cryptobyte.String) (full []GeneralName, relative bool, err error) {
	var inner cryptobyte.String
	switch {
	case s.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()):
		if !s.ReadASN1(&inner, cbasn1.Tag(0).Constructed().ContextSpecific()) || !s.Empty() {
			return nil, false, errors.New("malformed fullName")
		}
		full, err = readGeneralNames(inner)
		return full, false, err
	case s.PeekASN1Tag(cbasn1.Tag(1).Constructed().ContextSpecific()):
		return nil, true, nil
	}
	return nil, false, errors.New("unknown DistributionPointName")
}

func readGeneralNames(s cryptobyte.String) ([]GeneralName, error) {
	var out []GeneralName
	for !s.Empty() {
		var gn cryptobyte.String
		var tag cbasn1.Tag
		if !s.ReadAnyASN1Element(&gn, &tag) || tag&0xc0 != 0x80 {
			return nil, errors.New("malformed GeneralName")
		}
		out = append(out, GeneralName(gn))
	}
	if len(out) == 0 {
		return nil, errors.New("empty GeneralNames")
	}
	return out, nil
}

// IDP is a parsed IssuingDistributionPoint.
type IDP struct {
	FullName          []GeneralName
	RelativeName      bool
	OnlyUserCerts     bool
	OnlyCACerts       bool
	OnlySomeReasons   bool
	IndirectCRL       bool
	OnlyAttributeCert bool
}

// ParseIDP parses an IssuingDistributionPoint extension value.
func ParseIDP(der []byte) (IDP, error) {
	in := cryptobyte.String(der)
	var s cryptobyte.String
	if !in.ReadASN1(&s, cbasn1.SEQUENCE) || !in.Empty() {
		return IDP{}, errors.New("idp: malformed")
	}
	var idp IDP
	var name cryptobyte.String
	var has bool
	if !s.ReadOptionalASN1(&name, &has, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return IDP{}, errors.New("idp: malformed distributionPoint")
	}
	if has {
		full, rel, err := parseDistributionPointName(name)
		if err != nil {
			return IDP{}, fmt.Errorf("idp: %w", err)
		}
		idp.FullName, idp.RelativeName = full, rel
	}
	readBool := func(tag uint8, out *bool) error {
		var v cryptobyte.String
		var present bool
		if !s.ReadOptionalASN1(&v, &present, cbasn1.Tag(tag).ContextSpecific()) {
			return fmt.Errorf("idp: malformed [%d]", tag)
		}
		if present {
			if len(v) != 1 || (v[0] != 0x00 && v[0] != 0xff) {
				return fmt.Errorf("idp: bad BOOLEAN [%d]", tag)
			}
			*out = v[0] == 0xff
		}
		return nil
	}
	if err := readBool(1, &idp.OnlyUserCerts); err != nil {
		return IDP{}, err
	}
	if err := readBool(2, &idp.OnlyCACerts); err != nil {
		return IDP{}, err
	}
	var reasons cryptobyte.String
	if !s.ReadOptionalASN1(&reasons, &idp.OnlySomeReasons, cbasn1.Tag(3).ContextSpecific()) {
		return IDP{}, errors.New("idp: malformed onlySomeReasons")
	}
	if err := readBool(4, &idp.IndirectCRL); err != nil {
		return IDP{}, err
	}
	if err := readBool(5, &idp.OnlyAttributeCert); err != nil {
		return IDP{}, err
	}
	if !s.Empty() {
		return IDP{}, errors.New("idp: trailing data")
	}
	return idp, nil
}

// ParsedCRL is a parsed, signature-checked CRL kept in the cache: only what
// EvaluateCRL reads, without the DER or the x509.RevocationList.
type ParsedCRL struct {
	ThisUpdate time.Time
	NextUpdate time.Time            // zero when the CRL has none
	Number     *big.Int             // cRLNumber, nil when absent
	IDP        *IDP                 // nil when the CRL has no IDP
	Listed     map[string]CRLRecord // serial (lowercase hex of big.Int bytes) -> record
	Cost       int64                // estimated retained heap, for the cache bound
	URL        string
}

// Cache charge of a ParsedCRL: a conservative bound on its retained heap,
// calibrated by TestCRLCacheDenseEntryAccounting. An entry costs its key
// bytes plus crlCostEntry for its map slot, key header and size-class
// rounding (measured at most 128 bytes on Go 1.27 amd64, 1k to 1M entries).
const (
	crlCostBase  = 4 << 10
	crlCostEntry = 160
)

// CRLRecord is one listed serial.
type CRLRecord struct {
	RevokedAt time.Time
	Reason    int // -1 when the entry has no reasonCode
}

// SerialKey is the map key for a serial number.
func SerialKey(n *big.Int) string { return fmt.Sprintf("%x", n) }

// ParseCRL checks issuer name and signature against issuer, then parses der
// and enforces criticality: only IDP among critical CRL extensions; only
// reasonCode and invalidityDate among entry extensions; certificateIssuer and
// delta CRLs are unsupported. It returns a Status for the failure cases.
func ParseCRL(der []byte, issuer *x509.Certificate) (*ParsedCRL, Status, error) {
	if err := checkCRLSignature(der, issuer); err != nil {
		return nil, StatusInvalidEvidence, err
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, StatusInvalidEvidence, fmt.Errorf("crl: parse: %w", err)
	}
	p := &ParsedCRL{ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate, Number: rl.Number,
		Listed: make(map[string]CRLRecord, len(rl.RevokedCertificateEntries)), Cost: crlCostBase}
	seen := make(map[string]bool, len(rl.Extensions))
	for _, e := range rl.Extensions {
		id := e.Id.String()
		if seen[id] {
			return nil, StatusInvalidEvidence, fmt.Errorf("crl: duplicate extension %s", id)
		}
		seen[id] = true
		switch {
		case e.Id.Equal(oidExtIssuingDistPoint):
			idp, err := ParseIDP(bytes.Clone(e.Value)) // e.Value aliases der
			if err != nil {
				return nil, StatusInvalidEvidence, err
			}
			p.IDP = &idp
			p.Cost += int64(len(e.Value))
		case e.Id.Equal(oidExtDeltaCRLIndicator):
			return nil, StatusUnsupportedMethod, errors.New("crl: delta CRL")
		case e.Critical && !e.Id.Equal(oidExtCRLNumber) && !e.Id.Equal(oidExtAuthorityKeyID):
			return nil, StatusUnsupportedMethod, fmt.Errorf("crl: unhandled critical extension %s", e.Id)
		}
	}
	for _, entry := range rl.RevokedCertificateEntries {
		rec := CRLRecord{RevokedAt: entry.RevocationTime, Reason: -1}
		for _, e := range entry.Extensions {
			switch {
			case e.Id.Equal(oidEntryReasonCode):
				rec.Reason = entry.ReasonCode
			case e.Id.Equal(oidEntryInvalidityDate):
				v, at := cryptobyte.String(e.Value), time.Time{}
				if e.Critical && (!v.ReadASN1GeneralizedTime(&at) || !v.Empty()) {
					return nil, StatusInvalidEvidence, errors.New("crl: malformed critical invalidityDate entry extension")
				}
			case e.Id.Equal(oidEntryCertificateIssuer):
				return nil, StatusUnsupportedMethod, errors.New("crl: certificateIssuer entry extension (indirect CRL)")
			case e.Critical:
				return nil, StatusUnsupportedMethod, fmt.Errorf("crl: unhandled critical entry extension %s", e.Id)
			}
		}
		k := SerialKey(entry.SerialNumber)
		p.Listed[k] = rec
		p.Cost += crlCostEntry + int64(len(k))
	}
	return p, StatusGood, nil
}

// checkCRLSignature authenticates der before x509.ParseRevocationList
// allocates its entries: it splits the CertificateList, compares the TBS
// issuer Name with issuer and checks the signature (with the issuer
// constraints of RevocationList.CheckSignatureFrom).
func checkCRLSignature(der []byte, issuer *x509.Certificate) error {
	in := cryptobyte.String(der)
	var crl, tbs, body, sigAlg, name cryptobyte.String
	var sig asn1.BitString
	if !in.ReadASN1(&crl, cbasn1.SEQUENCE) || !in.Empty() ||
		!crl.ReadASN1Element(&tbs, cbasn1.SEQUENCE) || !crl.ReadASN1(&sigAlg, cbasn1.SEQUENCE) ||
		!crl.ReadASN1BitString(&sig) || sig.BitLength%8 != 0 || !crl.Empty() {
		return errors.New("crl: malformed CertificateList")
	}
	if b := tbs; !b.ReadASN1(&body, cbasn1.SEQUENCE) || !body.SkipOptionalASN1(cbasn1.INTEGER) ||
		!body.SkipASN1(cbasn1.SEQUENCE) || !body.ReadASN1Element(&name, cbasn1.SEQUENCE) {
		return errors.New("crl: malformed tbsCertList")
	}
	if !bytes.Equal(name, issuer.RawSubject) {
		return errors.New("crl: issuer name differs from the certificate issuer")
	}
	rl := x509.RevocationList{RawTBSRevocationList: tbs, SignatureAlgorithm: parseSignatureAlgorithm(sigAlg), Signature: sig.Bytes}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("crl: signature: %w", err)
	}
	return nil
}

// Scope is what the checked certificate is.
type Scope int

// Scopes.
const (
	ScopeLeaf Scope = iota + 1
	ScopeCA         // a pinned intermediate (DNIe AC DNIE 00N)
)

// EvaluateCRL applies freshness, scope and listing to a parsed CRL for cert,
// whose CDP DistributionPoint (the one the URL came from) is dp.
func EvaluateCRL(p *ParsedCRL, cert *x509.Certificate, dp DistributionPoint, scope Scope, now time.Time) (Status, CRLRecord, string) {
	if st, detail := crlApplies(p, dp, now); st != StatusGood {
		return st, CRLRecord{}, detail
	}
	if idp := p.IDP; idp != nil {
		if idp.RelativeName {
			return StatusUnsupportedMethod, CRLRecord{}, "idp nameRelativeToCRLIssuer"
		}
		if idp.OnlyAttributeCert || idp.IndirectCRL || idp.OnlySomeReasons {
			return StatusUnsupportedMethod, CRLRecord{}, "idp scope flag unsupported"
		}
		switch scope {
		case ScopeLeaf:
			if idp.OnlyCACerts {
				return StatusUnsupportedMethod, CRLRecord{}, "idp onlyContainsCACerts for a leaf"
			}
		case ScopeCA:
			if idp.OnlyUserCerts {
				return StatusUnsupportedMethod, CRLRecord{}, "idp onlyContainsUserCerts for a CA"
			}
		}
	}
	if rec, ok := p.Listed[SerialKey(cert.SerialNumber)]; ok {
		return StatusRevoked, rec, "serial listed"
	}
	return StatusGood, CRLRecord{}, "serial not listed"
}

// crlApplies is the part of EvaluateCRL that does not depend on the
// certificate: p is well dated and fresh at now and, when its IDP names
// distribution points, issued for dp. The name check comes before any scope
// flag, so a CRL of another DP is invalid evidence.
func crlApplies(p *ParsedCRL, dp DistributionPoint, now time.Time) (Status, string) {
	switch {
	case p.ThisUpdate.IsZero():
		return StatusInvalidEvidence, "crl thisUpdate is the zero time"
	case !p.NextUpdate.IsZero() && p.NextUpdate.Before(p.ThisUpdate):
		return StatusInvalidEvidence, "crl nextUpdate before thisUpdate"
	case p.ThisUpdate.After(now.Add(ClockSkew)):
		return StatusStale, "crl thisUpdate in the future"
	case p.NextUpdate.IsZero():
		return StatusStale, "crl without nextUpdate"
	case p.NextUpdate.Before(now):
		return StatusStale, "crl nextUpdate in the past"
	case p.IDP != nil && len(p.IDP.FullName) > 0 && !namesIntersect(p.IDP.FullName, dp.FullName):
		return StatusInvalidEvidence, "idp distributionPoint does not match the certificate CDP"
	}
	return StatusGood, ""
}

func namesIntersect(a, b []GeneralName) bool {
	for _, x := range a {
		for _, y := range b {
			if bytes.Equal(x, y) {
				return true
			}
		}
	}
	return false
}

// usableDistributionPoints returns the DPs this package can use for cert
// issued by issuer: fullName form, no reasons, and cRLIssuer absent or equal
// to the issuer (ACCV CA certificates name their own issuer).
func usableDistributionPoints(dps []DistributionPoint, issuer *x509.Certificate) []DistributionPoint {
	var out []DistributionPoint
	for _, dp := range dps {
		if dp.RelativeName || dp.HasReasons || len(dp.FullName) == 0 {
			continue
		}
		if dp.CRLIssuer != nil && !crlIssuerIsIssuer(dp.CRLIssuer, issuer) {
			continue
		}
		out = append(out, dp)
	}
	return out
}

func crlIssuerIsIssuer(names []GeneralName, issuer *x509.Certificate) bool {
	if len(names) != 1 {
		return false
	}
	s := cryptobyte.String(names[0])
	var inner cryptobyte.String
	if !s.ReadASN1(&inner, cbasn1.Tag(4).Constructed().ContextSpecific()) || !s.Empty() {
		return false
	}
	return bytes.Equal(inner, issuer.RawSubject)
}
