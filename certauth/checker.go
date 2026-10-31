package certauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Bounds.
const (
	DefaultMaxChainLen = 10
	MaxCertificateDER  = 16 << 10
)

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// extensionParsers validate critical extensions a profile handles itself
// (spec step 5 exception mechanism). Every HandledCriticalExtensions entry
// must have a parser here; NewChecker enforces it.
var extensionParsers = map[string]func([]byte) error{
	"1.3.6.1.5.5.7.1.3": parseQCStatements,
}

// parseQCStatements: QCStatements ::= SEQUENCE OF SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }.
func parseQCStatements(der []byte) error {
	var stmts []struct {
		ID   asn1.ObjectIdentifier
		Info asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(der, &stmts)
	if err != nil || len(rest) != 0 || len(stmts) == 0 {
		return errors.New("malformed qcStatements")
	}
	return nil
}

// Options configures a Checker.
type Options struct {
	Registry    *profiles.Registry  // required
	Revocation  *revocation.Checker // required
	Now         func() time.Time    // nil = time.Now
	MaxChainLen int                 // 0 = 10
	Version     string              // reported as diagnostics serverVersion
}

// Checker runs the validation pipeline. Safe for concurrent use.
type Checker struct {
	reg     *profiles.Registry
	rev     *revocation.Checker
	now     func() time.Time
	maxLen  int
	version string
}

// NewChecker validates options.
func NewChecker(o Options) (*Checker, error) {
	if o.Registry == nil || o.Revocation == nil {
		return nil, errors.New("certauth: Registry and Revocation are required")
	}
	for _, p := range o.Registry.Providers() {
		for _, prof := range p.Profiles {
			for _, oid := range prof.HandledCriticalExtensions {
				if _, ok := extensionParsers[oid]; !ok {
					return nil, fmt.Errorf("certauth: profile %s handles %s without a parser", prof.ID, oid)
				}
			}
		}
	}
	c := &Checker{reg: o.Registry, rev: o.Revocation, now: o.Now, maxLen: o.MaxChainLen, version: o.Version}
	if c.now == nil {
		c.now = time.Now
	}
	if c.maxLen <= 0 {
		c.maxLen = DefaultMaxChainLen
	}
	return c, nil
}

// Providers returns the enabled providers in display order.
func (c *Checker) Providers() []profiles.Provider { return c.reg.Providers() }

// ClientCAs returns the CA pool advertised for a provider.
func (c *Checker) ClientCAs(providerID string) (*x509.CertPool, error) {
	return c.reg.ClientCAs(providerID)
}

// run carries the diagnostics of one Check invocation.
type run struct {
	diag Diagnostics
}

func (r *run) fail(step Step, code ErrorCode, detail string) *Error {
	r.diag.FailedStep, r.diag.Code, r.diag.TechnicalDetail = step, code, detail
	return &Error{Code: code, Retryable: code.Retryable(), Detail: detail, Diagnostics: r.diag}
}

type candidate struct {
	e     *profiles.Enabled
	chain []*x509.Certificate
	err   error
}

// Check validates chain (as received: chain[0] is the leaf) for providerID.
// The returned error is always *Error.
func (c *Checker) Check(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error) {
	now := c.now()
	r := &run{diag: Diagnostics{DiagnosticID: NewDiagnosticID(), Time: now.UTC(), ServerVersion: c.version, Provider: providerID}}
	for _, cert := range chain {
		if cert != nil {
			r.diag.Chain = append(r.diag.Chain, ChainEntry{Subject: cert.Subject.String(), Issuer: cert.Issuer.String()})
		}
	}
	if len(chain) > 0 && chain[0] != nil {
		r.diag.Certificate = describeCertificate(chain[0])
	}

	// 1. Bounds.
	prov, ok := c.reg.Provider(providerID)
	if !ok {
		return nil, r.fail(StepBounds, CodeProviderMismatch, "unknown provider")
	}
	if len(chain) == 0 || chain[0] == nil {
		return nil, r.fail(StepBounds, CodeNoCertificate, "no client certificate")
	}
	if len(chain) > c.maxLen {
		return nil, r.fail(StepBounds, CodeInvalidChain, fmt.Sprintf("chain length %d exceeds %d", len(chain), c.maxLen))
	}
	for i, cert := range chain {
		if cert == nil || len(cert.Raw) > MaxCertificateDER {
			return nil, r.fail(StepBounds, CodeInvalidChain, fmt.Sprintf("certificate %d missing or larger than %d bytes", i, MaxCertificateDER))
		}
	}
	leaf := chain[0]

	// 2. Algorithms (before path building: Go reports a SHA-1 leaf signature as UnknownAuthorityError).
	if detail, ok := algorithmsOK(leaf, 2048); !ok {
		return nil, r.fail(StepAlgorithms, CodeWeakAlgorithm, detail)
	}

	// 3. Path, per enabled profile, with pinned roots and pinned intermediates only.
	var cands []candidate
	for _, e := range c.reg.Enabled(providerID) {
		chains, err := leafForProfile(leaf, e.Profile).Verify(verifyOptions(e.Roots, e.Inter, now))
		cand := candidate{e: e, err: err}
		if err == nil {
			cand.chain = chains[0]
		}
		cands = append(cands, cand)
	}
	var verified []candidate
	for _, cand := range cands {
		res := "path ok"
		if cand.err != nil {
			res = cand.err.Error()
		} else {
			verified = append(verified, cand)
		}
		r.diag.ProfileCandidates = append(r.diag.ProfileCandidates, CandidateResult{ProfileID: cand.e.Profile.ID, Result: res})
	}
	if len(verified) == 0 {
		code, detail := c.mapPathErrors(leaf, cands, now)
		return nil, r.fail(StepPath, code, detail)
	}

	// 4. Profile: exactly one verified profile whose exact OID the leaf asserts.
	var leafPolicies []string
	for _, p := range leaf.Policies {
		leafPolicies = append(leafPolicies, p.String())
	}
	var matched []candidate
	for _, cand := range verified {
		if slices.ContainsFunc(cand.e.Profile.PolicyOIDs, func(o string) bool { return slices.Contains(leafPolicies, o) }) {
			matched = append(matched, cand)
		}
	}
	switch len(matched) {
	case 0:
		var want []string
		for _, cand := range verified {
			want = append(want, cand.e.Profile.PolicyOIDs...)
		}
		return nil, r.fail(StepProfile, CodeUnsupportedProfile, fmt.Sprintf("policy OIDs present %v; expected one of %v", leafPolicies, want))
	case 1:
	default:
		return nil, r.fail(StepProfile, CodeInternal, "more than one profile matches (registry bug)")
	}
	m := matched[0]
	prof := m.e.Profile
	for i := range r.diag.ProfileCandidates {
		if r.diag.ProfileCandidates[i].ProfileID == prof.ID {
			r.diag.ProfileCandidates[i].Result = "path ok; policy match"
		}
	}
	if detail, ok := algorithmsOK(leaf, prof.Algorithms.MinRSABits); !ok {
		return nil, r.fail(StepAlgorithms, CodeWeakAlgorithm, detail)
	}

	// 5. Purpose.
	if detail, ok := purposeOK(leaf, prof); !ok {
		return nil, r.fail(StepPurpose, CodeUnsupportedPurpose, detail)
	}
	for _, oid := range prof.HandledCriticalExtensions {
		for _, ext := range leaf.Extensions {
			if ext.Id.String() == oid && ext.Critical {
				if err := extensionParsers[oid](ext.Value); err != nil {
					return nil, r.fail(StepPurpose, CodeInvalidChain, fmt.Sprintf("handled critical extension %s: %v", oid, err))
				}
			}
		}
	}

	// 6. Test certificates: fingerprint or documented subject marker combination.
	sum := sha256.Sum256(leaf.Raw)
	if m.e.IsFingerprintMarker(hex.EncodeToString(sum[:])) {
		return nil, r.fail(StepTestMarker, CodeTestCertificate, "known specimen fingerprint")
	}
	if subjectMarkerMatch(leaf, prof.TestMarkers) {
		return nil, r.fail(StepTestMarker, CodeTestCertificate, "documented test subject marker")
	}

	// 7. Identity.
	x, err := prof.Identity.Extract(leaf)
	switch {
	case errors.Is(err, identity.ErrUnsupportedDocument):
		return nil, r.fail(StepIdentity, CodeIdentityUnsupportedDocument, err.Error())
	case errors.Is(err, identity.ErrInvalid):
		return nil, r.fail(StepIdentity, CodeIdentityInvalid, err.Error())
	case err != nil:
		return nil, r.fail(StepIdentity, CodeInternal, err.Error())
	}
	// 7b. Reserved identities and name markers.
	if kind, hit := c.reg.Reserved().Match(x); hit {
		return nil, r.fail(StepTestMarker, CodeTestCertificate, "reserved identity: "+string(kind))
	}

	// 8. Revocation of chain[i] by chain[i+1] of the verified chain, leaf
	// first; anchors are governed by D1.
	var leafRev revocation.Result
	for i := range len(m.chain) - 1 {
		res, err := c.rev.Check(ctx, m.chain[i], m.chain[i+1], prof.Revocation)
		if err != nil {
			return nil, r.fail(StepRevocation, CodeInternal, err.Error())
		}
		r.diag.RevocationAttempts = append(r.diag.RevocationAttempts, reportAttempts(res.Attempts)...)
		if code, bad := revocationCode(res.Status); bad {
			if ctx.Err() != nil {
				return nil, r.fail(StepRevocation, CodeInternal, "validation deadline exceeded")
			}
			return nil, r.fail(StepRevocation, code, res.Detail)
		}
		if i == 0 {
			leafRev = res
		}
	}
	if leafRev.Status != revocation.StatusGood { // fail closed: no Result without good leaf evidence
		return nil, r.fail(StepRevocation, CodeInternal, "no revocation evidence for the leaf")
	}

	// 9. Result.
	var next *time.Time
	if !leafRev.NextUpdate.IsZero() {
		next = new(leafRev.NextUpdate.UTC())
	}
	return &Result{
		Provider:     profiles.ProviderInfo{ID: prov.ID, Name: prov.Name},
		Profile:      profiles.ProfileInfo{ID: prof.ID, Name: prof.Name, HolderRole: prof.HolderRole},
		Identity:     x.Identity,
		Organization: x.Organization,
		Certificate: CertificateInfo{
			Subject: leaf.Subject.String(), Issuer: leaf.Issuer.CommonName, SerialHex: fmt.Sprintf("%x", leaf.SerialNumber),
			NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), SHA256: hex.EncodeToString(sum[:]), KeyAlgorithm: keyAlgorithm(leaf),
		},
		Revocation: RevocationInfo{Status: leafRev.Status, Method: leafRev.Method, CheckedAt: leafRev.CheckedAt.UTC(),
			ThisUpdate: leafRev.ThisUpdate.UTC(), NextUpdate: next, Source: leafRev.Source},
		ValidatedAt: now.UTC(),
		Diagnostics: r.diag,
	}, nil
}

func verifyOptions(roots, inter *x509.CertPool, now time.Time) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

// leafForProfile returns the leaf, or a shallow copy whose
// UnhandledCriticalExtensions omits the profile's handled OIDs. Only that
// slice differs: Raw and RawTBSCertificate (the signature input) are shared.
func leafForProfile(leaf *x509.Certificate, p profiles.Profile) *x509.Certificate {
	if len(p.HandledCriticalExtensions) == 0 || len(leaf.UnhandledCriticalExtensions) == 0 {
		return leaf
	}
	cp := *leaf
	cp.UnhandledCriticalExtensions = nil
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !slices.Contains(p.HandledCriticalExtensions, oid.String()) {
			cp.UnhandledCriticalExtensions = append(cp.UnhandledCriticalExtensions, oid)
		}
	}
	return &cp
}

// pathRank orders candidate failures: a lower rank is more specific.
const (
	rankUsage = iota + 1
	rankExpired
	rankCritical
	rankUnknownAuthority
	rankOther
)

// mapPathErrors maps the candidates' x509 errors to one code. Priority:
// IncompatibleUsage > Expired > UnhandledCriticalExtension (when the leaf
// otherwise chains to that profile) > UnknownAuthority > other.
func (c *Checker) mapPathErrors(leaf *x509.Certificate, cands []candidate, now time.Time) (ErrorCode, string) {
	best, bestRank, detail := CodeInvalidChain, rankOther+1, ""
	consider := func(rank int, code ErrorCode, d string) {
		if rank < bestRank {
			best, bestRank, detail = code, rank, d
		}
	}
	for _, cand := range cands {
		err := cand.err
		if ucErr, ok := errors.AsType[x509.UnhandledCriticalExtension](err); ok {
			// Go rejects unhandled critical extensions before building chains, so
			// learn whether this profile's anchor issued the leaf (code choice only).
			stripped := *leaf
			stripped.UnhandledCriticalExtensions = nil
			_, err2 := stripped.Verify(verifyOptions(cand.e.Roots, cand.e.Inter, now))
			if _, unknown := errors.AsType[x509.UnknownAuthorityError](err2); unknown {
				err = err2
			} else {
				consider(rankCritical, CodeInvalidChain, fmt.Sprintf("%v %v", ucErr, leaf.UnhandledCriticalExtensions))
				continue
			}
		}
		if cie, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
			switch cie.Reason {
			case x509.IncompatibleUsage:
				consider(rankUsage, CodeUnsupportedPurpose, err.Error())
			case x509.Expired:
				switch {
				case now.Before(leaf.NotBefore):
					consider(rankExpired, CodeNotYetValid, err.Error())
				case now.After(leaf.NotAfter):
					consider(rankExpired, CodeExpired, err.Error())
				default:
					consider(rankExpired, CodeInvalidChain, "anchor or intermediate outside validity: "+err.Error())
				}
			default:
				consider(rankOther, CodeInvalidChain, err.Error())
			}
			continue
		}
		if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
			consider(rankUnknownAuthority, c.unknownAuthorityCode(leaf, now), err.Error())
			continue
		}
		consider(rankOther, CodeInvalidChain, fmt.Sprint(err))
	}
	return best, detail
}

// unknownAuthorityCode: provider_mismatch when the leaf verifies against the
// union of every enabled provider's pinned CAs, else untrusted_issuer.
func (c *Checker) unknownAuthorityCode(leaf *x509.Certificate, now time.Time) ErrorCode {
	roots, inter := c.reg.AllAnchors()
	probe := *leaf
	probe.UnhandledCriticalExtensions = nil // classification only, never acceptance
	_, err := probe.Verify(verifyOptions(roots, inter, now))
	if _, unknown := errors.AsType[x509.UnknownAuthorityError](err); err != nil && unknown {
		return CodeUntrustedIssuer
	}
	return CodeProviderMismatch
}

// algorithmsOK: RSA ≥ minRSA (floor 2048) or ECDSA P-256/P-384/P-521, and a
// SHA-256-or-stronger leaf signature.
func algorithmsOK(leaf *x509.Certificate, minRSA int) (string, bool) {
	minRSA = max(minRSA, 2048)
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSA {
			return fmt.Sprintf("RSA key %d bits; minimum %d", k.N.BitLen(), minRSA), false
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return "ECDSA curve " + k.Curve.Params().Name + " not allowed", false
		}
	default:
		return "key algorithm " + leaf.PublicKeyAlgorithm.String() + " not allowed", false
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return "", true
	}
	return "signature algorithm " + leaf.SignatureAlgorithm.String() + " not allowed", false
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oid) })
}

// purposeOK applies the profile's KU and EKU rules; a CA leaf is rejected.
func purposeOK(leaf *x509.Certificate, p profiles.Profile) (string, bool) {
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return "leaf is a CA certificate", false
	}
	if hasExtension(leaf, oidExtKeyUsage) {
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return "KeyUsage lacks digitalSignature", false
		}
	} else if !p.KeyUsage.AllowAbsent {
		return "KeyUsage extension absent", false
	}
	hasEKU := hasExtension(leaf, oidExtExtKeyUsage)
	clientAuth := slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	switch p.EKU {
	case profiles.EKURequireClientAuth:
		if !hasEKU || !clientAuth {
			return "ExtendedKeyUsage must be present and list clientAuth", false
		}
	case profiles.EKUAllowAbsent:
		if hasEKU && !clientAuth {
			return "ExtendedKeyUsage present without clientAuth", false
		}
	default:
		return "profile EKU rule unset", false
	}
	return "", true
}

// subjectMarkerMatch reports whether the leaf subject carries one of the
// documented test attribute combinations (exact values after NFC and white
// space normalisation, case-insensitive).
func subjectMarkerMatch(leaf *x509.Certificate, markers []profiles.TestMarker) bool {
	var (
		name   identity.Name
		parsed bool
	)
	for _, m := range markers {
		if len(m.Subject) == 0 {
			continue
		}
		if !parsed {
			n, err := identity.ParseName(leaf.RawSubject)
			if err != nil {
				return false // the identity step rejects an unparsable subject
			}
			name, parsed = n, true
		}
		all := true
		for _, want := range m.Subject {
			v, ok, err := name.Field(want.OID, identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP, identity.KindTeletex})
			if err != nil || !ok || !strings.EqualFold(identity.NormalizeName(v), identity.NormalizeName(want.Value)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// revocationCode maps a final revocation status; bad is false only for good.
func revocationCode(s revocation.Status) (ErrorCode, bool) {
	switch s {
	case revocation.StatusGood:
		return "", false
	case revocation.StatusRevoked:
		return CodeRevoked, true
	case revocation.StatusUnknown:
		return CodeRevocationUnknown, true
	}
	return CodeRevocationUnavailable, true // unavailable, stale, invalid_evidence, unsupported_method
}
