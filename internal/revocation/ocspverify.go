package revocation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // ResponderID byKey is defined with SHA-1
	"crypto/x509"
	"fmt"
	"slices"
	"time"
)

// OCSPInput is everything VerifyOCSP needs. Issuer is chain[i+1] of the
// verified chain, never a client-supplied certificate.
type OCSPInput struct {
	Response *Response
	Want     CertID            // the CertID that was requested
	Issuer   *x509.Certificate // verified issuer of the checked certificate
	Nonce    []byte            // extnValue sent; nil when no nonce was sent
	Now      time.Time
	MaxAge   time.Duration // bound when nextUpdate is absent
}

// OCSPEvidence is an accepted response's content.
type OCSPEvidence struct {
	Single           SingleResponse
	ProducedAt       time.Time
	Signer           *x509.Certificate
	ResponderSubject string
	NonceEchoed      bool
}

// VerifyOCSP applies the acceptance checks in order: response status,
// critical extensions, signer authorization and ResponderID binding,
// signature, CertID match, nonce, freshness. It returns StatusGood,
// StatusRevoked or StatusUnknown only for an accepted response; otherwise
// StatusUnavailable, StatusInvalidEvidence or StatusStale with a detail.
func VerifyOCSP(in OCSPInput) (OCSPEvidence, Status, string) {
	r := in.Response
	ev := OCSPEvidence{ProducedAt: r.ProducedAt}
	if r.Status != ResponseSuccessful {
		return ev, StatusUnavailable, fmt.Sprintf("responseStatus %d", r.Status)
	}
	for _, e := range r.Extensions {
		if e.Critical && !e.ID.Equal(oidOCSPNonce) {
			return ev, StatusInvalidEvidence, "unhandled critical response extension " + e.ID.String()
		}
	}
	if r.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return ev, StatusInvalidEvidence, "unsupported signature algorithm"
	}

	// Signer: the issuer itself, or a delegated responder directly issued by
	// the issuer. Only certificates identified by the ResponderID are tried,
	// so the certificate that verifies the signature is the one the
	// ResponderID names.
	signer, detail := authorizedSigner(in)
	if signer == nil {
		return ev, StatusInvalidEvidence, detail
	}
	ev.Signer, ev.ResponderSubject = signer, signer.Subject.String()

	var match *SingleResponse
	for i := range r.Responses {
		if r.Responses[i].CertID.Equal(in.Want) {
			if match != nil {
				return ev, StatusInvalidEvidence, "more than one SingleResponse matches the CertID"
			}
			match = &r.Responses[i]
		}
	}
	if match == nil {
		return ev, StatusInvalidEvidence, "no SingleResponse matches the requested CertID"
	}
	for _, e := range match.Extensions {
		if e.Critical {
			return ev, StatusInvalidEvidence, "unhandled critical singleExtension " + e.ID.String()
		}
	}
	ev.Single = *match

	if in.Nonce != nil {
		var got []byte
		for _, e := range r.Extensions {
			if e.ID.Equal(oidOCSPNonce) {
				got = e.Value
			}
		}
		if got == nil {
			return ev, StatusInvalidEvidence, "nonce sent but not echoed"
		}
		if !bytes.Equal(got, in.Nonce) {
			return ev, StatusInvalidEvidence, "nonce mismatch"
		}
		ev.NonceEchoed = true
	}

	if match.ThisUpdate.After(in.Now.Add(ClockSkew)) {
		return ev, StatusStale, "thisUpdate in the future"
	}
	if !match.NextUpdate.IsZero() {
		if match.NextUpdate.Before(in.Now) || match.NextUpdate.Before(match.ThisUpdate) {
			return ev, StatusStale, "nextUpdate in the past"
		}
	} else if match.ThisUpdate.Before(in.Now.Add(-in.MaxAge)) {
		return ev, StatusStale, "no nextUpdate and thisUpdate older than the maximum age"
	}

	switch match.Status {
	case CertGood:
		return ev, StatusGood, "good"
	case CertRevoked:
		return ev, StatusRevoked, fmt.Sprintf("revoked (reason %d)", match.Reason)
	case CertUnknown:
		return ev, StatusUnknown, "unknown"
	}
	return ev, StatusInvalidEvidence, "unknown certStatus"
}

// authorizedSigner returns the certificate that is identified by the
// ResponderID, authorized for the issuer, and verifies the signature.
func authorizedSigner(in OCSPInput) (*x509.Certificate, string) {
	r, issuer := in.Response, in.Issuer
	if identifiedBy(r, issuer) {
		if err := issuer.CheckSignature(r.SignatureAlgorithm, r.TBSResponseData, r.Signature); err != nil {
			return nil, "signature by the issuer does not verify"
		}
		return issuer, ""
	}
	detail := "no embedded certificate matches the ResponderID"
	for _, c := range r.Certificates {
		if !identifiedBy(r, c) {
			continue
		}
		switch {
		case !bytes.Equal(c.RawIssuer, issuer.RawSubject) || c.CheckSignatureFrom(issuer) != nil:
			detail = "responder not issued by the certificate issuer"
		case !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning):
			detail = "responder lacks id-kp-OCSPSigning"
		case in.Now.Before(c.NotBefore) || in.Now.After(c.NotAfter):
			detail = "responder certificate not valid now"
		case !onlyNoCheckUnhandled(c):
			detail = "responder has unhandled critical extensions"
		case !hasNoCheck(c):
			detail = "responder lacks id-pkix-ocsp-nocheck"
		case !strongKey(c):
			detail = "responder key too weak"
		case c.CheckSignature(r.SignatureAlgorithm, r.TBSResponseData, r.Signature) != nil:
			detail = "signature by the responder does not verify"
		default:
			return c, ""
		}
	}
	return nil, detail
}

func identifiedBy(r *Response, c *x509.Certificate) bool {
	if r.ResponderName != nil {
		return bytes.Equal(r.ResponderName, c.RawSubject)
	}
	bits, err := spkiBits(c.RawSubjectPublicKeyInfo)
	if err != nil {
		return false
	}
	h := sha1.Sum(bits) //nolint:gosec // ResponderID byKey
	return bytes.Equal(r.ResponderKeyHash, h[:])
}

func hasNoCheck(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidOCSPNoCheck) {
			return true
		}
	}
	return false
}

func onlyNoCheckUnhandled(c *x509.Certificate) bool {
	for _, oid := range c.UnhandledCriticalExtensions {
		if !oid.Equal(oidOCSPNoCheck) {
			return false
		}
	}
	return true
}

func strongKey(c *x509.Certificate) bool {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return true
	}
	return false
}
