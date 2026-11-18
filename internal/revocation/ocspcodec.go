package revocation

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // CertID and ResponderID byKey hashing, not signatures
	"crypto/sha256"
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
	oidOCSPBasic   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidHashSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHashSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// signatureAlgorithms maps accepted OCSP signature OIDs to x509 algorithms.
// SHA-1 and RSA-PSS are not accepted (no observed responder uses them).
// Parameters must be absent or NULL where nullOK (Camerfirma's live responder
// encodes ecdsa-with-SHA384 with NULL parameters).
var signatureAlgorithms = []struct {
	oid    asn1.ObjectIdentifier
	alg    x509.SignatureAlgorithm
	nullOK bool
}{
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, x509.SHA256WithRSA, true},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, x509.SHA384WithRSA, true},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, x509.SHA512WithRSA, true},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, x509.ECDSAWithSHA256, true},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, x509.ECDSAWithSHA384, true},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, x509.ECDSAWithSHA512, true},
	{asn1.ObjectIdentifier{1, 3, 101, 112}, x509.PureEd25519, false},
}

// Codec limits.
const (
	maxSingleResponses = 32
	maxEmbeddedCerts   = 8
	maxExtensions      = 16 // per list; real responses carry 0-2
	NonceLength        = 32
)

// CertID identifies the certificate an OCSP request or SingleResponse refers to.
type CertID struct {
	HashAlgorithm  asn1.ObjectIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// NewCertID builds the CertID for cert from the verified issuer. h is
// crypto.SHA1 (what every observed responder uses) or crypto.SHA256.
func NewCertID(h crypto.Hash, cert, issuer *x509.Certificate) (CertID, error) {
	if cert.SerialNumber == nil {
		return CertID{}, errors.New("ocsp: certificate without serial number")
	}
	keyBits, err := spkiBits(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return CertID{}, err
	}
	id := CertID{SerialNumber: new(big.Int).Set(cert.SerialNumber)}
	switch h {
	case crypto.SHA1:
		n, k := sha1.Sum(issuer.RawSubject), sha1.Sum(keyBits) //nolint:gosec // CertID
		id.HashAlgorithm, id.IssuerNameHash, id.IssuerKeyHash = oidHashSHA1, n[:], k[:]
	case crypto.SHA256:
		n, k := sha256.Sum256(issuer.RawSubject), sha256.Sum256(keyBits)
		id.HashAlgorithm, id.IssuerNameHash, id.IssuerKeyHash = oidHashSHA256, n[:], k[:]
	default:
		return CertID{}, fmt.Errorf("ocsp: unsupported CertID hash %v", h)
	}
	return id, nil
}

// Equal compares two CertIDs field by field.
func (c CertID) Equal(o CertID) bool {
	return c.HashAlgorithm.Equal(o.HashAlgorithm) &&
		string(c.IssuerNameHash) == string(o.IssuerNameHash) &&
		string(c.IssuerKeyHash) == string(o.IssuerKeyHash) &&
		c.SerialNumber != nil && o.SerialNumber != nil && c.SerialNumber.Cmp(o.SerialNumber) == 0
}

// spkiBits returns the subjectPublicKey BIT STRING contents of a DER SPKI.
func spkiBits(spki []byte) ([]byte, error) {
	s := cryptobyte.String(spki)
	var inner, alg cryptobyte.String
	var bits asn1.BitString
	if !s.ReadASN1(&inner, cbasn1.SEQUENCE) || !s.Empty() ||
		!inner.ReadASN1(&alg, cbasn1.SEQUENCE) || !inner.ReadASN1BitString(&bits) || !inner.Empty() ||
		bits.BitLength%8 != 0 {
		return nil, errors.New("ocsp: malformed SubjectPublicKeyInfo")
	}
	return bits.Bytes, nil
}

// MarshalRequest encodes an unsigned OCSPRequest for one CertID. When nonce is
// non-nil it adds the nonce extension whose extnValue is OCTET STRING(nonce)
// (RFC 8954) and returns that extnValue for the echo comparison.
func MarshalRequest(id CertID, nonce []byte) (der, nonceExtValue []byte, err error) {
	if id.SerialNumber == nil || len(id.HashAlgorithm) == 0 || id.IssuerNameHash == nil || id.IssuerKeyHash == nil {
		return nil, nil, errors.New("ocsp: incomplete CertID")
	}
	var b cryptobyte.Builder
	if nonce != nil {
		var nb cryptobyte.Builder
		nb.AddASN1OctetString(nonce)
		nonceExtValue, err = nb.Bytes()
		if err != nil {
			return nil, nil, err
		}
	}
	b.AddASN1(cbasn1.SEQUENCE, func(req *cryptobyte.Builder) { // OCSPRequest
		req.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) { // TBSRequest
			tbs.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) { // requestList
				list.AddASN1(cbasn1.SEQUENCE, func(r *cryptobyte.Builder) { // Request
					addCertID(r, id)
				})
			})
			if nonceExtValue != nil {
				tbs.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(e *cryptobyte.Builder) {
					e.AddASN1(cbasn1.SEQUENCE, func(exts *cryptobyte.Builder) {
						exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
							ext.AddASN1ObjectIdentifier(oidOCSPNonce)
							ext.AddASN1OctetString(nonceExtValue)
						})
					})
				})
			}
		})
	})
	der, err = b.Bytes()
	return der, nonceExtValue, err
}

func addCertID(b *cryptobyte.Builder, id CertID) {
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(id.HashAlgorithm)
			alg.AddASN1NULL()
		})
		c.AddASN1OctetString(id.IssuerNameHash)
		c.AddASN1OctetString(id.IssuerKeyHash)
		c.AddASN1BigInt(id.SerialNumber)
	})
}

// ResponseStatus is OCSPResponseStatus.
type ResponseStatus int

// Response statuses (RFC 6960 §4.2.1).
const (
	ResponseSuccessful       ResponseStatus = 0
	ResponseMalformedRequest ResponseStatus = 1
	ResponseInternalError    ResponseStatus = 2
	ResponseTryLater         ResponseStatus = 3
	ResponseSigRequired      ResponseStatus = 5
	ResponseUnauthorized     ResponseStatus = 6
)

// CertStatus is the certStatus CHOICE of a SingleResponse.
type CertStatus int

// Cert statuses.
const (
	CertGood CertStatus = iota + 1
	CertRevoked
	CertUnknown
)

// Extension is a parsed X.509 extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// SingleResponse is one entry of ResponseData.responses.
type SingleResponse struct {
	CertID     CertID
	Status     CertStatus
	RevokedAt  time.Time
	Reason     int // -1 when absent
	ThisUpdate time.Time
	NextUpdate time.Time // zero when absent
	Extensions []Extension
}

// Response is a parsed OCSPResponse. For a non-successful ResponseStatus only
// Status is set.
type Response struct {
	Status             ResponseStatus
	TBSResponseData    []byte // signed bytes (full DER of ResponseData)
	ResponderName      []byte // byName: full DER of the Name
	ResponderKeyHash   []byte // byKey: SHA-1 of the responder's subjectPublicKey
	ProducedAt         time.Time
	Responses          []SingleResponse
	Extensions         []Extension
	SignatureAlgorithm x509.SignatureAlgorithm // UnknownSignatureAlgorithm when not accepted
	Signature          []byte
	Certificates       []*x509.Certificate
}

var errMalformed = errors.New("ocsp: malformed response")

// ParseResponse strictly parses a DER OCSPResponse.
func ParseResponse(der []byte) (*Response, error) {
	in := cryptobyte.String(der)
	var top cryptobyte.String
	if !in.ReadASN1(&top, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errMalformed
	}
	var status int
	if !top.ReadASN1Enum(&status) {
		return nil, errMalformed
	}
	resp := &Response{Status: ResponseStatus(status)}
	if resp.Status != ResponseSuccessful {
		if !top.Empty() {
			return nil, errMalformed
		}
		switch resp.Status {
		case ResponseMalformedRequest, ResponseInternalError, ResponseTryLater, ResponseSigRequired, ResponseUnauthorized:
			return resp, nil
		}
		return nil, errMalformed
	}
	var rbExplicit, rb, rbType cryptobyte.String
	if !top.ReadASN1(&rbExplicit, cbasn1.Tag(0).Constructed().ContextSpecific()) || !top.Empty() ||
		!rbExplicit.ReadASN1(&rb, cbasn1.SEQUENCE) || !rbExplicit.Empty() {
		return nil, errMalformed
	}
	var respType asn1.ObjectIdentifier
	if !rb.ReadASN1ObjectIdentifier(&respType) || !rb.ReadASN1(&rbType, cbasn1.OCTET_STRING) || !rb.Empty() {
		return nil, errMalformed
	}
	if !respType.Equal(oidOCSPBasic) {
		return nil, fmt.Errorf("ocsp: unsupported response type %s", respType)
	}
	var basic, tbsRaw, tbs, sigAlg cryptobyte.String
	if !rbType.ReadASN1(&basic, cbasn1.SEQUENCE) || !rbType.Empty() {
		return nil, errMalformed
	}
	if !basic.ReadASN1Element(&tbsRaw, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	resp.TBSResponseData = tbsRaw
	if elem := tbsRaw; !elem.ReadASN1(&tbs, cbasn1.SEQUENCE) || !elem.Empty() {
		return nil, errMalformed
	}
	if !basic.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	resp.SignatureAlgorithm = parseSignatureAlgorithm(sigAlg)
	var sig asn1.BitString
	if !basic.ReadASN1BitString(&sig) || sig.BitLength%8 != 0 {
		return nil, errMalformed
	}
	resp.Signature = sig.Bytes
	var certsExplicit cryptobyte.String
	var hasCerts bool
	if !basic.ReadOptionalASN1(&certsExplicit, &hasCerts, cbasn1.Tag(0).Constructed().ContextSpecific()) || !basic.Empty() {
		return nil, errMalformed
	}
	if hasCerts {
		var certs cryptobyte.String
		if !certsExplicit.ReadASN1(&certs, cbasn1.SEQUENCE) || !certsExplicit.Empty() {
			return nil, errMalformed
		}
		for !certs.Empty() {
			var c cryptobyte.String
			if !certs.ReadASN1Element(&c, cbasn1.SEQUENCE) || len(resp.Certificates) == maxEmbeddedCerts {
				return nil, errMalformed
			}
			cert, err := x509.ParseCertificate(c)
			if err != nil {
				return nil, fmt.Errorf("ocsp: embedded certificate: %w", err)
			}
			resp.Certificates = append(resp.Certificates, cert)
		}
	}
	if err := parseResponseData(tbs, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func parseSignatureAlgorithm(s cryptobyte.String) x509.SignatureAlgorithm {
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1ObjectIdentifier(&oid) {
		return x509.UnknownSignatureAlgorithm
	}
	for _, a := range signatureAlgorithms {
		if !oid.Equal(a.oid) {
			continue
		}
		switch {
		case s.Empty():
			return a.alg
		case a.nullOK:
			var null cryptobyte.String
			if s.ReadASN1(&null, cbasn1.NULL) && len(null) == 0 && s.Empty() {
				return a.alg
			}
		}
		return x509.UnknownSignatureAlgorithm
	}
	return x509.UnknownSignatureAlgorithm
}

func parseResponseData(s cryptobyte.String, resp *Response) error {
	var version cryptobyte.String
	var hasVersion bool
	if !s.ReadOptionalASN1(&version, &hasVersion, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return errMalformed
	}
	if hasVersion {
		var v int
		if !version.ReadASN1Integer(&v) || !version.Empty() || v != 0 {
			return errors.New("ocsp: unsupported ResponseData version")
		}
	}
	var rid cryptobyte.String
	switch {
	case s.PeekASN1Tag(cbasn1.Tag(1).Constructed().ContextSpecific()):
		var name cryptobyte.String
		if !s.ReadASN1(&rid, cbasn1.Tag(1).Constructed().ContextSpecific()) ||
			!rid.ReadASN1Element(&name, cbasn1.SEQUENCE) || !rid.Empty() {
			return errMalformed
		}
		resp.ResponderName = name
	case s.PeekASN1Tag(cbasn1.Tag(2).Constructed().ContextSpecific()):
		var key cryptobyte.String
		if !s.ReadASN1(&rid, cbasn1.Tag(2).Constructed().ContextSpecific()) ||
			!rid.ReadASN1(&key, cbasn1.OCTET_STRING) || !rid.Empty() || len(key) != sha1.Size {
			return errMalformed
		}
		resp.ResponderKeyHash = key
	default:
		return errMalformed
	}
	if !readGeneralizedTime(&s, &resp.ProducedAt) {
		return errMalformed
	}
	var singles cryptobyte.String
	if !s.ReadASN1(&singles, cbasn1.SEQUENCE) {
		return errMalformed
	}
	for !singles.Empty() {
		if len(resp.Responses) == maxSingleResponses {
			return errMalformed
		}
		var single cryptobyte.String
		if !singles.ReadASN1(&single, cbasn1.SEQUENCE) {
			return errMalformed
		}
		sr, err := parseSingleResponse(single)
		if err != nil {
			return err
		}
		resp.Responses = append(resp.Responses, sr)
	}
	if len(resp.Responses) == 0 {
		return errMalformed
	}
	exts, err := readExplicitExtensions(&s, 1)
	if err != nil {
		return err
	}
	resp.Extensions = exts
	if !s.Empty() {
		return errMalformed
	}
	return nil
}

func parseSingleResponse(s cryptobyte.String) (SingleResponse, error) {
	sr := SingleResponse{Reason: -1}
	var cid, alg cryptobyte.String
	if !s.ReadASN1(&cid, cbasn1.SEQUENCE) || !cid.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&sr.CertID.HashAlgorithm) {
		return sr, errMalformed
	}
	if !alg.Empty() { // optional NULL parameters
		var null cryptobyte.String
		if !alg.ReadASN1(&null, cbasn1.NULL) || len(null) != 0 || !alg.Empty() {
			return sr, errMalformed
		}
	}
	var nameHash, keyHash cryptobyte.String
	sr.CertID.SerialNumber = new(big.Int)
	if !cid.ReadASN1(&nameHash, cbasn1.OCTET_STRING) || !cid.ReadASN1(&keyHash, cbasn1.OCTET_STRING) ||
		!cid.ReadASN1Integer(sr.CertID.SerialNumber) || !cid.Empty() {
		return sr, errMalformed
	}
	sr.CertID.IssuerNameHash, sr.CertID.IssuerKeyHash = nameHash, keyHash
	var st cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&st, &tag) {
		return sr, errMalformed
	}
	switch tag {
	case cbasn1.Tag(0).ContextSpecific():
		if len(st) != 0 {
			return sr, errMalformed
		}
		sr.Status = CertGood
	case cbasn1.Tag(1).Constructed().ContextSpecific():
		sr.Status = CertRevoked
		if !readGeneralizedTime(&st, &sr.RevokedAt) {
			return sr, errMalformed
		}
		var reason cryptobyte.String
		var hasReason bool
		if !st.ReadOptionalASN1(&reason, &hasReason, cbasn1.Tag(0).Constructed().ContextSpecific()) || !st.Empty() {
			return sr, errMalformed
		}
		if hasReason {
			if !reason.ReadASN1Enum(&sr.Reason) || !reason.Empty() {
				return sr, errMalformed
			}
		}
	case cbasn1.Tag(2).ContextSpecific():
		if len(st) != 0 {
			return sr, errMalformed
		}
		sr.Status = CertUnknown
	default:
		return sr, errMalformed
	}
	if !readGeneralizedTime(&s, &sr.ThisUpdate) {
		return sr, errMalformed
	}
	var next cryptobyte.String
	var hasNext bool
	if !s.ReadOptionalASN1(&next, &hasNext, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return sr, errMalformed
	}
	if hasNext {
		if !readGeneralizedTime(&next, &sr.NextUpdate) || !next.Empty() {
			return sr, errMalformed
		}
	}
	exts, err := readExplicitExtensions(&s, 1)
	if err != nil {
		return sr, err
	}
	sr.Extensions = exts
	if !s.Empty() {
		return sr, errMalformed
	}
	return sr, nil
}

// readGeneralizedTime reads a GeneralizedTime in its DER form
// YYYYMMDDHHMMSSZ (X.690 §11.7, RFC 5280 §4.1.2.5.2): no offset, no
// fractional seconds, no year 0000. The zero time is rejected too: it is the
// "absent" value of NextUpdate and RevokedAt.
func readGeneralizedTime(s *cryptobyte.String, out *time.Time) bool {
	const layout = "20060102150405Z"
	var raw cryptobyte.String
	if !s.ReadASN1(&raw, cbasn1.GeneralizedTime) || len(raw) != len(layout) {
		return false
	}
	t, err := time.Parse(layout, string(raw))
	if err != nil || t.Format(layout) != string(raw) || t.Year() < 1 || t.IsZero() {
		return false
	}
	*out = t
	return true
}

// readExplicitExtensions reads an optional [n] EXPLICIT Extensions.
func readExplicitExtensions(s *cryptobyte.String, n uint8) ([]Extension, error) {
	var wrapper cryptobyte.String
	var present bool
	if !s.ReadOptionalASN1(&wrapper, &present, cbasn1.Tag(n).Constructed().ContextSpecific()) {
		return nil, errMalformed
	}
	if !present {
		return nil, nil
	}
	var seq cryptobyte.String
	if !wrapper.ReadASN1(&seq, cbasn1.SEQUENCE) || !wrapper.Empty() {
		return nil, errMalformed
	}
	var out []Extension
	for !seq.Empty() {
		if len(out) == maxExtensions {
			return nil, errMalformed
		}
		var ext cryptobyte.String
		var e Extension
		if !seq.ReadASN1(&ext, cbasn1.SEQUENCE) || !ext.ReadASN1ObjectIdentifier(&e.ID) {
			return nil, errMalformed
		}
		// critical BOOLEAN DEFAULT FALSE is untagged. cryptobyte's
		// ReadOptionalASN1Boolean expects an explicitly tagged BOOLEAN, so
		// peek for the universal tag and read it directly.
		if ext.PeekASN1Tag(cbasn1.BOOLEAN) && !ext.ReadASN1Boolean(&e.Critical) {
			return nil, errMalformed
		}
		var v cryptobyte.String
		if !ext.ReadASN1(&v, cbasn1.OCTET_STRING) || !ext.Empty() {
			return nil, errMalformed
		}
		e.Value = v
		for _, prev := range out {
			if prev.ID.Equal(e.ID) {
				return nil, errors.New("ocsp: duplicate extension")
			}
		}
		out = append(out, e)
	}
	return out, nil
}
