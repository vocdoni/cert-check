package testpki

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // OCSP CertID hashing, not a signature
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"
)

var (
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// Responder is an OCSP signing identity (delegated responder or the CA itself).
type Responder struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// CertStatus is the OCSP certStatus to answer.
type CertStatus int

// OCSP certStatus values.
const (
	Good CertStatus = iota
	Revoked
	Unknown
)

// ResponderIDKind selects the ResponderID CHOICE.
type ResponderIDKind int

// ResponderID choices.
const (
	ByName ResponderIDKind = iota
	ByKey
)

// NonceMode controls the nonce extension in the response.
type NonceMode int

// Nonce modes.
const (
	NonceEcho  NonceMode = iota // echo the request nonce if one was sent
	NonceOmit                   // never include a nonce
	NonceWrong                  // include a different 32-byte nonce
)

// Request is the parsed content of an OCSP request seen by an OCSPServer.
type Request struct {
	HashAlgorithm  asn1.ObjectIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	Serial         *big.Int
	Nonce          []byte // extnValue bytes of the nonce extension; nil if absent
	Count          int    // number of Request entries in requestList
}

// OCSPSpec configures one OCSP response. Zero fields take the defaults noted.
type OCSPSpec struct {
	ResponseStatus int        // 0 successful (default); 1..6 error statuses (no responseBytes)
	Status         CertStatus // default Good
	RevokedAt      time.Time  // default ThisUpdate - 24h
	Reason         int        // CRLReason for Revoked (0 = unspecified, 6 = certificateHold)
	OmitReason     bool       // omit revocationReason
	ThisUpdate     time.Time  // default Now - 1m
	NextUpdate     time.Time  // zero: omitted
	ProducedAt     time.Time  // default ThisUpdate
	Now            time.Time  // reference for defaults; default time.Now()

	Signer        *Responder // default: the server's responder
	ResponderID   ResponderIDKind
	ResponderIDOf *x509.Certificate   // build ResponderID from this cert instead of the signer's
	Certs         []*x509.Certificate // embedded certs; nil: [Signer.Cert] unless Signer is the issuer
	NoCerts       bool                // embed no certificate

	Nonce NonceMode

	SerialOverride     *big.Int // answer for another serial
	NameHashOverride   []byte
	KeyHashOverride    []byte
	CertIDHash         crypto.Hash // default: the request's hash (SHA-1 when unknown)
	DuplicateSingle    bool        // add a second identical SingleResponse
	SingleExtensions   []pkix.Extension
	ResponseExtensions []pkix.Extension
	CorruptSignature   bool
}

// BuildOCSPResponse encodes an OCSPResponse answering req for a certificate
// issued by issuer.
func BuildOCSPResponse(t testing.TB, issuer *CA, req Request, spec OCSPSpec) []byte {
	t.Helper()
	if spec.ResponseStatus != 0 {
		return seq(derEnum(spec.ResponseStatus))
	}
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	if spec.ThisUpdate.IsZero() {
		spec.ThisUpdate = now.Add(-time.Minute)
	}
	if spec.ProducedAt.IsZero() {
		spec.ProducedAt = spec.ThisUpdate
	}
	if spec.RevokedAt.IsZero() {
		spec.RevokedAt = spec.ThisUpdate.Add(-24 * time.Hour)
	}
	signer := spec.Signer
	if signer == nil {
		t.Fatal("testpki: OCSPSpec.Signer is nil")
	}

	h := spec.CertIDHash
	if h == 0 {
		h = crypto.SHA1
		if req.HashAlgorithm.Equal(oidSHA256) {
			h = crypto.SHA256
		}
	}
	nameHash, keyHash := CertIDHashes(t, h, issuer.Cert)
	if spec.NameHashOverride != nil {
		nameHash = spec.NameHashOverride
	}
	if spec.KeyHashOverride != nil {
		keyHash = spec.KeyHashOverride
	}
	serial := req.Serial
	if spec.SerialOverride != nil {
		serial = spec.SerialOverride
	}
	hashOID := oidSHA1
	if h == crypto.SHA256 {
		hashOID = oidSHA256
	}
	certID := seq(seq(derOID(hashOID), derNull()), derOctets(nameHash), derOctets(keyHash), derInt(serial))

	var status []byte
	switch spec.Status {
	case Good:
		status = ctx(0, false)
	case Revoked:
		parts := [][]byte{derGeneralizedTime(spec.RevokedAt)}
		if !spec.OmitReason {
			parts = append(parts, ctx(0, true, derEnum(spec.Reason)))
		}
		status = ctx(1, true, parts...)
	case Unknown:
		status = ctx(2, false)
	}
	single := [][]byte{certID, status, derGeneralizedTime(spec.ThisUpdate)}
	if !spec.NextUpdate.IsZero() {
		single = append(single, ctx(0, true, derGeneralizedTime(spec.NextUpdate)))
	}
	if len(spec.SingleExtensions) > 0 {
		single = append(single, ctx(1, true, derExtensions(toExts(spec.SingleExtensions))))
	}
	singles := [][]byte{seq(single...)}
	if spec.DuplicateSingle {
		singles = append(singles, seq(single...))
	}

	idCert := signer.Cert
	if spec.ResponderIDOf != nil {
		idCert = spec.ResponderIDOf
	}
	var responderID []byte
	if spec.ResponderID == ByKey {
		responderID = ctx(2, true, derOctets(SPKIKeyHash(t, idCert)))
	} else {
		responderID = ctx(1, true, idCert.RawSubject)
	}

	var respExts []extension
	switch {
	case spec.Nonce == NonceEcho && req.Nonce != nil:
		respExts = append(respExts, extension{id: oidOCSPNonce, value: req.Nonce})
	case spec.Nonce == NonceWrong:
		respExts = append(respExts, extension{id: oidOCSPNonce, value: derOctets(make([]byte, 32))})
	}
	respExts = append(respExts, toExts(spec.ResponseExtensions)...)

	tbs := [][]byte{responderID, derGeneralizedTime(spec.ProducedAt), seq(singles...)}
	if len(respExts) > 0 {
		tbs = append(tbs, ctx(1, true, derExtensions(respExts)))
	}
	tbsDER := seq(tbs...)
	sig, algID, err := signDigest(signer.Key, tbsDER)
	if err != nil {
		t.Fatalf("testpki: sign OCSP: %v", err)
	}
	if spec.CorruptSignature {
		sig[len(sig)-1] ^= 0xff
	}
	basic := [][]byte{tbsDER, algID, derBitString(sig)}
	certs := spec.Certs
	if certs == nil && !spec.NoCerts && !signer.Cert.Equal(issuer.Cert) {
		certs = []*x509.Certificate{signer.Cert}
	}
	if len(certs) > 0 && !spec.NoCerts {
		var raw []byte
		for _, c := range certs {
			raw = append(raw, c.Raw...)
		}
		basic = append(basic, ctx(0, true, tlv(tagSequence, raw)))
	}
	return seq(derEnum(0), ctx(0, true, seq(derOID(oidOCSPBasic), derOctets(seq(basic...)))))
}

// CertIDHashes returns issuerNameHash and issuerKeyHash for issuer under h.
func CertIDHashes(t testing.TB, h crypto.Hash, issuer *x509.Certificate) (nameHash, keyHash []byte) {
	t.Helper()
	key := spkiKeyBits(t, issuer)
	switch h {
	case crypto.SHA1:
		n, k := sha1.Sum(issuer.RawSubject), sha1.Sum(key) //nolint:gosec // CertID
		return n[:], k[:]
	case crypto.SHA256:
		n, k := sha256.Sum256(issuer.RawSubject), sha256.Sum256(key)
		return n[:], k[:]
	}
	t.Fatalf("testpki: unsupported CertID hash %v", h)
	return nil, nil
}

// SPKIKeyHash is the SHA-1 of the subjectPublicKey BIT STRING value (ResponderID byKey).
func SPKIKeyHash(t testing.TB, c *x509.Certificate) []byte {
	t.Helper()
	s := sha1.Sum(spkiKeyBits(t, c)) //nolint:gosec // ResponderID byKey is defined with SHA-1
	return s[:]
}

func spkiKeyBits(t testing.TB, c *x509.Certificate) []byte {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatalf("testpki: SPKI: %v", err)
	}
	return spki.PublicKey.Bytes
}

func toExts(in []pkix.Extension) []extension {
	out := make([]extension, 0, len(in))
	for _, e := range in {
		out = append(out, extension{id: e.Id, critical: e.Critical, value: e.Value})
	}
	return out
}

// ParseOCSPRequest decodes an OCSP request (first Request entry and nonce).
func ParseOCSPRequest(der []byte) (Request, error) {
	type certID struct {
		HashAlgorithm  pkix.AlgorithmIdentifier
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		Serial         *big.Int
	}
	type request struct {
		Cert certID
		Ext  []pkix.Extension `asn1:"explicit,tag:0,optional"`
	}
	type tbsRequest struct {
		Version       int           `asn1:"explicit,tag:0,default:0,optional"`
		RequestorName asn1.RawValue `asn1:"explicit,tag:1,optional"`
		RequestList   []request
		Extensions    []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	type ocspRequest struct {
		TBS tbsRequest
	}
	var r ocspRequest
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil {
		return Request{}, err
	}
	if len(rest) > 0 || len(r.TBS.RequestList) == 0 {
		return Request{}, asn1.SyntaxError{Msg: "bad OCSP request"}
	}
	first := r.TBS.RequestList[0].Cert
	out := Request{
		HashAlgorithm:  first.HashAlgorithm.Algorithm,
		IssuerNameHash: first.IssuerNameHash,
		IssuerKeyHash:  first.IssuerKeyHash,
		Serial:         first.Serial,
		Count:          len(r.TBS.RequestList),
	}
	for _, e := range r.TBS.Extensions {
		if e.Id.Equal(oidOCSPNonce) {
			out.Nonce = e.Value
		}
	}
	return out, nil
}

// OCSPServer is an http.Handler answering POSTed OCSP requests for one issuer.
// Its answer is chosen per request by the Answer function (default: Good,
// signed by the server's responder, nextUpdate +1h).
type OCSPServer struct {
	Issuer    *CA
	Responder *Responder

	mu       sync.Mutex
	answer   func(Request) OCSPSpec
	raw      func(Request) []byte
	requests []Request
}

// NewOCSPServer returns a server for issuer signed by responder.
func NewOCSPServer(issuer *CA, responder *Responder) *OCSPServer {
	return &OCSPServer{Issuer: issuer, Responder: responder}
}

// SetAnswer sets the per-request response spec.
func (s *OCSPServer) SetAnswer(f func(Request) OCSPSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer, s.raw = f, nil
}

// SetRawAnswer makes the server reply with arbitrary bytes (malformed/oversized tests).
func (s *OCSPServer) SetRawAnswer(f func(Request) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = f
}

// Requests returns the requests received so far.
func (s *OCSPServer) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Handler returns the HTTP handler; t reports encoding failures.
func (s *OCSPServer) Handler(t testing.TB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		req, err := ParseOCSPRequest(body)
		if err != nil {
			w.Header().Set("Content-Type", "application/ocsp-response")
			_, _ = w.Write(seq(derEnum(1))) // malformedRequest
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, req)
		answer, raw := s.answer, s.raw
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/ocsp-response")
		if raw != nil {
			_, _ = w.Write(raw(req))
			return
		}
		spec := OCSPSpec{NextUpdate: time.Now().Add(time.Hour)}
		if answer != nil {
			spec = answer(req)
		}
		if spec.Signer == nil {
			spec.Signer = s.Responder
		}
		_, _ = w.Write(BuildOCSPResponse(t, s.Issuer, req, spec))
	})
}
