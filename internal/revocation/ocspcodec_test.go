package revocation

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// ocspTNow is the fixed clock of the synthetic OCSP tests.
var ocspTNow = time.Date(2026, time.October, 30, 12, 0, 0, 0, time.UTC)

// ocspTDir holds the real OCSP samples and their SOURCES.md.
const ocspTDir = "testdata/ocsp"

// Signature AlgorithmIdentifier OIDs used to build parser inputs.
var (
	ocspTOIDSHA256RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	ocspTOIDSHA512RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	ocspTOIDSHA1RSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	ocspTOIDRSAPSS      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	ocspTOIDECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	ocspTOIDECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	ocspTOIDEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
	ocspTOIDExtA        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	ocspTOIDExtB        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}
	ocspTOIDExtC        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3}
	ocspTOIDKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	ocspTDERNull        = []byte{0x05, 0x00}
)

// ocspTPKI is a synthetic issuer, delegated responder and leaf with the
// SHA-1 CertID of the leaf and the testpki requests that ask for it.
type ocspTPKI struct {
	now      time.Time
	ca       *testpki.CA
	resp     *testpki.Responder
	leaf     *testpki.Leaf
	want     CertID          // SHA-1 CertID of leaf, built from testpki hashes
	req      testpki.Request // request without a nonce
	nonceReq testpki.Request // the same request carrying nonceExt
	nonceExt []byte          // extnValue of the nonce: OCTET STRING(32 bytes)
}

func ocspTNewPKI(tb testing.TB) *ocspTPKI {
	tb.Helper()
	p := &ocspTPKI{now: ocspTNow}
	p.ca = testpki.NewRoot(tb, "ocspT CA", testpki.CertSpec{Now: p.now})
	p.resp = p.ca.OCSPResponder(tb, testpki.CertSpec{Now: p.now})
	p.leaf = p.ca.Leaf(tb, testpki.CertSpec{
		Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "ocspT leaf")},
		Now:     p.now,
	})
	nameHash, keyHash := testpki.CertIDHashes(tb, crypto.SHA1, p.ca.Cert)
	p.want = CertID{
		HashAlgorithm:  asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		SerialNumber:   new(big.Int).Set(p.leaf.Cert.SerialNumber),
	}
	p.req = testpki.Request{
		HashAlgorithm:  p.want.HashAlgorithm,
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		Serial:         p.leaf.Cert.SerialNumber,
		Count:          1,
	}
	nonce := bytes.Repeat([]byte{0x5a}, NonceLength)
	p.nonceExt = ocspTDER(tb, func(b *cryptobyte.Builder) { b.AddASN1OctetString(nonce) })
	p.nonceReq = p.req
	p.nonceReq.Nonce = p.nonceExt
	return p
}

// base is the default answer: good, signed by the delegated responder,
// thisUpdate now-1m, nextUpdate now+1h.
func (p *ocspTPKI) base() testpki.OCSPSpec {
	return testpki.OCSPSpec{
		Now:        p.now,
		Signer:     p.resp,
		ThisUpdate: p.now.Add(-time.Minute),
		NextUpdate: p.now.Add(time.Hour),
	}
}

// build returns the DER response to req after edit (nil: base) changes the spec.
func (p *ocspTPKI) build(tb testing.TB, req testpki.Request, edit func(*testpki.OCSPSpec)) []byte {
	tb.Helper()
	spec := p.base()
	if edit != nil {
		edit(&spec)
	}
	return testpki.BuildOCSPResponse(tb, p.ca, req, spec)
}

// ocspTDER runs f on a fresh cryptobyte.Builder and returns its bytes.
func ocspTDER(tb testing.TB, f func(*cryptobyte.Builder)) []byte {
	tb.Helper()
	var b cryptobyte.Builder
	f(&b)
	out, err := b.Bytes()
	if err != nil {
		tb.Fatalf("build DER: %v", err)
	}
	return out
}

// ocspTAlgID encodes an AlgorithmIdentifier with raw parameters (nil: absent).
func ocspTAlgID(tb testing.TB, oid asn1.ObjectIdentifier, params []byte) []byte {
	tb.Helper()
	return ocspTDER(tb, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(oid)
			alg.AddBytes(params)
		})
	})
}

// ocspTParts is a successful OCSPResponse split into raw DER elements so a
// test can replace one element and re-encode the rest unchanged.
type ocspTParts struct {
	respType     asn1.ObjectIdentifier
	version      []byte   // full [0] element; nil when absent
	responderID  []byte   // full [1] or [2] element
	producedAt   []byte   // full GeneralizedTime element
	singles      [][]byte // full SingleResponse elements
	respExts     []byte   // full [1] element; nil when absent
	tbsTrailer   []byte   // extra bytes at the end of ResponseData
	sigAlg       []byte   // full AlgorithmIdentifier element
	sig          []byte   // full BIT STRING element
	hasCerts     bool
	certs        [][]byte // full Certificate elements
	basicTrailer []byte   // extra bytes after BasicOCSPResponse in the OCTET STRING
	topTrailer   []byte   // extra bytes after the OCSPResponse
}

// ocspTSplit splits a successful testpki response. It is test scaffolding and
// independent of ParseResponse.
func ocspTSplit(tb testing.TB, der []byte) *ocspTParts {
	tb.Helper()
	fail := func(what string) { tb.Fatalf("ocspTSplit: cannot read %s", what) }
	var p ocspTParts
	in := cryptobyte.String(der)
	var top, wrap, rb, octets, basic, tbs, list, certsWrap, certs cryptobyte.String
	var status int
	if !in.ReadASN1(&top, cbasn1.SEQUENCE) || !top.ReadASN1Enum(&status) ||
		!top.ReadASN1(&wrap, cbasn1.Tag(0).Constructed().ContextSpecific()) ||
		!wrap.ReadASN1(&rb, cbasn1.SEQUENCE) || !rb.ReadASN1ObjectIdentifier(&p.respType) ||
		!rb.ReadASN1(&octets, cbasn1.OCTET_STRING) || !octets.ReadASN1(&basic, cbasn1.SEQUENCE) ||
		!basic.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		fail("response envelope")
	}
	var el cryptobyte.String
	var tag cbasn1.Tag
	if tbs.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()) {
		if !tbs.ReadAnyASN1Element(&el, &tag) {
			fail("version")
		}
		p.version = el
	}
	if !tbs.ReadAnyASN1Element(&el, &tag) {
		fail("responderID")
	}
	p.responderID = el
	if !tbs.ReadAnyASN1Element(&el, &tag) {
		fail("producedAt")
	}
	p.producedAt = el
	if !tbs.ReadASN1(&list, cbasn1.SEQUENCE) {
		fail("responses")
	}
	for !list.Empty() {
		if !list.ReadAnyASN1Element(&el, &tag) {
			fail("SingleResponse")
		}
		p.singles = append(p.singles, el)
	}
	if !tbs.Empty() {
		if !tbs.ReadAnyASN1Element(&el, &tag) || !tbs.Empty() {
			fail("responseExtensions")
		}
		p.respExts = el
	}
	if !basic.ReadAnyASN1Element(&el, &tag) {
		fail("signatureAlgorithm")
	}
	p.sigAlg = el
	if !basic.ReadAnyASN1Element(&el, &tag) {
		fail("signature")
	}
	p.sig = el
	if !basic.ReadOptionalASN1(&certsWrap, &p.hasCerts, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		fail("certs")
	}
	if p.hasCerts {
		if !certsWrap.ReadASN1(&certs, cbasn1.SEQUENCE) {
			fail("certs sequence")
		}
		for !certs.Empty() {
			if !certs.ReadAnyASN1Element(&el, &tag) {
				fail("certificate")
			}
			p.certs = append(p.certs, el)
		}
	}
	return &p
}

// encode reassembles the parts into a successful OCSPResponse.
func (p *ocspTParts) encode(tb testing.TB) []byte {
	tb.Helper()
	out := ocspTDER(tb, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(top *cryptobyte.Builder) {
			top.AddASN1Enum(0)
			top.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(wrap *cryptobyte.Builder) {
				wrap.AddASN1(cbasn1.SEQUENCE, func(rb *cryptobyte.Builder) {
					rb.AddASN1ObjectIdentifier(p.respType)
					rb.AddASN1(cbasn1.OCTET_STRING, func(octets *cryptobyte.Builder) {
						octets.AddASN1(cbasn1.SEQUENCE, func(basic *cryptobyte.Builder) {
							basic.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) {
								tbs.AddBytes(p.version)
								tbs.AddBytes(p.responderID)
								tbs.AddBytes(p.producedAt)
								tbs.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) {
									for _, s := range p.singles {
										list.AddBytes(s)
									}
								})
								tbs.AddBytes(p.respExts)
								tbs.AddBytes(p.tbsTrailer)
							})
							basic.AddBytes(p.sigAlg)
							basic.AddBytes(p.sig)
							if p.hasCerts {
								basic.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(w *cryptobyte.Builder) {
									w.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) {
										for _, c := range p.certs {
											list.AddBytes(c)
										}
									})
								})
							}
						})
						octets.AddBytes(p.basicTrailer)
					})
				})
			})
		})
	})
	return append(out, p.topTrailer...)
}

// ocspTMutate builds the base response, splits it, applies edit and re-encodes.
func ocspTMutate(edit func(tb testing.TB, p *ocspTPKI, parts *ocspTParts)) func(testing.TB, *ocspTPKI) []byte {
	return func(tb testing.TB, p *ocspTPKI) []byte {
		tb.Helper()
		parts := ocspTSplit(tb, p.build(tb, p.req, nil))
		edit(tb, p, parts)
		return parts.encode(tb)
	}
}

// ocspTGenTime encodes a GeneralizedTime element with the raw content s.
func ocspTGenTime(tb testing.TB, s string) []byte {
	tb.Helper()
	return ocspTDER(tb, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.GeneralizedTime, func(c *cryptobyte.Builder) { c.AddBytes([]byte(s)) })
	})
}

// ocspTCtx encodes a constructed context-specific [n] element around inner.
func ocspTCtx(tb testing.TB, n uint8, inner ...[]byte) []byte {
	tb.Helper()
	return ocspTDER(tb, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(n).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
			for _, e := range inner {
				c.AddBytes(e)
			}
		})
	})
}

// ocspTExtensions encodes Extensions with one non-critical NULL-valued
// extension per OID (no duplicate check).
func ocspTExtensions(tb testing.TB, oids ...asn1.ObjectIdentifier) []byte {
	tb.Helper()
	return ocspTDER(tb, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(exts *cryptobyte.Builder) {
			for _, oid := range oids {
				exts.AddASN1(cbasn1.SEQUENCE, func(e *cryptobyte.Builder) {
					e.AddASN1ObjectIdentifier(oid)
					e.AddASN1OctetString(ocspTDERNull)
				})
			}
		})
	})
}

// ocspTEditSingle builds the base response and rewrites the elements of its
// SingleResponse: certID, certStatus, thisUpdate and [0] nextUpdate.
func ocspTEditSingle(edit func(tb testing.TB, elems [][]byte) [][]byte) func(testing.TB, *ocspTPKI) []byte {
	return ocspTMutate(func(tb testing.TB, _ *ocspTPKI, parts *ocspTParts) {
		in := cryptobyte.String(parts.singles[0])
		var single cryptobyte.String
		if !in.ReadASN1(&single, cbasn1.SEQUENCE) {
			tb.Fatal("ocspTEditSingle: cannot read SingleResponse")
		}
		var elems [][]byte
		for !single.Empty() {
			var el cryptobyte.String
			var tag cbasn1.Tag
			if !single.ReadAnyASN1Element(&el, &tag) {
				tb.Fatal("ocspTEditSingle: cannot read element")
			}
			elems = append(elems, el)
		}
		parts.singles[0] = ocspTDER(tb, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
				for _, e := range edit(tb, elems) {
					c.AddBytes(e)
				}
			})
		})
	})
}

// ocspTSpec builds the response to the plain request with edit applied.
func ocspTSpec(edit func(p *ocspTPKI, s *testpki.OCSPSpec)) func(testing.TB, *ocspTPKI) []byte {
	return func(tb testing.TB, p *ocspTPKI) []byte {
		tb.Helper()
		return p.build(tb, p.req, func(s *testpki.OCSPSpec) {
			if edit != nil {
				edit(p, s)
			}
		})
	}
}

// ocspTWantErr is the expected ParseResponse error class.
type ocspTWantErr int

const (
	ocspTNoErr     ocspTWantErr = iota + 1 // success
	ocspTMalformed                         // errMalformed
	ocspTAnyErr                            // any non-nil error
)

type ocspTParseCase struct {
	name    string
	der     func(testing.TB, *ocspTPKI) []byte
	wantErr ocspTWantErr
	check   func(t *testing.T, p *ocspTPKI, r *Response)
}

// ocspTCheckBase checks the fields every base-derived good response carries.
func ocspTCheckBase(t *testing.T, p *ocspTPKI, r *Response) {
	t.Helper()
	if r.Status != ResponseSuccessful {
		t.Fatalf("Status = %d, want %d", r.Status, ResponseSuccessful)
	}
	if got := len(r.Responses); got != 1 {
		t.Fatalf("len(Responses) = %d, want 1", got)
	}
	sr := r.Responses[0]
	if !sr.CertID.Equal(p.want) {
		t.Errorf("CertID = %+v, want %+v", sr.CertID, p.want)
	}
	if want := p.now.Add(-time.Minute); !sr.ThisUpdate.Equal(want) {
		t.Errorf("ThisUpdate = %v, want %v", sr.ThisUpdate, want)
	}
	if want := p.now.Add(-time.Minute); !r.ProducedAt.Equal(want) {
		t.Errorf("ProducedAt = %v, want %v", r.ProducedAt, want)
	}
	if r.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want %v", r.SignatureAlgorithm, x509.ECDSAWithSHA256)
	}
	if err := p.resp.Cert.CheckSignature(r.SignatureAlgorithm, r.TBSResponseData, r.Signature); err != nil {
		t.Errorf("signature over TBSResponseData does not verify: %v", err)
	}
}

func ocspTCheckSingle(t *testing.T, r *Response, status CertStatus, reason int) {
	t.Helper()
	if len(r.Responses) != 1 {
		t.Fatalf("len(Responses) = %d, want 1", len(r.Responses))
	}
	sr := r.Responses[0]
	if sr.Status != status {
		t.Errorf("Status = %d, want %d", sr.Status, status)
	}
	if sr.Reason != reason {
		t.Errorf("Reason = %d, want %d", sr.Reason, reason)
	}
}

func ocspTCheckSigAlg(want x509.SignatureAlgorithm) func(*testing.T, *ocspTPKI, *Response) {
	return func(t *testing.T, _ *ocspTPKI, r *Response) {
		t.Helper()
		if r.SignatureAlgorithm != want {
			t.Errorf("SignatureAlgorithm = %v, want %v", r.SignatureAlgorithm, want)
		}
	}
}

func ocspTCheckStatusOnly(status ResponseStatus) func(*testing.T, *ocspTPKI, *Response) {
	return func(t *testing.T, _ *ocspTPKI, r *Response) {
		t.Helper()
		if want := (&Response{Status: status}); !reflect.DeepEqual(r, want) {
			t.Errorf("response = %+v, want %+v", r, want)
		}
	}
}

func ocspTCheckCerts(n int) func(*testing.T, *ocspTPKI, *Response) {
	return func(t *testing.T, _ *ocspTPKI, r *Response) {
		t.Helper()
		if got := len(r.Certificates); got != n {
			t.Errorf("len(Certificates) = %d, want %d", got, n)
		}
	}
}

// ocspTParseCases is the TestParseResponse table; FuzzParseResponse seeds
// with every response it builds.
func ocspTParseCases() []ocspTParseCase {
	sigAlg := func(oid asn1.ObjectIdentifier, params []byte) func(testing.TB, *ocspTPKI) []byte {
		return ocspTMutate(func(tb testing.TB, _ *ocspTPKI, parts *ocspTParts) {
			parts.sigAlg = ocspTAlgID(tb, oid, params)
		})
	}
	explicitVersion := func(v int64) func(testing.TB, *ocspTPKI) []byte {
		return ocspTMutate(func(tb testing.TB, _ *ocspTPKI, parts *ocspTParts) {
			parts.version = ocspTDER(tb, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
					c.AddASN1Int64(v)
				})
			})
		})
	}
	nSingles := func(n int) func(testing.TB, *ocspTPKI) []byte {
		return ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
			parts.singles = slices.Repeat(parts.singles[:1], n)
		})
	}
	nCerts := func(n int) func(testing.TB, *ocspTPKI) []byte {
		return ocspTMutate(func(_ testing.TB, p *ocspTPKI, parts *ocspTParts) {
			parts.hasCerts = true
			parts.certs = slices.Repeat([][]byte{p.resp.Cert.Raw}, n)
		})
	}
	status := func(n int) func(testing.TB, *ocspTPKI) []byte {
		return ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.ResponseStatus = n })
	}
	raw := func(b ...byte) func(testing.TB, *ocspTPKI) []byte {
		return func(testing.TB, *ocspTPKI) []byte { return b }
	}
	nExts := func(n int) []pkix.Extension {
		exts := make([]pkix.Extension, n)
		for i := range exts {
			exts[i] = pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 10, i}, Value: ocspTDERNull}
		}
		return exts
	}
	nRespExts := func(n int) func(testing.TB, *ocspTPKI) []byte {
		return ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.ResponseExtensions = nExts(n) })
	}
	nSingleExts := func(n int) func(testing.TB, *ocspTPKI) []byte {
		return ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.SingleExtensions = nExts(n) })
	}
	checkExts := func(resp, single int) func(*testing.T, *ocspTPKI, *Response) {
		return func(t *testing.T, _ *ocspTPKI, r *Response) {
			if len(r.Extensions) != resp || len(r.Responses[0].Extensions) != single {
				t.Errorf("extensions = %d response, %d single, want %d and %d",
					len(r.Extensions), len(r.Responses[0].Extensions), resp, single)
			}
		}
	}
	producedAt := func(s string) func(testing.TB, *ocspTPKI) []byte {
		return ocspTMutate(func(tb testing.TB, _ *ocspTPKI, parts *ocspTParts) {
			parts.producedAt = ocspTGenTime(tb, s)
		})
	}
	// singleElem replaces element i of the SingleResponse (1 certStatus,
	// 2 thisUpdate, 3 nextUpdate).
	singleElem := func(i int, el func(testing.TB) []byte) func(testing.TB, *ocspTPKI) []byte {
		return ocspTEditSingle(func(tb testing.TB, elems [][]byte) [][]byte {
			elems[i] = el(tb)
			return elems
		})
	}
	thisUpdate := func(s string) func(testing.TB, *ocspTPKI) []byte {
		return singleElem(2, func(tb testing.TB) []byte { return ocspTGenTime(tb, s) })
	}
	nextUpdate := func(s string) func(testing.TB, *ocspTPKI) []byte {
		return singleElem(3, func(tb testing.TB) []byte { return ocspTCtx(tb, 0, ocspTGenTime(tb, s)) })
	}
	revocationTime := func(s string) func(testing.TB, *ocspTPKI) []byte {
		return singleElem(1, func(tb testing.TB) []byte { return ocspTCtx(tb, 1, ocspTGenTime(tb, s)) })
	}
	revokedAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	cases := []ocspTParseCase{
		{
			name:    "good",
			der:     ocspTSpec(nil),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				ocspTCheckBase(t, p, r)
				ocspTCheckSingle(t, r, CertGood, -1)
				if !r.Responses[0].RevokedAt.IsZero() {
					t.Errorf("RevokedAt = %v, want zero", r.Responses[0].RevokedAt)
				}
			},
		},
		{
			name: "revoked with reason 6",
			der: ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) {
				s.Status, s.Reason, s.RevokedAt = testpki.Revoked, 6, revokedAt
			}),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				ocspTCheckBase(t, p, r)
				ocspTCheckSingle(t, r, CertRevoked, 6)
				if got := r.Responses[0].RevokedAt; !got.Equal(revokedAt) {
					t.Errorf("RevokedAt = %v, want %v", got, revokedAt)
				}
			},
		},
		{
			name: "revoked without reason",
			der: ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) {
				s.Status, s.OmitReason, s.RevokedAt = testpki.Revoked, true, revokedAt
			}),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				ocspTCheckBase(t, p, r)
				ocspTCheckSingle(t, r, CertRevoked, -1)
			},
		},
		{
			name:    "unknown",
			der:     ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.Status = testpki.Unknown }),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				ocspTCheckBase(t, p, r)
				ocspTCheckSingle(t, r, CertUnknown, -1)
			},
		},
		{
			name:    "responder byName",
			der:     ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.ResponderID = testpki.ByName }),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				if !bytes.Equal(r.ResponderName, p.resp.Cert.RawSubject) {
					t.Errorf("ResponderName = %x, want %x", r.ResponderName, p.resp.Cert.RawSubject)
				}
				if r.ResponderKeyHash != nil {
					t.Errorf("ResponderKeyHash = %x, want nil", r.ResponderKeyHash)
				}
			},
		},
		{
			name:    "responder byKey",
			der:     ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.ResponderID = testpki.ByKey }),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				want := testpki.SPKIKeyHash(t, p.resp.Cert)
				if len(r.ResponderKeyHash) != 20 || !bytes.Equal(r.ResponderKeyHash, want) {
					t.Errorf("ResponderKeyHash = %x, want %x (20 bytes)", r.ResponderKeyHash, want)
				}
				if r.ResponderName != nil {
					t.Errorf("ResponderName = %x, want nil", r.ResponderName)
				}
			},
		},
		{
			name:    "nextUpdate present",
			der:     ocspTSpec(nil),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				if got, want := r.Responses[0].NextUpdate, p.now.Add(time.Hour); !got.Equal(want) {
					t.Errorf("NextUpdate = %v, want %v", got, want)
				}
			},
		},
		{
			name:    "nextUpdate absent",
			der:     ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.NextUpdate = time.Time{} }),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				ocspTCheckBase(t, p, r)
				if got := r.Responses[0].NextUpdate; !got.IsZero() {
					t.Errorf("NextUpdate = %v, want zero", got)
				}
			},
		},
		{
			name: "single and response extensions",
			der: ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) {
				s.SingleExtensions = []pkix.Extension{
					{Id: ocspTOIDExtA, Critical: true, Value: []byte{0x04, 0x01, 0xaa}},
					{Id: ocspTOIDExtB, Value: ocspTDERNull},
				}
				s.ResponseExtensions = []pkix.Extension{{Id: ocspTOIDExtC, Critical: true, Value: []byte{0x02, 0x01, 0x07}}}
			}),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				ocspTCheckBase(t, p, r)
				wantSingle := []Extension{
					{ID: ocspTOIDExtA, Critical: true, Value: []byte{0x04, 0x01, 0xaa}},
					{ID: ocspTOIDExtB, Value: ocspTDERNull},
				}
				if got := r.Responses[0].Extensions; !reflect.DeepEqual(got, wantSingle) {
					t.Errorf("single Extensions = %+v, want %+v", got, wantSingle)
				}
				wantResp := []Extension{{ID: ocspTOIDExtC, Critical: true, Value: []byte{0x02, 0x01, 0x07}}}
				if got := r.Extensions; !reflect.DeepEqual(got, wantResp) {
					t.Errorf("response Extensions = %+v, want %+v", got, wantResp)
				}
			},
		},
		{
			name:    "no embedded certificate",
			der:     ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) { s.NoCerts = true }),
			wantErr: ocspTNoErr,
			check:   ocspTCheckCerts(0),
		},
		{
			name:    "one embedded certificate",
			der:     ocspTSpec(nil),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				if len(r.Certificates) != 1 || !r.Certificates[0].Equal(p.resp.Cert) {
					t.Errorf("Certificates = %d, want [responder]", len(r.Certificates))
				}
			},
		},
		{
			name: "two embedded certificates",
			der: ocspTSpec(func(p *ocspTPKI, s *testpki.OCSPSpec) {
				s.Certs = []*x509.Certificate{p.resp.Cert, p.ca.Cert}
			}),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				if len(r.Certificates) != 2 || !r.Certificates[0].Equal(p.resp.Cert) || !r.Certificates[1].Equal(p.ca.Cert) {
					t.Errorf("Certificates = %d, want [responder, issuer]", len(r.Certificates))
				}
			},
		},
		{name: "status malformedRequest", der: status(1), wantErr: ocspTNoErr, check: ocspTCheckStatusOnly(ResponseMalformedRequest)},
		{name: "status internalError", der: status(2), wantErr: ocspTNoErr, check: ocspTCheckStatusOnly(ResponseInternalError)},
		{name: "status tryLater", der: status(3), wantErr: ocspTNoErr, check: ocspTCheckStatusOnly(ResponseTryLater)},
		{name: "status sigRequired", der: status(5), wantErr: ocspTNoErr, check: ocspTCheckStatusOnly(ResponseSigRequired)},
		{name: "status unauthorized", der: status(6), wantErr: ocspTNoErr, check: ocspTCheckStatusOnly(ResponseUnauthorized)},
		{
			name:    "successful without responseBytes",
			der:     func(testing.TB, *ocspTPKI) []byte { return []byte{0x30, 0x03, 0x0a, 0x01, 0x00} },
			wantErr: ocspTMalformed,
		},
		{
			name: "response type not basic",
			der: ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.respType = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 99}
			}),
			wantErr: ocspTAnyErr,
		},
		{name: "rsa sha256 NULL parameters", der: sigAlg(ocspTOIDSHA256RSA, ocspTDERNull), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.SHA256WithRSA)},
		{name: "rsa sha256 absent parameters", der: sigAlg(ocspTOIDSHA256RSA, nil), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.SHA256WithRSA)},
		{name: "rsa sha512 NULL parameters", der: sigAlg(ocspTOIDSHA512RSA, ocspTDERNull), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.SHA512WithRSA)},
		{name: "rsa sha256 non-NULL parameters", der: sigAlg(ocspTOIDSHA256RSA, []byte{0x02, 0x01, 0x00}), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.UnknownSignatureAlgorithm)},
		{name: "rsa sha256 NULL then trailing element", der: sigAlg(ocspTOIDSHA256RSA, []byte{0x05, 0x00, 0x05, 0x00}), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.UnknownSignatureAlgorithm)},
		{name: "ecdsa sha256 absent parameters", der: sigAlg(ocspTOIDECDSASHA256, nil), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.ECDSAWithSHA256)},
		{name: "ecdsa sha384 NULL parameters", der: sigAlg(ocspTOIDECDSASHA384, ocspTDERNull), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.ECDSAWithSHA384)},
		{name: "ed25519 absent parameters", der: sigAlg(ocspTOIDEd25519, nil), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.PureEd25519)},
		{name: "ed25519 NULL parameters", der: sigAlg(ocspTOIDEd25519, ocspTDERNull), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.UnknownSignatureAlgorithm)},
		{name: "sha1WithRSA", der: sigAlg(ocspTOIDSHA1RSA, ocspTDERNull), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.UnknownSignatureAlgorithm)},
		{name: "rsa-pss", der: sigAlg(ocspTOIDRSAPSS, []byte{0x30, 0x00}), wantErr: ocspTNoErr, check: ocspTCheckSigAlg(x509.UnknownSignatureAlgorithm)},
		{
			name:    "explicit version 0",
			der:     explicitVersion(0),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, p *ocspTPKI, r *Response) {
				if r.Status != ResponseSuccessful || len(r.Responses) != 1 {
					t.Errorf("Status = %d, len(Responses) = %d, want successful with 1", r.Status, len(r.Responses))
				}
			},
		},
		{name: "explicit version 1", der: explicitVersion(1), wantErr: ocspTAnyErr},
		{
			name: "truncated",
			der: func(tb testing.TB, p *ocspTPKI) []byte {
				der := p.build(tb, p.req, nil)
				return der[:len(der)-1]
			},
			wantErr: ocspTMalformed,
		},
		{
			name: "trailing bytes after OCSPResponse",
			der: ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.topTrailer = ocspTDERNull
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "trailing bytes after BasicOCSPResponse",
			der: ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.basicTrailer = ocspTDERNull
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "trailing bytes inside ResponseData",
			der: ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.tbsTrailer = ocspTDERNull
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "duplicate response extension",
			der: ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) {
				s.ResponseExtensions = []pkix.Extension{{Id: ocspTOIDExtA, Value: ocspTDERNull}, {Id: ocspTOIDExtA, Value: ocspTDERNull}}
			}),
			wantErr: ocspTAnyErr,
		},
		{
			name: "duplicate single extension",
			der: ocspTSpec(func(_ *ocspTPKI, s *testpki.OCSPSpec) {
				s.SingleExtensions = []pkix.Extension{{Id: ocspTOIDExtA, Value: ocspTDERNull}, {Id: ocspTOIDExtA, Value: ocspTDERNull}}
			}),
			wantErr: ocspTAnyErr,
		},
		{name: "32 SingleResponses", der: nSingles(32), wantErr: ocspTNoErr, check: func(t *testing.T, _ *ocspTPKI, r *Response) {
			if len(r.Responses) != 32 {
				t.Errorf("len(Responses) = %d, want 32", len(r.Responses))
			}
		}},
		{name: "33 SingleResponses", der: nSingles(33), wantErr: ocspTMalformed},
		{name: "zero SingleResponses", der: nSingles(0), wantErr: ocspTMalformed},
		{name: "8 certificates", der: nCerts(8), wantErr: ocspTNoErr, check: ocspTCheckCerts(8)},
		{name: "9 certificates", der: nCerts(9), wantErr: ocspTMalformed},
		{
			name: "byKey hash of 19 bytes",
			der: ocspTMutate(func(tb testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.responderID = ocspTDER(tb, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
						c.AddASN1OctetString(make([]byte, 19))
					})
				})
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "responderID with another tag",
			der: ocspTMutate(func(tb testing.TB, p *ocspTPKI, parts *ocspTParts) {
				parts.responderID = ocspTDER(tb, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.Tag(3).Constructed().ContextSpecific(), func(c *cryptobyte.Builder) {
						c.AddBytes(p.resp.Cert.RawSubject)
					})
				})
			}),
			wantErr: ocspTMalformed,
		},

		// Non-successful statuses carry nothing else and only defined values.
		{name: "tryLater with a trailing NULL", der: raw(0x30, 0x05, 0x0a, 0x01, 0x03, 0x05, 0x00), wantErr: ocspTMalformed},
		{name: "tryLater with trailing junk", der: raw(0x30, 0x07, 0x0a, 0x01, 0x03, 0xde, 0xad, 0xbe, 0xef), wantErr: ocspTMalformed},
		{name: "tryLater with responseBytes", der: raw(0x30, 0x07, 0x0a, 0x01, 0x03, 0xa0, 0x02, 0x30, 0x00), wantErr: ocspTMalformed},
		{name: "undefined status 4", der: raw(0x30, 0x03, 0x0a, 0x01, 0x04), wantErr: ocspTMalformed},
		{name: "undefined status 99", der: raw(0x30, 0x03, 0x0a, 0x01, 0x63), wantErr: ocspTMalformed},
		{name: "negative status -1", der: raw(0x30, 0x03, 0x0a, 0x01, 0xff), wantErr: ocspTMalformed},

		// Extension lists are bounded.
		{name: "16 response extensions", der: nRespExts(16), wantErr: ocspTNoErr, check: checkExts(16, 0)},
		{name: "17 response extensions", der: nRespExts(17), wantErr: ocspTMalformed},
		{name: "16 single extensions", der: nSingleExts(16), wantErr: ocspTNoErr, check: checkExts(0, 16)},
		{name: "17 single extensions", der: nSingleExts(17), wantErr: ocspTMalformed},

		// GeneralizedTime: DER form YYYYMMDDHHMMSSZ only, never the zero time.
		{
			name:    "revocationTime in the DER form",
			der:     revocationTime("20260102030405Z"),
			wantErr: ocspTNoErr,
			check: func(t *testing.T, _ *ocspTPKI, r *Response) {
				ocspTCheckSingle(t, r, CertRevoked, -1)
				if got := r.Responses[0].RevokedAt; !got.Equal(revokedAt) {
					t.Errorf("RevokedAt = %v, want %v", got, revokedAt)
				}
			},
		},
		{name: "revocationTime with an offset", der: revocationTime("20260102030405+0100"), wantErr: ocspTMalformed},
		{name: "thisUpdate with an offset", der: thisUpdate("20261030115900+0100"), wantErr: ocspTMalformed},
		{name: "nextUpdate with an offset", der: nextUpdate("20261030125900-0130"), wantErr: ocspTMalformed},
		{name: "nextUpdate 00010101000000Z (the zero time)", der: nextUpdate("00010101000000Z"), wantErr: ocspTMalformed},

		// Tag form and BER encodings are rejected.
		{name: "certStatus good sent constructed", der: singleElem(1, func(testing.TB) []byte { return []byte{0xa0, 0x00} }), wantErr: ocspTMalformed},
		{
			name: "certStatus revoked sent primitive",
			der: singleElem(1, func(tb testing.TB) []byte {
				return ocspTDER(tb, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(c *cryptobyte.Builder) {
						c.AddBytes(ocspTGenTime(tb, "20260102030405Z"))
					})
				})
			}),
			wantErr: ocspTMalformed,
		},
		{name: "certStatus with a high tag number", der: singleElem(1, func(testing.TB) []byte { return []byte{0x9f, 0x1f, 0x00} }), wantErr: ocspTMalformed},
		{
			name: "BER indefinite length",
			der: func(tb testing.TB, p *ocspTPKI) []byte {
				in := cryptobyte.String(p.build(tb, p.req, nil))
				var content cryptobyte.String
				if !in.ReadASN1(&content, cbasn1.SEQUENCE) {
					tb.Fatal("cannot read the base response")
				}
				return slices.Concat([]byte{0x30, 0x80}, content, []byte{0x00, 0x00})
			},
			wantErr: ocspTMalformed,
		},
		{
			name: "non-minimal long-form length",
			der: ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.producedAt = append([]byte{0x18, 0x81, 0x0f}, "20261030115900Z"...)
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "critical BOOLEAN encoded as 01",
			der: ocspTMutate(func(tb testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.respExts = ocspTCtx(tb, 1, ocspTDER(tb, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(exts *cryptobyte.Builder) {
						exts.AddASN1(cbasn1.SEQUENCE, func(e *cryptobyte.Builder) {
							e.AddASN1ObjectIdentifier(ocspTOIDExtA)
							e.AddBytes([]byte{0x01, 0x01, 0x01})
							e.AddASN1OctetString(ocspTDERNull)
						})
					})
				}))
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "nextUpdate sent twice",
			der: ocspTEditSingle(func(_ testing.TB, elems [][]byte) [][]byte {
				return append(elems, elems[3])
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "singleExtensions sent twice",
			der: ocspTEditSingle(func(tb testing.TB, elems [][]byte) [][]byte {
				exts := ocspTCtx(tb, 1, ocspTExtensions(tb, ocspTOIDExtA))
				return append(elems, exts, exts)
			}),
			wantErr: ocspTMalformed,
		},
		{
			name: "responderID sent twice",
			der: ocspTMutate(func(_ testing.TB, _ *ocspTPKI, parts *ocspTParts) {
				parts.responderID = slices.Concat(parts.responderID, parts.responderID)
			}),
			wantErr: ocspTMalformed,
		},
	}
	for _, bad := range []struct{ name, s string }{
		{"offset +0100", "20261030115900+0100"},
		{"offset -0130", "20261030115900-0130"},
		{"fractional seconds", "20261030115900.5Z"},
		{"zero fractional seconds", "20261030115900.000Z"},
		{"without seconds", "202610301159Z"},
		{"without zone", "20261030115900"},
		{"year 0000", "00000101000000Z"},
		{"second 60", "20261030115960Z"},
	} {
		cases = append(cases, ocspTParseCase{name: "producedAt " + bad.name, der: producedAt(bad.s), wantErr: ocspTMalformed})
	}
	return cases
}

func TestParseResponse(t *testing.T) {
	p := ocspTNewPKI(t)
	for _, tc := range ocspTParseCases() {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseResponse(tc.der(t, p))
			switch tc.wantErr {
			case ocspTNoErr:
				if err != nil {
					t.Fatalf("ParseResponse error = %v, want nil", err)
				}
			case ocspTMalformed:
				if !errors.Is(err, errMalformed) {
					t.Fatalf("ParseResponse error = %v, want %v", err, errMalformed)
				}
			case ocspTAnyErr:
				if err == nil {
					t.Fatal("ParseResponse error = nil, want an error")
				}
			}
			if err != nil {
				if r != nil {
					t.Errorf("ParseResponse returned %+v with error %v, want nil", r, err)
				}
				return
			}
			if tc.check != nil {
				tc.check(t, p, r)
			}
		})
	}
}

func TestNewCertID(t *testing.T) {
	p := ocspTNewPKI(t)
	badSPKI := *p.ca.Cert
	badSPKI.RawSubjectPublicKeyInfo = []byte{0x30, 0x01, 0x00}
	noSerial := *p.leaf.Cert
	noSerial.SerialNumber = nil
	cases := []struct {
		name    string
		h       crypto.Hash
		cert    *x509.Certificate // nil: the leaf
		issuer  *x509.Certificate
		wantOID asn1.ObjectIdentifier
		wantErr bool
	}{
		{name: "sha1", h: crypto.SHA1, issuer: p.ca.Cert, wantOID: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		{name: "sha256", h: crypto.SHA256, issuer: p.ca.Cert, wantOID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		{name: "md5", h: crypto.MD5, issuer: p.ca.Cert, wantErr: true},
		{name: "sha384", h: crypto.SHA384, issuer: p.ca.Cert, wantErr: true},
		{name: "malformed issuer SPKI", h: crypto.SHA1, issuer: &badSPKI, wantErr: true},
		{name: "certificate without serial", h: crypto.SHA1, cert: &noSerial, issuer: p.ca.Cert, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := cmp.Or(tc.cert, p.leaf.Cert)
			id, err := NewCertID(tc.h, cert, tc.issuer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewCertID(%v) error = nil, want an error", tc.h)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCertID(%v) error = %v", tc.h, err)
			}
			nameHash, keyHash := testpki.CertIDHashes(t, tc.h, p.ca.Cert)
			if !id.HashAlgorithm.Equal(tc.wantOID) {
				t.Errorf("HashAlgorithm = %v, want %v", id.HashAlgorithm, tc.wantOID)
			}
			if !bytes.Equal(id.IssuerNameHash, nameHash) {
				t.Errorf("IssuerNameHash = %x, want %x", id.IssuerNameHash, nameHash)
			}
			if !bytes.Equal(id.IssuerKeyHash, keyHash) {
				t.Errorf("IssuerKeyHash = %x, want %x", id.IssuerKeyHash, keyHash)
			}
			if id.SerialNumber.Cmp(p.leaf.Cert.SerialNumber) != 0 {
				t.Errorf("SerialNumber = %v, want %v", id.SerialNumber, p.leaf.Cert.SerialNumber)
			}
			if id.SerialNumber == p.leaf.Cert.SerialNumber {
				t.Error("SerialNumber aliases the certificate's serial, want a copy")
			}
		})
	}
}

func TestCertIDEqual(t *testing.T) {
	base := func() CertID {
		return CertID{
			HashAlgorithm:  asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
			IssuerNameHash: bytes.Repeat([]byte{1}, 20),
			IssuerKeyHash:  bytes.Repeat([]byte{2}, 20),
			SerialNumber:   big.NewInt(42),
		}
	}
	cases := []struct {
		name string
		edit func(*CertID)
		want bool
	}{
		{name: "identical", edit: func(*CertID) {}, want: true},
		{name: "hash algorithm", edit: func(c *CertID) { c.HashAlgorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} }},
		{name: "name hash", edit: func(c *CertID) { c.IssuerNameHash = bytes.Repeat([]byte{3}, 20) }},
		{name: "key hash", edit: func(c *CertID) { c.IssuerKeyHash = bytes.Repeat([]byte{3}, 20) }},
		{name: "serial", edit: func(c *CertID) { c.SerialNumber = big.NewInt(43) }},
		{name: "nil serial", edit: func(c *CertID) { c.SerialNumber = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := base()
			tc.edit(&other)
			if got := base().Equal(other); got != tc.want {
				t.Errorf("base.Equal(other) = %v, want %v", got, tc.want)
			}
			if got := other.Equal(base()); got != tc.want {
				t.Errorf("other.Equal(base) = %v, want %v", got, tc.want)
			}
		})
	}
}

// ocspTRequestHasExtensions reports whether the TBSRequest of an
// unsigned OCSPRequest carries requestExtensions.
func ocspTRequestHasExtensions(t *testing.T, der []byte) bool {
	t.Helper()
	in := cryptobyte.String(der)
	var req, tbs, list cryptobyte.String
	if !in.ReadASN1(&req, cbasn1.SEQUENCE) || !in.Empty() || !req.ReadASN1(&tbs, cbasn1.SEQUENCE) || !req.Empty() ||
		!tbs.ReadASN1(&list, cbasn1.SEQUENCE) {
		t.Fatalf("request is not OCSPRequest{TBSRequest{requestList ...}}: %x", der)
	}
	var exts cryptobyte.String
	var present bool
	if !tbs.ReadOptionalASN1(&exts, &present, cbasn1.Tag(2).Constructed().ContextSpecific()) || !tbs.Empty() {
		t.Fatalf("unexpected TBSRequest content after requestList: %x", der)
	}
	return present
}

func TestMarshalRequest(t *testing.T) {
	p := ocspTNewPKI(t)
	nonce := bytes.Repeat([]byte{0xc3}, NonceLength)
	cases := []struct {
		name  string
		h     crypto.Hash
		nonce []byte
	}{
		{name: "sha1 without nonce", h: crypto.SHA1},
		{name: "sha256 without nonce", h: crypto.SHA256},
		{name: "sha1 with nonce", h: crypto.SHA1, nonce: nonce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := NewCertID(tc.h, p.leaf.Cert, p.ca.Cert)
			if err != nil {
				t.Fatalf("NewCertID: %v", err)
			}
			der, ext, err := MarshalRequest(id, tc.nonce)
			if err != nil {
				t.Fatalf("MarshalRequest error = %v", err)
			}
			req, err := testpki.ParseOCSPRequest(der)
			if err != nil {
				t.Fatalf("ParseOCSPRequest: %v", err)
			}
			nameHash, keyHash := testpki.CertIDHashes(t, tc.h, p.ca.Cert)
			if req.Count != 1 {
				t.Errorf("Count = %d, want 1", req.Count)
			}
			if !req.HashAlgorithm.Equal(id.HashAlgorithm) {
				t.Errorf("HashAlgorithm = %v, want %v", req.HashAlgorithm, id.HashAlgorithm)
			}
			if !bytes.Equal(req.IssuerNameHash, nameHash) || !bytes.Equal(req.IssuerKeyHash, keyHash) {
				t.Errorf("hashes = %x/%x, want %x/%x", req.IssuerNameHash, req.IssuerKeyHash, nameHash, keyHash)
			}
			if req.Serial.Cmp(p.leaf.Cert.SerialNumber) != 0 {
				t.Errorf("Serial = %v, want %v", req.Serial, p.leaf.Cert.SerialNumber)
			}
			hasExts := ocspTRequestHasExtensions(t, der)
			if tc.nonce == nil {
				if ext != nil || req.Nonce != nil || hasExts {
					t.Errorf("nonce ext = %x, request nonce = %x, extensions = %v; want none", ext, req.Nonce, hasExts)
				}
				return
			}
			want := append([]byte{0x04, 0x20}, tc.nonce...)
			if !bytes.Equal(ext, want) {
				t.Errorf("nonce extnValue = %x, want %x", ext, want)
			}
			if !bytes.Equal(req.Nonce, ext) {
				t.Errorf("request nonce = %x, want %x", req.Nonce, ext)
			}
		})
	}
}

func TestMarshalRequestIncompleteCertID(t *testing.T) {
	p := ocspTNewPKI(t)
	cases := []struct {
		name string
		edit func(*CertID)
	}{
		{"nil serial", func(id *CertID) { id.SerialNumber = nil }},
		{"no hash algorithm", func(id *CertID) { id.HashAlgorithm = nil }},
		{"nil issuerNameHash", func(id *CertID) { id.IssuerNameHash = nil }},
		{"nil issuerKeyHash", func(id *CertID) { id.IssuerKeyHash = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := p.want
			tc.edit(&id)
			der, ext, err := MarshalRequest(id, bytes.Repeat([]byte{0xc3}, NonceLength))
			if err == nil || der != nil || ext != nil {
				t.Errorf("MarshalRequest = %x, %x, %v; want an error and no output", der, ext, err)
			}
		})
	}
}

// ocspTReadFile reads a file under testdata/ocsp.
func ocspTReadFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ocspTDir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// ocspTReadCert reads a one-block PEM certificate under testdata/ocsp/certs.
func ocspTReadCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(ocspTReadFile(t, "certs/"+name))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("%s: want exactly one CERTIFICATE PEM block", name)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// ocspTSources parses the SOURCES.md table into file -> sha256.
func ocspTSources(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join(ocspTDir, "SOURCES.md"))
	if err != nil {
		t.Fatalf("open SOURCES.md: %v", err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 3 {
			continue
		}
		file, sum := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[2])
		if file == "file" || strings.HasPrefix(file, "-") {
			continue
		}
		if _, err := hex.DecodeString(sum); err != nil || len(sum) != 64 {
			t.Errorf("SOURCES.md %s: sha256 %q is not 64 hex digits", file, sum)
		}
		out[file] = sum
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read SOURCES.md: %v", err)
	}
	return out
}

func TestParseRealResponses(t *testing.T) {
	t.Run("sources", func(t *testing.T) {
		sources := ocspTSources(t)
		var onDisk []string
		err := filepath.WalkDir(ocspTDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(ocspTDir, path)
			if err != nil {
				return err
			}
			if rel != "SOURCES.md" {
				onDisk = append(onDisk, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", ocspTDir, err)
		}
		for _, name := range onDisk {
			want, ok := sources[name]
			if !ok {
				t.Errorf("%s is not listed in SOURCES.md", name)
				continue
			}
			sum := sha256.Sum256(ocspTReadFile(t, name))
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("%s: sha256 = %s, want %s", name, got, want)
			}
		}
		for name := range sources {
			if !slices.Contains(onDisk, name) {
				t.Errorf("SOURCES.md lists %s, which is missing", name)
			}
		}
	})

	nonceOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	hasNonce := func(r *Response) bool {
		return slices.ContainsFunc(r.Extensions, func(e Extension) bool { return e.ID.Equal(nonceOID) })
	}
	cases := []struct {
		file      string
		wantAlg   x509.SignatureAlgorithm
		wantCN    string
		wantCerts int
		want      CertStatus
		check     func(t *testing.T, der []byte, r *Response)
	}{
		{
			file: "aoc-casub-a2.ocsp", wantAlg: x509.ECDSAWithSHA384, wantCerts: 1, want: CertGood,
			wantCN: "Servei OCSP de CA CONSORCI AOC (G3) ROOT-A",
		},
		{
			file: "camerfirma-qc2024.ocsp", wantAlg: x509.ECDSAWithSHA384, wantCerts: 1, want: CertGood,
			wantCN: "OCSP RESPONDER INFOCERT-CAMERFIRMA CERTIFICATES 2024",
			check: func(t *testing.T, der []byte, _ *Response) {
				// The sample must really carry ecdsa-with-SHA384 with NULL parameters.
				if alg := ocspTAlgID(t, ocspTOIDECDSASHA384, ocspTDERNull); !bytes.Contains(der, alg) {
					t.Errorf("sample lacks ecdsa-with-SHA384 with NULL parameters (%x)", alg)
				}
			},
		},
		{file: "izenpe-profesional-sw-act.ocsp", wantAlg: x509.SHA256WithRSA, wantCerts: 2, want: CertGood, wantCN: "ocsp.izenpe.com"},
		{file: "izenpe-profesional-sw-rev.ocsp", wantAlg: x509.SHA256WithRSA, wantCerts: 2, want: CertRevoked, wantCN: "ocsp.izenpe.com"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			der := ocspTReadFile(t, tc.file)
			r, err := ParseResponse(der)
			if err != nil {
				t.Fatalf("ParseResponse error = %v", err)
			}
			if r.Status != ResponseSuccessful {
				t.Errorf("Status = %d, want %d", r.Status, ResponseSuccessful)
			}
			var rdn pkix.RDNSequence
			if rest, err := asn1.Unmarshal(r.ResponderName, &rdn); err != nil || len(rest) != 0 {
				t.Fatalf("ResponderName is not a byName Name: %v", err)
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			if name.CommonName != tc.wantCN {
				t.Errorf("responder CN = %q, want %q", name.CommonName, tc.wantCN)
			}
			if r.SignatureAlgorithm != tc.wantAlg {
				t.Errorf("SignatureAlgorithm = %v, want %v", r.SignatureAlgorithm, tc.wantAlg)
			}
			if got := len(r.Certificates); got != tc.wantCerts {
				t.Errorf("len(Certificates) = %d, want %d", got, tc.wantCerts)
			}
			if len(r.Responses) != 1 {
				t.Fatalf("len(Responses) = %d, want 1", len(r.Responses))
			}
			if got := r.Responses[0].Status; got != tc.want {
				t.Errorf("certStatus = %d, want %d", got, tc.want)
			}
			if !hasNonce(r) {
				t.Error("nonce response extension missing")
			}
			if tc.check != nil {
				tc.check(t, der, r)
			}
		})
	}
}
