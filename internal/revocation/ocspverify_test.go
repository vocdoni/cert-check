package revocation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/testpki"
)

// ocspTMaxAge is the MaxAge every synthetic VerifyOCSP case uses.
const ocspTMaxAge = 15 * time.Minute

// ocspTVerifyFixture extends ocspTPKI with responders that each break one
// authorization rule.
type ocspTVerifyFixture struct {
	*ocspTPKI
	otherResp      *testpki.Responder // issued by an unrelated CA
	impostorResp   *testpki.Responder // issued by a CA with the issuer's name and another key
	sameNameResp   *testpki.Responder // unrelated CA, same subject as resp
	clientAuthResp *testpki.Responder // EKU clientAuth only
	expiredResp    *testpki.Responder
	futureResp     *testpki.Responder
	noCheckResp    *testpki.Responder // OCSPSigning without id-pkix-ocsp-nocheck
	rsa1024Resp    *testpki.Responder
	p224Resp       *testpki.Responder
	criticalResp   *testpki.Responder // unknown critical extension
}

func ocspTRespName(cn string) testpki.Name {
	return testpki.Name{testpki.UTF8(testpki.OIDCommonName, cn), testpki.Printable(testpki.OIDCountry, "ES")}
}

func ocspTNewVerifyFixture(tb testing.TB) *ocspTVerifyFixture {
	tb.Helper()
	p := ocspTNewPKI(tb)
	f := &ocspTVerifyFixture{ocspTPKI: p}
	now := p.now
	other := testpki.NewRoot(tb, "ocspT other CA", testpki.CertSpec{Now: now})
	f.otherResp = other.OCSPResponder(tb, testpki.CertSpec{Now: now, Subject: ocspTRespName("ocspT other OCSP")})
	f.sameNameResp = other.OCSPResponder(tb, testpki.CertSpec{Now: now, Subject: ocspTRespName("ocspT CA OCSP")})

	// The issuer's default subject (testpki defaultCAName for label "ocspT CA").
	issuerName := testpki.Name{
		testpki.Printable(testpki.OIDCountry, "ES"),
		testpki.UTF8(testpki.OIDOrganization, "testpki"),
		testpki.UTF8(testpki.OIDCommonName, "ocspT CA"),
	}
	impostor := testpki.NewRoot(tb, "ocspT impostor", testpki.CertSpec{Now: now, Subject: issuerName})
	if !bytes.Equal(impostor.Cert.RawSubject, p.ca.Cert.RawSubject) {
		tb.Fatal("impostor CA subject differs from the issuer subject")
	}
	f.impostorResp = impostor.OCSPResponder(tb, testpki.CertSpec{Now: now, Subject: ocspTRespName("ocspT impostor OCSP")})

	ca := p.ca
	f.clientAuthResp = ca.OCSPResponder(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT clientAuth OCSP"),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	f.expiredResp = ca.OCSPResponder(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT expired OCSP"),
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour),
	})
	f.futureResp = ca.OCSPResponder(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT future OCSP"),
		NotBefore: now.Add(time.Hour), NotAfter: now.Add(48 * time.Hour),
	})
	noCheck := ca.Leaf(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT nocheck-less OCSP"),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	})
	f.noCheckResp = &testpki.Responder{Cert: noCheck.Cert, Key: noCheck.Key}
	f.rsa1024Resp = ca.OCSPResponder(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT rsa1024 OCSP"), Key: testpki.RSA1024,
	})
	f.p224Resp = ca.OCSPResponder(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT p224 OCSP"), Key: testpki.ECDSAP224,
	})
	f.criticalResp = ca.OCSPResponder(tb, testpki.CertSpec{
		Now: now, Subject: ocspTRespName("ocspT critical OCSP"),
		ExtraExtensions: []pkix.Extension{{Id: ocspTOIDExtA, Critical: true, Value: ocspTDERNull}},
	})
	return f
}

type ocspTVerifyCase struct {
	name      string
	sendNonce bool
	edit      func(f *ocspTVerifyFixture, s *testpki.OCSPSpec)
	mutate    func(r *Response) // applied after parsing
	want      Status
	// wantDetail is a substring of the returned detail.
	wantDetail string
	// wantSigner is the accepted signer; nil means the delegated responder.
	wantSigner func(f *ocspTVerifyFixture) *x509.Certificate
	wantEchoed bool
}

// response builds the DER answer of one case.
func (f *ocspTVerifyFixture) response(tb testing.TB, tc ocspTVerifyCase) []byte {
	tb.Helper()
	req := f.req
	if tc.sendNonce {
		req = f.nonceReq
	}
	return f.build(tb, req, func(s *testpki.OCSPSpec) {
		if tc.edit != nil {
			tc.edit(f, s)
		}
	})
}

func ocspTIssuerSigner(f *ocspTVerifyFixture) *x509.Certificate { return f.ca.Cert }

// ocspTVerifyCases is the TestVerifyOCSP table; FuzzParseResponse seeds with
// every response it builds.
func ocspTVerifyCases() []ocspTVerifyCase {
	now := ocspTNow
	signer := func(r func(f *ocspTVerifyFixture) *testpki.Responder) func(*ocspTVerifyFixture, *testpki.OCSPSpec) {
		return func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Signer = r(f) }
	}
	return []ocspTVerifyCase{
		{name: "good", want: StatusGood, wantDetail: "good"},
		{
			name:       "revoked",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Status, s.Reason = testpki.Revoked, 1 },
			want:       StatusRevoked,
			wantDetail: "revoked (reason 1)",
		},
		{
			name:       "unknown",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Status = testpki.Unknown },
			want:       StatusUnknown,
			wantDetail: "unknown",
		},
		{
			name: "never issued: certificateHold at 1970-01-01",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Status, s.Reason, s.RevokedAt = testpki.Revoked, 6, time.Unix(0, 0).UTC()
			},
			want:       StatusRevoked,
			wantDetail: "revoked (reason 6)",
		},
		{
			name:       "serial mismatch",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.SerialOverride = big.NewInt(424242) },
			want:       StatusInvalidEvidence,
			wantDetail: "no SingleResponse matches",
		},
		{
			name:       "issuerNameHash mismatch",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.NameHashOverride = bytes.Repeat([]byte{0x11}, 20) },
			want:       StatusInvalidEvidence,
			wantDetail: "no SingleResponse matches",
		},
		{
			name:       "issuerKeyHash mismatch",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.KeyHashOverride = bytes.Repeat([]byte{0x22}, 20) },
			want:       StatusInvalidEvidence,
			wantDetail: "no SingleResponse matches",
		},
		{
			name:       "CertID hashed with SHA-256 while SHA-1 was requested",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.CertIDHash = crypto.SHA256 },
			want:       StatusInvalidEvidence,
			wantDetail: "no SingleResponse matches",
		},
		{
			name:       "duplicate SingleResponse",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.DuplicateSingle = true },
			want:       StatusInvalidEvidence,
			wantDetail: "more than one SingleResponse",
		},
		{
			name:       "responder issued by another CA",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.otherResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "not issued by",
		},
		{
			name:       "responder issued by a CA with the issuer's name and another key",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.impostorResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "not issued by",
		},
		{
			name:       "responder with EKU clientAuth only",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.clientAuthResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "lacks id-kp-OCSPSigning",
		},
		{
			name:       "responder expired",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.expiredResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "not valid now",
		},
		{
			name:       "responder not yet valid",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.futureResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "not valid now",
		},
		{
			name:       "responder without nocheck",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.noCheckResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "lacks id-pkix-ocsp-nocheck",
		},
		{
			name:       "responder RSA-1024",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.rsa1024Resp }),
			want:       StatusInvalidEvidence,
			wantDetail: "key too weak",
		},
		{
			name:       "responder ECDSA P-224",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.p224Resp }),
			want:       StatusInvalidEvidence,
			wantDetail: "key too weak",
		},
		{
			name:       "responder with an unknown critical extension",
			edit:       signer(func(f *ocspTVerifyFixture) *testpki.Responder { return f.criticalResp }),
			want:       StatusInvalidEvidence,
			wantDetail: "unhandled critical",
		},
		{
			name:       "ResponderID byName of another certificate",
			edit:       func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ResponderIDOf = f.otherResp.Cert },
			want:       StatusInvalidEvidence,
			wantDetail: "no embedded certificate matches the ResponderID",
		},
		{
			name: "ResponderID byKey of another certificate",
			edit: func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ResponderID, s.ResponderIDOf = testpki.ByKey, f.otherResp.Cert
			},
			want:       StatusInvalidEvidence,
			wantDetail: "no embedded certificate matches the ResponderID",
		},
		{
			name:       "ResponderID names the issuer, delegated responder signs",
			edit:       func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ResponderIDOf = f.ca.Cert },
			want:       StatusInvalidEvidence,
			wantDetail: "signature by the issuer does not verify",
		},
		{
			name:       "delegated responder not embedded",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.NoCerts = true },
			want:       StatusInvalidEvidence,
			wantDetail: "no embedded certificate matches the ResponderID",
		},
		{
			name: "same-name certificate from another CA before the real responder",
			edit: func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Certs = []*x509.Certificate{f.sameNameResp.Cert, f.resp.Cert}
			},
			want: StatusGood,
		},
		{
			name: "signed by a same-name responder from another CA",
			edit: func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Signer, s.Certs = f.sameNameResp, []*x509.Certificate{f.sameNameResp.Cert, f.resp.Cert}
			},
			want:       StatusInvalidEvidence,
			wantDetail: "signature by the responder does not verify",
		},
		{
			name: "delegated responder byKey",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ResponderID = testpki.ByKey },
			want: StatusGood,
		},
		{
			name:       "signed by the issuer byName",
			edit:       func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Signer = f.ca.AsResponder() },
			want:       StatusGood,
			wantSigner: ocspTIssuerSigner,
		},
		{
			name: "signed by the issuer byKey",
			edit: func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Signer, s.ResponderID = f.ca.AsResponder(), testpki.ByKey
			},
			want:       StatusGood,
			wantSigner: ocspTIssuerSigner,
		},
		{
			name: "signed by the issuer, corrupt signature",
			edit: func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Signer, s.CorruptSignature = f.ca.AsResponder(), true
			},
			want:       StatusInvalidEvidence,
			wantDetail: "signature by the issuer does not verify",
		},
		{
			name:       "corrupt signature",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.CorruptSignature = true },
			want:       StatusInvalidEvidence,
			wantDetail: "signature by the responder does not verify",
		},
		{
			name:       "unsupported signature algorithm",
			mutate:     func(r *Response) { r.SignatureAlgorithm = x509.UnknownSignatureAlgorithm },
			want:       StatusInvalidEvidence,
			wantDetail: "unsupported signature algorithm",
		},
		{
			name: "no nextUpdate, thisUpdate 16m ago",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ThisUpdate, s.NextUpdate = now.Add(-16*time.Minute), time.Time{}
			},
			want:       StatusStale,
			wantDetail: "older than the maximum age",
		},
		{
			name: "no nextUpdate, thisUpdate 14m ago",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ThisUpdate, s.NextUpdate = now.Add(-14*time.Minute), time.Time{}
			},
			want: StatusGood,
		},
		{
			name: "nextUpdate in the past",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ThisUpdate, s.NextUpdate = now.Add(-2*time.Hour), now.Add(-time.Minute)
			},
			want:       StatusStale,
			wantDetail: "nextUpdate",
		},
		{
			name: "nextUpdate before thisUpdate",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ThisUpdate, s.NextUpdate = now.Add(4*time.Minute), now.Add(2*time.Minute)
			},
			want:       StatusStale,
			wantDetail: "nextUpdate",
		},
		{
			name:       "thisUpdate 6m in the future",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ThisUpdate = now.Add(6 * time.Minute) },
			want:       StatusStale,
			wantDetail: "thisUpdate in the future",
		},
		{
			name: "thisUpdate 4m in the future",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ThisUpdate = now.Add(4 * time.Minute) },
			want: StatusGood,
		},
		{
			name: "long window: thisUpdate -3d, nextUpdate +4d",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ThisUpdate, s.NextUpdate = now.Add(-72*time.Hour), now.Add(96*time.Hour)
			},
			want: StatusGood,
		},
		{
			name: "revoked but nextUpdate in the past",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Status, s.ThisUpdate, s.NextUpdate = testpki.Revoked, now.Add(-2*time.Hour), now.Add(-time.Minute)
			},
			want:       StatusStale,
			wantDetail: "nextUpdate",
		},
		{name: "nonce sent and echoed", sendNonce: true, want: StatusGood, wantEchoed: true},
		{
			name:       "nonce sent and omitted",
			sendNonce:  true,
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Nonce = testpki.NonceOmit },
			want:       StatusInvalidEvidence,
			wantDetail: "not echoed",
		},
		{
			name:       "nonce sent and wrong",
			sendNonce:  true,
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Nonce = testpki.NonceWrong },
			want:       StatusInvalidEvidence,
			wantDetail: "nonce mismatch",
		},
		{
			name: "nonce not sent but present",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.Nonce = testpki.NonceWrong },
			want: StatusGood,
		},
		{
			name: "critical unknown response extension",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ResponseExtensions = []pkix.Extension{{Id: ocspTOIDExtB, Critical: true, Value: ocspTDERNull}}
			},
			want:       StatusInvalidEvidence,
			wantDetail: "unhandled critical response extension",
		},
		{
			name: "non-critical unknown response extension",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.ResponseExtensions = []pkix.Extension{{Id: ocspTOIDExtB, Value: ocspTDERNull}}
			},
			want: StatusGood,
		},
		{
			name:      "critical nonce",
			sendNonce: true,
			edit: func(f *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.Nonce = testpki.NonceOmit
				s.ResponseExtensions = []pkix.Extension{{Id: oidOCSPNonce, Critical: true, Value: f.nonceExt}}
			},
			want:       StatusGood,
			wantEchoed: true,
		},
		{
			name: "critical single extension",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.SingleExtensions = []pkix.Extension{{Id: ocspTOIDExtC, Critical: true, Value: ocspTDERNull}}
			},
			want:       StatusInvalidEvidence,
			wantDetail: "unhandled critical singleExtension",
		},
		{
			name: "non-critical single extension",
			edit: func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) {
				s.SingleExtensions = []pkix.Extension{{Id: ocspTOIDExtC, Value: ocspTDERNull}}
			},
			want: StatusGood,
		},
		{
			name:       "responseStatus tryLater",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ResponseStatus = 3 },
			want:       StatusUnavailable,
			wantDetail: "responseStatus 3",
		},
		{
			name:       "responseStatus unauthorized",
			edit:       func(_ *ocspTVerifyFixture, s *testpki.OCSPSpec) { s.ResponseStatus = 6 },
			want:       StatusUnavailable,
			wantDetail: "responseStatus 6",
		},
	}
}

func ocspTAccepted(s Status) bool {
	return s == StatusGood || s == StatusRevoked || s == StatusUnknown
}

func TestVerifyOCSP(t *testing.T) {
	f := ocspTNewVerifyFixture(t)
	for _, tc := range ocspTVerifyCases() {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ParseResponse(f.response(t, tc))
			if err != nil {
				t.Fatalf("ParseResponse error = %v", err)
			}
			if tc.mutate != nil {
				tc.mutate(r)
			}
			in := OCSPInput{Response: r, Want: f.want, Issuer: f.ca.Cert, Now: f.now, MaxAge: ocspTMaxAge}
			if tc.sendNonce {
				in.Nonce = f.nonceExt
			}
			ev, got, detail := VerifyOCSP(in)
			if got != tc.want {
				t.Fatalf("status = %q (%s), want %q", got, detail, tc.want)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", detail, tc.wantDetail)
			}
			if ev.NonceEchoed != tc.wantEchoed {
				t.Errorf("NonceEchoed = %v, want %v", ev.NonceEchoed, tc.wantEchoed)
			}
			if !ocspTAccepted(tc.want) {
				return
			}
			wantSigner := f.resp.Cert
			if tc.wantSigner != nil {
				wantSigner = tc.wantSigner(f)
			}
			if ev.Signer == nil || !ev.Signer.Equal(wantSigner) {
				t.Errorf("Signer = %v, want %v", ev.Signer, wantSigner.Subject)
			}
			if want := wantSigner.Subject.String(); ev.ResponderSubject != want {
				t.Errorf("ResponderSubject = %q, want %q", ev.ResponderSubject, want)
			}
			if !ev.Single.CertID.Equal(f.want) {
				t.Errorf("Single.CertID = %+v, want %+v", ev.Single.CertID, f.want)
			}
			if !ev.ProducedAt.Equal(r.ProducedAt) {
				t.Errorf("ProducedAt = %v, want %v", ev.ProducedAt, r.ProducedAt)
			}
		})
	}
}

func TestVerifyRealResponses(t *testing.T) {
	cases := []struct {
		file, target, issuer string
		want                 Status
		wantSubject          string
	}{
		{
			file: "aoc-casub-a2.ocsp", target: "aoc-subca-ciutadania-g3-a2.pem", issuer: "aoc-g3-root-a.pem",
			want: StatusGood, wantSubject: "CA CONSORCI AOC (G3) ROOT-A",
		},
		{
			file: "camerfirma-qc2024.ocsp", target: "camerfirma-qc-2024.pem", issuer: "camerfirma-root-2024.pem",
			want: StatusGood, wantSubject: "OCSP RESPONDER INFOCERT-CAMERFIRMA CERTIFICATES 2024",
		},
		{
			file: "izenpe-profesional-sw-act.ocsp", target: "izenpe-profesional-sw-act.pem", issuer: "izenpe-ca4.pem",
			want: StatusGood, wantSubject: "ocsp.izenpe.com",
		},
		{
			file: "izenpe-profesional-sw-rev.ocsp", target: "izenpe-profesional-sw-rev.pem", issuer: "izenpe-ca4.pem",
			want: StatusRevoked, wantSubject: "ocsp.izenpe.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			target, issuer := ocspTReadCert(t, tc.target), ocspTReadCert(t, tc.issuer)
			want, err := NewCertID(crypto.SHA1, target, issuer)
			if err != nil {
				t.Fatalf("NewCertID: %v", err)
			}
			r, err := ParseResponse(ocspTReadFile(t, tc.file))
			if err != nil {
				t.Fatalf("ParseResponse: %v", err)
			}
			ev, got, detail := VerifyOCSP(OCSPInput{
				Response: r,
				Want:     want,
				Issuer:   issuer,
				Now:      r.ProducedAt.Add(time.Minute),
				MaxAge:   ocspTMaxAge,
			})
			if got != tc.want {
				t.Fatalf("status = %q (%s), want %q", got, detail, tc.want)
			}
			if !strings.Contains(ev.ResponderSubject, tc.wantSubject) {
				t.Errorf("ResponderSubject = %q, want it to contain %q", ev.ResponderSubject, tc.wantSubject)
			}
			if ev.NonceEchoed {
				t.Error("NonceEchoed = true, want false (no nonce sent)")
			}
		})
	}
}
