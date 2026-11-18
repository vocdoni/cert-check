package revocation

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ocspTRealSamples are the committed real OCSP responses.
var ocspTRealSamples = []string{
	"aoc-casub-a2.ocsp",
	"camerfirma-qc2024.ocsp",
	"izenpe-profesional-sw-act.ocsp",
	"izenpe-profesional-sw-rev.ocsp",
}

func FuzzParseResponse(f *testing.F) {
	for _, name := range ocspTRealSamples {
		der, err := os.ReadFile(filepath.Join(ocspTDir, name))
		if err != nil {
			f.Fatalf("read %s: %v", name, err)
		}
		f.Add(der)
	}
	vf := ocspTNewVerifyFixture(f)
	for _, tc := range ocspTParseCases() {
		f.Add(tc.der(f, vf.ocspTPKI))
	}
	for _, tc := range ocspTVerifyCases() {
		f.Add(vf.response(f, tc))
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		r, err := ParseResponse(der)
		if err != nil {
			if r != nil {
				t.Fatalf("ParseResponse returned a response with error %v", err)
			}
			return
		}
		if r.Status != ResponseSuccessful {
			if r.TBSResponseData != nil || r.Responses != nil || r.Certificates != nil || r.Signature != nil {
				t.Fatalf("non-successful status %d carries response fields", r.Status)
			}
			switch r.Status {
			case ResponseMalformedRequest, ResponseInternalError, ResponseTryLater, ResponseSigRequired, ResponseUnauthorized:
			default:
				t.Fatalf("undefined responseStatus %d accepted", r.Status)
			}
			return
		}
		// TBSResponseData is one complete DER SEQUENCE taken from the input.
		tbs := cryptobyte.String(r.TBSResponseData)
		var elem cryptobyte.String
		if !tbs.ReadASN1Element(&elem, cbasn1.SEQUENCE) || !tbs.Empty() {
			t.Fatalf("TBSResponseData is not exactly one SEQUENCE element: %x", r.TBSResponseData)
		}
		if !bytes.Contains(der, r.TBSResponseData) {
			t.Fatal("TBSResponseData is not part of the input")
		}
		if n := len(r.Responses); n < 1 || n > maxSingleResponses {
			t.Fatalf("len(Responses) = %d, want 1..%d", n, maxSingleResponses)
		}
		if n := len(r.Certificates); n > maxEmbeddedCerts {
			t.Fatalf("len(Certificates) = %d, want <= %d", n, maxEmbeddedCerts)
		}
		if (r.ResponderName == nil) == (r.ResponderKeyHash == nil) {
			t.Fatal("want exactly one of ResponderName and ResponderKeyHash")
		}
		if r.ResponderKeyHash != nil && len(r.ResponderKeyHash) != 20 {
			t.Fatalf("len(ResponderKeyHash) = %d, want 20", len(r.ResponderKeyHash))
		}
		if n := len(r.Extensions); n > maxExtensions {
			t.Fatalf("len(Extensions) = %d, want <= %d", n, maxExtensions)
		}
		if r.ProducedAt.IsZero() || r.ProducedAt.Location() != time.UTC {
			t.Fatalf("ProducedAt = %v, want a non-zero UTC time", r.ProducedAt)
		}
		for _, sr := range r.Responses {
			if sr.CertID.SerialNumber == nil {
				t.Fatal("SingleResponse without a serial number")
			}
			if sr.Status < CertGood || sr.Status > CertUnknown {
				t.Fatalf("certStatus = %d, want good, revoked or unknown", sr.Status)
			}
			if n := len(sr.Extensions); n > maxExtensions {
				t.Fatalf("len(singleExtensions) = %d, want <= %d", n, maxExtensions)
			}
			if sr.ThisUpdate.IsZero() || sr.ThisUpdate.Location() != time.UTC || sr.NextUpdate.Location() != time.UTC {
				t.Fatalf("thisUpdate %v, nextUpdate %v, want non-zero UTC thisUpdate and UTC nextUpdate", sr.ThisUpdate, sr.NextUpdate)
			}
		}
	})
}
