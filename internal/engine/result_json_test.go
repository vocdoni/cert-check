package engine

import (
	"crypto/x509"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// JSON shapes: a map is an object with exactly these keys, a one-element
// slice is a non-empty array of that shape, and a string names a kind.
const (
	jString = "string"
	jNumber = "number"
	jBool   = "bool"
	jNull   = "null"
	jTime   = "time"   // RFC 3339 string in UTC
	jDate   = "date"   // YYYY-MM-DD
	jObject = "object" // any object
)

func jsonResultShape(nextUpdate, birthDate, organization any) map[string]any {
	return map[string]any{
		"provider": map[string]any{"id": jString, "name": jString},
		"profile":  map[string]any{"id": jString, "name": jString, "holderRole": jString},
		"identity": map[string]any{
			"document":   map[string]any{"type": jString, "country": jString, "number": jString, "raw": jString, "source": jString},
			"givenNames": jString, "surnames": jString, "firstSurname": jString, "secondSurname": jString, "fullName": jString,
			"birthDate": birthDate, "sources": jObject,
		},
		"organization": organization,
		"certificate": map[string]any{"subject": jString, "issuer": jString, "serialHex": jString, "notBefore": jTime,
			"notAfter": jTime, "sha256": jString, "keyAlgorithm": jString},
		"revocation": map[string]any{"status": jString, "method": jString, "checkedAt": jTime, "thisUpdate": jTime,
			"nextUpdate": nextUpdate, "source": jString},
		"validatedAt": jTime,
		"diagnostics": map[string]any{
			"diagnosticId": jString, "time": jTime, "serverVersion": jString, "provider": jString, "failedStep": jString,
			"code": jString, "technicalDetail": jString, "tls": jNull,
			"certificate": map[string]any{"subject": jString, "issuer": jString, "serialHex": jString, "notBefore": jTime,
				"notAfter": jTime, "sha256": jString, "keyAlgorithm": jString, "signatureAlgorithm": jString,
				"keyUsage": []any{jString}, "extKeyUsage": []any{jString}, "policyOids": []any{jString},
				"criticalExtensions": []any{jString}, "ocspUrls": []any{jString}, "caIssuerUrls": jNull, "cdpUrls": jNull},
			"chain":             []any{map[string]any{"subject": jString, "issuer": jString}},
			"profileCandidates": []any{map[string]any{"profileId": jString, "result": jString}},
			"revocationAttempts": []any{map[string]any{"method": jString, "url": jString, "httpStatus": jNumber,
				"durationMs": jNumber, "outcome": jString, "detail": jString, "fromCache": jBool, "producedAt": jTime,
				"thisUpdate": jTime, "nextUpdate": nextUpdate, "responderSubject": jString, "nonceSent": jBool, "nonceEchoed": jBool}},
		},
	}
}

// checkJSONShape compares a decoded JSON value with a shape.
func checkJSONShape(t *testing.T, path string, got, want any) {
	t.Helper()
	switch w := want.(type) {
	case map[string]any:
		obj, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s = %T, want an object", path, got)
			return
		}
		if g, k := slices.Sorted(maps.Keys(obj)), slices.Sorted(maps.Keys(w)); !slices.Equal(g, k) {
			t.Errorf("%s keys = %v, want %v", path, g, k)
			return
		}
		for k, v := range w {
			checkJSONShape(t, path+"."+k, obj[k], v)
		}
	case []any:
		arr, ok := got.([]any)
		if !ok || len(arr) == 0 {
			t.Errorf("%s = %v, want a non-empty array", path, got)
			return
		}
		for i, v := range arr {
			checkJSONShape(t, path+"["+strconv.Itoa(i)+"]", v, w[0])
		}
	case string:
		ok := false
		switch w {
		case jString:
			_, ok = got.(string)
		case jNumber:
			_, ok = got.(float64)
		case jBool:
			_, ok = got.(bool)
		case jNull:
			ok = got == nil
		case jObject:
			_, ok = got.(map[string]any)
		case jTime:
			s, isStr := got.(string)
			ts, err := time.Parse(time.RFC3339, s)
			ok = isStr && err == nil && strings.HasSuffix(s, "Z") && ts.Location() == time.UTC
		case jDate:
			s, isStr := got.(string)
			_, err := time.Parse(time.DateOnly, s)
			ok = isStr && err == nil
		}
		if !ok {
			t.Errorf("%s = %#v, want %s", path, got, w)
		}
	default:
		t.Fatalf("%s: bad shape %T", path, want)
	}
}

func decodeJSON(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return out
}

func TestResultJSON(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)

	// DNIe-like evidence: good without nextUpdate.
	leaf := w.leaf(t, w.rootA, nil)
	w.answer(leaf.SerialNumber, testpki.OCSPSpec{})
	res, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf})
	if err != nil {
		t.Fatalf("Check error = %v", err)
	}
	if res.Revocation.NextUpdate != nil {
		t.Fatalf("fixture: nextUpdate = %v, want absent", res.Revocation.NextUpdate)
	}
	checkJSONShape(t, "result", decodeJSON(t, res), jsonResultShape(jNull, jNull, jNull))

	// nextUpdate, birthDate and organization present.
	withNext, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{w.leaf(t, w.rootA, nil)})
	if err != nil {
		t.Fatalf("Check error = %v", err)
	}
	withNext.Identity.BirthDate = &identity.Date{Year: 1980, Month: time.January, Day: 1}
	withNext.Organization = &identity.Organization{Name: "EMPRESA DEMO SL", Identifier: "VATES-B00000000"}
	checkJSONShape(t, "result", decodeJSON(t, withNext),
		jsonResultShape(jTime, jDate, map[string]any{"name": jString, "identifier": jString}))

	// Spot values: the issuer is the CN, the date is civil, statuses are the enum strings.
	got := decodeJSON(t, withNext).(map[string]any)
	if v := got["certificate"].(map[string]any)["issuer"]; v != w.rootA.Cert.Subject.CommonName {
		t.Errorf("certificate.issuer = %v, want the issuer CN %q", v, w.rootA.Cert.Subject.CommonName)
	}
	if v := got["identity"].(map[string]any)["birthDate"]; v != "1980-01-01" {
		t.Errorf("identity.birthDate = %v, want 1980-01-01", v)
	}
	if v := got["revocation"].(map[string]any)["status"]; v != "good" {
		t.Errorf("revocation.status = %v, want good", v)
	}
	if v := got["profile"].(map[string]any)["holderRole"]; v != "natural_person" {
		t.Errorf("profile.holderRole = %v, want natural_person", v)
	}
}

func TestErrorDiagnosticsJSON(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)
	_, err := w.chk.VerifyAs(t.Context(), "alpha", nil)
	e := tErr(t, err)
	got := decodeJSON(t, e.Diagnostics).(map[string]any)
	want := map[string]any{"diagnosticId": jString, "time": jTime, "serverVersion": jString, "provider": jString,
		"failedStep": jString, "code": jString, "technicalDetail": jString, "tls": jNull, "certificate": jNull,
		"chain": jNull, "profileCandidates": jNull, "revocationAttempts": jNull}
	checkJSONShape(t, "diagnostics", got, want)
	if got["code"] != string(CodeNoCertificate) || got["failedStep"] != string(StepBounds) {
		t.Errorf("code/failedStep = %v/%v, want %s/%s", got["code"], got["failedStep"], CodeNoCertificate, StepBounds)
	}
}
