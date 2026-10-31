package server_test

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
)

// fixturesDir holds the UI's redeem fixtures (Task 11, ruling R38).
const fixturesDir = "../../web/testdata/fixtures"

// decodeFixture strictly decodes a redeem fixture into redeemResponse.
// identity.Date has MarshalJSON only, so a non-null birthDate cannot be
// decoded into certauth.Result: it is checked against what Date.MarshalJSON
// writes, then nulled for the strict decode.
func decodeFixture(t *testing.T, raw []byte) redeemResponse {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	result, _ := generic["result"].(map[string]any)
	ident, _ := result["identity"].(map[string]any)
	if bd, ok := ident["birthDate"].(string); ok {
		d, err := time.Parse(time.DateOnly, bd)
		if err != nil {
			t.Fatalf("birthDate %q: %v", bd, err)
		}
		marshalled, err := identity.Date{Year: d.Year(), Month: d.Month(), Day: d.Day()}.MarshalJSON()
		if err != nil || string(marshalled) != strconv.Quote(bd) {
			t.Errorf("birthDate %q, want the identity.Date encoding %s", bd, marshalled)
		}
		ident["birthDate"] = nil
		if raw, err = json.Marshal(generic); err != nil {
			t.Fatalf("re-encode fixture: %v", err)
		}
	}
	return decodeRedeem(t, raw)
}

// keyPaths returns every object key path of a JSON document ("[]" stands
// for array elements); null values contribute their key only.
func keyPaths(t *testing.T, raw []byte) []string {
	t.Helper()
	var v any
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	set := map[string]bool{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				p := prefix + "." + k
				set[p] = true
				walk(p, e)
			}
		case []any:
			for _, e := range x {
				walk(prefix+"[]", e)
			}
		}
	}
	walk("", v)
	return slices.Sorted(maps.Keys(set))
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesDir, name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return raw
}

func TestUIFixturesDecodeIntoCertauth(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(fixturesDir, "redeem-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no redeem fixtures in %s (%v)", fixturesDir, err)
	}
	for _, f := range files {
		name := filepath.Base(f)
		t.Run(name, func(t *testing.T) {
			got := decodeFixture(t, readFixture(t, name))
			switch got.Status {
			case "success":
				if got.Result == nil || got.Error != nil || got.Diagnostics != nil {
					t.Errorf("success shape: result %v, error %v, diagnostics %v; want a result only",
						got.Result != nil, got.Error != nil, got.Diagnostics != nil)
				}
			case "error":
				if got.Result != nil || got.Error == nil || got.Diagnostics == nil || got.Error.Code == "" {
					t.Errorf("error shape: result %v, error %+v, diagnostics %v; want error and diagnostics",
						got.Result != nil, got.Error, got.Diagnostics != nil)
				}
			default:
				t.Errorf("status = %q, want success or error", got.Status)
			}
		})
	}

	// Real responses have the shape and the key set of the fixtures.
	w := newE2EWorld(t)
	real := []struct {
		fixture string
		body    func(*testing.T) []byte
	}{
		{"redeem-success.json", w.flowSuccess},
		{"redeem-error-no-certificate.json", w.flowNoClientCertificate},
		{"redeem-invalid.json", w.flowReplayedCode},
	}
	for _, r := range real {
		t.Run("real "+r.fixture, func(t *testing.T) {
			body := r.body(t)
			decodeRedeem(t, body)
			got, want := keyPaths(t, body), keyPaths(t, readFixture(t, r.fixture))
			if !slices.Equal(got, want) {
				t.Errorf("key set differs from %s\nonly in the response: %q\nonly in the fixture: %q",
					r.fixture, setMinus(got, want), setMinus(want, got))
			}
		})
	}
}

// setMinus returns the elements of a missing from b (both sorted).
func setMinus(a, b []string) []string {
	var out []string
	for _, s := range a {
		if _, found := slices.BinarySearch(b, s); !found {
			out = append(out, s)
		}
	}
	return out
}
