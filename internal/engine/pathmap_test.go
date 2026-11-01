package engine

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// ppEnabled returns the loaded profile id of providerID.
func ppEnabled(t testing.TB, reg *profiles.Registry, providerID, id string) *profiles.Enabled {
	t.Helper()
	for _, e := range reg.Enabled(providerID) {
		if e.Profile.ID == id {
			return e
		}
	}
	t.Fatalf("profile %s of %s not enabled", id, providerID)
	return nil
}

func TestCriticalExtensionCopy(t *testing.T) {
	t.Parallel()
	now := tNow()
	p := newPPPKI(t, now)
	reg := tRegistry(t, p.providers, now)
	g2Shape := ppShapeNamed(t, "aoc-idcat-g2-qc")
	leaf := p.issue(t, g2Shape)
	if len(leaf.UnhandledCriticalExtensions) != 1 || !leaf.UnhandledCriticalExtensions[0].Equal(ppOIDQC) {
		t.Fatalf("fixture: UnhandledCriticalExtensions = %v, want [qcStatements]", leaf.UnhandledCriticalExtensions)
	}
	wantUnhandled := slices.Clone(leaf.UnhandledCriticalExtensions)
	g2 := ppEnabled(t, reg, "idcat", "aoc-idcat-g2")
	g3 := ppEnabled(t, reg, "idcat", "aoc-idcat-g3")

	t.Run("accepted under G2", func(t *testing.T) {
		res, err := p.check(t, g2Shape, leaf, ppOCSPUp, nil)
		if err != nil {
			t.Fatalf("Check error = %v, want success", err)
		}
		if res.Profile.ID != "aoc-idcat-g2" {
			t.Errorf("profile = %s, want aoc-idcat-g2", res.Profile.ID)
		}
		if !slices.EqualFunc(leaf.UnhandledCriticalExtensions, wantUnhandled, func(a, b asn1.ObjectIdentifier) bool { return a.Equal(b) }) {
			t.Errorf("leaf.UnhandledCriticalExtensions = %v after Check, want %v unchanged", leaf.UnhandledCriticalExtensions, wantUnhandled)
		}
		if !slices.Contains(res.Diagnostics.Certificate.CriticalExtensions, ppOIDQC.String()) {
			t.Errorf("diagnostics critical extensions = %v, want qcStatements listed", res.Diagnostics.Certificate.CriticalExtensions)
		}
	})

	t.Run("copy shares the signed bytes", func(t *testing.T) {
		cp := leafForProfile(leaf, g2.Profile)
		if cp == leaf {
			t.Fatal("leafForProfile returned the original for a handled critical extension, want a copy")
		}
		if &cp.Raw[0] != &leaf.Raw[0] || &cp.RawTBSCertificate[0] != &leaf.RawTBSCertificate[0] || &cp.Signature[0] != &leaf.Signature[0] {
			t.Error("copy does not share Raw/RawTBSCertificate/Signature with the leaf")
		}
		if len(cp.UnhandledCriticalExtensions) != 0 {
			t.Errorf("copy UnhandledCriticalExtensions = %v, want none", cp.UnhandledCriticalExtensions)
		}
		if len(leaf.UnhandledCriticalExtensions) != 1 {
			t.Errorf("leaf UnhandledCriticalExtensions = %v, want the original", leaf.UnhandledCriticalExtensions)
		}
		if _, err := cp.Verify(verifyOptions(g2.Roots, g2.Inter, now)); err != nil {
			t.Errorf("copy Verify = %v, want success", err)
		}
		tampered := *cp
		tbs := bytes.Clone(cp.RawTBSCertificate)
		tbs[len(tbs)-1] ^= 0xff
		tampered.RawTBSCertificate = tbs
		if _, err := tampered.Verify(verifyOptions(g2.Roots, g2.Inter, now)); err == nil {
			t.Error("copy with a tampered RawTBSCertificate verifies, want failure")
		}
		if got := leafForProfile(leaf, g3.Profile); got != leaf {
			t.Error("leafForProfile copied for a profile without handled extensions, want the original")
		}
	})

	t.Run("rejected under G3", func(t *testing.T) {
		s := ppShapeNamed(t, "aoc-idcat-g3")
		s.extra = []pkix.Extension{{Id: ppOIDQC, Critical: true, Value: ppQCStatements(t)}}
		res, err := p.check(t, s, p.issue(t, s), ppOCSPUp, nil)
		e := tErr(t, err)
		if res != nil || e.Code != CodeInvalidChain || e.Diagnostics.FailedStep != StepPath {
			t.Errorf("got (%s at %s), want (%s at %s); detail %q", e.Code, e.Diagnostics.FailedStep, CodeInvalidChain, StepPath, e.Detail)
		}
	})

	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"empty qcStatements", []byte{0x30, 0x00}},
		{"truncated qcStatements", []byte{0x30, 0x05, 0x30, 0x03, 0x06}},
		{"trailing bytes", append(ppQCStatements(t), 0x00)},
	} {
		t.Run("malformed under G2: "+tc.name, func(t *testing.T) {
			s := g2Shape
			s.extra = []pkix.Extension{{Id: ppOIDQC, Critical: true, Value: tc.value}}
			res, err := p.check(t, s, p.issue(t, s), ppOCSPUp, nil)
			e := tErr(t, err)
			if res != nil || e.Code != CodeInvalidChain || e.Diagnostics.FailedStep != StepPurpose {
				t.Errorf("got (%s at %s), want (%s at %s); detail %q", e.Code, e.Diagnostics.FailedStep, CodeInvalidChain, StepPurpose, e.Detail)
			}
		})
	}
}

func TestPathPriority(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)

	for _, tc := range []struct {
		name string
		ca   func(w *codeWorld) *testpki.CA
	}{
		{"usage beats unknown authority (first profile)", cwByA},
		{"usage beats unknown authority (second profile)", cwByB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := w.leaf(t, tc.ca(w), func(s *testpki.CertSpec) {
				s.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			})
			_, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf})
			e := tErr(t, err)
			if e.Code != CodeUnsupportedPurpose || e.Diagnostics.FailedStep != StepPath {
				t.Errorf("got (%s at %s), want (%s at %s)", e.Code, e.Diagnostics.FailedStep, CodeUnsupportedPurpose, StepPath)
			}
			if n := len(e.Diagnostics.ProfileCandidates); n != 2 {
				t.Errorf("%d profile candidates, want 2", n)
			}
		})
	}

	t.Run("usage beats an expired anchor", func(t *testing.T) {
		// Two pinned certificates of one CA (same DN and key, a re-issued
		// anchor): the leaf fails IncompatibleUsage under the valid one and
		// Expired under the other; the more specific usage error wins.
		now := w.now
		key := tKey(t, "delta-root", testpki.ECDSAP256)
		valid := testpki.NewRoot(t, "Delta Root", testpki.CertSpec{Now: now, KeyPair: key, NotBefore: now.Add(-10 * 24 * time.Hour)})
		expired := testpki.NewRoot(t, "Delta Root", testpki.CertSpec{Now: now, KeyPair: key,
			NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
		profile := func(id, policy string, root *testpki.CA) profiles.Profile {
			return profiles.Profile{ID: id, ProviderID: "delta", Name: id, HolderRole: profiles.RoleNaturalPerson,
				Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{policy},
				EKU: profiles.EKURequireClientAuth, Identity: tPlainAdapter(), Revocation: revocation.Policy{OCSPHosts: []string{cwOCSPHost}}}
		}
		a, b := profile("delta-valid", cwPolicyA, valid), profile("delta-expired", cwPolicyB, expired)
		leaf := w.leaf(t, valid, func(s *testpki.CertSpec) {
			s.NotBefore = now.Add(-5 * 24 * time.Hour)
			s.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		})
		for _, order := range [][]profiles.Profile{{a, b}, {b, a}} {
			chk := tHandler(t, []profiles.Provider{{ID: "delta", Name: "Delta", Profiles: order}}, now.Add(-48*time.Hour), now, tRevocation(t, testpki.NewNet(), now))
			_, err := chk.VerifyAs(t.Context(), "delta", []*x509.Certificate{leaf})
			e := tErr(t, err)
			if e.Code != CodeUnsupportedPurpose || e.Diagnostics.FailedStep != StepPath {
				t.Errorf("order %s first: got (%s at %s, %q), want (%s at %s)", order[0].ID, e.Code, e.Diagnostics.FailedStep, e.Detail, CodeUnsupportedPurpose, StepPath)
			}
		}
	})

	t.Run("expired leaf of another provider", func(t *testing.T) {
		leaf := w.leaf(t, w.rootC, func(s *testpki.CertSpec) {
			s.NotBefore, s.NotAfter = s.Now.Add(-48*time.Hour), s.Now.Add(-24*time.Hour)
		})
		_, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf})
		e := tErr(t, err)
		if e.Code != CodeExpired || e.Diagnostics.FailedStep != StepPath {
			t.Errorf("got (%s at %s), want (%s at %s)", e.Code, e.Diagnostics.FailedStep, CodeExpired, StepPath)
		}
	})

	t.Run("expired anchor", func(t *testing.T) {
		now := w.now
		root := testpki.NewRoot(t, "Gamma Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "gamma-root", testpki.ECDSAP256),
			NotBefore: now.Add(-10 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
		prof := profiles.Profile{ID: "gamma-a", ProviderID: "gamma", Name: "Gamma", HolderRole: profiles.RoleNaturalPerson,
			Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{cwPolicyA},
			EKU: profiles.EKURequireClientAuth, Identity: tPlainAdapter(),
			Revocation: revocation.Policy{OCSPHosts: []string{cwOCSPHost}}}
		// The registry loaded while the anchor was valid; the clock moved on.
		chk := tHandler(t, []profiles.Provider{{ID: "gamma", Name: "Gamma", Profiles: []profiles.Profile{prof}}}, now.Add(-48*time.Hour), now, tRevocation(t, testpki.NewNet(), now))
		leaf := w.leaf(t, root, func(s *testpki.CertSpec) {
			s.NotBefore, s.NotAfter = now.Add(-5*24*time.Hour), now.Add(30*24*time.Hour)
		})
		_, err := chk.VerifyAs(t.Context(), "gamma", []*x509.Certificate{leaf})
		e := tErr(t, err)
		if e.Code != CodeInvalidChain || e.Diagnostics.FailedStep != StepPath || !strings.Contains(e.Detail, "anchor or intermediate outside validity") {
			t.Errorf("got (%s at %s, %q), want (%s at %s, anchor outside validity)", e.Code, e.Diagnostics.FailedStep, e.Detail, CodeInvalidChain, StepPath)
		}
	})

	t.Run("unhandled critical extension under another provider's anchor", func(t *testing.T) {
		leaf := w.leaf(t, w.rootC, func(s *testpki.CertSpec) {
			s.Policies = []asn1.ObjectIdentifier{tOID(t, cwPolicyC)}
			s.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1}, Critical: true, Value: []byte{0x05, 0x00}}}
		})
		_, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf})
		e := tErr(t, err)
		if e.Code != CodeProviderMismatch || e.Diagnostics.FailedStep != StepPath {
			t.Errorf("got (%s at %s), want (%s at %s)", e.Code, e.Diagnostics.FailedStep, CodeProviderMismatch, StepPath)
		}
	})

	t.Run("identity detail names the rule, not the value", func(t *testing.T) {
		leaf := w.leaf(t, w.rootA, func(s *testpki.CertSpec) { s.Subject = tPerson("IDCES-12345678A", cwGiven, cwSurnames) })
		_, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf})
		e := tErr(t, err)
		for _, v := range []string{"12345678A", cwGiven, cwSurnames} {
			if strings.Contains(e.Detail, v) {
				t.Errorf("detail %q contains the certificate value %q", e.Detail, v)
			}
		}
		if !strings.Contains(e.Detail, identity.ErrInvalid.Error()) {
			t.Errorf("detail %q, want the identity rule", e.Detail)
		}
	})
}

// specimenQCStatements returns the qcStatements values of the committed
// specimens (real issuer bytes).
func specimenQCStatements(t testing.TB) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "specimens", "*.pem"))
	if err != nil || len(files) == 0 {
		t.Fatalf("specimens: %v (%d files)", err, len(files))
	}
	out := map[string][]byte{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(raw)
		if blk == nil {
			t.Fatalf("%s: no PEM block", f)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, e := range c.Extensions {
			if e.Id.Equal(ppOIDQC) {
				out[filepath.Base(f)] = e.Value
			}
		}
	}
	return out
}

func TestParseQCStatementsSpecimens(t *testing.T) {
	vals := specimenQCStatements(t)
	if len(vals) < 20 {
		t.Fatalf("%d specimens with qcStatements, want the 24 committed ones", len(vals))
	}
	for f, v := range vals {
		if err := parseQCStatements(v); err != nil {
			t.Errorf("%s: parseQCStatements = %v, want nil", f, err)
		}
	}
}

func FuzzParseQCStatements(f *testing.F) {
	for _, v := range specimenQCStatements(f) {
		f.Add(v)
	}
	f.Add(ppQCStatements(f))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		err := parseQCStatements(der)
		if err == nil && (len(der) < 2 || der[0] != 0x30) {
			t.Errorf("accepted %x, want a DER SEQUENCE", der)
		}
		if err != nil && err.Error() != "malformed qcStatements" {
			t.Errorf("error %q leaks parser detail", err)
		}
	})
}
