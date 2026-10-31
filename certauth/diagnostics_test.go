package certauth

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/testpki"
)

var tDiagIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// tStepRank orders the pipeline steps.
var tStepRank = map[Step]int{StepBounds: 1, StepAlgorithms: 2, StepPath: 3, StepProfile: 4, StepPurpose: 5,
	StepTestMarker: 6, StepIdentity: 7, StepRevocation: 8}

func TestDiagnosticsComplete(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)
	var (
		mu  sync.Mutex
		ids = map[string]string{}
	)
	t.Run("rows", func(t *testing.T) {
		for _, c := range codeCases() {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				chain, res, err := w.run(t, c)
				var d Diagnostics
				if c.want == "" {
					if err != nil {
						t.Fatalf("Check error = %v, want success", err)
					}
					d = res.Diagnostics
					if d.FailedStep != "" || d.Code != "" || d.TechnicalDetail != "" {
						t.Errorf("step/code/detail = %q/%q/%q, want empty on success", d.FailedStep, d.Code, d.TechnicalDetail)
					}
				} else {
					d = tErr(t, err).Diagnostics
					if d.FailedStep == "" || d.Code == "" || d.TechnicalDetail == "" {
						t.Errorf("step/code/detail = %q/%q/%q, want all set", d.FailedStep, d.Code, d.TechnicalDetail)
					}
				}
				mu.Lock()
				if prev, dup := ids[d.DiagnosticID]; dup {
					t.Errorf("diagnosticId %s already used by %q", d.DiagnosticID, prev)
				}
				ids[d.DiagnosticID] = c.name
				mu.Unlock()

				if !tDiagIDRe.MatchString(d.DiagnosticID) {
					t.Errorf("diagnosticId = %q, want 32 lowercase hex digits", d.DiagnosticID)
				}
				if !d.Time.Equal(w.now) || d.Time.Location() != time.UTC {
					t.Errorf("time = %v, want the clock %v in UTC", d.Time, w.now)
				}
				if d.Provider == "" || d.ServerVersion != "test" {
					t.Errorf("provider/serverVersion = %q/%q, want set/test", d.Provider, d.ServerVersion)
				}
				if leafGiven := len(chain) > 0 && chain[0] != nil; leafGiven {
					if d.Certificate == nil {
						t.Error("certificate = nil, want the presented leaf described")
					} else if d.Certificate.SHA256 != testpki.SHA256Hex(chain[0].Raw) {
						t.Errorf("certificate sha256 = %s, want %s", d.Certificate.SHA256, testpki.SHA256Hex(chain[0].Raw))
					}
				} else if d.Certificate != nil {
					t.Errorf("certificate = %+v, want nil without a leaf", d.Certificate)
				}
				received := 0
				for _, cert := range chain {
					if cert != nil {
						received++
					}
				}
				if len(d.Chain) != received {
					t.Errorf("%d chain entries, want %d (one per received certificate)", len(d.Chain), received)
				}
				if (c.want == "" || tStepRank[c.step] >= tStepRank[StepPath]) && len(d.ProfileCandidates) == 0 {
					t.Error("profileCandidates empty, want the per-profile outcomes")
				}
				if (c.want == "" || c.step == StepRevocation) && len(d.RevocationAttempts) == 0 {
					t.Error("revocationAttempts empty, want the attempts")
				}
				if c.want != "" && tStepRank[c.step] < tStepRank[StepRevocation] && len(d.RevocationAttempts) != 0 {
					t.Errorf("%d revocation attempts before step revocation, want 0", len(d.RevocationAttempts))
				}
			})
		}
	})
	if len(ids) != len(codeCases()) {
		t.Errorf("%d distinct diagnostic IDs for %d rows", len(ids), len(codeCases()))
	}
}

func TestLogAttrsNoPII(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)
	good := w.leaf(t, w.rootA, nil)
	revoked := w.leaf(t, w.rootA, nil)
	w.answer(revoked.SerialNumber, testpki.OCSPSpec{Status: testpki.Revoked, NextUpdate: w.now.Add(time.Hour)})

	res, err := w.chk.Check(t.Context(), "alpha", []*x509.Certificate{good})
	if err != nil {
		t.Fatalf("Check(good) error = %v", err)
	}
	_, err = w.chk.Check(t.Context(), "alpha", []*x509.Certificate{revoked, w.rootA.Cert})
	failure := tErr(t, err)
	if failure.Code != CodeRevoked {
		t.Fatalf("Check(revoked) code = %s, want %s", failure.Code, CodeRevoked)
	}

	for _, tc := range []struct {
		name string
		leaf *x509.Certificate
		d    Diagnostics
	}{
		{"success", good, res.Diagnostics},
		{"failure", revoked, failure.Diagnostics},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "certauth outcome", tc.d.LogAttrs()...)
			out := buf.String()
			for _, pii := range []string{
				tc.leaf.Subject.String(), cwGiven, "GARCÍA", "LÓPEZ", cwSurnames, cwDNI,
				fmt.Sprintf("%x", tc.leaf.SerialNumber), testpki.SHA256Hex(tc.leaf.Raw), cwOCSPPath,
			} {
				if strings.Contains(out, pii) {
					t.Errorf("log line contains %q:\n%s", pii, out)
				}
			}
			for _, want := range []string{tc.d.DiagnosticID, cwOCSPHost, w.rootA.Cert.Subject.String(), cwPolicyA, "alpha-a"} {
				if !strings.Contains(out, want) {
					t.Errorf("log line lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestDescribeTLS(t *testing.T) {
	if DescribeTLS(nil) != nil {
		t.Error("DescribeTLS(nil) != nil")
	}
	w := newCodeWorld(t)
	leaf := w.leaf(t, w.rootA, nil)
	got := DescribeTLS(&tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		ServerName: "alpha.auth.example.test", PeerCertificates: []*x509.Certificate{leaf, w.rootA.Cert}})
	want := TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", SNI: "alpha.auth.example.test",
		ClientCertificatePresented: true, ChainLength: 2}
	if *got != want {
		t.Errorf("DescribeTLS = %+v, want %+v", *got, want)
	}
	if got := DescribeTLS(&tls.ConnectionState{Version: tls.VersionTLS12}); got.ClientCertificatePresented || got.ChainLength != 0 {
		t.Errorf("DescribeTLS without a client certificate = %+v", got)
	}
}

func TestDescribeCertificate(t *testing.T) {
	w := newCodeWorld(t)
	leaf := w.leaf(t, w.rootA, func(s *testpki.CertSpec) {
		s.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection}
		s.CDP = []testpki.DistributionPoint{{URIs: []string{"http://crl.alpha.test/a.crl"}}}
		s.CAIssuers = []string{"http://ca.alpha.test/a.crt"}
	})
	d := describeCertificate(leaf)
	if d.KeyAlgorithm != "ECDSA-P-256" || d.SignatureAlgorithm != "ECDSA-SHA256" {
		t.Errorf("key/signature algorithm = %s/%s, want ECDSA-P-256/ECDSA-SHA256", d.KeyAlgorithm, d.SignatureAlgorithm)
	}
	for _, c := range []struct {
		field     string
		got, want []string
	}{
		{"keyUsage", d.KeyUsage, []string{"digitalSignature", "contentCommitment"}},
		{"extKeyUsage", d.ExtKeyUsage, []string{"clientAuth", "emailProtection"}},
		{"policyOids", d.PolicyOIDs, []string{cwPolicyA}},
		{"criticalExtensions", d.CriticalExtensions, []string{"2.5.29.15", "2.5.29.19"}},
		{"ocspUrls", d.OCSPURLs, []string{cwOCSPURL}},
		{"caIssuerUrls", d.CAIssuerURLs, []string{"http://ca.alpha.test/a.crt"}},
		{"cdpUrls", d.CDPURLs, []string{"http://crl.alpha.test/a.crl"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	rsaLeaf := w.leaf(t, w.rootB, func(s *testpki.CertSpec) { s.KeyPair = tKey(t, "leaf", testpki.RSA2048) })
	if got := keyAlgorithm(rsaLeaf); got != "RSA-2048" {
		t.Errorf("keyAlgorithm(RSA) = %s, want RSA-2048", got)
	}
}
