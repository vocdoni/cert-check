package engine

import (
	"cmp"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// Shared helpers of the pipeline tests. The tests are package-internal so
// that pathmap_test and purpose_test can reach leafForProfile and purposeOK.

// tDiscard drops the registry and revocation logs of the tests.
var tDiscard = slog.New(slog.DiscardHandler)

var (
	tKeysMu sync.Mutex
	tKeys   = map[string]crypto.Signer{}
)

// tKey returns the key cached under slot, generating it on first use. Keys
// are shared across tests to keep RSA generation off the critical path;
// certificates that must not share a key use different slots.
func tKey(t testing.TB, slot string, spec testpki.KeySpec) crypto.Signer {
	t.Helper()
	tKeysMu.Lock()
	defer tKeysMu.Unlock()
	id := slot + "/" + strconv.Itoa(int(spec))
	if k, ok := tKeys[id]; ok {
		return k
	}
	k := testpki.NewKey(t, spec)
	tKeys[id] = k
	return k
}

// tNow is the fixed clock of one synthetic test.
func tNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// tOID parses a dotted OID.
func tOID(t testing.TB, dotted string) asn1.ObjectIdentifier {
	t.Helper()
	var oid asn1.ObjectIdentifier
	for part := range strings.SplitSeq(dotted, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			t.Fatalf("oid %q: %v", dotted, err)
		}
		oid = append(oid, n)
	}
	return oid
}

// tRevocation is a revocation checker on the fake network n with the clock
// fixed at now.
func tRevocation(t testing.TB, n *testpki.Net, now time.Time) *revocation.Checker {
	t.Helper()
	rc, err := revocation.NewChecker(revocation.Options{
		UserAgent: "cert-check/test", DialContext: n.DialContext, Now: func() time.Time { return now },
		Logger: tDiscard, OCSPTimeout: 2 * time.Second, CRLTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	return rc
}

// tRegistry loads providers at regNow with the production reserved identities.
func tRegistry(t testing.TB, providers []profiles.Provider, regNow time.Time) *profiles.Registry {
	t.Helper()
	reg, err := profiles.New(profiles.Config{Providers: providers, Reserved: identity.DefaultReserved(), Now: regNow, Logger: tDiscard})
	if err != nil {
		t.Fatalf("profiles.New: %v", err)
	}
	return reg
}

// tHandler builds one Provider per declaration, loaded at loadNow with the
// production reserved identities and clocked at now afterwards, and a Handler
// over the enabled ones (the registry hid the others). Handler.VerifyAs is
// what Checker.Check was.
func tHandler(t testing.TB, providers []profiles.Provider, loadNow, now time.Time, rc *revocation.Checker) *certcheck.Handler {
	t.Helper()
	var ps []certcheck.Provider
	for _, d := range providers {
		clock := loadNow // New reads the clock once, as the load time
		p, err := New(Config{Provider: d, Revocation: rc, Now: func() time.Time { return clock }, Logger: tDiscard, Version: "test"})
		if err != nil {
			t.Fatalf("New(%s): %v", d.ID, err)
		}
		clock = now
		if len(p.CAs()) > 0 {
			ps = append(ps, p)
		}
	}
	h, err := certcheck.NewHandler(ps, certcheck.WithClock(func() time.Time { return now }), certcheck.WithVersion("test"))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// tPerson is the common natural-person subject: C, serialNumber, GN, SN, CN.
func tPerson(doc, given, surnames string) testpki.Name {
	return testpki.Name{
		testpki.Printable(testpki.OIDCountry, "ES"),
		testpki.Printable(testpki.OIDSerialNumber, doc),
		testpki.UTF8(testpki.OIDGivenName, given),
		testpki.UTF8(testpki.OIDSurname, surnames),
		testpki.UTF8(testpki.OIDCommonName, given+" "+surnames),
	}
}

// tPlainAdapter: IDCES-<DNI|NIE> in serialNumber, complete surnames in SN.
func tPlainAdapter() identity.Adapter {
	return identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}}},
		Surnames:  identity.SurnamesFromSN, SAN: identity.SANCheck{Kind: identity.SANNone},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
}

// tErr returns err as *Error or stops the test.
func tErr(t testing.TB, err error) *Error {
	t.Helper()
	e, ok := errors.AsType[*Error](err)
	if !ok {
		t.Fatalf("error = %v (%T), want *Error", err, err)
	}
	return e
}

// tUnavailable answers every request with 503.
var tUnavailable = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "unavailable", http.StatusServiceUnavailable)
})

// tStall drains the request (so the server notices the client leaving) and
// answers only after the client gives up, or after 10 s.
var tStall = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body) // test handler: a read error only ends the wait sooner
	select {
	case <-r.Context().Done():
	case <-time.After(10 * time.Second):
	}
	http.Error(w, "too late", http.StatusServiceUnavailable)
})

// tSites groups handlers by host for a fake network.
type tSites struct {
	muxes map[string]*http.ServeMux
	seen  map[string]bool
}

// handle registers h for the host and path of rawURL (the whole host when
// the path is empty). A URL registered twice keeps its first handler.
func (s *tSites) handle(t testing.TB, rawURL string, h http.Handler) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" {
		t.Fatalf("site URL %q: want an http URL (%v)", rawURL, err)
	}
	if s.muxes == nil {
		s.muxes, s.seen = map[string]*http.ServeMux{}, map[string]bool{}
	}
	pattern := cmp.Or(u.Path, "/")
	if s.seen[u.Host+pattern] {
		return
	}
	s.seen[u.Host+pattern] = true
	mux := s.muxes[u.Host]
	if mux == nil {
		mux = http.NewServeMux()
		s.muxes[u.Host] = mux
	}
	mux.Handle(pattern, h)
}

// net serves every host on a new fake network.
func (s *tSites) net(t testing.TB) *testpki.Net {
	t.Helper()
	n := testpki.NewNet()
	for host, mux := range s.muxes {
		n.Serve(t, host, mux)
	}
	return n
}

// The code world: provider "alpha" with profiles alpha-a (P-256 anchor) and
// alpha-b (RSA anchor, MinRSABits 3072), provider "beta" with one profile.
const (
	cwPolicyA  = "1.3.6.1.4.1.99999.1.1"
	cwPolicyB  = "1.3.6.1.4.1.99999.1.2"
	cwPolicyC  = "1.3.6.1.4.1.99999.2.1"
	cwOCSPHost = "ocsp.alpha.test"
	cwOCSPPath = "/ocsp-responder-path"
	cwOCSPURL  = "http://" + cwOCSPHost + cwOCSPPath
	cwDownURL  = "http://down.alpha.test/"
	cwSlowURL  = "http://slow.alpha.test/"
	cwDNI      = "12345679S"
	cwGiven    = "JUAN"
	cwSurnames = "GARCÍA LÓPEZ"
)

type codeWorld struct {
	now                 time.Time
	rootA, rootB, rootC *testpki.CA
	ocsp                *testpki.OCSPServer
	marker              *x509.Certificate // alpha-a leaf pinned as a fingerprint marker
	chk                 *certcheck.Handler

	mu      sync.Mutex
	answers map[string]func(testpki.Request) testpki.OCSPSpec // OCSP answer by leaf serial; default good, nextUpdate +1h
}

func newCodeWorld(t *testing.T) *codeWorld {
	t.Helper()
	now := tNow()
	w := &codeWorld{now: now, answers: map[string]func(testpki.Request) testpki.OCSPSpec{}}
	w.rootA = testpki.NewRoot(t, "Alpha A Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "cw-rootA", testpki.ECDSAP256)})
	w.rootB = testpki.NewRoot(t, "Alpha B Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "cw-rootB", testpki.RSA2048)})
	w.rootC = testpki.NewRoot(t, "Beta Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "cw-rootC", testpki.ECDSAP256)})
	w.ocsp = testpki.NewOCSPServer(w.rootA, w.rootA.OCSPResponder(t, testpki.CertSpec{Now: now}))
	w.ocsp.SetAnswer(func(req testpki.Request) testpki.OCSPSpec {
		w.mu.Lock()
		answer, ok := w.answers[req.Serial.String()]
		w.mu.Unlock()
		spec := testpki.OCSPSpec{NextUpdate: now.Add(time.Hour)}
		if ok {
			spec = answer(req)
		}
		spec.Now = now
		return spec
	})
	var sites tSites
	sites.handle(t, cwOCSPURL, w.ocsp.Handler(t))
	sites.handle(t, cwDownURL, tUnavailable)
	sites.handle(t, cwSlowURL, tStall)
	w.marker = w.leaf(t, w.rootA, nil)

	rev := revocation.Policy{
		OCSPHosts: []string{cwOCSPHost, "down.alpha.test", "slow.alpha.test"},
		CRLHosts:  []string{"crl.alpha.test"}, AllowCRL: true, OCSPNonce: true,
	}
	profile := func(id, provider string, root *testpki.CA, policy string) profiles.Profile {
		return profiles.Profile{ID: id, ProviderID: provider, Name: id, HolderRole: profiles.RoleNaturalPerson,
			Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{policy},
			EKU: profiles.EKURequireClientAuth, Identity: tPlainAdapter(), Revocation: rev}
	}
	a := profile("alpha-a", "alpha", w.rootA, cwPolicyA)
	a.TestMarkers = []profiles.TestMarker{
		{SHA256: testpki.SHA256Hex(w.marker.Raw), Source: "test fingerprint"},
		{Subject: []profiles.AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}}, Source: "test subject"},
	}
	b := profile("alpha-b", "alpha", w.rootB, cwPolicyB)
	b.Algorithms = profiles.AlgPolicy{MinRSABits: 3072}
	providers := []profiles.Provider{
		{ID: "alpha", Name: "Alpha", Profiles: []profiles.Profile{a, b}},
		{ID: "beta", Name: "Beta", Profiles: []profiles.Profile{profile("beta-a", "beta", w.rootC, cwPolicyC)}},
	}
	w.chk = tHandler(t, providers, now, now, tRevocation(t, sites.net(t), now))
	return w
}

// leaf issues an alpha-a leaf (P-256, KU DS|NR, EKU clientAuth, OCSP at
// cwOCSPURL, no CDP) modified by edit.
func (w *codeWorld) leaf(t testing.TB, ca *testpki.CA, edit func(*testpki.CertSpec)) *x509.Certificate {
	t.Helper()
	spec := testpki.CertSpec{
		Now:         w.now,
		Subject:     tPerson("IDCES-"+cwDNI, cwGiven, cwSurnames),
		KeyPair:     tKey(t, "leaf", testpki.ECDSAP256),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies:    []asn1.ObjectIdentifier{tOID(t, cwPolicyA)},
		OCSPServers: []string{cwOCSPURL},
	}
	if edit != nil {
		edit(&spec)
	}
	return ca.Leaf(t, spec).Cert
}

// answer sets the OCSP answer for serial.
func (w *codeWorld) answer(serial *big.Int, spec testpki.OCSPSpec) {
	w.answerFunc(serial, func(testpki.Request) testpki.OCSPSpec { return spec })
}

// answerFunc sets the OCSP answer for serial per request.
func (w *codeWorld) answerFunc(serial *big.Int, f func(testpki.Request) testpki.OCSPSpec) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.answers[serial.String()] = f
}

// codeCase is one row of TestCheckCodes (and TestDiagnosticsComplete).
type codeCase struct {
	name     string
	provider string // "" = "alpha"
	chain    func(t *testing.T, w *codeWorld) []*x509.Certificate
	timeout  time.Duration // > 0: Check runs under this deadline
	want     ErrorCode     // "" = success
	step     Step
	detail   string // substring of Error.Detail; "" = not checked
}

// run executes c and returns the chain it presented.
func (w *codeWorld) run(t *testing.T, c codeCase) ([]*x509.Certificate, *Result, error) {
	t.Helper()
	chain := c.chain(t, w)
	ctx := t.Context()
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	res, err := w.chk.VerifyAs(ctx, cmp.Or(c.provider, "alpha"), chain)
	return chain, res, err
}

// cwChain returns a chain holding the alpha-a leaf modified by edit, issued by ca.
func cwChain(ca func(w *codeWorld) *testpki.CA, edit func(*testpki.CertSpec)) func(*testing.T, *codeWorld) []*x509.Certificate {
	return func(t *testing.T, w *codeWorld) []*x509.Certificate {
		return []*x509.Certificate{w.leaf(t, ca(w), edit)}
	}
}

func cwByA(w *codeWorld) *testpki.CA { return w.rootA }
func cwByB(w *codeWorld) *testpki.CA { return w.rootB }

// cwWithAnswer returns an alpha-a leaf whose OCSP answer is spec.
func cwWithAnswer(spec testpki.OCSPSpec) func(*testing.T, *codeWorld) []*x509.Certificate {
	return func(t *testing.T, w *codeWorld) []*x509.Certificate {
		l := w.leaf(t, w.rootA, nil)
		spec.NextUpdate = w.now.Add(time.Hour)
		w.answer(l.SerialNumber, spec)
		return []*x509.Certificate{l}
	}
}

func codeCases() []codeCase {
	policy := func(t *testing.T, p string) []asn1.ObjectIdentifier { return []asn1.ObjectIdentifier{tOID(t, p)} }
	return []codeCase{
		{name: "ok", chain: cwChain(cwByA, nil)},
		{name: "expired", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.NotBefore, s.NotAfter = s.Now.Add(-48*time.Hour), s.Now.Add(-24*time.Hour)
		}), want: CodeExpired, step: StepPath},
		{name: "not yet valid", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.NotBefore, s.NotAfter = s.Now.Add(time.Hour), s.Now.Add(48*time.Hour)
		}), want: CodeNotYetValid, step: StepPath},
		{name: "unknown CA", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			unknown := testpki.NewRoot(t, "Unknown Root", testpki.CertSpec{Now: w.now, KeyPair: tKey(t, "cw-unknown", testpki.ECDSAP256)})
			return []*x509.Certificate{w.leaf(t, unknown, nil)}
		}, want: CodeUntrustedIssuer, step: StepPath},
		{name: "another provider's leaf", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.leaf(t, w.rootC, func(s *testpki.CertSpec) { s.Policies = policy(t, cwPolicyC) })}
		}, want: CodeProviderMismatch, step: StepPath},
		{name: "no allowlisted policy", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.leaf(t, w.rootA, func(s *testpki.CertSpec) { s.Policies = policy(t, "1.3.6.1.4.1.99999.9.9") })}
		}, want: CodeUnsupportedProfile, step: StepProfile},
		{name: "policy of another profile of the provider", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.leaf(t, w.rootA, func(s *testpki.CertSpec) { s.Policies = policy(t, cwPolicyB) })}
		}, want: CodeUnsupportedProfile, step: StepProfile},
		{name: "KU without digitalSignature", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.KeyUsage = x509.KeyUsageContentCommitment
		}), want: CodeUnsupportedPurpose, step: StepPurpose, detail: "digitalSignature"},
		{name: "EKU emailProtection only", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		}), want: CodeUnsupportedPurpose, step: StepPath},
		{name: "RSA-1024", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.leaf(t, w.rootA, func(s *testpki.CertSpec) { s.KeyPair = tKey(t, "leaf", testpki.RSA1024) })}
		}, want: CodeWeakAlgorithm, step: StepAlgorithms, detail: "RSA key 1024 bits"},
		{name: "SHA-1 signature", chain: cwChain(cwByB, func(s *testpki.CertSpec) {
			s.SignatureAlgorithm = x509.SHA1WithRSA
		}), want: CodeWeakAlgorithm, step: StepAlgorithms, detail: "signature algorithm"},
		{name: "P-224", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.leaf(t, w.rootA, func(s *testpki.CertSpec) { s.KeyPair = tKey(t, "leaf", testpki.ECDSAP224) })}
		}, want: CodeWeakAlgorithm, step: StepAlgorithms, detail: "P-224"},
		{name: "RSA-2048 under MinRSABits 3072", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.leaf(t, w.rootB, func(s *testpki.CertSpec) {
				s.KeyPair, s.Policies = tKey(t, "leaf", testpki.RSA2048), policy(t, cwPolicyB)
			})}
		}, want: CodeWeakAlgorithm, step: StepAlgorithms, detail: "minimum 3072"},
		{name: "unknown critical extension", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 1}, Critical: true, Value: asn1.NullBytes}}
		}), want: CodeInvalidChain, step: StepPath},
		{name: "fingerprint marker", chain: func(_ *testing.T, w *codeWorld) []*x509.Certificate {
			return []*x509.Certificate{w.marker}
		}, want: CodeTestCertificate, step: StepTestMarker, detail: "known specimen fingerprint"},
		{name: "subject marker NOMDOS", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.Subject = tPerson("IDCES-"+cwDNI, "NOMDOS", "ESPECIMENDOS ESPECIMENDOS")
		}), want: CodeTestCertificate, step: StepTestMarker, detail: "documented test subject marker"},
		{name: "reserved document", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.Subject = tPerson("IDCES-99999999R", cwGiven, cwSurnames)
		}), want: CodeTestCertificate, step: StepTestMarker, detail: "reserved identity: reserved_document"},
		{name: "surname marker", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.Subject = tPerson("IDCES-"+cwDNI, cwGiven, "PRUEBAS GARCÍA")
		}), want: CodeTestCertificate, step: StepTestMarker, detail: "reserved identity: surname_marker"},
		{name: "bad checksum", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.Subject = tPerson("IDCES-12345678A", cwGiven, cwSurnames)
		}), want: CodeIdentityInvalid, step: StepIdentity},
		{name: "PASES document", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.Subject = tPerson("PASES-AB1234567", cwGiven, cwSurnames)
		}), want: CodeIdentityUnsupportedDocument, step: StepIdentity},
		{name: "OCSP revoked", chain: cwWithAnswer(testpki.OCSPSpec{Status: testpki.Revoked}), want: CodeRevoked, step: StepRevocation},
		{name: "OCSP unknown", chain: cwWithAnswer(testpki.OCSPSpec{Status: testpki.Unknown}), want: CodeRevocationUnknown, step: StepRevocation},
		{name: "OCSP down and no CRL", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.OCSPServers = []string{cwDownURL}
		}), want: CodeRevocationUnavailable, step: StepRevocation},
		{name: "context deadline", chain: cwChain(cwByA, func(s *testpki.CertSpec) {
			s.OCSPServers = []string{cwSlowURL}
		}), timeout: 300 * time.Millisecond, want: CodeInternal, step: StepRevocation, detail: "deadline"},
		{name: "chain of 11", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			chain := []*x509.Certificate{w.leaf(t, w.rootA, nil)}
			for range DefaultMaxChainLen {
				chain = append(chain, w.rootA.Cert)
			}
			return chain
		}, want: CodeInvalidChain, step: StepBounds, detail: "chain length 11"},
		{name: "certificate over 16 KiB", chain: func(t *testing.T, w *codeWorld) []*x509.Certificate {
			value, err := asn1.Marshal(make([]byte, 17<<10))
			if err != nil {
				t.Fatal(err)
			}
			return []*x509.Certificate{w.leaf(t, w.rootA, func(s *testpki.CertSpec) {
				s.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7, 2}, Value: value}}
			})}
		}, want: CodeInvalidChain, step: StepBounds, detail: "larger than"},
		{name: "empty chain", chain: func(*testing.T, *codeWorld) []*x509.Certificate { return nil },
			want: CodeNoCertificate, step: StepBounds},
		{name: "nil leaf", chain: func(*testing.T, *codeWorld) []*x509.Certificate { return []*x509.Certificate{nil} },
			want: CodeNoCertificate, step: StepBounds},
		{name: "unknown provider", provider: "nope", chain: cwChain(cwByA, nil), want: CodeProviderMismatch, step: StepBounds},
	}
}

func TestCheckCodes(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)
	for _, c := range codeCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, res, err := w.run(t, c)
			if c.want == "" {
				if err != nil {
					t.Fatalf("Check error = %v, want success", err)
				}
				if res.Diagnostics.FailedStep != "" || res.Diagnostics.Code != "" {
					t.Errorf("diagnostics step/code = %q/%q, want empty on success", res.Diagnostics.FailedStep, res.Diagnostics.Code)
				}
				if res.Provider.ID != "alpha" || res.Profile.ID != "alpha-a" || res.Profile.HolderRole != profiles.RoleNaturalPerson {
					t.Errorf("provider/profile = %+v/%+v, want alpha/alpha-a natural_person", res.Provider, res.Profile)
				}
				if got := res.Identity.Document; got.Number != cwDNI || got.Type != identity.DocumentDNI || got.Raw != "IDCES-"+cwDNI {
					t.Errorf("document = %+v, want DNI %s", got, cwDNI)
				}
				if got, want := res.Certificate.Issuer, w.rootA.Cert.Subject.CommonName; got != want {
					t.Errorf("certificate issuer = %q, want the issuer CN %q", got, want)
				}
				if got := res.Revocation; got.Status != revocation.StatusGood || got.Method != revocation.MethodOCSP || got.Source != cwOCSPHost || got.NextUpdate == nil {
					t.Errorf("revocation = %+v, want good via OCSP from %s with nextUpdate", got, cwOCSPHost)
				}
				if !res.ValidatedAt.Equal(w.now) {
					t.Errorf("validatedAt = %v, want %v", res.ValidatedAt, w.now)
				}
				return
			}
			if res != nil {
				t.Errorf("Result = %+v, want nil on failure", res)
			}
			e := tErr(t, err)
			if e.Code != c.want || e.Diagnostics.FailedStep != c.step {
				t.Errorf("got (%s at %s), want (%s at %s); detail %q", e.Code, e.Diagnostics.FailedStep, c.want, c.step, e.Detail)
			}
			if e.Retryable != c.want.Retryable() {
				t.Errorf("Retryable = %v, want %v", e.Retryable, c.want.Retryable())
			}
			if e.Diagnostics.Code != e.Code || e.Diagnostics.TechnicalDetail != e.Detail {
				t.Errorf("diagnostics code/detail = %q/%q, want %q/%q", e.Diagnostics.Code, e.Diagnostics.TechnicalDetail, e.Code, e.Detail)
			}
			if c.detail != "" && !strings.Contains(e.Detail, c.detail) {
				t.Errorf("detail = %q, want it to contain %q", e.Detail, c.detail)
			}
			if got, want := e.Error(), "certcheck: "+string(e.Code)+": "+e.Detail; got != want {
				t.Errorf("Error() = %q, want %q", got, want)
			}
		})
	}
}

// TestVerifyCanceledContextWithGoodCache: cached good evidence answers
// without a fetch, yet a cancelled or expired validation is never a success
// (the Provider contract: a deadline hit is a retryable internal error).
func TestVerifyCanceledContextWithGoodCache(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)
	leaf := w.leaf(t, w.rootA, nil)
	if _, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf}); err != nil {
		t.Fatalf("first VerifyAs = %v, want success (caches the good OCSP response)", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancel2 := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel2()
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"canceled", canceled},
		{"deadline exceeded", expired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := w.chk.VerifyAs(tc.ctx, "alpha", []*x509.Certificate{leaf})
			e := tErr(t, err)
			if res != nil || e.Code != CodeInternal || !e.Retryable || e.Diagnostics.FailedStep != StepRevocation {
				t.Errorf("got (%v, %s at %s, retryable %v); want (nil, %s at %s, true)", res, e.Code, e.Diagnostics.FailedStep, e.Retryable,
					CodeInternal, StepRevocation)
			}
		})
	}
}

func TestRetryableCodes(t *testing.T) {
	retryable := []ErrorCode{CodeRevocationUnavailable, CodeInternal}
	seen := map[ErrorCode]bool{}
	for _, c := range Codes {
		if seen[c] {
			t.Errorf("code %s listed twice", c)
		}
		seen[c] = true
		if got, want := c.Retryable(), slices.Contains(retryable, c); got != want {
			t.Errorf("%s.Retryable() = %v, want %v", c, got, want)
		}
	}
	if len(Codes) != 16 {
		t.Errorf("len(Codes) = %d, want 16", len(Codes))
	}
}

func TestNewCheckerOptions(t *testing.T) {
	t.Parallel()
	now := tNow()
	root := testpki.NewRoot(t, "Options Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "opt-root", testpki.ECDSAP256)})
	prof := profiles.Profile{ID: "opt-a", ProviderID: "opt", Name: "opt", HolderRole: profiles.RoleNaturalPerson,
		Anchors: []profiles.Anchor{profiles.TestAnchor(root.Cert)}, PolicyOIDs: []string{"1.3.6.1.4.1.99999.3.1"},
		EKU: profiles.EKURequireClientAuth, Identity: tPlainAdapter(),
		Revocation: revocation.Policy{OCSPHosts: []string{"ocsp.opt.test"}}}
	decl := profiles.Provider{ID: "opt", Name: "Opt", Description: "Opt provider", Profiles: []profiles.Profile{prof}}
	rc := tRevocation(t, testpki.NewNet(), now)

	unparsed := prof
	unparsed.HandledCriticalExtensions = []string{"1.3.6.1.4.1.99999.3.9"}
	declUnparsed := profiles.Provider{ID: "opt", Name: "Opt", Profiles: []profiles.Profile{unparsed}}

	for _, tc := range []struct {
		name string
		cfg  Config
		want string // error substring; "" = success
	}{
		{"invalid declaration", Config{Revocation: rc}, "invalid provider"},
		{"no revocation", Config{Provider: decl}, "required"},
		{"handled extension without a parser", Config{Provider: declUnparsed, Revocation: rc}, "opt-a handles 1.3.6.1.4.1.99999.3.9 without a parser"},
		{"defaults", Config{Provider: decl, Revocation: rc}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.cfg)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("New error = %v, want one containing %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("New error = %v", err)
			}
			if c.maxLen != DefaultMaxChainLen || c.now == nil {
				t.Errorf("defaults: maxLen %d, now set %v; want %d and true", c.maxLen, c.now != nil, DefaultMaxChainLen)
			}
			if got, want := c.Info(), (certcheck.ProviderInfo{ID: "opt", Name: "Opt", Description: "Opt provider"}); got != want {
				t.Errorf("Info() = %+v, want %+v", got, want)
			}
			if cas := c.CAs(); len(cas) != 1 || !cas[0].Equal(root.Cert) {
				t.Errorf("CAs() = %d certificates, want the anchor", len(cas))
			}
		})
	}
}

func TestClientIntermediatesIgnored(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t)

	t.Run("unpinned sub CA", func(t *testing.T) {
		sub := w.rootA.Intermediate(t, "Unpinned Sub CA", testpki.CertSpec{Now: w.now, KeyPair: tKey(t, "cw-sub", testpki.ECDSAP256)})
		leaf := w.leaf(t, sub, nil)
		res, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf, sub.Cert})
		e := tErr(t, err)
		if res != nil || e.Code != CodeUntrustedIssuer || e.Diagnostics.FailedStep != StepPath {
			t.Errorf("got (%s at %s), want (%s at %s)", e.Code, e.Diagnostics.FailedStep, CodeUntrustedIssuer, StepPath)
		}
		if n := len(e.Diagnostics.RevocationAttempts); n != 0 {
			t.Errorf("%d revocation attempts, want 0", n)
		}
		for _, r := range w.ocsp.Requests() {
			if r.Serial.Cmp(leaf.SerialNumber) == 0 {
				t.Errorf("OCSP request sent for the leaf, want none")
			}
		}
	})

	t.Run("forged issuer", func(t *testing.T) {
		// Same DN as the pinned anchor, attacker key. The attacker's responder
		// answers "good" for whatever CertID it is asked about and signs as the
		// forged issuer: only an issuer taken from the client chain accepts it.
		forged := testpki.NewRoot(t, "Alpha A Root", testpki.CertSpec{Now: w.now, KeyPair: tKey(t, "cw-attacker", testpki.ECDSAP256)})
		if string(forged.Cert.RawSubject) != string(w.rootA.Cert.RawSubject) {
			t.Fatal("forged issuer DN differs from the anchor DN")
		}
		leaf := w.leaf(t, w.rootA, nil)
		w.answerFunc(leaf.SerialNumber, func(req testpki.Request) testpki.OCSPSpec {
			return testpki.OCSPSpec{Signer: forged.AsResponder(), NoCerts: true, NameHashOverride: req.IssuerNameHash,
				KeyHashOverride: req.IssuerKeyHash, NextUpdate: w.now.Add(time.Hour)}
		})
		res, err := w.chk.VerifyAs(t.Context(), "alpha", []*x509.Certificate{leaf, forged.Cert})
		e := tErr(t, err)
		if res != nil || e.Code != CodeRevocationUnavailable || e.Diagnostics.FailedStep != StepRevocation {
			t.Errorf("got (%s at %s), want (%s at %s); detail %q", e.Code, e.Diagnostics.FailedStep, CodeRevocationUnavailable, StepRevocation, e.Detail)
		}
		_, wantKeyHash := testpki.CertIDHashes(t, crypto.SHA1, w.rootA.Cert)
		var asked int
		for _, r := range w.ocsp.Requests() {
			if r.Serial.Cmp(leaf.SerialNumber) != 0 {
				continue
			}
			asked++
			if string(r.IssuerKeyHash) != string(wantKeyHash) {
				t.Errorf("OCSP issuerKeyHash %x, want the pinned anchor's %x", r.IssuerKeyHash, wantKeyHash)
			}
		}
		if asked == 0 {
			t.Error("no OCSP request for the leaf")
		}
	})
}

func TestIntermediateRevocation(t *testing.T) {
	t.Parallel()
	now := tNow()
	p := newPPPKI(t, now)
	s := ppShapeNamed(t, "dnie-auth")
	leaf := p.issue(t, s)
	root := p.anchors["dnie-auth"][0]
	listed := root.CRL(t, testpki.CRLSpec{Now: now, IDP: &testpki.IDPSpec{URIs: []string{ppARLURL}, OnlyCA: true},
		Entries: []testpki.CRLEntry{{Serial: p.dnieInter.Cert.SerialNumber, RevokedAt: now.Add(-time.Hour), Reason: 1}}})
	for _, tc := range []struct {
		name string
		arl  http.Handler
		want ErrorCode
	}{
		{"ARL good", nil, ""},
		{"intermediate listed", testpki.Bytes("application/pkix-crl", listed), CodeRevoked},
		{"ARL down", tUnavailable, CodeRevocationUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := p.check(t, s, leaf, ppOCSPUp, tc.arl)
			var attempts []RevocationAttempt
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Check error = %v, want success", err)
				}
				attempts = res.Diagnostics.RevocationAttempts
			} else {
				e := tErr(t, err)
				if e.Code != tc.want || e.Diagnostics.FailedStep != StepRevocation {
					t.Fatalf("got (%s at %s), want (%s at %s); detail %q", e.Code, e.Diagnostics.FailedStep, tc.want, StepRevocation, e.Detail)
				}
				attempts = e.Diagnostics.RevocationAttempts
			}
			// The leaf is checked first (OCSP, issuer = the intermediate), then
			// the intermediate against both of its DPs (issuer = the anchor):
			// the empty root CRL never settles a CA on its own.
			if len(attempts) < 2 || attempts[0].Method != revocation.MethodOCSP || attempts[0].Outcome != revocation.StatusGood {
				t.Fatalf("attempts = %+v, want the leaf OCSP good first", attempts)
			}
			for _, u := range []string{ppCRLURL, ppARLURL} {
				if !slices.ContainsFunc(attempts[1:], func(a RevocationAttempt) bool { return a.Method == revocation.MethodCRL && a.URL == u }) {
					t.Errorf("attempts = %+v, want a CRL attempt at %s", attempts, u)
				}
			}
		})
	}
}
