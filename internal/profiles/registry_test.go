// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// wantProviders is the display order, UI name (ruling R39: spaced ASCII
// hyphen, preflight F5), Beta flag and number of profiles of every provider.
var wantProviders = []struct {
	id       string
	name     string
	beta     bool
	profiles int
}{
	{"fnmt", "FNMT - Persona Física", false, 2},
	{"idcat", "idCAT Certificat", false, 2},
	{"accv", "ACCV - Ciudadano (software)", false, 1},
	{"digitel", "DIGITEL ON - Ciudadano", false, 1},
	{"bewor", "Bewor - Persona Física", false, 1},
	{"sectigo", "Sectigo - Ciudadano", false, 1},
	{"fnmt-representative", "FNMT - Representante", true, 2},
	{"fnmt-employee", "FNMT - Empleado Público", true, 2},
	{"firmaprofesional", "Firmaprofesional", true, 1},
	{"anf", "ANF AC", true, 2},
	{"uanataca", "Uanataca", true, 1},
	{"signe", "SIGNE", true, 1},
	{"lleidanet", "Lleidanet / inDenova", true, 1},
	{"dnie", "DNIe (requires card reader)", true, 1},
}

// regTAdapter is a valid identity adapter for synthetic profiles.
func regTAdapter() identity.Adapter {
	return identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}}},
		Surnames:  identity.SurnamesFromSN, SAN: identity.SANCheck{Kind: identity.SANNone},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
}

// regTProfile is a valid synthetic profile.
func regTProfile(id, providerID string, anchors ...profiles.Anchor) profiles.Profile {
	return profiles.Profile{
		ID: id, ProviderID: providerID, Name: "Profile " + id, HolderRole: profiles.RoleNaturalPerson,
		Anchors: anchors, PolicyOIDs: []string{"1.2.3.4"}, EKU: profiles.EKURequireClientAuth,
		Identity:   regTAdapter(),
		Revocation: revocation.Policy{OCSPHosts: []string{"ocsp.example.test"}},
	}
}

func regTProvider(id string, ps ...profiles.Profile) profiles.Provider {
	return profiles.Provider{ID: id, Name: "Provider " + id, Profiles: ps}
}

// regTLogger captures warnings in a buffer.
func regTLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func regTPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func TestDefaultLoads(t *testing.T) {
	r, err := profiles.Default(time.Now(), nil)
	if err != nil {
		t.Fatalf("Default: %v", err)
	}

	got := r.Providers()
	if len(got) != len(wantProviders) {
		t.Fatalf("got %d providers, want %d", len(got), len(wantProviders))
	}
	for i, w := range wantProviders {
		p := got[i]
		if p.ID != w.id || p.Name != w.name || p.Beta != w.beta || len(p.Profiles) != w.profiles {
			t.Errorf("provider %d = {%q %q beta=%v profiles=%d}, want {%q %q beta=%v profiles=%d}",
				i, p.ID, p.Name, p.Beta, len(p.Profiles), w.id, w.name, w.beta, w.profiles)
		}
		if p.Description == "" {
			t.Errorf("provider %s: empty description", p.ID)
		}
		texts := []string{p.Name, p.Description}
		for _, prof := range p.Profiles {
			texts = append(texts, prof.Name)
		}
		for _, s := range texts {
			if strings.ContainsAny(s, "\u2013\u2014") {
				t.Errorf("provider %s: %q contains an en or em dash (ruling R39)", p.ID, s)
			}
		}
		byID, ok := r.Provider(w.id)
		if !ok || byID.ID != w.id || len(byID.Profiles) != w.profiles {
			t.Errorf("Provider(%q) = (%q, %d profiles, %v), want (%q, %d, true)", w.id, byID.ID, len(byID.Profiles), ok, w.id, w.profiles)
		}
		if n := len(r.Enabled(w.id)); n != w.profiles {
			t.Errorf("Enabled(%q): got %d profiles, want %d", w.id, n, w.profiles)
		}
	}

	for _, tc := range []struct {
		provider string
		want     int
	}{{"dnie", 4}, {"fnmt", 2}, {"uanataca", 4}} {
		pool, err := r.ClientCAs(tc.provider)
		if err != nil {
			t.Fatalf("ClientCAs(%q): %v", tc.provider, err)
		}
		var certs []*x509.Certificate
		for _, e := range r.Enabled(tc.provider) {
			certs = append(append(certs, e.Anchors...), e.Intermediates...)
		}
		if len(certs) != tc.want {
			t.Errorf("ClientCAs(%q): enabled profiles hold %d certificates, want %d", tc.provider, len(certs), tc.want)
		}
		if !pool.Equal(regTPool(certs...)) {
			t.Errorf("ClientCAs(%q) is not exactly the anchors and pinned intermediates of its enabled profiles", tc.provider)
		}
	}

	if _, err := r.ClientCAs("unknown"); err == nil {
		t.Error("ClientCAs(unknown): got nil error, want error")
	}
	if _, ok := r.Provider("unknown"); ok {
		t.Error("Provider(unknown): got ok, want not found")
	}
	if e := r.Enabled("unknown"); e != nil {
		t.Errorf("Enabled(unknown) = %d profiles, want nil", len(e))
	}
	if got, want := r.Reserved().Version, identity.DefaultReserved().Version; got != want {
		t.Errorf("Reserved().Version = %q, want %q", got, want)
	}
}

// regTCase is one New call expected to fail (wantErr/wantIs) or succeed.
type regTCase struct {
	name    string
	cfg     func() profiles.Config
	wantErr string // substring of the error; "" with wantIs nil means success
	wantIs  error
}

func TestRegistryErrors(t *testing.T) {
	now := time.Now()
	rootA := testpki.NewRoot(t, "root A", testpki.CertSpec{Now: now})
	rootB := testpki.NewRoot(t, "root B", testpki.CertSpec{Now: now})
	// rootA2 re-certifies rootA's key under another serial and validity.
	rootA2 := testpki.NewRoot(t, "root A", testpki.CertSpec{Now: now, KeyPair: rootA.Key})
	interB := rootB.Intermediate(t, "inter B", testpki.CertSpec{Now: now})
	// crossA is a cross-certificate: rootA's subject and key, issued by rootB.
	crossA := rootB.Intermediate(t, "root A", testpki.CertSpec{Now: now, KeyPair: rootA.Key})
	expiredRoot := testpki.NewRoot(t, "expired root", testpki.CertSpec{Now: now, NotBefore: now.AddDate(-3, 0, 0), NotAfter: now.AddDate(0, 0, -1)})
	leaf := rootA.Leaf(t, testpki.CertSpec{Now: now, Subject: testpki.Name{testpki.UTF8(testpki.OIDCommonName, "leaf")}})

	a, b, a2 := profiles.TestAnchor(rootA.Cert), profiles.TestAnchor(rootB.Cert), profiles.TestAnchor(rootA2.Cert)
	iB, xA := profiles.TestAnchor(interB.Cert), profiles.TestAnchor(crossA.Cert)
	one := func(mut func(*profiles.Profile)) func() profiles.Config {
		return func() profiles.Config {
			p := regTProfile("p1", "prov", a)
			mut(&p)
			return profiles.Config{Providers: []profiles.Provider{regTProvider("prov", p)}, Now: now}
		}
	}
	two := func(p1, p2 profiles.Profile) func() profiles.Config {
		return func() profiles.Config {
			return profiles.Config{Providers: []profiles.Provider{regTProvider("prov", p1, p2)}, Now: now}
		}
	}
	withOID := func(p profiles.Profile, oids ...string) profiles.Profile { p.PolicyOIDs = oids; return p }
	withInter := func(p profiles.Profile, in ...profiles.Anchor) profiles.Profile { p.Intermediates = in; return p }
	marker := func(m profiles.TestMarker) func() profiles.Config {
		return one(func(p *profiles.Profile) { p.TestMarkers = []profiles.TestMarker{m} })
	}
	files := fstest.MapFS{
		"anchors/a.pem":     {Data: testpki.PEM(rootA.Cert)},
		"anchors/two.pem":   {Data: append(testpki.PEM(rootA.Cert), testpki.PEM(rootB.Cert)...)},
		"anchors/key.pem":   {Data: []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")},
		"anchors/trail.pem": {Data: append(testpki.PEM(rootA.Cert), "trailing text\n"...)},
	}
	fromFile := func(name string) func() profiles.Config {
		return func() profiles.Config {
			anc := profiles.Anchor{File: name, SHA256: a.SHA256, SPKISHA256: a.SPKISHA256}
			return profiles.Config{Providers: []profiles.Provider{regTProvider("prov", regTProfile("p1", "prov", anc))}, Now: now, Files: files}
		}
	}

	tests := []regTCase{
		{name: "valid", cfg: one(func(*profiles.Profile) {})},
		{name: "anchor from file", cfg: fromFile("anchors/a.pem")},
		{name: "anchor file missing", cfg: fromFile("anchors/missing.pem"), wantErr: "missing.pem"},
		{name: "anchor file with two PEM blocks", cfg: fromFile("anchors/two.pem"), wantErr: "want exactly one PEM certificate"},
		{name: "anchor file with trailing text", cfg: fromFile("anchors/trail.pem"), wantErr: "want exactly one PEM certificate"},
		{name: "anchor file not a certificate", cfg: fromFile("anchors/key.pem"), wantErr: "want exactly one PEM certificate"},
		{name: "zero Now", cfg: func() profiles.Config {
			c := one(func(*profiles.Profile) {})()
			c.Now = time.Time{}
			return c
		}, wantErr: "Config.Now is required"},
		{name: "DER pin mismatch", cfg: one(func(p *profiles.Profile) { p.Anchors[0].SHA256 = b.SHA256 }), wantErr: "SHA-256 pin mismatch"},
		{name: "SPKI pin mismatch", cfg: one(func(p *profiles.Profile) { p.Anchors[0].SPKISHA256 = b.SPKISHA256 }), wantErr: "SPKI pin mismatch"},
		{name: "malformed DER pin", cfg: one(func(p *profiles.Profile) { p.Anchors[0].SHA256 = strings.ToUpper(a.SHA256) }), wantErr: "pins missing or malformed"},
		{name: "missing SPKI pin", cfg: one(func(p *profiles.Profile) { p.Anchors[0].SPKISHA256 = "" }), wantErr: "pins missing or malformed"},
		{name: "non-CA anchor", cfg: one(func(p *profiles.Profile) { p.Anchors = []profiles.Anchor{profiles.TestAnchor(leaf.Cert)} }), wantErr: "not a CA"},
		{name: "corrupt anchor DER", cfg: one(func(p *profiles.Profile) {
			der := []byte("not a certificate")
			anc := profiles.TestAnchor(rootA.Cert)
			anc.DER = der
			anc.SHA256 = testpki.SHA256Hex(der)
			p.Anchors = []profiles.Anchor{anc}
		}), wantErr: "x509: malformed certificate"},
		{name: "duplicate provider", cfg: func() profiles.Config {
			return profiles.Config{Now: now, Providers: []profiles.Provider{
				regTProvider("prov", regTProfile("p1", "prov", a)), regTProvider("prov", regTProfile("p2", "prov", b))}}
		}, wantErr: "duplicate provider"},
		{name: "duplicate profile across providers", cfg: func() profiles.Config {
			return profiles.Config{Now: now, Providers: []profiles.Provider{
				regTProvider("prov", regTProfile("p1", "prov", a)), regTProvider("other", regTProfile("p1", "other", b))}}
		}, wantErr: "duplicate profile"},
		{name: "duplicate profile in provider", cfg: two(regTProfile("p1", "prov", a), withOID(regTProfile("p1", "prov", b), "1.2.3.5")), wantErr: "duplicate profile"},
		{name: "bad provider ID Foo", cfg: func() profiles.Config {
			return profiles.Config{Now: now, Providers: []profiles.Provider{regTProvider("Foo", regTProfile("p1", "Foo", a))}}
		}, wantErr: "invalid provider"},
		{name: "provider without name", cfg: func() profiles.Config {
			p := regTProvider("prov", regTProfile("p1", "prov", a))
			p.Name = ""
			return profiles.Config{Now: now, Providers: []profiles.Provider{p}}
		}, wantErr: "invalid provider"},
		{name: "profile declares another provider", cfg: one(func(p *profiles.Profile) { p.ProviderID = "other" }), wantErr: "declares provider"},
		{name: "bad profile ID", cfg: one(func(p *profiles.Profile) { p.ID = "P_1" }), wantErr: "invalid id, name or role"},
		{name: "invalid role", cfg: one(func(p *profiles.Profile) { p.HolderRole = "citizen" }), wantErr: "invalid id, name or role"},
		{name: "no anchors", cfg: one(func(p *profiles.Profile) { p.Anchors = nil }), wantErr: "anchors and policy OIDs are required"},
		{name: "no policy OIDs", cfg: one(func(p *profiles.Profile) { p.PolicyOIDs = nil }), wantErr: "anchors and policy OIDs are required"},
		{name: "bad OID 1.2.03", cfg: one(func(p *profiles.Profile) { p.PolicyOIDs = []string{"1.2.03"} }), wantErr: `invalid OID "1.2.03"`},
		{name: "OID prefix wildcard", cfg: one(func(p *profiles.Profile) { p.PolicyOIDs = []string{"1.2.3.*"} }), wantErr: "invalid OID"},
		{name: "bad handled critical extension OID", cfg: one(func(p *profiles.Profile) { p.HandledCriticalExtensions = []string{"qcStatements"} }), wantErr: "invalid OID"},
		{name: "EKU unset", cfg: one(func(p *profiles.Profile) { p.EKU = 0 }), wantErr: "EKU rule unset"},
		{name: "EKU out of range", cfg: one(func(p *profiles.Profile) { p.EKU = 7 }), wantErr: "EKU rule unset"},
		{name: "MinRSABits below floor", cfg: one(func(p *profiles.Profile) { p.Algorithms.MinRSABits = 1024 }), wantErr: "MinRSABits below the 2048 floor"},
		{name: "invalid adapter", cfg: one(func(p *profiles.Profile) { p.Identity = identity.Adapter{} }), wantIs: identity.ErrInvalid},
		{name: "invalid policy", cfg: one(func(p *profiles.Profile) { p.Revocation = revocation.Policy{} }), wantErr: "no OCSP host and CRL not allowed"},
		{name: "invalid policy host", cfg: one(func(p *profiles.Profile) { p.Revocation.OCSPHosts = []string{"OCSP.example.test"} }), wantErr: "invalid host entry"},
		{name: "marker with both SHA256 and Subject", cfg: one(func(p *profiles.Profile) {
			p.TestMarkers = []profiles.TestMarker{{SHA256: a.SHA256, Subject: []profiles.AttributeMatch{{OID: identity.OIDGivenName, Value: "X"}}}}
		}), wantErr: "exactly one of SHA256 or Subject"},
		{name: "marker with neither", cfg: one(func(p *profiles.Profile) { p.TestMarkers = []profiles.TestMarker{{Source: "x"}} }), wantErr: "exactly one of SHA256 or Subject"},
		{name: "marker with malformed SHA256", cfg: one(func(p *profiles.Profile) { p.TestMarkers = []profiles.TestMarker{{SHA256: "abc"}} }), wantErr: "exactly one of SHA256 or Subject"},
		{name: "valid markers", cfg: one(func(p *profiles.Profile) {
			p.TestMarkers = []profiles.TestMarker{{SHA256: a.SHA256, Source: "x"},
				{Subject: []profiles.AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}}, Source: "x"}}
		})},
		{name: "subject marker with an empty attribute list", cfg: marker(profiles.TestMarker{Subject: []profiles.AttributeMatch{}, Source: "x"}), wantErr: "exactly one of SHA256 or Subject"},
		{name: "subject marker with a nil OID", cfg: marker(profiles.TestMarker{Subject: []profiles.AttributeMatch{{Value: "NOMDOS"}}, Source: "x"}), wantErr: "test marker attribute needs an OID and a value"},
		{name: "subject marker with a one-arc OID", cfg: marker(profiles.TestMarker{Subject: []profiles.AttributeMatch{{OID: []int{2}, Value: "NOMDOS"}}, Source: "x"}), wantErr: "test marker attribute needs an OID and a value"},
		{name: "subject marker with a blank value", cfg: marker(profiles.TestMarker{Subject: []profiles.AttributeMatch{
			{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: " \t"}}, Source: "x"}), wantErr: "test marker attribute needs an OID and a value"},
		{name: "marker without Source", cfg: marker(profiles.TestMarker{SHA256: a.SHA256}), wantErr: "test marker without Source"},
		{name: "intermediate not signed by an anchor", cfg: one(func(p *profiles.Profile) { p.Intermediates = []profiles.Anchor{profiles.TestAnchor(interB.Cert)} }), wantErr: "is not signed by a profile anchor"},
		{name: "all anchors expired, intermediate signed by an undeclared key", cfg: one(func(p *profiles.Profile) {
			p.Anchors, p.Intermediates = []profiles.Anchor{profiles.TestAnchor(expiredRoot.Cert)}, []profiles.Anchor{profiles.TestAnchor(interB.Cert)}
		}), wantErr: "is not signed by a profile anchor"},
		{name: "intermediate pin mismatch", cfg: one(func(p *profiles.Profile) {
			in := profiles.TestAnchor(interB.Cert)
			in.SPKISHA256 = a.SPKISHA256
			p.Intermediates = []profiles.Anchor{in}
		}), wantErr: "SPKI pin mismatch"},
		{name: "two profiles sharing an anchor and an OID", cfg: two(regTProfile("p1", "prov", a), regTProfile("p2", "prov", a)), wantErr: "share an anchor and policy 1.2.3.4"},
		{name: "two profiles sharing an anchor key and an OID", cfg: two(regTProfile("p1", "prov", a), regTProfile("p2", "prov", b, a2)), wantErr: "share an anchor and policy 1.2.3.4"},
		{name: "one shared OID among several", cfg: two(withOID(regTProfile("p1", "prov", a), "1.2.3.4", "1.2.3.9"), withOID(regTProfile("p2", "prov", a), "1.2.3.5", "1.2.3.9")), wantErr: "share an anchor and policy 1.2.3.9"},
		{name: "key pinned as an intermediate and as an anchor, shared OID", cfg: two(withInter(regTProfile("p1", "prov", b), iB), regTProfile("p2", "prov", iB)), wantErr: "share an anchor and policy 1.2.3.4"},
		{name: "cross-signed pinned intermediate, shared OID", cfg: two(regTProfile("p1", "prov", a), withInter(regTProfile("p2", "prov", b), xA)), wantErr: "share an anchor and policy 1.2.3.4"},
		{name: "cross-signed pinned intermediate, distinct OIDs", cfg: two(regTProfile("p1", "prov", a), withOID(withInter(regTProfile("p2", "prov", b), xA), "1.2.3.5"))},
		{name: "same anchor with distinct OIDs", cfg: two(regTProfile("p1", "prov", a), withOID(regTProfile("p2", "prov", a), "1.2.3.5"))},
		{name: "distinct anchors with the same OID", cfg: two(regTProfile("p1", "prov", a), regTProfile("p2", "prov", b))},
		{name: "same anchor and OID in different providers", cfg: func() profiles.Config {
			return profiles.Config{Now: now, Providers: []profiles.Provider{
				regTProvider("prov", regTProfile("p1", "prov", a)), regTProvider("other", regTProfile("p2", "other", a))}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := regTLogger()
			cfg := tc.cfg()
			cfg.Logger = logger
			r, err := profiles.New(cfg)
			switch {
			case tc.wantErr == "" && tc.wantIs == nil:
				if err != nil || r == nil {
					t.Fatalf("New: got (%v, %v), want a registry and nil error", r, err)
				}
			case err == nil:
				t.Fatalf("New: got nil error, want %q / %v", tc.wantErr, tc.wantIs)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("New error = %q, want it to contain %q", err, tc.wantErr)
			case tc.wantIs != nil && !errors.Is(err, tc.wantIs):
				t.Errorf("New error = %v, want errors.Is %v", err, tc.wantIs)
			}
			if err != nil && r != nil {
				t.Errorf("New returned a registry with error %v", err)
			}
		})
	}
}

// TestRegistryRejectInvalidOIDArcs: under a first arc of 0 or 1 the second
// arc is at most 39, so such an OID has no DER encoding and could never match.
func TestRegistryRejectInvalidOIDArcs(t *testing.T) {
	now := time.Now()
	root := testpki.NewRoot(t, "root", testpki.CertSpec{Now: now})
	for _, tc := range []struct {
		oid   string
		valid bool
	}{
		{"0.39", true}, {"0.40", false}, {"0.40.1", false},
		{"1.39.3", true}, {"1.40", false}, {"1.40.3", false}, {"1.400.3.4", false},
		{"2.40", true}, {"2.999.1.2", true},
	} {
		var arcs []int
		for s := range strings.SplitSeq(tc.oid, ".") {
			n, err := strconv.Atoi(s)
			if err != nil {
				t.Fatal(err)
			}
			arcs = append(arcs, n)
		}
		for _, field := range []struct {
			name    string
			set     func(*profiles.Profile)
			wantErr string
		}{
			{"policy", func(p *profiles.Profile) { p.PolicyOIDs = []string{tc.oid} }, fmt.Sprintf("invalid OID %q", tc.oid)},
			{"handled extension", func(p *profiles.Profile) { p.HandledCriticalExtensions = []string{tc.oid} }, fmt.Sprintf("invalid OID %q", tc.oid)},
			{"marker", func(p *profiles.Profile) {
				p.TestMarkers = []profiles.TestMarker{{Subject: []profiles.AttributeMatch{{OID: arcs, Value: "NOMDOS"}}, Source: "x"}}
			}, "test marker attribute needs an OID and a value"},
		} {
			t.Run(field.name+" "+tc.oid, func(t *testing.T) {
				p := regTProfile("p1", "prov", profiles.TestAnchor(root.Cert))
				field.set(&p)
				logger, _ := regTLogger()
				_, err := profiles.New(profiles.Config{Providers: []profiles.Provider{regTProvider("prov", p)}, Now: now, Logger: logger})
				switch {
				case tc.valid && err != nil:
					t.Errorf("New error = %v, want success", err)
				case !tc.valid && (err == nil || !strings.Contains(err.Error(), field.wantErr)):
					t.Errorf("New error = %v, want one containing %q", err, field.wantErr)
				}
			})
		}
	}
}

func TestValidityDisables(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	valid := testpki.CertSpec{Now: now, NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(5, 0, 0)}
	expired := testpki.CertSpec{Now: now, NotBefore: now.AddDate(-3, 0, 0), NotAfter: now.AddDate(0, 0, -1)}
	future := testpki.CertSpec{Now: now, NotBefore: now.AddDate(0, 0, 1), NotAfter: now.AddDate(5, 0, 0)}

	live := testpki.NewRoot(t, "live root", valid)
	dead := testpki.NewRoot(t, "expired root", expired)
	early := testpki.NewRoot(t, "future root", future)
	deadInter := live.Intermediate(t, "expired inter", expired)
	liveInter := live.Intermediate(t, "live inter", valid)
	earlyInter := live.Intermediate(t, "future inter", future)
	orphanInter := dead.Intermediate(t, "inter under expired root", valid)
	anc := profiles.TestAnchor

	tests := []struct {
		name          string
		anchors       []*testpki.CA
		intermediates []*testpki.CA
		wantEnabled   bool
		wantAnchors   []*testpki.CA
		wantInter     []*testpki.CA
		wantLog       []string
	}{
		{name: "all anchors expired", anchors: []*testpki.CA{dead},
			wantLog: []string{"anchor outside validity", "profile disabled: no valid anchor", "provider hidden"}},
		{name: "all anchors expired, intermediate signed by one", anchors: []*testpki.CA{dead}, intermediates: []*testpki.CA{orphanInter},
			wantLog: []string{"anchor outside validity", "profile disabled: no valid anchor", "provider hidden"}},
		{name: "anchor not yet valid", anchors: []*testpki.CA{early},
			wantLog: []string{"anchor outside validity", "profile disabled: no valid anchor", "provider hidden"}},
		{name: "one of two anchors expired", anchors: []*testpki.CA{dead, live},
			wantEnabled: true, wantAnchors: []*testpki.CA{live}, wantLog: []string{"anchor outside validity"}},
		{name: "intermediates all expired", anchors: []*testpki.CA{live}, intermediates: []*testpki.CA{deadInter},
			wantLog: []string{"intermediate outside validity", "profile disabled: no valid pinned intermediate", "provider hidden"}},
		{name: "not-yet-valid-intermediate", anchors: []*testpki.CA{live}, intermediates: []*testpki.CA{earlyInter},
			wantLog: []string{"intermediate outside validity", "profile disabled: no valid pinned intermediate", "provider hidden"}},
		{name: "one of two intermediates expired", anchors: []*testpki.CA{live}, intermediates: []*testpki.CA{deadInter, liveInter},
			wantEnabled: true, wantAnchors: []*testpki.CA{live}, wantInter: []*testpki.CA{liveInter}, wantLog: []string{"intermediate outside validity"}},
		{name: "intermediate under an expired anchor, second anchor valid", anchors: []*testpki.CA{dead, live}, intermediates: []*testpki.CA{orphanInter, liveInter},
			wantEnabled: true, wantAnchors: []*testpki.CA{live}, wantInter: []*testpki.CA{liveInter},
			wantLog: []string{"anchor outside validity", "intermediate signer outside validity"}},
		{name: "only intermediate under an expired anchor", anchors: []*testpki.CA{dead, live}, intermediates: []*testpki.CA{orphanInter},
			wantLog: []string{"intermediate signer outside validity", "profile disabled: no valid pinned intermediate", "provider hidden"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := regTProfile("p1", "prov")
			for _, ca := range tc.anchors {
				p.Anchors = append(p.Anchors, anc(ca.Cert))
			}
			for _, ca := range tc.intermediates {
				p.Intermediates = append(p.Intermediates, anc(ca.Cert))
			}
			logger, buf := regTLogger()
			r, err := profiles.New(profiles.Config{Providers: []profiles.Provider{regTProvider("prov", p)}, Now: now, Logger: logger})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			for _, w := range tc.wantLog {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("log %q does not contain %q", buf.String(), w)
				}
			}
			_, visible := r.Provider("prov")
			_, caErr := r.ClientCAs("prov")
			if got := len(r.Providers()) == 1 && visible && caErr == nil; got != tc.wantEnabled {
				t.Fatalf("provider visible = %v (Providers %d, Provider ok %v, ClientCAs err %v), want %v",
					got, len(r.Providers()), visible, caErr, tc.wantEnabled)
			}
			if !tc.wantEnabled {
				if e := r.Enabled("prov"); len(e) != 0 {
					t.Errorf("Enabled = %d profiles, want 0", len(e))
				}
				return
			}
			e := r.Enabled("prov")
			if len(e) != 1 {
				t.Fatalf("Enabled = %d profiles, want 1", len(e))
			}
			var wantA, wantI []*x509.Certificate
			for _, ca := range tc.wantAnchors {
				wantA = append(wantA, ca.Cert)
			}
			for _, ca := range tc.wantInter {
				wantI = append(wantI, ca.Cert)
			}
			if !e[0].Roots.Equal(regTPool(wantA...)) || len(e[0].Anchors) != len(wantA) {
				t.Errorf("Roots: got %d anchors, want exactly the %d valid ones", len(e[0].Anchors), len(wantA))
			}
			if !e[0].Inter.Equal(regTPool(wantI...)) || len(e[0].Intermediates) != len(wantI) {
				t.Errorf("Inter: got %d intermediates, want exactly the %d valid ones", len(e[0].Intermediates), len(wantI))
			}
		})
	}
}

// TestValidityBoundaries: validity includes NotBefore and NotAfter, to the
// second, for anchors and pinned intermediates alike.
func TestValidityBoundaries(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.AddDate(1, 0, 0)
	window := testpki.CertSpec{Now: notBefore, NotBefore: notBefore, NotAfter: notAfter}
	root := testpki.NewRoot(t, "window root", window)
	wideRoot := testpki.NewRoot(t, "wide root", testpki.CertSpec{Now: notBefore, NotBefore: notBefore.AddDate(-1, 0, 0), NotAfter: notAfter.AddDate(1, 0, 0)})
	inter := wideRoot.Intermediate(t, "window inter", window)
	viaInter := regTProfile("p1", "prov", profiles.TestAnchor(wideRoot.Cert))
	viaInter.Intermediates = []profiles.Anchor{profiles.TestAnchor(inter.Cert)}
	for _, at := range []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{"NotBefore-1s", notBefore.Add(-time.Second), false},
		{"NotBefore", notBefore, true},
		{"NotBefore+1s", notBefore.Add(time.Second), true},
		{"NotAfter-1s", notAfter.Add(-time.Second), true},
		{"NotAfter", notAfter, true},
		{"NotAfter+1s", notAfter.Add(time.Second), false},
	} {
		for _, ca := range []struct {
			name string
			p    profiles.Profile
		}{
			{"anchor", regTProfile("p1", "prov", profiles.TestAnchor(root.Cert))},
			{"intermediate", viaInter},
		} {
			t.Run(ca.name+" "+at.name, func(t *testing.T) {
				logger, _ := regTLogger()
				r, err := profiles.New(profiles.Config{Providers: []profiles.Provider{regTProvider("prov", ca.p)}, Now: at.now, Logger: logger})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				if got := len(r.Enabled("prov")) == 1; got != at.valid {
					t.Errorf("profile enabled = %v at %v, want %v", got, at.now, at.valid)
				}
			})
		}
	}
}

// TestRegistryRejectsIntermediateIssuerMismatch: an anchor holding the key of
// a pinned intermediate's issuer under another name does not issue it (path
// building is name-based: no leaf would chain through it).
func TestRegistryRejectsIntermediateIssuerMismatch(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	valid := testpki.CertSpec{Now: now, NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(5, 0, 0)}
	expired := testpki.CertSpec{Now: now, NotBefore: now.AddDate(-3, 0, 0), NotAfter: now.AddDate(0, 0, -1)}
	issuer := testpki.NewRoot(t, "issuer root", expired)
	sameKey := valid
	sameKey.KeyPair = issuer.Key
	renamed := testpki.NewRoot(t, "renamed root", sameKey)
	reissued := testpki.NewRoot(t, "issuer root", sameKey)
	inter := issuer.Intermediate(t, "inter", valid)
	anc := profiles.TestAnchor

	tests := []struct {
		name        string
		anchors     []*testpki.CA
		wantErr     string
		wantEnabled bool
		wantLog     string
	}{
		{name: "issuer key under another name", anchors: []*testpki.CA{renamed}, wantErr: "is not signed by a profile anchor"},
		{name: "expired issuer, its key valid under another name", anchors: []*testpki.CA{issuer, renamed},
			wantLog: "intermediate signer outside validity"},
		{name: "issuer re-certified under its name", anchors: []*testpki.CA{issuer, reissued}, wantEnabled: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := regTProfile("p1", "prov")
			for _, ca := range tc.anchors {
				p.Anchors = append(p.Anchors, anc(ca.Cert))
			}
			p.Intermediates = []profiles.Anchor{anc(inter.Cert)}
			logger, buf := regTLogger()
			r, err := profiles.New(profiles.Config{Providers: []profiles.Provider{regTProvider("prov", p)}, Now: now, Logger: logger})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if !strings.Contains(buf.String(), tc.wantLog) {
				t.Errorf("log %q does not contain %q", buf.String(), tc.wantLog)
			}
			e := r.Enabled("prov")
			if got := len(e) == 1 && len(e[0].Intermediates) == 1; got != tc.wantEnabled {
				t.Errorf("profile enabled with the intermediate = %v (%d profiles), want %v", got, len(e), tc.wantEnabled)
			}
		})
	}
}

// TestCheckAmbiguityAcrossProviders: the Handler's cross-provider check also
// compares pinned intermediates (each provider loads on its own).
func TestCheckAmbiguityAcrossProviders(t *testing.T) {
	now := time.Now()
	rootA := testpki.NewRoot(t, "root A", testpki.CertSpec{Now: now})
	rootB := testpki.NewRoot(t, "root B", testpki.CertSpec{Now: now})
	crossA := rootB.Intermediate(t, "root A", testpki.CertSpec{Now: now, KeyPair: rootA.Key})
	viaCross := regTProfile("p2", "other", profiles.TestAnchor(rootB.Cert))
	viaCross.Intermediates = []profiles.Anchor{profiles.TestAnchor(crossA.Cert)}
	for _, tc := range []struct {
		name    string
		oid     string
		wantErr string // "" = no ambiguity
	}{
		{"shared OID", "1.2.3.4", "p1 and p2 share an anchor and policy 1.2.3.4"},
		{"distinct OIDs", "1.2.3.5", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p2 := viaCross
			p2.PolicyOIDs = []string{tc.oid}
			logger, _ := regTLogger()
			r, err := profiles.New(profiles.Config{Now: now, Logger: logger, Providers: []profiles.Provider{
				regTProvider("prov", regTProfile("p1", "prov", profiles.TestAnchor(rootA.Cert))), regTProvider("other", p2)}})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			err = profiles.CheckAmbiguity(slices.Concat(r.Enabled("prov"), r.Enabled("other")))
			if (tc.wantErr == "") != (err == nil) || !strings.Contains(fmt.Sprint(err), tc.wantErr) {
				t.Errorf("CheckAmbiguity = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestAllAnchors(t *testing.T) {
	r, err := profiles.Default(time.Now(), nil)
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	var roots, inter []*x509.Certificate
	for _, p := range r.Providers() {
		var provCerts []*x509.Certificate
		for _, e := range r.Enabled(p.ID) {
			roots = append(roots, e.Anchors...)
			inter = append(inter, e.Intermediates...)
			provCerts = append(append(provCerts, e.Anchors...), e.Intermediates...)
			if !e.Roots.Equal(regTPool(e.Anchors...)) || !e.Inter.Equal(regTPool(e.Intermediates...)) {
				t.Errorf("%s: Roots/Inter pools differ from Anchors/Intermediates", e.Profile.ID)
			}
			for _, c := range e.Intermediates {
				signed := func(root *x509.Certificate) bool { return c.CheckSignatureFrom(root) == nil }
				if !slices.ContainsFunc(e.Anchors, signed) {
					t.Errorf("%s: intermediate %s is not signed by an enabled anchor", e.Profile.ID, c.Subject.CommonName)
				}
			}
		}
		pool, err := r.ClientCAs(p.ID)
		if err != nil {
			t.Fatalf("ClientCAs(%q): %v", p.ID, err)
		}
		if !pool.Equal(regTPool(provCerts...)) {
			t.Errorf("ClientCAs(%q) differs from the provider's enabled anchors and intermediates", p.ID)
		}
	}
	if len(roots) != 26 || len(inter) != 3 {
		t.Errorf("enabled anchors = %d roots and %d intermediates, want 26 and 3", len(roots), len(inter))
	}

	// The returned pools are copies.
	extra := testpki.NewRoot(t, "extra", testpki.CertSpec{})
	ca, _ := r.ClientCAs("fnmt")
	ca.AddCert(extra.Cert)
	if again, _ := r.ClientCAs("fnmt"); again.Equal(ca) {
		t.Error("mutating the ClientCAs result changed the registry")
	}
}
