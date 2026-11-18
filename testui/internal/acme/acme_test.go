// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"

	"github.com/vocdoni/cert-check/internal/testpki"
)

const (
	testDomain = "auth.example.test"
	testToken  = "tok-SECRET-123"
)

func validOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		AuthDomain:      testDomain,
		DataDir:         t.TempDir(),
		Email:           "ops@example.test",
		CloudflareToken: testToken,
	}
}

// newTestACME builds an ACME manager and stops its certmagic cache with the test.
func newTestACME(t *testing.T, o Options) *Manager {
	t.Helper()
	m, err := NewACME(o)
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}
	t.Cleanup(m.Close)
	return m
}

// selfSigned returns a self-signed certificate for names with the given validity.
func selfSigned(t *testing.T, notBefore, notAfter time.Time, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// wildcardCert is a currently valid certificate for "*.<testDomain>".
func wildcardCert(t *testing.T) tls.Certificate {
	t.Helper()
	now := time.Now()
	return selfSigned(t, now.Add(-time.Hour), now.Add(24*time.Hour), "*."+testDomain)
}

// writePEM stores cert and its key as PEM files in a fresh directory.
func writePEM(t *testing.T, cert tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestNewACMEValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"missing auth domain", func(o *Options) { o.AuthDomain = "" }},
		{"missing data dir", func(o *Options) { o.DataDir = "" }},
		{"missing email", func(o *Options) { o.Email = "" }},
		{"missing token", func(o *Options) { o.CloudflareToken = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := validOptions(t)
			tc.mutate(&o)
			m, err := NewACME(o)
			if err == nil {
				m.Close()
				t.Fatal("NewACME succeeded, want an error")
			}
			if m != nil {
				t.Errorf("NewACME returned a manager with an error: %v", m)
			}
		})
	}
}

func TestNewACMEConfig(t *testing.T) {
	tests := []struct {
		name     string
		staging  bool
		override string
		wantCA   string
	}{
		{"production", false, "", certmagic.LetsEncryptProductionCA},
		{"staging", true, "", certmagic.LetsEncryptStagingCA},
		{"override domain", false, "_acme-challenge.delegate.example.net", certmagic.LetsEncryptProductionCA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := validOptions(t)
			o.Staging, o.OverrideDomain = tc.staging, tc.override
			m := newTestACME(t, o)

			if want := "*." + testDomain; m.name != want {
				t.Errorf("name = %q, want %q", m.name, want)
			}
			if len(m.cfg.Issuers) != 1 {
				t.Fatalf("issuers = %d, want 1", len(m.cfg.Issuers))
			}
			issuer, ok := m.cfg.Issuers[0].(*certmagic.ACMEIssuer)
			if !ok {
				t.Fatalf("issuer is %T, want *certmagic.ACMEIssuer", m.cfg.Issuers[0])
			}
			if issuer.CA != tc.wantCA {
				t.Errorf("CA = %q, want %q", issuer.CA, tc.wantCA)
			}
			if issuer.Email != o.Email || !issuer.Agreed {
				t.Errorf("Email = %q, Agreed = %v, want %q, true", issuer.Email, issuer.Agreed, o.Email)
			}
			if !issuer.DisableHTTPChallenge || !issuer.DisableTLSALPNChallenge {
				t.Errorf("DisableHTTPChallenge = %v, DisableTLSALPNChallenge = %v, want true, true",
					issuer.DisableHTTPChallenge, issuer.DisableTLSALPNChallenge)
			}
			if issuer.DNS01Solver == nil {
				t.Fatal("DNS01Solver is nil, want a DNS-01 solver")
			}
			solver, ok := issuer.DNS01Solver.(*certmagic.DNS01Solver)
			if !ok {
				t.Fatalf("DNS01Solver is %T, want *certmagic.DNS01Solver", issuer.DNS01Solver)
			}
			provider, ok := solver.DNSProvider.(*cloudflare.Provider)
			if !ok {
				t.Fatalf("DNSProvider is %T, want *cloudflare.Provider", solver.DNSProvider)
			}
			if provider.APIToken != testToken {
				t.Errorf("APIToken = %q, want the configured token", provider.APIToken)
			}
			// Without a timeout libdns/cloudflare uses http.DefaultClient (U12-ASTRA-2).
			if client, ok := provider.HTTPClient.(*http.Client); !ok || client.Timeout != 30*time.Second {
				t.Errorf("HTTPClient = %#v, want an *http.Client with a 30s timeout", provider.HTTPClient)
			}
			if solver.OverrideDomain != tc.override {
				t.Errorf("OverrideDomain = %q, want %q", solver.OverrideDomain, tc.override)
			}
			storage, ok := m.cfg.Storage.(*certmagic.FileStorage)
			if !ok {
				t.Fatalf("Storage is %T, want *certmagic.FileStorage", m.cfg.Storage)
			}
			if want := filepath.Join(o.DataDir, "certmagic"); storage.Path != want {
				t.Errorf("Storage.Path = %q, want %q", storage.Path, want)
			}
			if !m.cfg.OCSP.DisableStapling {
				t.Error("OCSP.DisableStapling = false, want true")
			}
		})
	}
}

// TestNewACMEStorage: NewACME creates <DataDir>/certmagic (0700) and fails
// when it cannot write there, instead of starting and retrying hourly while
// not ready (U12-FABLE-2).
func TestNewACMEStorage(t *testing.T) {
	t.Run("created", func(t *testing.T) {
		o := validOptions(t)
		newTestACME(t, o)
		dir := filepath.Join(o.DataDir, "certmagic")
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("storage directory: %v", err)
		}
		if !st.IsDir() || st.Mode().Perm() != 0o700 {
			t.Errorf("storage directory mode = %v, want a 0700 directory", st.Mode())
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Errorf("storage directory entries = %v (%v), want the probe file removed", entries, err)
		}
	})

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	readOnly := t.TempDir()
	if err := os.Mkdir(filepath.Join(readOnly, "certmagic"), 0o500); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, dataDir string
		root          bool // the case holds for root too
	}{
		{"under a regular file", filepath.Join(file, "data"), true},
		{"data dir is a regular file", file, true},
		{"read-only storage directory", readOnly, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.root && os.Geteuid() == 0 {
				t.Skip("root writes to a 0500 directory")
			}
			o := validOptions(t)
			o.DataDir = tc.dataDir
			m, err := NewACME(o)
			if err == nil {
				m.Close()
				t.Fatal("NewACME succeeded, want a storage error")
			}
			if m != nil {
				t.Errorf("NewACME returned a manager with an error: %v", m)
			}
			if !strings.Contains(err.Error(), filepath.Join(tc.dataDir, "certmagic")) {
				t.Errorf("error = %q, want it to name the storage directory", err)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error = %q contains the token", err)
			}
		})
	}
}

// TestNewACMELogs: certmagic and acmez write JSON lines to LogOutput at the
// levels the app logger enables, instead of console lines on stderr at Info
// (U12-FABLE-3).
func TestNewACMELogs(t *testing.T) {
	const started, stopped = "started background certificate maintenance", "stopped background certificate maintenance"
	tests := []struct {
		level slog.Level
		want  map[string]string // msg -> level
	}{
		{slog.LevelDebug, map[string]string{"d": "DEBUG", "i": "INFO", "w": "WARN", "e": "ERROR", started: "INFO", stopped: "INFO"}},
		{slog.LevelInfo, map[string]string{"i": "INFO", "w": "WARN", "e": "ERROR", started: "INFO", stopped: "INFO"}},
		{slog.LevelWarn, map[string]string{"w": "WARN", "e": "ERROR"}},
		{slog.LevelError, map[string]string{"e": "ERROR"}},
	}
	for _, tc := range tests {
		t.Run(tc.level.String(), func(t *testing.T) {
			var out bytes.Buffer
			o := validOptions(t)
			o.Logger = slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: tc.level}))
			o.LogOutput = &out
			m, err := NewACME(o)
			if err != nil {
				t.Fatalf("NewACME: %v", err)
			}
			issuer := m.cfg.Issuers[0].(*certmagic.ACMEIssuer)
			if issuer.Logger != m.cfg.Logger || issuer.DNS01Solver.(*certmagic.DNS01Solver).Logger != m.cfg.Logger {
				t.Error("the ACME issuer or the DNS-01 solver does not log through the config's logger")
			}
			m.cfg.Logger.Debug("d")
			m.cfg.Logger.Info("i")
			m.cfg.Logger.Warn("w")
			m.cfg.Logger.Error("e")
			m.Close() // the cache's maintenance goroutine has logged "started" and "stopped" and exited

			got := map[string]string{}
			for line := range strings.Lines(out.String()) {
				var rec struct{ Time, Level, Msg, Logger string }
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("log line %q is not JSON: %v", line, err)
				}
				if _, err := time.Parse(time.RFC3339Nano, rec.Time); err != nil {
					t.Errorf("log line %q: time is not RFC 3339: %v", line, err)
				}
				if (rec.Msg == started || rec.Msg == stopped) && rec.Logger != "maintenance" {
					t.Errorf("log line %q: logger = %q, want maintenance", line, rec.Logger)
				}
				got[rec.Msg] = rec.Level
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("logged %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewACMEKeepsGlobalsUntouched(t *testing.T) {
	storage, issuers := certmagic.Default.Storage, certmagic.Default.Issuers
	acmeCA := certmagic.DefaultACME.CA
	newTestACME(t, validOptions(t))
	if certmagic.Default.Storage != storage || len(certmagic.Default.Issuers) != len(issuers) {
		t.Error("certmagic.Default was modified")
	}
	if certmagic.DefaultACME.CA != acmeCA || certmagic.DefaultACME.DNS01Solver != nil {
		t.Error("certmagic.DefaultACME was modified")
	}
}

func TestObtainBackoffSchedule(t *testing.T) {
	want := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}
	if !slices.Equal(obtainBackoff, want) {
		t.Errorf("obtainBackoff = %v, want %v", obtainBackoff, want)
	}
	m := newTestACME(t, validOptions(t))
	if !slices.Equal(m.backoff, want) {
		t.Errorf("Manager backoff = %v, want %v", m.backoff, want)
	}
	if m.attempt != 5*time.Minute {
		t.Errorf("Manager attempt = %v, want 5m", m.attempt)
	}
}

// TestRunBoundsEachAttempt: a stalled attempt ends at its deadline and Run
// goes on retrying (U12-ASTRA-2).
func TestRunBoundsEachAttempt(t *testing.T) {
	m := newTestACME(t, validOptions(t))
	m.backoff = []time.Duration{time.Millisecond}
	m.attempt = 50 * time.Millisecond
	var calls int
	m.manage = func(ctx context.Context, _ []string) error {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Errorf("attempt %d has no deadline", calls)
		}
		if calls == 1 { // stalls, as a Cloudflare call without a timeout would
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				t.Error("the stalled attempt was not cancelled within 5s")
				return errors.New("stalled")
			}
		}
		_, err := m.cfg.CacheUnmanagedTLSCertificate(ctx, wildcardCert(t), nil)
		return err
	}
	if err := m.Run(t.Context()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 || !m.Ready() {
		t.Errorf("calls = %d, Ready() = %v, want 2, true", calls, m.Ready())
	}
}

func TestRunRetriesWithBackoff(t *testing.T) {
	m := newTestACME(t, validOptions(t))
	m.backoff = []time.Duration{time.Millisecond}
	cert := wildcardCert(t)

	var calls int
	m.manage = func(ctx context.Context, names []string) error {
		calls++
		if want := []string{"*." + testDomain}; !slices.Equal(names, want) {
			t.Errorf("manage names = %v, want %v", names, want)
		}
		if m.Ready() {
			t.Errorf("Ready() = true during attempt %d, want false until the certificate is obtained", calls)
		}
		if calls < 3 {
			return errors.New("dns-01 failed")
		}
		_, err := m.cfg.CacheUnmanagedTLSCertificate(ctx, cert, nil)
		return err
	}

	if m.Ready() {
		t.Fatal("Ready() = true before Run")
	}
	if err := m.Run(t.Context()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 3 {
		t.Errorf("manage calls = %d, want 3", calls)
	}
	if !m.Ready() {
		t.Error("Ready() = false after Run, want true")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	m := newTestACME(t, validOptions(t))
	m.backoff = []time.Duration{time.Hour}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls int
	m.manage = func(context.Context, []string) error {
		calls++
		cancel() // the backoff wait must end on cancellation, not after an hour
		return errors.New("dns-01 failed")
	}

	err := m.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("manage calls = %d, want 1", calls)
	}
	if m.Ready() {
		t.Error("Ready() = true after a cancelled Run, want false")
	}
}

// TestRunCancelledAttempt: an attempt ended by Run's context (a shutdown)
// is not an issuance failure: no Error line, no "retrying" (U12-FABLE-5).
func TestRunCancelledAttempt(t *testing.T) {
	var logs bytes.Buffer
	o := validOptions(t)
	o.Logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	m := newTestACME(t, o)
	m.backoff = []time.Duration{time.Millisecond}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	m.manage = func(attempt context.Context, _ []string) error {
		cancel() // SIGTERM during the obtain
		<-attempt.Done()
		return fmt.Errorf("*.%s: obtaining certificate: %w", testDomain, attempt.Err())
	}
	if err := m.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v, want context.Canceled", err)
	}
	if got := logs.String(); strings.Contains(got, `"level":"ERROR"`) || strings.Contains(got, "retrying") {
		t.Errorf("logs = %s, want no Error line and no retry", got)
	}
}

func TestRunClampsBackoff(t *testing.T) {
	m := newTestACME(t, validOptions(t))
	m.backoff = []time.Duration{time.Millisecond, 2 * time.Millisecond}
	var calls int
	m.manage = func(ctx context.Context, _ []string) error {
		calls++
		if calls < 6 { // more failures than backoff entries
			return errors.New("dns-01 failed")
		}
		_, err := m.cfg.CacheUnmanagedTLSCertificate(ctx, wildcardCert(t), nil)
		return err
	}
	if err := m.Run(t.Context()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 6 || !m.Ready() {
		t.Errorf("calls = %d, Ready() = %v, want 6, true", calls, m.Ready())
	}
}

func TestReadyACMERequiresValidCertificate(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		cert tls.Certificate
		want bool
	}{
		{"valid wildcard", wildcardCert(t), true},
		{"expired wildcard", selfSigned(t, now.Add(-48*time.Hour), now.Add(-time.Hour), "*."+testDomain), false},
		{"not yet valid wildcard", selfSigned(t, now.Add(time.Hour), now.Add(48*time.Hour), "*."+testDomain), false},
		{"other name", selfSigned(t, now.Add(-time.Hour), now.Add(time.Hour), "*.other.example.test"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestACME(t, validOptions(t))
			m.manage = func(ctx context.Context, _ []string) error {
				_, err := m.cfg.CacheUnmanagedTLSCertificate(ctx, tc.cert, nil)
				return err
			}
			if err := m.Run(t.Context()); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := m.Ready(); got != tc.want {
				t.Errorf("Ready() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetCertificateACME(t *testing.T) {
	m := newTestACME(t, validOptions(t))
	cert := wildcardCert(t)
	if _, err := m.cfg.CacheUnmanagedTLSCertificate(t.Context(), cert, nil); err != nil {
		t.Fatalf("cache certificate: %v", err)
	}
	got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "abc." + testDomain})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if len(got.Certificate) == 0 || string(got.Certificate[0]) != string(cert.Certificate[0]) {
		t.Error("GetCertificate did not return the cached wildcard certificate")
	}
}

func TestRunStatic(t *testing.T) {
	cert, _ := testpki.ServerTLS(t, testDomain)
	if err := NewStatic(cert).Run(t.Context()); err != nil {
		t.Errorf("Run on a static manager = %v, want nil", err)
	}
}

func TestStatic(t *testing.T) {
	t.Run("serves the certificate", func(t *testing.T) {
		cert, _ := testpki.ServerTLS(t, testDomain)
		m := NewStatic(cert)
		got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: testDomain})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if len(got.Certificate) == 0 || string(got.Certificate[0]) != string(cert.Certificate[0]) {
			t.Error("GetCertificate did not return the static certificate")
		}
		if !m.Ready() {
			t.Error("Ready() = false, want true")
		}
	})

	t.Run("expired leaf is not ready", func(t *testing.T) {
		now := time.Now()
		m := NewStatic(selfSigned(t, now.Add(-48*time.Hour), now.Add(-time.Hour), testDomain))
		if m.Ready() {
			t.Error("Ready() = true for an expired certificate, want false")
		}
	})

	// Readiness needs NotBefore <= now < NotAfter; a nil Leaf is parsed (U12-ASTRA-6).
	t.Run("validity", func(t *testing.T) {
		now := time.Now()
		withoutLeaf := func(c tls.Certificate) tls.Certificate {
			c.Leaf = nil
			return c
		}
		tests := []struct {
			name string
			cert tls.Certificate
			want bool
		}{
			{"not yet valid", selfSigned(t, now.Add(time.Hour), now.Add(48*time.Hour), testDomain), false},
			{"expired without leaf", withoutLeaf(selfSigned(t, now.Add(-48*time.Hour), now.Add(-time.Hour), testDomain)), false},
			{"not yet valid without leaf", withoutLeaf(selfSigned(t, now.Add(time.Hour), now.Add(48*time.Hour), testDomain)), false},
			{"valid without leaf", withoutLeaf(selfSigned(t, now.Add(-time.Hour), now.Add(time.Hour), testDomain)), true},
			{"no certificate", tls.Certificate{}, false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				if got := NewStatic(tc.cert).Ready(); got != tc.want {
					t.Errorf("Ready() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("load from files", func(t *testing.T) {
		cert, _ := testpki.ServerTLS(t, testDomain)
		certFile, keyFile := writePEM(t, cert)
		m, err := LoadStatic(certFile, keyFile)
		if err != nil {
			t.Fatalf("LoadStatic: %v", err)
		}
		if !m.Ready() {
			t.Error("Ready() = false, want true")
		}
		got, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: testDomain})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		if string(got.Certificate[0]) != string(cert.Certificate[0]) {
			t.Error("GetCertificate did not return the certificate read from the file")
		}
	})

	t.Run("load errors", func(t *testing.T) {
		cert, _ := testpki.ServerTLS(t, testDomain)
		certFile, keyFile := writePEM(t, cert)
		otherCert, _ := testpki.ServerTLS(t, testDomain)
		_, otherKeyFile := writePEM(t, otherCert)
		garbage := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(garbage, []byte("not pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		missing := filepath.Join(t.TempDir(), "missing.pem")

		tests := []struct {
			name              string
			certFile, keyFile string
		}{
			{"garbage certificate", garbage, keyFile},
			{"garbage key", certFile, garbage},
			{"missing certificate", missing, keyFile},
			{"missing key", certFile, missing},
			{"key does not match", certFile, otherKeyFile},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				m, err := LoadStatic(tc.certFile, tc.keyFile)
				if err == nil {
					t.Fatalf("LoadStatic succeeded (%v), want an error", m)
				}
			})
		}
	})
}

func TestCloseIsIdempotent(t *testing.T) {
	m, err := NewACME(validOptions(t))
	if err != nil {
		t.Fatalf("NewACME: %v", err)
	}
	m.Close()
	m.Close()
	NewStatic(tls.Certificate{}).Close()
}
