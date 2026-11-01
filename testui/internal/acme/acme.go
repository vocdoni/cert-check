// Package acme provides the auth listener's certificate: certmagic with the
// Cloudflare DNS-01 solver only (HTTP-01 and TLS-ALPN-01 disabled), storage
// under the data directory, or a static certificate for local runs and tests.
package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// Options configures the ACME manager.
type Options struct {
	AuthDomain      string // certificate name is "*.<AuthDomain>"
	DataDir         string // storage at <DataDir>/certmagic
	Email           string
	Staging         bool
	CloudflareToken string
	OverrideDomain  string // optional DNS-01 CNAME delegation target
	Logger          *slog.Logger
}

// Manager serves the auth certificate and reports readiness.
type Manager struct {
	name   string
	cfg    *certmagic.Config // nil in static mode
	cache  *certmagic.Cache  // nil in static mode
	static *tls.Certificate
	ready  atomic.Bool
	log    *slog.Logger
	// manage performs one obtain/load attempt (cfg.ManageSync); tests replace it.
	manage    func(context.Context, []string) error
	backoff   []time.Duration
	closeOnce sync.Once
}

// NewACME builds a certmagic-backed manager. Run obtains the certificate; call
// Close to stop the certmagic cache when done.
func NewACME(o Options) (*Manager, error) {
	if o.AuthDomain == "" || o.DataDir == "" || o.Email == "" || o.CloudflareToken == "" {
		return nil, errors.New("acme: AuthDomain, DataDir, Email and CloudflareToken are required")
	}
	m := &Manager{name: "*." + o.AuthDomain, log: o.Logger}
	if m.log == nil {
		m.log = slog.Default()
	}
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
	})
	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: filepath.Join(o.DataDir, "certmagic")},
		OCSP:    certmagic.OCSPConfig{DisableStapling: true},
	})
	ca := certmagic.LetsEncryptProductionCA
	if o.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   o.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider:    &cloudflare.Provider{APIToken: o.CloudflareToken},
			OverrideDomain: o.OverrideDomain,
		}},
	})
	cfg.Issuers = []certmagic.Issuer{issuer}
	m.cfg, m.cache, m.manage, m.backoff = cfg, cache, cfg.ManageSync, obtainBackoff
	return m, nil
}

// NewStatic serves a fixed certificate (CERTCHECK_TLS_CERT_FILE/_KEY_FILE or tests).
func NewStatic(cert tls.Certificate) *Manager {
	m := &Manager{static: &cert, log: slog.Default()}
	m.ready.Store(true)
	return m
}

// LoadStatic reads a PEM certificate chain and key.
func LoadStatic(certFile, keyFile string) (*Manager, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("acme: static certificate: %w", err)
	}
	return NewStatic(c), nil
}

// Backoff between failed obtain attempts (Let's Encrypt allows 5 failed
// validations per hostname per hour; the process stays up and not ready).
var obtainBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

// Run obtains (or loads from storage) the certificate, retrying with backoff
// until it succeeds or ctx ends; certmagic then renews in the background.
// It returns nil once the certificate is ready (static mode: immediately).
func (m *Manager) Run(ctx context.Context) error {
	if m.cfg == nil {
		return nil
	}
	for i := 0; ; i++ {
		err := m.manage(ctx, []string{m.name}) // ManageSync: one interactive attempt, no internal retries
		if err == nil {
			m.ready.Store(true)
			m.log.Info("auth certificate ready", "name", m.name)
			return nil
		}
		wait := m.backoff[min(i, len(m.backoff)-1)]
		m.log.Error("auth certificate not obtained; retrying", "name", m.name, "error", err.Error(), "retryIn", wait.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Close stops certmagic's background renewal. It is safe to call more than
// once and is a no-op for a static manager.
func (m *Manager) Close() {
	if m.cache == nil {
		return
	}
	m.closeOnce.Do(m.cache.Stop)
}

// GetCertificate is the tls.Config hook.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.static != nil {
		return m.static, nil
	}
	return m.cfg.GetCertificate(hello)
}

// Ready reports whether a currently valid certificate is loaded.
func (m *Manager) Ready() bool {
	if !m.ready.Load() {
		return false
	}
	if m.static != nil {
		return m.static.Leaf == nil || time.Now().Before(m.static.Leaf.NotAfter)
	}
	for _, c := range m.cache.AllMatchingCertificates("readyz" + m.name[1:]) {
		if c.Leaf != nil && time.Now().Before(c.Leaf.NotAfter) {
			return true
		}
	}
	return false
}
