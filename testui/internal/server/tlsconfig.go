package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	certcheck "github.com/vocdoni/cert-check"
)

// ConfigOptions configures ServerConfig.
type ConfigOptions struct {
	Providers      []certcheck.Provider // one auth host each
	AuthDomain     string               // e.g. "auth.cert-check.vocdoni.dev"; provider hosts are "<id>.<AuthDomain>"
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	AllowTLS13     bool         // CERTCHECK_AUTH_TLS13 (deviation D2); default TLS 1.2 only
	Logger         *slog.Logger // handshake-level debug lines; nil = slog.Default()
}

// maxLoggedSNI caps the client-chosen server name in logs and errors.
const maxLoggedSNI = 64

// ServerConfig returns the auth listener's tls.Config. Its
// GetConfigForClient selects the provider config by exact, lowercased SNI
// "<id>.<AuthDomain>"; an unknown SNI is a handshake error (internal_error
// alert), so nothing is served without a provider. Each provider config is
// the certcheck.Handler TLSConfig of a handler holding that provider alone.
func ServerConfig(o ConfigOptions) (*tls.Config, error) {
	if len(o.Providers) == 0 || o.GetCertificate == nil || o.AuthDomain == "" {
		return nil, errors.New("server: Providers, GetCertificate and AuthDomain are required")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	var tlsOpts []certcheck.TLSOption
	if o.AllowTLS13 {
		tlsOpts = append(tlsOpts, certcheck.WithTLS13())
	}
	domain := strings.ToLower(o.AuthDomain)
	perSNI := map[string]*tls.Config{}
	for _, p := range o.Providers {
		h, err := certcheck.NewHandler([]certcheck.Provider{p})
		if err != nil {
			return nil, err
		}
		perSNI[p.Info().ID+"."+domain] = h.TLSConfig(o.GetCertificate, tlsOpts...)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := strings.ToLower(hello.ServerName)
			cfg, ok := perSNI[sni]
			if !ok {
				// Debug, not Warn: scanners reach the port with empty or
				// random SNI all the time. The client-chosen name is capped.
				shown := sni[:min(len(sni), maxLoggedSNI)]
				log.Debug("auth handshake rejected: unknown SNI", "sni", shown)
				return nil, fmt.Errorf("server: unknown server name %q", shown)
			}
			return cfg, nil
		},
	}, nil
}

// AuthHosts maps the auth listener's server names to provider IDs.
type AuthHosts struct {
	suffix string // "." + AuthDomain
}

// NewAuthHosts returns the AuthHosts of authDomain.
func NewAuthHosts(authDomain string) *AuthHosts {
	return &AuthHosts{suffix: "." + strings.ToLower(authDomain)}
}

// Provider returns the provider ID encoded in a TLS server name.
func (h *AuthHosts) Provider(serverName string) (string, bool) {
	id, ok := strings.CutSuffix(strings.ToLower(serverName), h.suffix)
	if !ok || id == "" || strings.Contains(id, ".") {
		return "", false
	}
	return id, true
}
