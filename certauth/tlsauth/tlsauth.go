// Package tlsauth is the handler-like integration a CSP imports: a per-SNI
// tls.Config that requests client certificates with the provider's CA list,
// and Handler.Authenticate, which validates the peer chain of a request.
package tlsauth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/vocdoni/cert-check/certauth"
)

// ErrMisdirected: the request Host differs from the TLS SNI (answer 421).
var ErrMisdirected = errors.New("tlsauth: Host does not match the TLS server name")

// ConfigOptions configures ServerConfig.
type ConfigOptions struct {
	Checker        *certauth.Checker
	AuthDomain     string // e.g. "auth.cert-check.vocdoni.dev"; provider hosts are "<id>.<AuthDomain>"
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	AllowTLS13     bool         // CERTCHECK_AUTH_TLS13 (deviation D2); default TLS 1.2 only
	Logger         *slog.Logger // handshake-level debug lines; nil = slog.Default()
}

// maxLoggedSNI caps the client-chosen server name in logs and errors.
const maxLoggedSNI = 64

var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// ServerConfig returns the auth listener's tls.Config. Its
// GetConfigForClient selects the provider config by exact, lowercased SNI
// "<id>.<AuthDomain>"; an unknown SNI is a handshake error (internal_error
// alert), so nothing is served without a provider.
func ServerConfig(o ConfigOptions) (*tls.Config, error) {
	if o.Checker == nil || o.GetCertificate == nil || o.AuthDomain == "" {
		return nil, errors.New("tlsauth: Checker, GetCertificate and AuthDomain are required")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	maxVersion := uint16(tls.VersionTLS12)
	if o.AllowTLS13 {
		maxVersion = tls.VersionTLS13
	}
	domain := strings.ToLower(o.AuthDomain)
	perSNI := map[string]*tls.Config{}
	for _, p := range o.Checker.Providers() {
		pool, err := o.Checker.ClientCAs(p.ID)
		if err != nil {
			return nil, err
		}
		perSNI[p.ID+"."+domain] = &tls.Config{
			MinVersion:             tls.VersionTLS12,
			MaxVersion:             maxVersion,
			CipherSuites:           tls12Suites,
			CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			ClientAuth:             tls.RequestClientCert,
			ClientCAs:              pool,
			SessionTicketsDisabled: true,
			NextProtos:             []string{"http/1.1"},
			GetCertificate:         o.GetCertificate,
		}
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
				return nil, fmt.Errorf("tlsauth: unknown server name %q", shown)
			}
			return cfg, nil
		},
	}, nil
}

// Handler validates the client certificate of requests served on the auth listener.
type Handler struct {
	checker *certauth.Checker
	suffix  string // "." + AuthDomain
}

// NewHandler returns a Handler for authDomain.
func NewHandler(c *certauth.Checker, authDomain string) *Handler {
	return &Handler{checker: c, suffix: "." + strings.ToLower(authDomain)}
}

// Provider returns the provider ID encoded in a TLS server name.
func (h *Handler) Provider(serverName string) (string, bool) {
	id, ok := strings.CutSuffix(strings.ToLower(serverName), h.suffix)
	if !ok || id == "" || strings.Contains(id, ".") {
		return "", false
	}
	return id, true
}

// CheckHost returns ErrMisdirected when r.Host (port stripped, lowercased)
// differs from r.TLS.ServerName.
func CheckHost(r *http.Request) error {
	if r.TLS == nil {
		return ErrMisdirected
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || !strings.EqualFold(host, r.TLS.ServerName) {
		return ErrMisdirected
	}
	return nil
}

// Authenticate validates r.TLS.PeerCertificates for the provider named by
// r.TLS.ServerName. Every call re-runs the full pipeline. The error is
// *certauth.Error (diagnostics include the TLS details). For a request
// without TLS state the error is CodeInternal and its Diagnostics are empty:
// it carries no diagnostic ID.
func (h *Handler) Authenticate(r *http.Request) (*certauth.Result, error) {
	if r.TLS == nil {
		return nil, &certauth.Error{Code: certauth.CodeInternal, Retryable: true, Detail: "request without TLS state"}
	}
	providerID, _ := h.Provider(r.TLS.ServerName)
	res, err := h.checker.Check(r.Context(), providerID, r.TLS.PeerCertificates)
	tlsInfo := certauth.DescribeTLS(r.TLS)
	if err != nil {
		if e, ok := errors.AsType[*certauth.Error](err); ok {
			e.Diagnostics.TLS = tlsInfo
		}
		return nil, err
	}
	res.Diagnostics.TLS = tlsInfo
	return res, nil
}
