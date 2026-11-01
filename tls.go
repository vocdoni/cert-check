package certcheck

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
)

// ErrMisdirected is returned by CheckHost when the request Host differs from
// the TLS server name (answer 421 Misdirected Request).
var ErrMisdirected = errors.New("certcheck: Host does not match the TLS server name")

// tls12Suites are the TLS 1.2 suites of TLSConfig: ECDHE with AEAD only.
var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// TLSOption configures Handler.TLSConfig.
type TLSOption func(*tlsSettings)

type tlsSettings struct{ tls13 bool }

// WithTLS13 allows TLS 1.3. Without it the configuration is TLS 1.2 only:
// TLS 1.3 needs an RSA-PSS CertificateVerify, which many smart cards, TPM
// keys and legacy Windows key stores cannot produce. The cost of TLS 1.2 is
// that the client certificate crosses the network unencrypted.
func WithTLS13() TLSOption { return func(s *tlsSettings) { s.tls13 = true } }

// TLSConfig returns the server configuration of a listener that
// authenticates with h: TLS 1.2 (see WithTLS13), ECDHE AEAD suites, curves
// X25519, P-256 and P-384, a client certificate requested but not required
// with h's CAs advertised, session tickets disabled (every connection
// presents its certificate again) and ALPN http/1.1 only. An http.Server adds
// h2 to NextProtos unless its Protocols allow HTTP/1 only: set them, as the
// Handler.Auth example does. getCert supplies the server certificate; it may
// be nil when the caller sets Certificates.
func (h *Handler) TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), options ...TLSOption) *tls.Config {
	var s tlsSettings
	for _, o := range options {
		if o != nil {
			o(&s)
		}
	}
	maxVersion := uint16(tls.VersionTLS12)
	if s.tls13 {
		maxVersion = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             maxVersion,
		CipherSuites:           slices.Clone(tls12Suites),
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		ClientAuth:             tls.RequestClientCert,
		ClientCAs:              h.ClientCAs(),
		SessionTicketsDisabled: true,
		NextProtos:             []string{"http/1.1"},
		GetCertificate:         getCert,
	}
}

// Auth verifies the client certificate chain of r (Verify on
// r.TLS.PeerCertificates) and adds the handshake details to the
// diagnostics. Every call runs the full pipeline. A request without TLS state
// is an internal error with empty Diagnostics. The error is always *Error.
func (h *Handler) Auth(r *http.Request) (*Result, error) {
	if r.TLS == nil {
		return nil, errNoTLS()
	}
	res, err := h.Verify(r.Context(), r.TLS.PeerCertificates)
	return withTLSInfo(r.TLS, res, err)
}

// AuthAs is Auth with the provider chosen by the caller (VerifyAs).
func (h *Handler) AuthAs(r *http.Request, providerID string) (*Result, error) {
	if r.TLS == nil {
		return nil, errNoTLS()
	}
	res, err := h.VerifyAs(r.Context(), providerID, r.TLS.PeerCertificates)
	return withTLSInfo(r.TLS, res, err)
}

func errNoTLS() *Error {
	return &Error{Code: CodeInternal, Retryable: true, Detail: "request without TLS state"}
}

// withTLSInfo adds the handshake details to a shallow copy of the outcome of
// Verify or VerifyAs, which is either a Result or an *Error, never neither.
// The outcome may be a provider's shared value: it is never modified.
func withTLSInfo(cs *tls.ConnectionState, res *Result, err error) (*Result, error) {
	info := DescribeTLS(cs)
	if err != nil {
		if e, ok := errors.AsType[*Error](err); ok && e != nil {
			cp := *e
			cp.Diagnostics.TLS = info
			return nil, &cp
		}
		return nil, err
	}
	cp := *res
	cp.Diagnostics.TLS = info
	return &cp, nil
}

// CheckHost returns ErrMisdirected when r.Host (port stripped, compared
// case-insensitively) differs from r.TLS.ServerName, or r has no TLS state.
// Call it before Auth on a listener that serves several names.
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
