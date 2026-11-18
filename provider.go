package certcheck

import (
	"context"
	"crypto/x509"
)

// Provider verifies client certificates of one certificate type (an issuer
// family such as FNMT citizen or idCAT). Implementations are safe for
// concurrent use; Handler relies only on this interface, so consumers may
// provide test doubles.
type Provider interface {
	// Info describes the provider (stable ID, display name, description, beta flag).
	Info() ProviderInfo
	// CAs returns the pinned CA certificates a TLS server should advertise
	// in its CertificateRequest for this provider (anchors and pinned
	// intermediates). The slice and the certificates are shared; callers
	// must not modify them. Handler builds its own pools from them.
	CAs() []*x509.Certificate
	// Verify runs the full validation pipeline on a client certificate chain
	// as received in tls.ConnectionState.PeerCertificates. chain is used as
	// received: chain[0] is the leaf; chain[1:] are never used for path
	// building. A standalone Verify (no Handler) answers untrusted_issuer for
	// any leaf that does not chain to its own CAs. On failure the error is
	// *Error. Verify performs network I/O (OCSP/CRL) bounded by ctx; callers
	// set a deadline (the testing UI uses 40 s). A deadline hit is
	// *Error{Code: internal, Retryable: true}.
	Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error)
}

// ProviderInfo describes a provider. ID is a DNS label and stable.
type ProviderInfo struct {
	ID          string // e.g. "idcat"
	Name        string // display name, e.g. "idCAT Certificat"
	Description string // one sentence, as shown by the testing UI
	Beta        bool
}

// ProviderRef is the provider part of a Result (JSON {"id","name"}).
type ProviderRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
