// Package accv provides the citizen certificate type of the ACCV (Agencia
// de Tecnología y Certificación Electrónica, Comunitat Valenciana). Pass its
// provider to certcheck.NewHandler.
package accv

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the ACCV Ciudadano provider: qualified citizen certificates
// in software issued by ACCV RSA1 CLIENTE and ACCV ECC1 CLIENTE (profile
// accv-citizen-software-current).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.ACCV(), opts...)
}
