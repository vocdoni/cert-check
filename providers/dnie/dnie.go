// Package dnie provides the authentication certificate type of the DNI
// electrónico, the Spanish electronic identity card (beta). Pass its provider
// to certcheck.NewHandler.
package dnie

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the DNIe provider (beta): the authentication certificate of
// the DNI electrónico (profile dnie-auth). The certificate lives on the card,
// so the browser must already be able to use the card through a reader.
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.DNIe(), opts...)
}
