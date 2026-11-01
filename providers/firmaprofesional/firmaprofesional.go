// Package firmaprofesional provides the Firmaprofesional natural person
// certificate type (beta). Pass its provider to certcheck.NewHandler.
package firmaprofesional

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the Firmaprofesional provider (beta): personal natural person
// certificates without a qualified signature creation device (profile
// firmaprofesional-personal-sw).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.Firmaprofesional(), opts...)
}
