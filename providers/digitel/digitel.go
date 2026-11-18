// Package digitel provides the DIGITEL ON citizen certificate type. Pass
// its provider to certcheck.NewHandler.
package digitel

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the DIGITEL ON Ciudadano provider: qualified citizen
// certificates in software issued by DIGITEL TS QUALIFIED CA G1 (profile
// digitel-citizen-sw-g1).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.Digitel(), opts...)
}
