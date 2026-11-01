// Package providers builds every supported certificate type at once.
// Programs that accept only some types import their packages instead
// (providers/fnmt, providers/idcat, ...).
package providers

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/providers/accv"
	"github.com/vocdoni/cert-check/providers/anf"
	"github.com/vocdoni/cert-check/providers/bewor"
	"github.com/vocdoni/cert-check/providers/digitel"
	"github.com/vocdoni/cert-check/providers/dnie"
	"github.com/vocdoni/cert-check/providers/firmaprofesional"
	"github.com/vocdoni/cert-check/providers/fnmt"
	"github.com/vocdoni/cert-check/providers/idcat"
	"github.com/vocdoni/cert-check/providers/lleidanet"
	"github.com/vocdoni/cert-check/providers/sectigo"
	"github.com/vocdoni/cert-check/providers/signe"
	"github.com/vocdoni/cert-check/providers/uanataca"
)

// constructors lists every certificate type in display order: the standard
// ones first, then the beta group.
var constructors = []func(...certcheck.Option) certcheck.Provider{
	fnmt.New, idcat.New, accv.New, digitel.New, bewor.New, sectigo.New,
	fnmt.NewRepresentative, fnmt.NewEmployee, firmaprofesional.New, anf.New, uanataca.New, signe.New, lleidanet.New, dnie.New,
}

// All returns every supported certificate type in display order (standard
// first, then beta), built with opts. A type with no valid anchor at
// construction (inert) is omitted, so the result can be passed to
// certcheck.NewHandler as is.
func All(opts ...certcheck.Option) []certcheck.Provider {
	out := make([]certcheck.Provider, 0, len(constructors))
	for _, newProvider := range constructors {
		if p := newProvider(opts...); len(p.CAs()) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// Standard is All without the beta types.
func Standard(opts ...certcheck.Option) []certcheck.Provider {
	var out []certcheck.Provider
	for _, p := range All(opts...) {
		if !p.Info().Beta {
			out = append(out, p)
		}
	}
	return out
}

// ByID returns the certificate type whose Info().ID is id, built with opts.
// It reports false for an unknown ID and for an inert type.
func ByID(id string, opts ...certcheck.Option) (certcheck.Provider, bool) {
	for _, newProvider := range constructors {
		if p := newProvider(opts...); p.Info().ID == id {
			if len(p.CAs()) == 0 {
				return nil, false
			}
			return p, true
		}
	}
	return nil, false
}
