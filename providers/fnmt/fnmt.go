// Package fnmt provides the certificate types of the FNMT-RCM (Fábrica
// Nacional de Moneda y Timbre). Pass its providers to certcheck.NewHandler.
package fnmt

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the FNMT Persona Física provider: citizen certificates issued
// by AC FNMT Usuarios (profile fnmt-citizen-rsa) and AC USUARIOS G2
// (fnmt-citizen-g2).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.FNMT(), opts...)
}

// NewRepresentative returns the FNMT Representante provider (beta):
// certificates of a representative of a legal person or entity, issued by AC
// Representación (profile fnmt-representative-rsa) and AC REPRESENTACIÓN G2
// (fnmt-representative-g2).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func NewRepresentative(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.FNMTRepresentative(), opts...)
}

// NewEmployee returns the FNMT Empleado Público provider (beta): public
// employee certificates in software, issued by AC Sector Público (profile
// fnmt-employee-rsa) and AC SECTOR PÚBLICO G2 (fnmt-employee-g2).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func NewEmployee(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.FNMTEmployee(), opts...)
}
