// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package certcheck

import (
	"log/slog"
	"time"

	"github.com/vocdoni/cert-check/internal/opts"
)

// Option configures providers (the constructors under providers/) and
// NewHandler.
type Option func(*opts.Settings)

// WithRevocation makes providers share r for OCSP and CRL checks. Without
// it, every provider uses one process-wide default with the User-Agent
// "cert-check/dev" and the wall clock. r must come from NewRevocation.
func WithRevocation(r *Revocation) Option {
	if r == nil || r.c == nil {
		panic("certcheck: WithRevocation needs a Revocation from NewRevocation")
	}
	return func(s *opts.Settings) { s.Revocation = r.c }
}

// WithClock sets the pipeline clock: providers check anchor validity at
// construction and certificates at validation with it, and the Handler
// stamps its own errors with it. The default is time.Now. The revocation
// checker keeps its own clock (RevocationOptions.Now).
func WithClock(now func() time.Time) Option {
	return func(s *opts.Settings) { s.Now = now }
}

// WithLogger sets the logger of construction warnings (an anchor outside
// validity, a disabled profile). The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *opts.Settings) { s.Logger = l }
}

// WithVersion sets Diagnostics.ServerVersion. The default is "".
func WithVersion(v string) Option {
	return func(s *opts.Settings) { s.Version = v }
}
