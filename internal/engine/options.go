// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/opts"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// FromOptions builds the provider of a public constructor (providers/...):
// it applies the certcheck options over the defaults (the process-wide
// revocation checker, time.Now, slog.Default()). The declaration is compiled
// in and tested, so a load error (pin mismatch, non-CA anchor, malformed
// declaration, handled extension without a parser) is a build-time invariant
// violation and panics with the loader's message. An anchor outside validity
// is not an error: the provider may be inert (see New).
func FromOptions(p profiles.Provider, options ...certcheck.Option) certcheck.Provider {
	s := opts.Apply(options...)
	rev := s.Revocation
	if rev == nil {
		var err error
		if rev, err = opts.DefaultRevocation(); err != nil {
			panic("certcheck: default revocation checker: " + err.Error())
		}
	}
	e, err := New(Config{Provider: p, Revocation: rev, Now: s.Now, Logger: s.Logger, Version: s.Version, MaxChainLen: s.MaxChainLen})
	if err != nil {
		panic("certcheck: provider " + p.ID + ": " + err.Error())
	}
	return e
}
