// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package idcat provides the idCAT certificate type of the Consorci AOC
// (Catalonia). Pass its provider to certcheck.NewHandler.
package idcat

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the idCAT Certificat provider: citizen certificates issued by
// EC-Ciutadania (profile aoc-idcat-g2) and SubCA CIUTADANIA Q (G3) A.2
// (aoc-idcat-g3). opts are certcheck options. If no pinned anchor is valid
// at construction the provider is inert (no CAs) and certcheck.NewHandler
// rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.IDCAT(), opts...)
}
