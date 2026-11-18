// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bewor provides the Bewor natural person certificate type. Pass
// its provider to certcheck.NewHandler.
package bewor

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the Bewor Persona Física provider: qualified natural person
// certificates in software issued by BEWOR TECH CA1 (profile
// bewor-natural-person-sw).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.Bewor(), opts...)
}
