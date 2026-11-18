// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package uanataca provides the Uanataca citizen certificate type (beta).
// Pass its provider to certcheck.NewHandler.
package uanataca

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the Uanataca provider (beta): qualified citizen certificates
// in software from any of its four issuing CAs (profile uanataca-citizen-sw).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.Uanataca(), opts...)
}
