// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lleidanet provides the Lleidanet / inDenova natural person
// certificate type (beta). Pass its provider to certcheck.NewHandler.
package lleidanet

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the Lleidanet / inDenova provider (beta): natural person
// certificates in software (profile lleidanet-natural-person-sw). Revocation
// is checked by CRL only.
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.Lleidanet(), opts...)
}
