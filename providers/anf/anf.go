// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package anf provides the ANF AC class 2 natural person certificate type
// (beta). Pass its provider to certcheck.NewHandler.
package anf

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the ANF AC provider (beta): class 2 natural person
// certificates in software, issued by ANF AC Qualified Certificates for
// eSignature (profile anf-asociacion-class2-sw) and ANF Qualified for
// eSignature CA (anf-sl-class2-sw).
// opts are certcheck options. If no pinned anchor is valid at construction
// the provider is inert (no CAs) and certcheck.NewHandler rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.ANF(), opts...)
}
