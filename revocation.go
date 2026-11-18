// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package certcheck

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// Revocation is a shared OCSP/CRL checker with bounded caches. Create it with
// NewRevocation and pass it to providers with WithRevocation; the zero value
// is not usable. It is safe for concurrent use.
type Revocation struct{ c *revocation.Checker }

// RevocationOptions configures NewRevocation. Zero values take the defaults.
type RevocationOptions struct {
	UserAgent        string           // "" = "cert-check/dev"
	Now              func() time.Time // evidence freshness clock; nil = time.Now; pass the WithClock clock in tests
	Logger           *slog.Logger     // rejected evidence warnings; nil = slog.Default()
	OCSPTimeout      time.Duration    // 0 = 5 s
	CRLTimeout       time.Duration    // 0 = 15 s
	CRLCacheBytes    int64            // parsed-CRL cache bound; 0 = 128 MiB
	OCSPCacheEntries int              // OCSP response cache bound; 0 = 4096
}

// NewRevocation returns a revocation checker. Negative timeouts or cache
// bounds are an error. Fetches go only to the hosts each profile allowlists
// and never to loopback, private or link-local addresses.
func NewRevocation(o RevocationOptions) (*Revocation, error) {
	c, err := revocation.NewChecker(revocation.Options{
		UserAgent: o.UserAgent, Now: o.Now, Logger: o.Logger, OCSPTimeout: o.OCSPTimeout, CRLTimeout: o.CRLTimeout,
		CRLCacheBytes: o.CRLCacheBytes, OCSPCacheEntries: o.OCSPCacheEntries,
	})
	if err != nil {
		return nil, fmt.Errorf("certcheck: %w", err)
	}
	return &Revocation{c: c}, nil
}
