// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// keyAlgorithm and reportAttempts moved here from certauth/diagnostics.go
// (certcheck.DescribeCertificate keeps its own keyAlgorithm).

func keyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	}
	return c.PublicKeyAlgorithm.String()
}

// describeChain returns the diagnostics of a received chain within the
// bounds: at most maxLen+1 entries (nil certificates skipped), each name cut
// to at most maxChainDN bytes plus a "..." marker, and the leaf described
// only when its DER is within MaxCertificateDER.
func describeChain(chain []*x509.Certificate, maxLen int) ([]ChainEntry, *CertificateDetails) {
	var entries []ChainEntry
	for _, c := range chain[:min(len(chain), maxLen+1)] {
		if c != nil {
			entries = append(entries, chainEntry(c))
		}
	}
	var leaf *CertificateDetails
	if len(chain) > 0 && chain[0] != nil && len(chain[0].Raw) <= MaxCertificateDER {
		leaf = describeCertificate(chain[0])
	}
	return entries, leaf
}

func reportAttempts(in []revocation.Attempt) []RevocationAttempt {
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return new(t.UTC())
	}
	out := make([]RevocationAttempt, 0, len(in))
	for _, a := range in {
		out = append(out, RevocationAttempt{
			Method: a.Method, URL: a.URL, HTTPStatus: a.HTTPStatus, DurationMS: a.Duration.Milliseconds(),
			Outcome: a.Outcome, Detail: a.Detail, FromCache: a.FromCache, ProducedAt: opt(a.ProducedAt),
			ThisUpdate: opt(a.ThisUpdate), NextUpdate: opt(a.NextUpdate), ResponderSubject: a.ResponderSubject,
			NonceSent: a.NonceSent, NonceEchoed: a.NonceEchoed,
		})
	}
	return out
}

// maxChainDN, chainEntry and capDN mirror package certcheck (handler.go).
// maxChainDN bounds each subject and issuer string of a chain entry: the
// client chose both, and real DNs are a few hundred bytes.
const maxChainDN = 1 << 10

// chainEntry describes c for Diagnostics.Chain, each name capped by capDN.
func chainEntry(c *x509.Certificate) ChainEntry {
	return ChainEntry{Subject: capDN(c.Subject.String()), Issuer: capDN(c.Issuer.String())}
}

// capDN returns s when it is at most maxChainDN bytes; otherwise it keeps at
// most maxChainDN bytes, cut back to a rune boundary, plus a "..." marker.
func capDN(s string) string {
	if len(s) <= maxChainDN {
		return s
	}
	return strings.ToValidUTF8(s[:maxChainDN], "") + "..."
}
