package engine

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
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
// bounds: at most maxLen+1 entries (nil certificates skipped), and the leaf
// described only when its DER is within MaxCertificateDER.
func describeChain(chain []*x509.Certificate, maxLen int) ([]ChainEntry, *CertificateDetails) {
	var entries []ChainEntry
	for _, c := range chain[:min(len(chain), maxLen+1)] {
		if c != nil {
			entries = append(entries, ChainEntry{Subject: c.Subject.String(), Issuer: c.Issuer.String()})
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
