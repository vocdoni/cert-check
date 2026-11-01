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
