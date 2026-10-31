package certauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"time"

	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Diagnostics is the session-bound support report. It contains certificate
// details and is shown only to the browser that ran the transaction; use
// LogAttrs for logging.
type Diagnostics struct {
	DiagnosticID       string              `json:"diagnosticId"`
	Time               time.Time           `json:"time"`
	ServerVersion      string              `json:"serverVersion"`
	Provider           string              `json:"provider"`
	FailedStep         Step                `json:"failedStep"`
	Code               ErrorCode           `json:"code"`
	TechnicalDetail    string              `json:"technicalDetail"`
	TLS                *TLSInfo            `json:"tls"`
	Certificate        *CertificateDetails `json:"certificate"`
	Chain              []ChainEntry        `json:"chain"`
	ProfileCandidates  []CandidateResult   `json:"profileCandidates"`
	RevocationAttempts []RevocationAttempt `json:"revocationAttempts"`
}

// TLSInfo describes the handshake (filled by tlsauth).
type TLSInfo struct {
	Version                    string `json:"version"`
	CipherSuite                string `json:"cipherSuite"`
	SNI                        string `json:"sni"`
	ClientCertificatePresented bool   `json:"clientCertificatePresented"`
	ChainLength                int    `json:"chainLength"`
}

// CertificateDetails describes the presented leaf.
type CertificateDetails struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialHex          string    `json:"serialHex"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SHA256             string    `json:"sha256"`
	KeyAlgorithm       string    `json:"keyAlgorithm"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	KeyUsage           []string  `json:"keyUsage"`
	ExtKeyUsage        []string  `json:"extKeyUsage"`
	PolicyOIDs         []string  `json:"policyOids"`
	CriticalExtensions []string  `json:"criticalExtensions"`
	OCSPURLs           []string  `json:"ocspUrls"`
	CAIssuerURLs       []string  `json:"caIssuerUrls"`
	CDPURLs            []string  `json:"cdpUrls"`
}

// ChainEntry is the subject and issuer of one received certificate.
type ChainEntry struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// CandidateResult is the per-profile outcome of steps 3-4.
type CandidateResult struct {
	ProfileID string `json:"profileId"`
	Result    string `json:"result"`
}

// RevocationAttempt is revocation.Attempt in report form.
type RevocationAttempt struct {
	Method           revocation.Method `json:"method"`
	URL              string            `json:"url"`
	HTTPStatus       int               `json:"httpStatus"`
	DurationMS       int64             `json:"durationMs"`
	Outcome          revocation.Status `json:"outcome"`
	Detail           string            `json:"detail"`
	FromCache        bool              `json:"fromCache"`
	ProducedAt       *time.Time        `json:"producedAt"`
	ThisUpdate       *time.Time        `json:"thisUpdate"`
	NextUpdate       *time.Time        `json:"nextUpdate"`
	ResponderSubject string            `json:"responderSubject"`
	NonceSent        bool              `json:"nonceSent"`
	NonceEchoed      bool              `json:"nonceEchoed"`
}

// NewDiagnosticID returns 16 random bytes in hex.
func NewDiagnosticID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // since Go 1.24 crypto/rand.Read never returns an error (it crashes instead)
	return hex.EncodeToString(b)
}

// DescribeTLS builds TLSInfo from a connection state.
func DescribeTLS(cs *tls.ConnectionState) *TLSInfo {
	if cs == nil {
		return nil
	}
	return &TLSInfo{
		Version:                    tls.VersionName(cs.Version),
		CipherSuite:                tls.CipherSuiteName(cs.CipherSuite),
		SNI:                        cs.ServerName,
		ClientCertificatePresented: len(cs.PeerCertificates) > 0,
		ChainLength:                len(cs.PeerCertificates),
	}
}

func describeCertificate(c *x509.Certificate) *CertificateDetails {
	sum := sha256.Sum256(c.Raw)
	d := &CertificateDetails{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), SerialHex: fmt.Sprintf("%x", c.SerialNumber),
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), SHA256: hex.EncodeToString(sum[:]),
		KeyAlgorithm: keyAlgorithm(c), SignatureAlgorithm: c.SignatureAlgorithm.String(),
		OCSPURLs: slices.Clone(c.OCSPServer), CAIssuerURLs: slices.Clone(c.IssuingCertificateURL),
		CDPURLs: slices.Clone(c.CRLDistributionPoints),
	}
	for bit, name := range []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"} {
		if c.KeyUsage&(1<<bit) != 0 {
			d.KeyUsage = append(d.KeyUsage, name)
		}
	}
	for _, e := range c.ExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, extKeyUsageName(e))
	}
	for _, o := range c.UnknownExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, o.String())
	}
	for _, p := range c.Policies {
		d.PolicyOIDs = append(d.PolicyOIDs, p.String())
	}
	for _, e := range c.Extensions {
		if e.Critical {
			d.CriticalExtensions = append(d.CriticalExtensions, e.Id.String())
		}
	}
	return d
}

func keyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	}
	return c.PublicKeyAlgorithm.String()
}

func extKeyUsageName(e x509.ExtKeyUsage) string {
	switch e {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	}
	return fmt.Sprintf("eku(%d)", e)
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

// LogAttrs returns the non-PII fields allowed in logs: id, code, step,
// provider, candidates, issuer DN, policy OIDs, revocation host/status/
// duration, TLS version/cipher. Never subject, names, document, serial,
// leaf hash, URL paths or technicalDetail.
func (d Diagnostics) LogAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("diagnosticId", d.DiagnosticID),
		slog.String("code", string(d.Code)),
		slog.String("step", string(d.FailedStep)),
		slog.String("provider", d.Provider),
	}
	var cands []string
	for _, c := range d.ProfileCandidates {
		cands = append(cands, c.ProfileID+":"+c.Result)
	}
	attrs = append(attrs, slog.Any("candidates", cands))
	if d.Certificate != nil {
		attrs = append(attrs, slog.String("issuer", d.Certificate.Issuer), slog.Any("policies", d.Certificate.PolicyOIDs))
	}
	var revs []string
	for _, a := range d.RevocationAttempts {
		host := ""
		if u, err := url.Parse(a.URL); err == nil {
			host = u.Host
		}
		revs = append(revs, fmt.Sprintf("%s %s %d %s %dms", a.Method, host, a.HTTPStatus, a.Outcome, a.DurationMS))
	}
	attrs = append(attrs, slog.Any("revocation", revs))
	if d.TLS != nil {
		attrs = append(attrs, slog.String("tlsVersion", d.TLS.Version), slog.String("cipher", d.TLS.CipherSuite))
	}
	return attrs
}
