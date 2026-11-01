package certcheck

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/internal/opts"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// Handler authenticates HTTP requests that arrived over TLS with a client
// certificate, using a fixed set of certificate types. It is immutable and
// safe for concurrent use.
type Handler struct {
	providers []Provider          // construction order
	byID      map[string]Provider // Info().ID
	byIssuer  map[string]Provider // RawSubject of each advertised CA (unique across providers)
	cas       []*x509.Certificate // advertised CAs, deduplicated, provider order
	pool      *x509.CertPool      // cas
	roots     *x509.CertPool      // trust anchors of every provider (provider_mismatch only)
	inter     *x509.CertPool      // pinned intermediates of every provider (provider_mismatch only)
	now       func() time.Time
	version   string
}

// pinnedProfiles is implemented by the providers that this module builds. It
// exposes the loaded profiles behind CAs: which CAs are trust anchors and
// which are pinned intermediates, and the policy OIDs of each profile. A
// Provider without it (a test double) contributes every CA as a trust anchor
// and is checked for shared CA subjects only.
type pinnedProfiles interface {
	EnabledProfiles() []*profiles.Enabled
}

// NewHandler returns a Handler for providers. It needs at least one provider,
// unique provider IDs, no inert provider (one whose CAs are empty because no
// profile is valid at construction) and no ambiguity: no CA subject may be
// advertised by two providers, and no two profiles of different providers may
// share an anchor key and a policy OID. Acceptance therefore never depends on
// the order of providers. A nil entry is an error; a typed nil (a nil pointer
// stored in a non-nil Provider) is a programmer error and may panic.
// NewHandler uses WithClock and WithVersion; other options are ignored.
func NewHandler(providers []Provider, options ...Option) (*Handler, error) {
	if len(providers) == 0 {
		return nil, errors.New("certcheck: NewHandler needs at least one provider")
	}
	s := opts.Apply(options...)
	h := &Handler{byID: map[string]Provider{}, byIssuer: map[string]Provider{}, pool: x509.NewCertPool(),
		roots: x509.NewCertPool(), inter: x509.NewCertPool(), now: s.Now, version: s.Version}
	if h.now == nil {
		h.now = time.Now
	}
	var enabled []*profiles.Enabled
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("certcheck: provider %d is nil", i)
		}
		id := p.Info().ID
		if _, dup := h.byID[id]; dup {
			return nil, fmt.Errorf("certcheck: duplicate provider %q", id)
		}
		cas := p.CAs()
		if len(cas) == 0 {
			return nil, fmt.Errorf("certcheck: provider %q has no enabled profile", id)
		}
		for _, c := range cas {
			if c == nil {
				return nil, fmt.Errorf("certcheck: provider %q advertises a nil certificate", id)
			}
			if other, ok := h.byIssuer[string(c.RawSubject)]; ok && other.Info().ID != id {
				return nil, fmt.Errorf("certcheck: providers %q and %q both advertise the CA %q", other.Info().ID, id, c.Subject)
			}
			h.byIssuer[string(c.RawSubject)] = p
			if !slices.ContainsFunc(h.cas, c.Equal) {
				h.cas = append(h.cas, c)
				h.pool.AddCert(c)
			}
		}
		if pp, ok := p.(pinnedProfiles); ok {
			for _, e := range pp.EnabledProfiles() {
				enabled = append(enabled, e)
				for _, c := range e.Anchors {
					h.roots.AddCert(c)
				}
				for _, c := range e.Intermediates {
					h.inter.AddCert(c)
				}
			}
		} else {
			for _, c := range cas {
				h.roots.AddCert(c)
			}
		}
		h.byID[id] = p
		h.providers = append(h.providers, p)
	}
	if err := profiles.CheckAmbiguity(enabled); err != nil {
		// CheckAmbiguity's message carries its own package prefix.
		return nil, errors.New("certcheck: " + strings.TrimPrefix(err.Error(), "profiles: "))
	}
	return h, nil
}

// Name returns "certcheck", for adapters to blind-csp-shaped interfaces.
func (h *Handler) Name() string { return "certcheck" }

// RequireCertificate reports true: authentication needs a client
// certificate. (TLSConfig still requests the certificate without requiring
// it, so that a browser without one gets a no_certificate answer instead of
// a handshake failure.)
func (h *Handler) RequireCertificate() bool { return true }

// Certificates returns the DER of every advertised CA, deduplicated, in
// provider order. The slices are fresh copies.
func (h *Handler) Certificates() [][]byte {
	out := make([][]byte, 0, len(h.cas))
	for _, c := range h.cas {
		out = append(out, bytes.Clone(c.Raw))
	}
	return out
}

// CertificateCheck reports whether subject (a DER-encoded distinguished
// name) is the subject of an advertised CA.
func (h *Handler) CertificateCheck(subject []byte) bool {
	_, ok := h.byIssuer[string(subject)]
	return ok
}

// ClientCAs returns a fresh pool of the advertised CAs, for
// tls.Config.ClientCAs.
func (h *Handler) ClientCAs() *x509.CertPool { return h.pool.Clone() }

// Providers returns the providers in construction order (a fresh slice).
func (h *Handler) Providers() []Provider { return slices.Clone(h.providers) }

// Verify selects the provider whose CAs include the issuer of chain[0] (by
// exact subject bytes, as crypto/x509 finds parents) and returns its Verify
// verbatim. A chain without a leaf is no_certificate; a leaf whose issuer no
// provider advertises is untrusted_issuer at step path. A provider error that
// wraps an *Error is returned as that *Error; any other provider error, or a
// provider that returns neither a Result nor an error, gives an internal
// error. The error is always *Error.
func (h *Handler) Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, h.fail(chain, "", StepBounds, CodeNoCertificate, "no client certificate")
	}
	p, ok := h.byIssuer[string(chain[0].RawIssuer)]
	if !ok {
		return nil, h.fail(chain, "", StepPath, CodeUntrustedIssuer, "no provider advertises the leaf's issuer")
	}
	return h.verify(ctx, p, chain)
}

// VerifyAs verifies chain with the provider providerID, for servers that
// already know which certificate type the user chose (for example from the
// TLS server name). An unknown providerID is provider_mismatch at step
// bounds. When the provider answers untrusted_issuer at step path and the
// leaf chains to the pinned CAs of the handler's providers, the code becomes
// provider_mismatch: the user picked the wrong certificate type. That check
// builds a path only; it never accepts and makes no network request.
// Provider errors are handled as in Verify. The error is always *Error.
func (h *Handler) VerifyAs(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error) {
	p, ok := h.byID[providerID]
	if !ok {
		return nil, h.fail(chain, providerID, StepBounds, CodeProviderMismatch, "unknown provider")
	}
	res, err := h.verify(ctx, p, chain)
	if e, ok := errors.AsType[*Error](err); ok && e.Code == CodeUntrustedIssuer && e.Diagnostics.FailedStep == StepPath &&
		len(chain) > 0 && chain[0] != nil && h.chainsToPinnedCA(chain[0]) {
		mismatch := *e
		mismatch.Code, mismatch.Diagnostics.Code = CodeProviderMismatch, CodeProviderMismatch
		return nil, &mismatch
	}
	return res, err
}

// verify returns p.Verify(ctx, chain) as (Result, nil) or (nil, *Error). A
// provider breaking its contract (an error that holds no *Error or a nil
// *Error, or neither a Result nor an error) gives an internal error.
func (h *Handler) verify(ctx context.Context, p Provider, chain []*x509.Certificate) (*Result, error) {
	res, err := p.Verify(ctx, chain)
	switch {
	case err != nil:
		e, ok := errors.AsType[*Error](err)
		if ok && e != nil {
			return nil, e
		}
		if ok {
			return nil, h.fail(chain, p.Info().ID, "", CodeInternal, "provider returned a nil *certcheck.Error")
		}
		return nil, h.fail(chain, p.Info().ID, "", CodeInternal, "provider returned an error that is not *certcheck.Error")
	case res == nil:
		return nil, h.fail(chain, p.Info().ID, "", CodeInternal, "provider returned no result")
	}
	return res, nil
}

// chainsToPinnedCA is the former engine's unknownAuthorityCode: it reports
// whether the leaf, with UnhandledCriticalExtensions cleared, path-builds
// against the union of every provider's trust anchors and pinned
// intermediates. Classification only, never acceptance.
func (h *Handler) chainsToPinnedCA(leaf *x509.Certificate) bool {
	probe := *leaf
	probe.UnhandledCriticalExtensions = nil // classification only, never acceptance
	_, err := probe.Verify(x509.VerifyOptions{Roots: h.roots, Intermediates: h.inter, CurrentTime: h.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if _, unknown := errors.AsType[x509.UnknownAuthorityError](err); err != nil && unknown {
		return false
	}
	return true
}

// fail returns an *Error decided by the handler, with Diagnostics filled as
// a provider fills them for any failure, within the bounds: at most
// DefaultMaxChainLen+1 chain entries, and no description of a leaf over
// MaxCertificateDER.
func (h *Handler) fail(chain []*x509.Certificate, providerID string, step Step, code ErrorCode, detail string) *Error {
	d := Diagnostics{DiagnosticID: NewDiagnosticID(), Time: h.now().UTC(), ServerVersion: h.version, Provider: providerID,
		FailedStep: step, Code: code, TechnicalDetail: detail}
	for _, c := range chain[:min(len(chain), DefaultMaxChainLen+1)] {
		if c != nil {
			d.Chain = append(d.Chain, ChainEntry{Subject: c.Subject.String(), Issuer: c.Issuer.String()})
		}
	}
	if len(chain) > 0 && chain[0] != nil && len(chain[0].Raw) <= MaxCertificateDER {
		d.Certificate = DescribeCertificate(chain[0])
	}
	return &Error{Code: code, Retryable: code.Retryable(), Detail: detail, Diagnostics: d}
}
