package profiles

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
)

//go:embed anchors/*.pem
var embeddedAnchors embed.FS

// AnchorsFS returns the embedded anchor files (for tests that compare them
// with the research bundle).
func AnchorsFS() fs.FS { return embeddedAnchors }

// Config configures New.
type Config struct {
	Providers []Provider        // display order
	Reserved  identity.Reserved // reserved identities and name markers
	Now       time.Time         // load time: anchor validity is checked against it
	Logger    *slog.Logger      // nil = slog.Default()
	Files     fs.FS             // where Anchor.File is read; nil = embedded anchors
}

// Enabled is a loaded profile with parsed anchors and pools. It is read-only
// for callers: the pools and slices are the ones Verify trusts.
type Enabled struct {
	Profile       Profile
	Anchors       []*x509.Certificate
	Intermediates []*x509.Certificate
	Roots         *x509.CertPool // anchors only
	Inter         *x509.CertPool // pinned intermediates only (never client-sent certificates)
	fingerprints  map[string]struct{}
}

// IsFingerprintMarker reports whether a leaf SHA-256 (hex) is a known specimen.
func (e *Enabled) IsFingerprintMarker(sha256Hex string) bool {
	_, ok := e.fingerprints[sha256Hex]
	return ok
}

type loadedProvider struct {
	info     Provider // Profiles holds only enabled profiles
	enabled  []*Enabled
	clientCA *x509.CertPool
}

// Registry is the immutable loaded registry. Safe for concurrent use.
type Registry struct {
	providers []*loadedProvider
	byID      map[string]*loadedProvider
	reserved  identity.Reserved
}

var (
	providerIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	profileIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hexSHA256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	oidRe        = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)
)

// Default loads the production registry from the embedded anchors.
func Default(now time.Time, logger *slog.Logger) (*Registry, error) {
	return New(Config{Providers: All(), Reserved: identity.DefaultReserved(), Now: now, Logger: logger})
}

// New validates and loads a registry. A pin mismatch, a non-CA anchor or an
// invalid declaration is fatal. A profile whose anchors have all expired (or
// are not yet valid) is disabled with a warning; a pinned intermediate outside
// validity, or signed only by such anchors, is skipped likewise; a provider
// without enabled profiles is hidden.
func New(cfg Config) (*Registry, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	files := cfg.Files
	if files == nil {
		files = embeddedAnchors
	}
	if cfg.Now.IsZero() {
		return nil, errors.New("profiles: Config.Now is required")
	}
	r := &Registry{byID: map[string]*loadedProvider{}, reserved: cfg.Reserved}
	profileIDs := map[string]bool{}
	for _, p := range cfg.Providers {
		if !providerIDRe.MatchString(p.ID) || p.Name == "" {
			return nil, fmt.Errorf("profiles: invalid provider %q", p.ID)
		}
		if _, dup := r.byID[p.ID]; dup {
			return nil, fmt.Errorf("profiles: duplicate provider %q", p.ID)
		}
		lp := &loadedProvider{info: p, clientCA: x509.NewCertPool()}
		lp.info.Profiles = nil
		for _, prof := range p.Profiles {
			if profileIDs[prof.ID] {
				return nil, fmt.Errorf("profiles: duplicate profile %q", prof.ID)
			}
			profileIDs[prof.ID] = true
			if prof.ProviderID != p.ID {
				return nil, fmt.Errorf("profiles: profile %q declares provider %q inside %q", prof.ID, prof.ProviderID, p.ID)
			}
			e, err := loadProfile(prof, files, cfg.Now, log)
			if err != nil {
				return nil, err
			}
			if e == nil {
				continue // disabled: all anchors outside validity
			}
			lp.enabled = append(lp.enabled, e)
			lp.info.Profiles = append(lp.info.Profiles, prof)
			for _, c := range e.Anchors {
				lp.clientCA.AddCert(c)
			}
			for _, c := range e.Intermediates {
				lp.clientCA.AddCert(c)
			}
		}
		if err := CheckAmbiguity(lp.enabled); err != nil {
			return nil, err
		}
		r.byID[p.ID] = lp
		if len(lp.enabled) == 0 {
			log.Warn("provider hidden: no enabled profile", "provider", p.ID)
			continue
		}
		r.providers = append(r.providers, lp)
	}
	return r, nil
}

func loadProfile(p Profile, files fs.FS, now time.Time, log *slog.Logger) (*Enabled, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	e := &Enabled{Profile: p, Roots: x509.NewCertPool(), Inter: x509.NewCertPool(), fingerprints: map[string]struct{}{}}
	var declared []*x509.Certificate // every anchor, before the validity filter
	for _, a := range p.Anchors {
		c, err := loadAnchor(a, files)
		if err != nil {
			return nil, fmt.Errorf("profiles: %s: %w", p.ID, err)
		}
		declared = append(declared, c)
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			log.Warn("anchor outside validity, not loaded", "profile", p.ID, "anchor", a.SHA256)
			continue
		}
		e.Anchors = append(e.Anchors, c)
		e.Roots.AddCert(c)
	}
	if len(e.Anchors) == 0 {
		log.Warn("profile disabled: no valid anchor", "profile", p.ID)
		return nil, nil
	}
	for _, a := range p.Intermediates {
		c, err := loadAnchor(a, files)
		if err != nil {
			return nil, fmt.Errorf("profiles: %s intermediate: %w", p.ID, err)
		}
		signed := func(root *x509.Certificate) bool { return c.CheckSignatureFrom(root) == nil }
		if !slices.ContainsFunc(declared, signed) {
			return nil, fmt.Errorf("profiles: %s: intermediate %s is not signed by a profile anchor", p.ID, a.SHA256)
		}
		if !slices.ContainsFunc(e.Anchors, signed) {
			log.Warn("intermediate signer outside validity, not loaded", "profile", p.ID, "intermediate", a.SHA256)
			continue
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			log.Warn("intermediate outside validity, not loaded", "profile", p.ID, "intermediate", a.SHA256)
			continue
		}
		e.Intermediates = append(e.Intermediates, c)
		e.Inter.AddCert(c)
	}
	if len(p.Intermediates) > 0 && len(e.Intermediates) == 0 {
		log.Warn("profile disabled: no valid pinned intermediate", "profile", p.ID)
		return nil, nil
	}
	for _, m := range p.TestMarkers {
		if m.SHA256 != "" {
			e.fingerprints[m.SHA256] = struct{}{}
		}
	}
	return e, nil
}

func validateProfile(p Profile) error {
	var errs []error
	if !profileIDRe.MatchString(p.ID) || p.Name == "" || !p.HolderRole.Valid() {
		errs = append(errs, errors.New("invalid id, name or role"))
	}
	if len(p.Anchors) == 0 || len(p.PolicyOIDs) == 0 {
		errs = append(errs, errors.New("anchors and policy OIDs are required"))
	}
	for _, o := range append(slices.Clone(p.PolicyOIDs), p.HandledCriticalExtensions...) {
		if !oidRe.MatchString(o) {
			errs = append(errs, fmt.Errorf("invalid OID %q", o))
		}
	}
	if p.EKU != EKURequireClientAuth && p.EKU != EKUAllowAbsent {
		errs = append(errs, errors.New("EKU rule unset"))
	}
	if p.Algorithms.MinRSABits != 0 && p.Algorithms.MinRSABits < 2048 {
		errs = append(errs, errors.New("MinRSABits below the 2048 floor"))
	}
	if err := p.Identity.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := p.Revocation.Validate(); err != nil {
		errs = append(errs, err)
	}
	for _, m := range p.TestMarkers {
		if (m.SHA256 == "") == (len(m.Subject) == 0) || (m.SHA256 != "" && !hexSHA256Re.MatchString(m.SHA256)) {
			errs = append(errs, errors.New("test marker needs exactly one of SHA256 or Subject"))
		}
		for _, am := range m.Subject {
			if !oidRe.MatchString(am.OID.String()) || strings.TrimSpace(am.Value) == "" {
				errs = append(errs, errors.New("test marker attribute needs an OID and a value"))
			}
		}
		if strings.TrimSpace(m.Source) == "" {
			errs = append(errs, errors.New("test marker without Source"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("profiles: %s: %w", p.ID, err)
	}
	return nil
}

func loadAnchor(a Anchor, files fs.FS) (*x509.Certificate, error) {
	der := a.DER
	if der == nil {
		b, err := fs.ReadFile(files, a.File)
		if err != nil {
			return nil, err
		}
		blk, rest := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" || len(bytesTrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%s: want exactly one PEM certificate", a.File)
		}
		der = blk.Bytes
	}
	if !hexSHA256Re.MatchString(a.SHA256) || !hexSHA256Re.MatchString(a.SPKISHA256) {
		return nil, errors.New("anchor pins missing or malformed")
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, fmt.Errorf("anchor %s: SHA-256 pin mismatch", a.SHA256)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("anchor %s: %w", a.SHA256, err)
	}
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(spki[:]) != a.SPKISHA256 {
		return nil, fmt.Errorf("anchor %s: SPKI pin mismatch", a.SHA256)
	}
	if !c.BasicConstraintsValid || !c.IsCA {
		return nil, fmt.Errorf("anchor %s: not a CA", a.SHA256)
	}
	return c, nil
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == '\n' || b[0] == '\r' || b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// CheckAmbiguity rejects two profiles that share a pinned CA key (anchor or
// pinned intermediate, so a cross-certificate counts) and a policy OID (step 4
// could then match both). The loader applies it per provider; the certcheck
// Handler applies it across providers.
func CheckAmbiguity(es []*Enabled) error {
	for i, a := range es {
		for _, b := range es[i+1:] {
			if !sharesKey(slices.Concat(a.Anchors, a.Intermediates), slices.Concat(b.Anchors, b.Intermediates)) {
				continue
			}
			for _, o := range a.Profile.PolicyOIDs {
				if slices.Contains(b.Profile.PolicyOIDs, o) {
					return fmt.Errorf("profiles: %s and %s share an anchor and policy %s", a.Profile.ID, b.Profile.ID, o)
				}
			}
		}
	}
	return nil
}

func sharesKey(a, b []*x509.Certificate) bool {
	for _, x := range a {
		for _, y := range b {
			if string(x.RawSubjectPublicKeyInfo) == string(y.RawSubjectPublicKeyInfo) {
				return true
			}
		}
	}
	return false
}

// Providers returns the enabled providers in display order; each Provider's
// Profiles lists only enabled profiles. The slices inside are the registry's
// own: callers must not modify them.
func (r *Registry) Providers() []Provider {
	out := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.info)
	}
	return out
}

// Provider returns an enabled provider (read-only, as for Providers).
func (r *Registry) Provider(id string) (Provider, bool) {
	p, ok := r.byID[id]
	if !ok || len(p.enabled) == 0 {
		return Provider{}, false
	}
	return p.info, true
}

// Enabled returns the enabled profiles of a provider, in declaration order.
// The values are the registry's own (read-only): callers must not modify the
// slice, the profiles or their pools; ClientCAs returns a copy.
func (r *Registry) Enabled(providerID string) []*Enabled {
	p, ok := r.byID[providerID]
	if !ok {
		return nil
	}
	return p.enabled
}

// ClientCAs returns the anchors and pinned intermediates of the provider's
// enabled profiles (sent as certificate_authorities in the TLS handshake).
func (r *Registry) ClientCAs(providerID string) (*x509.CertPool, error) {
	p, ok := r.byID[providerID]
	if !ok || len(p.enabled) == 0 {
		return nil, fmt.Errorf("profiles: unknown provider %q", providerID)
	}
	return p.clientCA.Clone(), nil
}

// Reserved returns the reserved-identity registry.
func (r *Registry) Reserved() identity.Reserved { return r.reserved }
