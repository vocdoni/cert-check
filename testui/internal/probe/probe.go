// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package probe checks, from the network it runs on, that the revocation
// endpoints of every enabled profile answer with evidence the revocation
// checker accepts (spec AC8). It backs the `cert-check probe` subcommand.
package probe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// Kind is what a Target probes.
type Kind string

// Target kinds.
const (
	// KindOCSP sends one request for a random serial under Issuer.
	KindOCSP Kind = "ocsp"
	// KindCRL fetches a CRL, checks its signature against Issuer and
	// evaluates it as the checker does (cost bound, freshness, IDP name and
	// scope, and the IDP name a CA with several CRLs requires).
	KindCRL Kind = "crl"
	// KindSpecimen runs the full revocation check of a live specimen.
	KindSpecimen Kind = "specimen"
)

// Valid reports whether k is a defined kind.
func (k Kind) Valid() bool {
	return k == KindOCSP || k == KindCRL || k == KindSpecimen
}

// Target is one endpoint (or specimen) to probe.
type Target struct {
	Profile  string            // profile ID
	Kind     Kind              // what to probe
	URL      string            // OCSP responder or CRL URL; unused for KindSpecimen
	Issuer   *x509.Certificate // pinned CA: OCSP CertID issuer, CRL signer or the specimen's issuer
	Specimen *x509.Certificate // KindSpecimen only: a live certificate expected to be good
	Policy   revocation.Policy // the profile's policy: host allowlists and nonce
	Scope    revocation.Scope  // KindCRL: what the CRL is evaluated for; zero means ScopeLeaf
	// Covers (KindCRL) are the certificates the CRL is judged for, each with
	// the distribution points of its own CDP, as the checker reads them (the
	// DNIe intermediates). nil is a certificate whose only DP names URL.
	Covers []*x509.Certificate
}

func (t Target) validate(rc *revocation.Checker) error {
	switch {
	case t.Profile == "":
		return errors.New("no profile")
	case !t.Kind.Valid():
		return fmt.Errorf("unknown kind %q", t.Kind)
	case t.Issuer == nil:
		return errors.New("no issuer")
	case t.Kind != KindSpecimen && t.URL == "":
		return errors.New("no URL")
	case t.Kind == KindSpecimen && t.Specimen == nil:
		return errors.New("specimen target without a certificate")
	case t.Kind == KindSpecimen && rc == nil:
		return errors.New("specimen target without a revocation checker")
	}
	if err := t.Policy.Validate(); err != nil {
		return err
	}
	if t.Kind == KindCRL {
		_, err := crlContexts(t)
		return err
	}
	return nil
}

// Verdict classifies one probe line.
type Verdict string

// Verdicts. Evidence the checker would reject is a FAIL; an endpoint that
// could not be reached or answered with an error status is a WARN.
const (
	VerdictOK   Verdict = "OK"
	VerdictWarn Verdict = "WARN"
	VerdictFail Verdict = "FAIL"
)

// Summary counts the verdicts of a run.
type Summary struct {
	OK, Warn, Fail int
}

// Failed reports whether any target failed, or whether nothing was verified
// (no OK line, also when there was no target); the probe then exits non-zero.
func (s Summary) Failed() bool { return s.Fail > 0 || s.nothingVerified() }

func (s Summary) nothingVerified() bool { return s.OK == 0 }

func (s *Summary) add(v Verdict) {
	switch v {
	case VerdictOK:
		s.OK++
	case VerdictWarn:
		s.Warn++
	default:
		s.Fail++
	}
}

// userAgent identifies probe fetches.
const userAgent = "cert-check-probe"

// serialBytes is the length of the random serial sent in OCSP probes.
const serialBytes = 16

// oidOCSPNonce is id-pkix-ocsp-nonce (RFC 8954).
var oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// Run probes targets in order, writing one line per target and a summary
// line to w. OCSP and CRL targets are fetched through a revocation.Fetcher
// with the production address checks; specimen targets go through rc
// (which may be nil when there are none). now is the clock, read once per
// OCSP or CRL target as the checker reads it once per check.
// The error reports an invalid target, a cancelled ctx or a write failure;
// endpoint failures are verdicts, counted in the Summary.
func Run(ctx context.Context, rc *revocation.Checker, targets []Target, now func() time.Time, w io.Writer) (Summary, error) {
	p := prober{rc: rc, fetcher: revocation.NewFetcher(revocation.FetcherOptions{UserAgent: userAgent}),
		now: now, crlLimit: revocation.DefaultCRLCacheBytes}
	return p.run(ctx, targets, w)
}

// prober is what a run uses; tests dial a fake network, set the clock and
// shrink the CRL cost limit.
type prober struct {
	rc       *revocation.Checker // specimen targets; nil when there are none
	fetcher  *revocation.Fetcher // OCSP and CRL targets
	now      func() time.Time
	crlLimit int64 // the checker's CRL cache limit: it refuses a CRL it could not keep
}

func (p prober) run(ctx context.Context, targets []Target, w io.Writer) (Summary, error) {
	for i, t := range targets {
		if err := t.validate(p.rc); err != nil {
			return Summary{}, fmt.Errorf("probe: target %d (%s %s): %w", i, t.Profile, t.Kind, err)
		}
	}
	var sum Summary
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		var l line
		switch t.Kind {
		case KindOCSP:
			l = probeOCSP(ctx, p.fetcher, t, p.now())
		case KindCRL:
			l = probeCRL(ctx, p.fetcher, t, p.now(), p.crlLimit)
		case KindSpecimen:
			l = probeSpecimen(ctx, p.rc, t)
		}
		sum.add(l.verdict)
		if _, err := io.WriteString(w, l.String()+"\n"); err != nil {
			return sum, err
		}
	}
	if err := ctx.Err(); err != nil { // cancelled during the last target
		return sum, err
	}
	note := ""
	if sum.nothingVerified() {
		note = " (no endpoint verified)"
	}
	_, err := fmt.Fprintf(w, "summary: %d ok, %d warn, %d fail%s\n", sum.OK, sum.Warn, sum.Fail, note)
	return sum, err
}

// line is one probe result.
type line struct {
	verdict    Verdict
	profile    string
	kind       Kind
	where      string // host and path probed
	httpStatus int
	elapsed    time.Duration
	outcome    revocation.Status
	detail     string
	signerKey  string // "responder" (OCSP) or "issuer" (CRL)
	signer     string
	nonce      string // "required/echoed|absent|mismatch", "-" when no nonce was sent
	thisUpdate time.Time
	nextUpdate time.Time
	size       int // CRL bytes
}

func (l line) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-4s %s %s %s http=%d %dms outcome=%s %s=%q nonce=%s thisUpdate=%s nextUpdate=%s",
		l.verdict, l.profile, l.kind, l.where, l.httpStatus, l.elapsed.Milliseconds(), l.outcome,
		l.signerKey, l.signer, l.nonce, stamp(l.thisUpdate), stamp(l.nextUpdate))
	if l.kind == KindCRL {
		fmt.Fprintf(&b, " bytes=%d", l.size)
	}
	fmt.Fprintf(&b, " detail=%q", l.detail)
	return b.String()
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// finish sets the outcome and its verdict; accepted lists the outcomes that pass.
func (l line) finish(st revocation.Status, detail string, accepted ...revocation.Status) line {
	l.outcome, l.detail = st, detail
	switch {
	case slices.Contains(accepted, st):
		l.verdict = VerdictOK
	case st == revocation.StatusUnavailable:
		l.verdict = VerdictWarn
	default:
		l.verdict = VerdictFail
	}
	return l
}

// ocspAnswered are the certStatus outcomes of an accepted response: a
// never-issued serial may come back revoked, unknown or even good.
var ocspAnswered = []revocation.Status{revocation.StatusGood, revocation.StatusRevoked, revocation.StatusUnknown}

// probeOCSP sends one request for a random serial under t.Issuer, with a
// nonce only when the profile requires one, as the checker does.
func probeOCSP(ctx context.Context, f *revocation.Fetcher, t Target, now time.Time) line {
	l := line{profile: t.Profile, kind: t.Kind, where: hostPath(t.URL), signerKey: "responder", nonce: "-"}
	serial, err := randomSerial()
	if err != nil {
		return l.finish(revocation.StatusUnavailable, err.Error())
	}
	id, err := revocation.NewCertID(crypto.SHA1, &x509.Certificate{SerialNumber: serial}, t.Issuer)
	if err != nil {
		return l.finish(revocation.StatusInvalidEvidence, err.Error())
	}
	var nonce []byte
	if t.Policy.OCSPNonce {
		nonce = make([]byte, revocation.NonceLength)
		if _, err := rand.Read(nonce); err != nil {
			return l.finish(revocation.StatusUnavailable, "nonce generation failed")
		}
	}
	reqDER, nonceExt, err := revocation.MarshalRequest(id, nonce)
	if err != nil {
		return l.finish(revocation.StatusInvalidEvidence, err.Error())
	}
	fr, err := f.Fetch(ctx, revocation.FetchRequest{
		URL: t.URL, Body: reqDER, ContentType: "application/ocsp-request", Accept: "application/ocsp-response",
		MaxBytes: revocation.MaxOCSPResponse, Timeout: revocation.OCSPTimeout, AllowedHosts: t.Policy.AllHosts(),
	})
	l.httpStatus, l.elapsed = fr.StatusCode, fr.Duration
	if err != nil {
		return l.finish(revocation.StatusUnavailable, err.Error())
	}
	resp, err := revocation.ParseResponse(fr.Body)
	if err != nil {
		return l.finish(revocation.StatusInvalidEvidence, err.Error())
	}
	ev, st, detail := revocation.VerifyOCSP(revocation.OCSPInput{Response: resp, Want: id, Issuer: t.Issuer, Now: now,
		MaxAge: t.Policy.MaxAge(), Nonce: nonceExt})
	l.signer, l.thisUpdate, l.nextUpdate = ev.ResponderSubject, ev.Single.ThisUpdate, ev.Single.NextUpdate
	if nonceExt != nil {
		l.nonce = nonceState(resp, nonceExt)
	}
	return l.finish(st, detail, ocspAnswered...)
}

// nonceState reports whether resp echoes the nonce extension value sent.
func nonceState(resp *revocation.Response, sent []byte) string {
	for _, e := range resp.Extensions {
		if e.ID.Equal(oidOCSPNonce) {
			if bytes.Equal(e.Value, sent) {
				return "required/echoed"
			}
			return "required/mismatch"
		}
	}
	return "required/absent"
}

// probeCRL fetches t.URL, checks the signature and issuer against t.Issuer
// and the checker's cost bound limit (ParseCRLLimit), and evaluates the CRL
// with revocation.EvaluateCRLFor, at t.Scope, for a random serial of each
// certificate it covers (crlContexts).
func probeCRL(ctx context.Context, f *revocation.Fetcher, t Target, now time.Time, limit int64) line {
	l := line{profile: t.Profile, kind: t.Kind, where: hostPath(t.URL), signerKey: "issuer", nonce: "-"}
	fr, err := f.Fetch(ctx, revocation.FetchRequest{URL: t.URL, MaxBytes: revocation.MaxCRLResponse,
		Timeout: revocation.CRLTimeout, AllowedHosts: t.Policy.AllHosts()})
	l.httpStatus, l.elapsed, l.size = fr.StatusCode, fr.Duration, len(fr.Body)
	if err != nil {
		return l.finish(revocation.StatusUnavailable, err.Error())
	}
	parsed, st, err := revocation.ParseCRLLimit(fr.Body, t.Issuer, limit)
	if err != nil {
		if st == "" || st == revocation.StatusGood {
			st = revocation.StatusInvalidEvidence
		}
		return l.finish(st, err.Error())
	}
	l.signer, l.thisUpdate, l.nextUpdate = t.Issuer.Subject.String(), parsed.ThisUpdate, parsed.NextUpdate // ParseCRLLimit checked the issuer name
	serial, err := randomSerial()
	if err != nil {
		return l.finish(revocation.StatusUnavailable, err.Error())
	}
	contexts, err := crlContexts(t)
	if err != nil {
		return l.finish(revocation.StatusInvalidEvidence, err.Error())
	}
	scope := t.Scope
	if scope == 0 {
		scope = revocation.ScopeLeaf
	}
	// Any listing of the random serial counts: the CRL applies and is fresh.
	for _, c := range contexts {
		var detail string
		st, _, detail = revocation.EvaluateCRLFor(parsed, &x509.Certificate{SerialNumber: serial}, c.dp, c.dps, scope, now)
		if st != revocation.StatusGood && st != revocation.StatusRevoked {
			return l.finish(st, c.name+detail)
		}
	}
	return l.finish(st, fmt.Sprintf("%d entries", len(parsed.Listed)), revocation.StatusGood, revocation.StatusRevoked)
}

// crlContext is a certificate a CRL is judged for: the distribution point
// the CRL was fetched from and all its usable ones, as the checker reads them.
type crlContext struct {
	name string // "<covered CA>: " for the detail; empty without Covers
	dp   revocation.DistributionPoint
	dps  []revocation.DistributionPoint
}

// crlContexts returns a context per usable DP naming t.URL of each covered
// certificate (the checker fetches the URL for each) or, without Covers,
// that of a certificate whose only DP names t.URL. A covered certificate
// that t.Issuer did not issue, or that names no such DP, is an error.
func crlContexts(t Target) ([]crlContext, error) {
	if len(t.Covers) == 0 {
		dp, err := revocation.URIDistributionPoint(t.URL)
		if err != nil {
			return nil, err
		}
		return []crlContext{{dp: dp, dps: []revocation.DistributionPoint{dp}}}, nil
	}
	var out []crlContext
	for _, c := range t.Covers {
		if c == nil || !bytes.Equal(c.RawIssuer, t.Issuer.RawSubject) {
			return nil, errors.New("covered certificate not issued by the CRL issuer")
		}
		dps, err := revocation.UsableDistributionPoints(c, t.Issuer)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Subject.CommonName, err)
		}
		n := len(out)
		for _, dp := range dps {
			if slices.ContainsFunc(dp.FullName, func(gn revocation.GeneralName) bool { u, ok := gn.URI(); return ok && u == t.URL }) {
				out = append(out, crlContext{name: c.Subject.CommonName + ": ", dp: dp, dps: dps})
			}
		}
		if len(out) == n {
			return nil, fmt.Errorf("%s: no usable distribution point names %s", c.Subject.CommonName, t.URL)
		}
	}
	return out, nil
}

// probeSpecimen runs rc.Check on a live specimen and expects good. The line
// shows the attempt that decided (the last one).
func probeSpecimen(ctx context.Context, rc *revocation.Checker, t Target) line {
	id := "specimen " + sha256Hex(t.Specimen.Raw)[:16]
	l := line{profile: t.Profile, kind: t.Kind, where: "-", signerKey: "responder", nonce: "-"}
	res, err := rc.Check(ctx, t.Specimen, t.Issuer, t.Policy)
	if err != nil {
		return l.finish(revocation.StatusInvalidEvidence, id+": "+err.Error())
	}
	for _, a := range res.Attempts {
		l.elapsed += a.Duration
	}
	if n := len(res.Attempts); n > 0 {
		a := res.Attempts[n-1]
		if a.URL != "" {
			l.where = hostPath(a.URL)
		}
		l.httpStatus, l.signer = a.HTTPStatus, a.ResponderSubject
		if a.NonceSent {
			l.nonce = "required/absent"
			if a.NonceEchoed {
				l.nonce = "required/echoed"
			}
		}
	}
	l.thisUpdate, l.nextUpdate = res.ThisUpdate, res.NextUpdate
	return l.finish(res.Status, id+": "+res.Detail, revocation.StatusGood)
}

// randomSerial returns a positive serial of exactly serialBytes bytes.
func randomSerial() (*big.Int, error) {
	b := make([]byte, serialBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = b[0]&0x7f | 0x40 // positive, no leading zero byte
	return new(big.Int).SetBytes(b), nil
}

// hostPath is the URL without scheme, for the report.
func hostPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host + u.EscapedPath()
}
