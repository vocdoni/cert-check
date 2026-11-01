package revocation

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"
)

// Options configures a Checker.
type Options struct {
	UserAgent        string           // "cert-check/<version>"
	DialContext      DialFunc         // tests only; nil = address-checking dialer
	Now              func() time.Time // nil = time.Now
	CRLCacheBytes    int64            // 0 = DefaultCRLCacheBytes
	OCSPCacheEntries int              // 0 = DefaultOCSPCacheEntries
	Logger           *slog.Logger     // nil = slog.Default()
	OCSPTimeout      time.Duration    // 0 = OCSPTimeout (5 s); tests shorten it
	CRLTimeout       time.Duration    // 0 = CRLTimeout (15 s)
}

// Checker checks revocation status. It is safe for concurrent use.
type Checker struct {
	fetcher *Fetcher
	now     func() time.Time
	crls    *crlCache
	ocsp    *ocspCache
	log     *slog.Logger
	ocspTO  time.Duration
	crlTO   time.Duration
	crlSem  chan struct{} // CRL fetches take at most half the fetch slots
}

// NewChecker builds a Checker. Zero cache bounds and timeouts take the
// defaults; negative ones are an error.
func NewChecker(o Options) (*Checker, error) {
	var errs []error
	if o.CRLCacheBytes < 0 {
		errs = append(errs, errors.New("revocation: negative CRLCacheBytes"))
	}
	if o.OCSPCacheEntries < 0 {
		errs = append(errs, errors.New("revocation: negative OCSPCacheEntries"))
	}
	if o.OCSPTimeout < 0 {
		errs = append(errs, errors.New("revocation: negative OCSPTimeout"))
	}
	if o.CRLTimeout < 0 {
		errs = append(errs, errors.New("revocation: negative CRLTimeout"))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	c := &Checker{
		fetcher: NewFetcher(FetcherOptions{UserAgent: o.UserAgent, DialContext: o.DialContext}),
		now:     o.Now,
		crls:    newCRLCache(o.CRLCacheBytes),
		ocsp:    newOCSPCache(o.OCSPCacheEntries),
		log:     o.Logger,
		ocspTO:  cmp.Or(o.OCSPTimeout, OCSPTimeout),
		crlTO:   cmp.Or(o.CRLTimeout, CRLTimeout),
		crlSem:  make(chan struct{}, MaxConcurrent/2),
	}
	if c.now == nil {
		c.now = time.Now
	}
	if o.CRLCacheBytes == 0 {
		c.crls.limit = DefaultCRLCacheBytes
	}
	if o.OCSPCacheEntries == 0 {
		c.ocsp.limit = DefaultOCSPCacheEntries
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	return c, nil
}

// Check returns the revocation status of cert, issued by issuer, under
// policy p. issuer must come from the caller's verified chain. A CA
// certificate (pinned intermediate) is checked with CA scope (ARLs with
// onlyContainsCACerts accepted). The error is non-nil only for misuse.
func (c *Checker) Check(ctx context.Context, cert, issuer *x509.Certificate, p Policy) (Result, error) {
	if cert == nil || issuer == nil {
		return Result{}, errors.New("revocation: nil certificate or issuer")
	}
	if cert.SerialNumber == nil || len(issuer.Raw) == 0 || len(issuer.RawSubject) == 0 || len(issuer.RawSubjectPublicKeyInfo) == 0 {
		return Result{}, errors.New("revocation: certificate or issuer lacks parsed DER fields")
	}
	if err := p.Validate(); err != nil {
		return Result{}, err
	}
	now := c.now()
	res := Result{CheckedAt: now, Reason: -1}
	scope := ScopeLeaf
	if cert.BasicConstraintsValid && cert.IsCA {
		scope = ScopeCA
	}

	ocspStatus := c.checkOCSP(ctx, cert, issuer, p, now, &res)
	switch ocspStatus {
	case StatusGood, StatusRevoked, StatusUnknown:
		res.Status, res.Method = ocspStatus, MethodOCSP
		return res, nil
	}
	crlStatus := StatusUnsupportedMethod
	if p.AllowCRL {
		crlStatus = c.checkCRL(ctx, cert, issuer, p, scope, now, &res)
		if crlStatus == StatusGood || crlStatus == StatusRevoked {
			res.Status, res.Method = crlStatus, MethodCRL
			return res, nil
		}
	}
	res.Status = worstFailure(ocspStatus, crlStatus)
	if res.Status == StatusInvalidEvidence {
		c.logRejected(issuer, res.Attempts)
	}
	return res, nil
}

// logRejected warns once per attempt whose evidence was rejected, with its
// method, outcome and host only: a URL path or query, a redirect target or
// an error text may carry data that does not belong in logs.
func (c *Checker) logRejected(issuer *x509.Certificate, attempts []Attempt) {
	logged := false
	for _, a := range attempts {
		if a.Outcome == StatusInvalidEvidence {
			c.log.Warn("revocation evidence rejected", "issuer", issuer.Subject.String(), "method", a.Method, "outcome", a.Outcome, "host", hostOf(a.URL))
			logged = true
		}
	}
	if !logged { // rejected before any attempt was recorded
		c.log.Warn("revocation evidence rejected", "issuer", issuer.Subject.String())
	}
}

// worstFailure folds two failed methods into one status: invalid evidence
// first (it is logged), then stale, otherwise unavailable. Neither method
// usable is unavailable.
func worstFailure(a, b Status) Status {
	switch {
	case a == StatusInvalidEvidence || b == StatusInvalidEvidence:
		return StatusInvalidEvidence
	case a == StatusStale || b == StatusStale:
		return StatusStale
	}
	return StatusUnavailable
}

func (c *Checker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate, p Policy, now time.Time, res *Result) Status {
	var urls []string
	for _, s := range cert.OCSPServer {
		if u, err := url.Parse(s); err == nil && hostAllowed(u, p.OCSPHosts) {
			urls = append(urls, s)
		}
	}
	if len(urls) == 0 {
		res.Attempts = append(res.Attempts, Attempt{Method: MethodOCSP, Outcome: StatusUnsupportedMethod, Detail: "no allowlisted OCSP URL"})
		res.Detail = "no allowlisted OCSP URL"
		return StatusUnsupportedMethod
	}
	key := issuerKey(issuer) + " " + SerialKey(cert.SerialNumber)
	if it, ok := c.ocsp.get(key, now, p); ok {
		c.fillOCSP(res, it)
		res.Attempts = append(res.Attempts, Attempt{Method: MethodOCSP, URL: it.source, Outcome: it.status, FromCache: true,
			ThisUpdate: it.thisUpdate, NextUpdate: it.nextUpdate, ResponderSubject: it.responderSubject})
		return it.status
	}
	id, err := NewCertID(crypto.SHA1, cert, issuer)
	if err != nil {
		res.Detail = err.Error()
		return StatusInvalidEvidence
	}
	last := StatusUnavailable
	for _, u := range urls {
		st, it := c.ocspOnce(ctx, u, id, issuer, p, now, res)
		switch st {
		case StatusGood, StatusRevoked, StatusUnknown:
			c.ocsp.put(key, it) // put ignores unknown
			return st
		}
		last = worstFailure(last, st)
	}
	return last
}

func (c *Checker) ocspOnce(ctx context.Context, u string, id CertID, issuer *x509.Certificate, p Policy, now time.Time, res *Result) (Status, ocspItem) {
	var nonce []byte
	if p.OCSPNonce {
		nonce = make([]byte, NonceLength)
		if _, err := rand.Read(nonce); err != nil {
			res.Detail = "nonce generation failed"
			return StatusUnavailable, ocspItem{}
		}
	}
	reqDER, nonceExt, err := MarshalRequest(id, nonce)
	if err != nil {
		res.Detail = err.Error()
		return StatusUnavailable, ocspItem{}
	}
	at := Attempt{Method: MethodOCSP, URL: u, NonceSent: nonce != nil}
	fr, err := c.fetcher.Fetch(ctx, FetchRequest{
		URL: u, Body: reqDER, ContentType: "application/ocsp-request", Accept: "application/ocsp-response",
		MaxBytes: MaxOCSPResponse, Timeout: c.ocspTO, AllowedHosts: p.AllHosts(),
	})
	at.HTTPStatus, at.Duration = fr.StatusCode, fr.Duration
	record := func(st Status, detail string) Status {
		at.Outcome, at.Detail = st, detail
		res.Attempts = append(res.Attempts, at)
		res.Detail = fmt.Sprintf("OCSP %s: %s", u, detail)
		return st
	}
	if err != nil {
		return record(StatusUnavailable, err.Error()), ocspItem{}
	}
	resp, err := ParseResponse(fr.Body)
	if err != nil {
		return record(StatusInvalidEvidence, err.Error()), ocspItem{}
	}
	ev, st, detail := VerifyOCSP(OCSPInput{Response: resp, Want: id, Issuer: issuer, Nonce: nonceExt, Now: now, MaxAge: p.MaxAge()})
	at.ProducedAt, at.ThisUpdate, at.NextUpdate = ev.ProducedAt, ev.Single.ThisUpdate, ev.Single.NextUpdate
	at.ResponderSubject, at.NonceEchoed = ev.ResponderSubject, ev.NonceEchoed
	st = record(st, detail)
	it := newOCSPItem(u, st, ev)
	if st == StatusGood || st == StatusRevoked || st == StatusUnknown {
		c.fillOCSP(res, it)
	}
	return st, it
}

func (c *Checker) fillOCSP(res *Result, it ocspItem) {
	res.ThisUpdate, res.NextUpdate, res.Source = it.thisUpdate, it.nextUpdate, it.source
	if it.status == StatusRevoked {
		res.RevokedAt, res.Reason = it.revokedAt, it.reason
	}
}

// checkCRL walks the usable distribution points in certificate order. A
// leaf is good at the first CRL that covers it and does not list it. A CA
// certificate (pinned intermediate) is checked against every usable
// distribution point and is good only when all of them answer good: AC RAIZ
// DNIE 2 publishes CA revocations in ARL.crl only, while AC DNIE 005/006
// name the empty CRL.crl first. With several DPs each CRL must name its DP
// in an IDP, so another CRL of the same issuer cannot stand in for the ARL.
func (c *Checker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate, p Policy, scope Scope, now time.Time, res *Result) Status {
	dps, err := ParseCRLDistributionPoints(cert)
	if err != nil {
		res.Attempts = append(res.Attempts, Attempt{Method: MethodCRL, Outcome: StatusUnsupportedMethod, Detail: err.Error()})
		return StatusUnsupportedMethod
	}
	usable := usableDistributionPoints(dps, issuer)
	needIDP := scope == ScopeCA && len(usable) > 1
	last, tried, good, failed := StatusUnsupportedMethod, false, false, false
	for _, dp := range usable {
		for _, gn := range dp.FullName {
			raw, ok := gn.URI()
			if !ok {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || !hostAllowed(u, p.CRLHosts) {
				continue
			}
			tried = true
			switch st := c.crlOnce(ctx, raw, cert, issuer, dp, p, scope, needIDP, now, res); st {
			case StatusRevoked:
				return st
			case StatusGood:
				if scope == ScopeLeaf {
					return st
				}
				good = true
			default:
				failed = true
				last = worstFailure(last, st)
			}
		}
	}
	if !tried {
		res.Attempts = append(res.Attempts, Attempt{Method: MethodCRL, Outcome: StatusUnsupportedMethod, Detail: "no usable allowlisted CDP URL"})
		return StatusUnsupportedMethod
	}
	if good && !failed {
		return StatusGood
	}
	return last
}

func (c *Checker) crlOnce(ctx context.Context, u string, cert, issuer *x509.Certificate, dp DistributionPoint, p Policy, scope Scope, needIDP bool, now time.Time, res *Result) Status {
	key := issuerKey(issuer) + " " + u
	load := c.crls.load(ctx, key, now, c.crlTO, func(fctx context.Context) crlLoad {
		at := Attempt{Method: MethodCRL, URL: u}
		select {
		case c.crlSem <- struct{}{}:
			defer func() { <-c.crlSem }()
		case <-fctx.Done():
			return crlLoad{status: StatusUnavailable, err: fctx.Err(), attempt: at}
		}
		fr, err := c.fetcher.Fetch(fctx, FetchRequest{URL: u, MaxBytes: MaxCRLResponse, Timeout: c.crlTO, AllowedHosts: p.AllHosts()})
		at.HTTPStatus, at.Duration = fr.StatusCode, fr.Duration
		if err != nil {
			return crlLoad{status: StatusUnavailable, err: err, attempt: at}
		}
		parsed, st, err := parseCRL(fr.Body, issuer, c.crls.limit)
		if err != nil {
			return crlLoad{status: st, err: err, attempt: at}
		}
		parsed.URL = u
		applies, _ := crlApplies(parsed, dp, now)
		return crlLoad{crl: parsed, status: StatusGood, attempt: at, admit: applies == StatusGood}
	})
	at := load.attempt
	if at.URL == "" {
		at.URL = u
	}
	if load.err != nil {
		at.Outcome, at.Detail = load.status, load.err.Error()
		res.Attempts = append(res.Attempts, at)
		res.Detail = fmt.Sprintf("CRL %s: %s", u, at.Detail)
		return load.status
	}
	st, rec, detail := EvaluateCRL(load.crl, cert, dp, scope, now)
	if st == StatusGood && needIDP && (load.crl.IDP == nil || len(load.crl.IDP.FullName) == 0) {
		st, detail = StatusUnsupportedMethod, "crl without an idp name for a CA with several DPs"
	}
	at.Outcome, at.Detail = st, detail
	at.ThisUpdate, at.NextUpdate = load.crl.ThisUpdate, load.crl.NextUpdate
	res.Attempts = append(res.Attempts, at)
	res.Detail = fmt.Sprintf("CRL %s: %s", u, detail)
	if st == StatusGood || st == StatusRevoked {
		res.ThisUpdate, res.NextUpdate, res.Source = load.crl.ThisUpdate, load.crl.NextUpdate, hostOf(u)
		if st == StatusRevoked {
			res.RevokedAt, res.Reason = rec.RevokedAt, rec.Reason
		}
	}
	return st
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
