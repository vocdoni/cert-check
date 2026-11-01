// Package revocation checks the revocation status of a certificate against
// its issuer with OCSP (preferred) and signed CRLs (fallback).
//
// Check takes the issuer from the caller's verified chain; it never derives it
// from client-supplied material.
package revocation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Status is the outcome of a revocation check. Only StatusGood passes.
type Status string

// Status values (spec "Revocation", status model).
const (
	StatusGood              Status = "good"
	StatusRevoked           Status = "revoked"
	StatusUnknown           Status = "unknown"
	StatusUnavailable       Status = "unavailable"
	StatusStale             Status = "stale"
	StatusInvalidEvidence   Status = "invalid_evidence"
	StatusUnsupportedMethod Status = "unsupported_method"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusGood, StatusRevoked, StatusUnknown, StatusUnavailable, StatusStale,
		StatusInvalidEvidence, StatusUnsupportedMethod:
		return true
	}
	return false
}

// Method is the evidence type that produced a status.
type Method string

// Method values.
const (
	MethodOCSP Method = "ocsp"
	MethodCRL  Method = "crl"
)

// DefaultMaxAgeWithoutNextUpdate bounds an OCSP response that omits nextUpdate.
const DefaultMaxAgeWithoutNextUpdate = 15 * time.Minute

// ClockSkew is the tolerance applied to evidence thisUpdate and to the OCSP
// producedAt only.
const ClockSkew = 5 * time.Minute

// Policy is the per-profile revocation configuration. Hosts are exact,
// lowercase DNS names, optionally with ":port" when the URL uses a
// non-default port. No wildcards.
type Policy struct {
	// OCSPHosts lists the hosts that leaf AIA OCSP URLs may point to.
	OCSPHosts []string
	// CRLHosts lists the hosts that CDP URLs may point to.
	CRLHosts []string
	// AllowCRL enables the CRL fallback.
	AllowCRL bool
	// OCSPNonce sends a 32-byte nonce and requires the responder to echo it.
	OCSPNonce bool
	// MaxAgeWithoutNextUpdate bounds thisUpdate when nextUpdate is absent.
	// Zero means DefaultMaxAgeWithoutNextUpdate.
	MaxAgeWithoutNextUpdate time.Duration
}

// Validate checks the policy is well formed.
func (p Policy) Validate() error {
	var errs []error
	for _, h := range append(append([]string(nil), p.OCSPHosts...), p.CRLHosts...) {
		if err := validateHostEntry(h); err != nil {
			errs = append(errs, err)
		}
	}
	if p.AllowCRL && len(p.CRLHosts) == 0 {
		errs = append(errs, errors.New("revocation: AllowCRL without CRLHosts"))
	}
	if len(p.OCSPHosts) == 0 && !p.AllowCRL {
		errs = append(errs, errors.New("revocation: no OCSP host and CRL not allowed"))
	}
	if p.MaxAgeWithoutNextUpdate < 0 {
		errs = append(errs, errors.New("revocation: negative MaxAgeWithoutNextUpdate"))
	}
	return errors.Join(errs...)
}

// MaxAge returns the effective bound for responses without nextUpdate.
func (p Policy) MaxAge() time.Duration {
	if p.MaxAgeWithoutNextUpdate == 0 {
		return DefaultMaxAgeWithoutNextUpdate
	}
	return p.MaxAgeWithoutNextUpdate
}

// AllHosts returns the union of OCSP and CRL hosts.
func (p Policy) AllHosts() []string {
	return append(append([]string(nil), p.OCSPHosts...), p.CRLHosts...)
}

// validateHostEntry accepts "name" or "name:port", the form hostAllowed
// builds: name is lowercase LDH labels with no trailing dot and a top label
// that is not all digits (so never an IPv4 literal); port is 1-65535 in
// plain decimal, but not 80 or 443 (hostAllowed strips a scheme's default
// port, so such an entry would not match the URLs it was written for).
func validateHostEntry(h string) error {
	host, port, hasPort := strings.Cut(h, ":")
	if !dnsName(host) {
		return fmt.Errorf("revocation: invalid host entry %q: not a lowercase DNS name", h)
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return fmt.Errorf("revocation: invalid host entry %q: bad port", h)
		}
		if n == 80 || n == 443 {
			return fmt.Errorf("revocation: invalid host entry %q: default port, use the bare name", h)
		}
	}
	return nil
}

func dnsName(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// Result is the outcome of Checker.Check for one certificate.
type Result struct {
	Status     Status
	Method     Method    // method that produced Status; "" when no method was usable
	CheckedAt  time.Time // time of the check (Checker clock)
	ThisUpdate time.Time
	NextUpdate time.Time // zero when the evidence carries none
	Source     string    // host that served the evidence
	RevokedAt  time.Time // zero unless Status == StatusRevoked
	Reason     int       // RFC 5280 CRLReason; -1 when absent
	Detail     string    // technical detail, never identity data
	Attempts   []Attempt // every attempt, in order, for diagnostics
}

// Attempt records one OCSP or CRL attempt for the diagnostic report.
type Attempt struct {
	Method           Method
	URL              string
	HTTPStatus       int
	Duration         time.Duration
	Outcome          Status
	Detail           string
	FromCache        bool
	ProducedAt       time.Time
	ThisUpdate       time.Time
	NextUpdate       time.Time
	ResponderSubject string
	NonceSent        bool
	NonceEchoed      bool
}
