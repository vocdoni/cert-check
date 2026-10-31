// Package certauth validates a TLS client-certificate chain against the
// pinned Spanish provider profiles and extracts the holder's typed identity.
// It is the importable entry point; see certauth/tlsauth for the HTTP/TLS glue.
package certauth

import (
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Identity and Document are the identity package's types.
type (
	Identity     = identity.Identity
	Document     = identity.Document
	Organization = identity.Organization
)

// ErrorCode is the typed failure reason shown to users.
type ErrorCode string

// Error codes (spec "Packages and public API").
const (
	CodeNoCertificate               ErrorCode = "no_certificate"
	CodeProviderMismatch            ErrorCode = "provider_mismatch"
	CodeUntrustedIssuer             ErrorCode = "untrusted_issuer"
	CodeInvalidChain                ErrorCode = "invalid_chain"
	CodeExpired                     ErrorCode = "expired"
	CodeNotYetValid                 ErrorCode = "not_yet_valid"
	CodeUnsupportedProfile          ErrorCode = "unsupported_profile"
	CodeUnsupportedPurpose          ErrorCode = "unsupported_purpose"
	CodeWeakAlgorithm               ErrorCode = "weak_algorithm"
	CodeTestCertificate             ErrorCode = "test_certificate"
	CodeIdentityInvalid             ErrorCode = "identity_invalid"
	CodeIdentityUnsupportedDocument ErrorCode = "identity_unsupported_document"
	CodeRevoked                     ErrorCode = "revoked"
	CodeRevocationUnknown           ErrorCode = "revocation_unknown"
	CodeRevocationUnavailable       ErrorCode = "revocation_unavailable"
	CodeInternal                    ErrorCode = "internal"
)

// Codes lists every ErrorCode (the server's message table must cover all).
var Codes = []ErrorCode{
	CodeNoCertificate, CodeProviderMismatch, CodeUntrustedIssuer, CodeInvalidChain, CodeExpired,
	CodeNotYetValid, CodeUnsupportedProfile, CodeUnsupportedPurpose, CodeWeakAlgorithm,
	CodeTestCertificate, CodeIdentityInvalid, CodeIdentityUnsupportedDocument, CodeRevoked,
	CodeRevocationUnknown, CodeRevocationUnavailable, CodeInternal,
}

// Retryable reports whether retrying later may succeed.
func (c ErrorCode) Retryable() bool { return c == CodeRevocationUnavailable || c == CodeInternal }

// Step is the pipeline step that failed.
type Step string

// Steps (diagnostics failedStep).
const (
	StepBounds     Step = "bounds"
	StepAlgorithms Step = "algorithms"
	StepPath       Step = "path"
	StepProfile    Step = "profile"
	StepPurpose    Step = "purpose"
	StepTestMarker Step = "test_marker"
	StepIdentity   Step = "identity"
	StepRevocation Step = "revocation"
)

// Error is the typed validation failure. Detail never contains identity data.
type Error struct {
	Code        ErrorCode
	Retryable   bool
	Detail      string
	Diagnostics Diagnostics
}

func (e *Error) Error() string { return "certauth: " + string(e.Code) + ": " + e.Detail }

// CertificateInfo describes the validated leaf.
type CertificateInfo struct {
	Subject      string    `json:"subject"` // RFC 4514
	Issuer       string    `json:"issuer"`  // issuer CN
	SerialHex    string    `json:"serialHex"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	SHA256       string    `json:"sha256"`
	KeyAlgorithm string    `json:"keyAlgorithm"` // e.g. "RSA-2048", "ECDSA-P-256"
}

// RevocationInfo is the leaf's accepted revocation evidence.
type RevocationInfo struct {
	Status     revocation.Status `json:"status"` // always "good" in a Result
	Method     revocation.Method `json:"method"`
	CheckedAt  time.Time         `json:"checkedAt"`
	ThisUpdate time.Time         `json:"thisUpdate"`
	NextUpdate *time.Time        `json:"nextUpdate"`
	Source     string            `json:"source"` // host
}

// Result is a successful validation.
type Result struct {
	Provider     profiles.ProviderInfo  `json:"provider"`
	Profile      profiles.ProfileInfo   `json:"profile"`
	Identity     Identity               `json:"identity"`
	Organization *identity.Organization `json:"organization"`
	Certificate  CertificateInfo        `json:"certificate"`
	Revocation   RevocationInfo         `json:"revocation"`
	ValidatedAt  time.Time              `json:"validatedAt"`
	Diagnostics  Diagnostics            `json:"diagnostics"`
}
