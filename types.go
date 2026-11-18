// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package certcheck

import (
	"time"

	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// Field types owned by internal packages, aliased so that a program can name
// every type of a Result.
type (
	Identity         = identity.Identity
	Document         = identity.Document
	Organization     = identity.Organization
	Date             = identity.Date
	DocumentType     = identity.DocumentType
	RevocationStatus = revocation.Status
	RevocationMethod = revocation.Method
	Role             = profiles.Role
	ProfileInfo      = profiles.ProfileInfo
)

// Bounds applied to every chain before path building.
const (
	DefaultMaxChainLen = 10       // certificates in a received chain
	MaxCertificateDER  = 16 << 10 // bytes of one received certificate
)

// Values of the aliased enum types, for comparisons with Result fields
// (Profile.HolderRole, Identity.Document.Type, Revocation.Status and
// Revocation.Method, RevocationAttempt.Outcome and RevocationAttempt.Method).
const (
	RoleNaturalPerson  = profiles.RoleNaturalPerson
	RoleRepresentative = profiles.RoleRepresentative
	RolePublicEmployee = profiles.RolePublicEmployee

	DocumentDNI = identity.DocumentDNI
	DocumentNIE = identity.DocumentNIE

	RevocationStatusGood              = revocation.StatusGood
	RevocationStatusRevoked           = revocation.StatusRevoked
	RevocationStatusUnknown           = revocation.StatusUnknown
	RevocationStatusUnavailable       = revocation.StatusUnavailable
	RevocationStatusStale             = revocation.StatusStale
	RevocationStatusInvalidEvidence   = revocation.StatusInvalidEvidence
	RevocationStatusUnsupportedMethod = revocation.StatusUnsupportedMethod

	RevocationMethodOCSP = revocation.MethodOCSP
	RevocationMethodCRL  = revocation.MethodCRL
)

// ErrorCode is the typed failure reason shown to users.
type ErrorCode string

// Error codes, carried by every *Error and its Diagnostics.
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

// Codes lists every ErrorCode, for tables keyed by code (user messages, metrics).
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

// Pipeline steps, in order (Diagnostics.FailedStep).
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

func (e *Error) Error() string { return "certcheck: " + string(e.Code) + ": " + e.Detail }

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
	Status     RevocationStatus `json:"status"` // always "good" in a Result
	Method     RevocationMethod `json:"method"`
	CheckedAt  time.Time        `json:"checkedAt"`
	ThisUpdate time.Time        `json:"thisUpdate"`
	NextUpdate *time.Time       `json:"nextUpdate"`
	Source     string           `json:"source"` // host
}

// Result is a successful validation.
type Result struct {
	Provider     ProviderRef     `json:"provider"`
	Profile      ProfileInfo     `json:"profile"`
	Identity     Identity        `json:"identity"`
	Organization *Organization   `json:"organization"`
	Certificate  CertificateInfo `json:"certificate"`
	Revocation   RevocationInfo  `json:"revocation"`
	ValidatedAt  time.Time       `json:"validatedAt"`
	Diagnostics  Diagnostics     `json:"diagnostics"`
}
