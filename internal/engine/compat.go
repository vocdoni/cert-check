// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine

import (
	"crypto/tls"
	"crypto/x509"

	certcheck "github.com/vocdoni/cert-check"
)

// The pipeline (checker.go) and its tests moved here from package certauth,
// where these names were declared. They now live in package certcheck; the
// aliases keep the moved code byte-identical apart from the declared changes.
type (
	CandidateResult    = certcheck.CandidateResult
	CertificateDetails = certcheck.CertificateDetails
	CertificateInfo    = certcheck.CertificateInfo
	ChainEntry         = certcheck.ChainEntry
	Diagnostics        = certcheck.Diagnostics
	Error              = certcheck.Error
	ErrorCode          = certcheck.ErrorCode
	ProviderRef        = certcheck.ProviderRef
	Result             = certcheck.Result
	RevocationAttempt  = certcheck.RevocationAttempt
	RevocationInfo     = certcheck.RevocationInfo
	Step               = certcheck.Step
	TLSInfo            = certcheck.TLSInfo
)

// Bounds, error codes and steps of package certcheck.
const (
	DefaultMaxChainLen = certcheck.DefaultMaxChainLen
	MaxCertificateDER  = certcheck.MaxCertificateDER

	CodeNoCertificate               = certcheck.CodeNoCertificate
	CodeProviderMismatch            = certcheck.CodeProviderMismatch
	CodeUntrustedIssuer             = certcheck.CodeUntrustedIssuer
	CodeInvalidChain                = certcheck.CodeInvalidChain
	CodeExpired                     = certcheck.CodeExpired
	CodeNotYetValid                 = certcheck.CodeNotYetValid
	CodeUnsupportedProfile          = certcheck.CodeUnsupportedProfile
	CodeUnsupportedPurpose          = certcheck.CodeUnsupportedPurpose
	CodeWeakAlgorithm               = certcheck.CodeWeakAlgorithm
	CodeTestCertificate             = certcheck.CodeTestCertificate
	CodeIdentityInvalid             = certcheck.CodeIdentityInvalid
	CodeIdentityUnsupportedDocument = certcheck.CodeIdentityUnsupportedDocument
	CodeRevoked                     = certcheck.CodeRevoked
	CodeRevocationUnknown           = certcheck.CodeRevocationUnknown
	CodeRevocationUnavailable       = certcheck.CodeRevocationUnavailable
	CodeInternal                    = certcheck.CodeInternal

	StepBounds     = certcheck.StepBounds
	StepAlgorithms = certcheck.StepAlgorithms
	StepPath       = certcheck.StepPath
	StepProfile    = certcheck.StepProfile
	StepPurpose    = certcheck.StepPurpose
	StepTestMarker = certcheck.StepTestMarker
	StepIdentity   = certcheck.StepIdentity
	StepRevocation = certcheck.StepRevocation
)

// Codes is certcheck.Codes.
var Codes = certcheck.Codes

// NewDiagnosticID is certcheck.NewDiagnosticID.
func NewDiagnosticID() string { return certcheck.NewDiagnosticID() }

// DescribeTLS is certcheck.DescribeTLS.
func DescribeTLS(cs *tls.ConnectionState) *TLSInfo { return certcheck.DescribeTLS(cs) }

func describeCertificate(c *x509.Certificate) *CertificateDetails {
	return certcheck.DescribeCertificate(c)
}
