// Package certcheck authenticates people by the client certificate their
// browser presents over TLS, for the Spanish certificate types it supports
// (FNMT, idCAT, ACCV, DNIe and others).
//
// A program picks the certificate types it accepts by constructing their
// providers (one package per issuer under providers/, for example
// idcat.New() or fnmt.New(), or providers.All()) and builds a Handler from
// them. The Handler supplies the tls.Config of the listener that requests the
// client certificate (TLSConfig) and verifies the certificate of each request
// (Auth). Verification checks the chain against pinned trust anchors only, the
// profile (exact policy OIDs), the key usage, test-certificate markers, the
// holder's identity and the revocation status (OCSP, then CRL), and fails
// closed. A success is a *Result with the typed Identity; a failure is an
// *Error with a typed ErrorCode and session-bound Diagnostics.
//
// Diagnostics contain certificate details: show them only to the browser that
// ran the check and log Diagnostics.LogAttrs instead.
package certcheck
