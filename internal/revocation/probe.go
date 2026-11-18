// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocation

import (
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// URIDistributionPoint is the DistributionPoint of a CDP whose only
// fullName is the URI uri. It lets a caller that fetched a CRL from uri
// without a certificate (the testui probe) judge it with EvaluateCRL.
func URIDistributionPoint(uri string) (DistributionPoint, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes([]byte(uri)) })
	name, err := b.Bytes()
	if err != nil {
		return DistributionPoint{}, fmt.Errorf("distribution point: %w", err)
	}
	return DistributionPoint{FullName: []GeneralName{name}}, nil
}

// UsableDistributionPoints returns the distribution points of cert's CDP
// that the checker uses when issuer issued cert, for EvaluateCRLFor.
func UsableDistributionPoints(cert, issuer *x509.Certificate) ([]DistributionPoint, error) {
	dps, err := ParseCRLDistributionPoints(cert)
	if err != nil {
		return nil, err
	}
	return usableDistributionPoints(dps, issuer), nil
}

// ParseCRLLimit is ParseCRL with the checker's bound: a CRL whose cache
// cost would exceed maxCost (the CRL cache limit, DefaultCRLCacheBytes by
// default) is refused before the full parse.
func ParseCRLLimit(der []byte, issuer *x509.Certificate, maxCost int64) (*ParsedCRL, Status, error) {
	return parseCRL(der, issuer, maxCost)
}
