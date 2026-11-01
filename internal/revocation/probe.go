package revocation

import (
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
