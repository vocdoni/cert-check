// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles

import (
	"github.com/vocdoni/cert-check/internal/identity"
)

// DNIe (beta): digest A dnie-auth plus the fixture manifest answers (G1).
func DNIe() Provider {
	a := identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniOnly}},
		Surnames:  identity.SurnamesDNIeCN, SAN: noSAN,
		BirthDate: identity.BirthDateOptional, Organization: identity.OrganizationNone,
	}
	p := person("dnie-auth", "dnie", "DNIe Autenticación",
		[]Anchor{anchor("c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11", "4a5dc6f078372f3497d01ba654c902357b54a1c53387f8b3cf3b92749cdeb44b")},
		[]string{"2.16.724.1.2.2.2.4"}, a,
		// pki.policia.es serves the root ARL for the pinned intermediates; leaves have no CDP.
		policy(true, []string{"ocsp.dnie.es"}, []string{"pki.policia.es"}),
		fp("ce3dff1caf0b15381a97f428f8346a0d81fafc818402a096960a90ce8bac0059", "dnie-ac004-auth-activo.pem"),
		fp("c6caec7063ae8a37efb36d54086444812ccdf2e8d9ae81b2d68cfe53a315f554", "dnie-ac004-auth-caducado.pem"),
		fp("7059081d082e86bf2678f61ce9c818ee73adf9ff52dbc7dcbd1618bbc6359541", "dnie-ac004-auth-revocado.pem"),
		fp("767cdce2cb7e3e5c5ca13dfb6695535c0d3bc678fd6ac9bf8c02d83226b6d2d6", "dnie-ac004-firma-activo.pem"),
		fp("9ed5001c16deac81eca78ff293fd78a15362a13b9867558f645a1cab0c7f4df5", "dnie-ac004-firma-caducado.pem"),
		fp("6c3315c2f98c396314224970494df9d77f609ed30b61b70a261e51fbf8998ddf", "dnie-ac004-firma-revocado.pem"),
		fp("7a74251ea5ca45c971ba067fa1941fc128bb4a3e7b886b90754209b1ccc44815", "dnie-ac004-firmacentralizada-activo.pem"),
		fp("64412f7a0b4540b0ce57b47c2339319094a1efba35109860bc047ce060558a0f", "dnie-ac004-firmacentralizada-caducado.pem"),
		fp("21ad4a4966ef8ec6f7904718c509506542d6e4ed7baf4079f925b1fbcce97dc6", "dnie-ac004-firmacentralizada-revocado.pem"),
		fp("cde734ca6f58e7450ed58cef14357c619474c80930171880c69c284a238492b5", "dnie-ac001-auth-activo.pem"),
		fp("6af1aec2a3422648643a353e3baf5362d7a91797c904cf50fa97c7db4288efc0", "dnie-ac001-auth-revocado.pem"),
		fp("a7aebe5c4d5864733439327180108bf524962d71fee55da0dc79b585dc3ef02a", "dnie-ac001-firma-activo.pem"),
		fp("a22ef3464ab64708854b832eeb4004e4afe0b6fdba614cbe62f4afb9345092fe", "dnie-ac001-firma-revocado.pem"),
	)
	p.EKU = EKUAllowAbsent // "extKeyUsage: No se utilizará" (CPS v3.4)
	p.Intermediates = []Anchor{
		anchor("ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c", "1b5b9b72ed25bdab71a112d252c747f5961bfed9ad4bce77292af34b1146481f"), // AC DNIE 004
		anchor("828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828", "1f6b84c54a1824bdc0f639487dfaa29c7b2bc7fefe69499651eb2036fcf859a2"), // AC DNIE 005
		anchor("eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd", "60a9a73a0c25f1e14b44508554076c2c48ad32c503c9bc534c945a82a290cb97"), // AC DNIE 006
	}
	return Provider{ID: "dnie", Name: "DNIe (requires card reader)", Beta: true,
		Description: "Certificado de Autenticación del DNI electrónico; the browser must already be able to use the card",
		Profiles:    []Profile{p}}
}

// IntermediateExceptions are pinned intermediates that are not TSL service
// identities. Reviewed: official AIA downloads (anchors/SOURCES.md), verified
// against AC RAIZ DNIE 2.
var IntermediateExceptions = []string{
	"ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c",
	"828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828",
	"eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd",
}
