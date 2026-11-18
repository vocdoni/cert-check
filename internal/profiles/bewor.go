// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles

// Bewor: digest C bewor-natural-person-sw (.1.1.1 centralised HSM is not listed).
// The specimen files are withheld (ruling R30); their fingerprints stay pinned.
func Bewor() Provider {
	return Provider{ID: "bewor", Name: "Bewor - Persona Física", Description: "Certificado cualificado de persona física Bewor (software)",
		Profiles: []Profile{person("bewor-natural-person-sw", "bewor", "Bewor Persona Física software (BEWOR TECH CA1)",
			[]Anchor{anchor("8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d", "ba0331d2b536d13f5d8953475ae3b945764ed54b3788ba5bf4f4a7ee6e770003")},
			[]string{"1.3.6.1.4.1.55693.1.1.2"}, plain(),
			policy(true, []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, []string{"crl1.uanataca.com", "crl2.uanataca.com"}),
			fp("da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab", "bewor-pfsoftbt-99949999A.pem"),
			fp("52bef7a958c349ed0dc1881865c911820e9ef9f7b32741d67273a8f1ba527d92", "bewor-pfsoftbt-revocado-99999999R.pem"),
		)}}
}
