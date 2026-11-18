// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles

import (
	"github.com/vocdoni/cert-check/internal/identity"
)

// ACCV: digest A accv-citizen-software-current (RSA1 and ECC1 CLIENTE).
func ACCV() Provider {
	a := identity.Adapter{
		Documents: bare, Surnames: identity.SurnamesFromSN,
		SAN:       identity.SANCheck{Kind: identity.SANPipeCN, DocumentOID: identity.OIDUID, DocumentRules: bare},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	p := person("accv-citizen-software-current", "accv", "ACCV Ciudadano en soporte software",
		[]Anchor{
			anchor("a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1", "03cd20b076b5b589a78efa46a09e6d1cc8ba5878088113749d16f7414cd9c1f1"),
			anchor("5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496", "73b39454c0f85a4f23e29e923073aa74f755934809e359f2ea87c9eebfa34b75"),
		},
		[]string{"1.3.6.1.4.1.8149.3.7.8.0"}, a,
		policy(true, []string{"ocsp.accv.es"}, []string{"www.accv.es"}))
	return Provider{ID: "accv", Name: "ACCV - Ciudadano (software)",
		Description: "Certificado cualificado de Ciudadano en soporte software de la ACCV", Profiles: []Profile{p}}
}
