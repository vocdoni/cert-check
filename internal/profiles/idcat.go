package profiles

import (
	"github.com/vocdoni/cert-check/internal/identity"
)

// IDCAT: digest B aoc-idcat-g2 / aoc-idcat-g3 (same OID, dispatched by anchor).
func IDCAT() Provider {
	g2 := plain()
	g2.CountryMatchesPrefix, g2.LegacyDNISuffix = true, true
	g3 := plain()
	g3.CountryMatchesPrefix = true
	hostsOCSP := []string{"ocsp.catcert.cat", "ocsp.aoc.cat"}
	hostsCRL := []string{"epscd.catcert.net", "epscd.aoc.cat"}
	p2 := person("aoc-idcat-g2", "idcat", "idCAT Certificat (EC-Ciutadania)",
		[]Anchor{anchor("0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6", "3761345542c20b314a744a7c54a82152a283be9cdcda233f050000c2d0e5070d")},
		[]string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, g2, policy(true, hostsOCSP, hostsCRL),
		fp("81ffa40e096b6cf32c3082454d22ace4f0bb009b99f26995eb59da36eae4482b", "idcat-g2-pf-peca-de-proves-00000000T.pem"),
		TestMarker{Subject: []AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}},
			Source: "AOC DPC v7.4 §1.1.3 production test certificate"},
	)
	p2.HandledCriticalExtensions = []string{"1.3.6.1.5.5.7.1.3"} // qcStatements, critical on leaves before profile v6.8
	p3 := person("aoc-idcat-g3", "idcat", "idCAT Certificat (SubCA CIUTADANIA Q (G3) A.2)",
		[]Anchor{anchor("e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735", "4da535844e847db014be7e842d7b243118f3d28ce487c32cb62e5a72c70b88c2")},
		[]string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, g3, policy(true, hostsOCSP, hostsCRL),
		TestMarker{Subject: []AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}},
			Source: "AOC DPC v7.4 §1.1.3 production test certificate"},
	)
	return Provider{ID: "idcat", Name: "idCAT Certificat", Description: "Certificat idCAT del Consorci AOC",
		Profiles: []Profile{p2, p3}}
}
