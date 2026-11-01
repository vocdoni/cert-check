package profiles

import (
	"github.com/vocdoni/cert-check/internal/identity"
)

// SIGNE (beta): digest C; NIE as PNOES-<NIE> only here; leaf OCSP unknown, so CRL only.
// signe-subca.crl answers 302 to https://crl.firmaprofesional.com (R64).
func SIGNE() Provider {
	a := plain()
	a.Documents = []identity.DocumentRule{
		{Encoding: identity.EncodingIDCES, Types: dniOnly},
		{Encoding: identity.EncodingPNOES, Types: nieOnly},
	}
	a.SAN = fp13177()
	return Provider{ID: "signe", Name: "SIGNE", Beta: true,
		Description: "Certificado Personal de Persona Física (otros dispositivos)",
		Profiles: []Profile{person("signe-personal-otros-dispositivos", "signe", "SIGNE Persona Física (otros dispositivos)",
			[]Anchor{
				anchor("b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea", "7988bdc1ad8ebd8bf150d25ffe876fb05bb3444e1c064bd13f2a57d82bb5f66f"),
				anchor("244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35", "6a30d221e4acfdae38d34006418094fa8337da2f30b9a99c04cfe7d98317dd70"),
			},
			[]string{"1.3.6.1.4.1.36035.1.3.2"}, a,
			policy(false, nil, []string{"www.signe.es", "crl.firmaprofesional.com"}))}}
}
