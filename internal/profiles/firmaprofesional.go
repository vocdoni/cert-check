package profiles

// Firmaprofesional (beta): digest C; CUALIFICADOS pinned once (alias 4ccf17c0 not loaded) plus ICA B01.
func Firmaprofesional() Provider {
	a := plain()
	a.SAN = fp13177()
	return Provider{ID: "firmaprofesional", Name: "Firmaprofesional", Beta: true,
		Description: "Certificado Personal de Persona Física (sin DCCF)",
		Profiles: []Profile{person("firmaprofesional-personal-sw", "firmaprofesional", "Firmaprofesional Persona Física (sin DCCF)",
			[]Anchor{
				anchor("2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf", "c695bd5c40f753beb93f653202a3d6354ede0dd21295fd894a0869be366753e6"),
				anchor("4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1", "dab1f8803dcf0900d5810e5d9b598781a1f039b30bdf89ad241bfa3e358dd8f9"),
			},
			[]string{"1.3.6.1.4.1.13177.10.1.40.2"}, a,
			policy(false, []string{"ocsp.firmaprofesional.com"}, []string{"crl.firmaprofesional.com"}))}}
}

// KnownAliases are TSL service identities deliberately not loaded because a
// pinned anchor has the same subject and key (crypto/tls would advertise the
// DN twice). Value: the pinned anchor.
var KnownAliases = map[string]string{
	"4ccf17c0c8c1c10d5876ec5e3280fe8d134df36aedd8444289b990bc3741e74f": "2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf",
}
