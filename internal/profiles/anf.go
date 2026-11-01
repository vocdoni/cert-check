package profiles

// ANF (beta): digest C, two legal providers, one anchor each; private SAN
// ignored. The responder echoes the OCSP nonce (live probe, R65).
func ANF() Provider {
	asoc := person("anf-asociacion-class2-sw", "anf", "ANF AC Clase 2 Persona Física (Asociación)",
		[]Anchor{anchor("b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23", "d1b4c6d6b4f387bd50f89359a11c3a07673effb796cbcecfd32219594362988c")},
		[]string{"1.3.6.1.4.1.18332.3.4.1.2.22"}, plain(),
		policy(true, []string{"ocsp.anf.es"}, []string{"crl.anf.es"}))
	sl := person("anf-sl-class2-sw", "anf", "ANF Clase 2 Persona Física (S.L.)",
		[]Anchor{anchor("5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a", "9992ddc44e5b001f31044fd4723e424e3e2509799b084211f660d321a2fea436")},
		[]string{"1.3.6.1.4.1.49201.3.4.1.2.22"}, plain(),
		policy(true, []string{"ocsp.anf.es"}, []string{"crl.anf.es"}))
	return Provider{ID: "anf", Name: "ANF AC", Beta: true,
		Description: "Certificado de Clase 2 de Persona Física (software)", Profiles: []Profile{asoc, sl}}
}
