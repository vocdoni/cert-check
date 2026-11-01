package profiles

// Uanataca (beta): digest C uanataca-citizen-sw, four issuing CAs. The
// responders echo the OCSP nonce (live probe, R65).
func Uanataca() Provider {
	return Provider{ID: "uanataca", Name: "Uanataca", Beta: true,
		Description: "Certificado cualificado de Persona Física Ciudadano en software",
		Profiles: []Profile{person("uanataca-citizen-sw", "uanataca", "Uanataca Ciudadano en software",
			[]Anchor{
				anchor("35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f", "c886cd88edc69bffba28dcc5ba092fa5906742ce4712ddfc71e4e5851fa51f26"),
				anchor("00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909", "fac53d2ea5667fa530415045aa563d293ed0de542e26a0607f31a480c695fe75"),
				anchor("9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a", "12093d696c24875b59dbc44b2ac814961b8bc73b870310f6cecd5d21a4e6787a"),
				anchor("15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a", "5f78b32f4a4770c8676ac81b467005ce22dde8f2613c5acca3612bcf6029a9b6"),
			},
			[]string{"1.3.6.1.4.1.47286.1.1.1.1"}, plain(),
			policy(true, []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, []string{"crl1.uanataca.com", "crl2.uanataca.com"}))}}
}
