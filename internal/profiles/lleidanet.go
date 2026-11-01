package profiles

// Lleidanet (beta): digest C lleidanet-natural-person-sw. CRL only (R63): the
// ocsp2.esigna.es responder certificate lacks id-pkix-ocsp-nocheck, so its
// answers are never acceptable; the leaves' AIA OCSP URL is ignored.
func Lleidanet() Provider {
	return Provider{ID: "lleidanet", Name: "Lleidanet / inDenova", Beta: true,
		Description: "Certificado de Persona Natural Software",
		Profiles: []Profile{person("lleidanet-natural-person-sw", "lleidanet", "Lleidanet Persona Natural Software",
			[]Anchor{anchor("3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25", "e0f0a51ac007c5ea964344e785c4ac005d8db0e8cd7a33943f726a46c0532d3e")},
			[]string{"1.3.6.1.4.1.49959.1.1.1.1.1"}, plain(),
			policy(false, nil, []string{"crl1.esigna.es", "crl.esigna.es"}))}}
}
