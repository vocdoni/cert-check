package profiles

// Digitel: digest C digitel-citizen-sw-g1.
func Digitel() Provider {
	return Provider{ID: "digitel", Name: "DIGITEL ON - Ciudadano", Description: "Certificado cualificado de ciudadano DIGITEL (software)",
		Profiles: []Profile{person("digitel-citizen-sw-g1", "digitel", "DIGITEL Ciudadano software (QUALIFIED CA G1)",
			[]Anchor{anchor("86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61", "00600557c6552a65e2dd8dee34d7b674043fd1c5935562ded5f26e2e5777eabb")},
			[]string{"1.3.6.1.4.1.54225.10.3.1"}, plain(),
			policy(true, []string{"ocsp.digitelts.es"}, []string{"crl1.pki.digitelts.es", "crl2.pki.digitelts.es"}),
			fp("fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8", "digitel-ciudadanosw-99949996T.pem"),
		)}}
}
