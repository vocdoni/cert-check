// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles

// Sectigo: digest C sectigo-citizen-local (R35 and E35); pre-generated OCSP, no nonce.
// The specimen files are withheld (ruling R30); their fingerprints stay pinned.
func Sectigo() Provider {
	return Provider{ID: "sectigo", Name: "Sectigo - Ciudadano", Description: "Certificado cualificado de ciudadano Sectigo (no QSCD)",
		Profiles: []Profile{person("sectigo-citizen-local", "sectigo", "Sectigo Qualified Natural Person (Citizen)",
			[]Anchor{
				anchor("ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde", "eb9f35a491f478c19fc0cdc02a8a5d54df26ed3b248f587459539bc2a48f6a24"),
				anchor("53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9", "8e351d9cb41b50d077af2842b9faf748c4269ea6cf01e34d29f1f83c85edf983"),
			},
			[]string{"1.3.6.1.4.1.6449.1.2.1.7.1"}, plain(),
			policy(false, []string{"ocsp.sectigo.com"}, []string{"crl.sectigo.com"}),
			fp("88059e9240bb96734d0a0c07d27a9fbd2741ebbdd49c08004b14b443962f2c30", "sectigo-citizen-99949990V.pem"),
			fp("5afc90f8e6a60ce17fc4bb80f11ce1e897565cf8d870e96eeeeaaa9c224df187", "sectigo-employee-99949993C.pem"),
		)}}
}
