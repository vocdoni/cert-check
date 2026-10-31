# OCSP test samples

Real OCSP responses and the certificates needed to verify them. Every file is a
byte-identical copy of the source listed below; `TestParseRealResponses`
recomputes the SHA-256 of each file and requires every file in this directory
to be listed.

The responses answer for CA certificates or for the Izenpe synthetic test kit
(identity `00000000T` NOMBRE APELLIDOUNO, e-mail `contacto@email.com`). None
concerns a real person. The leaf-level AOC responses `g2leaf.ocsp` and
`g3leaf.ocsp` answer for real persons' serials and are not committed.

Research cache: `~/.cache/cert-check/research/appb-ocsp/` (fetched 2026-10-30).
Bundle: `Vocdoni_CSP_Handoff/` research bundle.

| file | source | sha256 |
|---|---|---|
| aoc-casub-a2.ocsp | research cache `casub-a2.ocsp` (http://ocsp.aoc.cat, CA-level, 2026-10-30) | 27f593ee82ab41d6c6f95dfc280485d5a818d99d9eca14a80bff388477819c59 |
| camerfirma-qc2024.ocsp | research cache `cf2024qc.ocsp` (http://ocsp.camerfirma.com, CA-level) | c093b7842bd432a448ceab8801f40fe3261fb1437421d8e7d4aae6a580c1166b |
| izenpe-profesional-sw-act.ocsp | research cache `izenpe_profesional_sw_act.ocsp` (http://ocsp.izenpe.com, synthetic kit leaf) | bd28a19c11499b1db20aa6887c7382b2f664febae97c3ab1eb04764d89b70e11 |
| izenpe-profesional-sw-rev.ocsp | research cache `izenpe_profesional_sw_rev.ocsp` (http://ocsp.izenpe.com, synthetic kit leaf) | 6991f71b7157178e570796ad8342d9a334e90f52b8af7a6fb196ef6e8a61856c |
| certs/aoc-g3-root-a.pem | bundle `additional-ca-certificates/15651384ca70c580dff5fed06a02162f6aa6eddd3602313da4e124c25775baaa.pem` | fafc411eb1c25bd829f1e0de29940366b96304e3f6f2c4eaac18830bdbb3ee06 |
| certs/aoc-subca-ciutadania-g3-a2.pem | bundle `service-identities/e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735.pem` | 57a84099da3c38c557f5203a3de868322e0bc0f8747c8c161d7ccfcee0703ba5 |
| certs/camerfirma-root-2024.pem | bundle `additional-ca-certificates/5a81aba8d5fd06849aae21e11a535d4edef91f45984ec47e1f707854c5906cd1.pem` | fc818d01b06b9260a8a450d062b0a5867f2563be2cd43338c700cd427b129243 |
| certs/camerfirma-qc-2024.pem | bundle `service-identities/51583118e6c5e5d210df34dd3597f1136a5b16482218fcc2dd3b85f7a5c81cff.pem` | 5dc7f80df4259758fa33ea1f679944f81e54d3266e95339e885b41efe41a7fe2 |
| certs/izenpe-ca4.pem | bundle `additional-ca-certificates/7ed19361ad734d703fbadf029f52ec3b6648d8dd56baba0884ed4f859b5b9375.pem` | a3c8c8d49a468cbc0d2fed9edccead3d45a46865ef1e5cb90571c1f27a04fef1 |
| certs/izenpe-profesional-sw-act.pem | research cache `izenpe_profesional_sw_act.pem` (Izenpe synthetic kit, DER sha256 06c81a7f70a8f15ef9d5c55eeb4b98eb3409059e4b67702fecf80febfa632c65) | 5184711e6df323cdcb0fec54b55c54e6cd1a6d9e8136e62de956aa915e166880 |
| certs/izenpe-profesional-sw-rev.pem | research cache `izenpe_profesional_sw_rev.pem` (Izenpe synthetic kit, DER sha256 a3c07e07e36f50680fda1d8c38edc113a33805760f569f452b304c81b9e9d9d9) | 38c5e67c795a97fa1336768c8be4c508366469ef1bb7acf9972c7281733a02c9 |
