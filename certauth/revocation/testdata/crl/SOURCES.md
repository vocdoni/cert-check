# CRL samples: SOURCES

Real CRLs and the CA certificates needed to check them, used by `TestRealCRLs`
(`certauth/revocation/crl_test.go`). Every file is a byte-identical copy of the source below.
The test recomputes the SHA-256 of each file, compares it with the table, and fails on any file
in this directory that the table does not list.

| file | source | sha256 |
|---|---|---|
| dnie-arl.crl | `~/.cache/cert-check/audit-scratch/crl/ARL.crl` (live fetch of http://pki.policia.es/dnie/crls/ARL.crl, 2026-10-30) | 0c458a7ff513b28ec8eb62fabbaad9218cbb19c8924581b102c208184e11a235 |
| dnie-crl.crl | `~/.cache/cert-check/gatefix-crl/CRL.crl` (live fetch of http://pki.policia.es/dnie/crls/CRL.crl, 302 to /dnie/arls/CRL.crl, 2026-10-31; signature verified against AC RAIZ DNIE 2 with `openssl crl -verify`) | fa9d57ae346e5b86b87dfde630dc94f4a4421ddc1821df5bac0fc3e5fee278c4 |
| aoc-caroot-a.crl | `~/.cache/cert-check/research/appb-crl/caroot-a.crl` (http://epscd.aoc.cat/crl/caroot-a.crl, 2026-10-30) | 6063677f9de836521431b0d141802679119c75be8a8165206db5592eececb053 |
| certs/ac-raiz-dnie-2.pem | research bundle `service-identities/c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11.pem` | 6b05008b4ee898f78457c345da5a0d7b368541d715694c56527a34179d63f820 |
| certs/ac-dnie-004.pem | `~/.cache/cert-check/research/ca-downloads/dnie/AC004.crt` (http://pki.policia.es/dnie/certs/AC004.crt) | f368f0dc19cb72adfca9f46bdd3db39552fcccb22de275f52de18cba8670ff33 |
| certs/ac-dnie-005.pem | `~/.cache/cert-check/gatefix-crl/AC005.crt` (http://pki.policia.es/dnie/certs/AC005.crt, 2026-10-31; DER SHA-256 828a22ff… = the pinned anchor) | 4e6e246714a1263429b2916d3f52b7bcdcabd355340df386786272b858f36b89 |
| certs/aoc-g3-root-a.pem | research bundle `additional-ca-certificates/15651384ca70c580dff5fed06a02162f6aa6eddd3602313da4e124c25775baaa.pem` | fafc411eb1c25bd829f1e0de29940366b96304e3f6f2c4eaac18830bdbb3ee06 |
| certs/aoc-subca-ciutadania-g3-a2.pem | research bundle `service-identities/e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735.pem` | 57a84099da3c38c557f5203a3de868322e0bc0f8747c8c161d7ccfcee0703ba5 |

Privacy. The CRLs list only CA-certificate serials or none (the DNIe ARL is an authority
revocation list; the DNIe root `CRL.crl` is empty; the AOC G3 ROOT-A CRL is a root CRL). They carry
no person data. The FNMT partition CRL (`CRL2.crl`) lists person serials and is not committed; its
IDP shape (directoryName plus URI, onlyContainsUserCerts) is covered synthetically in
`TestEvaluateCRL`.

`dnie-crl.crl` documents the shape that makes CA-scope checks consult every distribution point:
AC DNIE 005/006 name this list first, its critical IDP carries only the distribution-point name (no
onlyContainsCACerts/onlyContainsUserCerts flag) and it has no entries, so it answers good for a CA
while CA revocations are published only in `ARL.crl`.
