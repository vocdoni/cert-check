# Appendices C, D, E: other Spanish providers, triaged for the native-mTLS citizen PoC

Research date: 2026-10-30. Scope: every provider in Appendices C, D and E of
`docs/Vocdoni_CSP_Handoff/Vocdoni_Spanish_Certificate_CSP_Implementation_Specification.md`
(lines 1202-1880), read against the product decision in `docs/Vocdoni_CSP_Authentication_Only_Agent_Note.md`
and spec sections 6.1, 7, 8, 9 and 16. All paths are relative to `/home/p4u/certificate_poc/` unless absolute.

The PoC question for each provider: can a **natural person (citizen)** hold a certificate **in software**, installed
in the browser/OS store, that authenticates via TLS client auth, validates against a **pinned TSL service
identity**, matches an **exact leaf policy OID**, and yields DNI/NIE + names through an **anchored grammar**?

## How the evidence was obtained

* **CA certificates.** Every CA cited was inspected with `openssl x509` (subject, dates, SHA-256 of DER,
  SPKI SHA-256 via `openssl pkey -pubin -outform der | sha256sum`, policies, AIA, CDP, KU, EKU, basic constraints).
  All 134 `service-identities/*.pem` were re-hashed: the DER and SPKI SHA-256 match the inventory JSON
  (0 mismatches). TSL status, service type and the `Qualifications` criteria (policy OIDs that the TSL marks
  `QCQSCDManagedOnBehalf`) come from `spanish_tsl_inventory_2026-10-30.json`.
* **Root and issuer chain checks.** The service-identity CAs below were verified with `openssl verify` against official
  roots downloaded to `/home/p4u/.cache/cert-check/research/ca-downloads/`:

  | Root (official URL) | DER SHA-256 | Verified to sign |
  |---|---|---|
  | DIGITEL TS CA ROOT 01 (`https://pki.digitelts.es/DTSROOTCA01.crt`) | `011e258310b37f92030d14a672079507632cf72789fc101ce0a0bdc5ef2808cc` | DIGITEL TS QUALIFIED CA G1 |
  | UANATACA ROOT 2016 (`https://web.uanataca.com/common/project/pdf/autoridad-certificacion/01_raiz-ca-2016.cer`) | `44607b3d0ebd0d2bf181cb62f3cea9766dbb6718743f55b153a320ea99dfb5a6` | UANATACA CA1/CA2 2016, CA1/CA2 2021, BEWOR TECH CA1, ELECTRONIC IDENTIFICATION CA1, DOCUTEN TECH CA1, INDIZE CA Subordinada 01, Permisso CA Subordinada 01 |
  | Autoridad de Certificacion Firmaprofesional CIF A62634068 (`http://crl.firmaprofesional.com/caroot.crt`) | `57de0583efd2b26e0361da99da9df4648def7ee8441c3b728afa9bcde0f9b26a` | AC Firmaprofesional - CUALIFICADOS (both DERs), SIGNE Autoridad de Certificacion - 2020 |
  | FIRMAPROFESIONAL CA ROOT-B GP (`http://crl.firmaprofesional.com/caroot-b_gp.crt`) | `7221c0a1668f4a38f1fa989dddab61a8c0ec71f32682c7cd0183e0a2d729aefd` | FIRMAPROFESIONAL ICA B01 QUALIFIED 2022 |
  | ANF Global Root CA (`http://crl.anf.es/certificates_download/ANF_Global_Root_CA_SHA256_2036.cer`) | `e0afbd2c0ee95a68cd9a3c590b2d3fe07c0a6d0be796ae5291e424d47792178e` | ANF AC Qualified Certificates for eSignature |
  | ANF AC SL Root CA (`http://crl.anf.es/certificates-download/ANFACSLRootCA.cer`) | `f8d86a96b7b215c5a8789697264104d296b45b5c79cb4158ee93a150e14dc9a4` | ANF Qualified for eSignature CA |
  | Sectigo Qualified Natural Person Root R45 / E45 (`http://crt.sectigo.com/SectigoQualifiedNaturalPersonRootR45.crt`, `...E45.crt`) | R45 `86b5017206da1000bf909c7644d37eadff2c8a8d925331a9e70c5fa029dbbcb9`, E45 `9a8084817dee917a73abef2ee6bb8b7c2a9022e6ee17fe203f855a515e60624e` | Natural Person CA R35, CA E35 |

* **Public leaf fixtures downloaded and decoded** (all from official issuer URLs, kept in `ca-downloads/<provider>/`):
  DIGITEL `CiudadanoSW.crt`; the Sectigo test ZIP (SHA-256 `0264a4ed94334a5c4fd0ef0a344ec14cabebb86f08fe78dd9518bc0b4b9b1bb2`);
  the DEH specimen ZIP (`ab109c36cb4ec3f046e62195fb41c3b322b07a29c2c3ab353e33bc01dfa6c02e`); the Permisso kit
  (`9a59f3317c63d63789fde5ab285a852ffb6838b694c6e40760320a2049cdfef0`); the Bewor specimen ZIP
  (`5535b824a82a285b86093fa4b5e2bc722f338c72d9a58bfb9c21245a66ce4c07`). From the Bewor PKCS#12 files only the public
  certificates were extracted (`-nokeys`), using the password the issuer publishes next to each file.
* **Live status checks run on 2026-10-30, about 22:35-22:45 UTC.** The DIGITEL, Sectigo and Bewor OCSP queries
  returned signed responses that verified. The DIGITEL leaf CRL and root ARL, and the Sectigo R45 ARL, were fetched
  and their signatures verified.
* **Official documents fetched with firecrawl (12 fetches, Markdown in `/home/p4u/.cache/cert-check/research/`):**
  Uanataca DPC v5.3; Firmaprofesional profiles 260205; ANF Asociación profiles v1.4; ANF S.L. profiles v1.4;
  Lleidanet profiles rev10; SIGNE PF CP v4.1; Víntegris profiles v1.4; SIA citizen CP v1.8; ACA CP6 002.3;
  EADTrust natural-person policy (April 2020); Sectigo profiles v2.8; the Uanataca CA-certificates page. The URLs
  are the ones cited in the spec lines quoted per provider below.
* **Go parse test.** Go 1.27.3, in `/home/p4u/.cache/cert-check/research/goparse/` (own `go.mod`). See section 3.

## 1. Triage table (all providers in scope)

Legend. **SW** means a natural-person certificate is issuable in software (installable in a browser or OS store).
**Bundle CA** gives the `service-identities/` SHA-256 prefix. All cells come from evidence read or verified in this
session. "Spec only" means the claim rests only on the handoff spec.

| Provider | SW citizen cert? | Exact leaf OID(s) with evidence | Bundle CA(s) | Identity grammar documented? | OCSP / CRL known? | Blockers | Verdict |
|---|---|---|---|---|---|---|---|
| **DIGITEL ON** | Yes, citizen software | `1.3.6.1.4.1.54225.10.3.1`: official fixture plus DPPC v4.0; the TSL QSCD-managed list excludes it | `86a62f63` | Yes, verified on fixture: `IDCES-`, GN, SN | Yes. OCSP live `good`; CRL and ARL verified | No private key in the fixture | **include** |
| **Bewor** | Yes, natural person software | `1.3.6.1.4.1.55693.1.1.2`: production-CA specimen (P12 + public password), valid to 2030 | `8a386ed1` | Yes, verified: `IDCES-`, GN, SN | Yes. OCSP live: `good` and `revoked` specimens | Specimens are production-CA test identities | **include** |
| **Sectigo (Europe)** | Yes. "Citizen" is non-QSCD, "issued online entirely" | `1.3.6.1.4.1.6449.1.2.1.7.1`: profiles v2.8 plus official test leaf | `ac866830` (R35), `53b24005` (E35) | Yes, verified: `IDCES-`, GN, SN | Yes. OCSP live `good`; R45 ARL verified | v2.8 makes `digitalSignature` optional; non-ES IDs are common | **include** (KU gate) |
| **Firmaprofesional** | Yes, "Personal sin DCCF" | `1.3.6.1.4.1.13177.10.1.40.2`: profiles 260205 §2.7.3; TSL lists `.40.3` (centralized) only | `2b75cc4f`, `4ccf17c0` (same key), `4a86f333` | Yes: §2.7.1 ETSI `IDCzz-`, GN, SN full, SAN `13177.0.1/2/3` | CA AIA OCSP `ocsp.firmaprofesional.com`; leaf CDP unknown | serialNumber text changed 2025-05/07 and 2026-02; no fixture | **include-if-fixture** |
| **ANF AC (Asociación)** | Yes, Clase 2 PF software | `1.3.6.1.4.1.18332.3.4.1.2.22`: profiles v1.4 §2.1.2 | `b7cdf23a` | Yes: ETSI NIF/NIE/passport, GN, SN | CA: `ocsp.anf.es/spain/AV`; leaf from AIA | Private leaf extensions `18332.19/.19.1` (criticality unknown); no fixture | **include-if-fixture** |
| **ANF Certification Authority S.L.** | Yes, Clase 2 PF software | `1.3.6.1.4.1.49201.3.4.1.2.22`: S.L. profiles v1.4 §2.1.2 | `5999789a` | Yes, as above (`49201` namespace) | As above | As above | **include-if-fixture** |
| **Uanataca** | Yes, "Ciudadano en software" | `1.3.6.1.4.1.47286.1.1.1.1`: DPC v5.3 §1.2.1 and §1.4.1.1 | `35a99284`, `00ff2ff2`, `9b083dc4`, `15ceab33` | Partly: ETSI serialNumber, SN, GN; technical profiles are "on request" | Yes: OCSP pair; four per-CA CRLs (DPC §4.9.7) | TSL criteria list legacy `.1.1.6`/`.1.1.6.2`, absent from v5.3; no fixture | **include-if-fixture** |
| **SIGNE** | Yes, "Otros dispositivos" (non-QSCD) | `1.3.6.1.4.1.36035.1.3.2`: PF CP v4.1 §5.3 | `b8df384f` (2020), `24416624` (SUBCA 2024) | Yes: `IDC` (DNI), `PNO` (NIE), `PAS`; SAN in the Firmaprofesional namespace | CRLs known; leaf OCSP from AIA | "Otros dispositivos" may mean a token; no fixture | **include-if-fixture** |
| **Lleidanet PKI / inDenova** | Yes, Persona Natural Software | `1.3.6.1.4.1.49959.1.1.1.1.1`: profiles rev10 §4 and §6.1 | `3452e967` | Yes: `IDCES`+NIF, GN, SN (upper case), no SAN | OCSP `ocsp2.esigna.es`; CRLs known | No fixture; RSA-4096 only since rev8 | **include-if-fixture** |
| **DEH / Certibox** | Yes, PF software | `1.3.6.1.4.1.57853.1.1.1`: CPS 2.3 plus production specimen | `e9485e07` | ETSI, but the specimen is `IDCEC-` (Ecuador) | OCSP Uanataca pair; CRL host migrating | No Spanish-ID fixture; older CPS tables are bare DNI/NIE | **include-if-ES-fixture** |
| **EADTrust** | Yes, "sin dispositivo cualificado" | `1.3.6.1.4.1.501.2.1.1.0.41221` (in person), `.3.41221` (video): policy April 2020 §10.1.1 | `82340ea4`, `04bf1da6`, `2002b8d5`, `e5f78053`, `f8ea3465` | Yes: ETSI (example `IDCES-012345678R` has 9 digits), GN, SN | OCSP `ocsp.eadtrust.eu`; per-algorithm CRLs | 2020 policy; malformed example; five CAs; no fixture | **include-if-fixture** (low) |
| **Víntegris** | Yes, "Individual de PF en SOFT" | `1.3.6.1.4.1.47155.1.10.2` (nebulaSUITE2), `1.3.6.1.4.1.47155.2.10.2` (TrustServices): profiles v1.4 table | `da1326d2`, `75a6330e` | Yes: `IDCES-NIF`, GN, SN, SAN `47155.1.1-.4` | OCSP `ocsp.vincasign.net`; CRLs known (spec) | Profile PDF only OCR-readable (garbled OIDs and hosts); cloud-first issuer | **include-if-fixture** (low) |
| **AC Abogacía (ACA)** | Yes, "Persona Física en software" | `1.3.6.1.4.1.16533.50.6.3`: CP6 002.3 §7.1.2.2 | `c6dfaaac` (ACA 1); legacy CA1/CA2 not in scope | Partly: **SN = first surname only**; SAN `16533.100.x` optional; serialNumber "NIF or ETSI" | OCSP `acaocsp.acabogacia.org`; partitioned CRL | Possibly incomplete surnames; two serialNumber encodings | **include-if-fixture** (low) |
| SIA | Medium level "optionally software" | `1.3.6.1.4.1.39131.10.1.3`: CP v1.8 Tabla 5 | `68690054`, `59b49880` | SN = first surname only; SAN `39131.10.2.2-.5` | OCSP `psc.sia.es/ocsp`; partitioned CRL | Tabla 5 EKU reads "Client Authentication \| 1 (no seleccionado)" (self-contradictory); citizen table lists company O/NIF | exclude. Unlock: a genuine `.10.1.3` leaf showing clientAuth EKU (or no EKU) plus SAN encoding |
| esFIRMA (esPublico) | No citizen profile: linked person and employee only, card or centralized | `.47281.1.6.x` (linked), `.1.1.x` (employee) | `2c182361` | Yes | Yes | No natural-person software citizen product; card auth leaves are NCP+ | exclude. Unlock: a citizen software product (none documented) |
| Validated ID | Yes on paper (`.54932.2.1.1`) | `1.3.6.1.4.1.54932.2.1.1` (spec, DPC 2.2) | `a83d4488` | No: serialNumber encoding undocumented | Yes (spec) | **Ceases 2026-11-30; all qualified certificates revoked** | exclude |
| EDICOM | Yes (`.21` software) | `1.3.6.1.4.1.30051.2.3.2.21` + 2026 fixture (spec) | `b211c48c` | Yes | Yes | Private use-limitation extension `30051.3.2`; the fixture says "commercial and tributary documents" only | exclude. Unlock: written issuer statement that access control or voting is a permitted use |
| IVNOSYS / IvSign | Yes on paper (`.1.1.2`) | `1.3.6.1.4.1.47304.3.16.1.1.2` (OCR of CPS annex; spec) | `d6ea13d3` | **No**: the CPS says CN holds the surnames; technical profiles unpublished | Yes (spec) | Grammar unknown | exclude. Unlock: technical DN profile plus DER fixture |
| ANCERT (CTNotariado) | No ordinary-citizen software. Notarial/professional; SEN is remote | Many (Appendix D §2.2-2.3) | 6 CAs (V2 and 2025) | Yes | Yes | Notarial and professional use restrictions (CPS §1.4); SEN-only | exclude (professional scope) |
| Colegio de Registradores | "External personal" (`.0.2.1.2` RSA / `.0.2.61.1` ECC); storage form unverified | Spec Appendix D §3.2 | `f67a0c98`, `fb7e801d` (+ ECC in `additional-ca-certificates/`) | Yes (`IDCES-`, SAN `17276.1.0.0.x`) | Yes | Purpose-limited to registry services; ECC role OIDs conflict; no leaf fixture | exclude. Unlock: a genuine external-personal leaf plus a permitted-use ruling |
| Ministerio de Defensa | No: TEMD smart card | `2.16.724.1.1.1.1.3.1`, `.3.11` (auth) | `81440633` | Yes (surname ` \| ID` suffix) | Yes | Hardware only; ministry use; CA expires 2027-09-08 | exclude |
| Signicat / Electronic Identification | No: remote HSM/QSCD only | `1.3.6.1.4.1.55193.1.1.1/.2` | `eedcf316` | Yes | Yes | Remote signing only | exclude |
| Docuten | No: centralized HSM/QSCD only | `1.3.6.1.4.1.56098.1.1.1` (indexed excerpt) | `b0cd0c09` | Not resolved | Yes | Remote only; incomplete documents | exclude |
| Indize | No: HSM or centralized QSCD only | `1.3.6.1.4.1.57967.1.1.1/.2` | `416da004` | Not resolved | Yes | Remote only | exclude |
| Permisso (Beyond the Scope) | Yes (`.60078.1.1.1`) | Profile v1 r2 plus 2023 specimen | `4ad810ef` | Yes (`IDCES-`, GN, SN) | Yes | **All 9 public specimens have RSA SPKI without NULL parameters, so Go `x509.ParseCertificate` fails**; specimen DNI checksum invalid; expired 2023 | exclude. Unlock: a current software leaf that Go parses, with a valid DNI |
| Firmafy | Yes on paper (`.59806.1.1.1`) | CPS 2.1 / workbook (spec) | `0e043bcc` (root `d54d506e` in `additional-ca-certificates/`) | Partly (the workbook has `XXX` placeholders) | Yes (modernpki) | No leaf observed anywhere | exclude. Unlock: one software leaf fixture |

## 2. Profile blocks (include / include-if)

Shared rules for every block: pin the listed service-identity certificate itself as the Go `x509.CertPool` root, so
no intermediate is needed. Accept only the exact leaf OID. Require the KU `digitalSignature` bit and `clientAuth`
when an EKU is present. Treat a leaf whose `QcStatements` contains `QcSSCD` (`0.4.0.1862.1.4`) as contradictory and reject it: every
software OID below is documented without QcSSCD. Use the DNI/NIE anchored grammar
`DNI := [0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]` and `NIE := [XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE]`, both with the mod-23
checksum (NIE X/Y/Z become 0/1/2). The blocks write this as `^IDCES-(DNI|NIE)$`. A `file:` name is the DER SHA-256.
Reject `PASES-` and non-`ES` country codes for a DNI census. None of these profiles documents a date of birth
(no `subjectDirectoryAttributes` in any profile or fixture): **birth_date is absent for every block**.

```yaml
profile_id: digitel-citizen-sw-g1
provider: DIGITEL ON TRUSTED SERVICES S.L.U.
display_name_es: "DIGITEL – Certificado cualificado de ciudadano (software)"
holder_role: natural_person
recommendation: include
confidence: high
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61.pem
    subject: "C=ES,L=Valladolid,O=DIGITEL ON TRUSTED SERVICES SLU,OU=DIGITEL TS CERTIFICATION AUTHORITY,serialNumber=B47447560,CN=DIGITEL TS QUALIFIED CA G1"
    sha256_der: 86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61
    spki_sha256: 00600557c6552a65e2dd8dee34d7b674043fd1c5935562ded5f26e2e5777eabb
    not_after: 2035-05-03T11:19:46Z
    key: RSA-4096 (sha512WithRSA, issued by DIGITEL TS CA ROOT 01)
    tsl_service_status: "CA/QC granted since 2025-03-27; ForeSignatures+ForeSeals; QSCD-managed criteria = .10.3.5/.15/.25/.35, .10.2.5 (not .10.3.1)"
intermediates_needed: []   # root DTSROOTCA01 (011e2583…) only for CA-status/ARL checks
leaf_policy_oids: ["1.3.6.1.4.1.54225.10.3.1"]
key_usage_expected: [digitalSignature, contentCommitment]      # fixture: critical
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [RSA-3072 (fixture)]                      # accept engine-wide RSA>=2048 / P-256 / P-384
identity:
  personal_id: {location: "subject 2.5.4.5 (PrintableString)", formats: ["IDCES-<DNI>", "IDCES-<NIE> (assumed, not observed)"], anchored_grammar: '^IDCES-(?P<id>[0-9]{8}[A-Z]|[XYZ][0-9]{7}[A-Z])$ + checksum'}
  given_names: {location: "subject 2.5.4.42 (UTF8String)"}
  surnames: {location: "subject 2.5.4.4 (UTF8String), both surnames", quirks: "CN = '<SURNAMES> <GIVEN> - <DNI>'; never parse CN"}
  cross_checks: ["optional: CN suffix ' - <id>' equals serialNumber id"]
  birth_date: {present: no, location: n/a, evidence: "fixture has no subjectDirectoryAttributes"}
revocation:
  ocsp: ["http://ocsp.digitelts.es"]
  responder_notes: "2026-10-30 live: good; delegated responder 'OCSP DIGITEL TS QUALIFIED CA G1' issued by the CA (OCSPSigning, ocsp-nocheck); nonce echoed; validity 5 min"
  crl: ["http://crl1.pki.digitelts.es/DTSQualifiedCAG1.crl", "http://crl2.pki.digitelts.es/DTSQualifiedCAG1.crl"]   # fetched: sig OK, 133 entries, 24 h window
  intermediate_status: "root ARL http://crl1.pki.digitelts.es/DTSROOTCA01.crl verified with root: 0 entries, nextUpdate 2027-09-18"
test_certificate_traps: "Specimen 'ESPECIMENSEIS/NOMSEIS', DNI 99949996T (checksum-valid), issued by the PRODUCTION CA and OCSP-good: deny-list its DER hash in production"
public_fixtures: "https://pki.digitelts.es/crt/CiudadanoSW.crt  DER SHA-256 fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8, valid 2026-05-18..2028-05-17, Go Verify(clientAuth) OK; no private key"
gaps: "No P12 for an E2E handshake; NIE and ECC leaves not observed; leaves issued under DPPC v3.1 (before 2026-07-23) not observed"
sources: [spec 1308-1318, "https://pki.digitelts.es/dppc/DIGITELTS_DPPC.v4.0.pdf", "https://pki.digitelts.es/crt/CiudadanoSW.crt"]
```

```yaml
profile_id: bewor-natural-person-sw
provider: Bewor tech, S.L.
display_name_es: "Bewor – Certificado cualificado de persona física (software)"
holder_role: natural_person
recommendation: include
confidence: high
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d.pem
    subject: "organizationIdentifier=VATES-B19603968,CN=BEWOR TECH CA1,OU=PSC-BEWOR,O=Bewor tech SL,L=GRANADA,C=ES"
    sha256_der: 8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d
    spki_sha256: ba0331d2b536d13f5d8953475ae3b945764ed54b3788ba5bf4f4a7ee6e770003
    not_after: 2033-05-12T08:46:35Z
    key: RSA-4096 (issued by UANATACA ROOT 2016; verified)
    tsl_service_status: "CA/QC granted since 2020-10-23; ForeSignatures; no qualification criteria"
intermediates_needed: []   # UANATACA ROOT 2016 (44607b3d…) only for the CA's ARL
leaf_policy_oids: ["1.3.6.1.4.1.55693.1.1.2"]   # .1.1.1 = centralized HSM: reject
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]   # critical
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [RSA-2048 (specimen)]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI>"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 (combined surnames)", quirks: "CN = '<GIVEN> <SURNAMES>'; SAN = email only"}
  cross_checks: []
  birth_date: {present: no, location: n/a, evidence: specimen}
revocation:
  ocsp: ["http://ocsp1.uanataca.com/public/pki/ocsp/", "http://ocsp2.uanataca.com/public/pki/ocsp/"]
  responder_notes: "Shared Uanataca host, but signed by the CA-delegated 'BEWOR TECH OCSP 01'; live 2026-10-30: valid specimen good, revoked specimen revoked (2022-06-03); nextUpdate +1 h; nonce echoed"
  crl: ["http://crl1.uanataca.com/public/pki/crl/bewor.crl", "http://crl2.uanataca.com/public/pki/crl/bewor.crl"]
  intermediate_status: "CA CDP -> http://crl1.uanataca.com/public/pki/crl/arl_uanataca.crl (not fetched)"
test_certificate_traps: "Specimens come from the PRODUCTION CA (NOMNUEVE ESPECIMENNUEVE, DNI 99949999A, checksum-valid, OCSP good): deny-list by DER hash in production"
public_fixtures: "Official ZIP https://public.bewor.com/bewor/legal/PSC/set_certificado_pruebas_bewor.zip contains PKCS#12 test identities with their passwords in credenciales/*.txt. 4763088_identity_PFsoftBT.p12: leaf DER da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab, valid 2025-05-19..2030-05-18, Go Verify(clientAuth) OK. It is the ONLY public software credential found that allows a real E2E browser mTLS test. 4762957_identity_PFsoftBT_revocado.p12: DER 52bef7a958c349ed0dc1881865c911820e9ef9f7b32741d67273a8f1ba527d92, expired 2024-06-02 and revoked. REPsoft* P12s serve as wrong-role negatives"
gaps: "Bewor CPS 5.5 not re-read this session (OID semantics from spec + specimen); NIE form not observed; keep test P12s out of the deliverable and production"
sources: [spec 1781-1800, "https://public.bewor.com/bewor/legal/PSC/PSC-1-DPC_BEWOR_ES.pdf"]
```

```yaml
profile_id: sectigo-citizen-local
provider: Sectigo (Europe) SL
display_name_es: "Sectigo – Certificado cualificado de ciudadano (no QSCD)"
holder_role: natural_person
recommendation: include          # with the mandatory digitalSignature KU gate
confidence: medium
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde.pem
    subject: "CN=Sectigo Qualified Natural Person CA R35,O=Sectigo (Europe) SL,C=ES"
    sha256_der: ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde
    spki_sha256: eb9f35a491f478c19fc0cdc02a8a5d54df26ed3b248f587459539bc2a48f6a24
    not_after: 2035-10-04T23:59:59Z
    key: RSA-3072 (sha384WithRSA by Root R45)
    tsl_service_status: "CA/QC granted since 2021-05-05; ForeSignatures; no criteria"
  - file: docs/Vocdoni_CSP_Handoff/service-identities/53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9.pem
    subject: "CN=Sectigo Qualified Natural Person CA E35,O=Sectigo (Europe) SL,C=ES"
    sha256_der: 53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9
    spki_sha256: 8e351d9cb41b50d077af2842b9faf748c4269ea6cf01e34d29f1f83c85edf983
    not_after: 2035-10-04T23:59:59Z
    key: EC P-256 (ecdsa-with-SHA384 by Root E45)
    tsl_service_status: "CA/QC granted since 2021-05-05; ForeSignatures; no criteria"
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.6449.1.2.1.7.1"]   # .7.2 CitizenQSCD, .7.3/.7.4 Employee, .7.5 QWAC: not enabled
key_usage_expected: [digitalSignature (REQUIRED; optional in v2.8), nonRepudiation]   # critical
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [RSA>=2048, EC P-256 min (profile); RSA-3072 (fixture)]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI>"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum; other country codes -> not a DNI'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4", quirks: "SAN = rfc822 only; CN = '<GIVEN> <SURNAMES>'"}
  cross_checks: []
  birth_date: {present: no, location: n/a, evidence: "profile v2.8 + fixture"}
revocation:
  ocsp: ["http://ocsp.sectigo.com"]
  responder_notes: "Live check on fixture: good, signature verified; thisUpdate 2026-10-27, nextUpdate 2026-11-03 (pre-generated, 7-day window). The freshness policy must honour nextUpdate and must not apply a 15-minute age limit here"
  crl: ["http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAR35.crl", "http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAE35.crl"]
  intermediate_status: "R45 ARL verified (0 entries, nextUpdate 2026-11-06); E45 ARL not fetched"
test_certificate_traps: "Official test leaves come from the PRODUCTION R35 CA (NOMDIEZ ESPECIMENDIEZ, DNI 99949990V, OCSP good): deny-list by hash"
public_fixtures: "https://www.sectigo.com/uploads/files/eIDAS/Natural-Person-Qualified-Test-Certificates.zip -> Citizen leaf DER 88059e9240bb96734d0a0c07d27a9fbd2741ebbdd49c08004b14b443962f2c30 (valid to 2028-09-16, Go Verify OK); Employee .7.3 leaf 5afc90f8e6a60ce17fc4bb80f11ce1e897565cf8d870e96eeeeaaa9c224df187 (negative: wrong profile)"
gaps: "E35 path untested; whether Spanish citizens receive these as browser-installable software is unconfirmed; real leaves may lack digitalSignature (these get rejected)"
sources: [spec 1344-1352, "https://www.sectigo.com/uploads/legal/eIDAS/Qualified_certificate_profiles_v2.8.pdf"]
```

```yaml
profile_id: firmaprofesional-personal-sw
provider: Firmaprofesional, S.A.
display_name_es: "Firmaprofesional – Certificado Personal de Persona Física (sin DCCF)"
holder_role: natural_person
recommendation: include-if-fixture
confidence: medium
trust_anchors:   # both CUALIFICADOS DERs share one key (SPKI c695bd5c…); pin both
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf.pem, subject: "CN=AC Firmaprofesional - CUALIFICADOS,serialNumber=A62634068,OU=Certificados Cualificados,O=Firmaprofesional S.A.,C=ES", sha256_der: 2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf, spki_sha256: c695bd5c40f753beb93f653202a3d6354ede0dd21295fd894a0869be366753e6, not_after: 2030-12-31T04:02:55Z, key: RSA-2048, tsl_service_status: "CA/QC granted since 2023-04-20 (5 history entries)"}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/4ccf17c0c8c1c10d5876ec5e3280fe8d134df36aedd8444289b990bc3741e74f.pem, subject: same, sha256_der: 4ccf17c0c8c1c10d5876ec5e3280fe8d134df36aedd8444289b990bc3741e74f, spki_sha256: c695bd5c40f753beb93f653202a3d6354ede0dd21295fd894a0869be366753e6, not_after: 2030-12-31T04:02:00Z, key: RSA-2048, tsl_service_status: same service}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1.pem, subject: "CN=FIRMAPROFESIONAL ICA B01 QUALIFIED 2022,organizationIdentifier=VATES-A62634068,O=Firmaprofesional SA,C=ES", sha256_der: 4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1, spki_sha256: dab1f8803dcf0900d5810e5d9b598781a1f039b30bdf89ad241bfa3e358dd8f9, not_after: 2047-03-31T09:04:41Z, key: EC P-384, tsl_service_status: "CA/QC granted since 2022-11-24"}
  # TSL QSCD-managed criteria on both services include .40.3, not .40.2 (consistent with .40.2 = software)
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.13177.10.1.40.2"]     # .40.3 = centralized DCCF: reject
key_usage_expected: [digitalSignature, contentCommitment, keyEncipherment]   # critical, §2.7.2
eku_expected: [clientAuth, "1.2.840.113583.1.1.5 (since 2023-09)", "emailProtection (only leaves issued before 2023-09)"]
leaf_key_algorithms: [unknown; not stated in profile]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI>", "IDCES-<NIE> (Firmaprofesional files NIE under IDC)"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum'}
  given_names: {location: "subject 2.5.4.42; SAN dirName 1.3.6.1.4.1.13177.0.1"}
  surnames: {location: "subject 2.5.4.4 (all surnames 'as in ID document')", quirks: "SAN 13177.0.2 first + 13177.0.3 second (may be empty)"}
  cross_checks: ["SAN 0.1 == GN; join(SAN 0.2, 0.3) == SN after NFC/space normalisation; mismatch -> reject"]
  birth_date: {present: no, location: n/a, evidence: "profile 260205 §2.7.1-2.7.4"}
revocation:
  ocsp: ["http://ocsp.firmaprofesional.com (CA AIA; leaf AIA expected, unverified)"]
  crl: ["leaf CDP (file name not documented)"]
  intermediate_status: "CUALIFICADOS -> http://crl.firmaprofesional.com/fproot.crl; ICA B01 -> http://crl.firmaprofesional.com/caroot-b_gp.crl"
test_certificate_traps: none known
public_fixtures: "none found"
gaps: "Changelog 250502 (2.7.1 updated), 250723 and 260205 ('Actualización de los campos SerialNumber'): leaves before 2025-05 may use another serialNumber form. Unlock: one genuine .40.2 leaf per CA (CUALIFICADOS RSA and ICA B01 ECC) showing the serialNumber form and SAN encoding"
sources: [spec 1214-1224, "https://firmaprofesional.com/wp-content/uploads/pdfs/FP_Perfiles_Certificados-260205-ES.pdf §2.7"]
```

```yaml
profile_id: anf-asociacion-class2-sw
provider: ANF Autoridad de Certificación Asociación ANF AC (NIF G63287510)
display_name_es: "ANF AC – Certificado de Clase 2 de Persona Física (software)"
holder_role: natural_person
recommendation: include-if-fixture
confidence: medium
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23.pem, subject: "CN=ANF AC Qualified Certificates for eSignature,OU=Certificados Cualificados de Firma Electronica,organizationIdentifier=VATES-G63287510,O=ANF Autoridad de Certificacion,C=ES", sha256_der: b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23, spki_sha256: d1b4c6d6b4f387bd50f89359a11c3a07673effb796cbcecfd32219594362988c, not_after: 2035-11-08T12:44:14Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2023-01-31; ForeSignatures; QSCD-managed criteria = .3.4.1.8.22 only"}
intermediates_needed: []   # ANF Global Root CA (e0afbd2c…) for the CA ARL
leaf_policy_oids: ["1.3.6.1.4.1.18332.3.4.1.2.22"]    # .4.22 QSCD, .5.22 centralized: reject
key_usage_expected: [digitalSignature, contentCommitment]          # profile v1.4 §2.1.2
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [unknown]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI|NIE>", "PASES-… (reject for DNI census)"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 (as in ID document)", quirks: "CN = 'Nombre apellidos - DNI'; OU 'Certificado de Clase 2 de Persona Física'; optional SAN 18332.10.1-.4, GeneralName encoding unknown: do not parse"}
  cross_checks: []
  birth_date: {present: no, location: n/a, evidence: "profile v1.4 §2.1"}
revocation:
  ocsp: ["leaf AIA (CA uses http://ocsp.anf.es/spain/AV)"]
  crl: ["leaf CDP"]
  intermediate_status: "http://crl.anf.es/crl/ANF_Global_Root_CA_2036_arl.crl"
test_certificate_traps: none known
public_fixtures: none found
gaps: "Leaf carries private extensions 1.3.6.1.4.1.18332.19 and .19.1 (request and operator locators) of unknown criticality. If they are marked critical, Go Verify fails. Unlock: one genuine .2.22 leaf"
sources: [spec 1226-1238, "https://anf.es/wp-content/uploads/2026/10/Perfiles-de-Certificados-v.1.4.pdf §2.1"]
```

```yaml
profile_id: anf-sl-class2-sw
provider: ANF Certification Authority, S.L. (NIF B87341228)
display_name_es: "ANF S.L. – Certificado de Clase 2 de Persona Física (software)"
holder_role: natural_person
recommendation: include-if-fixture
confidence: medium
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a.pem, subject: "CN=ANF Qualified for eSignature CA,OU=Qualified Certificates for electronic signature,organizationIdentifier=VATES-B87341228,O=ANF Certification Authority\\, S.L.,C=ES,serialNumber=B87341228", sha256_der: 5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a, spki_sha256: 9992ddc44e5b001f31044fd4723e424e3e2509799b084211f660d321a2fea436, not_after: 2032-10-04T14:16:18Z, key: RSA-4096 (sha512WithRSA by ANF AC SL Root CA), tsl_service_status: "CA/QC granted since 2024-02-08; QSCD-managed criteria = .2.5.1.13/.14/.15, .3.4.1.5.22, .3.4.1.8.22"}
intermediates_needed: []   # ANF AC SL Root CA (f8d86a96…)
leaf_policy_oids: ["1.3.6.1.4.1.49201.3.4.1.2.22"]    # verified in the S.L. PDF; never rewrite 18332<->49201
key_usage_expected: [digitalSignature, contentCommitment]
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [unknown]
identity: "identical to anf-asociacion-class2-sw; optional SAN 49201.10.1-.4; private extensions 49201.19/.19.1"
revocation:
  ocsp: ["leaf AIA (CA uses http://ocsp.anf.es/spain/AV)"]
  crl: ["leaf CDP"]
  intermediate_status: "http://crl.anf.es/crl/ANF_AC_SL_Root_CA-arl.crl"
test_certificate_traps: none known
public_fixtures: none found
gaps: "Same as Asociación; one genuine .2.22 leaf"
sources: [spec 1240-1246, "https://www.anf.ac/wp-content/uploads/2026/10/Perfiles-de-Certificados-v.1.4.pdf §2.1"]
```

```yaml
profile_id: uanataca-citizen-sw
provider: UANATACA, S.A.
display_name_es: "Uanataca – Certificado cualificado de Persona Física Ciudadano en software"
holder_role: natural_person
recommendation: include-if-fixture
confidence: medium
trust_anchors:   # all four issue end-entity certs (DPC §1.3.1.2-1.3.1.5); SHA-1 fingerprints match the DPC
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f.pem, subject: "organizationIdentifier=VATES-A66721499,CN=UANATACA CA1 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES", sha256_der: 35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f, spki_sha256: c886cd88edc69bffba28dcc5ba092fa5906742ce4712ddfc71e4e5851fa51f26, not_after: 2029-03-11T10:35:33Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2019-10-28"}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909.pem, subject: "organizationIdentifier=VATES-A66721499,CN=UANATACA CA2 2016,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona (see current address at www.uanataca.com/address),C=ES", sha256_der: 00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909, spki_sha256: fac53d2ea5667fa530415045aa563d293ed0de542e26a0607f31a480c695fe75, not_after: 2029-03-11T10:37:31Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2019-12-16"}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a.pem, subject: "organizationIdentifier=VATES-A66721499,CN=UANATACA CA1 2021,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona,C=ES", sha256_der: 9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a, spki_sha256: 12093d696c24875b59dbc44b2ac814961b8bc73b870310f6cecd5d21a4e6787a, not_after: 2034-06-03T10:52:31Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2021-11-16"}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a.pem, subject: "organizationIdentifier=VATES-A66721499,CN=UANATACA CA2 2021,OU=TSP-UANATACA,O=UANATACA S.A.,L=Barcelona,C=ES", sha256_der: 15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a, spki_sha256: 5f78b32f4a4770c8676ac81b467005ce22dde8f2613c5acca3612bcf6029a9b6, not_after: 2034-06-03T10:55:44Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2021-11-16"}
intermediates_needed: []   # UANATACA ROOT 2016 (44607b3d…) for the ARL
leaf_policy_oids: ["1.3.6.1.4.1.47286.1.1.1.1"]   # .1.1.1.2 HSM, .3 QSCD, .4 centralized QSCD, .5.x signing-only: reject
key_usage_expected: [digitalSignature, contentCommitment, keyEncipherment]   # DPC §1.4.1.1
eku_expected: "not documented in the DPC (§7.1.2: 'extensions are in the certificates'); Uanataca-platform specimens (Bewor, DEH, Permisso) carry clientAuth+emailProtection; require clientAuth if an EKU is present"
leaf_key_algorithms: [RSA (DPC §7.1.3 lists rsaEncryption only)]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["ETSI EN 319 412-1 (exact prefix not shown)"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum (confirm with fixture)'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 ('Apellidos')", quirks: "the DPC §3.1.1.1 citizen table also lists O/OU/organizationIdentifier/Title (likely copied from the linked-person table): ignore them; C = country of contractual relationship, not the ID country"}
  cross_checks: []
  birth_date: {present: no, location: n/a, evidence: "DPC §3.1.1.1"}
revocation:
  ocsp: ["http://ocsp1.uanataca.com/public/pki/ocsp/", "http://ocsp2.uanataca.com/public/pki/ocsp/"]
  crl: ["http://crl1.uanataca.com/public/pki/crl/CA1subordinada.crl", ".../CA2subordinada.crl", ".../2021CA1sub.crl", ".../2021CA2sub.crl (and crl2 mirrors)"]   # DPC §4.9.7; CRL at least every 24 h
  intermediate_status: "http://crl1.uanataca.com/public/pki/crl/arl_uanataca.crl"
test_certificate_traps: none known
public_fixtures: "none on https://web.uanataca.com/en/ca-certificates/ (CA certificates only)"
gaps: "The TSL criteria for CA1 2016 list legacy OIDs 1.3.6.1.4.1.47286.1.1.6 and .1.1.6.2, which are not in DPC v5.3, so older leaves may carry pre-v5 OIDs (do not wildcard). Unlock: one genuine .1.1.1.1 leaf (EKU, serialNumber prefix, issuing CA)"
sources: [spec 1260-1270, "https://web.uanataca.com/common/project/pdf/autoridad-certificacion/PSC-1.1-DPC_ES_v5.3-signed.pdf §1.2.1 §1.4.1.1 §3.1.1.1 §4.9.7"]
```

```yaml
profile_id: signe-personal-otros-dispositivos
provider: SIGNE S.A.
display_name_es: "SIGNE – Certificado Personal de Persona Física (otros dispositivos, nivel medio)"
holder_role: natural_person
recommendation: include-if-fixture
confidence: medium
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea.pem, subject: "CN=SIGNE Autoridad de Certificacion - 2020,OU=Autoridad de Certificacion,organizationIdentifier=VATES-A11029279,O=SIGNE S.A.,C=ES", sha256_der: b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea, spki_sha256: 7988bdc1ad8ebd8bf150d25ffe876fb05bb3444e1c064bd13f2a57d82bb5f66f, not_after: 2030-12-31T04:02:55Z, key: "RSA-4096 (under the Firmaprofesional root CIF A62634068; verified)", tsl_service_status: "CA/QC granted since 2024-12-03"}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35.pem, subject: "CN=SIGNE SUBCA 2024,organizationIdentifier=VATES-A11029279,O=Signe S.A.,C=ES", sha256_der: 244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35, spki_sha256: 6a30d221e4acfdae38d34006418094fa8337da2f30b9a99c04cfe7d98317dd70, not_after: 2049-11-28T12:16:00Z, key: "EC P-384 (under SIGNE ROOT 2024: not in bundle, http://www.signe.es/signe-ac/crl/signe-root.crt)", tsl_service_status: "CA/QC granted since 2025-10-02"}
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.36035.1.3.2"]   # .1.3.1 = portable DCCF: reject
key_usage_expected: [digitalSignature, contentCommitment]   # critical, CP v4.1 §5.2
eku_expected: [clientAuth, "1.2.840.113583.1.1.5"]
leaf_key_algorithms: [unknown]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI>", "PNOES-<NIE or other NIF>", "PASxx- (reject)"], anchored_grammar: '^IDCES-DNI$ | ^PNOES-NIE$ (checksum); PNOES- with non-NIE value -> unsupported'}
  given_names: {location: "subject 2.5.4.42; SAN dirName 1.3.6.1.4.1.13177.0.1"}
  surnames: {location: "subject 2.5.4.4 (full surnames)", quirks: "SAN uses the FIRMAPROFESIONAL namespace 13177.0.2/.0.3 (second may be empty); C = country that issued the identifier"}
  cross_checks: ["SAN given/surnames vs GN/SN"]
  birth_date: {present: no, location: n/a, evidence: "CP v4.1 §5"}
revocation:
  ocsp: ["leaf AIA (the profile shows only a placeholder)"]
  crl: ["http://www.signe.es/signe-ac/crl/signe-subca.crl (2024)", "https://www.signe.es/signe-ac/crl/signe2020.crl (2020)"]
  intermediate_status: "SUBCA 2024 -> http://www.signe.es/signe-ac/crl/signe-root.crl; SIGNE 2020 -> http://crl.firmaprofesional.com/fproot.crl"
test_certificate_traps: none known
public_fixtures: none found
gaps: "'Otros dispositivos' means non-QSCD, which may be a software store or a token; NIE under PNOES- is not seen elsewhere. Unlock: one leaf per CA generation"
sources: [spec 1320-1330, "SIGNE-ES-AC-PC-PER-06 v4.1 (Confluence URL in spec line 1322) §3.2.2 §5.1-5.3"]
```

```yaml
profile_id: lleidanet-natural-person-sw
provider: Lleidanet PKI S.L. (inDenova)
display_name_es: "Lleida.net – Certificado de Persona Natural Software"
holder_role: natural_person
recommendation: include-if-fixture
confidence: medium
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25.pem, subject: "description=inDenova Subordinate CA 003,CN=inDenova SUB CA 003,O=inDenova SL,organizationIdentifier=VATES-B97458996,serialNumber=B97458996,OU=Certification Authority inDenova SL,title=Subordinate Certificate Authority inDenova SL,L=VALENCIA,C=ES", sha256_der: 3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25, spki_sha256: e0f0a51ac007c5ea964344e785c4ac005d8db0e8cd7a33943f726a46c0532d3e, not_after: 2041-05-31T08:32:46Z, key: "RSA-4096 (root 'Certification Authority Root Indenova SL' not in bundle)", tsl_service_status: "CA/QC granted since 2024-06-05; QSCD-managed criteria = .1.1.x.3.x only"}
  # the profile's AKI c39c745dd022a8edf2ee50beafad7b6b29806c46 equals this CA's SKI (checked)
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.49959.1.1.1.1.1"]   # .1.1.1.2.1 HW, .3.x wallet/centralized: reject
key_usage_expected: [digitalSignature, contentCommitment]   # KU marked non-critical in rev10 §6.1
eku_expected: [clientAuth, emailProtection, "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.4.1.311.10.3.4"]
leaf_key_algorithms: ["RSA-4096 (rev8, 2025-12-18 onward)", "older leaves may be RSA-2048"]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<NIF>"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum'}
  given_names: {location: "subject 2.5.4.42 (upper case)"}
  surnames: {location: "subject 2.5.4.4 (APELLIDOS, upper case)", quirks: "C = nationality; CN = '(DOCUMENTO) NOMBRE APELLIDOS'; Subject also has description/email/L/ST; NO SAN (rev10 removed AAPP SAN fields)"}
  cross_checks: []
  birth_date: {present: no, location: n/a, evidence: "rev10 §6.1: 'Subject Directory Attributes: No está presente'"}
revocation:
  ocsp: ["http://ocsp2.esigna.es"]
  crl: ["http://crl1.esigna.es/sub/indenova_pki_003.crl", "http://crl.esigna.es/sub/indenova_pki_003.crl"]
  intermediate_status: "CA CDP -> http://crl.esigna.es/root/ca_root_indenova_sl.crl"
test_certificate_traps: none known
public_fixtures: none found
gaps: "Leaves issued before rev8/rev10 may still carry SAN and street-address fields, which is harmless. Unlock: one genuine leaf"
sources: [spec 1354-1364, "https://www.lleida.net/assets/docs/policies/general/lleidanetpki-perfiles-certificados.pdf rev10 §4 §6.1"]
```

```yaml
profile_id: deh-certibox-citizen-sw
provider: DEH Notificación Electrónica Habilitada S.L. (Certibox)
display_name_es: "Certibox – Certificado cualificado de Persona Física en software"
holder_role: natural_person
recommendation: include-if-spanish-fixture
confidence: low
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/e9485e076281b783846f4c03e9291d02cd22fd1a0da2c55f051dd48673440ae8.pem, subject: "C=ES,L=Madrid,O=DEH NOTIFICACION ELECTRONICA HABILITADA SL,organizationIdentifier=VATES-B86198306,OU=TSP-CERTIBOX,CN=CERTIBOX CA Subordinada 01", sha256_der: e9485e076281b783846f4c03e9291d02cd22fd1a0da2c55f051dd48673440ae8, spki_sha256: 8ed1834471ae50ac1cb9c63df2b09f3ee08c3dd5cc40d5087ad0be0073f2ac1b, not_after: 2036-03-05T11:43:15Z, key: "RSA-4096 (root CERTIBOX ROOT CA = additional-ca-certificates/cb5bf9eb…)", tsl_service_status: "CA/QC granted since 2026-03-26; QSCD-managed criteria = .1.x.3"}
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.57853.1.1.1"]   # .1.1.2 HSM, .1.1.3/.4 QSCD: reject
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]   # specimen, critical
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [RSA-2048 (specimen)]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI|NIE> (expected)", "specimen: IDCEC-00000000T (Ecuador; must be rejected for an ES census)", "older CPS tables: bare DNI/NIE (reject until fixture)"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 (combined)", quirks: "subject C follows the ID country (EC in specimen)"}
  cross_checks: []
  birth_date: {present: no, location: n/a, evidence: specimen}
revocation:
  ocsp: ["http://ocsp1.uanataca.com/public/pki/ocsp/", "http://ocsp2.uanataca.com/public/pki/ocsp/"]
  crl: ["http://crl1.uanataca.com/public/pki/crl/DEHCA1.crl (specimen CDP)", "repository alternative crl1.modernpki.com/public/pki/crl/DEHCA1.crl"]
  intermediate_status: "CA CDP -> http://crl1.uanataca.com/tsp/crl/arl_deh.crl"
test_certificate_traps: "Production-CA specimens with ID 00000000T"
public_fixtures: "deh.es specimen ZIP -> PFsoftDEHCiudadano_13335236.cer DER b7e5cb46ede6ebb3e6ace07915bd2fe6bb5b5e56e9da87c0f9b3ff7c5e85ffba (to 2028-05-11; Go Verify OK; a useful wrong-country negative)"
gaps: "Unlock: a software leaf carrying a Spanish IDCES- identifier"
sources: [spec 1834-1846, "https://deh.es/_files/ugd/DPC_VID_DEH_2048.v2.3.r1.pdf"]
```

```yaml
profile_id: eadtrust-natural-person-sw
provider: EAD Trust European Agency of Digital Trust, S.L.
display_name_es: "EADTrust – Certificado cualificado de persona física sin dispositivo cualificado"
holder_role: natural_person
recommendation: include-if-fixture
confidence: low
trust_anchors:   # the five 2019 "Natural Person" SubCAs; each CA cert also asserts policy 1.3.6.1.4.1.501.2.1.1.1.401 + anyPolicy
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/82340ea4d7acd80df97dc7598c9495588cc8873ec9506dad0c11ea119433399d.pem, subject: "OU=Natural Person,organizationIdentifier=VATES-B85626240,C=ES,O=European Agency of Digital Trust\\, S.L.,CN=EADTrust RSA 2048 SubCA For Qualified Certificates 2019", spki_sha256: 43e1f34acf44ef4d6832f5b197d28635ab31862850699653417ed48ccf948825, not_after: 2035-06-02T10:56:21Z, key: RSA-2048}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/04bf1da6d0168bdd3f2dec2e22c50d558bde5c7cc9516c83cb6393352a9f0f9c.pem, subject: "... CN=EADTrust RSA 4096 SubCA For Qualified Certificates 2019", spki_sha256: bfe28fded949976d66483b055cc99f033863e821b14d502f3b0e7c1999164c71, not_after: 2035-06-02T10:56:35Z, key: RSA-4096}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/2002b8d5af02c5a961e10a4da3c27f63f35d7f7aad941599da36d52e03b7a89d.pem, subject: "... CN=EADTrust RSA 8192 SubCA For Qualified Certificates 2019", spki_sha256: 83375022ce056a8105970f47bb68fe8ab398bb3e774439588988546d794376e2, not_after: 2035-06-02T11:20:51Z, key: RSA-8192}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/e5f78053300c169d79a7fb387361ad2a8d1a9bb750b9183c7bb19734d542f07c.pem, subject: "... CN=EADTrust ECC 256 SubCA For Qualified Certificates 2019", spki_sha256: 6b8c6a60ccd0d057b7296b0dd9384fb52a3b2345b73b082cebdc10d27729d657, not_after: 2035-06-02T11:23:12Z, key: EC P-256}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/f8ea34651355c407c903875608b0ffa188805e93081ad03a39b8226dc35eadb4.pem, subject: "... CN=EADTrust ECC 384 SubCA For Qualified Certificates 2019", spki_sha256: 2d1a16b17d23a07c7f7bebba7e61d99e00e4b317c1bb5e9459150fcb2d2ea8c0, not_after: 2035-06-02T11:23:16Z, key: EC P-384}
  # '...' = shared prefix 'OU=Natural Person,organizationIdentifier=VATES-B85626240,C=ES,O=European Agency of Digital Trust\, S.L.,'
  # all five: CA/QC granted since 2020-10-05, ForeSignatures, no criteria. "…-LP" (legal person) SubCAs share CN text: pin by hash only
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.501.2.1.1.0.41221", "1.3.6.1.4.1.501.2.1.1.3.41221"]   # in-person / video ID; .1./.4.41221 = QSCD: reject
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]   # critical, §10.1.1
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: ["RSA>=2048", "EC P-256", "EC P-384"]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["ETSI; the policy example 'IDCES-012345678R' has 9 digits (illustrative, invalid)"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum; a 9-digit form -> reject until a fixture explains it'}
  given_names: {location: "subject 2.5.4.42; SAN 501.1.1"}
  surnames: {location: "subject 2.5.4.4 (all surnames)", quirks: "SAN 501.1.2/.1.3; OU 'Certificado de persona física'"}
  cross_checks: ["SAN 501.1.4 id == serialNumber id (if present)"]
  birth_date: {present: no, location: n/a, evidence: "policy §10.1.1"}
revocation:
  ocsp: ["http://ocsp.eadtrust.eu"]
  crl: ["leaf CDP; spec: https://crl.eadtrust.eu/eadtrust-subca-{rsa2048,rsa4096,rsa8192,ecc256,ecc384}eadnp2019.crl (the policy prints the template eadtrust-subca-eadnp.crl)"]
  intermediate_status: "http://crl.eadtrust.eu/eadtrust-root-<alg>eadq2019.crl (CA CDPs)"
test_certificate_traps: none known
public_fixtures: none found
gaps: "The policy dates from April 2020 and is still listed as current. Unlock: one genuine software leaf (any algorithm)"
sources: [spec 1332-1342, "https://www.eadtrust.eu/wp-content/uploads/2025/02/emision-certificados-persona-fisica-abril-2020.pdf §10.1.1"]
```

```yaml
profile_id: vintegris-individual-sw
provider: VINTEGRIS S.L.U.
display_name_es: "Víntegris – Certificado Individual de Persona Física en software"
holder_role: natural_person
recommendation: include-if-fixture
confidence: low
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/da1326d22e64f7c21f388121f68c8f700d305c69fb0b5e8b9fc2846f7ae7cb70.pem, subject: "CN=vinCAsign nebulaSUITE2 Authority,O=VINTEGRIS SL,OU=vinCAsign,organizationIdentifier=VATES-B62913926,L=HOSPITALET DE LLOBREGAT,ST=BARCELONA,C=ES", spki_sha256: c7292e110fb531ef8fc86bba5c8974dc2a5138211d4d4ed5e083417b8495b067, not_after: 2030-09-27T14:20:46Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2019-11-06"}
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/75a6330ed167b2877a4387931303ba93d78f72f55a137aa5506fd32930b7e297.pem, subject: "C=ES,ST=BARCELONA,L=HOSPITALET DE LLOBREGAT,O=VINTEGRIS SLU,organizationIdentifier=VATES-B62913926,CN=CA Vintegris TrustServices", spki_sha256: 42dcb433cf0104a185485a183a32f2cb824d607ef1cb10831bdd65f0194b005f, not_after: 2032-01-22T13:09:19Z, key: RSA-4096, tsl_service_status: "CA/QC granted since 2025-06-10"}
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.47155.1.10.2 (only under nebulaSUITE2)", "1.3.6.1.4.1.47155.2.10.2 (only under TrustServices)"]   # .10.52 ephemeral (<=72 h): reject
key_usage_expected: [digitalSignature, contentCommitment, keyEncipherment]
eku_expected: [clientAuth, "1.2.840.113583.1.1.5"]
leaf_key_algorithms: [RSA-2048 (profile)]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<NIF>"], anchored_grammar: '^IDCES-(DNI|NIE)$ + checksum'}
  given_names: {location: "subject 2.5.4.42; SAN 47155.1.1"}
  surnames: {location: "subject 2.5.4.4", quirks: "SAN 47155.1.2/.1.3 (second optional); CN ends ' - DNI'"}
  cross_checks: ["SAN 47155.1.4 (IDCES-NIF) == serialNumber"]
  birth_date: {present: no, location: n/a, evidence: profile v1.4}
revocation:
  ocsp: ["http://ocsp.vincasign.net"]
  crl: ["http://crl1.vincasign.net/canebula2.crl", "http://crl1.vincasign.net/catrustservices.crl (+crl2)"]   # spec; the profile PDF OCR garbles them
  intermediate_status: "nebulaSUITE2 -> http://crl3.vincasign.net/casub.crl; TrustServices -> http://crl1.vincasign.net/cavintegris.crl (CA CDPs)"
test_certificate_traps: none known
public_fixtures: none found
gaps: "The profile PDF text is OCR-garbled (EKU printed as '1.3.6.1.5.5.7.3', SAN id as 'IDCZ5-'); the issuer is cloud/ephemeral-first. Unlock: one SOFT leaf per CA"
sources: [spec 1286-1296, "https://www.vincasign.net/policy/es/profile/profile-vintegrisroottrustservices_v.1.4.pdf"]
```

```yaml
profile_id: aca-persona-fisica-sw
provider: Consejo General de la Abogacía Española (ACA)
display_name_es: "ACA – Certificado Cualificado de Persona Física en software"
holder_role: natural_person
recommendation: include-if-fixture
confidence: low
trust_anchors:
  - {file: docs/Vocdoni_CSP_Handoff/service-identities/c6dfaaace235da93e1c87d4ec7768652563d54c538b31e8cbd0680e91db75316.pem, subject: "CN=ACA 1,O=CONSEJO GENERAL DE LA ABOGACIA ESPAÑOLA,organizationIdentifier=VATES-Q2863006I,OU=AUTORIDAD DE CERTIFICACION DE LA ABOGACIA,C=ES", sha256_der: c6dfaaace235da93e1c87d4ec7768652563d54c538b31e8cbd0680e91db75316, spki_sha256: 3c83cfbff4c94c2a45d8b0312fa69d13af0e9e1b16609c37980781656092f853, not_after: 2044-03-18T15:51:30Z, key: "EC P-521 (ecdsa-with-SHA512 by ACA ROOT 2: not in bundle, http://acacert.acabogacia.org/aca_root2.crt)", tsl_service_status: "CA/QC granted since 2026-02-19; QSCD-managed criteria = .50.{1..6}.2"}
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.16533.50.6.3"]   # .50.6.2 centralized (shared by sign and NCP+ auth): reject
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]   # critical, CP6 §7.1.2.2
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [RSA-3072, RSA-4096]   # signed ecdsaWithSHA256 by the P-521 CA
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["bare NIF", "IDCES-<NIF> (example IDCES-11111111H)"], anchored_grammar: '^(IDCES-)?(DNI|NIE)$ + checksum (both are documented by CP6 §3.1.1)'}
  given_names: {location: "subject 2.5.4.42; SAN dirName 16533.100.1 (optional)"}
  surnames: {location: "subject 2.5.4.4 = FIRST SURNAME ONLY; SAN 16533.100.2/.100.3 (optional)", quirks: "if SAN is absent, return surname1 only with name_completeness=partial; CN 'Nombre Apellido1 Apellido2 (SW)' only as a cross-check"}
  cross_checks: ["SAN 100.2 == SN"]
  birth_date: {present: no, location: n/a, evidence: CP6 §3.1.1, §7}
revocation:
  ocsp: ["http://acaocsp.acabogacia.org/"]
  crl: ["leaf CDP, partitioned http(s)://acacrl.acabogacia.org/crl/aca1_crl<N>.crl (never guess N)"]
  intermediate_status: "http://acacrl.acabogacia.org/crl/ACA_root2_ARL.crl"
test_certificate_traps: none known
public_fixtures: none found
gaps: "Incomplete surnames when SAN is absent; ACA CA1/CA2 legacy leaves use other policy arcs (not covered). Unlock: genuine .50.6.3 leaves with and without SAN"
sources: [spec 1248-1258, "https://www.abogacia.es/repositorio/acaplusdescarga/dpc_pc/2025/ACA1/CP6_ACA1_002_03.pdf §3.1.1 §6.1.7 §7.1.2"]
```

## 3. Generic engine implications

1. **Pin service identities, not roots.** Put the exact service-identity DER (or its SPKI) in the Go
   `x509.CertPool` used as `Roots`. Go never checks the anchor's own signature. This avoids two observed Go
   failures: the AOC EC-ACC root fails to parse (negative serial), and SHA-1-signed intermediates (ACCVCA-120 and
   the Izenpe 2007 CAs) fail chain building if their roots are the anchors. Keep the roots separately as
   **CA-status (ARL) verification keys only**. Use the same anchors in `tls.Config.ClientCAs` so the
   CertificateRequest advertises them. Firmaprofesional CUALIFICADOS has two DERs with one DN; deduplicate the
   advertised DN list.
2. **Go does not check KeyUsage bits.** `Verify(KeyUsages: ClientAuth)` checks only the EKU. The engine must itself
   require `digitalSignature`. This matters for Sectigo v2.8 (optional) and for split signing-only leaves (SIA high,
   ACA centralized).
3. **EKU nesting.** Go applies the requested EKU to every certificate in the chain, the anchor included. Every
   person CA in this report either has no EKU or has one that includes clientAuth: Sectigo NP R35/E35, inDenova 003,
   SIGNE 2020, ACA CA1/CA2 and CAEDICOM04. An `extendedKeyUsage` scan of all bundled CA certificates found
   clientAuth missing only on TLS-server/website and time-stamping CAs. Re-check whenever an anchor is added.
4. **Policy OIDs belong in application code.** Go 1.27 always runs RFC 5280 policy-graph processing. With the
   intermediate as anchor and no policy constraints, this is a no-op. Leave `VerifyOptions.CertificatePolicies` empty
   and compare `leaf.Policies` against the exact allowlist. CAEDICOM04 asserts only `1.3.6.1.4.1.30051.2.3.1.1`, not
   anyPolicy; EADTrust NP CAs assert `.501.2.1.1.1.401` plus anyPolicy.
5. **Unparseable leaves never reach the application.** All 9 Permisso 2023 specimens encode the RSA
   SubjectPublicKeyInfo without the NULL parameters, so Go fails with `x509: RSA key missing NULL parameters`.
   `crypto/tls` then aborts the handshake before any handler runs. Onboarding must parse a real leaf with the
   production Go version. The DIGITEL, Bewor, Sectigo and DEH leaves parse.
6. **Unhandled critical extensions.** No fixture here has one. The ANF private leaf extensions (`.19`, `.19.1`) are
   undetermined. Any critical private extension needs an explicit, reviewed handler, never a blanket ignore.
7. **OCSP freshness differs by issuer.** DIGITEL gives 5 minutes, Bewor (Uanataca platform) 1 hour, Sectigo a
   pre-generated 7-day window with `thisUpdate` about 3 days old. Bound by `nextUpdate`, not by a fixed age. Shared
   Uanataca OCSP hosts (Bewor, DEH, Uanataca, Signicat, Docuten, Indize, Permisso) answer through **per-CA
   delegated responders**, for example `BEWOR TECH OCSP 01`. Require that the responder certificate was issued by the
   leaf's actual issuer.
8. **Registradores/Defensa UserNotice VisibleString.** The `explicitText` VisibleStrings contain non-ASCII
   Latin-1 bytes (for example `0xF1` for "ñ"). Python `cryptography` rejects this. **Go 1.27 parses all of them**,
   because it decodes policy OIDs and ignores qualifiers. The Registradores AC Interna/Externa RSA and the ECC
   (P-521 key, RSA-SHA512-signed) intermediates also pass Go `Verify` to the bundled root. Oddity: the
   Registradores root's own notice reads "Certificado de Test …" with CPS `http://test.pki.registradores.org/…`.
9. **Production-CA specimens.** DIGITEL, Bewor, Sectigo and DEH publish test identities from production CAs, and
   these return OCSP `good`. Keep a deny-list of their DER SHA-256 values, and of any later fixture, for production
   elections.
10. **The NIE type prefix varies.** SIGNE uses `PNOES-`; Firmaprofesional, Lleidanet and others use `IDCES-`.
    Normalise to a typed `{country, kind, value}` per profile and never infer the kind from the prefix alone.

### Go 1.27 parse test (`crypto/x509.ParseCertificate`, then `CheckSignatureFrom` and `Verify`)

Program: `/home/p4u/.cache/cert-check/research/goparse/main.go` (`go 1.27`, default GODEBUG). It parses every PEM
block in `service-identities/`, `additional-ca-certificates/` and `evidence/public-test-certificates/`. It checks
the signature against any bundled certificate whose subject equals the issuer. It then runs `Verify` with all
bundled self-signed certificates as roots, `ExtKeyUsageAny`, at 2026-10-30T12:00Z. Raw TSV:
`/home/p4u/.cache/cert-check/research/goparse/result.tsv`. A second program, `leafcheck/`, verified the DIGITEL,
Sectigo, DEH and Bewor leaves against their single pinned anchors with `ExtKeyUsageClientAuth`: all OK.

**Result:** 206 PEM blocks (173 unique DER). **205 parse OK; 1 failure**: EC-ACC (`88497f01…`, AOC G2 root),
`x509: negative serial number`. It parses with `GODEBUG=x509negativeserial=1`, but its self-signature is
SHA1-RSA, so pin EC-Ciutadania instead. There are no unhandled critical extensions in any CA. Verify outcomes:
50 OK, 21 roots, 90 "no root in bundle" (expected, since service identities are mostly intermediates), 9 expired
(the archived ANCERT `_2010` V2 intermediates) and 3 "FAIL SHA1": ACCVCA-120 and the two Izenpe 2007 CAs, whose
issuers sign with SHA1-RSA. Pin these three as anchors. Legend for **in**: S = `service-identities/`,
A = `additional-ca-certificates/`, T = `evidence/public-test-certificates/`.

| sha256[:16] | in | subject CN | key | sig alg | Go parse | sig vs bundle issuer | Verify to bundle root |
|---|---|---|---|---|---|---|---|
| `002393fa0a6825f7` | S | Sectigo Qualified Website Authentication CA R35 | RSA-3072 | SHA384-RSA | OK | - | no root in bundle |
| `009dbad686cecd81` | S | EADTrust RSA 4096 SubCA For Qualified Web EV/PSD2 Ce | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `00c367a774b7ce9a` | S | Sectigo Qualified Website Authentication CA Natural  | EC-P-256 | ECDSA-SHA384 | OK | - | no root in bundle |
| `00ff2ff2efba98c6` | S | UANATACA CA2 2016 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `0414b95412a98b2d` | S | EADTrust ECC 384 SubCA For Qualified Certificates 20 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `04bf1da6d0168bdd` | S | EADTrust RSA 4096 SubCA For Qualified Certificates 2 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `05461634195849a1` | S | Sectigo Qualified Website Authentication CA E39 | EC-P-256 | ECDSA-SHA384 | OK | - | no root in bundle |
| `072c239e48ee4117` | S | EADTrust RSA 4096 SubCA For Qualified Web DV/OV Cert | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `0ca8b7a01506cafa` | SA | ANCERT Certificados Notariales Corporativos V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `0df2883b6074d5b7` | SA | AC REPRESENTACIÓN G2 | EC-P-256 | ECDSA-SHA384 | OK | ok | ok (2) |
| `0e043bccc0e9dd77` | SA | Firmafy CA Subordinada 01 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `0e1f3a20040ed5b2` | S | EADTrust ECC 256 SubCA For Qualified Web DV/OV Cert  | EC-P-256 | ECDSA-SHA256 | OK | - | no root in bundle |
| `0fd99aae1ffcd5d9` | SA | EC-Ciutadania | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `1485b4a7ded01028` | S | EAD Trust ECC 384 SubCA For Qualified Web DV/OV Cert | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `15ceab339144d48d` | S | UANATACA CA2 2021 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `16ad38142bf3d07d` | S | ANF Qualified for eSeal CA | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `1edb6bd91274882d` | S | AC SERVIDORES SEGUROS TIPO1 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `1f11a6555cc6f24d` | S | EAEko HAetako langileen CA - CA personal de AAPP vas | RSA-4096 | SHA1-RSA | OK | SHA1 rejected | FAIL SHA1 |
| `2002b8d5af02c5a9` | S | EADTrust RSA 8192 SubCA For Qualified Certificates 2 | RSA-8192 | SHA512-RSA | OK | - | no root in bundle |
| `22e41b4879faa211` | S | EADTrust RSA 8192 SubCA For Qualified Certificates 2 | RSA-8192 | SHA512-RSA | OK | - | no root in bundle |
| `244166240947c407` | S | SIGNE SUBCA 2024 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `25303cfd0bf1baa1` | SA | EAEko HAetako langileen CA - CA personal de AAPP vas | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `2626b19563bc78d9` | S | Herritar eta Erakundeen CA - CA de Ciudadanos y Enti | RSA-4096 | SHA1-RSA | OK | SHA1 rejected | FAIL SHA1 |
| `283a9f9fe9674f67` | SA | AC USUARIOS G2 | EC-P-256 | ECDSA-SHA384 | OK | ok | ok (2) |
| `29400d5d520da085` | S | EADTrust RSA 2048 SubCA For Qualified Certificates 2 | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `2b75cc4f36759cfc` | S | AC Firmaprofesional - CUALIFICADOS | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `2b7b390ff652aeca` | SA | SubCA SECTOR PUBLIC Q (G3) A.1 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `2c1823619d807311` | S | ESFIRMA AC AAPP 2 | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `2de620f2d1200aa9` | SA | ACCVCA-120 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `306bf8099636a44f` | S | ANF Secure Server CA | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `3395966916f8d39d` | S | Sectigo Qualified Legal Person CA R35 | RSA-3072 | SHA384-RSA | OK | - | no root in bundle |
| `339e6b92be5459f2` | S | Sectigo Qualified Website Authentication CA Natural  | RSA-3072 | SHA384-RSA | OK | - | no root in bundle |
| `3431292a66fb3ea5` | S | ANF AC Qualified Certificates for eSeal | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `3452e96743442607` | S | inDenova SUB CA 003 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `346440cf7674a529` | S | ACCV RSA1 TLS | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `34fdb6f3d2d1070d` | SA | ACCV ECC1 PROFESIONALES | EC-P-521 | ECDSA-SHA512 | OK | ok | ok (2) |
| `356a5f4d994e9efa` | S | EC-SectorPublic | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `35a99284a220789b` | S | UANATACA CA1 2016 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `360993593406e5aa` | S | EADTrust ECC 256 SubCA For Qualified Certificates 20 | EC-P-256 | ECDSA-SHA256 | OK | - | no root in bundle |
| `3845f56e3f6c150e` | S | EAD Trust ECC 384 SubCA For Qualified Web EV/PSD2 Ce | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `39e379db8a2f67cc` | SA | Centro Tecnológico del Notariado CA-QC Corporativos | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `3a8066266d28bd28` | S | AC CAMERFIRMA FOR LEGAL PERSONS - 2016 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `3bc51856040ad7ff` | S | ACCVCA-120 | RSA-4096 | SHA1-RSA | OK | SHA1 rejected | FAIL SHA1 |
| `3ccf0306bed8c910` | S | Sectigo Qualified Website Authentication CA Natural  | RSA-3072 | SHA384-RSA | OK | - | no root in bundle |
| `416da00480ebc814` | S | INDIZE CA Subordinada 01 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `459e0f12a7723f40` | S | EAD Trust ECC 256 SubCA For Qualified Web DV/OV Cert | EC-P-256 | ECDSA-SHA256 | OK | - | no root in bundle |
| `4a86f3337cec89a6` | S | FIRMAPROFESIONAL ICA B01 QUALIFIED 2022 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `4ad810ef18db53e0` | S | Permisso CA Subordinada 01 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `4b4c8eac327760e8` | S | EAD Trust RSA 8192 SubCA For Qualified Web DV/OV Cer | RSA-8192 | SHA512-RSA | OK | - | no root in bundle |
| `4ccf17c0c8c1c10d` | S | AC Firmaprofesional - CUALIFICADOS | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `4d187d4e5bba7bba` | SA | AC CAMERFIRMA QUALIFIED CERTIFICATES - 2021 | RSA-4096 | SHA384-RSA | OK | ok | ok (2) |
| `50d5748d831c2864` | S | ACCV RSA1 COMPONENTES | RSA-4096 | SHA512-RSA | OK | ok | ok (2) |
| `514a806a46d7b797` | S | EADTrust RSA 8192 SubCA For Qualified Web EV/PSD2 Ce | RSA-8192 | SHA512-RSA | OK | - | no root in bundle |
| `51583118e6c5e5d2` | SA | INFOCERT-CAMERFIRMA QUALIFIED CERTIFICATES - 2024 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `53b24005fd13671f` | S | Sectigo Qualified Natural Person CA E35 | EC-P-256 | ECDSA-SHA384 | OK | - | no root in bundle |
| `562d6a5b4b067465` | S | Sectigo Qualified Website Authentication CA E35 | EC-P-256 | ECDSA-SHA384 | OK | - | no root in bundle |
| `5999789a17df8674` | S | ANF Qualified for eSignature CA | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `59b49880637b4db1` | S | SIA SUB01 2025 | EC-P-384 | ECDSA-SHA512 | OK | - | no root in bundle |
| `5caf44b2923b146c` | SA | ACCV ECC1 CLIENTE | EC-P-521 | ECDSA-SHA512 | OK | ok | ok (2) |
| `5de90851a1a2235c` | SA | AC CONSULARES G2 | EC-P-256 | ECDSA-SHA384 | OK | ok | ok (2) |
| `601293ca20b09a03` | SA | AC FNMT Usuarios | RSA-2048 | SHA256-RSA | OK | ok | ok (2) |
| `60adc74248a45f7d` | SA | ACCV RSA1 PROFESIONALES | RSA-4096 | SHA512-RSA | OK | ok | ok (2) |
| `6284c3d2bb5e4a6a` | S | EAD Trust ECC 256 SubCA For Qualified Web EV/PSD2 Ce | EC-P-256 | ECDSA-SHA256 | OK | - | no root in bundle |
| `63eb5ba0de32d4ae` | S | SubCA Q TSA (G3) A.5 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `681ebc1822b079b9` | S | Entrust Certification Authority - QTSP1 | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `68690054b917c0e4` | S | SIA SUB01 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `6ad43c815cd847af` | S | AC DGP 004 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `705eb3a0b1f09ded` | S | ACA CA1 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `75a6330ed167b287` | S | CA Vintegris TrustServices | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `783ed47b5175a902` | S | SubCA SECTOR PUBLIC R Q (G3) A.3 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `79a49f18ea13d923` | S | ANF Secure SSL CA | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `7e4e551152f06c51` | SA | CA ADMINISTRAZIO PUBLIKOA-ADMINISTRACION PUBLICA 202 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `7e9316a5cecfb90a` | S | ACA CA2 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `7ed19361ad734d70` | SA | Herritar eta Erakundeen CA - CA de Ciudadanos y Enti | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `7fd0ffdf3aa0c969` | S | EADTrust RSA 4096 SubCA For Qualified Certificates 2 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `7feb6f8c9c847a44` | S | AC SERVIDORES SEGUROS TIPO2 G2 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `80ab1baac5caa236` | S | EADTrust ECC 384 SubCA For Qualified Web DV/OV Cert  | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `814406331b979fb1` | SA | DEFENSA-EC-WPG2016 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `82340ea4d7acd80d` | S | EADTrust RSA 2048 SubCA For Qualified Certificates 2 | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `8265756dd5cd8a37` | SA | AC Sector Público | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `86a62f63dcabec9f` | S | DIGITEL TS QUALIFIED CA G1 | RSA-4096 | SHA512-RSA | OK | - | no root in bundle |
| `8a386ed1c0932603` | S | BEWOR TECH CA1 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `8e6af1e1377adf7e` | S | AC TSA CLIENTES | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `8f540ab3e89d71e9` | S | EAD Trust RSA 8192 SubCA For Qualified Web EV/PSD2 C | RSA-8192 | SHA512-RSA | OK | - | no root in bundle |
| `8fd16a179944d5d1` | SA | AC Representación | RSA-2048 | SHA256-RSA | OK | ok | ok (2) |
| `93c087ab9331b74c` | S | ACCV ECC1 TLS | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `95829c3f0175ba8a` | S | FIRMAPROFESIONAL ICA A01 QWAC 2026 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `983329b00c3052d7` | SA | AC SECTOR PÚBLICO G2 | EC-P-256 | ECDSA-SHA384 | OK | ok | ok (2) |
| `9993d183292afc41` | S | AC SERVIDORES SEGUROS TIPO1 G2 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `9b083dc45b1bec21` | S | UANATACA CA1 2021 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `9ce630b35f8ae2c6` | S | AC Unidades de Sellado de Tiempo | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `a14616d1e8c0b49e` | S | EADTrust RSA 8192 SubCA For Qualified Web DV/OV Cert | RSA-8192 | SHA512-RSA | OK | - | no root in bundle |
| `a66b485645a5d66a` | SA | ACCV RSA1 CLIENTE | RSA-4096 | SHA512-RSA | OK | ok | ok (2) |
| `a83d4488255c469f` | S | Validated ID Subordinate CA 01 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `a885ec8218b1c967` | SA | ANCERT Certificados FERN V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `a9841d2e47cbe6d7` | S | Sectigo Qualified Website Authentication CA Natural  | EC-P-256 | ECDSA-SHA384 | OK | - | no root in bundle |
| `ac866830d7b8d712` | S | Sectigo Qualified Natural Person CA R35 | RSA-3072 | SHA384-RSA | OK | - | no root in bundle |
| `ac8c7ef96eb4b535` | S | Sectigo Qualified Website Authentication CA R39 | RSA-3072 | SHA384-RSA | OK | - | no root in bundle |
| `b0cd0c093ea1d652` | S | DOCUTEN TECH CA1 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `b211c48c2bd45066` | S | CAEDICOM04 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `b45ab8e079025df9` | S | AC SERVIDORES SEGUROS TIPO2 G2R | RSA-4096 | SHA384-RSA | OK | - | no root in bundle |
| `b4ce3f048f90aebe` | S | INFOCERT-CAMERFIRMA QUALIFIED TSA - 2024 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `b76911a3352d1a27` | S | EADTrust ECC 256 SubCA For Qualified Web EV/PSD2 Cer | EC-P-256 | ECDSA-SHA256 | OK | - | no root in bundle |
| `b78c7f63e24583c7` | S | AC Firmaprofesional - Secure Web 2025 | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `b7cdf23a73a2da1b` | S | ANF AC Qualified Certificates for eSignature | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `b87f2ca5ad30259f` | S | SUBCA SSL 2024 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `b8df384f1fcd6ecb` | S | SIGNE Autoridad de Certificacion - 2020 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `c3b28ba9153823bd` | S | EAD Trust RSA 4096 SubCA For Qualified Web EV/PSD2 C | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `c4472508c3bc689f` | SA | ANCERT Certificados Notariales Personales V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `c5c380eb9240fb36` | S | AC RAIZ DNIE 2 | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `c6dfaaace235da93` | S | ACA 1 | EC-P-521 | ECDSA-SHA512 | OK | - | no root in bundle |
| `c8792b47355fa3d1` | S | EADTrust ECC 384 SubCA For Qualified Web EV/PSD2 Cer | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `c97f2f6e6a8adb6e` | S | Entrust Certification Authority - ES QWAC2 | RSA-2048 | SHA256-RSA | OK | - | no root in bundle |
| `cc1b9f9e4370fb68` | S | FIRMAPROFESIONAL ICA A01 QWAC 2022 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `d11d9167b76ccf32` | S | Sectigo Qualified Legal Person CA E35 | EC-P-256 | ECDSA-SHA384 | OK | - | no root in bundle |
| `d26e702d039a5713` | S | ACCV ECC1 COMPONENTES | EC-P-521 | ECDSA-SHA512 | OK | ok | ok (2) |
| `d6ea13d3b7705717` | S | IvSign Global CA | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `d852490ed91838b0` | SA | CA HERRITARRAK ETA ENPRESA-CIUDADANIA Y EMPRESA 2025 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `da1326d22e64f7c2` | S | vinCAsign nebulaSUITE2 Authority | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `db476339ccbfcc9e` | S | CA de Certificados SSL EV | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `dc272648c1f47b25` | SA | Centro Tecnológico del Notariado CA-QC No Corporativ | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `dea1d4d5422ccec8` | S | ACA 2 | EC-P-521 | ECDSA-SHA512 | OK | - | no root in bundle |
| `e5f78053300c169d` | S | EADTrust ECC 256 SubCA For Qualified Certificates 20 | EC-P-256 | ECDSA-SHA256 | OK | - | no root in bundle |
| `e6dc96bb0dbcb242` | SA | SubCA CIUTADANIA Q (G3) A.2 | EC-P-384 | ECDSA-SHA384 | OK | ok | ok (2) |
| `e718f67c8b1f8e1f` | SA | ANCERT Certificados para empleados V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `e9485e076281b783` | SA | CERTIBOX CA Subordinada 01 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `ec751e45282021d1` | S | AC ENTIDADES G2 | EC-P-256 | ECDSA-SHA384 | OK | ok | ok (2) |
| `eedcf31633609acb` | S | ELECTRONIC IDENTIFICATION CA1 | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `eedd457af1353d76` | SA | AC CAMERFIRMA FOR NATURAL PERSONS - 2016 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `f038421f07f20d63` | S |  | RSA-2048 | SHA256-RSA | OK | ok | ok (2) |
| `f56a99f8a7b4dc80` | S | EAD Trust RSA 4096 SubCA For Qualified Web DV/OV Cer | RSA-4096 | SHA256-RSA | OK | - | no root in bundle |
| `f67a0c987d0d7d5e` | SA | Autoridad de Certificación de los Registradores - AC | RSA-4096 | SHA512-RSA | OK | ok | ok (2) |
| `f8ea34651355c407` | S | EADTrust ECC 384 SubCA For Qualified Certificates 20 | EC-P-384 | ECDSA-SHA384 | OK | - | no root in bundle |
| `fb7e801d60d04092` | SA | Autoridad de Certificación de los Registradores - AC | RSA-4096 | SHA512-RSA | OK | ok | ok (2) |
| `020786539f02b623` | A | AC RAIZ FNMT-RCM G2 | EC-P-384 | ECDSA-SHA384 | OK | self ok | root |
| `04f1bec36951bc14` | A | CHAMBERS OF COMMERCE ROOT - 2016 | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `15651384ca70c580` | A | CA CONSORCI AOC (G3) ROOT-A | EC-P-384 | ECDSA-SHA384 | OK | self ok | root |
| `186b5083f6cbe72e` | A | ANCERT Certificados Notariales de Sistemas V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `2530cc8e98321502` | A | Izenpe.com | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `2618a9ac8db25f36` | A | ANCERT Corporaciones de Derecho Publico Personales V | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `275650f55b05dfbb` | A | Centro Tecnológico del Notariado CA QTSA | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `2b5ec83cabfba08d` | A | ANCERT Corporativos de Sistemas V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `33e158568fab28e8` | A | ANCERT Corporaciones de Derecho Publico de Sistemas  | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `35803438853cadd4` | A | ANCERT Certificados para empleados V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `4be8b5a1c76c6aea` | A | ANCERT Certificados Notariales V2 | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `55a65b4d7dc3c7d5` | A | Autoridad de Certificación Raíz de los Registradores | RSA-4096 | SHA512-RSA | OK | self ok | root |
| `55f323c5c821b66c` | A | ANCERT Certificados FERN V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `5a769eb3d9d6a977` | A | ACCV ROOT RSA EIDAS 2023 | RSA-4096 | SHA512-RSA | OK | self ok | root |
| `5a81aba8d5fd0684` | A | INFOCERT-CAMERFIRMA CERTIFICATES 2024 | EC-P-384 | ECDSA-SHA384 | OK | self ok | root |
| `5c89a0a304cd090a` | A | ANCERT Corporaciones de Derecho Publico Personales V | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `6ed99b0972a5dab5` | A | Centro Tecnológico del Notariado RootCA-QC | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `6f5689223acd2d7f` | A | ANCERT Certificados Redes Privadas V2 | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `7adc638a1a81e83d` | A | ANCERT Corporaciones de Derecho Publico V2 | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `88497f01602f3154` | A | EC-ACC (AOC G2 root) | RSA-2048 | SHA1-RSA | **FAIL: x509: negative serial number** (parses with `GODEBUG=x509negativeserial=1`) | self: SHA1 rejected | root |
| `88c2bf64188e40b8` | A | ANCERT Certificados Notariales Corporativos V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `8ac2cfde0b8a6012` | A | ANCERT Corporativos Personales V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `8bd8e4bf355ac0c0` | A | ANCERT Corporativos de Sistemas V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `9a6ec012e1a7da9d` | A | ACCVRAIZ1 | RSA-4096 | SHA1-RSA | OK | SHA1 rejected | root |
| `a60480075ad74926` | A | ANCERT Corporaciones de Derecho Publico de Sistemas  | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `a6a176268ae84bac` | A | ANCERT Certificados Notariales Personales V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `adfc9410ee0d1091` | A | CAMERFIRMA ROOT 2021 | RSA-4096 | SHA384-RSA | OK | self ok | root |
| `ae9effcd7b830d9a` | A | ANCERT Corporativos Personales V2 | RSA-4096 | SHA256-RSA | OK | ok | ok (2) |
| `b89ee1f6e629a5ad` | A | ANCERT Certificados Notariales de Sistemas V2 | RSA-4096 | SHA256-RSA | OK | ok | EXPIRED |
| `c41559760d4e380a` | A | Autoridad de Certificación de los Registradores - AC | EC-P-521 | SHA512-RSA | OK | ok | ok (2) |
| `cb5bf9eb07685a01` | A | CERTIBOX ROOT CA | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `d2a934ae739b8b8b` | A | ROOT CA QC IZENPE 2025 | EC-P-384 | ECDSA-SHA384 | OK | self ok | root |
| `d54d506e45045460` | A | Firmafy CA ROOT | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `eb035ab415af48aa` | A | Autoridad de Certificación de los Registradores - AC | EC-P-521 | SHA512-RSA | OK | ok | ok (2) |
| `ebc5570c29018c4d` | A |  | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `f1aa0ec662705bb2` | A | ACCV ROOT ECC EIDAS 2023 | EC-P-521 | ECDSA-SHA512 | OK | self ok | root |
| `f4336bc2ac75950b` | A | ANCERT Certificados CGN V2 | RSA-4096 | SHA256-RSA | OK | self ok | root |
| `49cdee9289b910e8` | T | NOM UN O ESPECIMEN UÑO (Firma) | RSA-4096 | SHA256-RSA | OK | ok | ok (3) |
| `d5ed3b30878a9fee` | T | 99949992L NOMDOS ESPECIMENDOS (R:A00000000) (Firma) | RSA-4096 | SHA256-RSA | OK | ok | ok (3) |
