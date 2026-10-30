# Appendix A research: FNMT-RCM, DNIe and ACCV profile data for the cert-check PoC

Research date: 2026-10-30 (live checks run 22:30–22:40 UTC). Scope: spec Appendix A (lines 557–815) plus §6.1, §7, §8 and §9 (lines 139–354), and `docs/Vocdoni_CSP_Authentication_Only_Agent_Note.md`, which takes precedence on transport and launch scope.

Paths are relative to `/home/p4u/certificate_poc/` unless they are absolute. `BUNDLE` = `docs/Vocdoni_CSP_Handoff`. `DL` = `/home/p4u/.cache/cert-check/research/ca-downloads`.

Method:
- Every CA certificate cited here was decoded with OpenSSL 3.5.5. The DER SHA-256 is `openssl x509 -outform der | sha256sum`. The SPKI SHA-256 is the DER `pkey -pubin` hash. Chains were checked with `openssl verify -CAfile <issuer>`.
- Service status comes from `BUNDLE/spanish_tsl_inventory_2026-10-30.json` (TSL seq 189) and was cross-checked against `BUNDLE/evidence/ES_TSL.xml`.
- Live checks:
  - OCSP status of every in-scope CA certificate.
  - A random-serial probe (`0x0123456789ABCDEF0123456789ABCDEF01`) against each leaf responder, to observe responder identity, freshness and nonce behaviour.
  - CRL headers fetched to stdout. No CRLs were stored.
- Official PDFs were fetched with firecrawl into `/home/p4u/.cache/cert-check/research/*.md`. See "Fetched artifacts" below.
- Go parse results for the bundle CA certificates were read from another agent's run (`/home/p4u/.cache/cert-check/research/goparse/result.tsv`, go1.27.3). I did not write any code.

## Summary

| profile_id | recommendation (PoC) | confidence |
|---|---|---|
| fnmt-citizen-rsa | **include** | high (CA/OID/KU/EKU/endpoints); medium (bare vs `IDCES-` timeline) |
| fnmt-citizen-g2 | **include** | high (CA/OID/KU/EKU/endpoints); medium (identifier format: `IDCES-` only) |
| accv-citizen-software-current (RSA1 + ECC1) | **include** | high (CA/OID/KU/EKU/endpoints); medium (exact ECC leaf curve unknown) |
| fnmt-representative-rsa / -g2 | exclude (deferred by product note §3) | high (OIDs); medium (rest) |
| fnmt-employee-rsa / -g2 | exclude (deferred by product note §3) | medium |
| fnmt-consular-g2, fnmt-pseudonym-* | exclude (namespace is not DNI/NIE) | high |
| dnie-auth | exclude (deferred: card, reader and middleware) | medium; low on exact leaf OID suffix |
| accv-citizen-software-legacy-7 / -6 | exclude | medium; low on the v7 leaf OID |

New facts that are not in the spec or the note:
1. **The TSL no longer marks ACCVCA-120 as an e-signature service.** Its current instance (granted, since 2026-01-22T02:00Z) carries only `ForWebSiteAuthentication`. The 2018-01-16 instance had `ForeSignatures`, `ForeSeals` and `ForWebSiteAuthentication` (ES_TSL.xml lines ~9058–9135). The anchor also expires on 2026-12-31. This decides the legacy ACCV rows: exclude.
2. **FNMT G2 leaves are ECDSA P-256** (profile v2.6 §5). AC USUARIOS G2 is P-256, signed ecdsa-with-SHA384 by a P-384 root.
3. **Every leaf responder (FNMT RSA/G2, DNIe, ACCV) answers a never-issued serial with `revoked`**, reason certificateHold, revocationTime 1970-01-01 (RFC 6960 §2.2). The DNIe CPS v3.4 §7.3.7 text says "good" for anything not on the CRL; the live behaviour differs.
4. **ACCV OCSP is CRL-backed.**
   - Leaf responses: `thisUpdate` = latest CRL `lastUpdate` (~1 h old); `nextUpdate` = CRL `nextUpdate` (+3 days).
   - CA-level responses: pre-signed, with `thisUpdate` 2026-06-17 and `nextUpdate` 2026-12-14.
5. **DNIe is the only family with a date of birth:** SubjectDirectoryAttributes `dateOfBirth` (CPS v3.4 §7.1.2). FNMT and ACCV citizen profiles have no SDA.
6. **The DNIe intermediates AC DNIE 004/005/006 are not in the bundle.** I downloaded them from the official AIA URLs and verified them against the TSL root. See "Fetched artifacts".
7. **Official FNMT profile PDF v2.6 prints the G2 OCSP URL as `/ocspusug2/`, which returns HTTP 404.** The working path is `/ocspusuG2/`. Always use the leaf's signed AIA verbatim.
8. **The legacy ACCV CP v7.0.4 profile table lists policy `1.3.6.1.4.1.8149.3.7.0`**, while its header OID is `.3.7.7.0`. This is a likely typo, but it is unverified without a leaf.
9. **The ACCV RSA1 CLIENTE CRL is 13.6 MB.** The ECC1 CRL is 462 B.

---

## FNMT-RCM

### fnmt-citizen-rsa

```yaml
profile_id: fnmt-citizen-rsa
provider: FNMT-RCM
display_name_es: "FNMT – Certificado de Persona Física (AC FNMT Usuarios)"
holder_role: natural_person
recommendation: include   # mandatory initial family (note §2); software cert in the OS/browser store; clientAuth EKU documented
confidence: high          # CA bytes, TSL binding, OID, KU/EKU, endpoints verified; identifier-format timeline medium
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869.pem
    subject: "CN=AC FNMT Usuarios,OU=Ceres,O=FNMT-RCM,C=ES"
    issuer: "OU=AC RAIZ FNMT-RCM,O=FNMT-RCM,C=ES"
    serial: "455F3AE15C21CDBA544F82AA4751EBDB"
    sha256_der: "601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869"
    spki_sha256: "0b21720b91f0e45c43f2e7cb185f552eb7de7ed46b2ac172ee39b50841710a6f"
    not_after: "2029-10-28T11:48:58Z"   # notBefore 2014-10-28
    key: RSA-2048 (cert signed sha256WithRSA)
    ca_constraints: "BC CA:TRUE pathlen:0 critical; KU keyCertSign,cRLSign critical; no EKU; anyPolicy"
    tsl_service_status: "granted since 2016-06-30T22:00Z; CA/QC; ForeSignatures; no Qualifications ext (TSL provider idx 4, service idx 6)"
intermediates_needed: []   # anchor issues leaves directly
roots_above_anchor:
  - file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa.pem
    subject: "OU=AC RAIZ FNMT-RCM,O=FNMT-RCM,C=ES"
    sha256_der: "ebc5570c29018c4d67b1aa127baf12f703b4611ebc17b7dab5573894179b93fa"
    spki_sha256: "2fc5667a4b9a2678ed6ac6ad25465fcbf6094bfcd9504097c7a8fa47ade5e888"
    not_after: "2030-01-01T00:00:00Z"
    key: RSA-4096
    note: "not a TSL service identity; openssl verify anchor->root OK"
leaf_policy_oids: ["1.3.6.1.4.1.5734.3.10.1"]   # profile v2.6 (approved 2025-11-11) §3; leaf also has QCP-n 0.4.0.194112.1.0
key_usage_expected: [digitalSignature, contentCommitment, keyEncipherment]   # critical; require digitalSignature
eku_expected: ["1.3.6.1.5.5.7.3.2 clientAuth (require)", "1.3.6.1.4.1.311.10.3.12", "1.2.840.113583.1.1.5"]   # non-critical
leaf_key_algorithms: [RSA-2048]   # leaf signature sha256WithRSAEncryption; validity "variable, until 2028-12-31 at most"
other_leaf_extensions: "QCStatements (QcCompliance, QcType esign, QcPDS, retention 15y); BC CA:FALSE critical; SAN rfc822Name optional"
identity:
  personal_id:
    location: "subject 2.5.4.5 (PrintableString per profile)"
    formats: ["IDCES-<DNI|NIE> (v2.6 example IDCES-00000000T)", "bare <DNI|NIE> (v2.2 legacy, same OID)"]
    anchored_grammar: '^(?:IDCES-)?([0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]|[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE])$  + mod-23 check; whole value, no trimming beyond spec rules'
  given_names: {location: "subject 2.5.4.42 (UTF8String, <=50)"}
  surnames: {location: "subject 2.5.4.4", quirks: "both surnames in one field (e.g. 'ESPAÑOL ESPAÑOL'); split only via SAN .1.2/.1.3"}
  cross_checks:
    - "SAN directoryName 1.3.6.1.4.1.5734.1.4 = NIF, bare 9 chars (even when the Subject is IDCES-); must equal normalized 2.5.4.5"
    - "SAN 1.3.6.1.4.1.5734.1.1 (given name) must equal 2.5.4.42"
    - "SAN .1.2 (surname1, required) [+ ' ' + .1.3 surname2, optional] must equal 2.5.4.4 after whitespace normalization"
    - "CN ('Español Español Juan - 00000000T') is display only; do not parse"
  birth_date: {present: no, location: "n/a", evidence: "profile v2.6 §3 lists no SubjectDirectoryAttributes"}
revocation:
  ocsp: ["http://ocspusu.cert.fnmt.es/ocspusu/OcspResponder"]
  responder_notes: >-
    Live 2026-10-30: delegated responder "CN=Servidor OCSP AC FNMT Usuarios,OU=Ceres,O=FNMT-RCM,C=ES",
    issued by AC FNMT Usuarios (OCSPSigning, id-pkix-ocsp-nocheck, notAfter 2027-01-18); byName ResponderID;
    chain embedded; thisUpdate=now, nextUpdate=+8h; nonce echoed; SHA-1 CertID; signature verified.
    Non-issued serial -> revoked/certificateHold/1970-01-01. CPS v7.2: free service, unsigned requests and GET allowed.
  crl: ["http://www.cert.fnmt.es/crlsacusu/CRLU<n>.crl (partitioned; the leaf CDP also has an ldap:// URI first)"]
  notes: "CRLU1 live: 62,817 B, 24h validity, CRITICAL IssuingDistributionPoint naming that partition. Check the IDP matches the CDP used."
  intermediate_status: >-
    Anchor AC FNMT Usuarios: OCSP http://ocspfnmtrcmca.cert.fnmt.es/ocspfnmtrcmca/OcspResponder
    (responder "SERVIDOR OCSP AC RAIZ FNMT-RCM", 8h window, live = good) or ARL
    http://www.cert.fnmt.es/crls/ARLFNMTRCM.crl (2026-09-21 -> 2027-03-21, critical IDP).
test_certificate_traps: "Profile examples: IDCES-00000000T / 00000000T, SAN 99999999R, 'JUAN ESPAÑOL ESPAÑOL', jespanol@meh.es (both IDs pass mod-23). No FNMT production-CA test series found."
public_fixtures: "None in the bundle; no official public leaf found. A consented real certificate is needed (RSA, one bare and one IDCES-)."
gaps:
  - "Date when Subject serialNumber moved from bare to IDCES-; CN separator character in real certs"
  - "Prefix used for NIE holders (assumed IDCES-<NIE>; unverified)"
  - "Leaf CDP exact text/case for partitions; OCSP GET vs POST not tested"
  - "Windows: an RSA key stored under a legacy CAPI CSP may not sign RSA-PSS for TLS 1.3 (see engine implications)"
sources:
  - "spec lines 573-596 (§A.1), 642-678 (§A.5); note lines 31-34, 40-42"
  - https://www.sede.fnmt.gob.es/documents/10445900/10575386/perfiles_certificados_ac_usuarios.pdf (v2.6, §§2-3)
  - https://www.sede.fnmt.gob.es/documents/10445900/10536309/dgpc.pdf (CPS v7.2, via spec)
```

### fnmt-citizen-g2

```yaml
profile_id: fnmt-citizen-g2
provider: FNMT-RCM
display_name_es: "FNMT – Certificado de Persona Física (AC USUARIOS G2, ECC)"
holder_role: natural_person
recommendation: include   # mandatory initial family (note §2)
confidence: high          # identifier format restricted to IDCES- is medium (only form documented for G2)
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89.pem
    subject: "CN=AC USUARIOS G2,organizationIdentifier=VATES-Q2826004J,O=FNMT-RCM,C=ES"
    issuer: "CN=AC RAIZ FNMT-RCM G2,organizationIdentifier=VATES-Q2826004J,O=FNMT-RCM,C=ES"
    serial: "5DD5D6A543498EFE35685E8253C703E9A6DE89A9"
    sha256_der: "283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89"
    spki_sha256: "4a7bdf68ccebcdbfccfcdbe75ccb2d744e28be51a401fa34da558489696c807f"
    not_after: "2039-12-13T10:54:49Z"   # notBefore 2024-12-16
    key: EC P-256 (cert signed ecdsa-with-SHA384 by the P-384 root)
    ca_constraints: "BC CA:TRUE pathlen:0 critical; KU keyCertSign,cRLSign critical; EKU clientAuth, 1.3.6.1.4.1.311.10.3.12, 1.2.840.113583.1.1.5 (technically constrained); anyPolicy"
    tsl_service_status: "granted since 2025-07-17T02:00Z; CA/QC; ForeSignatures (provider 4, service 16)"
intermediates_needed: []
roots_above_anchor:
  - file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/020786539f02b623cfdf325b2e4e45e0d9e3f1b8e5ec9600ebf0ac8fbf03fbe2.pem
    subject: "CN=AC RAIZ FNMT-RCM G2,organizationIdentifier=VATES-Q2826004J,O=FNMT-RCM,C=ES"
    sha256_der: "020786539f02b623cfdf325b2e4e45e0d9e3f1b8e5ec9600ebf0ac8fbf03fbe2"
    spki_sha256: "8c2949cb2607318109f98b08bd7bf3331643f1782f33e605414f6d8f4c655f8d"
    not_after: "2049-10-04T09:13:51Z"
    key: EC P-384
leaf_policy_oids: ["1.3.6.1.4.1.5734.3.20.1.0"]   # profile v2.6 §5; leaf also has QCP-n 0.4.0.194112.1.0
key_usage_expected: [digitalSignature, contentCommitment]   # critical; no keyEncipherment
eku_expected: ["1.3.6.1.5.5.7.3.2 clientAuth (require)", "1.3.6.1.4.1.311.10.3.12", "1.2.840.113583.1.1.5"]
leaf_key_algorithms: [ECDSA P-256]   # leaf signature ecdsa-with-SHA256; validity 4 years
identity:
  personal_id:
    location: "subject 2.5.4.5 (PrintableString observed in the G2 kit; the G2 profile text says UTF8String; accept both)"
    formats: ["IDCES-<DNI|NIE>"]
    anchored_grammar: '^IDCES-([0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]|[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE])$  + mod-23 check'
  given_names: {location: "subject 2.5.4.42 (profile notes 'NIF/Pasaporte' as the source document)"}
  surnames: {location: "subject 2.5.4.4", quirks: "both surnames; the G2 table leaves 'Oblig' blank for SN, so reject when absent until a fixture shows otherwise"}
  cross_checks:
    - "SAN directoryName 1.3.6.1.4.1.5734.1.4 = bare 9-char NIF (example 00000000T); must equal the id after stripping IDCES-"
    - "SAN .1.1 given name; .1.2 surname1 (required); .1.3 surname2 (optional); same rules as RSA"
    - "CN example 'ESPAÑOL ESPAÑOL JUAN - DNI 00000000T': display only"
  birth_date: {present: no, location: "n/a", evidence: "profile v2.6 §5 has no SubjectDirectoryAttributes"}
revocation:
  ocsp: ["http://ocspusug2.cert.fnmt.es/ocspusuG2/OcspResponder"]   # case-sensitive; /ocspusug2/ (as printed in the PDF) = HTTP 404
  responder_notes: >-
    Live: responder "CN=SERVIDOR OCSP AC USUARIOS G2,O=FNMT-RCM,C=ES", issued by AC USUARIOS G2,
    OCSPSigning + nocheck, notAfter 2026-11-25 (rotation within 4 weeks; never pin it); ResponderID byKey
    (C7C52D5B9DBC9957FB65E584255AC8936E80A905); 8h window; nonce echoed; SHA-1 CertID; verified.
    Non-issued serial -> revoked/certificateHold/1970-01-01. Profile: requests need not be signed.
  crl: ["http://www.cert.fnmt.es/crlacusuG2/CRL<n>.crl (partitioned)"]
  notes: "CRL2 live: 1,792 B, 31 entries, 24h window. CRL0/CRL1/CRL10 return 404, so partition numbers are sparse. Use only the leaf CDP."
  intermediate_status: >-
    OCSP http://ocspcaraizg2.cert.fnmt.es/ocspcaraizG2/OcspResponder (responder "SERVIDOR OCSP AC RAIZ FNMT-RCM G2",
    8h window, live = good) or ARL http://www.cert.fnmt.es/crls/ARLFNMTRCMG2.crl (2026-05-25 -> 2026-11-21: refresh before then).
test_certificate_traps: "Same example values as RSA (IDCES-00000000T, 00000000T, 'JUAN ESPAÑOL ESPAÑOL')."
public_fixtures: "None. Need a consented G2 software cert (the FNMT 'obtener-certificado-software-ecc' flow)."
gaps:
  - "Whether any G2 leaf predates the 2025-07-17 service grant (if qualified-at-issuance semantics matter)"
  - "Browser/OS acceptance of P-256 software keys (expected fine) to be tested on the declared matrix"
sources:
  - "spec lines 579-592, 670-676; note line 34"
  - https://www.sede.fnmt.gob.es/documents/10445900/10575386/perfiles_certificados_ac_usuarios.pdf (v2.6 §§4-5)
```

### fnmt-representative-rsa / fnmt-representative-g2

```yaml
profile_id: fnmt-representative-rsa   # and fnmt-representative-g2 (differences inline)
provider: FNMT-RCM
display_name_es: "FNMT – Certificado de Representante (administrador único/solidario, persona jurídica, entidad sin personalidad jurídica)"
holder_role: representative
recommendation: exclude   # product note §3 defers representative profiles; also needs an election role policy
confidence: medium        # OIDs/KU/EKU from official v10.0 PDF; CA bytes verified; no leaf seen
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b.pem
    subject: "CN=AC Representación,OU=CERES,O=FNMT-RCM,C=ES"
    sha256_der: "8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b"
    spki_sha256: "da576c79f49f91353b1865dfcf889888f9ce50391b2a261d51a3c677676ef044"
    not_after: "2029-12-31T10:51:53Z"
    key: RSA-2048
    tsl_service_status: "granted since 2023-02-06; CA/QC; ForeSignatures + ForeSeals (service 7)"
  - file: docs/Vocdoni_CSP_Handoff/service-identities/0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64.pem   # G2
    subject: "CN=AC REPRESENTACIÓN G2,organizationIdentifier=VATES-Q2826004J,O=FNMT-RCM,C=ES"
    sha256_der: "0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64"
    spki_sha256: "66f3f2da778bf26070b42bc7accd97d9f188d25a15f1e2575603042618c13502"
    not_after: "2039-12-13T11:01:30Z"
    key: EC P-256 (EKU clientAuth, docSigning, Adobe in the CA)
    tsl_service_status: "granted since 2025-07-17; CA/QC; ForeSignatures (service 17)"
intermediates_needed: []
roots_above_anchor: ["RSA: ebc5570c… (as fnmt-citizen-rsa)", "G2: 020786539f… (as fnmt-citizen-g2)"]
leaf_policy_oids:   # v10.0 §§3,5; leaves also carry QCP-n and a national OID
  administrador_unico_solidario: {rsa: "1.3.6.1.4.1.5734.3.11.1", g2: "1.3.6.1.4.1.5734.3.21.1.0", national: "2.16.724.1.3.5.8"}
  persona_juridica:              {rsa: "1.3.6.1.4.1.5734.3.11.2", g2: "1.3.6.1.4.1.5734.3.21.2.0", national: "2.16.724.1.3.5.8"}
  entidad_sin_personalidad:      {rsa: "1.3.6.1.4.1.5734.3.11.3", g2: "1.3.6.1.4.1.5734.3.21.3.0", national: "2.16.724.1.3.5.9"}
key_usage_expected: {rsa: [digitalSignature, contentCommitment, keyEncipherment], g2: [digitalSignature, contentCommitment]}
eku_expected: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.10.3.12", "1.2.840.113583.1.1.5"]
leaf_key_algorithms: {rsa: [RSA-2048], g2: [ECDSA P-256]}   # validity 2 years
identity:
  personal_id: {location: "subject 2.5.4.5 (human representative)", formats: ["IDCES-<DNI|NIE>"], anchored_grammar: "same as fnmt-citizen-g2"}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 (both)"}
  cross_checks:
    - "SAN dirName 1.3.6.1.4.1.5734.1.4 = IDCES-prefixed human NIF here (differs from citizen bare form)"
    - "SAN .1.1/.1.2/.1.3 names; .1.6 entity name, .1.7 entity NIF (VATES-...), .1.20 role, .1.22 ESPJ type"
    - "subject 2.5.4.97 organizationIdentifier = ENTITY (VATES-...); never match it against a person census"
    - "CN '<NIF> <Nombre> <Apellido1> (R: <entity NIF>)': display only"
  birth_date: {present: no, location: "n/a", evidence: "v10.0 profile has no SDA"}
revocation:
  ocsp: ["http://ocsprep.cert.fnmt.es/ocsprep/OcspResponder", "G2: http://ocsprepg2.cert.fnmt.es/ocsprepG2/OcspResponder (spec F6; the PDF text is garbled)"]
  responder_notes: "Not probed; expect the same FNMT pattern (delegated per-CA responder, 8h window)."
  crl: ["http://www.cert.fnmt.es/crlsrep/CRL<nnn>.crl", "G2: http://www.cert.fnmt.es/crlsrepG2/CRL<n>.crl"]
  notes: "Partitioned; use the leaf CDP only."
  intermediate_status: "RSA: ocspfnmtrcmca / ARLFNMTRCM.crl; G2: ocspcaraizG2 / ARLFNMTRCMG2.crl"
test_certificate_traps: "Examples: O='Entidad de pruebas', VATES-Q0000000J, IDCES-0000000T (malformed 7-digit example), SAN IDCES-99999999R"
public_fixtures: "None."
gaps: ["Election role policy; G2 OCSP URL case unverified; no leaf"]
sources: ["spec lines 598-610", "https://www.sede.fnmt.gob.es/documents/10445900/10575386/perfiles_certificados_ac_representacion.pdf (v10.0)"]
```

### fnmt-employee-rsa / fnmt-employee-g2

```yaml
profile_id: fnmt-employee-rsa   # and fnmt-employee-g2
provider: FNMT-RCM
display_name_es: "FNMT – Certificado de Empleado Público"
holder_role: public_employee
recommendation: exclude   # product note §3 defers employee profiles
confidence: medium        # RSA rows read from official v1.15 PDF (first 70 pages); G2 rows from spec/TSL only
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498.pem
    subject: "CN=AC Sector Público,organizationIdentifier=VATES-Q2826004J,OU=Ceres,O=FNMT-RCM,C=ES"
    sha256_der: "8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498"
    spki_sha256: "68de305107cbd1889d7a9b039fdca503c1a88ad1f45d1752df8f50c72969d915"
    not_after: "2029-11-28T08:48:09Z"
    key: RSA-4096
    tsl_service_status: "granted since 2024-08-22; CA/QC; ForeSignatures + ForeSeals; QCQSCDManagedOnBehalf for 17.5/17.6/17.8 (service 12)"
  - file: docs/Vocdoni_CSP_Handoff/service-identities/983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe.pem   # G2
    subject: "CN=AC SECTOR PÚBLICO G2,organizationIdentifier=VATES-Q2826004J,O=FNMT-RCM,C=ES"
    sha256_der: "983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe"
    spki_sha256: "a1e3f004222a51998b97853b50fdbfbe9b3f932c3bd0b85737663bd19b33a906"
    not_after: "2039-12-13T10:58:12Z"
    key: EC P-256
    tsl_service_status: "granted since 2025-07-17; CA/QC; ForeSignatures; QCQSCDManagedOnBehalf for 23.1.1/23.3.1/23.4.1 (service 19)"
intermediates_needed: []
roots_above_anchor: ["RSA root ebc5570c…", "G2 root 020786539f…"]
leaf_policy_oids:   # only the named-human lanes; plus QCP-n and national 2.16.724.1.3.5.7.2 (medium) / .7.1 (high)
  employee_software:      {rsa: "1.3.6.1.4.1.5734.3.17.2", g2: "1.3.6.1.4.1.5734.3.23.1.0"}
  employee_qscd_medium:   {rsa: "1.3.6.1.4.1.5734.3.17.7", g2: "1.3.6.1.4.1.5734.3.23.1.2"}
  employee_qscd_high_auth: {rsa: "1.3.6.1.4.1.5734.3.17.9", g2: "1.3.6.1.4.1.5734.3.23.1.4 (reconstructed from wrapped PDF cell; low)"}
key_usage_expected: {"17.2 rsa": [digitalSignature, contentCommitment, keyEncipherment]}
eku_expected: ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.10.3.12", "1.2.840.113583.1.1.5", "1.3.6.1.4.1.311.20.2.2 (smart-card logon)"]
leaf_key_algorithms: {rsa: [RSA-2048], g2: ["unknown; probably ECDSA P-256 (not read)"]}
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI|NIE> (UTF8String <=15)"], anchored_grammar: "as fnmt-citizen-g2"}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 (both)"}
  cross_checks:
    - "SAN dirName medium: 2.16.724.1.3.5.7.2.4 = employee NIF (bare); .2.6 given; .2.7/.2.8 surnames; .2.3 = ENTITY NIF (do not confuse)"
    - "high-level branches use the 2.16.724.1.3.5.7.1.* arc instead"
    - "O = employing administration; OU='CERTIFICADO ELECTRONICO DE EMPLEADO PUBLICO'; QC semanticsId-Natural 0.4.0.194121.1.1"
  birth_date: {present: no, location: "n/a", evidence: "v1.15 §3.1 has no SDA"}
revocation:
  ocsp: ["http://ocspsp.cert.fnmt.es/ocspsp/OcspResponder", "G2: http://ocspspg2.cert.fnmt.es/ocspspG2/OcspResponder (spec F6)"]
  responder_notes: "Not probed."
  crl: ["leaf CDP (partitioned; pattern not verified)"]
  notes: ""
  intermediate_status: "as the other FNMT RSA/G2 CAs (ocspfnmtrcmca / ocspcaraizG2; ARLs)"
test_certificate_traps: "Example 2.16.724.1.3.5.7.2.4=99999999R, IDCES-0000000G, 'MINISTERIO DE ECONOMÍA Y HACIENDA'"
public_fixtures: "None."
gaps: ["G2 §5 pages not read (beyond the 70-page fetch); QSCD/card lanes are hardware-dependent"]
sources: ["spec lines 612-632", "https://www.sede.fnmt.gob.es/documents/10445900/10575386/perfiles_certificados_sector_publico.pdf (v1.15)"]
```

### fnmt-consular-g2 and fnmt-pseudonym / judicial lanes (documented exclusions)

```yaml
profile_id: fnmt-consular-g2
provider: FNMT-RCM
display_name_es: "FNMT – Certificado AC Consulares (NICC)"
holder_role: natural_person
recommendation: exclude   # Subject id is a consular NICC 'EX:ES-...', not a DNI/NIE; no verified mapping (spec §9.3, A.4)
confidence: high
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/5de90851a1a2235c515b8636c6a685990317cd4f30ef4a573e08ec07aaf1824c.pem
    subject: "CN=AC CONSULARES G2,organizationIdentifier=VATES-Q2826004J,O=FNMT-RCM,C=ES"
    sha256_der: "5de90851a1a2235c515b8636c6a685990317cd4f30ef4a573e08ec07aaf1824c"
    spki_sha256: "65b410ac672e2c7c9b09e0374a541ca4eeedb0c0578947c35961895803842f5d"
    not_after: "2039-10-07T11:06:36Z"
    key: EC P-256
    tsl_service_status: "granted since 2025-05-21; CA/QC; ForeSignatures (service 15)"
intermediates_needed: []
roots_above_anchor: ["G2 root 020786539f…"]
leaf_policy_oids: ["1.3.6.1.4.1.5734.3.26.1.0"]
identity: {personal_id: {location: "subject 2.5.4.5", formats: ["EX:ES-<NICC>"]}, cross_checks: ["SAN 1.3.6.1.4.1.5734.1.47 = NICC"]}
note: "Must be rejected even though the suffix looks like a DNI. Never strip 'EX:ES-'. Do not add this CA to the TLS acceptable-CA list."
---
profile_id: fnmt-pseudonym-and-judicial
recommendation: exclude   # pseudonym or JU:ES- identifiers; centralized (remote) signing lanes
leaf_policy_oids_to_reject: ["1.3.6.1.4.1.5734.3.17.3", "1.3.6.1.4.1.5734.3.17.4", "1.3.6.1.4.1.5734.3.17.5", "1.3.6.1.4.1.5734.3.17.6", "1.3.6.1.4.1.5734.3.17.8", "1.3.6.1.4.1.5734.3.17.10", "1.3.6.1.4.1.5734.3.23.2.0", "1.3.6.1.4.1.5734.3.23.3.0", "1.3.6.1.4.1.5734.3.23.1.1", "1.3.6.1.4.1.5734.3.23.3.1", "1.3.6.1.4.1.5734.3.23.4.1", "1.3.6.1.4.1.5734.3.23.1.3"]
note: "The TSL Qualifications ext of services 12/19 independently confirms 17.5/17.6/17.8 and 23.1.1/23.3.1/23.4.1 (the spec called 23.3.1 reconstructed). These leaves chain to the same Sector Público CAs. Policy-OID matching, not the anchor, is what excludes them."
```

---

## DNIe

### dnie-auth

```yaml
profile_id: dnie-auth
provider: Dirección General de la Policía (DNIe)
display_name_es: "DNIe – Certificado de Autenticación"
holder_role: natural_person
recommendation: exclude   # deferred by product note §3 (card, reader, PIN, middleware); keep data for a later lane
confidence: medium        # CA chain and responders verified live; leaf OID suffix, string types, SDA encoding unverified (no fixture)
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11.pem
    subject: "CN=AC RAIZ DNIE 2,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES"
    serial: "2B1BBBCB61CF482452455D3D5EDBE2A3"
    sha256_der: "c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11"
    spki_sha256: "4a5dc6f078372f3497d01ba654c902357b54a1c53387f8b3cf3b92749cdeb44b"
    not_after: "2043-09-27T10:26:05Z"
    key: RSA-4096 (self-signed sha256WithRSA)
    tsl_service_status: >-
      granted since 2016-06-30T22:00Z; CA/QC; RootCA-QC + ForeSignatures; Qualifications: QCQSCDManagedOnBehalf for 2.16.724.1.2.2.2.11
      (provider 2, service 3). Separate Certstatus/OCSP/QC service 'OCSP Responses issued by AC RAIZ DNIE 2' (granted since 2021-04-21)
      has the same root as its digital identity.
    note: "Do not confuse this with provider-2 service 4, 'AC DGP 004' (sha256 6ad43c81…, police staff PKI under AC RAIZ DGP 2)."
intermediates_needed:   # NOT in the bundle: downloaded from official AIA URLs, verified with openssl verify -CAfile <root> = OK
  - file: /home/p4u/.cache/cert-check/research/ca-downloads/dnie/AC004.pem   # source http://pki.policia.es/dnie/certs/AC004.crt (PEM; raw file sha256 f368f0dc…ff33)
    subject: "CN=AC DNIE 004,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES"
    serial: "439A9628B2660FEE539AEB66FCF15518"
    sha256_der: "ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c"
    spki_sha256: "1b5b9b72ed25bdab71a112d252c747f5961bfed9ad4bce77292af34b1146481f"
    not_after: "2029-06-13T12:15:34Z"
    key: RSA-4096; BC pathlen:0; CDP http://pki.policia.es/dnie/crls/ARL.crl; no AIA
  - file: /home/p4u/.cache/cert-check/research/ca-downloads/dnie/AC005.pem   # source http://pki.policia.es/dnie/certs/AC005.crt (raw sha256 4e6e2467…6b89)
    subject: "CN=AC DNIE 005,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES"
    serial: "68FC4E1957A3D005558144C143580BDD"
    sha256_der: "828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828"
    spki_sha256: "1f6b84c54a1824bdc0f639487dfaa29c7b2bc7fefe69499651eb2036fcf859a2"
    not_after: "2030-06-17T09:58:25Z"
    key: RSA-4096; CDP …/dnie/crls/CRL.crl and …/dnie/crls/ARL.crl
  - file: /home/p4u/.cache/cert-check/research/ca-downloads/dnie/AC006.pem   # source http://pki.policia.es/dnie/certs/AC006.crt (raw sha256 bf910f9e…f4a2)
    subject: "CN=AC DNIE 006,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES"
    serial: "267DEAB7265C1BC055B779E14109F042"
    sha256_der: "eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd"
    spki_sha256: "60a9a73a0c25f1e14b44508554076c2c48ad32c503c9bc534c945a82a290cb97"
    not_after: "2030-07-28T12:47:29Z"
    key: RSA-4096
roots_above_anchor: []   # the anchor is the root; AC DNIE 001-003 (Raíz 1) expired in 2021
leaf_policy_oids: ["2.16.724.1.2.2.2.4"]   # CPS v3.4 §7.1.6/7.1.9; the CPS says a '.X.Y' version suffix "se añadirá": confirm the exact OID on a real leaf (low)
key_usage_expected: [digitalSignature]   # critical; contentCommitment=0. The signing cert (…2.2.2.3) has contentCommitment only and is unusable for TLS
eku_expected: "absent (documented: 'extKeyUsage: No se utilizará'); accept only in this lane"
leaf_key_algorithms: [RSA-2048, "RSA-1920 (ROCA-affected DNIe 2.0/3.0 re-issues, 24 months, non-renewable, from ~2017; probably all expired; reject)"]
other_leaf_extensions: "biometricInfo 1.3.6.1.5.5.7.1.2 (non-critical), personalDataInfo 2.16.724.1.2.2.4.1 (criticality not stated), SAN rfc822 optional, no CDP, no QCStatements on the auth cert"
identity:
  personal_id: {location: "subject 2.5.4.5 (PrintableString per BOE 2006 policy)", formats: ["bare DNI"], anchored_grammar: '^([0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE])$ + mod-23 (no NIE: DNIe is for Spanish nationals)'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 = FIRST surname only", quirks: "full surnames only in CN 'APELLIDO1 APELLIDO2, NOMBRE (AUTENTICACIÓN)'"}
  cn_grammar: "CN must equal exactly SN + [' ' + rest] + ', ' + G + ' (AUTENTICACIÓN)'; surname2 = rest; compare with the known SN/G, never split on spaces"
  cross_checks: ["CN vs G/SN as above", "no SAN identity fields (SAN = e-mail)"]
  birth_date: {present: "yes (documented)", location: "SubjectDirectoryAttributes 2.5.29.9, attribute dateOfBirth 1.3.6.1.5.5.7.9.1 (GeneralizedTime per RFC 3739)", evidence: "CPS v3.4 §7.1.2 auth table row 10; presence on older-issued certs unverified"}
revocation:
  ocsp: ["http://ocsp.dnie.es"]
  responder_notes: >-
    Live: leaf-level responses are signed by per-issuer delegated responders "CN=OCSP Responder DNIE 00X,OU=FNMT,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES",
    issued by AC DNIE 00X (OCSPSigning, nocheck, policy 2.16.724.1.2.2.2.5, 2048-bit, valid 2026-09-14 -> 2027-03-14; 6-month rotation).
    Nonce echoed; SHA-1 CertID; non-issued serial -> revoked/certificateHold/1970 with nextUpdate +1h.
    CPS §7.3.7: 'good' responses OMIT nextUpdate, so a local max age is required. Not observable without a real leaf.
    Official responder bundle: https://www.dnielectronico.es/descargas/certificados/Certificados_OCSP_Responder_FNMT.zip (zip sha256 3cdad19b…2e08).
  crl: []
  notes: "The leaf has no CDP; leaf CRLs are not public. OCSP outage = blocking (no CRL fallback)."
  intermediate_status: >-
    ocsp.dnie.es with responder "CN=AV DNIE FNMT" issued by AC RAIZ DNIE 2 (live: AC DNIE 004 good, nextUpdate +1h, nonce echoed) or
    root CRLs http://pki.policia.es/dnie/crls/ARL.crl and …/CRL.crl (both 302 -> /dnie/arls/…; issuer AC RAIZ DNIE 2; 2026-09-23 -> 2027-03-23; 1 and 0 entries).
test_certificate_traps: "CPS v3.4 (test certs): DNI 00000000T; NIE X0000000T, Y0000000R, Z0000000W (the last two fail mod-23); names 'Nombre'/'Apellido1'/'Apellido2'."
public_fixtures: "None public. Test DNIe cards exist only through DGP channels."
gaps:
  - "Exact leaf policy OID (versioned suffix?) and attribute string types"
  - "Whether personalDataInfo is marked critical (Go would flag an unhandled critical extension)"
  - "Live 'good' response without nextUpdate; rate limits for companies"
  - "Smart-card RSA-PSS support for TLS 1.3 CertificateVerify (middleware-dependent)"
sources:
  - "spec lines 680-729, 145, 212, 250; note lines 56, 66"
  - https://www.dnielectronico.es/PDFs/Politicas_de_certificacion_v3.4.pdf (§§2.1, 6.1.5, 7.1-7.3, NOTA INFORMATIVA)
  - https://www.dnielectronico.es/PortalDNIe/PRF1_Cons02.action?pag=REF_078 ; …pag=REF_079
```

---

## ACCV / ISTEC

### accv-citizen-software-current

```yaml
profile_id: accv-citizen-software-current
provider: ACCV (ISTEC, Generalitat Valenciana)
display_name_es: "ACCV – Certificado cualificado de Ciudadano en soporte software"
holder_role: natural_person
recommendation: include   # mandatory initial family (note §2); RSA and ECC paths
confidence: high          # CA bytes, TSL, OID, KU/EKU, endpoints verified; exact ECC leaf curve unknown
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1.pem
    subject: "CN=ACCV RSA1 CLIENTE,organizationIdentifier=VATES-A40573396,O=ISTEC,L=BURJASSOT,ST=VALENCIA,C=ES"
    serial: "1036CED2D94D91D8ADDDD33711B89759008E3F38"
    sha256_der: "a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1"
    spki_sha256: "03cd20b076b5b589a78efa46a09e6d1cc8ba5878088113749d16f7414cd9c1f1"
    not_after: "2047-07-19T12:09:24Z"   # notBefore 2023-07-25
    key: RSA-4096 (signed sha512WithRSA)
    ca_constraints: "BC CA:TRUE (no pathlen); KU digitalSignature,keyCertSign,cRLSign; EKU clientAuth + 1.2.840.113583.1.1.5; CDP has cRLIssuer = root DN"
    tsl_service_status: "granted since 2023-12-21; CA/QC; ForeSignatures (provider 10, service 8)"
  - file: docs/Vocdoni_CSP_Handoff/service-identities/5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496.pem
    subject: "CN=ACCV ECC1 CLIENTE,organizationIdentifier=VATES-A40573396,O=ISTEC,L=BURJASSOT,ST=VALENCIA,C=ES"
    serial: "488B28611292F4986643D0D61FF9691A0B25C0EC"
    sha256_der: "5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496"
    spki_sha256: "73b39454c0f85a4f23e29e923073aa74f755934809e359f2ea87c9eebfa34b75"
    not_after: "2047-07-19T12:15:01Z"
    key: EC P-521 (signed ecdsa-with-SHA512)
    ca_constraints: "same as RSA1"
    tsl_service_status: "granted since 2023-12-21; CA/QC; ForeSignatures (service 11)"
intermediates_needed: []
roots_above_anchor:
  - {file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/5a769eb3d9d6a9770bdc1bf412632bd35dad69bdf24ee9cd75d2b659b4a0ddc9.pem, subject: "CN=ACCV ROOT RSA EIDAS 2023,…", spki_sha256: "bdbb1dfe68e36b8517142dba48b173da2989da54c9ab3796a645cd1c714b66a1", not_after: "2048-07-18T09:19:13Z", key: RSA-4096}
  - {file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/f1aa0ec662705bb297b437f67ea9e4650ec5bc5e956757aa7f04d7d9945471e3.pem, subject: "CN=ACCV ROOT ECC EIDAS 2023,…", spki_sha256: "94e5db89263dca86205dc00de7791be8da0756588f9d120ee4c85b8ab6ec833c", not_after: "2048-07-18T09:22:51Z", key: EC P-521}
leaf_policy_oids: ["1.3.6.1.4.1.8149.3.7.8.0"]   # CP-07 v8.0.4 (2026-02-04) §7.1.6; leaf also has QCP-n 0.4.0.194112.1.0
key_usage_expected: {rsa: [digitalSignature, nonRepudiation, keyEncipherment], ecc: [digitalSignature, nonRepudiation, keyAgreement]}   # critical
eku_expected: ["1.3.6.1.5.5.7.3.2 clientAuth (require)", "1.2.840.113583.1.1.5"]
leaf_key_algorithms: ["RSA >= 3072", "ECDSA >= P-256 (curve not fixed by CP)"]   # leaf sigs sha256WithRSA / ecdsa-with-SHA256; validity 3 years
other_leaf_extensions: "QCStatements (QcCompliance, QcType esign, retention 15y, QcPDS); Subject OU='CIUDADANOS', O='ACCV'"
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["bare 9-char NIF (DNI or NIE), left zero-padded"], anchored_grammar: '^([0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]|[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE])$ + mod-23; no ETSI prefix (do not require IDCES-); K/L/M personal NIFs -> separate namespace, reject for DNI census'}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 (both surnames)", quirks: "all Subject/SAN fields uppercase, accents omitted (Ñ handling unverified)"}
  cross_checks:
    - "SAN directoryName CN = 'NOMBRE|APELLIDO1|APELLIDO2': split on '|' into exactly 3 fields (surname2 may be empty: unverified); must match G and SN"
    - "SAN directoryName UID (0.9.2342.19200300.100.1.1) = NIF; must equal subject 2.5.4.5"
    - "CN 'NOMBRE APELLIDO1 APELLIDO2 - NIF:<NIF>': display only"
  birth_date: {present: no, location: "n/a", evidence: "CP-07 v8.0.4 §7.1.2 profile table has no SDA ('F. Nacimiento' only appears in the video-ID annex)"}
revocation:
  ocsp: ["http://ocsp.accv.es"]
  responder_notes: >-
    Live: delegated responders "CN=OCSP ACCV RSA1 CLIENTE,O=ISTEC,C=ES" / "CN=OCSP ACCV ECC1 CLIENTE,O=ISTEC,C=ES", issued by
    the respective CA (OCSPSigning, nocheck; notAfter 2027-07-17); verified. CRL-backed freshness: thisUpdate = CRL lastUpdate
    (~1h old), nextUpdate = CRL nextUpdate (+3 days). Nonce echoed; SHA-1 CertID. Non-issued serial -> revoked/certificateHold/1970.
  crl: ["http://www.accv.es/gestcert/accv_rsa1_cliente.crl", "http://www.accv.es/gestcert/accv_ecc1_cliente.crl"]
  notes: "Both answer HTTP 302 -> http://www.accv.es/fileadmin/Archivos/certificados/<same name>. Hourly issue, 3-day nextUpdate. RSA1 CRL = 13,657,584 B; ECC1 = 462 B."
  intermediate_status: >-
    ocsp.accv.es responders "OCSP ACCV ROOT RSA EIDAS 2023" / "…ECC…" (live good; pre-signed thisUpdate 2026-06-17, nextUpdate 2026-12-14)
    or root CRLs http://www.accv.es/gestcert/accv_root_{rsa,ecc}_eidas_2023.crl (302 as above; same window).
test_certificate_traps: "None documented in CP-07; no ACCV test series found."
public_fixtures: "None in the bundle; no official public leaf found. Need consented RSA and ECC fixtures."
gaps:
  - "ECC leaf curve(s) actually issued (P-256/P-384/P-521)"
  - "SAN surname2 empty-field encoding; Ñ in uppercase-no-accent fields"
  - "Whether leaves also carry the CDP cRLIssuer form seen in the CA certs"
sources:
  - "spec lines 731-768, 797-801; note lines 36, 44, 48"
  - https://www.accv.es/fileadmin/Archivos/Politicas_pdf/ACCV-CP-07V8.0.4-ES-2026.pdf (§§1.3.1, 6.1.5, 7.1)
  - https://www.accv.es/servicios/administracion-publica/descarga-de-certificados-jerarquia/
```

### accv-citizen-software-legacy-7 and accv-citizen-software-legacy-6

```yaml
profile_id: accv-citizen-software-legacy-7   # and accv-citizen-software-legacy-6 (identical except the OID)
provider: ACCV (ISTEC)
display_name_es: "ACCV – Certificado de Ciudadano en soporte software (ACCVCA-120, legado)"
holder_role: natural_person
recommendation: exclude
# 1) The current TSL instance (since 2026-01-22) is ForWebSiteAuthentication only, so it no longer binds e-signature/person certs.
# 2) The anchor expires 2026-12-31T23:59:00Z, 62 days after this research.
# 3) No fixture exists, and the v7 OID text is inconsistent. The note forbids letting this block release.
confidence: medium   # anchor/TSL verified; the legacy-7 leaf OID is low
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/2de620f2d1200aa90b16c3ccf670fd7ed14379ab06fa8b031cfef8da051ea5a2.pem
    subject: "CN=ACCVCA-120,OU=PKIACCV,O=ACCV,C=ES"
    serial: "41F69CD2BD80C0B7"   # SHA-256 re-signature (notBefore 2015-01-27); served by the leaf AIA ACCVCA120SHA2.cacert.crt; SHA-1 fp 48:72:A4:…:5D as quoted in the CP
    sha256_der: "2de620f2d1200aa90b16c3ccf670fd7ed14379ab06fa8b031cfef8da051ea5a2"
    spki_sha256: "5c7dd687916e1fd65e65c09d2d933455bb32420dda785575c2e8ef34460d450f"
    not_after: "2026-12-31T23:59:00Z"
    key: RSA-4096 (sha256WithRSA)
    tsl_service_status: >-
      granted (provider 10, service 5) but the current instance since 2026-01-22 carries ONLY ForWebSiteAuthentication.
      Qualifications: QCStatement+QCForESig only for 8149.3.7.5.0/3.6.6.0; NotQualified for 3.16.3.0/3.17.3.0/3.14.3.0/3.15.3.0.
      Previous instance (2018-01-16 -> 2026-01-22): ForeSignatures + ForeSeals + ForWebSiteAuthentication.
  - file: docs/Vocdoni_CSP_Handoff/service-identities/3bc51856040ad7ff6683aa85a0d34f9ea680cd23c37cb8a0423b0f89a24405b9.pem
    note: "Same key (spki 5c7dd687…), serial 6482C4AB654B00A6, 2011, signed SHA1withRSA. Go rejects it as a chain link. Pin by SPKI or use 2de620f2."
intermediates_needed: []
roots_above_anchor:
  - {file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/9a6ec012e1a7da9dbe34194d478ad7c0db1822fb071df12981496ed104384113.pem, subject: "CN=ACCVRAIZ1,OU=PKIACCV,O=ACCV,C=ES", spki_sha256: "05570ae6eb0fceb4210e6db79486b7094caf200401e149b6677441b5f25e449b", not_after: "2030-12-31T09:37:37Z", key: "RSA-4096, SHA-1 self-signature"}
leaf_policy_oids:
  legacy-7: ["1.3.6.1.4.1.8149.3.7.7.0"]   # CP-07 v7.0.4 header OID; its §7.1.2 table prints 1.3.6.1.4.1.8149.3.7.0 (low)
  legacy-6: ["1.3.6.1.4.1.8149.3.7.6.0"]   # CP-07 v6.0.7 header + table agree
key_usage_expected: [digitalSignature, nonRepudiation]   # critical; no keyEncipherment in legacy tables
eku_expected: ["1.3.6.1.5.5.7.3.2", "1.2.840.113583.1.1.5"]
leaf_key_algorithms: ["RSA >= 2048"]   # sha256WithRSA leaf sigs; 3-year validity
identity: "as accv-citizen-software-current (bare 9-char NIF; G/SN; SAN CN 'Nombre|Apellido1|Apellido2', UID=NIF); no SDA"
revocation:
  ocsp: ["http://ocsp.accv.es"]
  responder_notes: "Live: 'CN=Servidor OCSP ACCVCA120 DE ACCV-ISTEC,…' (responder notAfter 2026-12-31); CRL-backed 3-day window; nonce echoed."
  crl: ["http://www.accv.es/fileadmin/Archivos/certificados/accvca120_der.crl (3,108,666 B; 3-day window)"]
  intermediate_status: "ACCVCA-120 live good via 'Servidor OCSP ACCVRAIZ1' (thisUpdate 2026-06-12, nextUpdate 2026-12-09) or ARL …/raizaccv1_der.crl (5 entries, same window)"
test_certificate_traps: "none known"
public_fixtures: "none"
gaps: ["Real leaf OID for v7; whether any 3.7.6/3.7.7 leaf is still unexpired; legal effect of the 2026-01-22 TSL change"]
sources: ["spec lines 744-747, 797-799; note line 44", "https://www.accv.es/fileadmin/Archivos/Politicas_pdf/ACCV-CP-07V7.0.4-ES-2023.pdf", "https://www.accv.es/fileadmin/Archivos/Politicas_pdf/ACCV-CP-07V6.0.7-ES-2023.pdf", "BUNDLE/evidence/ES_TSL.xml ~9058-9330"]
```

Not profiled, out of scope for this PoC: ACCV citizen QSCD `1.3.6.1.4.1.8149.3.6.9.0` and legacy `.3.6.8.0`/`.3.6.7.0` (card products, deferred), and the ACCV PROFESIONALES families (spec lines 770–795).

---

## Generic engine implications

1. **Trust anchors are issuing CAs.** Pin the TSL service-identity CA (FNMT, ACCV), or the root plus the verified intermediates (DNIe), as Go `x509.VerifyOptions.Roots`.
   - Always set `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}`. Go's default is ServerAuth.
   - Go checks the anchor's own validity, so ACCVCA-120 fails automatically after 2026-12-31.
   - Pin by SPKI as well as DER where a CA was re-signed. ACCVCA-120 has two certificates with one key; the SHA-1 variant fails in Go.
2. **EKU nesting.** The FNMT G2 and ACCV CLIENTE CA certificates carry EKU lists (clientAuth, plus document signing on FNMT G2 and Adobe on both). Go enforces chain EKU nesting, which passes for clientAuth. Do not verify with any other EKU.
   - DNIe leaves and the DNIe and FNMT RSA CAs have no EKU. Go treats absent EKU as "any". The profile must allow absent EKU only in the DNIe lane, per spec §6.1.
3. **Leaf KeyUsage is not checked by Go `Verify`.** Check `digitalSignature` explicitly. `contentCommitment`, `keyEncipherment` and `keyAgreement` are allowed extras.
4. **Policy matching.**
   - Leaves carry several OIDs: QCP-n `0.4.0.194112.1.0` and national `2.16.724.1.3.5.7.x` / `.5.8` / `.5.9`.
   - Match "exact allowlisted OID ∈ policies". Reject when two different allowlisted profiles match.
   - DNIe may add a `.X.Y` version suffix: enumerate exact versions and never use prefixes.
   - Every in-scope CA certificate (FNMT, ACCV, DNIe) asserts anyPolicy, so Go's RFC 5280 policy processing cannot block these chains. Do the exact-OID check in the profile layer.
5. **Identity parsing.**
   - Walk `RawSubject` RDNs. Accept PrintableString and UTF8String for 2.5.4.5: FNMT RSA uses PrintableString, G2 uses PrintableString in the observed kit (the G2 profile text says UTF8String).
   - Decode SAN `directoryName` with private OIDs: `1.3.6.1.4.1.5734.1.{1,2,3,4,6,7,20,22,47}`, `2.16.724.1.3.5.7.{1,2}.*`, and UID `0.9.2342.19200300.100.1.1`.
   - Parse SubjectDirectoryAttributes `2.5.29.9` / `dateOfBirth 1.3.6.1.5.5.7.9.1` yourself (Go does not) for DNIe.
   - The SAN NIF form differs by profile: FNMT citizen SAN is bare, FNMT representative SAN is `IDCES-` prefixed. Normalize both sides before comparing.
6. **Specimen-ID denylist** (all pass mod-23): `00000000T`, `99999999R`, `X0000000T`. DNIe test names are `Nombre`/`Apellido1`/`Apellido2`. Keep this as a configurable production denylist; it does not replace pinning.
7. **OCSP request and response handling.**
   - All observed responders use a SHA-1 CertID and echo a request nonce. `golang.org/x/crypto/ocsp.CreateRequest` cannot add a nonce: either hand-build the request or document a no-nonce policy with strict freshness.
   - x/crypto/ocsp does not enforce the responder EKU (`OCSPSigning`), the responder certificate's validity, or the ResponderID/certificate match. Do those checks yourself.
   - Support byKey ResponderIDs (FNMT G2) as well as byName.
   - Responder certificates rotate: the FNMT G2 responder expires 2026-11-25 and DNIe rotates every 6 months. Never pin them. `id-pkix-ocsp-nocheck` is present on all of them.
   - Map the "non-issued" pattern (revoked, certificateHold, 1970-01-01) to a rejection. Do not offer "temporarily suspended, retry later" UX for it.
8. **OCSP freshness is per issuer.**
   - FNMT: thisUpdate = now, 8h window.
   - ACCV leaves: CRL-backed, thisUpdate up to ~1h old, nextUpdate +3 days.
   - DNIe "good": `nextUpdate` absent, so a local max age applies (spec §8.1, 15 min).
   - CA-level evidence (ACCV OCSP, FNMT/DNIe/ACCV ARLs) has windows of about 6 months with months-old thisUpdate. Accept within [thisUpdate, nextUpdate] and run CA status as a periodic job.
   - Do not apply one global "thisUpdate < N minutes" rule when nextUpdate is present.
9. **CRLs.**
   - FNMT CRLs are partitioned with a critical IssuingDistributionPoint. Parse the IDP and require it to match the CDP URI used. Confirm Go's `ParseRevocationList` behaviour with critical IDP on these real bytes.
   - Partition numbers are sparse, so never enumerate them.
   - The ACCV RSA1 CLIENTE CRL is 13.6 MB, so set a per-issuer size cap of 32 MB or more, or treat CRL as a background fallback only.
   - ACCV `/gestcert/` and DNIe `/dnie/crls/` answer HTTP 302 to same-host paths. The SSRF-guarded fetcher must follow bounded same-host redirects over plain HTTP.
   - The ACCV CA-certificate CDPs carry a `cRLIssuer` equal to the root DN. Do not reject that as "indirect CRL unsupported" when the issuer matches.
   - DNIe leaves have no CDP: OCSP only, and failure blocks.
10. **Algorithms.**
    - Key sizes: RSA-2048 (FNMT, DNIe), RSA ≥3072 (ACCV current), RSA ≥2048 (ACCV legacy).
    - RSA-1920 (DNIe ROCA re-issues): reject as a deliberate legacy exclusion.
    - ECDSA P-256 (FNMT G2) and ECDSA ≥P-256 (ACCV).
    - The ACCV ECC1 CA is P-521 with ecdsa-with-SHA512 and signs leaves with ecdsa-with-SHA256. Go accepts this; keep it out of any "hash must match curve" rule.
    - SHA-1 appears only in the ACCVRAIZ1 self-signature and the old ACCVCA-120 copy. Never enable SHA-1 chain signatures.
11. **TLS edge (Go).**
    - Use `RequireAnyClientCert` plus `VerifyConnection`, with `ClientCAs` = the pinned issuing CAs. That sends the acceptable-CA DNs `CN=AC FNMT Usuarios…`, `CN=AC USUARIOS G2…` and `CN=ACCV RSA1/ECC1 CLIENTE…`.
    - Exclude consular, representative and employee CAs from the list while those profiles are disabled.
    - Disable session tickets and resumption.
    - TLS 1.3 requires RSA-PSS for RSA client keys. Software keys in Windows legacy CAPI CSPs, and smart cards (DNIe), may only do PKCS#1 v1.5. Keep TLS 1.2 enabled on the auth host and test FNMT RSA on Windows Chrome/Edge before declaring support.
    - Go supports `ecdsa_secp521r1_sha512` if an ACCV leaf is P-521.
12. **Parser compatibility.**
    - Go 1.27.3 parses every in-scope bundle CA, with no unhandled critical extensions and no negative serials (goparse `result.tsv`). The DNIe intermediates were not in that run; OpenSSL decodes them cleanly.
    - The DNIe leaf `personalDataInfo` (2.16.724.1.2.2.4.1) criticality is unknown. If it is critical, Go reports `UnhandledCriticalExtension`, and only an explicit reviewed allowance for that OID may clear it.
13. **TSL semantics.** Record the service status period in the evidence.
    - AC USUARIOS G2 has been granted only since 2025-07-17.
    - ACCVCA-120 lost ForeSignatures on 2026-01-22.
    - A static pin in this PoC must be re-reviewed whenever the TSL sequence changes. The current TSL's nextUpdate is 2027-03-21.

## Fetched artifacts (all outside the repository)

| What | Source URL | Local path | SHA-256 |
|---|---|---|---|
| AC DNIE 004 (PEM) | http://pki.policia.es/dnie/certs/AC004.crt | `DL/dnie/AC004.crt` (+ `.pem` copy) | file f368f0dc19cb72adfca9f46bdd3db39552fcccb22de275f52de18cba8670ff33 / DER ebae9930…6f6c |
| AC DNIE 005 | http://pki.policia.es/dnie/certs/AC005.crt | `DL/dnie/AC005.crt` | file 4e6e246714a1263429b2916d3f52b7bcdcabd355340df386786272b858f36b89 / DER 828a22ff…e828 |
| AC DNIE 006 | http://pki.policia.es/dnie/certs/AC006.crt | `DL/dnie/AC006.crt` | file bf910f9e22924c70d250137ec3fef031cfb496e18de0b49f1893d7946e09f4a2 / DER eda47e8a…3bbd |
| DNIe OCSP responder bundle | https://www.dnielectronico.es/descargas/certificados/Certificados_OCSP_Responder_FNMT.zip | `DL/dnie-ocsp-zip/`, extracted to `DL/dnie-ocsp-extracted/` | zip 3cdad19b28132999f76d914c7e8ae76b3f6c617d213e0717d6f8272228f12e08; DER: AV DNIE FNMT 6ac22776…9741, DNIE004 0bc4066a…dabe, DNIE005 7c2bed6e…b354, DNIE006 096edc2d…5e0e (informational, do not pin) |
| FNMT citizens profiles v2.6 | perfiles_certificados_ac_usuarios.pdf | `/home/p4u/.cache/cert-check/research/fnmt_perfiles_ac_usuarios_v2.6.md` | — |
| FNMT representatives v10.0 | perfiles_certificados_ac_representacion.pdf | `…/fnmt_perfiles_ac_representacion_v10.md` | — |
| FNMT public sector v1.15 (pp. 1–70) | perfiles_certificados_sector_publico.pdf | `…/fnmt_perfiles_sector_publico.md` | — |
| DNIe CPS v3.4 | https://www.dnielectronico.es/PDFs/Politicas_de_certificacion_v3.4.pdf | `…/dnie_politicas_v3.4.md` | — |
| ACCV CP-07 v8.0.4 / v7.0.4 / v6.0.7 | accv.es `Politicas_pdf/ACCV-CP-07V{8.0.4-ES-2026,7.0.4-ES-2023,6.0.7-ES-2023}.pdf` | `…/accv_cp07_v{8.0.4,7.0.4,6.0.7}.md` | — |
