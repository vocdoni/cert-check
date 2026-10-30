# Appendix B research: AOC idCAT / T-CAT, Izenpe, Camerfirma

Research date: 2026-10-30. Scope: spec Appendix B (`Vocdoni_Spanish_Certificate_CSP_Implementation_Specification.md` lines 818-1200), generic rules §6.1, §7, §8, §9 (lines 139-354), predecessor review §13 (line 443), and the product decision in `docs/Vocdoni_CSP_Authentication_Only_Agent_Note.md` (AN). Paths below are relative to `/home/p4u/certificate_poc/docs/Vocdoni_CSP_Handoff/` unless absolute.

## How the data was checked

- Each CA file cited was decoded with `openssl x509` (subject, issuer, dates, serial, SHA-256 of DER, extensions). SPKI hashes were computed with `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256sum`. Every chain link was checked with `openssl verify`. File names equal the recomputed DER SHA-256, and SPKI hashes equal `spki_sha256` in the inventory JSON.
- TSL status comes from `spanish_tsl_inventory_2026-10-30.json` (TSL sequence 189, issued 2026-09-24, next update 2027-03-21). The exporter did not validate the XML signature (`xml_signature_cryptographically_validated_by_exporter: false`).
- Go behaviour was tested with **go1.27.3** using a scratch harness at `/home/p4u/.cache/cert-check/research/appb-goparse/` (`x509.ParseCertificate`, `Verify`, `ParseRevocationList`).
- Live, read-only status checks were run from this host on 2026-10-30 between 22:33 and 22:42 UTC:
  - OCSP for AOC, Izenpe and Camerfirma intermediates;
  - OCSP for AOC leaf serials taken from the public CRLs;
  - OCSP for the Izenpe synthetic active and revoked leaves;
  - CRL downloads.

  Every response signature was verified. Saved bytes are in `/home/p4u/.cache/cert-check/research/appb-ocsp/` and `appb-crl/`.
- Official fetches made here (stored under `/home/p4u/.cache/cert-check/research/`):
  - F1 `appb-aoc-perfils-7.4.md` ← A2 https://epscd.aoc.cat/assets/documents/politiques/vigents/perfils-certificats/Perfils_de_Certificats_7.4-ES.pdf
  - F2 `appb-aoc-perfils-7.1.md` ← https://epscd.aoc.cat/assets/documents/politiques/documentacion_del_periode/del_18-12-24_fins_08-03-25/perfils-certificats/Perfils_de_Certificats_7.1-ES.pdf
  - F3 `appb-aoc-dpc-7.4.md` ← A3 https://epscd.aoc.cat/assets/documents/politiques/vigents/declaracio-practiques/DPC-7.4-ES.pdf
  - F4 `appb-aoc-jerarquia.json` ← A5 https://epscd.aoc.cat/ca/jerarquia.html
  - F5 AOC OCSP responder certificates in `ca-downloads/aoc-ocsp_*`. Source is `https://epscd.aoc.cat/assets/documents/jerarquia/{ocsp_ciutadania,ocsp_casub-a2,ocsp_acc,ocsp_caroot-a}.zip`, with zip SHA-256 `abdd07c7…`, `1dfa1359…`, `d6016f79…`, `00f3c3e2…`.
  - F6 `appb-izenpe-kit/` ← I4 `Kit_certificados_ficticios_PRODUCCION_Izenpe.zip`, zip SHA-256 `1d2c5423a22649dcf459fea72517d260eec8bfab67c67fa8d8a02da7602944f7`.
  - F7 `appb-izenpe-perfiles-8.1.md` ← I2 https://www.izenpe.eus/contenidos/informacion/perfiles_certificados/es_def/adjuntos/Perfiles_de_Certificados.pdf
  - F8 `appb-camerfirma-cp-personales-1.0.md` ← C3 https://www.camerfirma.com/wp-content/uploads/2025/08/PUB-2025-18-11-CP_CAMERFIRMA_CERTIFICADOS_PERSONALES_ES_v1.0.pdf
  - F9 `appb-camerfirma-ciudadano.md` ← https://www.camerfirma.com/certificados-digitales/certificado-cualificado-de-ciudadano
  - F10 site map searches of camerfirma.com. These found no public test-certificate page.

## Summary

| profile_id | holder_role | recommendation | confidence |
|---|---|---|---|
| aoc-idcat-g2 | natural_person | **include** (mandatory, AN §2) | high: anchor, OID, KU, EKU, OCSP. medium: identity encoding (no leaf fixture) |
| aoc-idcat-g3 | natural_person | **include** (mandatory, AN §2) | high: anchor, OID, OCSP. medium: identity/leaf key (no fixture) |
| aoc-tcatp-employee / -linked / -worker (software) | public_employee / linked | exclude (AN §3 defers) | high (profile doc) |
| aoc-tcat-card-and-remote | public_employee / representative | exclude (card / remote) | high |
| aoc-reject-classes | pseudonym / seal / app / TSA | reject | high |
| izenpe-citizen-card, izenpe-citizen-bakq | natural_person | exclude (card / centralized, AN §3) | high |
| izenpe-nonqualified (B@K, Mobile, autónomo NQ) | natural_person | exclude (issuer CCEENR is not a TSL service) | high |
| izenpe-professional-sw-{legacy,2025} | professional | exclude (deferred). Browser-usable software | high legacy (fixture), medium 2025 |
| izenpe-employee-sw-{legacy,2025} | public_employee | exclude (deferred). Browser-usable software | high legacy (fixture), medium 2025 |
| izenpe-representative-sw-{legacy,2025} | representative | exclude (deferred) | high legacy |
| izenpe-reject-classes | pseudonym / seal | reject | high |
| camerfirma-citizen-sw-2024 | natural_person | include-if a real 2024 specimen plus product onboarding | high: anchor and OID. **low: identity / AIA / CDP** |
| camerfirma-citizen-sw-2016 | natural_person | include-if a still-valid specimen exists (otherwise exclude) | medium: anchor and OID. low: identity |
| camerfirma-citizen-2021-card-cloud | natural_person | exclude (no software variant) | high |
| camerfirma-employee/corporate/representative | various | exclude (deferred) | medium |
| camerfirma-global-2016 | natural_person | reject (TSL withdrawn 2017-07-21) | high |

---

## A. AOC / Consorci AOC (TSL provider index 5)

The spec says "legacy DNI suffix in the idCAT surname". The AOC documents do not support that wording for idCAT:

- Profiles v7.1 (F2 line 642) and v7.4 (F1 line 843) define the idCAT `SN` as "Apellidos del firmante tal y como aparecen en el documento de identidad" with **no** DNI suffix.
- In v7.1 (F2 lines 170-595, 676), the `" - DNI " + NIF` surname suffix belongs to the **T-CAT/T-CATP employee, linked-person, worker and seal-custodian** profiles. v7.2 (2025-03-09) removed it from those profiles.
- For idCAT, `" - DNI <id>"` appears only in the **CN**.

AN §2 still asks for a gated legacy strip rule. Implement it exactly as below, but expect it never to fire for idCAT.

```yaml
profile_id: aoc-idcat-g2
provider: AOC (Consorci Administració Oberta de Catalunya)
display_name_es: "idCAT Certificat"
holder_role: natural_person
recommendation: include   # mandatory initial family (AN §2); software cert, TLS clientAuth documented
confidence: high (anchor/OID/KU/EKU/revocation endpoints verified live); medium (identity encoding: no real leaf fixture)
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6.pem   # identical copy in additional-ca-certificates/
    subject: "C=ES, O=CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA, OU=Serveis Públics de Certificació, CN=EC-Ciutadania"
    sha256_der: 0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6
    spki_sha256: 3761345542c20b314a744a7c54a82152a283be9cdcda233f050000c2d0e5070d
    not_after: 2030-09-18T08:21:00Z      # not_before 2014-09-18
    key: RSA-2048, sha256WithRSAEncryption, CA:TRUE pathlen:0, no EKU, SKI 0b68593e…
    tsl_service_status: granted since 2016-06-30T22:00:00Z, CA/QC "Certificados Reconocidos emitidos por CA Ciutadania", ForeSignatures, no Qualifications ext
intermediates_needed: []          # EC-Ciutadania issues leaves directly (pathlen:0)
roots_above_anchor:
  - file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/88497f01602f3154246ae28c4d5aef10f1d87ebb76626f4ae0b7f95ba7968799.pem
    subject: "C=ES, O=Agencia Catalana de Certificacio (NIF Q-0801176-I), OU=Serveis Publics de Certificacio, OU=Vegeu https://www.catcert.net/verarrel (c)03, OU=Jerarquia Entitats de Certificacio Catalanes, CN=EC-ACC"
    sha256_der: 88497f01602f3154246ae28c4d5aef10f1d87ebb76626f4ae0b7f95ba7968799
    spki_sha256: b21d2a743318712ba16f39919d961a4bafba3bca9a43a75b1fcfe22c5d70caba
    not_after: 2031-01-07T22:59:59Z ; RSA-2048 ; sha1WithRSA self-signature ; serial -11D4C2142BDE21EB579D53FB0C223BFF (negative)
    note: not a TSL service identity; go1.27.3 ParseCertificate -> "x509: negative serial number" (passes only with GODEBUG=x509negativeserial=1)
leaf_policy_oids: ["1.3.6.1.4.1.15096.1.3.2.86.2"]   # Perfils v7.4 §3.1.2 (identical in v7.1); QCP-n 0.4.0.194112.1.0 NOT listed in the idCAT row -> tolerate, do not require
key_usage_expected: [digitalSignature (required), contentCommitment]   # critical; tolerate keyEncipherment on older leaves
eku_expected: [clientAuth 1.3.6.1.5.5.7.3.2 (required), 1.2.840.113583.1.1.5 Adobe]   # since v6.9 (2023-11-15); earlier leaves: emailProtection+clientAuth
leaf_key_algorithms: [RSA-3072+, EC P-384 (CPS v7.4 §6.1.5 current minimum)]   # older G2 leaves may be RSA-2048 (v7.4 changelog "actualización de longitudes"): accept RSA-2048 for G2, unverified
identity:
  personal_id:
    location: "subject 2.5.4.5 (ETSI EN 319 412-1 semantics, Perfils §3.1.1)"
    formats: ["IDCES-<DNI>  (documented example IDCES-99949992L)", "IDCES-<NIE>? (unverified)", "PASxx-/IDCxx- foreign document (C = issuing country)"]
    anchored_grammar: '^IDC(?P<cc>[A-Z]{2})-(?P<v>[0-9A-Z]+)$ ; DNI census only when cc=="ES" and v matches ^[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]$ (mod-23) or ^[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE]$ (NIE check); any other prefix -> non-DNI namespace (no match). No bare-ID fallback.'
  given_names: {location: "subject 2.5.4.42, exact as in ID document"}
  surnames:
    location: "subject 2.5.4.4, both surnames in one field (no split SAN for idCAT) -> family_names only, surname1/surname2 = null"
    quirks: "AOC profiles v7.1/v7.4 document NO ' - DNI' suffix in idCAT SN (suffix is in CN). Gated legacy rule per AN: strip only if SN matches ^(.+) - DNI ([0-9A-Z]+)$ AND group 2 == bare ID from 2.5.4.5; otherwise keep whole value."
  cross_checks:
    - "subject C (2.5.4.6) = document issuing country since v6.6 (2022-03-31): must equal the cc in serialNumber prefix"
    - "CN = '<SURNAMES> <GIVEN> - DNI <id>' (profile example uses an en dash and a 9-digit number): do not parse; diagnostics only"
    - "no SAN identity tuple documented; leaves before v6.9 may carry rfc822Name SAN: ignore"
  birth_date: {present: no, location: "no SubjectDirectoryAttributes in Perfils v7.1/v7.4 §3.1.2", evidence: "profile doc only; confidence medium until a real leaf is inspected"}
revocation:
  ocsp: ["http://ocsp.catcert.cat (AOC: every cert carries an OCSP AIA; take the leaf AIA)"]
  responder_notes: >
    Live check of a revoked EC-Ciutadania serial taken from the public CRL. Response verified
    with EC-Ciutadania as partial-chain anchor.
    Responder: "Servei OCSP de EC-Ciutadania", issued directly by EC-Ciutadania. EKU OCSPSigning,
    id-pkix-ocsp-nocheck, RSA-3072. Valid 2026-02-17..2027-02-17, so it rotates yearly.
    DER 3f1248518427391bdee82350ccfa952d7ec33a535825192b01e90a5cb3f8d6aa (from ocsp_ciutadania.zip).
    Status revoked, reason cessationOfOperation.
    thisUpdate = producedAt; nextUpdate = thisUpdate + 5 min. Nonce echoed. SHA-1 CertID accepted.
    A multi-certificate request would be signed by the EC-ACC root responder, which is NOT
    authorized for EC-Ciutadania leaves (A5). Send one certificate per request.
  crl: ["http://epscd.catcert.net/crl/ec-ciutadania.crl (EC-era host, still served)", "https://epscd.aoc.cat/crl/ec-ciutadania.crl (same bytes)"]
  crl_notes: >
    6,858,105 bytes; 154,004 entries; full CRL with no IDP and no delta.
    thisUpdate 2026-10-30T22:20Z; nextUpdate +7 days. CPS §4.9.7: issued daily and within 30 min
    of each revocation; expired certificates are removed.
    Go ParseRevocationList parses it in about 83 ms; signature OK.
    Reasons seen: cessationOfOperation, affiliationChanged, keyCompromise, superseded.
    No certificateHold.
  intermediate_status: >
    EC-Ciutadania by OCSP at http://ocsp.catcert.cat returned good, signed by "Servei OCSP de
    EC-ACC" (issued by EC-ACC, nocheck, DER 6b9a3d24…). Verifying that responder requires
    EC-ACC's key.
    ARL http://epscd.catcert.net/crl/ec-acc.crl: 903 bytes, 5 entries, nextUpdate 2027-08-25,
    NON-critical IDP = that same URI. The epscd2.catcert.net mirror returned HTTP 403 to HEAD.
    Choose one: (a) take the TSL service status (granted) as the anchor's status (spec §8.3), or
    (b) pin EC-ACC's SPKI offline and use it only to verify the EC-ACC responder / ARL.
test_certificate_traps: >
  Current marker (CPS v7.4 §1.1.3, F3 lines 639-654): given name NOMDOS, surnames ESPECIMENDOS
  ESPECIMENDOS, DNI 99949992L. The checksum is valid; the profile docs also use IDCES-99949992L
  as their example.
  Earlier marker (CPS v7.1, per spec line 962; not re-verified): 00000000T, "de la Peça",
  "de Proves".
  These certificates are signed by production CAs, so chain and OCSP checks pass. Reject them by
  a versioned reserved-identity registry.
  AOC also publishes a separate PRE-PRODUCTION hierarchy (arxiucp_preproduccio_2025.zip on A5).
  Never load it.
public_fixtures: "none. No idCAT leaf is in the bundle or publicly downloadable. AOC issues production test certificates on request (A7). The OCSP/CRL code paths can be exercised with public revoked serials from ec-ciutadania.crl."
gaps:
  - "real leaf: NIE encoding (IDCES-X… vs PNOES-…), leaf AIA/CDP host (catcert.net vs aoc.cat), presence of 0.4.0.194112.1.0, RSA size"
  - "leaves issued before profile v6.8 (2023-05-10) may carry a CRITICAL qcStatements extension. Go then reports it in UnhandledCriticalExtensions and Verify fails. A fixture is needed."
  - "max leaf validity is 5 years (CPS §4.9.13): G2 leaves from 2021-2025 are still in circulation"
sources: ["spec 849-964", "AN lines 35, 38, 43", "F1 §3.1 (lines 833-863)", "F2 §3.1", "F3 §1.1.3, §4.9.7, §4.9.13, §6.1.5", "F4/A5", "predecessor idcat.go lines 62-72 (old URLs http://www.catcert.cat/descarrega/ec-ciutadania.crt, http://epscd.catcert.net/crl/ec-ciutadania.crl)"]
```

```yaml
profile_id: aoc-idcat-g3
provider: AOC (Consorci Administració Oberta de Catalunya)
display_name_es: "idCAT Certificat"
holder_role: natural_person
recommendation: include   # mandatory (AN §2); G3 production since 2025-10-15 (A6)
confidence: high (anchor, OID, OCSP/CRL verified live); medium (leaf key algorithm and identity encoding: no fixture)
trust_anchors:
  - file: docs/Vocdoni_CSP_Handoff/service-identities/e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735.pem   # identical copy in additional-ca-certificates/
    subject: "C=ES, O=CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA, organizationIdentifier=VATES-Q0801175A, CN=SubCA CIUTADANIA Q (G3) A.2"
    sha256_der: e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735
    spki_sha256: 4da535844e847db014be7e842d7b243118f3d28ce487c32cb62e5a72c70b88c2
    not_after: 2048-01-20T10:21:14Z      # not_before 2023-02-02
    key: EC P-384, ecdsa-with-SHA384, CA:TRUE pathlen:0; EKU on the CA = clientAuth + 1.2.840.113583.1.1.5; AIA caIssuers http://epscd.aoc.cat/descarrega/caroot-a.crt, OCSP http://ocsp.aoc.cat; CDP http://epscd.aoc.cat/crl/caroot-a.crl
    tsl_service_status: granted since 2024-10-16T00:00:00Z, CA/QC "Certificados Cualificados emitidos por SubCA CIUTADANIA Q (G3) A.2", ForeSignatures
intermediates_needed: []
roots_above_anchor:
  - file: docs/Vocdoni_CSP_Handoff/additional-ca-certificates/15651384ca70c580dff5fed06a02162f6aa6eddd3602313da4e124c25775baaa.pem
    subject: "C=ES, O=CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA, organizationIdentifier=VATES-Q0801175A, CN=CA CONSORCI AOC (G3) ROOT-A"
    sha256_der: 15651384ca70c580dff5fed06a02162f6aa6eddd3602313da4e124c25775baaa
    spki_sha256: 83a7f7447acb2e6b61a9fb1c21c24bd816f97f384a95051c66aa6cb5dff404d8
    not_after: 2048-01-20T10:21:14Z ; EC P-384 ; parses in Go ; not a TSL service identity
leaf_policy_oids: ["1.3.6.1.4.1.15096.1.3.2.86.2"]   # same OID as G2; dispatch on (anchor SPKI, OID)
key_usage_expected: [digitalSignature (required), contentCommitment]
eku_expected: [clientAuth (required), 1.2.840.113583.1.1.5]   # the anchor's own EKU permits clientAuth -> Go chain EKU check passes
leaf_key_algorithms: [EC P-384, RSA-3072+]   # CPS v7.4 §6.1.5; which one AOC actually issues for idCAT G3 is unverified
identity: same as aoc-idcat-g2 (Perfils §3.1 is generation-independent). No legacy surname rule is needed for G3: all G3 leaves post-date v7.2.
revocation:
  ocsp: ["http://ocsp.aoc.cat (A.2 AIA; leaf AIA assumed identical, confirm on fixture)"]
  responder_notes: >
    Live check of a revoked A.2 serial taken from the CRL; verified against A.2 + root.
    Responder: "Servei OCSP de SubCA CIUTADANIA Q (G3) A.2", issued directly by A.2, P-384,
    OCSPSigning + nocheck. Valid 2026-02-17..2027-02-17.
    DER a5631cb01658757c0155d4250838cfcbab4d772a824a99e9642bc21bfda6cb02.
    Status revoked (cessationOfOperation); nextUpdate +5 min; nonce echoed.
  crl: ["https://epscd.aoc.cat/crl/casub-a2.crl (leaf CDP scheme/host to confirm on fixture)"]
  crl_notes: "1,005,376 bytes; 20,880 entries; no IDP; nextUpdate +7 days; signature OK (openssl and Go)."
  intermediate_status: >
    A.2 by OCSP at http://ocsp.aoc.cat returned good. The responder "Servei OCSP de CA CONSORCI AOC
    (G3) ROOT-A" (DER 0bf4720c…, nocheck) is issued by the G3 root, which Go parses, so pin the
    root SPKI for this check.
    ARL http://epscd.aoc.cat/crl/caroot-a.crl: 553 bytes, 4 entries, nextUpdate 2027-02-21.
    CPS: the ARL is issued at least every 6 months.
test_certificate_traps: same registry as G2 (NOMDOS / ESPECIMENDOS / 99949992L); pre-production G3 keys exist (A5).
public_fixtures: none (as G2).
gaps: ["real G3 leaf: key algorithm, AIA/CDP exact URIs, identity encoding"]
sources: ["spec 851-860, 934-958", "F1 §3.1", "F3 §1.1.2, §6.1.5", "F4", "A6"]
```

```yaml
profile_id: aoc-tcatp-software   # three rows: employee .7.3.1, linked person .86.1, public worker .86.3
provider: AOC
display_name_es: "T-CATP (empleat públic / persona vinculada / treballador públic de nivell mig)"
holder_role: public_employee | linked_person
recommendation: exclude   # AN §3 defers employee/professional/representative incl. software T-CATP; documented for later
confidence: high (Perfils v7.4 §2.2, §2.4, §2.12; CPS: "se emiten para su uso en software")
trust_anchors:
  - {file: service-identities/356a5f4d994e9efa7caefc491768911d65ec25977465b610e2f29aa4472631c3.pem, subject: "C=ES, O=CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA, OU=Serveis Públics de Certificació, CN=EC-SectorPublic", sha256_der: 356a5f4d994e9efa7caefc491768911d65ec25977465b610e2f29aa4472631c3, spki_sha256: 54c9375378ffb1a53d7737427834f17b4312cee651dada656b24c17cdc46da84, not_after: 2030-09-18T08:23:27Z, key: RSA-2048 pathlen:0, tsl_service_status: "granted since 2022-06-29, CA/QC, ForeSignatures+ForeSeals, NotQualified for 15096.1.3.1.161.1/.91.1/.121.1 (TSL URNs carry a trailing space)"}
  - {file: service-identities/2b7b390ff652aeca8b2f352325ae89fb153aa99440aa9fe80257b6d79887a560.pem, subject: "C=ES, O=CONSORCI ADMINISTRACIO OBERTA DE CATALUNYA, organizationIdentifier=VATES-Q0801175A, CN=SubCA SECTOR PUBLIC Q (G3) A.1", sha256_der: 2b7b390ff652aeca8b2f352325ae89fb153aa99440aa9fe80257b6d79887a560, spki_sha256: fda75f749a43bb8c76ac3aa74e41dd568e9830cc9213e658ffe9af0d6ea35164, not_after: 2048-01-20T10:21:14Z, key: "EC P-384; CA EKU clientAuth+smartcardLogon+Adobe", tsl_service_status: "granted since 2024-10-16, CA/QC, ForeSignatures+ForeSeals"}
intermediates_needed: []
roots_above_anchor: [EC-ACC (as idCAT G2), CA CONSORCI AOC (G3) ROOT-A (as idCAT G3)]
leaf_policy_oids: ["1.3.6.1.4.1.15096.1.3.2.7.3.1 (+2.16.724.1.3.5.7.2, 0.4.0.194112.1.0)", "1.3.6.1.4.1.15096.1.3.2.86.1 (+0.4.0.194112.1.0)", "1.3.6.1.4.1.15096.1.3.2.86.3 (+0.4.0.194112.1.0)"]
key_usage_expected: [digitalSignature, contentCommitment]
eku_expected: [clientAuth, 1.2.840.113583.1.1.5]
leaf_key_algorithms: [RSA-3072+, EC P-384]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<NIF> (ETSI EN 319 412-1)"]}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4", quirks: "≤v7.1: '<s1> <s2> - DNI <NIF>'; v7.2+ (2025-03-09): plain"}
  cross_checks: ["employee: SAN directoryName 2.16.724.1.3.5.7.2.{4 id, 6 given, 7 surname1, 8 surname2}; .3 = org NIF (not holder)", "linked/worker: SAN directoryName 1.3.6.1.4.1.15096.0.{1 given, 2 surname1, 3 surname2}", "2.5.4.97 VATES-… is the organization"]
  birth_date: {present: no, location: "-", evidence: "Perfils v7.4 §2.2/2.4/2.12"}
revocation: {ocsp: ["http://ocsp.catcert.cat (G2)", "http://ocsp.aoc.cat (G3)"], crl: ["https://epscd.aoc.cat/crl/ec-sectorpublic.crl", "https://epscd.aoc.cat/crl/casub-a1.crl"], intermediate_status: "as idCAT (EC-ACC / G3 root responders)"}
test_certificate_traps: same AOC registry (IDCES-99949992L appears as the documented example)
public_fixtures: none
gaps: ["role/eligibility semantics; real fixtures"]
sources: ["spec 867-879, 906-918", "F1 §2.2, §2.4, §2.12", "F3 §1.1.1.2"]
```

`aoc-tcat-card-and-remote`: **exclude**.
- Smart-card profiles (AN §3): `.7.1.2` (T-CAT authentication, nonqualified), `.7.1.1` (signature, QSCD), `.82.1`, `.82.2`, `.8.1.1` (representative).
- Remote-key profiles under **SubCA SECTOR PUBLIC R Q (G3) A.3**: `.7.3.3`, `.86.5`, `.86.6`. The anchor is `service-identities/783ed47b5175a90288d2767568426e8fc5ff726fa4bc0a035f4bbf3a9386a60f.pem`, SPKI `d48aff89c3499ed85ebf99a2a101b93a99b1149b87c74349b2d7f89711b46af5`, P-384, TSL granted since 2025-10-02. Spec line 943 says this certificate was "not locally fingerprinted", but it **is in the bundle**.

All of these sit under prefix `1.3.6.1.4.1.15096.1.3.2`.

`aoc-reject-classes`: **reject** before any identity parsing. These are all suffixes of `1.3.6.1.4.1.15096.1.3.2`:
- pseudonyms: `.4.1.2`, `.4.1.1`, `.4.2`;
- seals: `.6.2`, `.6.3`;
- application: `.91.1`;
- timestamps: `.112`, `.113`.

Historical EC-idCAT OIDs `1.3.6.1.4.1.15096.1.3.1.*` are never allowlisted. Source: spec lines 867-889.

---

## B. Izenpe (TSL provider index 16)

**Which products a browser can use.** The source is profiles v8.1 (F7, index line 50) together with the official synthetic kit (F6). Izenpe has **no qualified citizen software certificate**, which is consistent with AN §3.

| Product | Legacy OID (CA) | 2025 OID (CA) | Key storage | Browser mTLS |
|---|---|---|---|---|
| Ciudadano tarjeta | `1.3.6.1.4.1.14777.2.18.1` (CA (4)) | `.51.1.1` (CCEER2025) | smart card | card reader (deferred) |
| B@KQ | `.2.18.3` | `.51.1.3` | centralized HSM | no local key |
| B@K, Izenpe Mobile, Autónomo NQ software | `.5.2.5`, `.5.2.5.4`, `.5.2.7.2` | none | centralized / mobile / software | issuer `CA de Ciudadanos y Entidades (3)` (CCEENR) is **not a TSL service**, so no anchor |
| Profesional | `.2.19.1` card / `.2.19.2` **software** / `.2.19.3` HSM | `.51.2.1` / `.51.2.2` / `.51.2.3` | software available | yes (software) |
| Funcionario / PeP | `.4.14.1` / `.4.14.2` **software** / `.4.14.3` | `.52.1.1` / `.52.1.2` / `.52.1.3` | software available | yes (software) |
| Representante (with / without legal personality) | `.2.16` / `.2.17` **software**; card `.2.12`/`.2.13`(+`.5`), HSM `.2.14`/`.2.15` | `.51.3.2` / `.51.4.2` software, etc. | software available | yes (software) |
| PeP seudónimo software | `.4.13.2` | `.52.2.2` | software | reject (pseudonym) |

### Anchors

| ID | File | SHA-256 DER | SPKI SHA-256 | Key, not_after | TSL status |
|---|---|---|---|---|---|
| IZ-CCEER-L | `additional-ca-certificates/7ed19361ad734d703fbadf029f52ec3b6648d8dd56baba0884ed4f859b5b9375.pem` (sha256WithRSA, 2010) and `service-identities/2626b19563bc78d9b1442b93ce98d14a1e4b74264acc90222f1f3c2385c27337.pem` (**sha1WithRSA**, 2009) | as file names | `a6cc591dedf7b811375f608bbabd9facc255fce28b55c8f23d555286903ef8de` (same key) | RSA-4096, 2037-12-12T23:00Z | service 16/1 granted since 2016-12-21. NotQualified for `14777.2.7/.2.8/.2.9` |
| IZ-AAPP-L | `additional-ca-certificates/25303cfd0bf1baa1ef248c29f073fffc2e7c81582ee23b45c7f1c3b32e341ad8.pem` (sha256) and `service-identities/1f11a6555cc6f24d43e6e4e30ee804d41645847b7fd1565a191863345c4e256f.pem` (sha1) | as file names | `7c8a050a8a76af91f0f37f0f2fb72b578b6cd7a2ead6cd718e4ec4f88f7c744f` | RSA-4096, 2037-12-12T23:00Z | service 16/2 granted since 2026-05-20. NotQualified for `14777.4.3/.4.4/.4.5` |
| IZ-CCEER-2025 | `service-identities/d852490ed91838b06f6885e17153738debfe9a5ff9ddb96ba0e36e5d4572efee.pem` | `d852490e…efee` | `9001c02f1f4e12fdf4570f6e785a350c24f75e54583723cacad7965b798bde49` | P-384, 2045-09-25T12:41:16Z. CA EKU clientAuth, 1.3.6.1.5.5.7.3.36, emailProtection, smartcardLogon | service 16/14 granted since 2026-05-20 |
| IZ-AAPP-2025 | `service-identities/7e4e551152f06c51db576236162514bafd7abce1a3a4141a1a7949bdcfe1a432.pem` | `7e4e5511…a432` | `2fda1dcdadd80c4c0cc6bff126bd922c9bb0bd992f6d8f5519a0c58a8215ed9a` | P-384, 2045-09-25T13:05:27Z, same CA EKU as CCEER2025 | service 16/15 granted since 2026-05-20 |

Full subjects:
- IZ-CCEER-L: `C=ES, O=IZENPE S.A., OU=NZZ Ziurtagiri publikoa - Certificado publico SCI, CN=Herritar eta Erakundeen CA - CA de Ciudadanos y Entidades (4)`
- IZ-AAPP-L: `… OU=AZZ Ziurtagiri publikoa - Certificado publico SCA, CN=EAEko HAetako langileen CA - CA personal de AAPP vascas (2)`
- IZ-CCEER-2025: `C=ES, O=IZENPE S.A., organizationIdentifier=VATES-A01337260, CN=CA HERRITARRAK ETA ENPRESA-CIUDADANIA Y EMPRESA 2025`
- IZ-AAPP-2025: `… CN=CA ADMINISTRAZIO PUBLIKOA-ADMINISTRACION PUBLICA 2025`

Roots, informational only:
- `Izenpe.com`: `additional-ca-certificates/2530cc8e98321502bad96f9b1fba1b099e2d299e0f4548bb914f363bc0d4531f.pem`, SPKI `952c2039c0243eb515dd73d83fc3643184874feb0862a9837731ed9b4742e17a`, RSA-4096, expires 2037-12-13.
- `ROOT CA QC IZENPE 2025`: `additional-ca-certificates/d2a934ae739b8b8b0c1d3857c324de595eeb1dcafd086a4a7e99dc08d77af0ca.pem`, SPKI `38c563767938b6666fadd7029f481841bcff0b08be810e7602e1ecc884c5bdc4`, P-384, expires 2050-09-25.

All CA → root links pass `openssl verify`.

```yaml
profile_id: izenpe-professional-sw-legacy
provider: Izenpe
display_name_es: "Certificado Profesional Cualificado (software)"
holder_role: professional   # natural person linked to an organization (organizationIdentifier present)
recommendation: exclude   # AN §3 defers professional profiles; technically browser-usable
confidence: high (official synthetic leaf decoded, chain verified in openssl and Go, live OCSP)
trust_anchors: [IZ-CCEER-L]   # both DER variants share one key; pin by SPKI
intermediates_needed: []
roots_above_anchor: [Izenpe.com]
leaf_policy_oids: ["1.3.6.1.4.1.14777.2.19.2", "0.4.0.194112.1.0"]   # v8.1; observed in profesional_sw_act.cer
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]   # critical, observed
eku_expected: [clientAuth, emailProtection]   # observed
leaf_key_algorithms: [RSA-2048 (kit, 2024), RSA-3072+ (v8.1 card row says "3072 mínimo")]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["bare 00000000T (kit)"], anchored_grammar: "^[0-9]{8}[A-Z]$|^[XYZ][0-9]{7}[A-Z]$ + checksum (bare, Izenpe-legacy-only)"}
  given_names: {location: "subject 2.5.4.42"}
  surnames: {location: "subject 2.5.4.4 = 'S1 S2'", quirks: "CN 'GIVEN S1 S2 - <ID>' (ignore)"}
  cross_checks: ["SAN directoryName 1.3.6.1.4.1.14777.0.{2 surname1, 3 surname2, 4 ID}; .0.1 given name ABSENT in kit; .0.5 org, .0.6 org CIF (not holder), .0.7 email, .0.9 dept", "2.5.4.97 VATES-<org>"]
  birth_date: {present: no, evidence: "kit leaf has no SDA; v8.1 lists dateOfBirth only for citizen profiles"}
revocation:
  ocsp: ["http://ocsp.izenpe.com"]
  responder_notes: "live: responder CN=ocsp.izenpe.com issued directly by CA (4), OCSPSigning+nocheck, notAfter 2027-06-05; act=good, rev=revoked 2024-05-29T14:43:10Z; nextUpdate +48 h; nonce echoed; verified"
  crl: ["http://crl.izenpe.com/cgi-bin/crl2"]
  intermediate_status: "CA (4) via OCSP http://ocsp.izenpe.com:8094 -> good (responder ocsp.izenpe.com issued by Izenpe.com); ARL http://crl.izenpe.com/cgi-bin/arl2"
test_certificate_traps: "kit identity 00000000T, NOMBRE/APELLIDOUNO/APELLIDODOS, org 'ENTIDAD PRUEBA SW' VATES-Q0000000J; kit fingerprints e.g. profesional_sw_act 06c81a7f70a8f15ef9d5c55eeb4b98eb3409059e4b67702fecf80febfa632c65, _rev a3c07e07e36f50680fda1d8c38edc113a33805760f569f452b304c81b9e9d9d9"
public_fixtures: "I4 kit (F6): 60 synthetic DER .cer, 30 active/revoked pairs, issued 2024-05 under the legacy hierarchy; active ones valid to 2027/2028. Not in the bundle. No 2025 ECC specimens."
gaps: ["NIE / passport encodings in bare form"]
sources: ["spec 974-1043", "F7 (Profesional sections)", "F6"]
```

```yaml
profile_id: izenpe-professional-sw-2025
provider: Izenpe
display_name_es: "Certificado Profesional Cualificado Software 2025"
holder_role: professional
recommendation: exclude   # deferred (AN §3)
confidence: medium (profile doc only; no specimen)
trust_anchors: [IZ-CCEER-2025]
intermediates_needed: []
roots_above_anchor: [ROOT CA QC IZENPE 2025]
leaf_policy_oids: ["1.3.6.1.4.1.14777.51.2.2", "0.4.0.194112.1.0"]
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]
eku_expected: [clientAuth]
leaf_key_algorithms: ["EC ≥256 (v8.1: 'ECC 256 bits mínimo')"]
identity: {personal_id: "subject 2.5.4.5 'DNI / NIE / NIF / PASS' (format unspecified)", given_names: 2.5.4.42, surnames: 2.5.4.4, cross_checks: "SAN 14777.0.{1,2,3,4}; .0.6 org CIF", birth_date: {present: no}}
revocation: {ocsp: ["http://ocsp.izenpe.eus"], crl: ["http://crl.izenpe.eus/crls/crlccer.crl (as printed in v8.1; the citizen row says crlcceer.crl, possible typo)"], intermediate_status: "CCEER2025 has NO OCSP AIA; CRL http://crl.izenpe.eus/crls/izqcroot.crl (327 B, 1 entry: serial F39007D47F6C6C60CD75CA692C902A72, revoked 2026-10-06, not CCEER2025/AAPPR2025; nextUpdate 2027-09-06; verified)"}
test_certificate_traps: "unknown for 2025 (kit predates it)"
public_fixtures: none
gaps: ["identifier prefix (bare vs IDCES-) in 2025 leaves", "exact CDP name"]
sources: ["F7 lines 2223-2280"]
```

```yaml
profile_id: izenpe-employee-sw-legacy   # 2025 twin: izenpe-employee-sw-2025 (OID .52.1.2, anchor IZ-AAPP-2025, EC ≥256, EKU clientAuth, CDP http://crl.izenpe.eus/crls/crlaapp.crl, OCSP http://ocsp.izenpe.eus)
provider: Izenpe
display_name_es: "Certificado de Personal de Entidades Públicas / Funcionario Cualificado (software)"
holder_role: public_employee
recommendation: exclude   # deferred (AN §3)
confidence: high legacy (pep_sw_act/_rev decoded and verified); medium 2025 (doc only)
trust_anchors: [IZ-AAPP-L]
intermediates_needed: []
leaf_policy_oids: ["1.3.6.1.4.1.14777.4.14.2", "0.4.0.194112.1.0", "2.16.724.1.3.5.7.2"]
key_usage_expected: [digitalSignature, nonRepudiation, keyEncipherment]
eku_expected: [clientAuth, emailProtection]
leaf_key_algorithms: [RSA-2048 (kit)]
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["IDCES-<DNI> (kit: IDCES-00000000T)"], anchored_grammar: "^IDCES-(DNI|NIE)$"}
  surnames: {location: "2.5.4.4 'S1 S2'", quirks: "CN 'GIVEN S1 S2 - <ID>'"}
  cross_checks: ["SAN directoryName 2.16.724.1.3.5.7.2.{6,7,8}; .4 (holder ID) OMITTED in the kit; .5 NIP, .9 email, .10 unit, .11 title"]
  birth_date: {present: no}
revocation: {ocsp: ["http://ocsp.izenpe.com"], crl: ["http://crl.izenpe.com/cgi-bin/crlscar2"], intermediate_status: "AAPP (2) has AIA http://ocsp.izenpe.com:8094 and CDP arl2 (same as CA (4))"}
test_certificate_traps: "kit pep_sw_act 8493c1fbaed52b93e55b6e62564a7600ad7e525a72c871fec6a4f0a13294d6de / pep_sw_rev 870d1a6083e0727937baaeefe05977e6ddd73487a4c13c24f78d74385dec845e; IDCES-00000000T"
public_fixtures: "F6 kit (legacy only)"
gaps: ["2025 specimen"]
sources: ["spec 1009", "F7 lines 2399-2456", "F6"]
```

`izenpe-representative-sw-{legacy,2025}`: **exclude** (role deferred). OIDs `.2.16`, `.2.17` (legacy, anchor IZ-CCEER-L) and `.51.3.2`, `.51.4.2` (anchor IZ-CCEER-2025). The kit leaf `representante_sw_act` (DER `489fbb1d48ff12cfca0d444bf69b7ad6261b2684739932499bf124b1ef8abfa2`) has:
- policies `.2.16`, `0.4.0.194112.1.0`, `2.16.724.1.3.5.8` (SPJ variant: `2.16.724.1.3.5.9`);
- EKU clientAuth plus `1.3.6.1.4.1.311.10.3.12`;
- serialNumber bare `00000000T`;
- CN `00000000T NOMBRE APELLIDOUNO (R: Q0000000J)`;
- a `description` attribute carrying registry data.

The holder ID must come only from `2.5.4.5`.

`izenpe-citizen-card` (`.2.18.1` / `.51.1.1`) and `izenpe-citizen-bakq` (`.2.18.3` / `.51.1.3`): **exclude**. These are a card and a centralized HSM (AN line 57-58). They are recorded here because they are the only Izenpe profiles that carry **date of birth**. The kit leaf `ciudadano_scard_act` (`ac68822a…`) and v8.1 lines 96/147/2106/2157 place it in SubjectDirectoryAttributes `2.5.29.9` → `id-pda-dateOfBirth 1.3.6.1.5.5.7.9.1`, encoded as GeneralizedTime (for example `20000529000000Z`). The same certificate uses a bare ID and the SAN `14777.0.{1,2,3,4}`.

`izenpe-nonqualified` (`.5.2.5`, `.5.2.5.4`, `.5.2.7.2`) and the legacy corporate rows: **exclude**. Their issuer, CCEENR `CA de Ciudadanos y Entidades (3)`, has no current TSL service identity. The Mobile kit leaf uses a P-256 key.

`izenpe-reject-classes`: reject the pseudonyms and seals listed at spec lines 989-991. Seals can carry a custodian DNI together with clientAuth.

---

## C. Camerfirma / InfoCert-Camerfirma (TSL provider index 11)

**Natural-person software products.** The CP v1.0 policy list (F8 line 814) says:

- Citizen: `.10.16.1.1.2` No-QSCD (2016 hierarchy) and `.10.21.1.1.2` No-QSCD (2024 hierarchy). The 2021 hierarchy has card (`.10.21.1.1.1`) and cloud (`.10.21.1.1.3`) only.
- The product page (F9) sells the citizen certificate in **"Formato Software"** for 35 € over **2 years**. The current citizen software certificate therefore comes from the 2024 hierarchy.

| ID | File | SHA-256 DER | SPKI SHA-256 | Key, not_after | TSL status |
|---|---|---|---|---|---|
| CF-QC-2024 | `service-identities/51583118e6c5e5d210df34dd3597f1136a5b16482218fcc2dd3b85f7a5c81cff.pem` | as name | `1d80af2b862f6b017242a3c68a3df6e68c9a7323b0e35388c7fadadbf77e78c7` | P-384, ecdsa-SHA384, pathlen 0, CA EKU **clientAuth + 1.2.840.113583.1.1.5 only**, 2040-02-16T11:55:23Z | 11/20 granted since 2024-10-16, ForeSignatures+ForeSeals |
| CF-NP-2016 | `service-identities/eedd457af1353d76f48e7c6123f39140e5f9a069ca51b43eea8615c9cec0d4bb.pem` | as name | `c865f0281f1de6fb0de8541c622979d3f3a1e121ee42271175c64b112e789e1d` | RSA-4096, **pathlen:2**, CA EKU emailProtection+clientAuth, 2040-03-09T08:48:09Z | 11/10 granted since 2016-06-30 |
| CF-QC-2021 | `service-identities/4d187d4e5bba7bbad422b75befb4dcb2179d1ccd115a18d2c8350fffac316b34.pem` | as name | `b74d10b04a7bf1e86362f0fa80820dfe68385a95e1b646210a08cf4464140291` | RSA-4096, pathlen 0, CA EKU emailProtection+clientAuth, 2037-10-16T15:12:16Z | 11/18 granted since 2023-01-31 |

Full subjects:
- CF-QC-2024: `C=ES, O=AC CAMERFIRMA S.A., organizationIdentifier=VATES-A82743287, CN=INFOCERT-CAMERFIRMA QUALIFIED CERTIFICATES - 2024`
- CF-NP-2016: `C=ES, L=MADRID, ST=MADRID, OU=see current address at https://www.camerfirma.com/address, OU=AC CAMERFIRMA FOR NATURAL PERSONS - 2016, serialNumber=A82743287, organizationIdentifier=VATES-A82743287, O=AC CAMERFIRMA S.A., CN=AC CAMERFIRMA FOR NATURAL PERSONS - 2016`
- CF-QC-2021: `C=ES, ST=MADRID, L=MADRID, O=AC CAMERFIRMA S.A., OU=PKI SERVICES, serialNumber=A82743287, organizationIdentifier=VATES-A82743287, CN=AC CAMERFIRMA QUALIFIED CERTIFICATES - 2021`

Roots, informational only:
- `INFOCERT-CAMERFIRMA CERTIFICATES 2024`: `5a81aba8…6cd1`, SPKI `27903329c11a85f21e215b72f9828b28c51a9c1437846a2b0f729ab7e36fdf91`, P-384, expires 2045-01-22.
- `CHAMBERS OF COMMERCE ROOT - 2016`: `04f1bec3…ad51`, SPKI `b89bcbb8acd474c1bea7dad65037f48dcecc9dfaa0612c3c2445956419df32fe`, RSA-4096, expires 2040-04-08.
- `CAMERFIRMA ROOT 2021`: `adfc9410…538e`, SPKI `370c4d8c3548ad0728ab3bbe237831c8836ba3be3e1d65e37f6ed580335c3933`, RSA-4096, expires 2045-10-13.

All three are in `additional-ca-certificates/`. Every CA → root link passes `openssl verify`.

```yaml
profile_id: camerfirma-citizen-sw-2024
provider: Camerfirma (InfoCert-Camerfirma)
display_name_es: "Certificado Cualificado de Ciudadano (software, No QSCD)"
holder_role: natural_person
recommendation: include-if-real-2024-specimen-and-product-onboarding   # AN §3: other issuers stay disabled; leaf grammar/AIA/CDP undocumented publicly
confidence: high (anchor, OID, documented KU/EKU); low (identity grammar, leaf AIA/CDP, birth date)
trust_anchors: [CF-QC-2024]
intermediates_needed: []
roots_above_anchor: [INFOCERT-CAMERFIRMA CERTIFICATES 2024]
leaf_policy_oids: ["1.3.6.1.4.1.17326.10.21.1.1.2"]   # note the '21' segment under the 2024 hierarchy (CP v1.0 §1.2); expect also 0.4.0.194112.1.0 (QCP-n, CP §1.3 text)
key_usage_expected: [digitalSignature, contentCommitment, keyEncipherment]   # critical; CP v1.0 §4.5.1 (F8 line 1551)
eku_expected: [emailProtection, clientAuth]   # CP table; the CA EKU lacks emailProtection (irrelevant for clientAuth under Go, see engine notes)
leaf_key_algorithms: "unknown (CA is P-384; leaf key policy in CPS v2.1 §6.1.5 not re-read)"
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["hypothesis from the 2021 sheet: IDCES-<DNI>, PNOES-<NIE/other NIF>; historical TINES-"], anchored_grammar: "do not enable until confirmed on a 2024 leaf"}
  given_names: {location: "subject 2.5.4.42 (2021 sheet)"}
  surnames: {location: "subject 2.5.4.4 (2021 sheet)", quirks: "CN may hold only surname1 / be truncated / carry (C:)/(R:)/(A:) suffixes"}
  cross_checks: ["2021 sheet: SAN directoryName 1.3.6.1.4.1.17326.30.{7 given, 8 surname1, 9 surname2 (may be empty), 10 type text}; unverified for 2024"]
  birth_date: {present: unknown}
revocation:
  ocsp: ["leaf AIA unknown (2021 leaves use http://ocspqc2021.ca.camerfirma.com); intermediate AIA http://ocsp.camerfirma.com"]
  responder_notes: "intermediate check live: responder 'OCSP RESPONDER INFOCERT-CAMERFIRMA CERTIFICATES 2024' issued by the 2024 root, nocheck; good; nextUpdate +1 h; nonce echoed; SHA-1 CertID; verified. CPS v2.1 §4.9.10 (spec): GET+POST, 1-h validity, 'unknown' after CA termination."
  crl: ["leaf CDP unknown; may be segmented like 2021 (http://crls.ca.camerfirma.com/qc2021/CRL$$.crl)"]
  intermediate_status: "OCSP above; CDP http://crl.ca.camerfirma.com/root_certificates_2024.crl + crl1 mirror"
test_certificate_traps: "CPS v2.1 §1.3.2.6 (spec 1146, not re-verified): NOMBRE / APELLIDO1 APELLIDO2 / 12345678Z (checksum-valid) / EMPRESA DE PRUEBAS / B-1234567R; legacy CPS 1.2.20: DE LA CÁMARA ESPAÑOL / 00000000T / [SOLO PRUEBAS]/[TEST ONLY]"
public_fixtures: "none found (bundle has none; camerfirma.com site search found no test-certificate page). Profile sheets on request: https://www.camerfirma.com/contacto-soporte, +34 91 136 91 05 (CP §3.1.1)"
gaps: ["everything leaf-level: subject grammar, SAN, AIA/CDP/partitioning, key algorithm, birth date"]
sources: ["spec 1045-1168", "F8 lines 640-650, 814, 1500-1551, 1255-1290", "F9"]
```

```yaml
profile_id: camerfirma-citizen-sw-2016
provider: Camerfirma
display_name_es: "Certificado Cualificado de Ciudadano (No QSCD), jerarquía 2016"
holder_role: natural_person
recommendation: include-if-still-valid-specimen   # 2-year leaves; whether 2016 issuance continued after 2024-10 is unknown -> otherwise exclude
confidence: medium (anchor, OID); low (identity)
trust_anchors: [CF-NP-2016]
intermediates_needed: []   # but the anchor has pathlen:2 -> require leaf.Issuer == anchor (chain length exactly 2)
roots_above_anchor: [CHAMBERS OF COMMERCE ROOT - 2016]
leaf_policy_oids: ["1.3.6.1.4.1.17326.10.16.1.1.2"]   # must NOT also contain 1.3.6.1.4.1.17326.99.18.1 (cloud conjunction)
key_usage_expected: [digitalSignature, contentCommitment, keyEncipherment]
eku_expected: [emailProtection, clientAuth]
leaf_key_algorithms: "unknown (RSA expected)"
identity:
  personal_id: {location: "subject 2.5.4.5", formats: ["unknown for citizen; 2016 employee leaves observed IDCES-<DNI>"]}
  surnames: {location: "2.5.4.4", quirks: "observed 2016 EMPLOYEE variant '<s1> <s2> - <bare DNI>' (spec 1131); do NOT generalize to citizen"}
  cross_checks: ["unknown for citizen"]
  birth_date: {present: unknown}
revocation:
  ocsp: ["http://ocsp.camerfirma.com (observed in 2016 employee leaves)"]
  crl: ["http://crl.camerfirma.com/ac_camerfirma_natural_persons-2016.crl", "http://crl1.camerfirma.com/ac_camerfirma_natural_persons-2016.crl"]
  intermediate_status: "live OCSP http://ocsp.camerfirma.com -> good, responder 'OCSP RESPONDER CHAMBERS OF COMMERCE ROOT - 2016' (issued by root, nocheck), nextUpdate +1 h, nonce echoed; CDP chambersofcommerceroot-2016.crl + crl1"
test_certificate_traps: same Camerfirma registry
public_fixtures: none (the spec's C9/C10 genuine employee leaves are excluded from the bundle by design)
gaps: ["any citizen 2016 leaf"]
sources: ["spec 1080-1081, 1121-1138, 1162", "F8 line 814"]
```

Other Camerfirma rows, documented only:

- `camerfirma-citizen-2021-card-cloud`: **exclude**. OIDs `.10.21.1.1.1` (card) and `.10.21.1.1.3` (cloud); anchor CF-QC-2021.
  - The identity mapping is exact from the 2021 sheet (spec 1101-1119).
  - Leaf OCSP is `http://ocspqc2021.ca.camerfirma.com`. Leaf CRLs are segmented, `CRL$$`, with one segment per 50,000 certificates.
  - Intermediate OCSP `http://ocsp2021.camerfirma.com` was checked live: good, responder `OCSP RESPONDER CAMERFIRMA ROOT 2021`, nextUpdate +1 h.
- `camerfirma-employee-medium-2016` (`.10.16.1.5.1.3.4.4`, CP: "QSCD Tarjeta/Token / No QSCD"), corporate and representative rows (2016 `.10.16.1.2.x`, `.10.16.1.3.x.x`; 2021 `.10.21.1.2-8.x`): **exclude**, deferred roles. Do not admit encryption-only certificates (`…4.3`).
- `camerfirma-global-2016` (`.20.16.1.1.1.1/.2`, `.20.16.1.1.2.1/.2`): **reject**. TSL service 11/12 `AC CAMERFIRMA GLOBAL FOR NATURAL PERSONS - 2016` has been withdrawn since 2017-07-21 (spec 1142).

---

## Generic engine implications

1. **EC-ACC negative serial.**
   - go1.27.3 `x509.ParseCertificate` rejects EC-ACC with `x509: negative serial number`. Only `GODEBUG=x509negativeserial=1` lets it through, and that relaxes parsing for the whole process.
   - Anchoring at the TSL service identity **EC-Ciutadania** avoids parsing EC-ACC: Go `Verify` accepts a non-self-signed root in `Roots`. The EC-Ciutadania leaf OCSP response verified with only EC-Ciutadania as anchor.
   - EC-ACC is still needed for the anchor's **own** status: both its OCSP responder ("Servei OCSP de EC-ACC") and its ARL are signed by EC-ACC.
   - Either treat TSL `granted` as the anchor status (spec §8.3), or verify with an offline-pinned EC-ACC SPKI (`b21d2a74…`) through a minimal parent `x509.Certificate{PublicKey,…}`. Do not turn on the GODEBUG.
2. **Pin issuing CAs, not roots, and require the exact chain shape `[leaf, anchor]`.**
   - CF-NP-2016 has `pathlen:2`. The Izenpe legacy CAs have no pathlen. The Izenpe 2025 root has already revoked one unrelated sub-CA (serial `F39007D4…`).
   - Anchoring at a root, or allowing extra intermediates, would admit unknown sub-CAs.
3. **SHA-1-signed CA certificates.** The TSL lists sha1WithRSA variants for the Izenpe legacy CAs (2626b195, 1f11a655), and EC-ACC is sha1-self-signed.
   - Go `Verify` rejects SHA-1 signatures on non-root certificates in a chain. Used as **anchors**, their own signature is never checked.
   - Key the anchor by SPKI; both variants share one key.
4. **CA certificates carry EKUs.** AOC A.1/A.2/A.3, Izenpe 2025, and Camerfirma 2016/2021/2024 all do.
   - Go checks EKU nesting across the whole chain, the anchor included. Call `Verify` with `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}`. Every anchor here permits clientAuth.
   - The Camerfirma 2024 leaf (documented EKU emailProtection+clientAuth) under a CA without emailProtection still passes for clientAuth. Do not add a stricter "every leaf EKU must be permitted" rule.
   - `ExtKeyUsageAny` would skip the purpose check entirely.
5. **Critical qcStatements on older idCAT leaves.** Profile v6.8 (2023-05-10) "marcó QCStatements como no crítica". Pre-2023 leaves that are still valid (5-year maximum) may carry a critical `1.3.6.1.5.5.7.1.3`.
   - Go places that in `UnhandledCriticalExtensions`, and `Verify` then fails.
   - If a fixture confirms it, parse the QC statements explicitly and remove that one OID from the slice before `Verify`. Make no other relaxation.
6. **Very large full CRLs.** EC-Ciutadania's CRL is 6.86 MB with 154k entries; A.2's is 1.0 MB with 21k.
   - The fetch size cap must be at least about 16 MB. Prefetch and cache per issuer. Go parses the big one in about 83 ms.
   - Prefer OCSP for interactive checks (AN §4.2). The CRL `nextUpdate` is +7 days while OCSP `nextUpdate` is +5 min, so the two freshness models differ.
7. **CRL scope.**
   - AOC CA CRLs have no IDP, so they are full CRLs.
   - `ec-acc.crl` has a **non-critical** IDP (RFC 5280 says it must be critical) whose URI is `http://epscd.catcert.net/crl/ec-acc.crl`. Scope matching must compare it with the CDP URIs inside the certificate, not with the URL that was fetched.
   - Camerfirma 2021 leaves use segmented CRLs (`CRL$$`): take the segment URI from the leaf, never "any segment".
   - Izenpe 2025 intermediates have CRL only, with no OCSP AIA.
8. **OCSP responders.** All four providers checked (AOC G2/G3, Izenpe legacy, Camerfirma 2016/2021/2024) use delegated responders issued **directly** by the CA whose certificates they answer for.
   - These responders carry EKU OCSPSigning and `id-pkix-ocsp-nocheck`. They have about 1-year validity, so they rotate: AOC's were valid 2026-02-17..2027-02-17, Izenpe's until 2027-06-05. Never pin them.
   - All echoed a nonce. All accepted SHA-1 CertID.
   - `nextUpdate` windows were AOC 5 min, Camerfirma 1 h, Izenpe 48 h.
   - Check explicitly that the responder certificate is issued by the leaf's issuer and has OCSPSigning. Do not assume `golang.org/x/crypto/ocsp` enforces the EKU.
   - For AOC, send one certificate per request: multi-certificate requests are answered by the root-level responder, which is not authorized for leaves.
9. **Endpoint inventory for SSRF allowlisting.**
   - AOC: `ocsp.catcert.cat`, `ocsp.aoc.cat`, `epscd.catcert.net`, `epscd.aoc.cat`. These are plain HTTP and serve the same bytes as their HTTPS forms. `epscd2.catcert.net` returned 403.
   - Izenpe: `ocsp.izenpe.com` and `:8094`, `crl.izenpe.com`, `ocsp.izenpe.eus`, `crl.izenpe.eus`.
   - Camerfirma: `ocsp.camerfirma.com`, `ocsp2021.camerfirma.com`, `ocspqc2021.ca.camerfirma.com`, `crl(1).camerfirma.com`, `crl(1).ca.camerfirma.com`, `crls.ca.camerfirma.com`.
10. **Dispatch on (anchor SPKI, exact policy OID).**
    - The same OID (`…15096.1.3.2.86.2`) spans G2 and G3.
    - Camerfirma's 2024 citizen OID carries a `.21` segment.
    - Leaves carry extra policies (`0.4.0.194112.1.0`, `2.16.724.1.3.5.7.2`, `2.16.724.1.3.5.8/9`). Match "the allowlisted OID is present", plus explicit `must_not_include` rules such as Camerfirma's cloud `.99.18.1`.
11. **Identifier grammars differ per profile, so there is no global prefix rule.**
    - idCAT: ETSI `IDCES-`.
    - Izenpe legacy citizen, professional and representative: **bare** `00000000T`.
    - Izenpe employee: `IDCES-`.
    - Camerfirma 2021: `IDCES-` / `PNOES-`.
    - The predecessor's unanchored `FindString` regexes for DNI / NIE / old 9-digit NIE / passport (`idcat.go` lines 34-51) must not be reused.
12. **Name encoding.**
    - AOC CA DNs contain UTF8 non-ASCII text (`Públics`, `Certificació`). Profile serialNumbers are PrintableString.
    - Parse `RawSubject` by OID, keeping duplicate and multi-valued RDNs. Izenpe representative subjects add `description` and put the ID inside the CN.
    - Izenpe v8.1 OU texts contain typos ("zuriatgiria", "Ziertagiri"), so never match on OU or CN text.
    - AOC TSL qualifier URNs carry trailing spaces.
13. **SubjectDirectoryAttributes** (`2.5.29.9` / `1.3.6.1.5.5.7.9.1` GeneralizedTime) is the date-of-birth carrier at Izenpe (citizen profiles only). None of the profiles recommended for inclusion is documented to carry a birth date, so the birth-date output will normally be empty.
14. **Test-identity registry, versioned.**
    - AOC `99949992L` (NOMDOS / ESPECIMENDOS) and `00000000T`.
    - Izenpe kit `00000000T` with org `Q0000000J`, plus the 60 kit fingerprints.
    - Camerfirma `12345678Z` (plus EMPRESA DE PRUEBAS / B-1234567R), and the legacy `00000000T` / `[TEST ONLY]`.
    - All of these pass checksum and chain validation.
15. **TLS acceptable-CA list.** Include the anchor DNs: `EC-Ciutadania` and `SubCA CIUTADANIA Q (G3) A.2`. The leaf's issuer is the anchor itself, so browser filtering lines up.
    - If G3 idCAT leaves are P-384, CertificateVerify uses `ecdsa_secp384r1_sha384`.
    - RSA leaves under TLS 1.3 need RSA-PSS. Software keys in the OS stores support it, but confirm on the browser matrix.

## Corrections and additions to the spec

- §1.5: the A.3 certificate is in the bundle (`service-identities/783ed47b…`).
- §1.3/§1.4: the idCAT `SN` never documents a DNI suffix (v7.1/v7.4). That suffix belongs to T-CAT/T-CATP/seal profiles ≤v7.1; in idCAT the `- DNI` sits in the CN.
- §1.6: `http://epscd.catcert.net/crl/*` still serves the same bytes as `https://epscd.aoc.cat/crl/*`. EC-Ciutadania's own CDP points to catcert.net.
- §2.4 / §5: live Izenpe OCSP **did** work from this network (active = good, revoked = revoked), as did AOC and Camerfirma intermediate OCSP.
- Izenpe v8.1 professional SW 2025 CDP `crlccer.crl` versus citizen `crlcceer.crl`: verify which one is real.
