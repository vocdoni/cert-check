# Certificate Authentication Checker: design

Status: approved (2026-10-31)   Class: architectural
Owner decisions so far:
- 2026-10-30 (request): Go backend + very simple Vocdoni-branded web UI. One page titled
  "Certificate Authentication Checker", a selector of supported certificates and an
  "Authenticate" button; on success a "Success" page with the data the backend extracted (DNI/NIE,
  given name + surnames, birth date if present). Backend verifies validity and revocation.
  Support as many official Spanish certificates as possible, idCAT and FNMT mandatory.
  Production quality: "we must not fail and it must work".
- 2026-10-30 (request): handler-like Go packages importable later by Vocdoni's CSP. Use the
  vocdoni-go skills. Private repo `github.com/vocdoni/cert-check`; Railway project
  `CertificateCheck`; domain `cert-check.vocdoni.dev`; Railway always deploys latest `main`;
  any GitHub workflow runs on self-hosted runners.
- 2026-10-30 (Q1): mTLS hosting = Railway TCP proxy (Railway-assigned non-443 port), Go
  terminates TLS, Let's Encrypt certificate via ACME DNS-01 with a Cloudflare API token scoped to
  DNS edit on `vocdoni.dev`; per-provider auth subdomains `<provider>.auth.cert-check.vocdoni.dev`.
- 2026-10-30 (Q2): provider scope = verified providers (FNMT, idCAT, ACCV, DIGITEL, Bewor,
  Sectigo) plus a "Beta" group (FNMT representative/employee, Firmaprofesional, ANF, Uanataca,
  SIGNE, Lleidanet, DNIe).
- 2026-10-30 (Q3): auth listener TLS 1.2 by default (D2), switch for 1.3.
- 2026-10-31: spec approved; Cloudflare token scope = zone-wide `vocdoni.dev` (risk accepted, delegation not used).
- 2026-10-30 (mid-audit request): on error, show a detailed diagnostic report that is easy to copy/paste for Vocdoni support.

## Problem

Vocdoni must show a prospective client (online voting with Spanish official certificates) that
its backend can authenticate holders of Spanish personal certificates in an ordinary browser,
validate them correctly (trust, profile, validity, revocation) and extract the person's identity.

The only existing code is the old blind-csp idCAT handler
(`blind-csp/handlers/idcathandler/idcat.go`). Its defects are catalogued in the research spec
(`docs/Vocdoni_CSP_Handoff/Vocdoni_Spanish_Certificate_CSP_Implementation_Specification.md`
§13, lines 443–463), among them:

- It installs CA certificates downloaded over plain HTTP as trust anchors (`idcat.go:172-184`,
  `getCAcertificate` at `idcat.go:210-221`).
- It classifies the issuer by a substring of the issuer DN (`idcat.go:24-25, 281`).
- It covers only the two old G2 CAs and misses AOC G3 (`idcat.go:62-73`).
- It finds the DNI with unanchored regexes (`idcat.go:33-52`).
- Revocation is CRL-only with broken freshness handling and no OCSP (`idcat.go:223-241, 300`).
- It accepts any EKU.

There is no repository for the new work yet. The research bundle in
`/home/p4u/certificate_poc/docs` (TSL inventory, CA certificates, per-provider profile research)
is the evidence base. The product note `Vocdoni_CSP_Authentication_Only_Agent_Note.md` (the
"note") fixes the transport to native browser TLS client authentication and takes precedence
over the research spec on transport and launch scope.

## Goals

1. **Browser-native possession proof.** The user authenticates with a certificate already
   installed in their browser/OS store through native TLS client authentication, requested in the
   initial handshake on a dedicated host. No upload of a certificate, key or password; no signing
   app, extension or helper.
2. **Correct validation.** A success result only for a certificate that:
   - chains to a pinned, reviewed trust anchor of the selected provider;
   - carries an exact allowlisted policy OID of an enabled profile;
   - is suitable for TLS client authentication (KU/EKU rules per profile) and uses an acceptable
     algorithm;
   - is currently within validity, is not a known test or specimen certificate;
   - has fresh, cryptographically verified revocation status `good` (OCSP preferred, signed CRL
     fallback).
3. **Typed identity.** From validated fields only, under the matched profile's anchored grammar,
   extract:
   - the identity document as a type (DNI or NIE), country (ES) and number;
   - given names and surnames, plus first and second surname when the profile provides them
     separately;
   - the full name;
   - the birth date when the certificate carries it.

   Each value records its source field.
4. **Session-bound flow.** One-use random state, one-use authorization code bound to the
   initiating browser by an HttpOnly cookie, fixed callback, 5-minute lifetime, and no DNI, names
   or certificate data in any URL.
5. **Minimal branded UI.**
   - Vocdoni brand, title "Certificate Authentication Checker", a native selector of supported
     certificates and an "Authenticate" button.
   - After success, a page titled "Success" listing the extracted data.
   - Clear recovery guidance on every failure.
6. **Importable packages.** The validation engine is a set of public Go packages (`certauth/...`)
   with a handler-like entry point that a future CSP can call with an `*http.Request` or
   `*tls.ConnectionState`. App-specific code (transactions, UI, ACME) stays in `internal/`.
7. **Deployed.**
   - Railway project `CertificateCheck`: UI at `https://cert-check.vocdoni.dev`, authentication at
     `https://<provider>.auth.cert-check.vocdoni.dev:<railway-tcp-port>`.
   - Railway auto-deploys `main` of `github.com/vocdoni/cert-check` after CI passes.
   - CI runs on the org's self-hosted runners.
8. **Provider coverage.** Every profile in the scope table (section "Provider profiles") is
   enabled with pinned anchors, exact OIDs, identity grammar and revocation endpoints, plus a test
   per profile.

## Non-goals

- Census matching, credential issuance, blind signatures, any persistence of identities. The
  checker displays the result to the person who authenticated and forgets it.
- Live LOTL/TSL XML-signature import and refresh (deviation D1). Anchors are pinned at build time
  from the research bundle, cross-checked against the TSL inventory.
- Signed-challenge/AutoFirma, CMS, remote/cloud signing connectors, Cl@ve, idCAT Mòbil.
- Smart-card onboarding. DNIe (if enabled) works only when the user's browser can already use the
  card. We add no drivers or instructions beyond a one-line hint.
- High availability. One replica; in-memory state; a restart drops in-flight attempts (users
  retry).
- Internationalisation. UI in English (the requested title is English); provider names are in
  their official form.
- Admin UI, metrics backend, analytics, cookies other than the transaction cookie.

## Current state

- No `cert-check` code exists. The repository is initialised at
  `/home/p4u/certificate_poc/cert-check` (empty, branch `main`).
- Predecessor: `blind-csp/handlers/idcathandler/idcat.go` and `blind-csp/certvalid/`. These are
  reference only; nothing is reused (defects above).
- Research inputs:
  - `docs/Vocdoni_CSP_Handoff/service-identities/*.pem`: 134 CA certificates that are current TSL
    service digital identities.
  - `additional-ca-certificates/*.pem`: 70 more.
  - `spanish_tsl_inventory_2026-10-30.json`: TSL `TSL20260924`, sequence 189, next update
    2027-03-21. It lives outside this repository; see "Profile registry" for the in-repo copy.
  - `policy_candidates/*.json` and the evidence files.
  - Per-provider digests extracted for this project, in `docs/research/appendix-*.md` of this repo.
- Toolchain: Go 1.27.3 locally.
- Verified Go stdlib facts:
  - The TLS server sends `ClientCAs.Subjects()` as `certificate_authorities` for every
    `ClientAuth` mode that requests a certificate (`>= RequestClientCert`;
    `crypto/tls/handshake_server.go:654-671`, `handshake_server_tls13.go:840-841`).
  - `SessionTicketsDisabled` disables resumption (`handshake_server.go:450, 602`).
  - `x509.ParseCertificate` rejects negative serials unless `GODEBUG=x509negativeserial=1`
    (`crypto/x509/parser.go:962-1011`).
  - `Verify` checks EKU nesting over the whole chain, root included
    (`crypto/x509/verify.go:994-1035`).
- Railway facts:
  - The HTTP edge terminates TLS on 443 and cannot request client certificates (Railway staff
    answer, Central Station thread "Does Railway TCP Proxy support end-to-end mTLS…").
  - The TCP proxy forwards raw TCP on a Railway-assigned port, supports a custom-domain CNAME
    (Cloudflare must be "DNS only") and can coexist with an HTTP domain on the same service
    (docs.railway.com/networking/tcp-proxy).
  - It load-balances randomly across replicas.
- DNS for `vocdoni.dev` is on Cloudflare (`dig NS`).
- Org self-hosted runners `z4`, `z5`, `z7-2` (labels `self-hosted, Linux, X64, z, ci`) are in
  runner group `Default` (visibility all).
- The Railway GitHub app is installed on the vocdoni org: service `rocketchat/meet-bot` deploys
  from `vocdoni/rocket-meet-bot@main`.

## Design

### Topology

```
                     ┌──────────────── Railway service "cert-check" (1 replica) ────────────────┐
Browser ──HTTPS 443──▶ Railway HTTP edge ──HTTP──▶ :8080  main listener (UI + JSON API)          │
   │                                               │  shared in-memory transaction store        │
   └──TLS :NNNNN──▶ Railway TCP proxy ──raw TCP──▶ :8443  auth listener (Go terminates TLS+mTLS) │
                                                   │  certmagic cert *.auth.cert-check.vocdoni.dev│
                     └───────────── volume /data (ACME account + certificate storage) ───────────┘
Outbound: OCSP/CRL (HTTP, allowlisted hosts), ACME (Let's Encrypt), Cloudflare DNS API.
```

DNS (Cloudflare, both "DNS only"):
- `cert-check.vocdoni.dev` CNAME → Railway custom-domain target, plus Railway's verification TXT
  record if it asks for one.
- `*.auth.cert-check.vocdoni.dev` CNAME → `<x>.proxy.rlwy.net`.

### Authentication flow

1. UI `GET /` loads providers from `GET /api/v1/providers`. The user picks a provider and presses
   **Authenticate**.
2. UI `POST /api/v1/transactions {"provider":"<id>"}`. The server creates a transaction and:
   - sets the cookie
     `__Host-certcheck_tx=<cookie secret>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300`;
   - returns `{"authUrl":"https://<id>.auth.<authDomain>:<port>/v1/authenticate?state=<state>","expiresAt":…}`.
3. UI performs a top-level navigation to `authUrl`. TLS handshake on the auth listener:
   - SNI `<id>.auth.<authDomain>` selects the provider's TLS config.
   - `CertificateRequest` lists only that provider's CA subjects.
   - The browser shows its certificate picker and proves possession of the key (CertificateVerify,
     checked by Go).
4. `GET /v1/authenticate?state=…` on the auth listener:
   - Atomically consumes the state; it must exist, be unexpired, be unused and belong to the SNI
     provider.
   - Runs `certauth` validation on the peer chain and stores the result, success or typed error,
     in the transaction.
   - Issues a one-use code and answers `303 See Other` to `<publicURL>/#code=<code>`. The base is
     fixed by configuration, never taken from the request.
   - Unknown, expired or used state: `303 See Other` to
     `<publicURL>/#error=invalid_state&diag=<diagnosticId>`. The diagnostic ID is logged with the
     SNI, the reason and the time. The auth listener never renders HTML: every user-facing
     message, including the copyable diagnostic report, comes from the main UI.
5. UI reads `location.hash`, clears it with `history.replaceState(null, '', '/')`, and:
   - with `#code=<code>`, calls `POST /api/v1/transactions/redeem {"code":"…"}`. The browser
     sends the cookie.
   - with `#error=<code>&diag=<id>`, renders the error view directly. The report holds the
     diagnostic ID, error code, time, user agent and the pending-attempt data from
     `sessionStorage`; the server log holds the rest under the same ID.
   - The server consumes the code atomically. The code's transaction must equal the cookie's
     transaction (constant-time compare), otherwise the generic error `invalid_or_expired`.
   - It returns the result, deletes the transaction and expires the cookie.
6. UI renders **Success** with the identity data, or an error view with recovery guidance.

Secrets (cookie secret, state, code) are 32 bytes from `crypto/rand`, base64url without padding.
The store keys them by SHA-256 so raw secrets are never retained.

### Packages and public API

Module `github.com/vocdoni/cert-check`, `go 1.27`.

| Package | Role |
|---|---|
| `certauth` | Public entry point. `Checker`, `Result`, `Identity`, `Document`, `RevocationInfo`, typed `*Error` with `Code`. Orchestrates the pipeline. |
| `certauth/profiles` | Profile registry types, embedded pinned anchors (`anchors/*.pem`, fingerprints pinned in Go source and checked at load), the production `Default()` registry, test-certificate markers. |
| `certauth/identity` | Strict RDN parsing of `RawSubject` (duplicates and multi-valued RDNs preserved), SAN directoryName decoding, SubjectDirectoryAttributes `dateOfBirth`, DNI/NIE validation, name normalisation (NFC), per-profile identity adapters. |
| `certauth/revocation` | Safe fetcher (scheme/host allowlist, private-IP block, size/time bounds, redirect control), OCSP request/verify, CRL verify with scope checks, bounded caches, explicit status model. `Check` takes the issuer from the caller's verified chain; it never derives it from client-supplied material. |
| `certauth/tlsauth` | Handler-like integration: `ServerConfig(...) *tls.Config` with SNI→provider, `ClientCAs`, TLS policy, tickets off, `RequestClientCert`; `Handler.Authenticate(r *http.Request) (*certauth.Result, error)` resolving the provider from `r.TLS.ServerName`. This is the unit a future CSP imports. |
| `internal/server` | Main and auth HTTP handlers, transaction store, rate limiting, security headers, health/readiness. |
| `internal/acme` | certmagic configuration, DNS-01 via `libdns/cloudflare`, storage under the data dir; static cert/key alternative for local dev and tests. |
| `internal/config` | Environment configuration with validation. |
| `web` | Embedded static UI (HTML/CSS/JS, fonts, logo), no build step. |
| `cmd/cert-check` | `main`: wiring, graceful shutdown. |

Core signatures (names are binding for the plan; field lists may grow):

```go
package certauth

type Checker struct{ /* registry, revocation checker, clock */ }

type Options struct {
    Registry   *profiles.Registry   // required
    Revocation *revocation.Checker  // required
    Now        func() time.Time     // nil = time.Now
    MaxChainLen int                 // 0 = 10
}

func NewChecker(o Options) (*Checker, error)
func (c *Checker) Providers() []profiles.Provider
func (c *Checker) ClientCAs(providerID string) (*x509.CertPool, error)
func (c *Checker) Check(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error)

type Result struct {
    Provider    profiles.ProviderInfo
    Profile     profiles.ProfileInfo   // ID, Name, HolderRole
    Identity    Identity
    Certificate CertificateInfo        // subject (RFC 4514), issuer CN, serial hex, validity, SHA-256, key algorithm
    Revocation  RevocationInfo         // status, method (ocsp|crl), checkedAt, thisUpdate, nextUpdate, source host
    ValidatedAt time.Time
    Diagnostics Diagnostics        // session-bound report, see "Diagnostics and support report"
}

type Identity struct {
    Document      Document   // Type: "DNI"|"NIE"; Country: "ES"; Number; Raw; Source ("subject.2.5.4.5")
    GivenNames    string
    Surnames      string     // complete family names as certified
    FirstSurname  string     // "" when the profile does not provide it separately
    SecondSurname string
    FullName      string
    BirthDate     *civil date (YYYY-MM-DD) or nil
    Sources       map[string]string // field -> provenance
}

type Error struct {
    Code        ErrorCode
    Retryable   bool
    Detail      string       // internal, never PII
    Diagnostics Diagnostics  // session-bound report, see "Diagnostics and support report"
}
```

`ErrorCode` values, each mapped to a UI message:
- `no_certificate`
- `provider_mismatch`
- `untrusted_issuer`
- `invalid_chain`
- `expired`
- `not_yet_valid`
- `unsupported_profile` (no allowlisted policy OID)
- `unsupported_purpose` (KU/EKU)
- `weak_algorithm`
- `test_certificate`
- `identity_invalid` (grammar, checksum or cross-field disagreement)
- `identity_unsupported_document` (valid certificate whose identifier is not a Spanish DNI/NIE,
  e.g. a foreign passport)
- `revoked` (includes certificateHold)
- `revocation_unknown`
- `revocation_unavailable` (retryable)
- `internal` (retryable)

### Profile registry

A **provider** is a selectable UI entry and an auth subdomain (`fnmt`, `idcat`, …). It groups one
or more **profiles**. A profile is a versioned, exact allowlist entry:

```go
type Profile struct {
    ID             string        // e.g. "fnmt-citizen-g2-v1"
    ProviderID     string
    Name           string
    HolderRole     Role          // NaturalPerson | Representative | PublicEmployee
    Anchors        []Anchor      // pinned: embedded PEM + SHA-256(DER) + SPKI SHA-256; issuing CA(s)
    Intermediates  []Anchor      // pinned CAs between anchor and leaf, if any (usually none)
    PolicyOIDs     []string      // exact; leaf must assert at least one; no arcs/wildcards
    KeyUsage       KURule        // e.g. require digitalSignature
    EKU            EKURule       // RequireClientAuthIfPresent | RequireClientAuth | MustBeAbsentOrClientAuth...
    Algorithms     AlgPolicy     // default: RSA>=2048, ECDSA P-256/P-384/P-521, SHA-256+ signatures
    Identity       IdentityAdapter // anchored grammar for this profile
    Revocation     RevocationPolicy // allowed OCSP/CRL hosts, OCSP-first, no-nextUpdate max age, CRL allowed?
    TestMarkers    []TestMarker  // fingerprints/subject markers of known specimens to reject
}
```

Rules:
- An anchor is the certificate the TSL names as the service digital identity, normally the
  issuing CA. Pinning the issuing CA means `Verify` never needs to parse higher roots. This
  avoids the EC-ACC root's negative serial. It is not used to bypass leaf checks.
- At startup the registry:
  - parses every embedded anchor;
  - checks its SHA-256 against the pin (mismatch = fatal);
  - checks it is a CA (`BasicConstraints CA:TRUE`) and that its validity covers now;
  - disables a profile whose anchors have all expired, logging a warning (for example ACCVCA-120
    after 2026-12-31).
- `ClientCAs(provider)` holds the anchors and intermediates of that provider's enabled profiles.
- A unit test asserts that every anchor fingerprint appears in
  `spanish_tsl_inventory_2026-10-30.json` with a granted CA/QC status, or in a reviewed exception
  list. The exception list holds intermediates only.
- `spanish_tsl_inventory_2026-10-30.json` is copied verbatim to `certauth/profiles/testdata/`
  with its SHA-256 recorded in `certauth/profiles/testdata/SOURCES.md`; the test reads it from
  there.

### Validation pipeline (`Checker.Check`)

Order matters. Each step fails closed with a typed error.

1. **Bounds.**
   - Chain length 1..`MaxChainLen`, each DER at most 16 KiB.
   - Empty chain → `no_certificate`.
   - Unknown provider → `provider_mismatch`.
2. **Algorithms (before path building).** Leaf key: RSA ≥ 2048 bits, or ECDSA P-256/P-384/
   P-521 (per-profile `MinRSABits` override only where documented). Leaf signature algorithm:
   SHA-256 or stronger. Failure → `weak_algorithm`. This runs first because Go reports a
   SHA-1 leaf signature inside `Verify` as `UnknownAuthorityError`, not as a distinct error.
3. **Path.** For each enabled profile of the provider, run `leaf.Verify` with:
   - `Roots` = the profile's anchors;
   - `Intermediates` = the profile's pinned intermediates **only**. Client-sent certificates beyond
     the leaf are ignored for path building, so a client cannot route through an unknown sub-CA
     (some CAs allow sub-CAs: Camerfirma 2016 has `pathlen:2`). Every verified chain therefore
     has the shape `leaf → pinned intermediates → anchor`.
   - `CurrentTime = now`;
   - `KeyUsages = [ExtKeyUsageClientAuth]`. Go enforces EKU nesting over the whole chain.
     Research verified that every in-scope anchor either has no EKU or includes clientAuth
     (FNMT G2 and the ACCV CLIENTE CAs carry EKU lists with clientAuth).

   Go treats an absent leaf EKU as "any", so step 5 applies the profile's stricter leaf EKU rule.
   The candidates are the profiles whose path verifies. None → map the `x509` error:
   - `CertificateInvalidError{Reason: Expired}`: if `now` is before `leaf.NotBefore` →
     `not_yet_valid`; if after `leaf.NotAfter` → `expired`; otherwise the failing certificate
     is an anchor or intermediate → `invalid_chain` (Go uses `Expired` for every date failure
     and for every certificate in the chain);
   - `UnknownAuthorityError`: if the leaf verifies (same options) against the union of all
     enabled providers' anchors → `provider_mismatch`, else `untrusted_issuer`;
   - `CertificateInvalidError{Reason: IncompatibleUsage}` → `unsupported_purpose`;
   - `UnhandledCriticalExtension` → `invalid_chain` (Detail names the OID; the step-5
     exception mechanism runs before `Verify`, so this only fires for unlisted OIDs);
   - anything else → `invalid_chain`.
4. **Profile.** The leaf asserts at least one OID of exactly one candidate profile, read from
   `leaf.Policies`. Zero profiles → `unsupported_profile`. More than one profile (two profiles
   sharing a key under distinct OIDs, both asserted) → `unsupported_profile` as well.
5. **Purpose.**
   - KeyUsage must include `digitalSignature` when the extension is present. An absent KU is
     allowed only if the profile says so.
   - EKU follows the profile rule. The default, `RequireClientAuth`, needs the EKU extension
     present and containing `clientAuth`: every FNMT, idCAT and ACCV citizen profile documents it.
     `AllowAbsent` (EKU absent, or present with `clientAuth`) is used only by profiles that
     document no EKU (DNIe authentication).
   - No unknown critical extensions: Go's `Verify` already rejects unhandled critical extensions,
     and a test asserts it.
   - Exception mechanism, profile-scoped. A profile may list `HandledCriticalExtensions` (OIDs)
     that our code parses and validates itself.
     - Only listed OIDs are removed from a **copy** of the leaf's `UnhandledCriticalExtensions`
       before `Verify` (step 3); the signature input (`RawTBSCertificate`) is untouched.
     - Each listed OID needs a parser that must succeed (malformed → `invalid_chain`).
     - First and only planned use: `qcStatements` (1.3.6.1.5.5.7.1.3) on `aoc-idcat-g2`. Leaves
       issued before AOC profile v6.8 (2023-05-10) may mark it critical, and they can still be
       valid until 2028.
     - The DNIe `personalDataInfo` (2.16.724.1.2.2.4.1) is added only if a fixture shows it
       critical.
6. **Test certificates.** Reject `test_certificate` when the leaf matches a profile marker:
   - fingerprint;
   - exact subject marker combination documented by the issuer.
7. **Identity.** The profile adapter extracts the typed identity (see "Identity extraction"). Any
   grammar failure, checksum failure or disagreement between duplicated fields →
   `identity_invalid`.
7b. **Reserved identities.** The extracted document number and the name markers are checked
   against the reserved-identity registry → `test_certificate`.
8. **Revocation.** Let `chain` be the single verified chain returned by step 3
   (`[leaf, pinned intermediates…, anchor]`). Call
   `revocation.Checker.Check(ctx, chain[0], chain[1], profile.Revocation)`. `chain[1]` is the
   only certificate used for CertID construction, OCSP responder authorization and CRL
   signature/issuer checks. `r.TLS.PeerCertificates[1:]` is never read after step 1, except to
   echo subject and issuer in the diagnostic report. When a profile pins intermediates, every
   `chain[i]` with `0 < i < len(chain)-1` is checked the same way with `chain[i+1]` as issuer.
   Anchors themselves are governed by the pinned trust configuration (D1). The result must be
   `good` for every checked certificate.
9. **Result.** Assembled with `ValidatedAt = now`.

Identity (steps 7 and 7b) runs before revocation so a malformed certificate is rejected without
network traffic. The result is never returned before step 8 succeeds.

### Revocation

Status model: `good | revoked | unknown | unavailable | stale | invalid_evidence |
unsupported_method`. Only `good` passes. Errors map as follows:
- `revoked` → `revoked`;
- `unknown` → `revocation_unknown`;
- `unavailable` and `stale` → `revocation_unavailable` (retryable);
- `invalid_evidence` → `revocation_unavailable` (retryable), with a warning logged.

**Order.**
1. OCSP, using the leaf AIA URLs whose host is in the profile allowlist.
2. If OCSP is `unavailable`, `stale`, `invalid_evidence` or `unsupported_method` (never after
   `revoked` or `unknown`), a signed CRL from the leaf CDP URLs whose host is in the
   allowlist, when the profile permits CRL.

If the leaf has no OCSP AIA URL on an allowlisted host, OCSP yields `unsupported_method` and
the CRL step runs when permitted; if neither method is usable → `unavailable` →
`revocation_unavailable`.

**OCSP.** Request and response are encoded and decoded by our own `cryptobyte` code in
`certauth/revocation` (RFC 6960 §4.1 `OCSPRequest`, §4.2 `BasicOCSPResponse`).
`golang.org/x/crypto/ocsp` is not used: its parser exposes neither
`ResponseData.responseExtensions` (where the nonce comes back) nor any embedded certificate
beyond the first, and it checks neither the responder's EKU, validity nor the ResponderID
binding. The parser yields: responderID (byName DER or byKey SHA-1), producedAt, every
SingleResponse (CertID hash algorithm, issuerNameHash, issuerKeyHash, serial, status,
revocationTime/reason, thisUpdate, optional nextUpdate, singleExtensions), responseExtensions
(nonce 1.3.6.1.5.5.7.48.1.2) and every embedded certificate. An unknown critical single- or
response-level extension → `invalid_evidence`. Exactly one SingleResponse must match the
requested CertID.
- **Request.** Built by our own ASN.1 encoding: CertID from the actual issuer (SHA-1 CertID
  hashing is allowed; it is not a signature algorithm), plus the nonce extension when required.
  Sent by HTTP POST `application/ocsp-request`.
- **Signer.** The response signer must be either:
  - the issuer itself; or
  - a responder certificate directly issued by the issuer, with `id-kp-OCSPSigning`, valid now,
    whose signature verifies against the issuer. `id-pkix-ocsp-nocheck` is honoured only for that
    responder.

  The ResponderID (byName or byKey) must identify the certificate that verifies the signature.
  Responder certificates rotate (the FNMT G2 responder expires 2026-11-25; DNIe rotates every
  6 months), so they are never pinned. Anything else → `invalid_evidence`.
- **CertID.** Serial plus issuer hashes must match.
- **Freshness.** `thisUpdate ≤ now + 5m`. If `nextUpdate` is present it must be `≥ now`, and no
  extra age limit applies: ACCV's CRL-backed responses have `thisUpdate` about 1 h old and a
  3-day window. If `nextUpdate` is absent, `thisUpdate ≥ now − 15m` (profile override allowed
  with a documented reason).
- **Nonce.** Send a 32-byte nonce when the profile marks the responder nonce-capable, and require
  the same nonce back; a missing or different nonce → `invalid_evidence`. All FNMT, DNIe and
  ACCV responders echo nonces (checked live 2026-10-30); the live probe of 2026-10-31 saw the
  idCAT (EC-Ciutadania), DIGITEL, Bewor, ANF and Uanataca responders echo them too. Every profile
  requires the nonce except Sectigo and Firmaprofesional (no nonce back; freshness only); SIGNE
  and Lleidanet are CRL-only.
- **Non-issued serials.** Responders answer a never-issued serial with
  `revoked/certificateHold/1970-01-01` (RFC 6960 §2.2). It is mapped to `revoked` with no "retry
  later" UX.
- Cache `good` for min(5 min, nextUpdate − now). OCSP cache key: (SHA-256 of issuer DER, serial
  hex); a cached `good` is reused only within min(5 min, nextUpdate − now) of its own
  `thisUpdate`. Never cache `unknown`, `unavailable` or invalid evidence. `revoked` may be
  cached until nextUpdate.

**CRL:**
- Fetched only from allowlisted CDP hosts.
- `x509.ParseRevocationList`; issuer and signature checks are in the Issuer bullet below.
- `thisUpdate ≤ now + 5m` and `nextUpdate ≥ now`; a missing nextUpdate → `stale`.
- Scope. If the CRL carries IssuingDistributionPoint: at least one GeneralName of its
  `distributionPoint.fullName` must byte-equal one GeneralName of the DistributionPoint of the
  checked certificate's CDP extension from which the fetch URL was taken (RFC 5280
  §6.3.3 b.2.i). The comparison uses the certificate's CDP names, never the final URL after
  redirects (ACCV and DNIe redirect). `nameRelativeToCRLIssuer` → `unsupported_method`.
  For a leaf check, `onlyContainsCACerts`, `onlyContainsAttributeCerts`, `indirectCRL` or
  `onlySomeReasons` → `unsupported_method`. For a pinned-intermediate check (DNIe), an ARL with
  `onlyContainsCACerts` is accepted (AC RAIZ DNIE 2 sets it), and `onlyContainsUserCerts` →
  `unsupported_method`. FNMT CRLs are partitioned (`CRLU<n>.crl`, sparse numbers) and carry a
  critical IDP naming the partition; only the leaf's CDP names are used and partitions are never
  enumerated.
- Distribution points are walked in certificate order. A leaf is `good` at the first CRL that
  covers it and does not list it. A pinned intermediate is checked against every usable
  allowlisted distribution point and is `good` only when all of them answer `good`; `revoked`
  from any wins. AC DNIE 005/006 name the empty, unscoped root `CRL.crl` before `ARL.crl`, and
  AC RAIZ DNIE 2 publishes CA revocations in the ARL only.
- Issuer: `bytes.Equal(crl.RawIssuer, issuer.RawSubject)` on DER, then
  `crl.CheckSignatureFrom(issuer)`.
- Criticality: Go's `ParseRevocationList` stores CRL and CRL-entry extensions without enforcing
  criticality (`crypto/x509/parser.go:1190+`). Our code rejects (`unsupported_method`) any
  critical CRL or CRL-entry extension other than IDP and the standard entry extensions (reason
  code, invalidity date). A certificateIssuer entry extension → `unsupported_method` (indirect
  CRL).
- Delta CRLs are not used.
- A serial listed with any reason, including certificateHold → `revoked`.
- Cache: the parsed `*x509.RevocationList` and a `map[string]struct{}` of listed serials (hex)
  are cached by URL until min(nextUpdate, 1 h); the raw bytes are discarded after parsing.
  Fetch and parse run once per URL under singleflight; concurrent checks wait for the cached
  entry. The cache bound (default 128 MiB, estimated as 2 × raw size per entry) evicts the least
  recently used entry. A single CRL above the 32 MiB response cap → `unavailable`.

**Fetcher (SSRF controls):**
- `http`/`https` only, and the host must be in the union of the profile allowlists.
- Dial through a `net.Dialer.Control` that rejects loopback, private, link-local, multicast and
  unspecified IPs after resolution.
- Redirects: at most 3, only to the same scheme or an `http`→`https` upgrade (never `https`→`http`),
  and only to the same host or another host in the allowlist. SIGNE's `signe-subca.crl` answers
  302 to `https://crl.firmaprofesional.com/` (allowlisted for SIGNE).
  ACCV `/gestcert/` and DNIe `/dnie/crls/` answer 302 to same-host paths.
- Timeouts: 5 s total for OCSP, 15 s for CRL.
- Response caps: OCSP 64 KiB, CRL 32 MiB.
- At most 16 concurrent fetches.
- No cookies, and a fixed User-Agent `cert-check/<version>`.
- No identity data in requests.

### Identity extraction

**Generic machinery (`certauth/identity`):**
- RDN parse of `RawSubject` via `encoding/asn1` into an ordered list of (OID, value, ASN.1 tag),
  preserving duplicates.
  - Values must be UTF8String or PrintableString; BMPString and TeletexString are rejected unless
    a profile allows them.
  - Reject control characters, U+FFFD and bidi controls.
- `SAN directoryName`: decode `GeneralNames`, select tag-4 entries and parse their RDNs.
- `SubjectDirectoryAttributes` (2.5.29.9): decode the attribute sequence and read `dateOfBirth`
  (1.3.6.1.5.5.7.9.1) as GeneralizedTime → civil date. Any other attribute is ignored and not
  returned. A malformed SDA → `identity_invalid` only when the profile declares a birth date;
  otherwise it is ignored with a debug log.
- **DNI:** `^[0-9]{8}[TRWAGMYFPDXBNJZSQVHLCKE]$` with the mod-23 check.
- **NIE:** `^[XYZ][0-9]{7}[TRWAGMYFPDXBNJZSQVHLCKE]$`, with X/Y/Z → 0/1/2 before the mod-23
  check.
- Uppercase ASCII only after trimming permitted surrounding spaces. Leading zeros are preserved.
- Typed prefixes (ETSI EN 319 412-1): `IDCES-` → DNI or NIE by value shape. Any other prefix
  (`PASxx-`, `IDCxx-` with xx≠ES, `TINES-`, `EX:ES-`, `JU:ES-`, …) → error code
  `identity_unsupported_document` ("this certificate identifies the holder with a document other
  than a Spanish DNI/NIE"). The prefix is never stripped to force a match. A bare value is
  accepted only when the profile declares `AllowBare`.
- Reserved and test identities (versioned registry, all checksum-valid) → `test_certificate`,
  checked after identity extraction (step 7b) for every profile:
  - `00000000T`, `99999999R`, `99999972C`, `99999018D`, `X0000000T` (FNMT and DNIe kits and
    profile examples);
  - the shared ESPECIMEN series `99949990V`, `99949991H`, `99949992L`, `99949993C`,
    `99949994K`, `99949995E`, `99949996T`, `99949997R`, `99949998W`, `99949999A`
    (FNMT, AOC, DIGITEL, Bewor and Sectigo specimens all use it);
  - `12345678Z` (Camerfirma test series).
- Name markers (compared after NFC, case-folded): surnames containing `ESPECIMEN`,
  `PRUEBAS`, `FICTICIO`, `APELLIDOUNO`, `APELLIDO1`, `DE LA PEÇA DE PROVES`, `DE PROVES`;
  given names equal to `NOMBRE`, `PRUEBAS`, `PRUEBASPF`, `PRUEBASREV`, `CIUDADANO`, or
  matching `^NOM ?(UN O|D'DIEZ|DOS|SEIS|NUEVE|DIEZ)$`; organization `ENTIDAD DE PRUEBAS` /
  `Entidad de pruebas`.
  A marker match → `test_certificate`. This list is a backstop for kit refreshes; it does not
  replace fingerprint pinning of the committed specimens.
- Names: Unicode NFC, collapse internal whitespace, trim. Never split given names. Never split a
  combined surname field. First and second surname come only from separate documented fields.
- Full name: `GivenNames + " " + Surnames`.

**Per-profile adapters** declare:
- the source of the document and its accepted encodings;
- the sources of given names and surnames;
- documented quirks (for example idCAT legacy surname suffix ` - DNI <id>`, stripped only by
  exact grammar and only when `<id>` equals the extracted document);
- consistency fields that must agree (for example FNMT SAN directoryName 1.3.6.1.4.1.5734.1.4);
- whether a birth date is expected.

Exact grammars are in the section "Provider profiles".

### TLS on the auth listener (`certauth/tlsauth`)

- `GetConfigForClient` picks the provider config by exact SNI `<id>.auth.<authDomain>`
  (lowercased). An unknown SNI makes `GetConfigForClient` return an error; Go aborts the
  handshake with the `internal_error` alert (`crypto/tls/handshake_server.go:170-172`), so no
  certificate-less page is served.
- Per-provider config:
  - `ClientAuth: tls.RequestClientCert`. The handshake succeeds without a certificate so we can
    redirect with `no_certificate`; Go still verifies CertificateVerify when a certificate is
    sent.
  - `ClientCAs` = the provider's CAs.
  - `SessionTicketsDisabled: true`.
  - `MinVersion` and `MaxVersion` TLS 1.2 by default. TLS 1.3 is opt-in with
    `CERTCHECK_AUTH_TLS13=true` (deviation D2).
  - TLS 1.2 cipher suites: ECDHE-ECDSA/RSA with AES-128/256-GCM or ChaCha20-Poly1305.
  - Curves: X25519, P-256, P-384.
  - `GetCertificate` from `internal/acme`.
- `NextProtos: []string{"http/1.1"}` on every per-provider config, and
  `TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}` on the auth
  `http.Server`, so HTTP/2 is never negotiated and no connection can be reused across provider
  hosts under the wildcard certificate.
- Every HTTP request on the auth listener re-runs the checks: no connection-level caching of
  results.
- HTTP server timeouts:
  - `ReadHeaderTimeout` 10 s, `ReadTimeout` 30 s, `WriteTimeout` 60 s, `IdleTimeout` 30 s.
  - `MaxHeaderBytes` 16 KiB.
- The validation context on the auth listener is bounded to 40 s; on expiry the transaction
  stores `internal` (retryable) and the 303 is still sent, so the UI shows a retry message
  instead of a hung navigation.
- The handler returns `421 Misdirected Request` when `r.Host` (port stripped, lowercased)
  differs from `r.TLS.ServerName`.
- Only `GET /v1/authenticate` is routed. Any other path or method → 404 with an empty body and
  `Cache-Control: no-store`. The auth listener serves no HTML and sets
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on every response.
- `tlsauth.Handler.Authenticate(r)` gets the provider from `r.TLS.ServerName` and the chain from
  `r.TLS.PeerCertificates`, then calls `Checker.Check`.

### Certificates for the auth host (`internal/acme`)

- certmagic with only the DNS-01 solver (`libdns/cloudflare`, token from `CLOUDFLARE_API_TOKEN`).
  HTTP-01 and TLS-ALPN-01 are disabled.
- Token scope (owner choice, recorded at spec approval). Default: `CLOUDFLARE_API_TOKEN` has
  `Zone:DNS:Edit` on `vocdoni.dev`; risk accepted: a leaked token can rewrite every
  `vocdoni.dev` record. Supported alternative: CNAME delegation — `_acme-challenge.auth.cert-check.vocdoni.dev`
  CNAME → `_acme-challenge.cert-check.<acme-zone>` on a dedicated Cloudflare zone holding nothing
  else, the token scoped to that zone only, and `CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN=_acme-challenge.cert-check.<acme-zone>`
  passed to certmagic's `DNS01Solver.OverrideDomain`.
- Name: `*.auth.<authDomain>`.
- Issuer: Let's Encrypt production by default; staging via `CERTCHECK_ACME_CA=staging`.
- Storage: `<CERTCHECK_DATA_DIR>/certmagic` on the Railway volume, so redeploys don't re-issue
  (LE duplicate-certificate rate limit).
- The certificate is obtained synchronously at startup before the auth listener serves. Renewal
  is automatic.
- `/readyz` is not ready until a valid certificate is loaded.
- Dev/test alternative: `CERTCHECK_TLS_CERT_FILE` and `CERTCHECK_TLS_KEY_FILE` (static
  cert/key), mutually exclusive with ACME.

### Main listener (`internal/server`)

Routes (Go 1.22+ `ServeMux` patterns, stdlib only):

| Route | Behaviour |
|---|---|
| `GET /` and static assets | Embedded UI |
| `GET /api/v1/providers` | 200 `[{"id":"fnmt","name":"FNMT – Persona Física","description":"…","beta":false}, …]`, enabled providers only, display order; `beta:true` entries go in the Beta `<optgroup>` |
| `POST /api/v1/transactions` | `Content-Type: application/json`, body ≤ 1 KiB `{"provider":"fnmt"}` → 201 `{"authUrl":"https://fnmt.auth.<authDomain>:<port>/v1/authenticate?state=<state>","expiresAt":"2026-10-30T23:05:00Z"}` (RFC 3339, UTC) + cookie. Errors use `{"status":"error","error":{"code","message","retryable"}}`: 400 `unknown_provider`, 415 `unsupported_media_type`, 429 `rate_limited` (+ `Retry-After`), 503 `store_full` (retryable) |
| `POST /api/v1/transactions/redeem` | body ≤ 1 KiB `{"code":"…"}` + cookie → 200 `{"status":"success","result":<Result>}` or 200 `{"status":"error","error":{"code":"<ErrorCode>","message":"…","retryable":bool},"diagnostics":<Diagnostics>}`; invalid/expired/mismatch → 400 `{"status":"error","error":{"code":"invalid_or_expired","message":"…","retryable":false},"diagnostics":{"diagnosticId","time","serverVersion","code":"invalid_or_expired","technicalDetail":"code_unknown_or_expired"\|"cookie_missing"\|"cookie_mismatch"}}` (no identity data) |
| `GET /api/v1/transactions/current` | Cookie-bound → 200 `{"status":"pending"\|"completed"\|"none","provider","createdAt","authHost","authPort"}`. The UI uses it to detect an authentication step that never reached the server (see "Diagnostics and support report") |
| `GET /healthz` | 200 if the process is serving |
| `GET /readyz` | 200 when the registry is loaded, the auth cert is present and both listeners are up; else 503 |

`<Result>` (camelCase; absent optional strings are `""`, absent objects `null`):

```
{"provider":{"id","name"},
 "profile":{"id","name","holderRole":"natural_person|representative|public_employee"},
 "identity":{"document":{"type":"DNI|NIE","country":"ES","number","raw","source"},
             "givenNames","surnames","firstSurname","secondSurname","fullName",
             "birthDate":"YYYY-MM-DD"|null,"sources":{"<field>":"<provenance>"}},
 "organization":{"name","identifier"}|null,
 "certificate":{"subject","issuer","serialHex","notBefore","notAfter","sha256","keyAlgorithm"},
 "revocation":{"status":"good","method":"ocsp|crl","checkedAt","thisUpdate","nextUpdate"|null,"source":"<host>"},
 "validatedAt",
 "diagnostics":<Diagnostics>}
```

`message` is produced by the server's single code→English-message table (the UI shows it and
adds per-code recovery guidance). All timestamps are RFC 3339 UTC.

Both POST handlers require `Content-Type: application/json` (415 otherwise) and, when present,
`Sec-Fetch-Site` ∈ {`same-origin`, `none`} and `Origin` equal to `CERTCHECK_PUBLIC_URL` (403
otherwise).

- **Transaction store.** Mutex-protected maps keyed by SHA-256 of secrets.
  - Lifetime: 5 min from creation. A completed result is kept until redeemed or expired.
  - A janitor runs every 30 s.
  - Capacity 10 000 transactions → 503 when full.
- **Rate limiting.** Client IP on the main listener = the `X-Forwarded-For` entry
  `CERTCHECK_TRUSTED_PROXY_HOPS` places from the right (default `1`). Confirmed at rollout
  (2026-10-31): the Railway edge strips any client-supplied `X-Forwarded-For` and sends exactly
  two entries, `<client>, <railway hop>` (a spoofed header still arrives as two entries;
  Railway staff: "the first value of the X-Forwarded-For is the real connecting IP"). Production
  therefore runs with `CERTCHECK_TRUSTED_PROXY_HOPS=2`, which selects the client. `X-Real-IP` is
  also set by the edge but not used. Without any forwarded header (local run) the TCP remote
  address is used.
  Limits: 20 transaction creations and 60 redeems per minute per IP → 429 with `Retry-After`.
  IPv6 clients are keyed by their /64 (one allocation), IPv4 clients by address.
  The auth listener caps concurrent connections at 512 (listener-level semaphore; excess
  connections are closed before the handshake) and runs no validation until the state check
  passes. Global validation concurrency: 32; a validation waiting more than 10 s for a slot →
  `internal` (retryable).
- **Server timeouts.** Main listener: `ReadHeaderTimeout` 10 s, `ReadTimeout` 15 s,
  `WriteTimeout` 30 s, `IdleTimeout` 60 s, `MaxHeaderBytes` 16 KiB.
- **Security headers on every response:**
  - `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self';
    script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
    base-uri 'none'; form-action 'self'`
  - `Referrer-Policy: no-referrer`
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security: max-age=31536000`
  - `Cache-Control: no-store` on the API.
- The auth listener sends `Referrer-Policy`, `X-Content-Type-Options`, HSTS and its own
  `default-src 'none'` CSP on its redirects and 404s.

### UI (`web/`)

- Static HTML, CSS and vanilla JS. No framework, no build step, no third-party requests.
- Self-hosted Fraunces (headings) and Hanken Grotesk (body) woff2 (OFL), Vocdoni SVG logo and
  favicon.
- Brand tokens from vocdoni.io:
  - primary `#296948`, button text `#FCFAF1`;
  - background `#FDFBF3`, text `#202019`;
  - secondary `#E0F3E1`, accent `#F0EAD2`;
  - pill buttons.
- Views, swapped by JS in one page:
  - **Start.** Logo, H1 "Certificate Authentication Checker", one-sentence explanation, a
    labelled native `<select>` of providers, primary button "Authenticate", and a short privacy
    note: "Your browser will ask you to choose a certificate. Nothing is uploaded and your private
    key never leaves your device."
  - **Working.** Shown while creating the transaction and while redeeming.
  - **Success.** H1 "Success", and a definition list:
    - Full name; Given name(s); Surname(s), with first/second when available;
    - Document type and number;
    - Birth date, or "Not included in this certificate";
    - Certificate provider and profile; Issuer; Valid until;
    - Revocation check (method, time).

    A button "Check another certificate".
  - **Error.** Human message per error code, with recovery guidance:
    - cancelled or no certificate → choose a certificate; browsers may remember a choice, so close
      all browser windows and retry;
    - a different certificate type was presented → select the matching provider;
    - temporary revocation outage → retry shortly.
    - Every error view includes the diagnostic report and the 'Copy diagnostic report' button (see 'Diagnostics and support report').
- Rendering: all identity, certificate and error strings are inserted with `textContent`;
  `innerHTML` is never used with API data.
- Accessibility: labels, visible focus, `aria-live` status region, contrast AA, works at 320 px
  width.

### Diagnostics and support report

- `certauth.Error` carries `Diagnostics` (also attached to `Result` on success):
  - `diagnosticId` (random 16 bytes, hex; never derived from identity);
  - `time`, `serverVersion`, `provider`, `failedStep` (`bounds|path|profile|purpose|algorithms|test_marker|identity|revocation`);
  - `code`, `technicalDetail` (exact underlying error text, e.g. the x509 error, "policy OIDs present [...]; expected one of [...]", "OCSP http://host/path → HTTP 503 after 4.9s");
  - `tls`: version, cipher suite, SNI, client certificate presented (bool), chain length received;
  - `certificate` (leaf; plus subject/issuer of every chain cert received): subject DN (RFC 4514), issuer DN, serial (hex), notBefore/notAfter, SHA-256, key algorithm/size/curve, signature algorithm, KU, EKU (incl. unknown OIDs), policy OIDs, critical extension OIDs, AIA OCSP/caIssuers URLs, CDP URLs;
  - `profileCandidates`: profile ids tried, with the path or profile result per candidate;
  - `revocationAttempts[]`: method, URL, HTTP status, duration, outcome, producedAt/thisUpdate/nextUpdate, responder subject, nonce sent/echoed.
- Redeem error responses include `diagnostics` (session-bound, like the result).
- New `GET /api/v1/transactions/current` (cookie-bound) → `{status: "pending"|"completed"|"none", provider, createdAt, authHost, authPort}`. The UI remembers an in-flight attempt in `sessionStorage`. When the user comes back without `#code` and the transaction is still `pending`, the UI shows "the authentication step never reached our server". It then lists the likely causes (certificate selection cancelled, port NNNNN blocked by the network, the browser could not use the key) and offers a report with the auth host and port, the time and the user agent.
- UI error view: human message + recovery guidance, a collapsible "Technical details" `<pre>` holding the full plain-text report, and a "Copy diagnostic report" button (Clipboard API, with select-all fallback). Report header: diagnostic ID, time, page URL without query, user agent, server version. Notice: "This report contains your certificate details (name and ID number). Share it only with Vocdoni support."
- The server logs one line per failure with the diagnostic ID and the non-PII fields: code, step, provider, profile candidates, issuer DN, policy OIDs, revocation URL host/status/duration, TLS version/cipher. It never logs the subject DN, names, DNI, serial or SHA-256 of the leaf.
- Auth-listener TLS handshake errors go to slog at warn, with the SNI and the error text (no PII available at that layer).
- Acceptance criterion: AC13.

### Configuration (`internal/config`)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Main listener port (Railway sets it) |
| `CERTCHECK_PUBLIC_URL` | required | Fixed callback origin, e.g. `https://cert-check.vocdoni.dev` |
| `CERTCHECK_AUTH_DOMAIN` | required | e.g. `auth.cert-check.vocdoni.dev` |
| `CERTCHECK_AUTH_PUBLIC_PORT` | `$RAILWAY_TCP_PROXY_PORT` | External auth port used in `authUrl` |
| `CERTCHECK_AUTH_LISTEN` | `:8443` | Auth listener address |
| `CERTCHECK_DATA_DIR` | `/data` | ACME storage |
| `CERTCHECK_ACME_EMAIL` | required with ACME | ACME account contact |
| `CERTCHECK_ACME_CA` | `production` | `production` \| `staging` |
| `CLOUDFLARE_API_TOKEN` | required with ACME | DNS-01 token (secret) |
| `CERTCHECK_TLS_CERT_FILE` / `_KEY_FILE` | unset | Static cert instead of ACME |
| `CERTCHECK_AUTH_TLS13` | `false` | Allow TLS 1.3 on the auth listener (D2) |
| `CERTCHECK_TRUSTED_PROXY_HOPS` | `1` | Trusted proxy hops; selects the client IP counted from the right of `X-Forwarded-For` |
| `CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN` | unset | Optional DNS-01 CNAME delegation target, passed to certmagic's `DNS01Solver.OverrideDomain` |
| `CERTCHECK_LOG_LEVEL` | `info` | slog level |

Invalid or missing required configuration makes startup fail with a clear message. Nothing secret
is logged.

### Observability and privacy

- `log/slog` JSON. Log lines carry the diagnostic ID, provider, profile id, outcome code and
  revocation method/latency. The diagnostic ID is the request id; no separate request-id
  attribute (ruling R49).
- **Never logged:** DNI/NIE, names, birth date, subject DN, certificate bytes or fingerprint,
  state, code or cookie values.
- The diagnostic ID links the user's copied report to the server log line.
- Identity data lives only in the transaction's memory until redeemed or expired, and is never
  written to disk.

### Deployment

- **Dockerfile:**
  - Build stage: `golang:1.27` with `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X …version"`.
  - Runtime: `gcr.io/distroless/static-debian12:nonroot` (CA bundle included for ACME and the
    Cloudflare API).
  - Exposes 8080 and 8443.
- **Railway**, project `CertificateCheck`, environment `production`, service `cert-check`:
  - source repo `vocdoni/cert-check` branch `main` with auto-deploy and "wait for CI";
  - 1 replica;
  - volume at `/data`;
  - `RAILWAY_RUN_UID=0` is set on the service: Railway mounts volumes as `root`
    (docs.railway.com/volumes#permissions) and the `nonroot` image (UID 65532) cannot create
    `/data/certmagic` otherwise. The process therefore runs as root inside the container; the
    image stays `distroless:static` (no shell, no package manager). Rollout step 3 is complete
    only when `/data/certmagic/` exists on the volume and `/readyz` returns 200;
  - HTTP domain `cert-check.vocdoni.dev` → port 8080, plus the generated `*.up.railway.app`
    domain;
  - TCP proxy → port 8443;
  - healthcheck `/readyz`, `healthcheckTimeout: 600` in `railway.json`;
  - the variables above, with `CLOUDFLARE_API_TOKEN` as a sealed secret;
  - config-as-code in `railway.json` (builder Dockerfile, healthcheck path and timeout, restart
    policy).
- The TCP proxy port is checked against Chrome's restricted-port list. If restricted, recreate
  the proxy.
- **CI** (`.github/workflows/ci.yml`) on `runs-on: [self-hosted, ci]`, on pull requests and pushes
  to `main`:
  - `gofmt` check, `go vet`, `staticcheck`, `go test -race ./...`, `govulncheck`;
  - Docker build.

  Branch protection on `main` requires CI if the org plan allows it; otherwise Railway's
  wait-for-CI alone gates deploys.
- **Rollback:** redeploy the previous Railway deployment (`railway redeploy` or the dashboard).
  DNS and the volume are unaffected. The ACME certificate persists.

### Deviations from the research spec / note

- **D1. Pinned anchors instead of live LOTL/TSL import.**
  - Anchors are the TSL service-identity certificates from the 2026-09-24 TSL (sequence 189,
    next update 2027-03-21), pinned by SHA-256.
  - Their granted status is verified by a test against the bundled inventory.
  - Ceiling: a TSL withdrawal or new CA key is not picked up until the registry is updated and
    redeployed.
  - Upgrade path: an authenticated LOTL/TSL import (spec §5) feeding the same registry.
- **D2. TLS 1.2 maximum on the auth listener by default.**
  - TLS 1.3 requires RSA-PSS for the client's CertificateVerify. Keys that cannot sign PSS fail
    with no fallback: smart cards, TPM-backed keys, legacy Windows CAPI keys (Chromium issue
    40093814, where the Chrome TLS engineer advises disabling TLS 1.3 on client-cert servers).
  - Cost: in TLS 1.2 the client certificate travels unencrypted, so a passive network observer
    can read the holder's name and DNI.
  - The switch `CERTCHECK_AUTH_TLS13` allows 1.3 once the client base is known to work.
- **D3. Non-443 auth port** (Railway TCP proxy). Strict corporate egress firewalls may block it.
  The UI shows a hint when the user returns without a code while the transaction is still
  `pending` (see "Diagnostics and support report").
- **D4. No census or issuance.** The checker stops at the validated identity.

### Alternatives considered

| Option | Why not |
|---|---|
| Railway HTTP edge with client auth | Impossible: the edge terminates TLS and never requests client certificates |
| Cloudflare mTLS forwarding the cert in a header | Arbitrary-CA client cert requests need Cloudflare Enterprise BYO-CA; trusting a forwarded header needs an authenticated proxy hop that Railway's edge breaks (note §4.4, RFC 9440) |
| Upload of a `.cer` file | Proves nothing about possession; forbidden by the note §1 |
| One auth hostname with all providers' CAs | Browser shows every certificate; a remembered selection blocks switching provider; the selector becomes cosmetic |
| DSS Java sidecar (spec §1) | Second runtime and service for a demo; the note §4 allows mature libraries in the current stack |
| Live TSL import now | XMLDSig plus LOTL pivot bootstrap is a project of its own; pinning gives the same trust set today (D1) |
| lego instead of certmagic | certmagic handles storage, locking, renewal and serving in-process with less wiring |

## Compatibility and rollout

New service with no existing consumers. The JSON API is versioned `/api/v1`. The `certauth`
packages are v0 (no stability promise until the CSP imports them).

Rollout:
1. CI green and Railway build.
2. Owner adds the DNS records.
3. ACME certificate issued (`/readyz` 200).
4. Smoke tests:
   - `/api/v1/providers`;
   - a TLS handshake to each provider subdomain lists the expected CA names
     (`openssl s_client -connect … -servername …`);
   - the no-certificate path returns `no_certificate`;
   - the header the Railway edge actually sets for the client IP (`X-Forwarded-For`, `X-Real-IP`,
     `X-Envoy-External-Address`) is confirmed and recorded in the rate-limiting bullet.
5. Owner tests with real certificates per provider in Chrome, Firefox and Safari/Edge as
   available.

Rollback: redeploy the previous deployment; for a bad profile, set it disabled in the registry
and redeploy.

## Failure modes and security

**Threat model.** The attacker:
- controls their browser and TLS client (any certificate chain, crafted ASN.1, oversized input,
  replayed or forged state and code, spoofed headers);
- can sit on the path of plain-HTTP OCSP/CRL fetches (block, delay, replay, modify);
- can send arbitrary traffic to both listeners;
- may try to read another user's result.

What must hold:
- A **Success** is shown only after the presenting party proved possession of the private key of
  a currently valid, non-revoked certificate of an enabled profile.
- The displayed identity comes only from validated fields under that profile.
- One user's result can be read only by the browser that started the transaction.
- No identity data appears in URLs or logs.
- The server cannot be used to fetch arbitrary URLs.

| Failure | Behaviour |
|---|---|
| OCSP down/slow | CRL fallback if permitted; else `revocation_unavailable` (retryable). Never success. |
| OCSP/CRL tampered or replayed | Signature/CertID/freshness checks → `invalid_evidence` → retryable error; old `good` cannot outlive its bounds |
| Malformed or oversized ASN.1 | Bounded parse → typed error; fuzz tests on identity parsers |
| Wrong provider's certificate presented | `provider_mismatch` (leaf verifies against another enabled provider's anchors); a certificate from no enabled provider → `untrusted_issuer` |
| State replay / code replay / code without cookie | One-use, constant-time match → generic `invalid_or_expired` |
| ACME failure at boot | Auth listener not serving; `/readyz` 503; Railway healthcheck keeps the previous deployment (or the service stays not-ready); logs say why |
| Anchor expiry | Profile auto-disabled at startup with a warning; provider hidden if it has no enabled profile |
| Memory pressure | Bounded transaction store, parsed-CRL cache size, auth connections, validation and fetch concurrency |
| Restart | In-flight transactions lost; UI shows `invalid_or_expired` with "start again" |
| Clock skew | 5 min tolerance on evidence `thisUpdate` only; certificate validity uses the real clock |
| Spoofed identity headers | No header ever carries identity; the auth decision uses only the local TLS state |

## Acceptance criteria

- [ ] **AC1** `go test -race ./...` passes with 0 skipped tests in the default run (live tests
  behind a build tag); `go vet`, `staticcheck` and `govulncheck` are clean.
- [ ] **AC2** Identity: table tests cover, per enabled profile, every documented identifier
  encoding (prefixed, bare where allowed) and name quirk. They also cover the DNI/NIE checksum
  (valid, invalid, leading zero), foreign passport rejection, conflicting duplicate fields, the
  legacy suffix accepted only on an exact match, control characters and wrong string types. Fuzz
  targets exist for the RDN, SAN and SDA parsers (`go test -fuzz` runs 30 s each without crash in
  CI).
- [ ] **AC3** Validation: a synthetic PKI test suite covers success and each `ErrorCode` path:
  - expired and not-yet-valid leaves;
  - an untrusted issuer, and a different provider's certificate;
  - a missing policy OID, and a policy OID from a different profile;
  - KU without digitalSignature, and an EKU without clientAuth;
  - RSA-1024, and a SHA-1 signature;
  - an unknown critical extension;
  - a test-marker match;
  - a chain that is too long or too large.
- [ ] **AC4** Revocation tests:
  - OCSP good, revoked and unknown;
  - wrong CertID;
  - a responder not issued by the issuer, and a responder without the OCSPSigning EKU;
  - stale thisUpdate without nextUpdate, an expired nextUpdate, a future thisUpdate;
  - a bad signature, a nonce mismatch, a timeout and an oversized response;
  - CRL good and listed, certificateHold, wrong signer, IDP scope mismatch, expired;
  - OCSP-unavailable → CRL fallback success, and OCSP revoked → no fallback;
  - private-IP destination blocked, a redirect not followed, a non-allowlisted host blocked.
- [ ] **AC5** Profiles: every embedded anchor matches its pinned SHA-256, parses with Go 1.27, is a
  CA valid at the build date, and appears as a granted service identity in the bundled TSL
  inventory (`certauth/profiles/testdata/`, or is in the reviewed intermediate exception list). A
  test per profile runs a synthetic leaf shaped like the real profile (same subject attribute
  layout, extensions and OIDs) through the full pipeline with a test anchor substituted. Each
  committed specimen is rejected with `test_certificate` twice: once by fingerprint, and once with
  the fingerprint list emptied in the test, by identity or name marker.
- [ ] **AC6** End-to-end (Go test, real listeners on loopback, synthetic test provider injected by
  the test only):
  - create a transaction, mTLS-authenticate with a client certificate, follow the 303, redeem with
    the cookie, then assert the result;
  - negatives: no client certificate, wrong SNI provider, replayed state, replayed code, redeem
    without or with another cookie, expired transaction, unknown SNI handshake failure;
  - the test passes the `__Host-certcheck_tx` value as an explicit `Cookie` header (a Secure
    cookie is not sent over `http://127.0.0.1` by `cookiejar`).
- [ ] **AC7** Security headers present on all main-listener and auth-listener responses (test).
  No log line in the e2e run contains the test identity's DNI or names (test captures slog
  output).
- [ ] **AC8** Live check (build tag `live`, run by the controller from the deployment network and
  locally):
  - For each enabled profile, fetch and verify the configured CRL(s), or send an OCSP request for
    a specimen serial and verify the responder signature and freshness. Report per endpoint.
  - **Live E2E with a production-CA credential:** a Go TLS client presents the official Bewor
    PKCS#12 test identity (kept outside the repo) to a local instance.
    - With the specimen deny-list replaced by an empty list in the test, the result is success
      with live OCSP `good` and the specimen's identity.
    - With the production deny-list, the result is `test_certificate`.
- [ ] **AC9** UI: the page shows the title, the selector populated from the API and the
  Authenticate button. Success and error views render from fixtures. No external network requests
  (Playwright check against a local run). Passes an axe-core or Lighthouse accessibility check
  with no serious violations.
- [ ] **AC10** Deployment:
  - Railway project `CertificateCheck` exists, deploys `main` automatically after CI, and is
    healthy on `/readyz`.
  - `https://cert-check.vocdoni.dev` serves the UI.
  - Each `https://<provider>.auth.cert-check.vocdoni.dev:<port>` presents a valid Let's Encrypt
    certificate and requests a client certificate listing that provider's CAs.
  - CI runs on self-hosted runners.
- [ ] **AC11** The owner authenticates successfully with at least one real idCAT or FNMT
  certificate on the deployed service and sees the correct data. Recorded with browser and OS
  versions.
- [ ] **AC12** `go list -deps ./certauth/...` contains no package under
  `github.com/vocdoni/cert-check/internal/` or `/web` (CI step).
- [ ] **AC13** Diagnostics present and complete for each error-code path in the AC3/AC4 suites.
  The e2e test asserts that the log has the diagnostic ID and no identity fields. The UI shows
  the copy button and the report text matches the fixture.

## Constraints

- Go 1.27; module `github.com/vocdoni/cert-check`. Follow the vocdoni-go skills
  (`go-code-quality`, `go-modern`, `go-best-practices`):
  - domain types, not primitives;
  - typed errors wrapped with `%w`;
  - `context` everywhere I/O happens;
  - bounded goroutines with clear lifetimes;
  - table-driven tests with got/want.
- **Allowed third-party dependencies:**
  - `github.com/caddyserver/certmagic`
  - `github.com/libdns/cloudflare`
  - `golang.org/x/text/unicode/norm`
  - `golang.org/x/sync/singleflight`
  - `golang.org/x/time/rate`
  - `golang.org/x/crypto/cryptobyte` (strict DER parsing and encoding for the OCSP codec; the
    module `golang.org/x/crypto` is allowed for this package only)

  The allowlist names direct dependencies. Transitive modules pulled by `go mod tidy` are
  accepted; `go.sum` is committed and `govulncheck` covers them. Adding a direct dependency
  still needs a ruling.
- Pure Go, `CGO_ENABLED=0`. No `GODEBUG` relaxations of x509 parsing.
- No PII in logs, URLs, error details or test fixtures committed to the repo. Real personal
  certificates are never committed.
- Embedded anchors are byte-identical copies of the research-bundle PEMs (or official downloads
  recorded with source URL and SHA-256).
- Commits: conventional commits `type(scope): lowercase summary`, no AI attribution and no
  `Co-Authored-By` trailers.
- Build output and scratch files under `~/.cache/cert-check/`, never `/tmp`.

## Provider profiles

Scope approved by the owner on 2026-10-30 ("verified + beta group", "DNIe as beta").

**Binding sources.** The exact data for every profile comes from the research digests committed
in `docs/research/`:
- `appendix-a-fnmt-dnie-accv.md` (A)
- `appendix-b-idcat-izenpe-camerfirma.md` (B)
- `appendix-cde-other-providers.md` (C)

These cover anchor files and SHA-256, policy OIDs, KU/EKU, identity grammar and revocation
endpoints. The specimen fixtures are listed in `certauth/testdata/specimens/MANIFEST.md`, copied
from the fixture research. Where a digest marks a value `low` or unverified, the implementation
uses exactly the documented form and nothing broader. It fails closed, so an unverified variant is
rejected, never guessed.

**Providers (UI entry = auth subdomain id).** Standard first, then a "Beta" `<optgroup>`:

| Provider id | UI name | Profiles (digest) | Notes |
|---|---|---|---|
| `fnmt` | FNMT – Persona Física | `fnmt-citizen-rsa` (A), `fnmt-citizen-g2` (A) | ID in 2.5.4.5: `fnmt-citizen-rsa`: `IDCES-<DNI/NIE>` or bare (`AllowBare`, May-2016 kit); `fnmt-citizen-g2`: `IDCES-` only; SAN dirName `5734.1.{1,2,3,4}` must agree, order-independent. Split surnames from SAN `.1.2`/`.1.3`. G2 leaves are ECDSA P-256. Some leaves have LDAP-only CDP, so OCSP only. G2 OCSP path `/ocspusuG2/` (case-sensitive): always use the leaf AIA verbatim. TestMarkers: fingerprints of the 14 FNMT fixtures plus the identities above. |
| `idcat` | idCAT Certificat | `aoc-idcat-g2` (B), `aoc-idcat-g3` (B) | Policy `1.3.6.1.4.1.15096.1.3.2.86.2` for both, dispatched by anchor. ID `IDCES-<id>` only (no bare). `IDCxx-`/`PASxx-` → `identity_unsupported_document`. Subject C must equal the prefix country. G2 handles critical qcStatements. Legacy ` - DNI <id>` surname strip only on exact grammar plus equality (expected never to fire). OCSP: one certificate per request. RSA leaves use the global 2048-bit floor (the CP/DPC 3072 minimum is not enforced, R73). |
| `accv` | ACCV – Ciudadano (software) | `accv-citizen-software-current` (A), anchors RSA1 + ECC1 CLIENTE | Bare 9-char NIF (DNI or NIE; K/L/M → unsupported). SAN dirName CN `NOMBRE\|APELLIDO1\|APELLIDO2` plus UID must agree. OCSP CRL-backed (3-day window). RSA1 CRL 13.6 MB. RSA leaves use the global 2048-bit floor (the CP/DPC 3072 minimum is not enforced, R73). |
| `digitel` | DIGITEL ON – Ciudadano | `digitel-citizen-sw-g1` (C) | Specimen `99949996T` deny-listed. |
| `bewor` | Bewor – Persona Física | `bewor-natural-person-sw` (C) | `.1.1.1` (centralised HSM) not allowed. Specimen `99949999A` deny-listed. |
| `sectigo` | Sectigo – Ciudadano | `sectigo-citizen-local` (C), anchors R35 + E35 | `digitalSignature` mandatory (optional in Sectigo v2.8). OCSP pre-generated 7-day window. Specimen `99949990V` deny-listed. |
| `fnmt-representative` (beta) | FNMT – Representante | `fnmt-representative-rsa`, `-g2` (A), three roles each | Human identity from 2.5.4.5/42/4. Entity from O + 2.5.4.97 is shown as "Represents". SAN `.1.4` is `IDCES-` prefixed here. Holder role `representative`. |
| `fnmt-employee` (beta) | FNMT – Empleado Público | `fnmt-employee-rsa` (`17.2`), `fnmt-employee-g2` (`23.1.0`) software lanes only (A) | Pseudonym/judicial OIDs explicitly rejected. Employing administration (O) shown. Holder role `public_employee`. |
| `firmaprofesional` (beta) | Firmaprofesional | `firmaprofesional-personal-sw` (C) | Pin `2b75cc4f…` only; `4ccf17c0…` (same key, same DN, 55 s shorter validity) is recorded in the exception list as a known alias and not loaded. |
| `anf` (beta) | ANF AC | `anf-asociacion-class2-sw`, `anf-sl-class2-sw` (C) | Two legal providers, two anchors. Standard Subject mapping only; private SAN is ignored. |
| `uanataca` (beta) | Uanataca | `uanataca-citizen-sw` (C), OID `1.3.6.1.4.1.47286.1.1.1.1` | Older TSL-cited OIDs not enabled. |
| `signe` (beta) | SIGNE | `signe-personal-otros-dispositivos` (C) | NIE as `PNOES-<NIE>` accepted only for this profile, as documented. CRL only (leaf OCSP answers unknown). `signe-subca.crl` answers 302 to `https://crl.firmaprofesional.com/signe/signe-subca.crl`; that host is allowlisted for SIGNE. |
| `lleidanet` (beta) | Lleidanet / inDenova | `lleidanet-natural-person-sw` (C) | CRL only: the `ocsp2.esigna.es` responder certificate lacks id-pkix-ocsp-nocheck, so its answers are never acceptable; the leaf AIA OCSP URL is ignored. |
| `dnie` (beta) | DNIe (requires card reader) | `dnie-auth` (A, plus fixture answers) | Anchor AC RAIZ DNIE 2 with pinned intermediates AC DNIE 004/005/006 (official AIA downloads, verified against the root; source URL and SHA-256 recorded). Policy exactly `2.16.724.1.2.2.2.4`. EKU `AllowAbsent`. RSA ≥ 2048 (1920-bit ROCA re-issues rejected). ID bare DNI only. SN = first surname. Full surnames from CN grammar `<SURNAMES>, <GIVEN> (AUTENTICACIÓN\|AUTENTICACION)`: CN must start with SN, and GN must match. Birth date from SDA `dateOfBirth` (GeneralizedTime) when present, optional. OCSP only, `good` without nextUpdate → 15 min max age. Intermediates' status via the root CRLs: every allowlisted DP (`CRL.crl` and `ARL.crl` for 005/006, `ARL.crl` for 004) must answer good (cached until min(nextUpdate, 1 h)). AC DNIE 00N beyond 006 are not pinned; a DNIe under a newer sub-CA fails `untrusted_issuer`. The AIA list at `http://pki.policia.es/dnie/certs/` is re-checked at every registry update. |

Not enabled, with the reasons recorded in the digests:
- Izenpe (no citizen software certificate);
- Camerfirma (leaf format not public);
- EADTrust, Víntegris, AC Abogacía, DEH/Certibox (low confidence);
- SIA, esFIRMA, EDICOM, IVNOSYS, ANCERT, Registradores, Defensa;
- Validated ID (ceases 2026-11-30);
- remote-only providers;
- ACCV legacy (TSL no longer ForeSignatures; anchor expires 2026-12-31).

**Result additions for roles.** `Result.Organization *Organization{Name, Identifier}` is filled only
for `representative` and `public_employee` profiles, from validated subject fields. It is never
used as the person's identity.

**Specimen fixtures in the repo.** The 28 official test or specimen leaves from the fixture
research (FNMT RSA 12, FNMT G2 2, idCAT 2015 legacy 1, DNIe 13) are committed under
`certauth/testdata/specimens/` with a manifest (source URL, SHA-256, expected parse result). They
are public test identities, not personal data. They are used for:
- parser and identity tests on real bytes;
- test-marker rejection tests.

The DIGITEL, Bewor and Sectigo specimen leaves from digest C are added the same way. The Bewor
PKCS#12 test credential is **not** committed; the controller uses it only for a local live E2E run
(AC8).

## Open questions

None. Owner decisions on 2026-10-30:
- provider scope = verified plus beta group, including DNIe as beta;
- D2 = TLS 1.2 default (client certificate unencrypted on the wire accepted), with the
  `CERTCHECK_AUTH_TLS13` switch.
