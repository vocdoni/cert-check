# Certificate Authentication Checker: implementation plan

Spec: docs/specs/2026-10-30-cert-check-design.md (approved 2026-10-31)
Class: architectural
Repos and branches: /home/p4u/certificate_poc/cert-check → feat/cert-check-v1 (base: the plan commit)

Reference code. Every Go block in this plan was compiled with go1.27.3 in a scratch module with the
same module path (`~/.cache/cert-check/scratch/plan/`): `gofmt`, `go vet`, `staticcheck` v0.8.2 and
`go test -race` were clean. Throwaway tests exercised it against all 33 specimen leaves, 4 real OCSP
responses, 2 real ARLs, a synthetic DNIe chain with a redirected ARL, and a loopback mTLS run (create,
handshake, 303, redeem, replayed state). Blocks are binding: implement identifiers, signatures and
semantics as written. Any deviation needs a controller ruling. Tests are not pasted. Each task lists
them by name and case, and the implementer writes them before the code (TDD).

Task numbers versus the suggested decomposition: 1 = T1; 2 = T2; 3, 4, 5 = T3 split (3a fetcher and
CRL, 3b OCSP codec and acceptance, 3c checker); 6 = T4; 7 = T5; 8, 9, 10 = T6 split (6a config and
ACME, 6b tlsauth and transaction store, 6c handlers, app and main); 11 = T7; 12 = T8; 13 = T9.

## Global Constraints

Copied from the spec ("Constraints"):
- Go 1.27; module `github.com/vocdoni/cert-check`. Follow the vocdoni-go skills (`go-code-quality`,
  `go-modern`, `go-best-practices`): domain types, not primitives; typed errors wrapped with `%w`;
  `context` everywhere I/O happens; bounded goroutines with clear lifetimes; table-driven tests with
  got/want.
- Allowed direct third-party dependencies: `github.com/caddyserver/certmagic`,
  `github.com/libdns/cloudflare`, `golang.org/x/text/unicode/norm`, `golang.org/x/sync/singleflight`,
  `golang.org/x/time/rate`, `golang.org/x/crypto/cryptobyte` (the x/crypto module is allowed for
  cryptobyte only). Transitive modules pulled by `go mod tidy` are accepted; `go.sum` is committed.
  Adding a direct dependency needs a ruling.
- Pure Go, `CGO_ENABLED=0`. No `GODEBUG` relaxations of x509 parsing.
- No PII in logs, URLs, error details or test fixtures committed to the repo. Real personal
  certificates are never committed.
- Embedded anchors are byte-identical copies of the research-bundle PEMs (or official downloads
  recorded with source URL and SHA-256).
- Commits: conventional commits `type(scope): lowercase summary`; no AI attribution, no
  Co-Authored-By or similar trailers.
- Build output and scratch files under `~/.cache/cert-check/`, never `/tmp`.

Added by this plan:
- Before writing any Go, invoke the skills `vocdoni-go:go-code-quality`, `vocdoni-go:go-modern` and
  `vocdoni-go:go-best-practices` (Skill tool). Target Go 1.27. The rules that bind this codebase:
  - Named domain types with typed constants for every enum (`Status`, `Method`, `ErrorCode`, `Step`,
    `Role`, `EKURule`, `Encoding`, `SANKind`, `TxStatus`, …), each with `Valid()` where it is parsed.
  - Return errors, never panic, except for build-time invariants (embedded FS). Handle each error
    once. Use `%w` only for errors that are part of a package contract (`identity.ErrInvalid`,
    `revocation.ErrBlockedAddress`, …). Error strings are lowercase with no trailing punctuation.
  - `context.Context` is the first parameter and is never stored in a struct.
  - Every goroutine has a stop path: use `sync.WaitGroup.Go`. Never fire-and-forget.
  - Interfaces are declared at the consumer (`server.CertSource`). Constructors return concrete types.
  - Use modern forms: `errors.AsType`, `wg.Go`, `t.Context()`, `new(v)`, `slices`/`maps`/`cmp`,
    `for i := range n`, `strings.SplitSeq`, `min`/`max`.
  - Use `crypto/rand` for every secret, nonce and ID.
- Pinned versions. Task 1 writes go.mod/go.sum once, with
  `certmagic v0.25.6, libdns/cloudflare v0.2.2, x/crypto v0.58.0, x/sync v0.24.0, x/text v0.43.0,
  x/time v0.16.0` and `x/net v0.62.0` (indirect; clears GO-2026-6860/6866). The pins are held by a
  `//go:build tools` file. No other task edits go.mod/go.sum (Task 13 deletes the tools file and
  checks `go mod tidy -diff`). `x/crypto/cryptobyte` is imported only by `certauth/revocation`.
  `x/crypto/ocsp` and `x/crypto/pkcs12` are forbidden.
- Tools run as `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...` and
  `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`. They are never added to go.mod.
- Before any go command, export `TMPDIR=$HOME/.cache/cert-check/tmp` and
  `GOTMPDIR=$HOME/.cache/cert-check/gotmp` (`mkdir -p` both). Build binaries with
  `-o ~/.cache/cert-check/bin/...`.
- Every task ends with all of these clean, run from the repo root:
  - `test -z "$(gofmt -l .)"`;
  - `go vet ./...`;
  - staticcheck;
  - `go test -race -count=1 ./...` with no FAIL;
  - `go test -race -count=1 -json ./... | grep -c '"Action":"skip"'` printing `0`.
- Tests:
  - No network beyond loopback (`httptest`, `net.Listen("tcp","127.0.0.1:0")`) and
    `testpki.Net`. Live checks go only in `//go:build live` files.
  - Tests that use real fixtures fix the clock inside the fixture's validity.
  - Table-driven with `got`/`want` in failure messages.
  - Each parser has a fuzz target seeded with real bytes.
- Privacy in code:
  - Error strings and `certauth.Error.Detail` never include certificate values. They name fields,
    OIDs and rules.
  - Logs carry only `certauth.Diagnostics.LogAttrs()` fields and fixed non-identity attributes.
  - State, code and cookie values are never logged. On the auth listener the query string is never
    logged.
- Fixtures and anchors:
  - Anchors are file-identical copies.
  - Specimens are DER-identical, one clean PEM block each.
  - OCSP/CRL samples are file-identical.
  - Each directory has a SOURCES.md or MANIFEST.md with the source URL or archive and the SHA-256.
    A test recomputes the hashes.
  - `.gitattributes` marks these files `-text`.
- Security invariants (do not weaken):
  - Only the chain returned by `x509.Verify` against pinned roots and pinned intermediates is used.
    `PeerCertificates[1:]` is never used for path building or revocation.
  - Revocation runs on `chain[i]` with issuer `chain[i+1]` of the verified chain.
  - Everything fails closed. Only revocation status `good` passes.
  - The auth listener is HTTP/1.1 only, has no session resumption, requests a client certificate
    with the provider's CA list, and returns 421 when Host ≠ SNI.
- Downloads (fonts, axe-core, live fixtures) are untrusted data. Put each in its own new directory
  under `~/.cache/cert-check/`, verify the published digest, and never execute anything from it.
- Touch only the files listed by your task. Anything else needs a controller ruling.

## Review Focus

Read these in full at every task review and at the gate audit:
- `certauth/checker.go`. `Check`: step order 1 → 9. `leafForProfile`: the copy keeps
  `Raw`/`RawTBSCertificate`. `mapPathErrors`: the rank order. `unknownAuthorityCode`: union pool,
  used for classification only. Also `algorithmsOK`, `purposeOK`, and the revocation loop
  (issuer = `m.chain[i+1]`).
- `certauth/revocation/ocspverify.go`. `VerifyOCSP` order. `authorizedSigner`: issuer or a delegated
  responder directly issued by the issuer with OCSPSigning, valid now, nocheck and a strong key.
  `identifiedBy`: the ResponderID binding.
- `certauth/revocation/ocspcodec.go`: `ParseResponse`, `parseSingleResponse`,
  `readExplicitExtensions`, `parseSignatureAlgorithm`, `MarshalRequest` (nonce extnValue), `NewCertID`.
- `certauth/revocation/crl.go`. `ParseCRL`: issuer bytes, signature, criticality. `EvaluateCRL`:
  freshness, IDP scope and the leaf/CA flags. `ParseCDP`, `ParseIDP`, `usableDistributionPoints`.
- `certauth/revocation/fetcher.go`: `checkDialAddress`/`AddressAllowed` run after DNS;
  `hostAllowed`; `checkRedirect`; size caps; `Proxy: nil`.
- `certauth/revocation/checker.go` and `ocspcache.go`: fallback rules (never after revoked or
  unknown), `worstFailure`, cache reuse bounds.
- `certauth/identity/*`. `ParseName`/`Field` (string kinds, controls, duplicates). `ParseDocument`
  (typed prefixes are never stripped). `Adapter.Extract`, `crossCheckSAN`, `dnieSurnames`, the
  legacy suffix rule, `Reserved.Match`.
- `certauth/profiles/registry.go` (`loadAnchor` pins, `checkAmbiguity`) and
  `certauth/profiles/providers.go` against the per-profile table in Task 6.
- `certauth/tlsauth/tlsauth.go`: `ServerConfig`, `CheckHost`, `Authenticate`.
- `internal/server/txstore.go` (whole file), `auth.go` (`ServeHTTP`, `validate`, `limitListener`,
  `newAuthServer`), `http.go` (cookie, `postGuard`, `clientIP`, `ipLimiter`), `api.go`
  (`handleCreate`, `handleRedeem`).
- `internal/acme/acme.go`: DNS-01 only, storage path, retry. `internal/config/config.go`: the
  `Secret` redaction.
- `web/static/app.js`: `textContent` only, fragment handling, `history.replaceState`.

## Task order and parallelism

| Task | Depends on | Repo/files | May run in parallel with |
|---|---|---|---|
| 1 Scaffold, `internal/testpki`, specimens, `revocation/policy.go` seed (opus) | — | go.mod, go.sum, .gitignore, .gitattributes, internal/deps, internal/testpki, certauth/revocation/policy.go, certauth/testdata/specimens, certauth/specimens_test.go, web/embed.go, web/static/index.html | — |
| 2 `certauth/identity` (opus) | 1 | certauth/identity/** | 3, 4, 8, 11 |
| 3 revocation: fetcher, CRL, CRL cache (opus) | 1 | certauth/revocation/{fetcher,crl,crlcache}*.go, testdata/crl/** | 2, 4, 8, 11 |
| 4 revocation: OCSP codec and acceptance (opus) | 1 | certauth/revocation/{ocspcodec,ocspverify}*.go, testdata/ocsp/** | 2, 3, 8, 11 |
| 5 revocation: Checker, OCSP cache (opus) | 3, 4 | certauth/revocation/{checker,ocspcache}*.go | 6, 8, 11 |
| 6 `certauth/profiles` (opus) | 2 (and 1's policy.go) | certauth/profiles/** | 3, 4, 5, 8, 11 |
| 7 `certauth` pipeline and diagnostics (opus) | 5, 6 | certauth/{types,diagnostics,checker}*.go, certauth/*_test.go | 8, 11 |
| 8 `internal/config`, `internal/acme` (sonnet) | 1 | internal/config/**, internal/acme/** | 2–7, 9, 11 |
| 9 `certauth/tlsauth`, txstore, HTTP helpers (opus) | 7 | certauth/tlsauth/**, internal/server/{txstore,http}*.go | 8, 11 |
| 10 handlers, app, `cmd/cert-check` (opus) | 8, 9 | internal/server/{auth,api,app}*.go, cmd/cert-check/** | 11 |
| 11 `web/` UI (sonnet) | 1 | web/** (except embed.go) | 2–10 |
| 12 e2e, live, probe (opus) | 10, 11 | internal/server/{e2e,live}_test.go, internal/probe/**, cmd/cert-check/main.go (probe subcommand) | 13 |
| 13 Dockerfile, CI, README (sonnet) | 10 | Dockerfile, .dockerignore, .github/workflows/ci.yml, README.md, internal/deps (delete), go.mod/go.sum (tidy only) | 12 |

Critical path: 1 → 2 → 6 → 7 → 9 → 10 → 12. Worktrees: one per parallel task. Shared files are
avoided by design: go.mod is pinned in Task 1, and the revocation testdata is split into `crl/`
(Task 3) and `ocsp/` (Task 4). Merge order is the task numbers.

Owner rulings needed before the tasks they block:
- **R-P1** (blocks Task 1's last step). The Bewor specimens (×2) and the Sectigo specimens (×2) carry
  a named CA employee's e-mail address in SAN rfc822Name. The spec says to commit them, but its
  Constraints forbid PII in fixtures. Default if no ruling arrives: do not commit those 4 files.
  Their fingerprints stay pinned in `providers.go`. Their double-rejection rows run under the `live`
  tag from `~/.cache/cert-check/live/specimens/`.
- **R-P2** (blocks Task 13 and the deploy). Railway config-as-code `railway.json` is deprecated: new
  services cannot opt in, and files stop being read on 2026-12-01 (Railway plugin reference
  `use-railway/references/iac.md`). The plan sets the same service settings with
  `railway environment edit --service-config` and writes no `railway.json`.


## Tasks

### Task 1: module scaffold, synthetic PKI helper, specimen fixtures
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `go.mod`, `go.sum`, `.gitignore`, `.gitattributes`, `internal/deps/deps.go`;
- `internal/testpki/{der.go,testpki.go,ocsp.go,crl.go,net.go,testpki_test.go}`;
- `certauth/revocation/{policy.go,policy_test.go}`;
- `certauth/testdata/specimens/*.pem`, `certauth/testdata/specimens/MANIFEST.md`,
  `certauth/specimens_test.go`;
- `web/embed.go`, `web/static/index.html` (placeholder).

Goal: everything later tasks build on. A pinned module, the synthetic PKI used by every test suite
(AC3, AC4, AC5, AC6), the specimen leaves (AC2, AC5), the revocation policy and status types that
Tasks 3–7 share, and the embedded web FS that Task 10 serves.

Path note. The helper lives at `internal/testpki`, not `certauth/internal/testpki`. Go's internal
rule would forbid `internal/server` (the AC6 e2e test) from importing `certauth/internal/...`. AC12
still holds: `testpki` is imported only by `_test.go` files, and `go list -deps ./certauth/...` lists
non-test dependencies only. Task 13 adds a CI guard against non-test imports of testpki.

Step 1: write the failing tests.
- `internal/testpki/testpki_test.go`:
  - `TestNameDER`: order, duplicate attributes, a multi-valued RDN, and each string tag
    (UTF8/Printable/Teletex/IA5/BMP) survive a round trip through `x509.ParseCertificate`
    (`RawSubject` equals `Name.DER()`). BMP decodes `ÑÜ` correctly.
  - `TestLeafExtensions`:
    - policies appear in `cert.Policies`;
    - AIA OCSP and caIssuers;
    - CDP with URIs-then-DirName and with `DirNamesFirst`;
    - SAN rfc822 plus dirName parse;
    - SDA dateOfBirth bytes;
    - `SANRaw` and `SDARaw` override;
    - `ExtraExtensions` critical bit preserved (`UnhandledCriticalExtensions` lists it);
    - `PathLen` nil/0/1;
    - `NoKeyUsage` omits 2.5.29.15.
  - `TestWeakKeysAndSHA1`: RSA1024, RSA1920, ECDSAP224 and a `SignatureAlgorithm: x509.SHA1WithRSA`
    leaf are created and parse.
  - `TestOCSPResponseShapes`: decode `BuildOCSPResponse` output with `encoding/asn1` structs
    declared in the test, independent of revocation. Cases:
    - good, revoked with reason 6, revoked with `OmitReason`, unknown;
    - byName and byKey ResponderID;
    - nextUpdate present and absent;
    - nonce echo/omit/wrong;
    - `DuplicateSingle`;
    - `ResponseStatus: 3` yields `30 03 0a 01 03`;
    - embedded certs default (delegated: 1, issuer-signed: 0);
    - the signature verifies with `Signer.Cert.CheckSignature(x509.ECDSAWithSHA256 or SHA256WithRSA, tbs, sig)`;
    - `CorruptSignature` fails it.
  - `TestParseOCSPRequest`: a hand-built request (SHA-1 CertID plus nonce extension) round-trips;
    trailing data fails.
  - `TestCRLShapes`:
    - `x509.ParseRevocationList` accepts every variant;
    - `CheckSignatureFrom(ca)` passes, and fails with `Signer` set to another CA;
    - `NoNextUpdate` gives zero `NextUpdate`;
    - entries carry the reason;
    - the IDP extension value decodes for URIs, DirNames, `RelativeName`, each flag;
    - `NonCritical`;
    - `IssuerDER` override;
    - `CorruptSig`.
  - `TestNetDial`: `Serve` plus `DialContext` reach the handler; unknown host fails.
  - `TestServerTLS`: a TLS handshake to `ServerTLS` with the returned pool succeeds.
- `certauth/revocation/policy_test.go`:
  - `TestPolicyValidate` table:
    - valid;
    - uppercase host;
    - IP host;
    - wildcard;
    - `host:port` valid;
    - `host:0`;
    - `AllowCRL` without hosts;
    - neither method;
    - negative max age.
  - `TestStatusValid`, `TestPolicyMaxAge`, `TestAllHosts`.
- `certauth/specimens_test.go` (package `certauth_test`): `TestSpecimenManifest` parses the
  MANIFEST.md table and checks:
  - every listed file exists and holds exactly one PEM CERTIFICATE block;
  - its DER SHA-256 equals the manifest;
  - every `.pem` in the directory is listed;
  - each certificate parses with go1.27.

Run: `go test -race -count=1 ./internal/testpki/... ./certauth/...`
Expected: build failure (`undefined: Name`, …), because nothing exists yet.

Step 2: implement.

`go.mod` (then `go get` the exact versions below and `go mod tidy`; the tools file keeps them):
```
module github.com/vocdoni/cert-check

go 1.27
```
`internal/deps/deps.go`:
```go
//go:build tools

// Package deps pins the allowed direct dependencies until every one is
// imported by real code (removed in Task 13).
package deps

import (
	_ "github.com/caddyserver/certmagic"
	_ "github.com/libdns/cloudflare"
	_ "golang.org/x/crypto/cryptobyte"
	_ "golang.org/x/sync/singleflight"
	_ "golang.org/x/text/unicode/norm"
	_ "golang.org/x/time/rate"
)
```
Commands: `go get github.com/caddyserver/certmagic@v0.25.6 github.com/libdns/cloudflare@v0.2.2
golang.org/x/crypto@v0.58.0 golang.org/x/sync@v0.24.0 golang.org/x/text@v0.43.0
golang.org/x/time@v0.16.0 golang.org/x/net@v0.62.0 && go mod tidy`.

`.gitignore`: `/bin/`, `*.test`, `*.out`, `*.p12`, `*.pfx`, `*.key`. The untracked `.delivery/`
ledger is left alone. It is never staged, because commits list explicit paths.
`.gitattributes`:
```
certauth/profiles/anchors/** -text
certauth/testdata/** -text
certauth/revocation/testdata/** -text
certauth/profiles/testdata/** -text
web/static/fonts/** -text
web/static/favicon.ico -text
```

`certauth/revocation/policy.go` (shared types; Tasks 3–5 add the rest of the package):
```go
// Package revocation checks the revocation status of a certificate against
// its issuer with OCSP (preferred) and signed CRLs (fallback).
//
// Check takes the issuer from the caller's verified chain; it never derives it
// from client-supplied material.
package revocation

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Status is the outcome of a revocation check. Only StatusGood passes.
type Status string

// Status values (spec "Revocation", status model).
const (
	StatusGood              Status = "good"
	StatusRevoked           Status = "revoked"
	StatusUnknown           Status = "unknown"
	StatusUnavailable       Status = "unavailable"
	StatusStale             Status = "stale"
	StatusInvalidEvidence   Status = "invalid_evidence"
	StatusUnsupportedMethod Status = "unsupported_method"
)

// Valid reports whether s is one of the defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusGood, StatusRevoked, StatusUnknown, StatusUnavailable, StatusStale,
		StatusInvalidEvidence, StatusUnsupportedMethod:
		return true
	}
	return false
}

// Method is the evidence type that produced a status.
type Method string

// Method values.
const (
	MethodOCSP Method = "ocsp"
	MethodCRL  Method = "crl"
)

// DefaultMaxAgeWithoutNextUpdate bounds an OCSP response that omits nextUpdate.
const DefaultMaxAgeWithoutNextUpdate = 15 * time.Minute

// ClockSkew is the tolerance applied to evidence thisUpdate only.
const ClockSkew = 5 * time.Minute

// Policy is the per-profile revocation configuration. Hosts are exact,
// lowercase DNS names, optionally with ":port" when the URL uses a
// non-default port. No wildcards.
type Policy struct {
	// OCSPHosts lists the hosts that leaf AIA OCSP URLs may point to.
	OCSPHosts []string
	// CRLHosts lists the hosts that CDP URLs may point to.
	CRLHosts []string
	// AllowCRL enables the CRL fallback.
	AllowCRL bool
	// OCSPNonce sends a 32-byte nonce and requires the responder to echo it.
	OCSPNonce bool
	// MaxAgeWithoutNextUpdate bounds thisUpdate when nextUpdate is absent.
	// Zero means DefaultMaxAgeWithoutNextUpdate.
	MaxAgeWithoutNextUpdate time.Duration
}

// Validate checks the policy is well formed.
func (p Policy) Validate() error {
	var errs []error
	for _, h := range append(append([]string(nil), p.OCSPHosts...), p.CRLHosts...) {
		if err := validateHostEntry(h); err != nil {
			errs = append(errs, err)
		}
	}
	if p.AllowCRL && len(p.CRLHosts) == 0 {
		errs = append(errs, errors.New("revocation: AllowCRL without CRLHosts"))
	}
	if len(p.OCSPHosts) == 0 && !p.AllowCRL {
		errs = append(errs, errors.New("revocation: no OCSP host and CRL not allowed"))
	}
	if p.MaxAgeWithoutNextUpdate < 0 {
		errs = append(errs, errors.New("revocation: negative MaxAgeWithoutNextUpdate"))
	}
	return errors.Join(errs...)
}

// MaxAge returns the effective bound for responses without nextUpdate.
func (p Policy) MaxAge() time.Duration {
	if p.MaxAgeWithoutNextUpdate == 0 {
		return DefaultMaxAgeWithoutNextUpdate
	}
	return p.MaxAgeWithoutNextUpdate
}

// AllHosts returns the union of OCSP and CRL hosts.
func (p Policy) AllHosts() []string {
	return append(append([]string(nil), p.OCSPHosts...), p.CRLHosts...)
}

func validateHostEntry(h string) error {
	if h == "" || h != strings.ToLower(h) || strings.ContainsAny(h, "/*@ ") {
		return fmt.Errorf("revocation: invalid host entry %q", h)
	}
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host, port = h, ""
	}
	if host == "" || net.ParseIP(host) != nil {
		return fmt.Errorf("revocation: host entry %q must be a DNS name", h)
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("revocation: invalid port in host entry %q", h)
		}
	}
	return nil
}

// Result is the outcome of Checker.Check for one certificate.
type Result struct {
	Status     Status
	Method     Method    // method that produced Status; "" when no method was usable
	CheckedAt  time.Time // time of the check (Checker clock)
	ThisUpdate time.Time
	NextUpdate time.Time // zero when the evidence carries none
	Source     string    // host that served the evidence
	RevokedAt  time.Time // zero unless Status == StatusRevoked
	Reason     int       // RFC 5280 CRLReason; -1 when absent
	Detail     string    // technical detail, never identity data
	Attempts   []Attempt // every attempt, in order, for diagnostics
}

// Attempt records one OCSP or CRL attempt for the diagnostic report.
type Attempt struct {
	Method           Method
	URL              string
	HTTPStatus       int
	Duration         time.Duration
	Outcome          Status
	Detail           string
	FromCache        bool
	ProducedAt       time.Time
	ThisUpdate       time.Time
	NextUpdate       time.Time
	ResponderSubject string
	NonceSent        bool
	NonceEchoed      bool
}
```

`internal/testpki/der.go`:
```go
package testpki

import (
	"encoding/asn1"
	"math/big"
	"time"
	"unicode/utf16"
)

// DER tag bytes used by the hand-written encoders below.
const (
	tagBoolean         = 0x01
	tagInteger         = 0x02
	tagBitString       = 0x03
	tagOctetString     = 0x04
	tagNull            = 0x05
	tagEnumerated      = 0x0a
	tagUTF8String      = 0x0c
	tagPrintableString = 0x13
	tagT61String       = 0x14
	tagIA5String       = 0x16
	tagGeneralizedTime = 0x18
	tagBMPString       = 0x1e
	tagSequence        = 0x30
	tagSet             = 0x31
)

// tlv returns tag || DER length || concatenation of contents.
func tlv(tag byte, contents ...[]byte) []byte {
	var body []byte
	for _, c := range contents {
		body = append(body, c...)
	}
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

func seq(contents ...[]byte) []byte { return tlv(tagSequence, contents...) }

// ctx returns a context-specific tag: constructed when explicit or when the
// implicitly tagged type is constructed.
func ctx(n byte, constructed bool, contents ...[]byte) []byte {
	tag := 0x80 | n
	if constructed {
		tag |= 0x20
	}
	return tlv(tag, contents...)
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func derOID(oid asn1.ObjectIdentifier) []byte { return mustMarshal(oid) }
func derInt(n *big.Int) []byte                { return mustMarshal(n) }
func derNull() []byte                         { return []byte{tagNull, 0x00} }
func derOctets(b []byte) []byte               { return tlv(tagOctetString, b) }
func derEnum(n int) []byte                    { return tlv(tagEnumerated, []byte{byte(n)}) }

// derGeneralizedTime encodes t (UTC, whole seconds) as GeneralizedTime.
func derGeneralizedTime(t time.Time) []byte {
	return tlv(tagGeneralizedTime, []byte(t.UTC().Format("20060102150405Z")))
}

// derTime encodes t as UTCTime before 2050 and GeneralizedTime after (RFC 5280).
func derTime(t time.Time) []byte {
	t = t.UTC()
	if t.Year() < 2050 && t.Year() >= 1950 {
		return tlv(0x17, []byte(t.Format("060102150405Z")))
	}
	return derGeneralizedTime(t)
}

func derBitString(b []byte) []byte { return tlv(tagBitString, append([]byte{0}, b...)) }

// encodeString encodes s with the given universal string tag.
func encodeString(tag int, s string) []byte {
	if tag == tagBMPString {
		var b []byte
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u>>8), byte(u))
		}
		return tlv(tagBMPString, b)
	}
	return tlv(byte(tag), []byte(s))
}

func derExtensions(exts []extension) []byte {
	var items [][]byte
	for _, e := range exts {
		parts := [][]byte{derOID(e.id)}
		if e.critical {
			parts = append(parts, []byte{tagBoolean, 0x01, 0xff})
		}
		parts = append(parts, derOctets(e.value))
		items = append(items, seq(parts...))
	}
	return seq(items...)
}

type extension struct {
	id       asn1.ObjectIdentifier
	critical bool
	value    []byte
}
```

`internal/testpki/testpki.go`:
```go
// Package testpki builds synthetic PKIs for tests: CAs, intermediates and
// leaves with arbitrary raw subjects, SAN directoryName entries,
// SubjectDirectoryAttributes, policies, KU/EKU, critical extensions, AIA/CDP,
// weak keys and SHA-1 signatures; OCSP responders with configurable answers;
// CRL issuers with IssuingDistributionPoint variants; and an in-process fake
// network for HTTP fetches. It is imported only from _test.go files.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// Common attribute and extension OIDs.
var (
	OIDCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	OIDSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
	OIDCountry                = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDLocality               = asn1.ObjectIdentifier{2, 5, 4, 7}
	OIDOrganization           = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDOrganizationalUnit     = asn1.ObjectIdentifier{2, 5, 4, 11}
	OIDTitle                  = asn1.ObjectIdentifier{2, 5, 4, 12}
	OIDDescription            = asn1.ObjectIdentifier{2, 5, 4, 13}
	OIDGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
	OIDOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	OIDUID                    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	OIDEmailAddress           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	OIDExtSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDExtSubjectDirAttrs     = asn1.ObjectIdentifier{2, 5, 29, 9}
	OIDExtCRLDistPoints       = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDExtQCStatements        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	OIDExtOCSPNoCheck         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	OIDAttrDateOfBirth        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
	OIDAttrCountryOfResidence = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 5}
)

// String tags accepted by Attr.Tag.
const (
	TagUTF8      = tagUTF8String
	TagPrintable = tagPrintableString
	TagTeletex   = tagT61String
	TagIA5       = tagIA5String
	TagBMP       = tagBMPString
)

// Attr is one AttributeTypeAndValue. Tag 0 means UTF8String.
type Attr struct {
	OID   asn1.ObjectIdentifier
	Value string
	Tag   int
}

// RDN is one RelativeDistinguishedName; more than one Attr makes it multi-valued.
// Attributes are encoded in the given order (tests may build non-DER SETs).
type RDN []Attr

// Name is an RDNSequence encoded verbatim: order and duplicates preserved.
type Name []RDN

// UTF8 returns a single-attribute RDN with a UTF8String value.
func UTF8(oid asn1.ObjectIdentifier, v string) RDN { return RDN{{OID: oid, Value: v, Tag: TagUTF8}} }

// Printable returns a single-attribute RDN with a PrintableString value.
func Printable(oid asn1.ObjectIdentifier, v string) RDN {
	return RDN{{OID: oid, Value: v, Tag: TagPrintable}}
}

// Tagged returns a single-attribute RDN with an explicit string tag.
func Tagged(oid asn1.ObjectIdentifier, tag int, v string) RDN {
	return RDN{{OID: oid, Value: v, Tag: tag}}
}

// DER encodes the name.
func (n Name) DER() []byte {
	var rdns [][]byte
	for _, rdn := range n {
		var atvs [][]byte
		for _, a := range rdn {
			tag := a.Tag
			if tag == 0 {
				tag = TagUTF8
			}
			atvs = append(atvs, seq(derOID(a.OID), encodeString(tag, a.Value)))
		}
		rdns = append(rdns, tlv(tagSet, atvs...))
	}
	return seq(rdns...)
}

// KeySpec selects a key algorithm and size.
type KeySpec int

// Key specs. Weak ones exist to test weak_algorithm.
const (
	ECDSAP256 KeySpec = iota + 1
	ECDSAP384
	ECDSAP521
	ECDSAP224
	RSA1024
	RSA1920
	RSA2048
	RSA3072
	RSA4096
)

// NewKey generates a fresh key. Every call returns a distinct key.
func NewKey(t testing.TB, k KeySpec) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch k {
	case ECDSAP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ECDSAP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case ECDSAP521:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case ECDSAP224:
		key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case RSA1024:
		key, err = rsa.GenerateKey(rand.Reader, 1024)
	case RSA1920:
		key, err = rsa.GenerateKey(rand.Reader, 1920)
	case RSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		t.Fatalf("testpki: unknown key spec %d", k)
	}
	if err != nil {
		t.Fatalf("testpki: generate key: %v", err)
	}
	return key
}

// DistributionPoint is one CRL DistributionPoint (fullName form). Names are
// encoded URIs first, then directoryNames, unless DirNamesFirst is set.
type DistributionPoint struct {
	URIs          []string
	DirNames      []Name
	DirNamesFirst bool
}

// CertSpec describes a certificate. Zero fields take the defaults noted.
type CertSpec struct {
	Subject            Name               // leaf: required; CA: default CN=<label>,O=testpki,C=ES
	Key                KeySpec            // default ECDSAP256
	KeyPair            crypto.Signer      // overrides Key (reuse a key across certificates)
	Serial             *big.Int           // default random 128-bit positive
	NotBefore          time.Time          // default Now - 1h
	NotAfter           time.Time          // default Now + 365 days
	Now                time.Time          // reference time for defaults; default time.Now()
	KeyUsage           x509.KeyUsage      // default: leaf DigitalSignature; CA CertSign|CRLSign
	NoKeyUsage         bool               // omit the KeyUsage extension
	ExtKeyUsage        []x509.ExtKeyUsage // nil and UnknownEKU nil: extension omitted
	UnknownEKU         []asn1.ObjectIdentifier
	Policies           []asn1.ObjectIdentifier // certificatePolicies (no qualifiers)
	OCSPServers        []string                // AIA id-ad-ocsp
	CAIssuers          []string                // AIA id-ad-caIssuers
	CDP                []DistributionPoint     // cRLDistributionPoints
	SANDirNames        []Name                  // SAN directoryName entries
	SANEmails          []string                // SAN rfc822Name entries
	SANRaw             []byte                  // full SAN extension value (overrides SANDirNames/SANEmails)
	DateOfBirth        string                  // SDA dateOfBirth GeneralizedTime text, e.g. "19800101120000Z"
	SDARaw             []byte                  // full SDA extension value (overrides DateOfBirth)
	PathLen            *int                    // CA only; nil = no pathLenConstraint, new(0) = pathlen:0
	ExtraExtensions    []pkix.Extension        // e.g. critical qcStatements or an unknown critical OID
	SignatureAlgorithm x509.SignatureAlgorithm // e.g. x509.SHA1WithRSA; default per issuer key
}

// CA is a certificate authority that can issue certificates, OCSP responses and CRLs.
type CA struct {
	Cert  *x509.Certificate
	Key   crypto.Signer
	Label string
}

// Leaf is an end-entity certificate with its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// TLSCertificate returns the leaf as a tls.Certificate (leaf only in the chain).
func (l *Leaf) TLSCertificate(extra ...*x509.Certificate) tls.Certificate {
	chain := [][]byte{l.Cert.Raw}
	for _, c := range extra {
		chain = append(chain, c.Raw)
	}
	return tls.Certificate{Certificate: chain, PrivateKey: l.Key, Leaf: l.Cert}
}

// NewRoot creates a self-signed CA.
func NewRoot(t testing.TB, label string, spec CertSpec) *CA {
	t.Helper()
	key := spec.KeyPair
	if key == nil {
		key = NewKey(t, orDefault(spec.Key, ECDSAP256))
	}
	if spec.Subject == nil {
		spec.Subject = defaultCAName(label)
	}
	tpl := template(t, spec, true)
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("testpki: create root %s: %v", label, err)
	}
	return &CA{Cert: mustParse(t, der), Key: key, Label: label}
}

// Intermediate issues a CA certificate.
func (ca *CA) Intermediate(t testing.TB, label string, spec CertSpec) *CA {
	t.Helper()
	key := spec.KeyPair
	if key == nil {
		key = NewKey(t, orDefault(spec.Key, ECDSAP256))
	}
	if spec.Subject == nil {
		spec.Subject = defaultCAName(label)
	}
	der := ca.sign(t, template(t, spec, true), key.Public())
	return &CA{Cert: mustParse(t, der), Key: key, Label: label}
}

// Leaf issues an end-entity certificate.
func (ca *CA) Leaf(t testing.TB, spec CertSpec) *Leaf {
	t.Helper()
	if spec.Subject == nil {
		t.Fatal("testpki: leaf needs a Subject")
	}
	key := spec.KeyPair
	if key == nil {
		key = NewKey(t, orDefault(spec.Key, ECDSAP256))
	}
	der := ca.sign(t, template(t, spec, false), key.Public())
	return &Leaf{Cert: mustParse(t, der), Key: key}
}

// OCSPResponder issues a delegated responder certificate: EKU OCSPSigning,
// id-pkix-ocsp-nocheck, KU digitalSignature. spec may override any field.
func (ca *CA) OCSPResponder(t testing.TB, spec CertSpec) *Responder {
	t.Helper()
	if spec.Subject == nil {
		spec.Subject = Name{UTF8(OIDCommonName, ca.Label+" OCSP"), Printable(OIDCountry, "ES")}
	}
	if spec.ExtKeyUsage == nil && spec.UnknownEKU == nil {
		spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	spec.ExtraExtensions = append(spec.ExtraExtensions,
		pkix.Extension{Id: OIDExtOCSPNoCheck, Value: derNull()})
	l := ca.Leaf(t, spec)
	return &Responder{Cert: l.Cert, Key: l.Key}
}

// AsResponder returns a Responder that signs with the CA key itself.
func (ca *CA) AsResponder() *Responder { return &Responder{Cert: ca.Cert, Key: ca.Key} }

// SHA256Hex returns the hex SHA-256 of DER bytes.
func SHA256Hex(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// PEM encodes a certificate as PEM.
func PEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func (ca *CA) sign(t testing.TB, tpl *x509.Certificate, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatalf("testpki: issue under %s: %v", ca.Label, err)
	}
	return der
}

func defaultCAName(label string) Name {
	return Name{
		Printable(OIDCountry, "ES"),
		UTF8(OIDOrganization, "testpki"),
		UTF8(OIDCommonName, label),
	}
}

func orDefault(k, def KeySpec) KeySpec {
	if k == 0 {
		return def
	}
	return k
}

func template(t testing.TB, spec CertSpec, isCA bool) *x509.Certificate {
	t.Helper()
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	serial := spec.Serial
	if serial == nil {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		b[0] &= 0x7f
		b[0] |= 0x01
		serial = new(big.Int).SetBytes(b)
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		RawSubject:            spec.Subject.DER(),
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		ExtKeyUsage:           spec.ExtKeyUsage,
		UnknownExtKeyUsage:    spec.UnknownEKU,
		OCSPServer:            spec.OCSPServers,
		IssuingCertificateURL: spec.CAIssuers,
		SignatureAlgorithm:    spec.SignatureAlgorithm,
		ExtraExtensions:       append([]pkix.Extension(nil), spec.ExtraExtensions...),
	}
	if tpl.NotBefore.IsZero() {
		tpl.NotBefore = now.Add(-time.Hour)
	}
	if tpl.NotAfter.IsZero() {
		tpl.NotAfter = now.Add(365 * 24 * time.Hour)
	}
	switch {
	case spec.NoKeyUsage:
	case spec.KeyUsage != 0:
		tpl.KeyUsage = spec.KeyUsage
	case isCA:
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	default:
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	tpl.MaxPathLen = -1
	if isCA && spec.PathLen != nil {
		tpl.MaxPathLen = *spec.PathLen
		tpl.MaxPathLenZero = *spec.PathLen == 0
	}
	for _, p := range spec.Policies {
		oid, err := x509.OIDFromInts(oidInts(p))
		if err != nil {
			t.Fatalf("testpki: policy %v: %v", p, err)
		}
		tpl.Policies = append(tpl.Policies, oid)
	}
	if len(spec.CDP) > 0 {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtCRLDistPoints, Value: encodeCDP(spec.CDP)})
	}
	switch {
	case spec.SANRaw != nil:
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectAltName, Value: spec.SANRaw})
	case len(spec.SANDirNames) > 0 || len(spec.SANEmails) > 0:
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectAltName, Value: encodeSAN(spec.SANEmails, spec.SANDirNames)})
	}
	switch {
	case spec.SDARaw != nil:
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectDirAttrs, Value: spec.SDARaw})
	case spec.DateOfBirth != "":
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: OIDExtSubjectDirAttrs, Value: DateOfBirthSDA(spec.DateOfBirth)})
	}
	return tpl
}

// DateOfBirthSDA encodes SubjectDirectoryAttributes holding one dateOfBirth
// attribute whose value is GeneralizedTime text gt (not validated).
func DateOfBirthSDA(gt string) []byte {
	return seq(seq(derOID(OIDAttrDateOfBirth), tlv(tagSet, tlv(tagGeneralizedTime, []byte(gt)))))
}

func encodeSAN(emails []string, dirs []Name) []byte {
	var names [][]byte
	for _, e := range emails {
		names = append(names, ctx(1, false, []byte(e)))
	}
	for _, d := range dirs {
		names = append(names, ctx(4, true, d.DER()))
	}
	return seq(names...)
}

func encodeGeneralNames(uris []string, dirs []Name, dirsFirst bool) []byte {
	var u, d []byte
	for _, name := range dirs {
		d = append(d, ctx(4, true, name.DER())...)
	}
	for _, uri := range uris {
		u = append(u, ctx(6, false, []byte(uri))...)
	}
	if dirsFirst {
		return append(d, u...)
	}
	return append(u, d...)
}

func encodeCDP(dps []DistributionPoint) []byte {
	var items [][]byte
	for _, dp := range dps {
		items = append(items, seq(ctx(0, true, ctx(0, true, encodeGeneralNames(dp.URIs, dp.DirNames, dp.DirNamesFirst)))))
	}
	return seq(items...)
}

func oidInts(oid asn1.ObjectIdentifier) []uint64 {
	out := make([]uint64, len(oid))
	for i, v := range oid {
		out[i] = uint64(v)
	}
	return out
}

func mustParse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testpki: parse: %v", err)
	}
	return c
}

// signDigest signs data with key using SHA-256 and returns the signature and
// the DER AlgorithmIdentifier.
func signDigest(key crypto.Signer, data []byte) (sig, algID []byte, err error) {
	h := sha256.Sum256(data)
	sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}
	return sig, algIDFor(key.Public()), nil
}

// algIDFor returns the SHA-256 signature AlgorithmIdentifier for a public key.
func algIDFor(pub crypto.PublicKey) []byte {
	if _, ok := pub.(*rsa.PublicKey); ok {
		return seq(derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), derNull())
	}
	return seq(derOID(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}))
}
```

`internal/testpki/ocsp.go`:
```go
package testpki

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // OCSP CertID hashing, not a signature
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"
)

var (
	oidOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidSHA1      = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// Responder is an OCSP signing identity (delegated responder or the CA itself).
type Responder struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// CertStatus is the OCSP certStatus to answer.
type CertStatus int

// OCSP certStatus values.
const (
	Good CertStatus = iota
	Revoked
	Unknown
)

// ResponderIDKind selects the ResponderID CHOICE.
type ResponderIDKind int

// ResponderID choices.
const (
	ByName ResponderIDKind = iota
	ByKey
)

// NonceMode controls the nonce extension in the response.
type NonceMode int

// Nonce modes.
const (
	NonceEcho  NonceMode = iota // echo the request nonce if one was sent
	NonceOmit                   // never include a nonce
	NonceWrong                  // include a different 32-byte nonce
)

// Request is the parsed content of an OCSP request seen by an OCSPServer.
type Request struct {
	HashAlgorithm  asn1.ObjectIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	Serial         *big.Int
	Nonce          []byte // extnValue bytes of the nonce extension; nil if absent
	Count          int    // number of Request entries in requestList
}

// OCSPSpec configures one OCSP response. Zero fields take the defaults noted.
type OCSPSpec struct {
	ResponseStatus int        // 0 successful (default); 1..6 error statuses (no responseBytes)
	Status         CertStatus // default Good
	RevokedAt      time.Time  // default ThisUpdate - 24h
	Reason         int        // CRLReason for Revoked (0 = unspecified, 6 = certificateHold)
	OmitReason     bool       // omit revocationReason
	ThisUpdate     time.Time  // default Now - 1m
	NextUpdate     time.Time  // zero: omitted
	ProducedAt     time.Time  // default ThisUpdate
	Now            time.Time  // reference for defaults; default time.Now()

	Signer        *Responder // default: the server's responder
	ResponderID   ResponderIDKind
	ResponderIDOf *x509.Certificate   // build ResponderID from this cert instead of the signer's
	Certs         []*x509.Certificate // embedded certs; nil: [Signer.Cert] unless Signer is the issuer
	NoCerts       bool                // embed no certificate

	Nonce NonceMode

	SerialOverride     *big.Int // answer for another serial
	NameHashOverride   []byte
	KeyHashOverride    []byte
	CertIDHash         crypto.Hash // default: the request's hash (SHA-1 when unknown)
	DuplicateSingle    bool        // add a second identical SingleResponse
	SingleExtensions   []pkix.Extension
	ResponseExtensions []pkix.Extension
	CorruptSignature   bool
}

// BuildOCSPResponse encodes an OCSPResponse answering req for a certificate
// issued by issuer.
func BuildOCSPResponse(t testing.TB, issuer *CA, req Request, spec OCSPSpec) []byte {
	t.Helper()
	if spec.ResponseStatus != 0 {
		return seq(derEnum(spec.ResponseStatus))
	}
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	if spec.ThisUpdate.IsZero() {
		spec.ThisUpdate = now.Add(-time.Minute)
	}
	if spec.ProducedAt.IsZero() {
		spec.ProducedAt = spec.ThisUpdate
	}
	if spec.RevokedAt.IsZero() {
		spec.RevokedAt = spec.ThisUpdate.Add(-24 * time.Hour)
	}
	signer := spec.Signer
	if signer == nil {
		t.Fatal("testpki: OCSPSpec.Signer is nil")
	}

	h := spec.CertIDHash
	if h == 0 {
		h = crypto.SHA1
		if req.HashAlgorithm.Equal(oidSHA256) {
			h = crypto.SHA256
		}
	}
	nameHash, keyHash := CertIDHashes(t, h, issuer.Cert)
	if spec.NameHashOverride != nil {
		nameHash = spec.NameHashOverride
	}
	if spec.KeyHashOverride != nil {
		keyHash = spec.KeyHashOverride
	}
	serial := req.Serial
	if spec.SerialOverride != nil {
		serial = spec.SerialOverride
	}
	hashOID := oidSHA1
	if h == crypto.SHA256 {
		hashOID = oidSHA256
	}
	certID := seq(seq(derOID(hashOID), derNull()), derOctets(nameHash), derOctets(keyHash), derInt(serial))

	var status []byte
	switch spec.Status {
	case Good:
		status = ctx(0, false)
	case Revoked:
		parts := [][]byte{derGeneralizedTime(spec.RevokedAt)}
		if !spec.OmitReason {
			parts = append(parts, ctx(0, true, derEnum(spec.Reason)))
		}
		status = ctx(1, true, parts...)
	case Unknown:
		status = ctx(2, false)
	}
	single := [][]byte{certID, status, derGeneralizedTime(spec.ThisUpdate)}
	if !spec.NextUpdate.IsZero() {
		single = append(single, ctx(0, true, derGeneralizedTime(spec.NextUpdate)))
	}
	if len(spec.SingleExtensions) > 0 {
		single = append(single, ctx(1, true, derExtensions(toExts(spec.SingleExtensions))))
	}
	singles := [][]byte{seq(single...)}
	if spec.DuplicateSingle {
		singles = append(singles, seq(single...))
	}

	idCert := signer.Cert
	if spec.ResponderIDOf != nil {
		idCert = spec.ResponderIDOf
	}
	var responderID []byte
	if spec.ResponderID == ByKey {
		responderID = ctx(2, true, derOctets(SPKIKeyHash(t, idCert)))
	} else {
		responderID = ctx(1, true, idCert.RawSubject)
	}

	var respExts []extension
	switch {
	case spec.Nonce == NonceEcho && req.Nonce != nil:
		respExts = append(respExts, extension{id: oidOCSPNonce, value: req.Nonce})
	case spec.Nonce == NonceWrong:
		respExts = append(respExts, extension{id: oidOCSPNonce, value: derOctets(make([]byte, 32))})
	}
	respExts = append(respExts, toExts(spec.ResponseExtensions)...)

	tbs := [][]byte{responderID, derGeneralizedTime(spec.ProducedAt), seq(singles...)}
	if len(respExts) > 0 {
		tbs = append(tbs, ctx(1, true, derExtensions(respExts)))
	}
	tbsDER := seq(tbs...)
	sig, algID, err := signDigest(signer.Key, tbsDER)
	if err != nil {
		t.Fatalf("testpki: sign OCSP: %v", err)
	}
	if spec.CorruptSignature {
		sig[len(sig)-1] ^= 0xff
	}
	basic := [][]byte{tbsDER, algID, derBitString(sig)}
	certs := spec.Certs
	if certs == nil && !spec.NoCerts && !signer.Cert.Equal(issuer.Cert) {
		certs = []*x509.Certificate{signer.Cert}
	}
	if len(certs) > 0 && !spec.NoCerts {
		var raw []byte
		for _, c := range certs {
			raw = append(raw, c.Raw...)
		}
		basic = append(basic, ctx(0, true, tlv(tagSequence, raw)))
	}
	return seq(derEnum(0), ctx(0, true, seq(derOID(oidOCSPBasic), derOctets(seq(basic...)))))
}

// CertIDHashes returns issuerNameHash and issuerKeyHash for issuer under h.
func CertIDHashes(t testing.TB, h crypto.Hash, issuer *x509.Certificate) (nameHash, keyHash []byte) {
	t.Helper()
	key := spkiKeyBits(t, issuer)
	switch h {
	case crypto.SHA1:
		n, k := sha1.Sum(issuer.RawSubject), sha1.Sum(key) //nolint:gosec // CertID
		return n[:], k[:]
	case crypto.SHA256:
		n, k := sha256.Sum256(issuer.RawSubject), sha256.Sum256(key)
		return n[:], k[:]
	}
	t.Fatalf("testpki: unsupported CertID hash %v", h)
	return nil, nil
}

// SPKIKeyHash is the SHA-1 of the subjectPublicKey BIT STRING value (ResponderID byKey).
func SPKIKeyHash(t testing.TB, c *x509.Certificate) []byte {
	t.Helper()
	s := sha1.Sum(spkiKeyBits(t, c)) //nolint:gosec // ResponderID byKey is defined with SHA-1
	return s[:]
}

func spkiKeyBits(t testing.TB, c *x509.Certificate) []byte {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatalf("testpki: SPKI: %v", err)
	}
	return spki.PublicKey.Bytes
}

func toExts(in []pkix.Extension) []extension {
	out := make([]extension, 0, len(in))
	for _, e := range in {
		out = append(out, extension{id: e.Id, critical: e.Critical, value: e.Value})
	}
	return out
}

// ParseOCSPRequest decodes an OCSP request (first Request entry and nonce).
func ParseOCSPRequest(der []byte) (Request, error) {
	type certID struct {
		HashAlgorithm  pkix.AlgorithmIdentifier
		IssuerNameHash []byte
		IssuerKeyHash  []byte
		Serial         *big.Int
	}
	type request struct {
		Cert certID
		Ext  []pkix.Extension `asn1:"explicit,tag:0,optional"`
	}
	type tbsRequest struct {
		Version       int           `asn1:"explicit,tag:0,default:0,optional"`
		RequestorName asn1.RawValue `asn1:"explicit,tag:1,optional"`
		RequestList   []request
		Extensions    []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	type ocspRequest struct {
		TBS tbsRequest
	}
	var r ocspRequest
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil {
		return Request{}, err
	}
	if len(rest) > 0 || len(r.TBS.RequestList) == 0 {
		return Request{}, asn1.SyntaxError{Msg: "bad OCSP request"}
	}
	first := r.TBS.RequestList[0].Cert
	out := Request{
		HashAlgorithm:  first.HashAlgorithm.Algorithm,
		IssuerNameHash: first.IssuerNameHash,
		IssuerKeyHash:  first.IssuerKeyHash,
		Serial:         first.Serial,
		Count:          len(r.TBS.RequestList),
	}
	for _, e := range r.TBS.Extensions {
		if e.Id.Equal(oidOCSPNonce) {
			out.Nonce = e.Value
		}
	}
	return out, nil
}

// OCSPServer is an http.Handler answering POSTed OCSP requests for one issuer.
// Its answer is chosen per request by the Answer function (default: Good,
// signed by the server's responder, nextUpdate +1h).
type OCSPServer struct {
	Issuer    *CA
	Responder *Responder

	mu       sync.Mutex
	answer   func(Request) OCSPSpec
	raw      func(Request) []byte
	requests []Request
}

// NewOCSPServer returns a server for issuer signed by responder.
func NewOCSPServer(issuer *CA, responder *Responder) *OCSPServer {
	return &OCSPServer{Issuer: issuer, Responder: responder}
}

// SetAnswer sets the per-request response spec.
func (s *OCSPServer) SetAnswer(f func(Request) OCSPSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answer, s.raw = f, nil
}

// SetRawAnswer makes the server reply with arbitrary bytes (malformed/oversized tests).
func (s *OCSPServer) SetRawAnswer(f func(Request) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = f
}

// Requests returns the requests received so far.
func (s *OCSPServer) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Handler returns the HTTP handler; t reports encoding failures.
func (s *OCSPServer) Handler(t testing.TB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/ocsp-request" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		req, err := ParseOCSPRequest(body)
		if err != nil {
			w.Header().Set("Content-Type", "application/ocsp-response")
			_, _ = w.Write(seq(derEnum(1))) // malformedRequest
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, req)
		answer, raw := s.answer, s.raw
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/ocsp-response")
		if raw != nil {
			_, _ = w.Write(raw(req))
			return
		}
		spec := OCSPSpec{NextUpdate: time.Now().Add(time.Hour)}
		if answer != nil {
			spec = answer(req)
		}
		if spec.Signer == nil {
			spec.Signer = s.Responder
		}
		_, _ = w.Write(BuildOCSPResponse(t, s.Issuer, req, spec))
	})
}
```

`internal/testpki/crl.go`:
```go
package testpki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

var (
	oidExtCRLNumber        = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtAKI              = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtIDP              = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidEntryReason         = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidEntryInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}
	OIDEntryCertIssuer     = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// CRLEntry is one revoked certificate.
type CRLEntry struct {
	Serial     *big.Int
	RevokedAt  time.Time
	Reason     int  // CRLReason; ignored when NoReason
	NoReason   bool // omit the reasonCode entry extension
	Extensions []pkix.Extension
}

// IDPSpec describes an IssuingDistributionPoint extension.
type IDPSpec struct {
	URIs            []string // distributionPoint fullName URIs
	DirNames        []Name   // distributionPoint fullName directoryNames
	DirNamesFirst   bool     // encode directoryNames before URIs
	RelativeName    RDN      // nameRelativeToCRLIssuer (instead of fullName) when non-nil
	OnlyUser        bool
	OnlyCA          bool
	OnlySomeReasons bool
	Indirect        bool
	OnlyAttr        bool
	NonCritical     bool // RFC 5280 requires critical; some CAs (EC-ACC) do not
}

// CRLSpec describes a CRL signed by a CA.
type CRLSpec struct {
	Number          int64
	ThisUpdate      time.Time // default Now - 1m
	NextUpdate      time.Time // default ThisUpdate + 24h
	NoNextUpdate    bool
	Now             time.Time
	Entries         []CRLEntry
	IDP             *IDPSpec
	ExtraExtensions []pkix.Extension
	Signer          *CA    // default: the receiver CA (wrong-signer tests set another CA)
	IssuerDER       []byte // override the issuer Name (default: receiver's RawSubject)
	CorruptSig      bool
}

// CRL encodes and signs a CRL for ca.
func (ca *CA) CRL(t testing.TB, spec CRLSpec) []byte {
	t.Helper()
	now := spec.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	if spec.ThisUpdate.IsZero() {
		spec.ThisUpdate = now.Add(-time.Minute)
	}
	if spec.NextUpdate.IsZero() {
		spec.NextUpdate = spec.ThisUpdate.Add(24 * time.Hour)
	}
	signer := spec.Signer
	if signer == nil {
		signer = ca
	}
	issuer := spec.IssuerDER
	if issuer == nil {
		issuer = ca.Cert.RawSubject
	}
	tbs := [][]byte{derInt(big.NewInt(1)), algIDFor(signer.Key.Public()), issuer, derTime(spec.ThisUpdate)}
	if !spec.NoNextUpdate {
		tbs = append(tbs, derTime(spec.NextUpdate))
	}
	if len(spec.Entries) > 0 {
		var entries [][]byte
		for _, e := range spec.Entries {
			var exts []extension
			if !e.NoReason {
				exts = append(exts, extension{id: oidEntryReason, value: derEnum(e.Reason)})
			}
			exts = append(exts, toExts(e.Extensions)...)
			parts := [][]byte{derInt(e.Serial), derTime(e.RevokedAt)}
			if len(exts) > 0 {
				parts = append(parts, derExtensions(exts))
			}
			entries = append(entries, seq(parts...))
		}
		tbs = append(tbs, seq(entries...))
	}
	exts := []extension{{id: oidExtCRLNumber, value: derInt(big.NewInt(spec.Number))}}
	if len(ca.Cert.SubjectKeyId) > 0 {
		exts = append(exts, extension{id: oidExtAKI, value: seq(ctx(0, false, ca.Cert.SubjectKeyId))})
	}
	if spec.IDP != nil {
		exts = append(exts, extension{id: oidExtIDP, critical: !spec.IDP.NonCritical, value: EncodeIDP(*spec.IDP)})
	}
	exts = append(exts, toExts(spec.ExtraExtensions)...)
	tbs = append(tbs, ctx(0, true, derExtensions(exts)))
	tbsDER := seq(tbs...)
	sig, algID, err := signDigest(signer.Key, tbsDER)
	if err != nil {
		t.Fatalf("testpki: sign CRL: %v", err)
	}
	if spec.CorruptSig {
		sig[len(sig)-1] ^= 0xff
	}
	return seq(tbsDER, algID, derBitString(sig))
}

// EncodeIDP encodes an IssuingDistributionPoint extension value.
func EncodeIDP(s IDPSpec) []byte {
	var parts [][]byte
	switch {
	case s.RelativeName != nil:
		var atvs [][]byte
		for _, a := range s.RelativeName {
			tag := a.Tag
			if tag == 0 {
				tag = TagUTF8
			}
			atvs = append(atvs, seq(derOID(a.OID), encodeString(tag, a.Value)))
		}
		parts = append(parts, ctx(0, true, ctx(1, true, atvs...)))
	case len(s.URIs) > 0 || len(s.DirNames) > 0:
		parts = append(parts, ctx(0, true, ctx(0, true, encodeGeneralNames(s.URIs, s.DirNames, s.DirNamesFirst))))
	}
	boolTrue := []byte{0xff}
	if s.OnlyUser {
		parts = append(parts, ctx(1, false, boolTrue))
	}
	if s.OnlyCA {
		parts = append(parts, ctx(2, false, boolTrue))
	}
	if s.OnlySomeReasons {
		parts = append(parts, ctx(3, false, []byte{0x07, 0x80})) // unused=7, keyCompromise
	}
	if s.Indirect {
		parts = append(parts, ctx(4, false, boolTrue))
	}
	if s.OnlyAttr {
		parts = append(parts, ctx(5, false, boolTrue))
	}
	return seq(parts...)
}

// InvalidityDate returns an invalidityDate CRL entry extension.
func InvalidityDate(t time.Time) pkix.Extension {
	return pkix.Extension{Id: oidEntryInvalidityDate, Value: derGeneralizedTime(t)}
}
```

`internal/testpki/net.go`:
```go
package testpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Net is a fake network: DNS names map to in-process httptest servers.
// Its DialContext is meant for revocation.Options.DialContext in tests.
type Net struct {
	mu    sync.Mutex
	hosts map[string]string // "host:port" -> listener address
}

// NewNet returns an empty fake network.
func NewNet() *Net { return &Net{hosts: make(map[string]string)} }

// Serve starts an HTTP server for host (plain HTTP, port 80) and registers it.
// The server is closed when the test ends.
func (n *Net) Serve(t testing.TB, host string, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hosts[net.JoinHostPort(host, "80")] = srv.Listener.Addr().String()
	return srv
}

// DialContext routes registered "host:port" pairs to their servers and fails
// for anything else.
func (n *Net) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	target, ok := n.hosts[addr]
	n.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("testpki: no route to %s", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

// Bytes returns a handler serving body with contentType.
func Bytes(contentType string, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	})
}

// Redirect returns a handler answering 302 to location.
func Redirect(location string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location, http.StatusFound)
	})
}

// Slow returns a handler that waits d (or until the request is cancelled) before h.
func Slow(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(d):
			h.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	})
}

// ServerTLS returns a TLS server certificate for the given DNS names, issued
// by a fresh root, and a pool holding that root (for test clients).
func ServerTLS(t testing.TB, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	root := NewRoot(t, "testpki server root", CertSpec{})
	tpl := CertSpec{
		Subject:     Name{UTF8(OIDCommonName, names[0])},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SANRaw:      dnsSAN(names),
	}
	leaf := root.Leaf(t, tpl)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	return tls.Certificate{Certificate: [][]byte{leaf.Cert.Raw}, PrivateKey: leaf.Key, Leaf: leaf.Cert}, pool
}

func dnsSAN(names []string) []byte {
	var gns [][]byte
	for _, n := range names {
		gns = append(gns, ctx(2, false, []byte(n)))
	}
	return seq(gns...)
}
```

`web/embed.go`, plus `web/static/index.html` holding only
`<!doctype html><title>Certificate Authentication Checker</title>` (Task 11 replaces it):
```go
// Package web holds the embedded static UI (no build step).
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var static embed.FS

// FS returns the UI files rooted at static/.
func FS() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic("web: embedded static directory missing: " + err.Error()) // build-time invariant
	}
	return sub
}
```

Specimens. Copy into `certauth/testdata/specimens/`. Each file is the DER re-encoded as one clean
PEM block (`openssl x509 -in SRC -outform pem` or `-inform der`), with no "Bag Attributes" text:
- the 28 fixtures from `/home/p4u/.cache/cert-check/research/fixtures/certs/`, keeping their names;
- `digitel-ciudadanosw-99949996T.pem` from `…/research/ca-downloads/digitel/CiudadanoSW.crt`;
- only with ruling R-P1:
  - `bewor-pfsoftbt-99949999A.pem` and `bewor-pfsoftbt-revocado-99999999R.pem` from
    `…/ca-downloads/bewor/PFsoftBT.leaf.pem` and `PFsoftBT_revocado.leaf.pem`;
  - `sectigo-citizen-99949990V.pem` and `sectigo-employee-99949993C.pem` from
    `…/ca-downloads/sectigo/extracted/{Citizen,Employee} Qualified Certificate.crt`.

`MANIFEST.md` has these columns: `| file | status | sha256(DER) | issuer CN | validity | source archive (URL; SHA-256) | expected pipeline result (production markers / markers emptied) |`.
`status` is `committed` or `withheld (R-P1)`. `TestSpecimenManifest` requires the file only for
`committed` rows.
- The rows for the 28 come from the research MANIFEST
  (`/home/p4u/.cache/cert-check/research/fixtures/MANIFEST.md`): source archive URLs and SHA-256s,
  the decoded summaries, and its privacy note.
- The rows for the others come from digest C `public_fixtures`.
- The expected results were measured on the scratch pipeline with the clock at NotBefore+30 min:

| specimen(s) | expected (both runs) |
|---|---|
| 14 FNMT (12 RSA, 2 G2), `dnie-ac004-auth-{activo,caducado,revocado}`, DIGITEL, Bewor ×2, Sectigo citizen | `test_certificate`: step `test_marker`, fingerprint in run 1 and `reserved_document` in run 2 |
| `dnie-ac004-firma-*` ×3, `dnie-ac004-firmacentralizada-*` ×3, Sectigo employee | `unsupported_profile` (`.2.2.2.3` / `.2.2.2.11` / `6449.1.2.1.7.3`) |
| `dnie-ac001-*` ×4 | `untrusted_issuer` (AC DNIE 001 is not pinned) |
| `idcat-g2-pf-peca-de-proves-00000000T.pem` | `weak_algorithm` (sha1WithRSA leaf; policy `.3.1.86.1` not enabled) |

| file | sha256(DER) |
|---|---|
| digitel-ciudadanosw-99949996T.pem | fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8 |
| bewor-pfsoftbt-99949999A.pem | da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab |
| bewor-pfsoftbt-revocado-99999999R.pem | 52bef7a958c349ed0dc1881865c911820e9ef9f7b32741d67273a8f1ba527d92 |
| sectigo-citizen-99949990V.pem | 88059e9240bb96734d0a0c07d27a9fbd2741ebbdd49c08004b14b443962f2c30 |
| sectigo-employee-99949993C.pem | 5afc90f8e6a60ce17fc4bb80f11ce1e897565cf8d870e96eeeeaaa9c224df187 |

Run: `go test -race -count=1 ./internal/testpki/... ./certauth/...`, then the Global Constraints
checks.
Expected: `ok  github.com/vocdoni/cert-check/internal/testpki`,
`ok  github.com/vocdoni/cert-check/certauth/revocation`, `ok  github.com/vocdoni/cert-check/certauth`.
Also `go list -deps ./certauth/... | grep -E 'cert-check/(internal|web)'` prints nothing.

Step 3: commit (explicit paths)
`git add go.mod go.sum .gitignore .gitattributes internal/deps internal/testpki certauth/revocation/policy.go certauth/revocation/policy_test.go certauth/testdata/specimens certauth/specimens_test.go web/embed.go web/static/index.html`
`git commit -m "feat(scaffold): add module pins, synthetic pki helper and specimen fixtures" -- <same paths>`

Interfaces this task provides to later tasks:
- `testpki`:
  - names and keys: `Name`, `RDN`, `Attr`, `UTF8`, `Printable`, `Tagged`, `KeySpec` constants,
    `NewKey`;
  - certificates: `CertSpec`, `DistributionPoint`, `CA` (`NewRoot`, `Intermediate`, `Leaf`,
    `OCSPResponder`, `AsResponder`, `CRL`), `Leaf.TLSCertificate`;
  - OCSP: `Responder`, `OCSPSpec`, `CertStatus` (Good/Revoked/Unknown), `ResponderIDKind`,
    `NonceMode`, `Request`, `BuildOCSPResponse`, `ParseOCSPRequest`, `CertIDHashes`, `SPKIKeyHash`,
    `OCSPServer` (`NewOCSPServer`, `SetAnswer`, `SetRawAnswer`, `Requests`, `Handler`);
  - CRLs: `CRLSpec`, `CRLEntry`, `IDPSpec`, `EncodeIDP`, `InvalidityDate`;
  - network and helpers: `Net` (`NewNet`, `Serve`, `DialContext`), `Bytes`, `Redirect`, `Slow`,
    `ServerTLS`, `PEM`, `SHA256Hex`, `DateOfBirthSDA`;
  - OIDs: `OID*`.
- `revocation`: `Status*`, `Method*`, `Policy` (`Validate`, `MaxAge`, `AllHosts`), `Result`,
  `Attempt`, `ClockSkew`, `DefaultMaxAgeWithoutNextUpdate`.
- `web.FS()`. The specimen directory `certauth/testdata/specimens/` and its MANIFEST.


### Task 2: `certauth/identity`: strict parsing, DNI/NIE, adapters, reserved identities
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files: `certauth/identity/{name.go,document.go,extensions.go,adapter.go,reserved.go}` and
`certauth/identity/{name_test.go,document_test.go,extensions_test.go,adapter_test.go,reserved_test.go,fuzz_test.go,specimens_test.go}`.

Goal: AC2. Also the identity half of AC5 (reserved identities and name markers), and the step-7/7b
building blocks of the pipeline.

Behaviour notes (beyond the code):
- String types. `ParseName` records every attribute's tag. String kinds are enforced only when a
  field is read for identity (`Name.Field`), with `DefaultKinds` = UTF8String and PrintableString.
  This keeps subjects that carry other attributes parseable. For example, Lleidanet subjects carry
  an IA5String `emailAddress`, which is never read.
- Duplicates. A duplicated identity attribute must be identical in every occurrence, otherwise
  `ErrInvalid`. This applies within the subject and across SAN dirNames.
- Cross-field comparison. Agreement between subject and SAN uses `ComparisonKey`: normalized,
  diacritics removed, upper-cased. Evidence: FNMT's own specimen 99949990V certifies SN
  `ESPECIMENDIEZ ESPECIMEN-DIEZ` and SAN `.1.3` `ESPECIMEN-DÍEZ`. With a byte-exact comparison it
  would fail `identity_invalid` instead of `test_certificate` (AC5). Reported values keep the
  certified spelling.
- `identity_unsupported_document` covers typed prefixes other than `IDCES-` (and `PNOES-` where a
  profile allows it), and K/L/M personal NIFs. Everything else that fails is `identity_invalid`.
- Errors never contain values. The test `TestErrorsCarryNoValues` enforces it.

Step 1: write the failing tests (all table-driven, got/want):
- `document_test.go`:
  - `TestValidDNI`: `00000000T`, `00012345V` (leading zeros), `12345678Z`, `99949992L` are valid.
    `12345678A` (checksum), `1234567Z` (length), `12345678z` (lower case) and `1234567AZ` are
    invalid.
  - `TestValidNIE`: `X0000000T`, `X1234567L`, `Y1234567X`, `Y0000000Z`, `Z1234567R`, `Z0000000M`
    are valid. `Y0000000R` and `Z0000000W` (digest A's examples) and `W1234567L` are invalid.
  - `TestParseDocument`:
    - `IDCES-12345678Z` → DNI;
    - `IDCES-X1234567L` → NIE;
    - bare with a bare rule → ok, without one → `ErrInvalid`;
    - `PASES-AB123456`, `IDCFR-123456789`, `TINES-12345678Z`, `EX:ES-12345678Z`, `JU:ES-12345678Z`
      → `ErrUnsupportedDocument`;
    - `PNOES-X1234567L` with a PNOES rule → NIE; without one → `ErrUnsupportedDocument`;
    - `PNOES-12345678Z` under a PNOES/NIE-only rule → `ErrInvalid`;
    - `IDCES-X1234567L` under an IDCES/DNI-only rule (SIGNE) → `ErrInvalid`;
    - bare `K1234567L` → `ErrUnsupportedDocument`;
    - `  12345678Z  ` → trimmed ok;
    - `1234 5678Z`, `idces-12345678Z`, `IDCES-012345678R` (9 digits, EADTrust example) → `ErrInvalid`;
    - empty → `ErrInvalid`;
    - `Raw` keeps the prefix and `Source` echoes the argument.
- `name_test.go`:
  - `TestParseNamePreservesOrder`: duplicates and a multi-valued RDN keep their order and RDN index.
  - `TestNameFieldKinds`: BMP/Teletex are rejected by default and accepted with an explicit
    `KindSet`; IA5 is rejected by default.
  - `TestNameFieldText`: rejects control U+0007, U+0085, U+FFFD, U+202E, U+2066, invalid UTF-8,
    PrintableString `*` and `&`.
  - `TestNameFieldDuplicates`: identical duplicates ok, conflicting → `ErrInvalid`.
  - `TestParseNameMalformed`: truncated, trailing bytes, RDN not a SET, empty SET, non-string value
    (constructed) kept as `KindOther` with `Err`, 65 attributes → `ErrInvalid`.
- `extensions_test.go`:
  - `TestParseSANDirectoryNames`: email + two dirNames; DNS-only SAN → none; malformed → error;
    65 entries → error; dirName not constructed → error.
  - `TestDateOfBirth`:
    - `19800101120000Z` → 1980-01-01;
    - `20000529000000Z`;
    - an extra `countryOfResidence` attribute is ignored;
    - UTCTime tag, two values, two dateOfBirth attributes, `19800230120000Z`, `198001011200Z` →
      `ErrInvalid`;
    - absent → found=false.
  - `TestNormalizeName` (NFC composition of `Ñ`, runs of spaces/tabs, trim).
  - `TestComparisonKey` (`ESPECIMEN-DIEZ` == `ESPECIMEN-DÍEZ`; `MUÑOZ` == `MUNOZ`; `GARCIA` != `GARCIAS`).
- `adapter_test.go`. `TestAdapterExtract` builds one table row per adapter shape that Task 6 will
  declare (copy the shapes from Task 6's per-profile table). Leaves come from `testpki`. Rows:
  - FNMT citizen RSA `IDCES-` and bare, with SAN `5734.1.4` bare in both orders (RSA descending, G2
    ascending), SAN second surname absent (single surname), SAN `.1.4` disagreeing → invalid, SAN
    given name disagreeing → invalid, SAN missing → invalid.
  - FNMT G2 bare → invalid.
  - FNMT representative with SAN `.1.4 = IDCES-<id>` and Organization O + 2.5.4.97; O missing →
    invalid.
  - FNMT employee with SAN `2.16.724.1.3.5.7.2.{4,6,7,8}`.
  - idCAT:
    - `IDCES-` with C=ES; C=FR → invalid; `IDCFR-…` → unsupported;
    - legacy suffix `GARCIA LOPEZ - DNI 12345678Z` with a matching number → stripped (and the
      `surnamesQuirk` source set); non-matching → kept verbatim; flag off → kept.
  - ACCV:
    - SAN CN `JUAN|GARCIA|LOPEZ` plus UID → first/second surnames;
    - `JUAN|GARCIA|` (empty second) ok;
    - `JUAN|GARCIA` (2 fields) → invalid;
    - UID ≠ serialNumber → invalid;
    - `IDCES-` under ACCV → invalid;
    - `K1234567L` → unsupported.
  - Firmaprofesional SAN `13177.0.{1,2,3}`.
  - SIGNE `PNOES-X1234567L` → NIE and `IDCES-12345678Z` → DNI.
  - DNIe:
    - CN `GARCÍA LÓPEZ, JOSÉ (AUTENTICACIÓN)` and the unaccented `(AUTENTICACION)` → surnames
      `GARCÍA LÓPEZ`, first `GARCÍA`, second `LÓPEZ`;
    - CN not starting with SN → invalid; CN with a different GN → invalid; CN without suffix →
      invalid; `(FIRMA)` → invalid;
    - SDA birth date present → `BirthDate` set, absent → nil, malformed → invalid;
    - NIE under DNIe → invalid.
  - Non-DNIe adapter with malformed SDA → ok, plus a note.
  - Every row checks `FullName == GivenNames + " " + Surnames` and the exact `Sources` map.
- `TestAdapterValidate`: no document rules, unset rules, `SANPipeCN` without DocumentOID, SAN
  document without rules → error.
- `reserved_test.go`. `TestReservedMatch`:
  - each of the 16 documents → `reserved_document`;
  - surname markers: `De La Peça De Proves` in mixed case, `ESPECIMENDIEZ ESPECIMEN-DIEZ`,
    `FICTICIO`, `APELLIDO1 X`;
  - given names `NOMBRE`, `Ciudadano`, `NOM UN O`, `NOMDOS`, `NOM D'DIEZ`;
  - organization `Entidad de pruebas`;
  - no match for `JUAN GARCIA LOPEZ 12345679S`.
  Also `TestDefaultReservedVersion`.
- `specimens_test.go`. `TestSpecimenIdentities` runs the shaped adapters on the real bytes in
  `../testdata/specimens` and expects these values (test values only):
  - FNMT nosmime 99999999R → DNI `99999999R`, GN `PRUEBAS`, SN `EIDAS CERTIFICADO`, first `EIDAS`,
    second `CERTIFICADO`;
  - legacy 2016 → bare `00000000T`, SN `APELLIDOUNOPF APELLIDODOSPF`;
  - G2 99949991H → first `ESPECIMEN UÑO`;
  - supervisor 99949990V succeeds despite the DÍEZ/DIEZ difference;
  - DNIe AC004 auth activo → surnames `Ficticio Activo`, first `Ficticio`, second `Activo`, DNI
    `00000000T`;
  - DNIe AC001 (accented `AUTENTICACIÓN`) → `99999018D`;
  - DIGITEL → `99949996T`, SN `ESPECIMENSEIS ESPECIMENSEIS`;
  - idCAT 2015 under an `IDCES`-only adapter → `ErrInvalid` (bare), and under a bare adapter →
    `00000000T`.
  Every specimen then matches `DefaultReserved()`.
- `TestErrorsCarryNoValues`: for every failing row above, the error string contains none of the
  input values (document number, names).
- `fuzz_test.go`: `FuzzParseName`, `FuzzParseSANDirectoryNames`, `FuzzParseDateOfBirth`,
  `FuzzParseDocument`. Seeds: specimen `RawSubject`/extension bytes and the table inputs.
  Invariants: no panic. Success implies re-parse stability (`Field` returns the same value twice).
  `ParseDocument` success implies `ValidDNI` or `ValidNIE` of `Number`.

Run: `go test -race -count=1 ./certauth/identity/...` → build failure.

Step 2: implement.

`certauth/identity/name.go`:
```go
// Package identity parses and validates the personal identity carried by a
// certificate: strict RDN parsing of the raw subject, SAN directoryName
// decoding, SubjectDirectoryAttributes dateOfBirth, DNI/NIE grammar and
// checksum, name normalisation, and declarative per-profile adapters.
//
// Errors never contain certificate values: they name fields and rules only.
package identity

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// Sentinel errors. Every error returned by this package wraps exactly one.
var (
	// ErrInvalid: grammar, checksum, string type or cross-field disagreement.
	ErrInvalid = errors.New("identity invalid")
	// ErrUnsupportedDocument: a valid typed identifier that is not a Spanish DNI/NIE.
	ErrUnsupportedDocument = errors.New("identity document unsupported")
)

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// StringKind is the ASN.1 string type of an attribute value.
type StringKind int

// String kinds. Zero is unset.
const (
	KindUTF8 StringKind = iota + 1
	KindPrintable
	KindBMP
	KindTeletex
	KindIA5
	KindOther
)

// KindSet is a set of accepted string kinds for identity fields.
type KindSet []StringKind

// DefaultKinds are the kinds accepted for identity fields unless a profile
// allows more: UTF8String and PrintableString.
var DefaultKinds = KindSet{KindUTF8, KindPrintable}

func (s KindSet) has(k StringKind) bool {
	for _, x := range s {
		if x == k {
			return true
		}
	}
	return false
}

// Attribute is one AttributeTypeAndValue, in DER order.
type Attribute struct {
	OID  asn1.ObjectIdentifier
	Kind StringKind
	Tag  int    // universal tag number of the value
	Raw  []byte // value contents (no tag/length)
	Text string // decoded text; "" when Kind is KindOther or decoding failed
	Err  error  // decoding error, nil when Text is valid for Kind
	RDN  int    // index of the enclosing RDN; multi-valued RDNs share it
}

// Name is a parsed RDNSequence with order, duplicates and multi-valued RDNs preserved.
type Name struct {
	Attributes []Attribute
}

// maxNameAttributes bounds parsing work on hostile input.
const maxNameAttributes = 64

// ParseName strictly parses a DER RDNSequence (for example x509.Certificate.RawSubject).
func ParseName(der []byte) (Name, error) {
	var rdns []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &rdns)
	if err != nil {
		return Name{}, invalidf("name: malformed RDNSequence")
	}
	if len(rest) != 0 {
		return Name{}, invalidf("name: trailing data")
	}
	var out Name
	for i, rdn := range rdns {
		if rdn.Class != asn1.ClassUniversal || rdn.Tag != asn1.TagSet || !rdn.IsCompound {
			return Name{}, invalidf("name: RDN %d is not a SET", i)
		}
		inner := rdn.Bytes
		if len(inner) == 0 {
			return Name{}, invalidf("name: RDN %d is empty", i)
		}
		for len(inner) > 0 {
			var atv struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			inner, err = asn1.Unmarshal(inner, &atv)
			if err != nil {
				return Name{}, invalidf("name: RDN %d: malformed attribute", i)
			}
			if len(out.Attributes) == maxNameAttributes {
				return Name{}, invalidf("name: too many attributes")
			}
			out.Attributes = append(out.Attributes, decodeAttribute(atv.Type, atv.Value, i))
		}
	}
	return out, nil
}

func decodeAttribute(oid asn1.ObjectIdentifier, v asn1.RawValue, rdn int) Attribute {
	a := Attribute{OID: oid, Tag: v.Tag, Raw: v.Bytes, RDN: rdn, Kind: KindOther}
	if v.Class != asn1.ClassUniversal || v.IsCompound {
		a.Err = errors.New("not a universal primitive string")
		return a
	}
	switch v.Tag {
	case asn1.TagUTF8String:
		a.Kind = KindUTF8
		if !utf8.Valid(v.Bytes) {
			a.Err = errors.New("invalid UTF-8")
			return a
		}
		a.Text = string(v.Bytes)
	case asn1.TagPrintableString:
		a.Kind = KindPrintable
		for _, b := range v.Bytes {
			if !isPrintable(b) {
				a.Err = errors.New("invalid PrintableString character")
				return a
			}
		}
		a.Text = string(v.Bytes)
	case asn1.TagIA5String:
		a.Kind = KindIA5
		for _, b := range v.Bytes {
			if b >= 0x80 {
				a.Err = errors.New("invalid IA5String character")
				return a
			}
		}
		a.Text = string(v.Bytes)
	case asn1.TagBMPString:
		a.Kind = KindBMP
		if len(v.Bytes)%2 != 0 {
			a.Err = errors.New("odd BMPString length")
			return a
		}
		u := make([]uint16, len(v.Bytes)/2)
		for i := range u {
			u[i] = uint16(v.Bytes[2*i])<<8 | uint16(v.Bytes[2*i+1])
		}
		for _, c := range u {
			if c >= 0xd800 && c <= 0xdfff {
				a.Err = errors.New("surrogate in BMPString")
				return a
			}
		}
		a.Text = string(utf16.Decode(u))
	case asn1.TagT61String:
		a.Kind = KindTeletex
		r := make([]rune, len(v.Bytes)) // decoded as ISO-8859-1, the common practice
		for i, b := range v.Bytes {
			r[i] = rune(b)
		}
		a.Text = string(r)
	}
	return a
}

// isPrintable reports whether b is in the X.680 PrintableString set.
func isPrintable(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	switch b {
	case ' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?':
		return true
	}
	return false
}

// Field returns the text of the attribute oid for identity use. found is false
// when the attribute is absent. Every occurrence must have an accepted kind and
// clean text; duplicates must be identical, otherwise ErrInvalid.
func (n Name) Field(oid asn1.ObjectIdentifier, kinds KindSet) (value string, found bool, err error) {
	for _, a := range n.Attributes {
		if !a.OID.Equal(oid) {
			continue
		}
		if !kinds.has(a.Kind) {
			return "", true, invalidf("attribute %s: string type not accepted", oid)
		}
		if a.Err != nil {
			return "", true, invalidf("attribute %s: %v", oid, a.Err)
		}
		if err := checkText(a.Text); err != nil {
			return "", true, invalidf("attribute %s: %v", oid, err)
		}
		if found && a.Text != value {
			return "", true, invalidf("attribute %s: conflicting duplicate values", oid)
		}
		value, found = a.Text, true
	}
	return value, found, nil
}

// checkText rejects control characters, U+FFFD and bidi controls.
func checkText(s string) error {
	for _, r := range s {
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f:
			return errors.New("control character")
		case r == utf8.RuneError:
			return errors.New("replacement character")
		case r == 0x061c, r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			return errors.New("bidi control")
		}
	}
	return nil
}
```

`certauth/identity/document.go`:
```go
package identity

import (
	"fmt"
	"strings"
)

// DocumentType is the kind of Spanish identity document.
type DocumentType string

// Document types.
const (
	DocumentDNI DocumentType = "DNI"
	DocumentNIE DocumentType = "NIE"
)

// Encoding is how a profile writes the document number in its source field.
type Encoding string

// Encodings. Each is an exact grammar; nothing is stripped to force a match.
const (
	EncodingIDCES Encoding = "IDCES" // "IDCES-<number>" (ETSI EN 319 412-1)
	EncodingPNOES Encoding = "PNOES" // "PNOES-<number>" (SIGNE NIE only)
	EncodingBare  Encoding = "bare"  // "<number>" (only when the profile declares it)
)

// DocumentRule accepts one encoding with the listed document types.
type DocumentRule struct {
	Encoding Encoding
	Types    []DocumentType
}

// Document is a validated Spanish identity document.
type Document struct {
	Type    DocumentType `json:"type"`
	Country string       `json:"country"` // always "ES"
	Number  string       `json:"number"`  // 9 characters, uppercase, leading zeros kept
	Raw     string       `json:"raw"`     // the field value as certified (after trimming spaces)
	Source  string       `json:"source"`  // provenance, e.g. "subject.2.5.4.5"
}

const controlLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// ValidDNI reports whether s is exactly 8 digits plus the mod-23 letter.
func ValidDNI(s string) bool {
	if len(s) != 9 {
		return false
	}
	n := 0
	for i := range 8 {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return s[8] == controlLetters[n%23]
}

// ValidNIE reports whether s is X/Y/Z + 7 digits + the mod-23 letter
// (X/Y/Z read as 0/1/2).
func ValidNIE(s string) bool {
	if len(s) != 9 {
		return false
	}
	var lead byte
	switch s[0] {
	case 'X':
		lead = '0'
	case 'Y':
		lead = '1'
	case 'Z':
		lead = '2'
	default:
		return false
	}
	return ValidDNI(string(lead) + s[1:])
}

// typedPrefix reports whether v starts with an ETSI-style typed prefix
// ("XXXcc-" or "XX:cc-") and returns it without the dash.
func typedPrefix(v string) (string, bool) {
	isUpper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	if len(v) > 6 && v[5] == '-' && isUpper(v[0]) && isUpper(v[1]) && isUpper(v[2]) && isUpper(v[3]) && isUpper(v[4]) {
		return v[:5], true
	}
	if len(v) > 6 && v[5] == '-' && v[2] == ':' && isUpper(v[0]) && isUpper(v[1]) && isUpper(v[3]) && isUpper(v[4]) {
		return v[:5], true
	}
	return "", false
}

// otherSpanishNIF reports K/L/M personal NIFs and similar letter-led numbers
// that are valid identifiers but not a DNI/NIE.
func otherSpanishNIF(v string) bool {
	if len(v) != 9 || !strings.ContainsRune("KLM", rune(v[0])) {
		return false
	}
	for i := 1; i < 8; i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return v[8] >= 'A' && v[8] <= 'Z'
}

// ParseDocument validates value (the raw field text) against rules.
// Surrounding ASCII spaces are trimmed; anything else must match exactly.
// It returns ErrUnsupportedDocument for a well-formed identifier of another
// document kind, ErrInvalid otherwise.
func ParseDocument(value, source string, rules []DocumentRule) (Document, error) {
	v := strings.Trim(value, " ")
	if v == "" {
		return Document{}, invalidf("%s: empty document", source)
	}
	for i := range len(v) {
		c := v[i]
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == ':') {
			return Document{}, invalidf("%s: document is not uppercase ASCII", source)
		}
	}
	enc, number := EncodingBare, v
	if p, ok := typedPrefix(v); ok {
		switch p {
		case "IDCES":
			enc, number = EncodingIDCES, v[6:]
		case "PNOES":
			enc, number = EncodingPNOES, v[6:]
		default:
			return Document{}, fmt.Errorf("%w: %s: typed identifier %s", ErrUnsupportedDocument, source, p)
		}
	}
	var rule *DocumentRule
	for i := range rules {
		if rules[i].Encoding == enc {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		if enc == EncodingPNOES {
			return Document{}, fmt.Errorf("%w: %s: typed identifier PNOES", ErrUnsupportedDocument, source)
		}
		return Document{}, invalidf("%s: encoding %s not accepted by this profile", source, enc)
	}
	allowed := func(t DocumentType) bool {
		for _, x := range rule.Types {
			if x == t {
				return true
			}
		}
		return false
	}
	switch {
	case ValidDNI(number) && allowed(DocumentDNI):
		return Document{Type: DocumentDNI, Country: "ES", Number: number, Raw: v, Source: source}, nil
	case ValidNIE(number) && allowed(DocumentNIE):
		return Document{Type: DocumentNIE, Country: "ES", Number: number, Raw: v, Source: source}, nil
	case otherSpanishNIF(number):
		return Document{}, fmt.Errorf("%w: %s: personal NIF that is not a DNI/NIE", ErrUnsupportedDocument, source)
	}
	return Document{}, invalidf("%s: number fails the %s grammar or checksum", source, enc)
}
```

`certauth/identity/extensions.go`:
```go
package identity

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var (
	oidExtSubjectAltName  = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtSubjectDirAttrs = asn1.ObjectIdentifier{2, 5, 29, 9}
	oidAttrDateOfBirth    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
)

// maxSANEntries bounds parsing work on hostile input.
const maxSANEntries = 64

// DirectoryNames returns the parsed directoryName entries of the SAN
// extension, in order. A certificate without SAN yields (nil, nil).
func DirectoryNames(cert *x509.Certificate) ([]Name, error) {
	ext, ok := findExtension(cert, oidExtSubjectAltName)
	if !ok {
		return nil, nil
	}
	return ParseSANDirectoryNames(ext)
}

// ParseSANDirectoryNames parses a SubjectAltName extension value and returns
// its directoryName entries.
func ParseSANDirectoryNames(der []byte) ([]Name, error) {
	var gns []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &gns)
	if err != nil || len(rest) != 0 {
		return nil, invalidf("san: malformed GeneralNames")
	}
	if len(gns) > maxSANEntries {
		return nil, invalidf("san: too many entries")
	}
	var out []Name
	for _, gn := range gns {
		if gn.Class != asn1.ClassContextSpecific {
			return nil, invalidf("san: GeneralName is not context-specific")
		}
		if gn.Tag != 4 {
			continue
		}
		if !gn.IsCompound {
			return nil, invalidf("san: directoryName is not constructed")
		}
		n, err := ParseName(gn.Bytes)
		if err != nil {
			return nil, fmt.Errorf("san: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}

// Date is a civil date.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// String formats the date as YYYY-MM-DD.
func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day) }

// MarshalJSON encodes the date as "YYYY-MM-DD".
func (d Date) MarshalJSON() ([]byte, error) { return []byte(`"` + d.String() + `"`), nil }

// DateOfBirth reads SubjectDirectoryAttributes dateOfBirth. found is false
// when the extension or the attribute is absent. The value must be exactly one
// GeneralizedTime "YYYYMMDDHHMMSSZ"; the civil date is its first 8 digits.
func DateOfBirth(cert *x509.Certificate) (d Date, found bool, err error) {
	ext, ok := findExtension(cert, oidExtSubjectDirAttrs)
	if !ok {
		return Date{}, false, nil
	}
	return ParseDateOfBirth(ext)
}

// ParseDateOfBirth parses a SubjectDirectoryAttributes extension value.
func ParseDateOfBirth(der []byte) (d Date, found bool, err error) {
	var attrs []struct {
		Type   asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	rest, err := asn1.Unmarshal(der, &attrs)
	if err != nil || len(rest) != 0 {
		return Date{}, false, invalidf("sda: malformed attributes")
	}
	for _, a := range attrs {
		if !a.Type.Equal(oidAttrDateOfBirth) {
			continue
		}
		if found || len(a.Values) != 1 {
			return Date{}, true, invalidf("sda: dateOfBirth must have exactly one value")
		}
		v := a.Values[0]
		if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagGeneralizedTime || v.IsCompound {
			return Date{}, true, invalidf("sda: dateOfBirth is not GeneralizedTime")
		}
		t, perr := time.Parse("20060102150405Z", string(v.Bytes))
		if perr != nil || len(v.Bytes) != 15 {
			return Date{}, true, invalidf("sda: dateOfBirth is not YYYYMMDDHHMMSSZ")
		}
		d, found = Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}, true
	}
	return d, found, nil
}

func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

// NormalizeName applies NFC, collapses runs of white space to one ASCII
// space and trims. It never splits or reorders words.
func NormalizeName(s string) string {
	return strings.Join(strings.Fields(norm.NFC.String(s)), " ")
}

// ComparisonKey is the key used only for cross-field consistency checks:
// NormalizeName, then diacritics removed (NFD, drop Mn), upper-cased. FNMT's
// own specimen 99949990V certifies SN "ESPECIMEN-DIEZ" and SAN "ESPECIMEN-DÍEZ".
// Reported values always keep the certified spelling.
func ComparisonKey(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(NormalizeName(s)) {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(norm.NFC.String(b.String()))
}
```

`certauth/identity/adapter.go`:
```go
package identity

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
)

// Subject attribute OIDs used by adapters.
var (
	OIDCommonName             = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDSurname                = asn1.ObjectIdentifier{2, 5, 4, 4}
	OIDSerialNumber           = asn1.ObjectIdentifier{2, 5, 4, 5}
	OIDCountry                = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDOrganization           = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDGivenName              = asn1.ObjectIdentifier{2, 5, 4, 42}
	OIDOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	OIDUID                    = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
)

// SurnameRule says where the complete surnames come from.
type SurnameRule int

// Surname rules.
const (
	// SurnamesFromSN: 2.5.4.4 holds the complete surnames.
	SurnamesFromSN SurnameRule = iota + 1
	// SurnamesDNIeCN: 2.5.4.4 holds the first surname only; the complete
	// surnames come from CN "<SURNAMES>, <GIVEN> (AUTENTICACIÓN|AUTENTICACION)".
	SurnamesDNIeCN
)

// SANKind selects the SAN directoryName cross-check.
type SANKind int

// SAN cross-check kinds.
const (
	SANNone SANKind = iota + 1
	// SANAttributes: separate attributes for document, given name, first and
	// second surname (FNMT 5734.1.*, FNMT employee 2.16.724.1.3.5.7.2.*,
	// Firmaprofesional/SIGNE 13177.0.*).
	SANAttributes
	// SANPipeCN: ACCV, CN "GIVEN|SURNAME1|SURNAME2" plus UID = document.
	SANPipeCN
)

// SANCheck declares the SAN consistency fields that must agree with the subject.
// Absent OIDs (nil) are not checked. All present ones are required.
type SANCheck struct {
	Kind             SANKind
	DocumentOID      asn1.ObjectIdentifier // FNMT 5734.1.4; ACCV UID; nil = none
	DocumentRules    []DocumentRule        // grammar of the SAN document value
	GivenNameOID     asn1.ObjectIdentifier
	FirstSurnameOID  asn1.ObjectIdentifier
	SecondSurnameOID asn1.ObjectIdentifier // optional in the certificate (may be absent or empty)
}

// BirthDateRule says whether the profile declares a birth date.
type BirthDateRule int

// Birth date rules.
const (
	// BirthDateNone: SDA is ignored; a malformed SDA is noted, not an error.
	BirthDateNone BirthDateRule = iota + 1
	// BirthDateOptional: dateOfBirth from SDA when present; malformed → ErrInvalid.
	BirthDateOptional
)

// OrganizationRule says whether the profile reports an organization.
type OrganizationRule int

// Organization rules.
const (
	OrganizationNone OrganizationRule = iota + 1
	// OrganizationFromSubject: Name from O (required), Identifier from 2.5.4.97 (optional).
	OrganizationFromSubject
)

// Adapter declares a profile's identity grammar. The zero value is invalid;
// use Validate.
type Adapter struct {
	Documents            []DocumentRule // accepted encodings of subject 2.5.4.5
	Kinds                KindSet        // accepted string kinds; nil = DefaultKinds
	Surnames             SurnameRule
	SAN                  SANCheck
	CountryMatchesPrefix bool // idCAT: subject C must equal the IDC country (ES)
	LegacyDNISuffix      bool // idCAT G2: strip "<SN> - DNI <id>" only when <id> equals the document
	BirthDate            BirthDateRule
	Organization         OrganizationRule
}

// Validate checks the adapter declaration.
func (a Adapter) Validate() error {
	var errs []error
	if len(a.Documents) == 0 {
		errs = append(errs, errors.New("identity: adapter has no document rules"))
	}
	if a.Surnames == 0 || a.SAN.Kind == 0 || a.BirthDate == 0 || a.Organization == 0 {
		errs = append(errs, errors.New("identity: adapter has unset rules"))
	}
	if a.SAN.Kind == SANPipeCN && a.SAN.DocumentOID == nil {
		errs = append(errs, errors.New("identity: SANPipeCN needs DocumentOID"))
	}
	if a.SAN.DocumentOID != nil && len(a.SAN.DocumentRules) == 0 {
		errs = append(errs, errors.New("identity: SAN document without rules"))
	}
	return errors.Join(errs...)
}

// Identity is the typed identity extracted from validated fields.
type Identity struct {
	Document      Document          `json:"document"`
	GivenNames    string            `json:"givenNames"`
	Surnames      string            `json:"surnames"`
	FirstSurname  string            `json:"firstSurname"`
	SecondSurname string            `json:"secondSurname"`
	FullName      string            `json:"fullName"`
	BirthDate     *Date             `json:"birthDate"`
	Sources       map[string]string `json:"sources"`
}

// Organization is the entity a representative or employee acts for. It is
// never the person's identity.
type Organization struct {
	Name       string `json:"name"`
	Identifier string `json:"identifier"`
}

// Extracted is the output of Adapter.Extract.
type Extracted struct {
	Identity     Identity
	Organization *Organization
	// Notes are non-PII remarks for debug logging (e.g. "malformed SDA ignored").
	Notes []string
}

// Extract applies the adapter to a certificate whose chain and profile have
// already been validated.
func (a Adapter) Extract(cert *x509.Certificate) (Extracted, error) {
	if err := a.Validate(); err != nil {
		return Extracted{}, err
	}
	kinds := a.Kinds
	if kinds == nil {
		kinds = DefaultKinds
	}
	subj, err := ParseName(cert.RawSubject)
	if err != nil {
		return Extracted{}, err
	}
	src := map[string]string{}

	rawDoc, ok, err := subj.Field(OIDSerialNumber, kinds)
	if err != nil {
		return Extracted{}, err
	}
	if !ok {
		return Extracted{}, invalidf("subject serialNumber absent")
	}
	doc, err := ParseDocument(rawDoc, "subject.2.5.4.5", a.Documents)
	if err != nil {
		return Extracted{}, err
	}
	src["document"] = doc.Source

	if a.CountryMatchesPrefix && strings.HasPrefix(doc.Raw, "IDC") {
		c, ok, err := subj.Field(OIDCountry, kinds)
		if err != nil {
			return Extracted{}, err
		}
		if !ok || c != doc.Raw[3:5] {
			return Extracted{}, invalidf("subject C does not match the identifier country")
		}
	}

	given, err := requiredName(subj, OIDGivenName, kinds)
	if err != nil {
		return Extracted{}, err
	}
	src["givenNames"] = "subject.2.5.4.42"
	sn, err := requiredName(subj, OIDSurname, kinds)
	if err != nil {
		return Extracted{}, err
	}

	id := Identity{Document: doc, GivenNames: given, Sources: src}
	switch a.Surnames {
	case SurnamesFromSN:
		if a.LegacyDNISuffix {
			// Exact grammar ^(.+) - DNI ([0-9A-Z]+)$ with group 2 == document number.
			if i := strings.LastIndex(sn, " - DNI "); i > 0 && sn[i+len(" - DNI "):] == doc.Number {
				sn = sn[:i]
				src["surnamesQuirk"] = "legacy ' - DNI <id>' suffix removed"
			}
		}
		id.Surnames = sn
		src["surnames"] = "subject.2.5.4.4"
	case SurnamesDNIeCN:
		cn, err := requiredName(subj, OIDCommonName, kinds)
		if err != nil {
			return Extracted{}, err
		}
		full, err := dnieSurnames(cn, sn, given)
		if err != nil {
			return Extracted{}, err
		}
		id.Surnames, id.FirstSurname = full, sn
		id.SecondSurname = strings.TrimPrefix(strings.TrimPrefix(full, sn), " ")
		src["surnames"] = "subject.2.5.4.3 (DNIe CN grammar)"
		src["firstSurname"] = "subject.2.5.4.4"
		if id.SecondSurname != "" {
			src["secondSurname"] = "subject.2.5.4.3 (DNIe CN grammar)"
		}
	default:
		return Extracted{}, invalidf("unknown surname rule")
	}

	if err := a.crossCheckSAN(cert, &id, kinds); err != nil {
		return Extracted{}, err
	}

	out := Extracted{}
	switch a.BirthDate {
	case BirthDateOptional:
		d, found, err := DateOfBirth(cert)
		if err != nil {
			return Extracted{}, err
		}
		if found {
			id.BirthDate = &d
			src["birthDate"] = "sda.1.3.6.1.5.5.7.9.1"
		}
	case BirthDateNone:
		if _, _, err := DateOfBirth(cert); err != nil {
			out.Notes = append(out.Notes, "malformed SubjectDirectoryAttributes ignored")
		}
	}

	if a.Organization == OrganizationFromSubject {
		name, ok, err := subj.Field(OIDOrganization, kinds)
		if err != nil {
			return Extracted{}, err
		}
		if !ok || NormalizeName(name) == "" {
			return Extracted{}, invalidf("subject O absent for an organization profile")
		}
		ident, _, err := subj.Field(OIDOrganizationIdentifier, kinds)
		if err != nil {
			return Extracted{}, err
		}
		out.Organization = &Organization{Name: NormalizeName(name), Identifier: strings.TrimSpace(ident)}
		src["organization"] = "subject.2.5.4.10"
		if ident != "" {
			src["organizationIdentifier"] = "subject.2.5.4.97"
		}
	}

	id.FullName = id.GivenNames + " " + id.Surnames
	out.Identity = id
	return out, nil
}

func requiredName(n Name, oid asn1.ObjectIdentifier, kinds KindSet) (string, error) {
	v, ok, err := n.Field(oid, kinds)
	if err != nil {
		return "", err
	}
	v = NormalizeName(v)
	if !ok || v == "" {
		return "", invalidf("subject %s absent or empty", oid)
	}
	return v, nil
}

// dnieSurnames applies the DNIe CN grammar against the known SN and GN.
func dnieSurnames(cn, sn, given string) (string, error) {
	var rest string
	var ok bool
	for _, suffix := range []string{" (AUTENTICACIÓN)", " (AUTENTICACION)"} {
		if rest, ok = strings.CutSuffix(cn, suffix); ok {
			break
		}
	}
	if !ok {
		return "", invalidf("DNIe CN lacks the authentication suffix")
	}
	full, ok := strings.CutSuffix(rest, ", "+given)
	if !ok {
		return "", invalidf("DNIe CN given name does not match GN")
	}
	if full != sn && !strings.HasPrefix(full, sn+" ") {
		return "", invalidf("DNIe CN surnames do not start with SN")
	}
	return full, nil
}

func (a Adapter) crossCheckSAN(cert *x509.Certificate, id *Identity, kinds KindSet) error {
	if a.SAN.Kind == SANNone {
		return nil
	}
	dirs, err := DirectoryNames(cert)
	if err != nil {
		return err
	}
	field := func(oid asn1.ObjectIdentifier) (string, bool, error) {
		var val string
		var found bool
		for _, d := range dirs {
			v, ok, err := d.Field(oid, kinds)
			if err != nil {
				return "", true, err
			}
			if ok {
				if found && v != val {
					return "", true, invalidf("san %s: conflicting duplicate values", oid)
				}
				val, found = v, true
			}
		}
		return val, found, nil
	}
	if a.SAN.DocumentOID != nil {
		v, ok, err := field(a.SAN.DocumentOID)
		if err != nil {
			return err
		}
		if !ok {
			return invalidf("san document %s absent", a.SAN.DocumentOID)
		}
		sanDoc, err := ParseDocument(v, "san."+a.SAN.DocumentOID.String(), a.SAN.DocumentRules)
		if err != nil {
			return invalidf("san document %s: does not parse", a.SAN.DocumentOID)
		}
		if sanDoc.Number != id.Document.Number || sanDoc.Type != id.Document.Type {
			return invalidf("san document %s disagrees with subject serialNumber", a.SAN.DocumentOID)
		}
	}
	var given, first, second string
	switch a.SAN.Kind {
	case SANAttributes:
		var ok bool
		if a.SAN.GivenNameOID != nil {
			if given, ok, err = field(a.SAN.GivenNameOID); err != nil || !ok {
				return orInvalid(err, "san given name absent")
			}
		}
		if first, ok, err = field(a.SAN.FirstSurnameOID); err != nil || !ok {
			return orInvalid(err, "san first surname absent")
		}
		if a.SAN.SecondSurnameOID != nil {
			if second, _, err = field(a.SAN.SecondSurnameOID); err != nil {
				return err
			}
		}
	case SANPipeCN:
		cn, ok, err := field(OIDCommonName)
		if err != nil || !ok {
			return orInvalid(err, "san CN absent")
		}
		parts := strings.Split(cn, "|")
		if len(parts) != 3 {
			return invalidf("san CN is not GIVEN|SURNAME1|SURNAME2")
		}
		given, first, second = parts[0], parts[1], parts[2]
	}
	given, first, second = NormalizeName(given), NormalizeName(first), NormalizeName(second)
	if first == "" {
		return invalidf("san first surname empty")
	}
	if (a.SAN.GivenNameOID != nil || a.SAN.Kind == SANPipeCN) && ComparisonKey(given) != ComparisonKey(id.GivenNames) {
		return invalidf("san given name disagrees with subject GN")
	}
	joined := first
	if second != "" {
		joined += " " + second
	}
	if ComparisonKey(joined) != ComparisonKey(id.Surnames) {
		return invalidf("san surnames disagree with subject SN")
	}
	id.FirstSurname, id.SecondSurname = first, second
	if a.SAN.Kind == SANPipeCN {
		id.Sources["firstSurname"] = "san.dirName.2.5.4.3[1]"
		if second != "" {
			id.Sources["secondSurname"] = "san.dirName.2.5.4.3[2]"
		}
		return nil
	}
	id.Sources["firstSurname"] = "san.dirName." + a.SAN.FirstSurnameOID.String()
	if second != "" {
		id.Sources["secondSurname"] = "san.dirName." + a.SAN.SecondSurnameOID.String()
	}
	return nil
}

func orInvalid(err error, msg string) error {
	if err != nil {
		return err
	}
	return invalidf("%s", msg)
}
```

`certauth/identity/reserved.go`:
```go
package identity

import (
	"regexp"
	"slices"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// MarkerKind names which reserved-identity rule matched. It never carries a value.
type MarkerKind string

// Marker kinds.
const (
	MarkerDocument     MarkerKind = "reserved_document"
	MarkerSurname      MarkerKind = "surname_marker"
	MarkerGivenName    MarkerKind = "given_name_marker"
	MarkerOrganization MarkerKind = "organization_marker"
)

// Reserved is the versioned registry of test and specimen identities
// (spec "Identity extraction", reserved identities and name markers).
type Reserved struct {
	Version            string
	Documents          []string       // document numbers, exact
	SurnameContains    []string       // compared after NFC + upper-casing
	GivenNameEquals    []string       // compared after NFC + upper-casing
	GivenNamePattern   *regexp.Regexp // applied to the NFC + upper-cased given names
	OrganizationEquals []string       // compared after NFC + upper-casing
}

// DefaultReserved returns the production registry.
func DefaultReserved() Reserved {
	return Reserved{
		Version: "2026-10-31",
		Documents: []string{
			"00000000T", "99999999R", "99999972C", "99999018D", "X0000000T",
			"99949990V", "99949991H", "99949992L", "99949993C", "99949994K",
			"99949995E", "99949996T", "99949997R", "99949998W", "99949999A",
			"12345678Z",
		},
		SurnameContains: []string{
			"ESPECIMEN", "PRUEBAS", "FICTICIO", "APELLIDOUNO", "APELLIDO1",
			"DE LA PEÇA DE PROVES", "DE PROVES",
		},
		GivenNameEquals:    []string{"NOMBRE", "PRUEBAS", "PRUEBASPF", "PRUEBASREV", "CIUDADANO"},
		GivenNamePattern:   regexp.MustCompile(`^NOM ?(UN O|D'DIEZ|DOS|SEIS|NUEVE|DIEZ)$`),
		OrganizationEquals: []string{"ENTIDAD DE PRUEBAS"},
	}
}

func fold(s string) string { return strings.ToUpper(NormalizeName(norm.NFC.String(s))) }

// Match reports whether the extraction hits a reserved identity or a name
// marker. The returned kind never includes the matched value.
func (r Reserved) Match(x Extracted) (MarkerKind, bool) {
	if slices.Contains(r.Documents, x.Identity.Document.Number) {
		return MarkerDocument, true
	}
	sn := fold(x.Identity.Surnames)
	for _, m := range r.SurnameContains {
		if strings.Contains(sn, fold(m)) {
			return MarkerSurname, true
		}
	}
	gn := fold(x.Identity.GivenNames)
	for _, m := range r.GivenNameEquals {
		if gn == fold(m) {
			return MarkerGivenName, true
		}
	}
	if r.GivenNamePattern != nil && r.GivenNamePattern.MatchString(gn) {
		return MarkerGivenName, true
	}
	if x.Organization != nil {
		on := fold(x.Organization.Name)
		for _, m := range r.OrganizationEquals {
			if on == fold(m) {
				return MarkerOrganization, true
			}
		}
	}
	return "", false
}
```

Run:
- `go test -race -count=1 ./certauth/identity/...` → `ok  github.com/vocdoni/cert-check/certauth/identity`;
- for each of the 4 targets, a fuzz smoke:
  `go test -run '^$' -fuzz '^FuzzParseName$' -fuzztime 30s ./certauth/identity` (and likewise for
  the other three) → `PASS`, no new crashers in `testdata/fuzz`;
- the Global Constraints checks.

Step 3: commit
`git commit -m "feat(identity): add strict rdn, san and sda parsing with dni/nie adapters" -- certauth/identity`

Interfaces this task provides to later tasks:
- types: `Attribute`, `Name`, `StringKind`/`KindSet`, `DefaultKinds`, `DocumentType`, `Encoding`,
  `DocumentRule`, `Document`, `Date`;
- functions: `ParseName`, `Name.Field`, `ParseDocument`, `ValidDNI`, `ValidNIE`, `DirectoryNames`,
  `ParseSANDirectoryNames`, `DateOfBirth`, `ParseDateOfBirth`, `NormalizeName`, `ComparisonKey`;
- adapters: `Adapter` (`Validate`, `Extract`), `SurnameRule`, `SANKind`, `SANCheck`,
  `BirthDateRule`, `OrganizationRule`, `Identity`, `Organization`, `Extracted`;
- reserved identities: `Reserved`, `DefaultReserved`, `MarkerKind`;
- sentinel errors `ErrInvalid` and `ErrUnsupportedDocument`, and the OID vars.


### Task 3: `certauth/revocation`: SSRF-safe fetcher, CRL checks, parsed-CRL cache
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `certauth/revocation/{fetcher.go,crl.go,crlcache.go}`;
- `certauth/revocation/{fetcher_test.go,crl_test.go,crlcache_test.go,crl_fuzz_test.go}`;
- `certauth/revocation/testdata/crl/{dnie-arl.crl,aoc-caroot-a.crl,SOURCES.md}` and
  `certauth/revocation/testdata/crl/certs/{ac-raiz-dnie-2.pem,ac-dnie-004.pem,aoc-g3-root-a.pem,aoc-subca-ciutadania-g3-a2.pem}`.

Goal: AC4. CRL good and listed, certificateHold, wrong signer, IDP scope mismatch, expired;
private-IP destination blocked; redirect not followed; non-allowlisted host blocked. Also the
fetcher limits and the CRL cache rules of spec "Revocation".

Behaviour notes:
- The CDP is parsed by `ParseCDP`, never from `x509.Certificate.CRLDistributionPoints`. Go stops
  reading a DistributionPoint at the first non-URI name (verified with a DirName-first CDP), and
  the IDP comparison needs every GeneralName.
- The cache key is (SHA-256 of the issuer DER, URL). The spec says "by URL". Adding the issuer
  keeps a CRL verified for one issuer from being applied to another issuer that names the same URL.
- `ParseCRL` treats critical CRLNumber/AKI as understood. Every other critical CRL extension except
  IDP → `unsupported_method`. Delta CRL indicator → `unsupported_method`.
- The DNIe ARL is cached under the generic rule min(nextUpdate, 1 h), not "until its nextUpdate"
  (spec `dnie` row). The refetch is 1 KB per hour.
- `crlCache`, `crlLoad`, `hostAllowed` and `usableDistributionPoints` are used by Task 5's checker.
  Until then, `crlcache_test.go` and `crl_test.go` exercise them, which keeps staticcheck's U1000
  quiet. Add no `//lint:ignore`.

Step 1: write the failing tests:
- `fetcher_test.go`:
  - `TestAddressAllowed` table. Blocked: 127.0.0.1, ::1, 10.1.2.3, 172.16.0.1, 192.168.1.1,
    169.254.169.254, fe80::1, fc00::1, fd12::1 (Railway private network), 100.64.0.1, 0.0.0.0, ::,
    224.0.0.1, ff02::1, 255.255.255.255, ::ffff:127.0.0.1, ::ffff:10.0.0.1, 64:ff9b::a00:1,
    198.18.0.1, 240.0.0.1, 2001:db8::1. Allowed: 8.8.8.8, 2001:4860:4860::8888.
  - `TestFetchBlocksPrivateDestination`:
    - default dialer;
    - an `httptest` server on 127.0.0.1:P;
    - URL `http://localhost:P/x` with `AllowedHosts: ["localhost:P"]`;
    - want `errors.Is(err, ErrBlockedAddress)` and 0 requests seen by the server (AC4 "private-IP
      destination blocked").
  - `TestFetchHostNotAllowlisted`: host not listed, `ftp://`, `ldap://`, `file:///`, userinfo
    `http://u@host/` → `ErrHostNotAllowed`, and no dial.
  - `TestFetchRedirects` (via `testpki.Net`):
    - same host /a→/b→/c→/d followed (3 redirects);
    - a 4th is blocked (`ErrRedirectBlocked`);
    - a redirect to another allowlisted host is followed;
    - to a non-allowlisted host it is blocked (AC4 "redirect not followed");
    - an `http`→`https` scheme change is blocked.
  - `TestFetchSizeCap`: a Content-Length over the cap and a chunked body over the cap →
    `ErrTooLarge`.
  - `TestFetchTimeout`: a `testpki.Slow(2s)` handler with `Timeout: 200ms` →
    `context.DeadlineExceeded`.
  - `TestFetchConcurrency`: 40 parallel fetches; the handler records at most
    `MaxConcurrent` (16) concurrent.
  - `TestFetchRequestHeaders`: User-Agent; POST body and Content-Type; no `Cookie` header after the
    server set one; no `Accept-Encoding: gzip`.
  - `TestFetchHTTPStatus`: 503 → `ErrHTTPStatus` with `StatusCode` 503 recorded.
- `crl_test.go`:
  - `TestParseCDP`:
    - URIs plus DirName in one DP;
    - DirName-first (the case Go misses);
    - two DPs;
    - a DP with `reasons`;
    - `nameRelativeToCRLIssuer`;
    - cRLIssuer equal to the issuer → usable;
    - another cRLIssuer → skipped;
    - malformed → error.
  - `TestParseIDP`: each flag; fullName URIs plus DirName; relative name; bad BOOLEAN; trailing
    data.
  - `TestParseCRL`:
    - issuer DN differs → `invalid_evidence`;
    - signed by another CA (testpki `Signer`) → `invalid_evidence`;
    - corrupt signature → `invalid_evidence`;
    - critical unknown CRL extension, critical unknown entry extension, certificateIssuer entry,
      delta CRL indicator → `unsupported_method`;
    - non-critical unknown → ok;
    - entry reasons (`NoReason` → -1).
  - `TestEvaluateCRL` table (clock fixed):
    - good; listed → revoked; certificateHold (reason 6) listed → revoked;
    - nextUpdate past → stale; no nextUpdate → stale;
    - thisUpdate now+6m → stale; now+4m → ok;
    - IDP URI match → good; IDP DirName match → good; IDP mismatch → `invalid_evidence`;
    - IDP relative name → unsupported;
    - leaf with `OnlyCA` → unsupported; CA with `OnlyCA` → good; CA with `OnlyUser` → unsupported;
    - `Indirect`/`OnlySomeReasons`/`OnlyAttr` → unsupported;
    - non-critical IDP is honoured the same way.
  - `TestRealCRLs` at 2026-10-30T12:00:00Z:
    - `dnie-arl.crl` against `ac-dnie-004.pem`, issuer `ac-raiz-dnie-2.pem`, scope CA → `good`
      (the critical IDP with onlyContainsCACerts names the CDP URI);
    - `aoc-caroot-a.crl` against `aoc-subca-ciutadania-g3-a2.pem`, issuer `aoc-g3-root-a.pem` →
      `good`;
    - the SHA-256 of each testdata file equals SOURCES.md.
- `crlcache_test.go`. `TestCRLCache`:
  - singleflight: 20 concurrent loads → 1 fetch;
  - expiry at min(nextUpdate, 1h);
  - LRU eviction past the byte bound (cost = 2 × size);
  - an entry above the bound is not cached;
  - failures are not cached;
  - a waiter whose ctx is cancelled returns `unavailable` while the shared fetch completes and is
    cached for the next caller;
  - the key separates issuers.
- `crl_fuzz_test.go`: `FuzzParseIDP`, `FuzzParseCDP` (seeds: real IDP/CDP values and the table
  inputs). No panic.

Run: `go test -race -count=1 ./certauth/revocation/...` → build failure.

Step 2: implement.

`certauth/revocation/fetcher.go`:
```go
package revocation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Fetch limits (spec "Fetcher (SSRF controls)").
const (
	OCSPTimeout      = 5 * time.Second
	CRLTimeout       = 15 * time.Second
	MaxOCSPResponse  = 64 << 10
	MaxCRLResponse   = 32 << 20
	MaxRedirects     = 3
	MaxConcurrent    = 16
	maxHeaderBytes   = 16 << 10
	defaultUserAgent = "cert-check/dev"
)

// Fetch errors. All of them map to StatusUnavailable.
var (
	ErrHostNotAllowed  = errors.New("revocation: URL scheme or host not allowlisted")
	ErrBlockedAddress  = errors.New("revocation: destination address blocked")
	ErrRedirectBlocked = errors.New("revocation: redirect not allowed")
	ErrTooLarge        = errors.New("revocation: response exceeds size cap")
	ErrHTTPStatus      = errors.New("revocation: unexpected HTTP status")
)

// DialFunc dials a network connection.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// FetcherOptions configures a Fetcher.
type FetcherOptions struct {
	UserAgent     string // default "cert-check/dev"; production passes "cert-check/<version>"
	MaxConcurrent int    // default 16
	// DialContext replaces the address-checking dialer. Tests only (fake
	// network); production wiring never sets it.
	DialContext DialFunc
}

// Fetcher performs bounded HTTP fetches of revocation evidence.
type Fetcher struct {
	client *http.Client
	sem    chan struct{}
	ua     string
}

type allowKey struct{}

// NewFetcher returns a Fetcher. The default dialer rejects loopback, private,
// link-local, multicast, unspecified and other non-public addresses after DNS
// resolution; no proxy, no cookies, no transparent decompression.
func NewFetcher(o FetcherOptions) *Fetcher {
	dial := o.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: 5 * time.Second, Control: checkDialAddress}
		dial = d.DialContext
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      false,
	}
	n := o.MaxConcurrent
	if n <= 0 {
		n = MaxConcurrent
	}
	ua := o.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	return &Fetcher{
		client: &http.Client{Transport: tr, CheckRedirect: checkRedirect},
		sem:    make(chan struct{}, n),
		ua:     ua,
	}
}

// FetchRequest describes one fetch.
type FetchRequest struct {
	URL          string
	Body         []byte // POST when non-nil
	ContentType  string
	Accept       string
	MaxBytes     int64
	Timeout      time.Duration
	AllowedHosts []string // the union of the profile allowlists
}

// FetchResult is the outcome of a successful fetch (HTTP 200, within caps).
type FetchResult struct {
	Body       []byte
	StatusCode int
	FinalURL   string
	Duration   time.Duration
}

// Fetch performs the request. On error the returned result still carries the
// HTTP status (if any) and the duration for diagnostics.
func (f *Fetcher) Fetch(ctx context.Context, r FetchRequest) (FetchResult, error) {
	start := time.Now()
	res := FetchResult{}
	u, err := url.Parse(r.URL)
	if err != nil || !hostAllowed(u, r.AllowedHosts) {
		return res, ErrHostNotAllowed
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return res, ctx.Err()
	}
	ctx = context.WithValue(ctx, allowKey{}, r.AllowedHosts)
	method, body := http.MethodGet, io.Reader(nil)
	if r.Body != nil {
		method, body = http.MethodPost, bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", f.ua)
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	resp, err := f.client.Do(req)
	res.Duration = time.Since(start)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res.StatusCode, res.FinalURL = resp.StatusCode, resp.Request.URL.String()
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("%w %d", ErrHTTPStatus, resp.StatusCode)
	}
	if resp.ContentLength > r.MaxBytes {
		return res, ErrTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, r.MaxBytes+1))
	res.Duration = time.Since(start)
	if err != nil {
		return res, err
	}
	if int64(len(b)) > r.MaxBytes {
		return res, ErrTooLarge
	}
	res.Body = b
	return res, nil
}

// hostAllowed: http/https only, no userinfo, host (and non-default port)
// exactly in the allowlist.
func hostAllowed(u *url.URL, allowed []string) bool {
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	key := host
	if port != "" {
		key = net.JoinHostPort(host, port)
	}
	return slices.Contains(allowed, key)
}

// checkRedirect: at most MaxRedirects, same scheme, and the target is the same
// host or another allowlisted host.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > MaxRedirects {
		return fmt.Errorf("%w: too many redirects", ErrRedirectBlocked)
	}
	prev := via[len(via)-1].URL
	if req.URL.Scheme != prev.Scheme {
		return fmt.Errorf("%w: scheme change", ErrRedirectBlocked)
	}
	allowed, _ := req.Context().Value(allowKey{}).([]string)
	if !hostAllowed(req.URL, allowed) {
		return fmt.Errorf("%w: host not allowlisted", ErrRedirectBlocked)
	}
	return nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// AddressAllowed reports whether a resolved destination IP may be dialed.
func AddressAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsUnspecified() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// checkDialAddress is the net.Dialer Control hook: it runs after DNS
// resolution, on the literal IP being dialed.
func checkDialAddress(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedAddress
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !AddressAllowed(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, network)
	}
	return nil
}
```

`certauth/revocation/crl.go`:
```go
package revocation

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidExtCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtIssuingDistPoint      = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidExtCRLNumber             = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidExtAuthorityKeyID        = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtDeltaCRLIndicator     = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidEntryReasonCode          = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidEntryInvalidityDate      = asn1.ObjectIdentifier{2, 5, 29, 24}
	oidEntryCertificateIssuer   = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// GeneralName is one GeneralName kept as its full DER TLV, compared byte for byte.
type GeneralName []byte

// URI returns the uniformResourceIdentifier ([6]) value, if it is one.
func (g GeneralName) URI() (string, bool) {
	s := cryptobyte.String(g)
	var v cryptobyte.String
	if !s.ReadASN1(&v, cbasn1.Tag(6).ContextSpecific()) || !s.Empty() {
		return "", false
	}
	return string(v), true
}

// DistributionPoint is one entry of a certificate's CRLDistributionPoints.
type DistributionPoint struct {
	FullName     []GeneralName
	RelativeName bool          // nameRelativeToCRLIssuer present (unsupported)
	HasReasons   bool          // reasons present (partial DP, unsupported)
	CRLIssuer    []GeneralName // cRLIssuer, nil when absent
}

// ParseCRLDistributionPoints parses the certificate's CDP extension itself:
// x509.Certificate.CRLDistributionPoints stops at the first non-URI name and
// loses the names needed for the IDP comparison.
func ParseCRLDistributionPoints(cert *x509.Certificate) ([]DistributionPoint, error) {
	var raw []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidExtCRLDistributionPoints) {
			raw = e.Value
		}
	}
	if raw == nil {
		return nil, nil
	}
	return ParseCDP(raw)
}

// ParseCDP parses a CRLDistributionPoints extension value.
func ParseCDP(raw []byte) ([]DistributionPoint, error) {
	in := cryptobyte.String(raw)
	var dps cryptobyte.String
	if !in.ReadASN1(&dps, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errors.New("cdp: malformed")
	}
	var out []DistributionPoint
	for !dps.Empty() {
		var dpDER cryptobyte.String
		if !dps.ReadASN1(&dpDER, cbasn1.SEQUENCE) {
			return nil, errors.New("cdp: malformed DistributionPoint")
		}
		var dp DistributionPoint
		var name cryptobyte.String
		var has bool
		if !dpDER.ReadOptionalASN1(&name, &has, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("cdp: malformed distributionPoint")
		}
		if has {
			full, rel, err := parseDistributionPointName(name)
			if err != nil {
				return nil, fmt.Errorf("cdp: %w", err)
			}
			dp.FullName, dp.RelativeName = full, rel
		}
		var skip cryptobyte.String
		if !dpDER.ReadOptionalASN1(&skip, &dp.HasReasons, cbasn1.Tag(1).ContextSpecific()) {
			return nil, errors.New("cdp: malformed reasons")
		}
		var issuer cryptobyte.String
		var hasIssuer bool
		if !dpDER.ReadOptionalASN1(&issuer, &hasIssuer, cbasn1.Tag(2).Constructed().ContextSpecific()) {
			return nil, errors.New("cdp: malformed cRLIssuer")
		}
		if hasIssuer {
			names, err := readGeneralNames(issuer)
			if err != nil {
				return nil, fmt.Errorf("cdp: cRLIssuer: %w", err)
			}
			dp.CRLIssuer = names
		}
		if !dpDER.Empty() {
			return nil, errors.New("cdp: trailing data")
		}
		out = append(out, dp)
	}
	return out, nil
}

// parseDistributionPointName parses the content of a [0] DistributionPointName.
func parseDistributionPointName(s cryptobyte.String) (full []GeneralName, relative bool, err error) {
	var inner cryptobyte.String
	switch {
	case s.PeekASN1Tag(cbasn1.Tag(0).Constructed().ContextSpecific()):
		if !s.ReadASN1(&inner, cbasn1.Tag(0).Constructed().ContextSpecific()) || !s.Empty() {
			return nil, false, errors.New("malformed fullName")
		}
		full, err = readGeneralNames(inner)
		return full, false, err
	case s.PeekASN1Tag(cbasn1.Tag(1).Constructed().ContextSpecific()):
		return nil, true, nil
	}
	return nil, false, errors.New("unknown DistributionPointName")
}

func readGeneralNames(s cryptobyte.String) ([]GeneralName, error) {
	var out []GeneralName
	for !s.Empty() {
		var gn cryptobyte.String
		var tag cbasn1.Tag
		if !s.ReadAnyASN1Element(&gn, &tag) || tag&0xc0 != 0x80 {
			return nil, errors.New("malformed GeneralName")
		}
		out = append(out, GeneralName(gn))
	}
	if len(out) == 0 {
		return nil, errors.New("empty GeneralNames")
	}
	return out, nil
}

// IDP is a parsed IssuingDistributionPoint.
type IDP struct {
	FullName          []GeneralName
	RelativeName      bool
	OnlyUserCerts     bool
	OnlyCACerts       bool
	OnlySomeReasons   bool
	IndirectCRL       bool
	OnlyAttributeCert bool
}

// ParseIDP parses an IssuingDistributionPoint extension value.
func ParseIDP(der []byte) (IDP, error) {
	in := cryptobyte.String(der)
	var s cryptobyte.String
	if !in.ReadASN1(&s, cbasn1.SEQUENCE) || !in.Empty() {
		return IDP{}, errors.New("idp: malformed")
	}
	var idp IDP
	var name cryptobyte.String
	var has bool
	if !s.ReadOptionalASN1(&name, &has, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return IDP{}, errors.New("idp: malformed distributionPoint")
	}
	if has {
		full, rel, err := parseDistributionPointName(name)
		if err != nil {
			return IDP{}, fmt.Errorf("idp: %w", err)
		}
		idp.FullName, idp.RelativeName = full, rel
	}
	readBool := func(tag uint8, out *bool) error {
		var v cryptobyte.String
		var present bool
		if !s.ReadOptionalASN1(&v, &present, cbasn1.Tag(tag).ContextSpecific()) {
			return fmt.Errorf("idp: malformed [%d]", tag)
		}
		if present {
			if len(v) != 1 || (v[0] != 0x00 && v[0] != 0xff) {
				return fmt.Errorf("idp: bad BOOLEAN [%d]", tag)
			}
			*out = v[0] == 0xff
		}
		return nil
	}
	if err := readBool(1, &idp.OnlyUserCerts); err != nil {
		return IDP{}, err
	}
	if err := readBool(2, &idp.OnlyCACerts); err != nil {
		return IDP{}, err
	}
	var reasons cryptobyte.String
	if !s.ReadOptionalASN1(&reasons, &idp.OnlySomeReasons, cbasn1.Tag(3).ContextSpecific()) {
		return IDP{}, errors.New("idp: malformed onlySomeReasons")
	}
	if err := readBool(4, &idp.IndirectCRL); err != nil {
		return IDP{}, err
	}
	if err := readBool(5, &idp.OnlyAttributeCert); err != nil {
		return IDP{}, err
	}
	if !s.Empty() {
		return IDP{}, errors.New("idp: trailing data")
	}
	return idp, nil
}

// ParsedCRL is a parsed, signature-checked CRL kept in the cache. Raw bytes are discarded.
type ParsedCRL struct {
	List   *x509.RevocationList
	IDP    *IDP                 // nil when the CRL has no IDP
	Listed map[string]CRLRecord // serial (lowercase hex of big.Int bytes) -> record
	Size   int64                // raw size, for the cache bound
	URL    string
}

// CRLRecord is one listed serial.
type CRLRecord struct {
	RevokedAt time.Time
	Reason    int // -1 when the entry has no reasonCode
}

// SerialKey is the map key for a serial number.
func SerialKey(n *big.Int) string { return fmt.Sprintf("%x", n) }

// ParseCRL parses der, checks issuer name and signature against issuer, and
// enforces criticality: only IDP among critical CRL extensions; only
// reasonCode and invalidityDate among entry extensions; certificateIssuer and
// delta CRLs are unsupported. It returns a Status for the failure cases.
func ParseCRL(der []byte, issuer *x509.Certificate) (*ParsedCRL, Status, error) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, StatusInvalidEvidence, fmt.Errorf("crl: parse: %w", err)
	}
	if !bytes.Equal(rl.RawIssuer, issuer.RawSubject) {
		return nil, StatusInvalidEvidence, errors.New("crl: issuer name differs from the certificate issuer")
	}
	if err := rl.CheckSignatureFrom(issuer); err != nil {
		return nil, StatusInvalidEvidence, fmt.Errorf("crl: signature: %w", err)
	}
	p := &ParsedCRL{List: rl, Listed: make(map[string]CRLRecord, len(rl.RevokedCertificateEntries)), Size: int64(len(der))}
	for _, e := range rl.Extensions {
		switch {
		case e.Id.Equal(oidExtIssuingDistPoint):
			idp, err := ParseIDP(e.Value)
			if err != nil {
				return nil, StatusInvalidEvidence, err
			}
			p.IDP = &idp
		case e.Id.Equal(oidExtDeltaCRLIndicator):
			return nil, StatusUnsupportedMethod, errors.New("crl: delta CRL")
		case e.Critical && !e.Id.Equal(oidExtCRLNumber) && !e.Id.Equal(oidExtAuthorityKeyID):
			return nil, StatusUnsupportedMethod, fmt.Errorf("crl: unhandled critical extension %s", e.Id)
		}
	}
	for _, entry := range rl.RevokedCertificateEntries {
		rec := CRLRecord{RevokedAt: entry.RevocationTime, Reason: -1}
		for _, e := range entry.Extensions {
			switch {
			case e.Id.Equal(oidEntryReasonCode):
				rec.Reason = entry.ReasonCode
			case e.Id.Equal(oidEntryInvalidityDate):
			case e.Id.Equal(oidEntryCertificateIssuer):
				return nil, StatusUnsupportedMethod, errors.New("crl: certificateIssuer entry extension (indirect CRL)")
			case e.Critical:
				return nil, StatusUnsupportedMethod, fmt.Errorf("crl: unhandled critical entry extension %s", e.Id)
			}
		}
		p.Listed[SerialKey(entry.SerialNumber)] = rec
	}
	return p, StatusGood, nil
}

// Scope is what the checked certificate is.
type Scope int

// Scopes.
const (
	ScopeLeaf Scope = iota + 1
	ScopeCA         // a pinned intermediate (DNIe AC DNIE 00N)
)

// EvaluateCRL applies freshness, scope and listing to a parsed CRL for cert,
// whose CDP DistributionPoint (the one the URL came from) is dp.
func EvaluateCRL(p *ParsedCRL, cert *x509.Certificate, dp DistributionPoint, scope Scope, now time.Time) (Status, CRLRecord, string) {
	rl := p.List
	if rl.ThisUpdate.After(now.Add(ClockSkew)) {
		return StatusStale, CRLRecord{}, "crl thisUpdate in the future"
	}
	if rl.NextUpdate.IsZero() {
		return StatusStale, CRLRecord{}, "crl without nextUpdate"
	}
	if rl.NextUpdate.Before(now) {
		return StatusStale, CRLRecord{}, "crl nextUpdate in the past"
	}
	if idp := p.IDP; idp != nil {
		if idp.RelativeName {
			return StatusUnsupportedMethod, CRLRecord{}, "idp nameRelativeToCRLIssuer"
		}
		if idp.OnlyAttributeCert || idp.IndirectCRL || idp.OnlySomeReasons {
			return StatusUnsupportedMethod, CRLRecord{}, "idp scope flag unsupported"
		}
		switch scope {
		case ScopeLeaf:
			if idp.OnlyCACerts {
				return StatusUnsupportedMethod, CRLRecord{}, "idp onlyContainsCACerts for a leaf"
			}
		case ScopeCA:
			if idp.OnlyUserCerts {
				return StatusUnsupportedMethod, CRLRecord{}, "idp onlyContainsUserCerts for a CA"
			}
		}
		if len(idp.FullName) > 0 && !namesIntersect(idp.FullName, dp.FullName) {
			return StatusInvalidEvidence, CRLRecord{}, "idp distributionPoint does not match the certificate CDP"
		}
	}
	if rec, ok := p.Listed[SerialKey(cert.SerialNumber)]; ok {
		return StatusRevoked, rec, "serial listed"
	}
	return StatusGood, CRLRecord{}, "serial not listed"
}

func namesIntersect(a, b []GeneralName) bool {
	for _, x := range a {
		for _, y := range b {
			if bytes.Equal(x, y) {
				return true
			}
		}
	}
	return false
}

// usableDistributionPoints returns the DPs this package can use for cert
// issued by issuer: fullName form, no reasons, and cRLIssuer absent or equal
// to the issuer (ACCV CA certificates name their own issuer).
func usableDistributionPoints(dps []DistributionPoint, issuer *x509.Certificate) []DistributionPoint {
	var out []DistributionPoint
	for _, dp := range dps {
		if dp.RelativeName || dp.HasReasons || len(dp.FullName) == 0 {
			continue
		}
		if dp.CRLIssuer != nil && !crlIssuerIsIssuer(dp.CRLIssuer, issuer) {
			continue
		}
		out = append(out, dp)
	}
	return out
}

func crlIssuerIsIssuer(names []GeneralName, issuer *x509.Certificate) bool {
	if len(names) != 1 {
		return false
	}
	s := cryptobyte.String(names[0])
	var inner cryptobyte.String
	if !s.ReadASN1(&inner, cbasn1.Tag(4).Constructed().ContextSpecific()) || !s.Empty() {
		return false
	}
	return bytes.Equal(inner, issuer.RawSubject)
}
```

`certauth/revocation/crlcache.go`:
```go
package revocation

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Cache bounds.
const (
	DefaultCRLCacheBytes = 128 << 20
	crlCacheMaxAge       = time.Hour
)

func issuerKey(issuer *x509.Certificate) string {
	s := sha256.Sum256(issuer.Raw)
	return hex.EncodeToString(s[:])
}

// crlCache caches parsed CRLs keyed by (issuer SHA-256, URL) until
// min(nextUpdate, fetched+1h). Cost is estimated as 2 × raw size; the least
// recently used entries are evicted past the bound. Fetch+parse run once per
// key under singleflight, detached from any single caller's cancellation.
type crlCache struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	cost  int64
	limit int64
	sf    singleflight.Group
}

type crlItem struct {
	key     string
	crl     *ParsedCRL
	expires time.Time
	cost    int64
}

func newCRLCache(limit int64) *crlCache {
	return &crlCache{items: make(map[string]*list.Element), lru: list.New(), limit: limit}
}

func (c *crlCache) get(key string, now time.Time) (*ParsedCRL, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	it := el.Value.(*crlItem)
	if !now.Before(it.expires) {
		c.removeLocked(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return it.crl, true
}

func (c *crlCache) put(key string, p *ParsedCRL, now time.Time) {
	expires := now.Add(crlCacheMaxAge)
	if p.List.NextUpdate.Before(expires) {
		expires = p.List.NextUpdate
	}
	cost := 2 * p.Size
	if cost > c.limit || !now.Before(expires) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.removeLocked(el)
	}
	c.items[key] = c.lru.PushFront(&crlItem{key: key, crl: p, expires: expires, cost: cost})
	c.cost += cost
	for c.cost > c.limit {
		c.removeLocked(c.lru.Back())
	}
}

func (c *crlCache) removeLocked(el *list.Element) {
	it := el.Value.(*crlItem)
	c.lru.Remove(el)
	delete(c.items, it.key)
	c.cost -= it.cost
}

type crlLoad struct {
	crl     *ParsedCRL
	status  Status
	attempt Attempt
	err     error
}

// load returns the cached CRL or fetches it once for all concurrent callers.
func (c *crlCache) load(ctx context.Context, key string, now time.Time, timeout time.Duration, fetch func(context.Context) crlLoad) crlLoad {
	if p, ok := c.get(key, now); ok {
		return crlLoad{crl: p, status: StatusGood, attempt: Attempt{Method: MethodCRL, URL: p.URL, FromCache: true}}
	}
	ch := c.sf.DoChan(key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		res := fetch(fctx)
		if res.err == nil && res.crl != nil {
			c.put(key, res.crl, now)
		}
		return res, nil
	})
	select {
	case r := <-ch:
		return r.Val.(crlLoad)
	case <-ctx.Done():
		return crlLoad{status: StatusUnavailable, err: ctx.Err(), attempt: Attempt{Method: MethodCRL, Outcome: StatusUnavailable, Detail: "cancelled while waiting for CRL fetch"}}
	}
}
```

Testdata. Copy the files byte for byte and record source and SHA-256 in `testdata/crl/SOURCES.md`:

| file | source | sha256 |
|---|---|---|
| dnie-arl.crl | `/home/p4u/.cache/cert-check/audit-scratch/crl/ARL.crl` (live fetch of http://pki.policia.es/dnie/crls/ARL.crl, 2026-10-30) | 0c458a7ff513b28ec8eb62fabbaad9218cbb19c8924581b102c208184e11a235 |
| aoc-caroot-a.crl | `/home/p4u/.cache/cert-check/research/appb-crl/caroot-a.crl` (http://epscd.aoc.cat/crl/caroot-a.crl, 2026-10-30) | 6063677f9de836521431b0d141802679119c75be8a8165206db5592eececb053 |
| certs/ac-raiz-dnie-2.pem | bundle `service-identities/c5c380eb9240fb36….pem` | 6b05008b4ee898f78457c345da5a0d7b368541d715694c56527a34179d63f820 |
| certs/ac-dnie-004.pem | `…/ca-downloads/dnie/AC004.crt` (http://pki.policia.es/dnie/certs/AC004.crt) | f368f0dc19cb72adfca9f46bdd3db39552fcccb22de275f52de18cba8670ff33 |
| certs/aoc-g3-root-a.pem | bundle `additional-ca-certificates/15651384ca70c580….pem` | fafc411eb1c25bd829f1e0de29940366b96304e3f6f2c4eaac18830bdbb3ee06 |
| certs/aoc-subca-ciutadania-g3-a2.pem | bundle `service-identities/e6dc96bb0dbcb242….pem` | 57a84099da3c38c557f5203a3de868322e0bc0f8747c8c161d7ccfcee0703ba5 |

Both CRLs list only CA-certificate serials, with no person data. The FNMT partition CRL (`CRL2.crl`)
lists person serials and is not committed. Its IDP shape (DirName plus URI, onlyUser) is covered
synthetically.

Run:
- `go test -race -count=1 ./certauth/revocation/...` → `ok  github.com/vocdoni/cert-check/certauth/revocation`;
- fuzz smoke 30 s each for `FuzzParseIDP` and `FuzzParseCDP` → `PASS`;
- the Global Constraints checks.

Step 3: commit
`git commit -m "feat(revocation): add ssrf-safe fetcher, crl scope checks and parsed crl cache" -- certauth/revocation/fetcher.go certauth/revocation/crl.go certauth/revocation/crlcache.go certauth/revocation/fetcher_test.go certauth/revocation/crl_test.go certauth/revocation/crlcache_test.go certauth/revocation/crl_fuzz_test.go certauth/revocation/testdata/crl`

Interfaces this task provides to later tasks:
- fetcher: `Fetcher`, `NewFetcher`, `FetcherOptions`, `DialFunc`, `FetchRequest`, `FetchResult`,
  `AddressAllowed`, the limit constants, and the errors `ErrHostNotAllowed`, `ErrBlockedAddress`,
  `ErrRedirectBlocked`, `ErrTooLarge`, `ErrHTTPStatus`;
- CRL: `GeneralName`, `DistributionPoint`, `ParseCRLDistributionPoints`, `ParseCDP`, `IDP`,
  `ParseIDP`, `ParsedCRL`, `CRLRecord`, `ParseCRL`, `Scope` (`ScopeLeaf`/`ScopeCA`), `EvaluateCRL`,
  `SerialKey`;
- unexported, used by Task 5: `crlCache` (`newCRLCache`, `load`), `crlLoad`, `issuerKey`,
  `usableDistributionPoints`, `hostAllowed`.


### Task 4: `certauth/revocation`: OCSP codec (cryptobyte) and acceptance checks
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `certauth/revocation/{ocspcodec.go,ocspverify.go}`;
- `certauth/revocation/{ocspcodec_test.go,ocspverify_test.go,ocsp_fuzz_test.go}`;
- `certauth/revocation/testdata/ocsp/{aoc-casub-a2.ocsp,camerfirma-qc2024.ocsp,izenpe-profesional-sw-act.ocsp,izenpe-profesional-sw-rev.ocsp,SOURCES.md}` and
  `certauth/revocation/testdata/ocsp/certs/{aoc-g3-root-a.pem,aoc-subca-ciutadania-g3-a2.pem,camerfirma-root-2024.pem,camerfirma-qc-2024.pem,izenpe-ca4.pem,izenpe-profesional-sw-act.pem,izenpe-profesional-sw-rev.pem}`.

Goal: AC4 for OCSP: good, revoked, unknown; wrong CertID; a responder not issued by the issuer; a
responder without the OCSPSigning EKU; stale thisUpdate without nextUpdate, expired nextUpdate,
future thisUpdate; bad signature; nonce mismatch. Spec "OCSP": our own RFC 6960 codec, with no
`x/crypto/ocsp`.

Behaviour notes:
- Signature algorithms accepted on responses: RSA PKCS#1 v1.5 with SHA-256/384/512 (parameters
  NULL or absent), ECDSA with SHA-256/384/512 (parameters absent or NULL), and Ed25519. SHA-1 and
  RSA-PSS give `invalid_evidence`.
  - NULL parameters on ECDSA are accepted because Camerfirma's live responder sends them
    (`camerfirma-qc2024.ocsp`).
  - Every observed responder signs with sha256WithRSA or ecdsa-with-SHA384.
- Delegated responders must carry `id-pkix-ocsp-nocheck`. The spec says nocheck "is honoured only
  for that responder". Because responder status is never checked, a responder without nocheck is
  rejected (fail closed). Every documented responder (FNMT, DNIe, ACCV, AOC, Izenpe, Camerfirma,
  DIGITEL, Bewor) carries it. Task 12's live probe confirms the rest.
- Responder keys must be RSA ≥ 2048, ECDSA P-256/384/521 or Ed25519.
- `VerifyOCSP` order: response status → critical response extensions → signature algorithm →
  signer authorization and ResponderID binding plus signature → exactly one matching SingleResponse
  → critical single extensions → nonce → freshness → certStatus. A never-issued serial answered as
  revoked/certificateHold/1970 maps to `revoked`, like any revocation.

Step 1: write the failing tests (testpki builds every response):
- `ocspcodec_test.go`:
  - `TestNewCertID`: SHA-1 and SHA-256 hashes equal `testpki.CertIDHashes`; MD5 → error.
  - `TestMarshalRequest`: `testpki.ParseOCSPRequest` decodes serial and hashes. With a nonce, the
    returned extnValue is `04 20 ‖ nonce` and is what the request carries. Without a nonce there
    are no request extensions.
  - `TestParseResponse` table:
    - good;
    - revoked with reason 6 and without a reason (`Reason == -1`);
    - unknown;
    - byName (`ResponderName == signer RawSubject`) and byKey (20 bytes);
    - nextUpdate present and absent;
    - single and response extensions (critical flag kept);
    - 0, 1 and 2 embedded certificates;
    - statuses 1, 2, 3, 5, 6 → only `Status` set;
    - response type not basic → error;
    - RSA alg with NULL and with absent parameters; ECDSA absent and NULL; sha1WithRSA →
      `UnknownSignatureAlgorithm`;
    - explicit version 0 ok, version 1 → error;
    - truncated, trailing bytes after the OCSPResponse, after the BasicOCSPResponse, inside
      ResponseData → `errMalformed`;
    - duplicate response extension → error;
    - 33 SingleResponses or 9 certificates → error;
    - zero SingleResponses → error.
  - `TestParseRealResponses` (fields only):
    - `aoc-casub-a2.ocsp`: successful, byName "Servei OCSP de CA CONSORCI AOC (G3) ROOT-A",
      1 cert, ECDSA-SHA384, nonce extension present;
    - `camerfirma-qc2024.ocsp`: ECDSA-SHA384 with NULL parameters → accepted algorithm;
    - `izenpe-profesional-sw-act.ocsp`: 2 embedded certs, good;
    - `-rev`: revoked;
    - the file SHA-256 equals SOURCES.md.
- `ocspverify_test.go`. `TestVerifyOCSP` table. Issuer `ca`, delegated responder `resp` unless
  stated, clock fixed, `MaxAge` 15m:
  - good / revoked / unknown;
  - revoked with certificateHold and RevokedAt 1970-01-01 → `revoked`;
  - `SerialOverride` → `invalid_evidence` "no SingleResponse matches";
  - `NameHashOverride` → `invalid_evidence`;
  - `CertIDHash: crypto.SHA256` while SHA-1 was requested → `invalid_evidence`;
  - `DuplicateSingle` → `invalid_evidence`;
  - responder issued by another CA → `invalid_evidence` "not issued by";
  - responder with EKU clientAuth only → "lacks id-kp-OCSPSigning";
  - responder expired / not yet valid → "not valid now";
  - responder without nocheck (build with `ca.Leaf` plus OCSPSigning) → "lacks id-pkix-ocsp-nocheck";
  - responder RSA-1024 → "key too weak";
  - responder with an unknown critical extension → "unhandled critical";
  - `ResponderIDOf` another cert, byName and byKey → `invalid_evidence`;
  - signed by the issuer itself, byName and byKey → good;
  - `CorruptSignature` → `invalid_evidence`;
  - no nextUpdate, thisUpdate −16m → `stale`; −14m → good;
  - nextUpdate in the past → `stale`; nextUpdate < thisUpdate → `stale`;
  - thisUpdate +6m → `stale`; +4m → good;
  - Sectigo-like: thisUpdate −3d, nextUpdate +4d → good (no age limit when nextUpdate is present);
  - nonce sent and echoed → good with `NonceEchoed`; sent and omitted → "not echoed"; sent and
    wrong → "nonce mismatch"; not sent but present → good;
  - critical unknown response extension → `invalid_evidence`; critical nonce → good; critical
    single extension → `invalid_evidence`;
  - `ResponseStatus: 3` → `unavailable`.
  - `TestVerifyRealResponses` at `ProducedAt + 1m`, no nonce:
    - `aoc-casub-a2.ocsp` (target A.2, issuer G3 ROOT-A) → `good`, responder subject contains
      "CA CONSORCI AOC (G3) ROOT-A";
    - `camerfirma-qc2024.ocsp` (target QC 2024, issuer root 2024) → `good`;
    - izenpe act → `good`, rev → `revoked`.
- `ocsp_fuzz_test.go`: `FuzzParseResponse`. Seeds: the four real files plus every table response.
  No panic. Success implies `TBSResponseData` is a prefix-free element of the input.

Run: `go test -race -count=1 ./certauth/revocation/...` → build failure.

Step 2: implement.

`certauth/revocation/ocspcodec.go`:
```go
package revocation

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // CertID and ResponderID byKey hashing, not signatures
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidOCSPBasic   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidOCSPNonce   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	oidHashSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidHashSHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// signatureAlgorithms maps accepted OCSP signature OIDs to x509 algorithms.
// SHA-1 and RSA-PSS are not accepted (no observed responder uses them).
// Parameters must be absent or NULL where nullOK (Camerfirma's live responder
// encodes ecdsa-with-SHA384 with NULL parameters).
var signatureAlgorithms = []struct {
	oid    asn1.ObjectIdentifier
	alg    x509.SignatureAlgorithm
	nullOK bool
}{
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, x509.SHA256WithRSA, true},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, x509.SHA384WithRSA, true},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, x509.SHA512WithRSA, true},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, x509.ECDSAWithSHA256, true},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, x509.ECDSAWithSHA384, true},
	{asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, x509.ECDSAWithSHA512, true},
	{asn1.ObjectIdentifier{1, 3, 101, 112}, x509.PureEd25519, false},
}

// Codec limits.
const (
	maxSingleResponses = 32
	maxEmbeddedCerts   = 8
	NonceLength        = 32
)

// CertID identifies the certificate an OCSP request or SingleResponse refers to.
type CertID struct {
	HashAlgorithm  asn1.ObjectIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

// NewCertID builds the CertID for cert from the verified issuer. h is
// crypto.SHA1 (what every observed responder uses) or crypto.SHA256.
func NewCertID(h crypto.Hash, cert, issuer *x509.Certificate) (CertID, error) {
	keyBits, err := spkiBits(issuer.RawSubjectPublicKeyInfo)
	if err != nil {
		return CertID{}, err
	}
	id := CertID{SerialNumber: new(big.Int).Set(cert.SerialNumber)}
	switch h {
	case crypto.SHA1:
		n, k := sha1.Sum(issuer.RawSubject), sha1.Sum(keyBits) //nolint:gosec // CertID
		id.HashAlgorithm, id.IssuerNameHash, id.IssuerKeyHash = oidHashSHA1, n[:], k[:]
	case crypto.SHA256:
		n, k := sha256.Sum256(issuer.RawSubject), sha256.Sum256(keyBits)
		id.HashAlgorithm, id.IssuerNameHash, id.IssuerKeyHash = oidHashSHA256, n[:], k[:]
	default:
		return CertID{}, fmt.Errorf("ocsp: unsupported CertID hash %v", h)
	}
	return id, nil
}

// Equal compares two CertIDs field by field.
func (c CertID) Equal(o CertID) bool {
	return c.HashAlgorithm.Equal(o.HashAlgorithm) &&
		string(c.IssuerNameHash) == string(o.IssuerNameHash) &&
		string(c.IssuerKeyHash) == string(o.IssuerKeyHash) &&
		c.SerialNumber != nil && o.SerialNumber != nil && c.SerialNumber.Cmp(o.SerialNumber) == 0
}

// spkiBits returns the subjectPublicKey BIT STRING contents of a DER SPKI.
func spkiBits(spki []byte) ([]byte, error) {
	s := cryptobyte.String(spki)
	var inner, alg cryptobyte.String
	var bits asn1.BitString
	if !s.ReadASN1(&inner, cbasn1.SEQUENCE) || !s.Empty() ||
		!inner.ReadASN1(&alg, cbasn1.SEQUENCE) || !inner.ReadASN1BitString(&bits) || !inner.Empty() ||
		bits.BitLength%8 != 0 {
		return nil, errors.New("ocsp: malformed SubjectPublicKeyInfo")
	}
	return bits.Bytes, nil
}

// MarshalRequest encodes an unsigned OCSPRequest for one CertID. When nonce is
// non-nil it adds the nonce extension whose extnValue is OCTET STRING(nonce)
// (RFC 8954) and returns that extnValue for the echo comparison.
func MarshalRequest(id CertID, nonce []byte) (der, nonceExtValue []byte, err error) {
	var b cryptobyte.Builder
	if nonce != nil {
		var nb cryptobyte.Builder
		nb.AddASN1OctetString(nonce)
		nonceExtValue, err = nb.Bytes()
		if err != nil {
			return nil, nil, err
		}
	}
	b.AddASN1(cbasn1.SEQUENCE, func(req *cryptobyte.Builder) { // OCSPRequest
		req.AddASN1(cbasn1.SEQUENCE, func(tbs *cryptobyte.Builder) { // TBSRequest
			tbs.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) { // requestList
				list.AddASN1(cbasn1.SEQUENCE, func(r *cryptobyte.Builder) { // Request
					addCertID(r, id)
				})
			})
			if nonceExtValue != nil {
				tbs.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(e *cryptobyte.Builder) {
					e.AddASN1(cbasn1.SEQUENCE, func(exts *cryptobyte.Builder) {
						exts.AddASN1(cbasn1.SEQUENCE, func(ext *cryptobyte.Builder) {
							ext.AddASN1ObjectIdentifier(oidOCSPNonce)
							ext.AddASN1OctetString(nonceExtValue)
						})
					})
				})
			}
		})
	})
	der, err = b.Bytes()
	return der, nonceExtValue, err
}

func addCertID(b *cryptobyte.Builder, id CertID) {
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1(cbasn1.SEQUENCE, func(alg *cryptobyte.Builder) {
			alg.AddASN1ObjectIdentifier(id.HashAlgorithm)
			alg.AddASN1NULL()
		})
		c.AddASN1OctetString(id.IssuerNameHash)
		c.AddASN1OctetString(id.IssuerKeyHash)
		c.AddASN1BigInt(id.SerialNumber)
	})
}

// ResponseStatus is OCSPResponseStatus.
type ResponseStatus int

// Response statuses (RFC 6960 §4.2.1).
const (
	ResponseSuccessful       ResponseStatus = 0
	ResponseMalformedRequest ResponseStatus = 1
	ResponseInternalError    ResponseStatus = 2
	ResponseTryLater         ResponseStatus = 3
	ResponseSigRequired      ResponseStatus = 5
	ResponseUnauthorized     ResponseStatus = 6
)

// CertStatus is the certStatus CHOICE of a SingleResponse.
type CertStatus int

// Cert statuses.
const (
	CertGood CertStatus = iota + 1
	CertRevoked
	CertUnknown
)

// Extension is a parsed X.509 extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// SingleResponse is one entry of ResponseData.responses.
type SingleResponse struct {
	CertID     CertID
	Status     CertStatus
	RevokedAt  time.Time
	Reason     int // -1 when absent
	ThisUpdate time.Time
	NextUpdate time.Time // zero when absent
	Extensions []Extension
}

// Response is a parsed OCSPResponse. For a non-successful ResponseStatus only
// Status is set.
type Response struct {
	Status             ResponseStatus
	TBSResponseData    []byte // signed bytes (full DER of ResponseData)
	ResponderName      []byte // byName: full DER of the Name
	ResponderKeyHash   []byte // byKey: SHA-1 of the responder's subjectPublicKey
	ProducedAt         time.Time
	Responses          []SingleResponse
	Extensions         []Extension
	SignatureAlgorithm x509.SignatureAlgorithm // UnknownSignatureAlgorithm when not accepted
	Signature          []byte
	Certificates       []*x509.Certificate
}

var errMalformed = errors.New("ocsp: malformed response")

// ParseResponse strictly parses a DER OCSPResponse.
func ParseResponse(der []byte) (*Response, error) {
	in := cryptobyte.String(der)
	var top cryptobyte.String
	if !in.ReadASN1(&top, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errMalformed
	}
	var status int
	if !top.ReadASN1Enum(&status) {
		return nil, errMalformed
	}
	resp := &Response{Status: ResponseStatus(status)}
	if resp.Status != ResponseSuccessful {
		return resp, nil
	}
	var rbExplicit, rb, rbType cryptobyte.String
	if !top.ReadASN1(&rbExplicit, cbasn1.Tag(0).Constructed().ContextSpecific()) || !top.Empty() ||
		!rbExplicit.ReadASN1(&rb, cbasn1.SEQUENCE) || !rbExplicit.Empty() {
		return nil, errMalformed
	}
	var respType asn1.ObjectIdentifier
	if !rb.ReadASN1ObjectIdentifier(&respType) || !rb.ReadASN1(&rbType, cbasn1.OCTET_STRING) || !rb.Empty() {
		return nil, errMalformed
	}
	if !respType.Equal(oidOCSPBasic) {
		return nil, fmt.Errorf("ocsp: unsupported response type %s", respType)
	}
	var basic, tbsRaw, tbs, sigAlg cryptobyte.String
	if !rbType.ReadASN1(&basic, cbasn1.SEQUENCE) || !rbType.Empty() {
		return nil, errMalformed
	}
	if !basic.ReadASN1Element(&tbsRaw, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	resp.TBSResponseData = tbsRaw
	if elem := tbsRaw; !elem.ReadASN1(&tbs, cbasn1.SEQUENCE) || !elem.Empty() {
		return nil, errMalformed
	}
	if !basic.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return nil, errMalformed
	}
	resp.SignatureAlgorithm = parseSignatureAlgorithm(sigAlg)
	var sig asn1.BitString
	if !basic.ReadASN1BitString(&sig) || sig.BitLength%8 != 0 {
		return nil, errMalformed
	}
	resp.Signature = sig.Bytes
	var certsExplicit cryptobyte.String
	var hasCerts bool
	if !basic.ReadOptionalASN1(&certsExplicit, &hasCerts, cbasn1.Tag(0).Constructed().ContextSpecific()) || !basic.Empty() {
		return nil, errMalformed
	}
	if hasCerts {
		var certs cryptobyte.String
		if !certsExplicit.ReadASN1(&certs, cbasn1.SEQUENCE) || !certsExplicit.Empty() {
			return nil, errMalformed
		}
		for !certs.Empty() {
			var c cryptobyte.String
			if !certs.ReadASN1Element(&c, cbasn1.SEQUENCE) || len(resp.Certificates) == maxEmbeddedCerts {
				return nil, errMalformed
			}
			cert, err := x509.ParseCertificate(c)
			if err != nil {
				return nil, fmt.Errorf("ocsp: embedded certificate: %w", err)
			}
			resp.Certificates = append(resp.Certificates, cert)
		}
	}
	if err := parseResponseData(tbs, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func parseSignatureAlgorithm(s cryptobyte.String) x509.SignatureAlgorithm {
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1ObjectIdentifier(&oid) {
		return x509.UnknownSignatureAlgorithm
	}
	for _, a := range signatureAlgorithms {
		if !oid.Equal(a.oid) {
			continue
		}
		switch {
		case s.Empty():
			return a.alg
		case a.nullOK:
			var null cryptobyte.String
			if s.ReadASN1(&null, cbasn1.NULL) && len(null) == 0 && s.Empty() {
				return a.alg
			}
		}
		return x509.UnknownSignatureAlgorithm
	}
	return x509.UnknownSignatureAlgorithm
}

func parseResponseData(s cryptobyte.String, resp *Response) error {
	var version cryptobyte.String
	var hasVersion bool
	if !s.ReadOptionalASN1(&version, &hasVersion, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return errMalformed
	}
	if hasVersion {
		var v int
		if !version.ReadASN1Integer(&v) || !version.Empty() || v != 0 {
			return errors.New("ocsp: unsupported ResponseData version")
		}
	}
	var rid cryptobyte.String
	switch {
	case s.PeekASN1Tag(cbasn1.Tag(1).Constructed().ContextSpecific()):
		var name cryptobyte.String
		if !s.ReadASN1(&rid, cbasn1.Tag(1).Constructed().ContextSpecific()) ||
			!rid.ReadASN1Element(&name, cbasn1.SEQUENCE) || !rid.Empty() {
			return errMalformed
		}
		resp.ResponderName = name
	case s.PeekASN1Tag(cbasn1.Tag(2).Constructed().ContextSpecific()):
		var key cryptobyte.String
		if !s.ReadASN1(&rid, cbasn1.Tag(2).Constructed().ContextSpecific()) ||
			!rid.ReadASN1(&key, cbasn1.OCTET_STRING) || !rid.Empty() || len(key) != sha1.Size {
			return errMalformed
		}
		resp.ResponderKeyHash = key
	default:
		return errMalformed
	}
	if !s.ReadASN1GeneralizedTime(&resp.ProducedAt) {
		return errMalformed
	}
	var singles cryptobyte.String
	if !s.ReadASN1(&singles, cbasn1.SEQUENCE) {
		return errMalformed
	}
	for !singles.Empty() {
		if len(resp.Responses) == maxSingleResponses {
			return errMalformed
		}
		var single cryptobyte.String
		if !singles.ReadASN1(&single, cbasn1.SEQUENCE) {
			return errMalformed
		}
		sr, err := parseSingleResponse(single)
		if err != nil {
			return err
		}
		resp.Responses = append(resp.Responses, sr)
	}
	if len(resp.Responses) == 0 {
		return errMalformed
	}
	exts, err := readExplicitExtensions(&s, 1)
	if err != nil {
		return err
	}
	resp.Extensions = exts
	if !s.Empty() {
		return errMalformed
	}
	return nil
}

func parseSingleResponse(s cryptobyte.String) (SingleResponse, error) {
	sr := SingleResponse{Reason: -1}
	var cid, alg cryptobyte.String
	if !s.ReadASN1(&cid, cbasn1.SEQUENCE) || !cid.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&sr.CertID.HashAlgorithm) {
		return sr, errMalformed
	}
	if !alg.Empty() { // optional NULL parameters
		var null cryptobyte.String
		if !alg.ReadASN1(&null, cbasn1.NULL) || len(null) != 0 || !alg.Empty() {
			return sr, errMalformed
		}
	}
	var nameHash, keyHash cryptobyte.String
	sr.CertID.SerialNumber = new(big.Int)
	if !cid.ReadASN1(&nameHash, cbasn1.OCTET_STRING) || !cid.ReadASN1(&keyHash, cbasn1.OCTET_STRING) ||
		!cid.ReadASN1Integer(sr.CertID.SerialNumber) || !cid.Empty() {
		return sr, errMalformed
	}
	sr.CertID.IssuerNameHash, sr.CertID.IssuerKeyHash = nameHash, keyHash
	var st cryptobyte.String
	var tag cbasn1.Tag
	if !s.ReadAnyASN1(&st, &tag) {
		return sr, errMalformed
	}
	switch tag {
	case cbasn1.Tag(0).ContextSpecific():
		if len(st) != 0 {
			return sr, errMalformed
		}
		sr.Status = CertGood
	case cbasn1.Tag(1).Constructed().ContextSpecific():
		sr.Status = CertRevoked
		if !st.ReadASN1GeneralizedTime(&sr.RevokedAt) {
			return sr, errMalformed
		}
		var reason cryptobyte.String
		var hasReason bool
		if !st.ReadOptionalASN1(&reason, &hasReason, cbasn1.Tag(0).Constructed().ContextSpecific()) || !st.Empty() {
			return sr, errMalformed
		}
		if hasReason {
			if !reason.ReadASN1Enum(&sr.Reason) || !reason.Empty() {
				return sr, errMalformed
			}
		}
	case cbasn1.Tag(2).ContextSpecific():
		if len(st) != 0 {
			return sr, errMalformed
		}
		sr.Status = CertUnknown
	default:
		return sr, errMalformed
	}
	if !s.ReadASN1GeneralizedTime(&sr.ThisUpdate) {
		return sr, errMalformed
	}
	var next cryptobyte.String
	var hasNext bool
	if !s.ReadOptionalASN1(&next, &hasNext, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return sr, errMalformed
	}
	if hasNext {
		if !next.ReadASN1GeneralizedTime(&sr.NextUpdate) || !next.Empty() {
			return sr, errMalformed
		}
	}
	exts, err := readExplicitExtensions(&s, 1)
	if err != nil {
		return sr, err
	}
	sr.Extensions = exts
	if !s.Empty() {
		return sr, errMalformed
	}
	return sr, nil
}

// readExplicitExtensions reads an optional [n] EXPLICIT Extensions.
func readExplicitExtensions(s *cryptobyte.String, n uint8) ([]Extension, error) {
	var wrapper cryptobyte.String
	var present bool
	if !s.ReadOptionalASN1(&wrapper, &present, cbasn1.Tag(n).Constructed().ContextSpecific()) {
		return nil, errMalformed
	}
	if !present {
		return nil, nil
	}
	var seq cryptobyte.String
	if !wrapper.ReadASN1(&seq, cbasn1.SEQUENCE) || !wrapper.Empty() {
		return nil, errMalformed
	}
	var out []Extension
	for !seq.Empty() {
		var ext cryptobyte.String
		var e Extension
		if !seq.ReadASN1(&ext, cbasn1.SEQUENCE) || !ext.ReadASN1ObjectIdentifier(&e.ID) ||
			!ext.ReadOptionalASN1Boolean(&e.Critical, cbasn1.BOOLEAN, false) {
			return nil, errMalformed
		}
		var v cryptobyte.String
		if !ext.ReadASN1(&v, cbasn1.OCTET_STRING) || !ext.Empty() {
			return nil, errMalformed
		}
		e.Value = v
		for _, prev := range out {
			if prev.ID.Equal(e.ID) {
				return nil, errors.New("ocsp: duplicate extension")
			}
		}
		out = append(out, e)
	}
	return out, nil
}
```

`certauth/revocation/ocspverify.go`:
```go
package revocation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // ResponderID byKey is defined with SHA-1
	"crypto/x509"
	"fmt"
	"slices"
	"time"
)

// OCSPInput is everything VerifyOCSP needs. Issuer is chain[i+1] of the
// verified chain, never a client-supplied certificate.
type OCSPInput struct {
	Response *Response
	Want     CertID            // the CertID that was requested
	Issuer   *x509.Certificate // verified issuer of the checked certificate
	Nonce    []byte            // extnValue sent; nil when no nonce was sent
	Now      time.Time
	MaxAge   time.Duration // bound when nextUpdate is absent
}

// OCSPEvidence is an accepted response's content.
type OCSPEvidence struct {
	Single           SingleResponse
	ProducedAt       time.Time
	Signer           *x509.Certificate
	ResponderSubject string
	NonceEchoed      bool
}

// VerifyOCSP applies the acceptance checks in order: response status,
// critical extensions, signer authorization and ResponderID binding,
// signature, CertID match, nonce, freshness. It returns StatusGood,
// StatusRevoked or StatusUnknown only for an accepted response; otherwise
// StatusUnavailable, StatusInvalidEvidence or StatusStale with a detail.
func VerifyOCSP(in OCSPInput) (OCSPEvidence, Status, string) {
	r := in.Response
	ev := OCSPEvidence{ProducedAt: r.ProducedAt}
	if r.Status != ResponseSuccessful {
		return ev, StatusUnavailable, fmt.Sprintf("responseStatus %d", r.Status)
	}
	for _, e := range r.Extensions {
		if e.Critical && !e.ID.Equal(oidOCSPNonce) {
			return ev, StatusInvalidEvidence, "unhandled critical response extension " + e.ID.String()
		}
	}
	if r.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return ev, StatusInvalidEvidence, "unsupported signature algorithm"
	}

	// Signer: the issuer itself, or a delegated responder directly issued by
	// the issuer. Only certificates identified by the ResponderID are tried,
	// so the certificate that verifies the signature is the one the
	// ResponderID names.
	signer, detail := authorizedSigner(in)
	if signer == nil {
		return ev, StatusInvalidEvidence, detail
	}
	ev.Signer, ev.ResponderSubject = signer, signer.Subject.String()

	var match *SingleResponse
	for i := range r.Responses {
		if r.Responses[i].CertID.Equal(in.Want) {
			if match != nil {
				return ev, StatusInvalidEvidence, "more than one SingleResponse matches the CertID"
			}
			match = &r.Responses[i]
		}
	}
	if match == nil {
		return ev, StatusInvalidEvidence, "no SingleResponse matches the requested CertID"
	}
	for _, e := range match.Extensions {
		if e.Critical {
			return ev, StatusInvalidEvidence, "unhandled critical singleExtension " + e.ID.String()
		}
	}
	ev.Single = *match

	if in.Nonce != nil {
		var got []byte
		for _, e := range r.Extensions {
			if e.ID.Equal(oidOCSPNonce) {
				got = e.Value
			}
		}
		if got == nil {
			return ev, StatusInvalidEvidence, "nonce sent but not echoed"
		}
		if !bytes.Equal(got, in.Nonce) {
			return ev, StatusInvalidEvidence, "nonce mismatch"
		}
		ev.NonceEchoed = true
	}

	if match.ThisUpdate.After(in.Now.Add(ClockSkew)) {
		return ev, StatusStale, "thisUpdate in the future"
	}
	if !match.NextUpdate.IsZero() {
		if match.NextUpdate.Before(in.Now) || match.NextUpdate.Before(match.ThisUpdate) {
			return ev, StatusStale, "nextUpdate in the past"
		}
	} else if match.ThisUpdate.Before(in.Now.Add(-in.MaxAge)) {
		return ev, StatusStale, "no nextUpdate and thisUpdate older than the maximum age"
	}

	switch match.Status {
	case CertGood:
		return ev, StatusGood, "good"
	case CertRevoked:
		return ev, StatusRevoked, fmt.Sprintf("revoked (reason %d)", match.Reason)
	case CertUnknown:
		return ev, StatusUnknown, "unknown"
	}
	return ev, StatusInvalidEvidence, "unknown certStatus"
}

// authorizedSigner returns the certificate that is identified by the
// ResponderID, authorized for the issuer, and verifies the signature.
func authorizedSigner(in OCSPInput) (*x509.Certificate, string) {
	r, issuer := in.Response, in.Issuer
	if identifiedBy(r, issuer) {
		if err := issuer.CheckSignature(r.SignatureAlgorithm, r.TBSResponseData, r.Signature); err != nil {
			return nil, "signature by the issuer does not verify"
		}
		return issuer, ""
	}
	detail := "no embedded certificate matches the ResponderID"
	for _, c := range r.Certificates {
		if !identifiedBy(r, c) {
			continue
		}
		switch {
		case !bytes.Equal(c.RawIssuer, issuer.RawSubject) || c.CheckSignatureFrom(issuer) != nil:
			detail = "responder not issued by the certificate issuer"
		case !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning):
			detail = "responder lacks id-kp-OCSPSigning"
		case in.Now.Before(c.NotBefore) || in.Now.After(c.NotAfter):
			detail = "responder certificate not valid now"
		case !onlyNoCheckUnhandled(c):
			detail = "responder has unhandled critical extensions"
		case !hasNoCheck(c):
			detail = "responder lacks id-pkix-ocsp-nocheck"
		case !strongKey(c):
			detail = "responder key too weak"
		case c.CheckSignature(r.SignatureAlgorithm, r.TBSResponseData, r.Signature) != nil:
			detail = "signature by the responder does not verify"
		default:
			return c, ""
		}
	}
	return nil, detail
}

func identifiedBy(r *Response, c *x509.Certificate) bool {
	if r.ResponderName != nil {
		return bytes.Equal(r.ResponderName, c.RawSubject)
	}
	bits, err := spkiBits(c.RawSubjectPublicKeyInfo)
	if err != nil {
		return false
	}
	h := sha1.Sum(bits) //nolint:gosec // ResponderID byKey
	return bytes.Equal(r.ResponderKeyHash, h[:])
}

func hasNoCheck(c *x509.Certificate) bool {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidOCSPNoCheck) {
			return true
		}
	}
	return false
}

func onlyNoCheckUnhandled(c *x509.Certificate) bool {
	for _, oid := range c.UnhandledCriticalExtensions {
		if !oid.Equal(oidOCSPNoCheck) {
			return false
		}
	}
	return true
}

func strongKey(c *x509.Certificate) bool {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return true
	}
	return false
}
```

Testdata (`testdata/ocsp/SOURCES.md`, files byte-identical):

| file | source | sha256 |
|---|---|---|
| aoc-casub-a2.ocsp | `/home/p4u/.cache/cert-check/research/appb-ocsp/casub-a2.ocsp` (http://ocsp.aoc.cat, CA-level, 2026-10-30) | 27f593ee82ab41d6c6f95dfc280485d5a818d99d9eca14a80bff388477819c59 |
| camerfirma-qc2024.ocsp | `…/appb-ocsp/cf2024qc.ocsp` (http://ocsp.camerfirma.com, CA-level) | c093b7842bd432a448ceab8801f40fe3261fb1437421d8e7d4aae6a580c1166b |
| izenpe-profesional-sw-act.ocsp | `…/appb-ocsp/izenpe_profesional_sw_act.ocsp` (http://ocsp.izenpe.com, synthetic kit leaf) | bd28a19c11499b1db20aa6887c7382b2f664febae97c3ab1eb04764d89b70e11 |
| izenpe-profesional-sw-rev.ocsp | `…/appb-ocsp/izenpe_profesional_sw_rev.ocsp` | 6991f71b7157178e570796ad8342d9a334e90f52b8af7a6fb196ef6e8a61856c |
| certs/aoc-g3-root-a.pem | bundle `additional-ca-certificates/15651384ca70c580….pem` | fafc411eb1c25bd829f1e0de29940366b96304e3f6f2c4eaac18830bdbb3ee06 |
| certs/aoc-subca-ciutadania-g3-a2.pem | bundle `service-identities/e6dc96bb0dbcb242….pem` | 57a84099da3c38c557f5203a3de868322e0bc0f8747c8c161d7ccfcee0703ba5 |
| certs/camerfirma-root-2024.pem | bundle `additional-ca-certificates/5a81aba8d5fd0684….pem` | fc818d01b06b9260a8a450d062b0a5867f2563be2cd43338c700cd427b129243 |
| certs/camerfirma-qc-2024.pem | bundle `service-identities/51583118e6c5e5d2….pem` | 5dc7f80df4259758fa33ea1f679944f81e54d3266e95339e885b41efe41a7fe2 |
| certs/izenpe-ca4.pem | bundle `additional-ca-certificates/7ed19361ad734d70….pem` | a3c8c8d49a468cbc0d2fed9edccead3d45a46865ef1e5cb90571c1f27a04fef1 |
| certs/izenpe-profesional-sw-act.pem | `…/appb-ocsp/izenpe_profesional_sw_act.pem` (Izenpe synthetic kit, DER 06c81a7f…2c65) | record |
| certs/izenpe-profesional-sw-rev.pem | `…/appb-ocsp/izenpe_profesional_sw_rev.pem` (DER a3c07e07…d9d9) | record |

These responses answer for CA certificates or the Izenpe synthetic kit (identity `00000000T`
NOMBRE APELLIDOUNO, e-mail `contacto@email.com`). None concerns a real person. The leaf-level AOC
responses `g2leaf.ocsp` and `g3leaf.ocsp` answer for real persons' serials and are not committed.

Run:
- `go test -race -count=1 ./certauth/revocation/...` → `ok`;
- `go test -run '^$' -fuzz '^FuzzParseResponse$' -fuzztime 30s ./certauth/revocation` → `PASS`;
- the Global Constraints checks.

Step 3: commit
`git commit -m "feat(revocation): add rfc 6960 ocsp codec and response acceptance checks" -- certauth/revocation/ocspcodec.go certauth/revocation/ocspverify.go certauth/revocation/ocspcodec_test.go certauth/revocation/ocspverify_test.go certauth/revocation/ocsp_fuzz_test.go certauth/revocation/testdata/ocsp`

Interfaces this task provides to later tasks:
- request: `CertID` (`NewCertID`, `Equal`), `MarshalRequest`, `NonceLength`;
- response: `ResponseStatus*`, `CertStatus` (`CertGood`/`CertRevoked`/`CertUnknown`), `Extension`,
  `SingleResponse`, `Response`, `ParseResponse`;
- acceptance: `OCSPInput`, `OCSPEvidence`, `VerifyOCSP`.


### Task 5: `certauth/revocation`: Checker (OCSP first, CRL fallback) and OCSP cache
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files: `certauth/revocation/{checker.go,ocspcache.go,checker_test.go,ocspcache_test.go}`.

Goal: AC4: OCSP-unavailable → CRL fallback success; OCSP revoked → no fallback; timeout; oversized
response; private-IP destination blocked (end to end). Also the spec "Order", "Cache" and status
mapping rules. The Checker is what `certauth` calls in step 8.

Behaviour notes:
- Order:
  1. OCSP, over the leaf's AIA URLs whose host is allowlisted, in certificate order. The first
     good/revoked/unknown answer ends the step. A failed URL falls through to the next.
  2. CRL, only when OCSP did not end with good/revoked/unknown and `AllowCRL` is set. It walks the
     usable DPs' `http(s)` URIs on allowlisted hosts in order. LDAP URIs are skipped.
- Final failure status: `worstFailure` (invalid_evidence > stale > unavailable). Neither method
  usable → `unavailable`.
- `invalid_evidence` is logged at warn with the issuer DN and the detail only.
- Scope: a verified CA certificate (`BasicConstraintsValid && IsCA`) is checked with CA scope. In
  production these are the pinned DNIe intermediates.
- OCSP cache, key (issuer SHA-256, serial):
  - `good` is reused while `now − thisUpdate < min(5 min, nextUpdate − now)`;
  - `revoked` is reused until nextUpdate;
  - `unknown`, failures and invalid evidence are never cached.
  - Reuse is bound to the response's own thisUpdate, per the spec's second sentence. So ACCV/Sectigo
    answers with an old thisUpdate are simply refetched.
- Nonce: 32 bytes from `crypto/rand` per request when `Policy.OCSPNonce`.
- Timeouts: 5 s for OCSP and 15 s for CRL. Tests may shorten them through `Options`.

Step 1: write the failing tests. Use `testpki.Net` with realistic host names, e.g. `ocsp.test`,
`crl.test`:
- `checker_test.go`:
  - `TestCheckOCSPStatuses`: good / revoked / unknown via OCSP. For revoked and unknown, the CRL
    server sees 0 requests (no fallback).
  - `TestCheckFallback` table. Each of these makes OCSP fail and the CRL answer good, giving
    Method `crl`, status good:
    - OCSP HTTP 503; `ResponseStatus` 3; invalid signature; nonce missing; stale; wrong CertID;
    - no OCSP URL in AIA; AIA host not allowlisted (0 OCSP requests).
  - `TestCheckFailures`:
    - OCSP down and `AllowCRL` false → `unavailable`;
    - OCSP invalid and CRL down → `invalid_evidence`;
    - OCSP down and CRL stale → `stale`;
    - leaf without AIA or CDP → `unavailable`;
    - CRL listed → `revoked` with `RevokedAt` and `Reason`.
  - `TestCheckTimeouts`: OCSP `Slow(1s)` with `Options.OCSPTimeout=100ms` → falls back; the attempt
    detail mentions the deadline.
  - `TestCheckOversizedOCSP`: a 70 KiB raw answer → `unavailable` (`ErrTooLarge`).
  - `TestCheckSecondOCSPURL`: first URL 503, second good → good, two attempts.
  - `TestCheckPrivateIPBlocked`:
    - no `DialContext` override;
    - leaf AIA `http://localhost:P/`, policy host `localhost:P`;
    - want `unavailable` and 0 requests on the loopback server.
  - `TestCheckRedirectToForeignHost`: CDP host redirects to an unlisted host → `unavailable`.
  - `TestCheckCAScope`: an intermediate with a CDP to an ARL carrying `OnlyCA` → good, with a 302
    to the same host first (DNIe pattern).
  - `TestCheckAttempts`: the fields (URL, HTTPStatus, Duration>0, Outcome, ResponderSubject,
    NonceSent, NonceEchoed, ThisUpdate/NextUpdate) are filled for OCSP and CRL attempts.
  - `TestCheckMisuse`: nil cert, nil issuer, invalid policy → error.
  - `TestCheckConcurrent`: 50 goroutines against one Checker under `-race`.
- `ocspcache_test.go`:
  - `TestOCSPCacheGood`: reused at thisUpdate+4m (0 new requests); not reused at +6m; not reused
    after nextUpdate.
  - `TestOCSPCacheRevoked`: reused until nextUpdate; not cached without nextUpdate.
  - `TestOCSPCacheNeverUnknownOrInvalid`.
  - `TestOCSPCacheKeyIncludesIssuer`: same serial under two issuers → two fetches.
  - `TestOCSPCacheBound`: LRU eviction at the entry limit.

Run: `go test -race -count=1 ./certauth/revocation/...` → build failure.

Step 2: implement.

`certauth/revocation/ocspcache.go`:
```go
package revocation

import (
	"container/list"
	"sync"
	"time"
)

// OCSP cache bounds.
const (
	DefaultOCSPCacheEntries = 4096
	ocspGoodMaxAge          = 5 * time.Minute
)

// ocspCache caches accepted good and revoked OCSP answers by (issuer SHA-256, serial).
type ocspCache struct {
	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List
	limit int
}

type ocspItem struct {
	key    string
	ev     OCSPEvidence
	status Status
	source string
}

func newOCSPCache(limit int) *ocspCache {
	return &ocspCache{items: make(map[string]*list.Element), lru: list.New(), limit: limit}
}

// get returns a cached answer still usable at now: good only while
// now − thisUpdate < min(5 min, nextUpdate − now); revoked until nextUpdate.
func (c *ocspCache) get(key string, now time.Time) (ocspItem, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return ocspItem{}, false
	}
	it := el.Value.(*ocspItem)
	s := it.ev.Single
	usable := false
	switch it.status {
	case StatusGood:
		ttl := ocspGoodMaxAge
		if !s.NextUpdate.IsZero() && s.NextUpdate.Sub(now) < ttl {
			ttl = s.NextUpdate.Sub(now)
		}
		age := now.Sub(s.ThisUpdate)
		usable = age >= -ClockSkew && age < ttl
	case StatusRevoked:
		usable = !s.NextUpdate.IsZero() && now.Before(s.NextUpdate)
	}
	if !usable {
		c.lru.Remove(el)
		delete(c.items, key)
		return ocspItem{}, false
	}
	c.lru.MoveToFront(el)
	return *it, true
}

func (c *ocspCache) put(it ocspItem) {
	if it.status != StatusGood && it.status != StatusRevoked {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[it.key]; ok {
		c.lru.Remove(el)
	}
	c.items[it.key] = c.lru.PushFront(&it)
	for c.lru.Len() > c.limit {
		back := c.lru.Back()
		c.lru.Remove(back)
		delete(c.items, back.Value.(*ocspItem).key)
	}
}
```

`certauth/revocation/checker.go`:
```go
package revocation

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"
)

// Options configures a Checker.
type Options struct {
	UserAgent        string           // "cert-check/<version>"
	DialContext      DialFunc         // tests only; nil = address-checking dialer
	Now              func() time.Time // nil = time.Now
	CRLCacheBytes    int64            // 0 = DefaultCRLCacheBytes
	OCSPCacheEntries int              // 0 = DefaultOCSPCacheEntries
	Logger           *slog.Logger     // nil = slog.Default()
	OCSPTimeout      time.Duration    // 0 = OCSPTimeout (5 s); tests shorten it
	CRLTimeout       time.Duration    // 0 = CRLTimeout (15 s)
}

// Checker checks revocation status. It is safe for concurrent use.
type Checker struct {
	fetcher *Fetcher
	now     func() time.Time
	crls    *crlCache
	ocsp    *ocspCache
	log     *slog.Logger
	ocspTO  time.Duration
	crlTO   time.Duration
}

// NewChecker builds a Checker.
func NewChecker(o Options) (*Checker, error) {
	c := &Checker{
		fetcher: NewFetcher(FetcherOptions{UserAgent: o.UserAgent, DialContext: o.DialContext}),
		now:     o.Now,
		crls:    newCRLCache(o.CRLCacheBytes),
		ocsp:    newOCSPCache(o.OCSPCacheEntries),
		log:     o.Logger,
		ocspTO:  cmp.Or(o.OCSPTimeout, OCSPTimeout),
		crlTO:   cmp.Or(o.CRLTimeout, CRLTimeout),
	}
	if c.now == nil {
		c.now = time.Now
	}
	if o.CRLCacheBytes == 0 {
		c.crls.limit = DefaultCRLCacheBytes
	}
	if o.OCSPCacheEntries == 0 {
		c.ocsp.limit = DefaultOCSPCacheEntries
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	return c, nil
}

// Check returns the revocation status of cert, issued by issuer, under
// policy p. issuer must come from the caller's verified chain. A CA
// certificate (pinned intermediate) is checked with CA scope (ARLs with
// onlyContainsCACerts accepted). The error is non-nil only for misuse.
func (c *Checker) Check(ctx context.Context, cert, issuer *x509.Certificate, p Policy) (Result, error) {
	if cert == nil || issuer == nil {
		return Result{}, errors.New("revocation: nil certificate or issuer")
	}
	if err := p.Validate(); err != nil {
		return Result{}, err
	}
	now := c.now()
	res := Result{CheckedAt: now, Reason: -1}
	scope := ScopeLeaf
	if cert.BasicConstraintsValid && cert.IsCA {
		scope = ScopeCA
	}

	ocspStatus := c.checkOCSP(ctx, cert, issuer, p, now, &res)
	switch ocspStatus {
	case StatusGood, StatusRevoked, StatusUnknown:
		res.Status, res.Method = ocspStatus, MethodOCSP
		return res, nil
	}
	crlStatus := StatusUnsupportedMethod
	if p.AllowCRL {
		crlStatus = c.checkCRL(ctx, cert, issuer, p, scope, now, &res)
		if crlStatus == StatusGood || crlStatus == StatusRevoked {
			res.Status, res.Method = crlStatus, MethodCRL
			return res, nil
		}
	}
	res.Status = worstFailure(ocspStatus, crlStatus)
	if res.Status == StatusInvalidEvidence {
		c.log.Warn("revocation evidence rejected", "issuer", issuer.Subject.String(), "detail", res.Detail)
	}
	return res, nil
}

// worstFailure folds two failed methods into one status: invalid evidence
// first (it is logged), then stale, otherwise unavailable. Neither method
// usable is unavailable.
func worstFailure(a, b Status) Status {
	switch {
	case a == StatusInvalidEvidence || b == StatusInvalidEvidence:
		return StatusInvalidEvidence
	case a == StatusStale || b == StatusStale:
		return StatusStale
	}
	return StatusUnavailable
}

func (c *Checker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate, p Policy, now time.Time, res *Result) Status {
	var urls []string
	for _, s := range cert.OCSPServer {
		if u, err := url.Parse(s); err == nil && hostAllowed(u, p.OCSPHosts) {
			urls = append(urls, s)
		}
	}
	if len(urls) == 0 {
		res.Attempts = append(res.Attempts, Attempt{Method: MethodOCSP, Outcome: StatusUnsupportedMethod, Detail: "no allowlisted OCSP URL"})
		res.Detail = "no allowlisted OCSP URL"
		return StatusUnsupportedMethod
	}
	key := issuerKey(issuer) + " " + SerialKey(cert.SerialNumber)
	if it, ok := c.ocsp.get(key, now); ok {
		c.fillOCSP(res, it.ev, it.source)
		res.Attempts = append(res.Attempts, Attempt{Method: MethodOCSP, URL: it.source, Outcome: it.status, FromCache: true,
			ThisUpdate: it.ev.Single.ThisUpdate, NextUpdate: it.ev.Single.NextUpdate, ResponderSubject: it.ev.ResponderSubject})
		return it.status
	}
	id, err := NewCertID(crypto.SHA1, cert, issuer)
	if err != nil {
		res.Detail = err.Error()
		return StatusInvalidEvidence
	}
	last := StatusUnavailable
	for _, u := range urls {
		st, ev := c.ocspOnce(ctx, u, id, issuer, p, now, res)
		switch st {
		case StatusGood, StatusRevoked, StatusUnknown:
			c.ocsp.put(ocspItem{key: key, ev: ev, status: st, source: hostOf(u)}) // put ignores unknown
			return st
		}
		last = worstFailure(last, st)
	}
	return last
}

func (c *Checker) ocspOnce(ctx context.Context, u string, id CertID, issuer *x509.Certificate, p Policy, now time.Time, res *Result) (Status, OCSPEvidence) {
	var nonce []byte
	if p.OCSPNonce {
		nonce = make([]byte, NonceLength)
		if _, err := rand.Read(nonce); err != nil {
			res.Detail = "nonce generation failed"
			return StatusUnavailable, OCSPEvidence{}
		}
	}
	reqDER, nonceExt, err := MarshalRequest(id, nonce)
	if err != nil {
		res.Detail = err.Error()
		return StatusUnavailable, OCSPEvidence{}
	}
	at := Attempt{Method: MethodOCSP, URL: u, NonceSent: nonce != nil}
	fr, err := c.fetcher.Fetch(ctx, FetchRequest{
		URL: u, Body: reqDER, ContentType: "application/ocsp-request", Accept: "application/ocsp-response",
		MaxBytes: MaxOCSPResponse, Timeout: c.ocspTO, AllowedHosts: p.AllHosts(),
	})
	at.HTTPStatus, at.Duration = fr.StatusCode, fr.Duration
	record := func(st Status, detail string) Status {
		at.Outcome, at.Detail = st, detail
		res.Attempts = append(res.Attempts, at)
		res.Detail = fmt.Sprintf("OCSP %s: %s", u, detail)
		return st
	}
	if err != nil {
		return record(StatusUnavailable, err.Error()), OCSPEvidence{}
	}
	resp, err := ParseResponse(fr.Body)
	if err != nil {
		return record(StatusInvalidEvidence, err.Error()), OCSPEvidence{}
	}
	ev, st, detail := VerifyOCSP(OCSPInput{Response: resp, Want: id, Issuer: issuer, Nonce: nonceExt, Now: now, MaxAge: p.MaxAge()})
	at.ProducedAt, at.ThisUpdate, at.NextUpdate = ev.ProducedAt, ev.Single.ThisUpdate, ev.Single.NextUpdate
	at.ResponderSubject, at.NonceEchoed = ev.ResponderSubject, ev.NonceEchoed
	st = record(st, detail)
	if st == StatusGood || st == StatusRevoked || st == StatusUnknown {
		c.fillOCSP(res, ev, hostOf(u))
	}
	return st, ev
}

func (c *Checker) fillOCSP(res *Result, ev OCSPEvidence, source string) {
	res.ThisUpdate, res.NextUpdate, res.Source = ev.Single.ThisUpdate, ev.Single.NextUpdate, source
	if ev.Single.Status == CertRevoked {
		res.RevokedAt, res.Reason = ev.Single.RevokedAt, ev.Single.Reason
	}
}

func (c *Checker) checkCRL(ctx context.Context, cert, issuer *x509.Certificate, p Policy, scope Scope, now time.Time, res *Result) Status {
	dps, err := ParseCRLDistributionPoints(cert)
	if err != nil {
		res.Attempts = append(res.Attempts, Attempt{Method: MethodCRL, Outcome: StatusUnsupportedMethod, Detail: err.Error()})
		return StatusUnsupportedMethod
	}
	last, tried := StatusUnsupportedMethod, false
	for _, dp := range usableDistributionPoints(dps, issuer) {
		for _, gn := range dp.FullName {
			raw, ok := gn.URI()
			if !ok {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil || !hostAllowed(u, p.CRLHosts) {
				continue
			}
			tried = true
			st := c.crlOnce(ctx, raw, cert, issuer, dp, p, scope, now, res)
			if st == StatusGood || st == StatusRevoked {
				return st
			}
			last = worstFailure(last, st)
		}
	}
	if !tried {
		res.Attempts = append(res.Attempts, Attempt{Method: MethodCRL, Outcome: StatusUnsupportedMethod, Detail: "no usable allowlisted CDP URL"})
		return StatusUnsupportedMethod
	}
	return last
}

func (c *Checker) crlOnce(ctx context.Context, u string, cert, issuer *x509.Certificate, dp DistributionPoint, p Policy, scope Scope, now time.Time, res *Result) Status {
	key := issuerKey(issuer) + " " + u
	load := c.crls.load(ctx, key, now, c.crlTO, func(fctx context.Context) crlLoad {
		at := Attempt{Method: MethodCRL, URL: u}
		fr, err := c.fetcher.Fetch(fctx, FetchRequest{URL: u, MaxBytes: MaxCRLResponse, Timeout: c.crlTO, AllowedHosts: p.AllHosts()})
		at.HTTPStatus, at.Duration = fr.StatusCode, fr.Duration
		if err != nil {
			return crlLoad{status: StatusUnavailable, err: err, attempt: at}
		}
		parsed, st, err := ParseCRL(fr.Body, issuer)
		if err != nil {
			return crlLoad{status: st, err: err, attempt: at}
		}
		parsed.URL = u
		return crlLoad{crl: parsed, status: StatusGood, attempt: at}
	})
	at := load.attempt
	if at.URL == "" {
		at.URL = u
	}
	if load.err != nil {
		at.Outcome, at.Detail = load.status, load.err.Error()
		res.Attempts = append(res.Attempts, at)
		res.Detail = fmt.Sprintf("CRL %s: %s", u, at.Detail)
		return load.status
	}
	st, rec, detail := EvaluateCRL(load.crl, cert, dp, scope, now)
	at.Outcome, at.Detail = st, detail
	at.ThisUpdate, at.NextUpdate = load.crl.List.ThisUpdate, load.crl.List.NextUpdate
	res.Attempts = append(res.Attempts, at)
	res.Detail = fmt.Sprintf("CRL %s: %s", u, detail)
	if st == StatusGood || st == StatusRevoked {
		res.ThisUpdate, res.NextUpdate, res.Source = load.crl.List.ThisUpdate, load.crl.List.NextUpdate, hostOf(u)
		if st == StatusRevoked {
			res.RevokedAt, res.Reason = rec.RevokedAt, rec.Reason
		}
	}
	return st
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
```

Run: `go test -race -count=1 ./certauth/revocation/...` →
`ok  github.com/vocdoni/cert-check/certauth/revocation`, then the Global Constraints checks.

Step 3: commit
`git commit -m "feat(revocation): add ocsp-first checker with crl fallback and bounded caches" -- certauth/revocation/checker.go certauth/revocation/ocspcache.go certauth/revocation/checker_test.go certauth/revocation/ocspcache_test.go`

Interfaces this task provides to later tasks: `revocation.Checker` (`NewChecker(Options)`,
`Check(ctx, cert, issuer, Policy) (Result, error)`), `revocation.Options` (`UserAgent`,
`DialContext`, `Now`, cache bounds, `Logger`, `OCSPTimeout`, `CRLTimeout`).


### Task 6: `certauth/profiles`: registry, pinned anchors, provider data, TSL cross-check
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `certauth/profiles/{types.go,registry.go,providers.go}`;
- `certauth/profiles/anchors/*.pem` (29 files), `certauth/profiles/anchors/SOURCES.md`;
- `certauth/profiles/testdata/{spanish_tsl_inventory_2026-10-30.json,SOURCES.md}`;
- `certauth/profiles/{registry_test.go,tsl_test.go,providers_test.go,specimens_test.go}`.

Goal: AC5, except the per-profile pipeline runs, which are in Task 7. That covers anchor pins,
parsing with Go 1.27, CA flag, validity at build time, TSL granted status or a reviewed exception,
and fingerprint markers. Also Goal 8: every scoped profile is present with pinned anchors, exact
OIDs, grammar and revocation endpoints.

Behaviour notes:
- Load rules (spec "Profile registry"):
  - fatal: pin or SPKI mismatch, non-CA anchor, invalid declaration, an intermediate not signed by
    a profile anchor, two profiles of a provider sharing an anchor key and a policy OID;
  - an anchor outside its validity is skipped with a warning;
  - a profile with no valid anchor (or no valid pinned intermediate, when it declares some) is
    disabled with a warning;
  - a provider without enabled profiles is hidden.
- `ClientCAs` holds the anchors and the pinned intermediates. DNIe advertises 4 DNs.
- Firmaprofesional:
  - Of the two CUALIFICADOS DERs, only `2b75cc4f…` is pinned. `4ccf17c0…` (same key and DN) is in
    `KnownAliases`, not loaded.
  - FIRMAPROFESIONAL ICA B01 QUALIFIED 2022 (`4a86f333…`) is pinned too: digest C lists it as the
    profile's anchor. The spec's "Pin `2b75cc4f…` only" (audit F16) is read as "of the CUALIFICADOS
    pair". The controller confirms or drops ICA B01.
- `IntermediateExceptions` holds only the three DNIe intermediates. `KnownAliases` is a separate
  list. The spec's "exception list holds intermediates only" stays true.
- Nonce flags. `OCSPNonce: true` only where the digests record a live nonce echo: FNMT citizen,
  AOC, ACCV, DIGITEL, Bewor and DNIe. Sectigo is pre-generated, so no nonce. The others are
  unprobed, so false. Task 12's probe reports echo behaviour, and a later ruling may flip a flag.
- Exclusions are by omission. These OIDs are not allowlisted, and `TestExcludedOIDsAbsent` asserts
  it:
  - FNMT pseudonym/judicial `5734.3.17.{3,4,5,6,8,10}` and `5734.3.23.{2.0,3.0,1.1,3.1,4.1,1.3}`;
  - consular `5734.3.26.1.0`;
  - Bewor `55693.1.1.1`;
  - Sectigo `6449.1.2.1.7.{2,3,4,5}`;
  - Firmaprofesional `13177.10.1.40.3`;
  - ANF `18332.3.4.1.{4,5}.22` and `49201.3.4.1.{4,5}.22`;
  - Uanataca `47286.1.1.1.{2,3,4}`, `47286.1.1.6`, `47286.1.1.6.2`;
  - SIGNE `36035.1.3.1`;
  - Lleidanet `49959.1.1.1.2.1`;
  - DNIe `2.16.724.1.2.2.2.3` and `.2.2.2.11`;
  - historical AOC `15096.1.3.1.*`;
  - ACCV legacy `8149.3.7.{6,7}.0`.

**Per-profile data** (transcribed from the digests; the reviewer checks `providers.go` against this
table and this table against the digests). Confidence notes repeat the digests'
`low`/`unverified` flags, and the implementation uses exactly the documented form.

| # | profile id | provider id | anchor DER SHA-256 (SPKI SHA-256 prefix) | pinned intermediates | policy OIDs (exact) | EKU | identity grammar | OCSP hosts / CRL hosts | nonce | flags; confidence |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | fnmt-citizen-rsa | fnmt | 601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869 (0b21720b91f0) | — | 1.3.6.1.4.1.5734.3.10.1 | RequireClientAuth | 2.5.4.5 `IDCES-<DNI\|NIE>` or bare `<DNI\|NIE>`; GN 2.5.4.42; SN 2.5.4.4 complete; SAN dirName 5734.1.4 bare = doc, .1.1 = GN, .1.2 [+ .1.3] = SN → first/second | ocspusu.cert.fnmt.es / www.cert.fnmt.es | yes | 12 specimen fingerprints. Some leaves have an LDAP-only CDP, so OCSP only. Medium: bare-to-IDCES timeline; the NIE prefix assumed to be `IDCES-` |
| 2 | fnmt-citizen-g2 | fnmt | 283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89 (4a7bdf68cceb) | — | 1.3.6.1.4.1.5734.3.20.1.0 | RequireClientAuth | as #1 but `IDCES-` only | ocspusug2.cert.fnmt.es (path `/ocspusuG2/`, from the leaf AIA verbatim) / www.cert.fnmt.es | yes | 2 fingerprints. ECDSA P-256 leaves. SN required |
| 3 | aoc-idcat-g2 | idcat | 0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6 (3761345542c2) | — | 1.3.6.1.4.1.15096.1.3.2.86.2 | RequireClientAuth | `IDCES-<DNI\|NIE>` only; `IDCxx-`/`PASxx-` → unsupported; subject C = ES; SN legacy ` - DNI <id>` stripped only on an exact match | ocsp.catcert.cat, ocsp.aoc.cat / epscd.catcert.net, epscd.aoc.cat | yes | `HandledCriticalExtensions` qcStatements 1.3.6.1.5.5.7.1.3. Subject marker NOMDOS/ESPECIMENDOS. Fingerprint of the 2015 fixture. Medium: identity (no current leaf); leaf host catcert vs aoc unverified, so both AOC hosts; NIE form unverified |
| 4 | aoc-idcat-g3 | idcat | e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735 (4da535844e84) | — | 1.3.6.1.4.1.15096.1.3.2.86.2 | RequireClientAuth | as #3, no legacy suffix | same as #3 | yes | MinRSABits 3072 (DPC v7.4 §6.1.5). Medium: leaf key type and identity unverified |
| 5 | accv-citizen-software-current | accv | a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1 (03cd20b076b5); 5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496 (73b39454c0f8) | — | 1.3.6.1.4.1.8149.3.7.8.0 | RequireClientAuth | bare `<DNI\|NIE>`; K/L/M → unsupported; SAN dirName CN `GIVEN\|S1\|S2` (exactly 3 fields) = GN/SN; SAN UID = doc | ocsp.accv.es / www.accv.es (302 to the same host) | yes | MinRSABits 3072 (CP-07 v8.0.4). RSA1 CRL is 13.6 MB (< 32 MiB cap). Medium: ECC curve; empty S2 and Ñ handling unverified |
| 6 | digitel-citizen-sw-g1 | digitel | 86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61 (00600557c655) | — | 1.3.6.1.4.1.54225.10.3.1 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN | ocsp.digitelts.es / crl1.pki.digitelts.es, crl2.pki.digitelts.es | yes | Specimen 99949996T fingerprint. NIE form assumed |
| 7 | bewor-natural-person-sw | bewor | 8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d (ba0331d2b536) | — | 1.3.6.1.4.1.55693.1.1.2 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN | ocsp1.uanataca.com, ocsp2.uanataca.com / crl1.uanataca.com, crl2.uanataca.com | yes | `.1.1.1` (HSM) not listed. 2 specimen fingerprints. NIE form not observed |
| 8 | sectigo-citizen-local | sectigo | ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde (eb9f35a491f4); 53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9 (8e351d9cb41b) | — | 1.3.6.1.4.1.6449.1.2.1.7.1 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN | ocsp.sectigo.com / crl.sectigo.com | no (pre-generated, 7-day window) | digitalSignature mandatory. Fingerprints: citizen and employee specimens. E35 path untested |
| 9 | fnmt-representative-rsa | fnmt-representative (beta) | 8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b (da576c79f49f) | — | 1.3.6.1.4.1.5734.3.11.1, .11.2, .11.3 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN; SAN 5734.1.4 `IDCES-` = doc; .1.1/.1.2/.1.3; Organization O (required) + 2.5.4.97 | ocsprep.cert.fnmt.es / www.cert.fnmt.es | no (unprobed) | role representative. Medium: no leaf |
| 10 | fnmt-representative-g2 | fnmt-representative (beta) | 0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64 (66f3f2da778b) | — | 1.3.6.1.4.1.5734.3.21.1.0, .21.2.0, .21.3.0 | RequireClientAuth | as #9 | ocsprepg2.cert.fnmt.es / www.cert.fnmt.es | no | URL case unverified |
| 11 | fnmt-employee-rsa | fnmt-employee (beta) | 8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498 (68de305107cb) | — | 1.3.6.1.4.1.5734.3.17.2 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN; SAN 2.16.724.1.3.5.7.2.4 bare = doc, .2.6 GN, .2.7 first, .2.8 second; Organization O + 2.5.4.97 | ocspsp.cert.fnmt.es / www.cert.fnmt.es | no | role public_employee. Medium |
| 12 | fnmt-employee-g2 | fnmt-employee (beta) | 983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe (a1e3f004222a) | — | 1.3.6.1.4.1.5734.3.23.1.0 | RequireClientAuth | as #11 | ocspspg2.cert.fnmt.es / www.cert.fnmt.es | no | Low: G2 §5 not read |
| 13 | firmaprofesional-personal-sw | firmaprofesional (beta) | 2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf (c695bd5c40f7); 4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1 (dab1f8803dcf) | — | 1.3.6.1.4.1.13177.10.1.40.2 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN; SAN 13177.0.1 = GN, 0.2 [+ 0.3] = SN | ocsp.firmaprofesional.com / crl.firmaprofesional.com | no | Alias 4ccf17c0 not loaded. Medium: leaf AIA/CDP unverified; serialNumber form changed in 2025 |
| 14 | anf-asociacion-class2-sw | anf (beta) | b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23 (d1b4c6d6b4f3) | — | 1.3.6.1.4.1.18332.3.4.1.2.22 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN; private SAN ignored | ocsp.anf.es / crl.anf.es | no | Private extensions 18332.19/.19.1: if critical → `invalid_chain` (no handler). Medium |
| 15 | anf-sl-class2-sw | anf (beta) | 5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a (9992ddc44e5b) | — | 1.3.6.1.4.1.49201.3.4.1.2.22 | RequireClientAuth | as #14 | ocsp.anf.es / crl.anf.es | no | as #14 |
| 16 | uanataca-citizen-sw | uanataca (beta) | 35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f (c886cd88edc6); 00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909 (fac53d2ea566); 9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a (12093d696c24); 15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a (5f78b32f4a47) | — | 1.3.6.1.4.1.47286.1.1.1.1 | RequireClientAuth (DPC silent; the spec reserves AllowAbsent for DNIe) | `IDCES-<DNI\|NIE>`; GN; SN | ocsp1.uanataca.com, ocsp2.uanataca.com / crl1.uanataca.com, crl2.uanataca.com | no | Low: prefix and EKU unconfirmed; older leaves may carry legacy OIDs (rejected) |
| 17 | signe-personal-otros-dispositivos | signe (beta) | b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea (7988bdc1ad8e); 244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35 (6a30d221e4ac) | — | 1.3.6.1.4.1.36035.1.3.2 | RequireClientAuth | `IDCES-<DNI>` or `PNOES-<NIE>`; `PASxx-` → unsupported; SAN 13177.0.{1,2,3} = GN/SN | — (leaf OCSP unknown) / www.signe.es | n/a | CRL only. Medium: "otros dispositivos" may mean a token |
| 18 | lleidanet-natural-person-sw | lleidanet (beta) | 3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25 (e0f0a51ac007) | — | 1.3.6.1.4.1.49959.1.1.1.1.1 | RequireClientAuth | `IDCES-<DNI\|NIE>`; GN; SN (upper case); no SAN | ocsp2.esigna.es / crl1.esigna.es, crl.esigna.es | no | Medium |
| 19 | dnie-auth | dnie (beta) | c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11 (4a5dc6f07837) | AC DNIE 004 ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c (1b5b9b72ed25); 005 828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828 (1f6b84c54a18); 006 eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd (60a9a73a0c25) | 2.16.724.1.2.2.2.4 | AllowAbsent | bare DNI only; SN = first surname; CN `<SURNAMES>, <GN> (AUTENTICACIÓN\|AUTENTICACION)` must start with SN and end with GN; SDA dateOfBirth optional | ocsp.dnie.es / pki.policia.es (intermediates' ARL only; leaves have no CDP) | yes | Good answers without nextUpdate → 15 min max age. RSA ≥ 2048 (1920-bit ROCA rejected by the floor). 13 fingerprints. Newer sub-CAs (007+) are not pinned → `untrusted_issuer` |

Every profile has KU `digitalSignature` required, with absent KU rejected. RSA ≥ 2048 unless noted.
Display order and UI names (spec table):
- standard: fnmt "FNMT – Persona Física", idcat "idCAT Certificat", accv "ACCV – Ciudadano
  (software)", digitel "DIGITEL ON – Ciudadano", bewor "Bewor – Persona Física", sectigo "Sectigo –
  Ciudadano";
- Beta: fnmt-representative "FNMT – Representante", fnmt-employee "FNMT – Empleado Público",
  firmaprofesional "Firmaprofesional", anf "ANF AC", uanataca "Uanataca", signe "SIGNE", lleidanet
  "Lleidanet / inDenova", dnie "DNIe (requires card reader)".

Step 1: write the failing tests:
- `registry_test.go`:
  - `TestDefaultLoads`:
    - `Default(time.Now())` succeeds;
    - provider IDs in exact display order;
    - beta flags as above;
    - profile counts 2,2,1,1,1,1,2,2,1,2,1,1,1,1;
    - `ClientCAs("dnie")` has 4 certificates, `ClientCAs("fnmt")` 2, `ClientCAs("uanataca")` 4;
    - unknown provider → error.
  - `TestRegistryErrors` table (each built with `New` and `TestAnchor` from testpki CAs):
    - DER pin mismatch, SPKI pin mismatch, malformed pin, non-CA anchor (testpki leaf) → error;
    - duplicate provider/profile ID; bad provider ID `Foo`;
    - bad OID `1.2.03`; EKU unset; invalid adapter; invalid policy; marker with both or neither of
      SHA256/Subject;
    - intermediate not signed by an anchor;
    - two profiles sharing an anchor and an OID → error;
    - same anchor with distinct OIDs → ok.
  - `TestValidityDisables`:
    - all anchors expired → profile disabled and provider hidden (warning logged);
    - one of two anchors expired → still enabled with one root;
    - intermediates all expired → disabled.
  - `TestAllAnchors`: the union pools cover every enabled profile.
  - Use `slices.ContainsFunc` over `Enabled().Anchors` rather than `CertPool.Subjects` (deprecated,
    SA1019).
- `tsl_test.go`:
  - `TestTSLInventorySource`: the file SHA-256 equals `647da585e4949b6e6a14d7190dc7dead70a60e60b46b051d7de7829a9175a8b8` (recorded in `testdata/SOURCES.md`).
  - `TestAnchorsGrantedInTSL` (AC5). Every anchor of `DefaultProviders()` appears in the inventory
    as a service identity whose service has `status` `…/Svcstatus/granted`, `service_type`
    `…/Svctype/CA/QC` and `current_granted_CA_QC: true`. The inventory `spki_sha256` equals the pin.
    Every intermediate is in `IntermediateExceptions` and absent from the inventory. Every
    `KnownAliases` key is granted and shares its SPKI with its value.
- `providers_test.go`:
  - `TestAnchorFiles` (AC5). Every `anchors/*.pem` file:
    - is referenced by exactly one pin;
    - holds one PEM block whose DER SHA-256 is the file name;
    - has its file SHA-256 equal to `anchors/SOURCES.md`;
    - parses with Go 1.27;
    - is CA:TRUE, valid at `time.Now()`, has no unhandled critical extension;
    - has an EKU that is absent or contains clientAuth.
    Every referenced file exists.
  - `TestProfilesTable`: an independent table in the test repeats the per-profile data above (id,
    provider, anchors, OIDs, EKU rule, OCSP/CRL hosts, nonce, MinRSABits, handled extensions) and
    compares field by field.
  - `TestExcludedOIDsAbsent`: the list in the behaviour notes.
  - `TestSpecimenMarkers`: every specimen in `certauth/testdata/specimens/MANIFEST.md` is a
    fingerprint marker of exactly one profile. That includes the AC DNIE 001 leaves (under
    `dnie-auth`), the 2015 idCAT leaf (under `aoc-idcat-g2`) and the Sectigo employee leaf (under
    `sectigo-citizen-local`). When R-P1 withheld files, their fingerprints are still checked against
    the manifest table.
- `specimens_test.go`. `TestProfileAdaptersOnSpecimens`: each specimen through the adapter of the
  profile that pins its issuer gives the expected identity. Reuse the values listed in Task 2's
  `TestSpecimenIdentities`, now through the real declarations.

Run: `go test -race -count=1 ./certauth/profiles/...` → build failure.

Step 2: implement.

`certauth/profiles/types.go`:
```go
// Package profiles holds the provider/profile registry: pinned anchors
// (embedded PEM, SHA-256 and SPKI pins checked at load), exact policy OIDs,
// purpose and algorithm rules, identity adapters, revocation policies and
// test-certificate markers.
package profiles

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Role is the holder role of a profile.
type Role string

// Roles (JSON values of profile.holderRole).
const (
	RoleNaturalPerson  Role = "natural_person"
	RoleRepresentative Role = "representative"
	RolePublicEmployee Role = "public_employee"
)

// Valid reports whether r is a defined role.
func (r Role) Valid() bool {
	return r == RoleNaturalPerson || r == RoleRepresentative || r == RolePublicEmployee
}

// Anchor is a pinned CA certificate: a trust anchor or a pinned intermediate.
type Anchor struct {
	File       string // path in the embedded FS, "anchors/<sha256>.pem"; empty when DER is set
	DER        []byte // tests only: the certificate itself
	SHA256     string // pinned SHA-256 of the DER, lowercase hex
	SPKISHA256 string // pinned SHA-256 of the SubjectPublicKeyInfo, lowercase hex
}

// TestAnchor builds an Anchor from a certificate with computed pins (tests).
func TestAnchor(c *x509.Certificate) Anchor {
	d, s := sha256.Sum256(c.Raw), sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return Anchor{DER: c.Raw, SHA256: hex.EncodeToString(d[:]), SPKISHA256: hex.EncodeToString(s[:])}
}

// KURule is the leaf KeyUsage rule. digitalSignature is always required when
// the extension is present.
type KURule struct {
	AllowAbsent bool // no enabled profile sets this
}

// EKURule is the leaf ExtendedKeyUsage rule.
type EKURule int

// EKU rules.
const (
	// EKURequireClientAuth: the extension is present and lists clientAuth.
	EKURequireClientAuth EKURule = iota + 1
	// EKUAllowAbsent: absent, or present and listing clientAuth (DNIe only).
	EKUAllowAbsent
)

// AlgPolicy tightens the global algorithm floor (RSA ≥ 2048, ECDSA
// P-256/P-384/P-521, SHA-256+ signatures) where a profile documents it.
type AlgPolicy struct {
	MinRSABits int // 0 = 2048
}

// AttributeMatch is one exact subject attribute value.
type AttributeMatch struct {
	OID   asn1.ObjectIdentifier
	Value string
}

// TestMarker identifies a known test or specimen certificate.
type TestMarker struct {
	SHA256  string           // leaf DER SHA-256 (lowercase hex); or
	Subject []AttributeMatch // an exact subject attribute combination documented by the issuer
	Source  string           // where it comes from (fixture file, CPS section)
}

// Profile is a versioned, exact allowlist entry.
type Profile struct {
	ID                        string
	ProviderID                string
	Name                      string
	HolderRole                Role
	Anchors                   []Anchor
	Intermediates             []Anchor // pinned CAs between anchor and leaf (DNIe only)
	PolicyOIDs                []string // exact dotted OIDs; the leaf asserts at least one
	KeyUsage                  KURule
	EKU                       EKURule
	Algorithms                AlgPolicy
	Identity                  identity.Adapter
	Revocation                revocation.Policy
	TestMarkers               []TestMarker
	HandledCriticalExtensions []string // dotted OIDs parsed by certauth itself (aoc-idcat-g2: qcStatements)
}

// Provider is a selectable UI entry and auth subdomain grouping profiles.
type Provider struct {
	ID          string // DNS label: [a-z][a-z0-9-]{0,62}
	Name        string
	Description string
	Beta        bool
	Profiles    []Profile
}

// ProviderInfo is the provider part of a result.
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ProfileInfo is the profile part of a result.
type ProfileInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	HolderRole Role   `json:"holderRole"`
}
```

`certauth/profiles/registry.go`:
```go
package profiles

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
)

//go:embed anchors/*.pem
var embeddedAnchors embed.FS

// AnchorsFS returns the embedded anchor files (for tests that compare them
// with the research bundle).
func AnchorsFS() fs.FS { return embeddedAnchors }

// Config configures New.
type Config struct {
	Providers []Provider        // display order
	Reserved  identity.Reserved // reserved identities and name markers
	Now       time.Time         // load time: anchor validity is checked against it
	Logger    *slog.Logger      // nil = slog.Default()
	Files     fs.FS             // where Anchor.File is read; nil = embedded anchors
}

// Enabled is a loaded profile with parsed anchors and pools.
type Enabled struct {
	Profile       Profile
	Anchors       []*x509.Certificate
	Intermediates []*x509.Certificate
	Roots         *x509.CertPool // anchors only
	Inter         *x509.CertPool // pinned intermediates only (never client-sent certificates)
	fingerprints  map[string]struct{}
}

// IsFingerprintMarker reports whether a leaf SHA-256 (hex) is a known specimen.
func (e *Enabled) IsFingerprintMarker(sha256Hex string) bool {
	_, ok := e.fingerprints[sha256Hex]
	return ok
}

type loadedProvider struct {
	info     Provider // Profiles holds only enabled profiles
	enabled  []*Enabled
	clientCA *x509.CertPool
}

// Registry is the immutable loaded registry. Safe for concurrent use.
type Registry struct {
	providers []*loadedProvider
	byID      map[string]*loadedProvider
	reserved  identity.Reserved
	allRoots  *x509.CertPool
	allInter  *x509.CertPool
}

var (
	providerIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	profileIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hexSHA256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	oidRe        = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)
)

// Default loads the production registry from the embedded anchors.
func Default(now time.Time, logger *slog.Logger) (*Registry, error) {
	return New(Config{Providers: DefaultProviders(), Reserved: identity.DefaultReserved(), Now: now, Logger: logger})
}

// New validates and loads a registry. A pin mismatch, a non-CA anchor or an
// invalid declaration is fatal. A profile whose anchors have all expired (or
// are not yet valid) is disabled with a warning; a provider without enabled
// profiles is hidden.
func New(cfg Config) (*Registry, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	files := cfg.Files
	if files == nil {
		files = embeddedAnchors
	}
	if cfg.Now.IsZero() {
		return nil, errors.New("profiles: Config.Now is required")
	}
	r := &Registry{byID: map[string]*loadedProvider{}, reserved: cfg.Reserved,
		allRoots: x509.NewCertPool(), allInter: x509.NewCertPool()}
	profileIDs := map[string]bool{}
	for _, p := range cfg.Providers {
		if !providerIDRe.MatchString(p.ID) || p.Name == "" {
			return nil, fmt.Errorf("profiles: invalid provider %q", p.ID)
		}
		if _, dup := r.byID[p.ID]; dup {
			return nil, fmt.Errorf("profiles: duplicate provider %q", p.ID)
		}
		lp := &loadedProvider{info: p, clientCA: x509.NewCertPool()}
		lp.info.Profiles = nil
		for _, prof := range p.Profiles {
			if profileIDs[prof.ID] {
				return nil, fmt.Errorf("profiles: duplicate profile %q", prof.ID)
			}
			profileIDs[prof.ID] = true
			if prof.ProviderID != p.ID {
				return nil, fmt.Errorf("profiles: profile %q declares provider %q inside %q", prof.ID, prof.ProviderID, p.ID)
			}
			e, err := loadProfile(prof, files, cfg.Now, log)
			if err != nil {
				return nil, err
			}
			if e == nil {
				continue // disabled: all anchors outside validity
			}
			lp.enabled = append(lp.enabled, e)
			lp.info.Profiles = append(lp.info.Profiles, prof)
			for _, c := range e.Anchors {
				lp.clientCA.AddCert(c)
				r.allRoots.AddCert(c)
			}
			for _, c := range e.Intermediates {
				lp.clientCA.AddCert(c)
				r.allInter.AddCert(c)
			}
		}
		if err := checkAmbiguity(lp.enabled); err != nil {
			return nil, err
		}
		r.byID[p.ID] = lp
		if len(lp.enabled) == 0 {
			log.Warn("provider hidden: no enabled profile", "provider", p.ID)
			continue
		}
		r.providers = append(r.providers, lp)
	}
	return r, nil
}

func loadProfile(p Profile, files fs.FS, now time.Time, log *slog.Logger) (*Enabled, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	e := &Enabled{Profile: p, Roots: x509.NewCertPool(), Inter: x509.NewCertPool(), fingerprints: map[string]struct{}{}}
	for _, a := range p.Anchors {
		c, err := loadAnchor(a, files)
		if err != nil {
			return nil, fmt.Errorf("profiles: %s: %w", p.ID, err)
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			log.Warn("anchor outside validity, not loaded", "profile", p.ID, "anchor", a.SHA256)
			continue
		}
		e.Anchors = append(e.Anchors, c)
		e.Roots.AddCert(c)
	}
	if len(e.Anchors) == 0 {
		log.Warn("profile disabled: no valid anchor", "profile", p.ID)
		return nil, nil
	}
	for _, a := range p.Intermediates {
		c, err := loadAnchor(a, files)
		if err != nil {
			return nil, fmt.Errorf("profiles: %s intermediate: %w", p.ID, err)
		}
		if !slices.ContainsFunc(e.Anchors, func(root *x509.Certificate) bool { return c.CheckSignatureFrom(root) == nil }) {
			return nil, fmt.Errorf("profiles: %s: intermediate %s is not signed by a profile anchor", p.ID, a.SHA256)
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			log.Warn("intermediate outside validity, not loaded", "profile", p.ID, "intermediate", a.SHA256)
			continue
		}
		e.Intermediates = append(e.Intermediates, c)
		e.Inter.AddCert(c)
	}
	if len(p.Intermediates) > 0 && len(e.Intermediates) == 0 {
		log.Warn("profile disabled: no valid pinned intermediate", "profile", p.ID)
		return nil, nil
	}
	for _, m := range p.TestMarkers {
		if m.SHA256 != "" {
			e.fingerprints[m.SHA256] = struct{}{}
		}
	}
	return e, nil
}

func validateProfile(p Profile) error {
	var errs []error
	if !profileIDRe.MatchString(p.ID) || p.Name == "" || !p.HolderRole.Valid() {
		errs = append(errs, errors.New("invalid id, name or role"))
	}
	if len(p.Anchors) == 0 || len(p.PolicyOIDs) == 0 {
		errs = append(errs, errors.New("anchors and policy OIDs are required"))
	}
	for _, o := range append(slices.Clone(p.PolicyOIDs), p.HandledCriticalExtensions...) {
		if !oidRe.MatchString(o) {
			errs = append(errs, fmt.Errorf("invalid OID %q", o))
		}
	}
	if p.EKU != EKURequireClientAuth && p.EKU != EKUAllowAbsent {
		errs = append(errs, errors.New("EKU rule unset"))
	}
	if p.Algorithms.MinRSABits != 0 && p.Algorithms.MinRSABits < 2048 {
		errs = append(errs, errors.New("MinRSABits below the 2048 floor"))
	}
	if err := p.Identity.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := p.Revocation.Validate(); err != nil {
		errs = append(errs, err)
	}
	for _, m := range p.TestMarkers {
		if (m.SHA256 == "") == (len(m.Subject) == 0) || (m.SHA256 != "" && !hexSHA256Re.MatchString(m.SHA256)) {
			errs = append(errs, errors.New("test marker needs exactly one of SHA256 or Subject"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("profiles: %s: %w", p.ID, err)
	}
	return nil
}

func loadAnchor(a Anchor, files fs.FS) (*x509.Certificate, error) {
	der := a.DER
	if der == nil {
		b, err := fs.ReadFile(files, a.File)
		if err != nil {
			return nil, err
		}
		blk, rest := pem.Decode(b)
		if blk == nil || blk.Type != "CERTIFICATE" || len(bytesTrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%s: want exactly one PEM certificate", a.File)
		}
		der = blk.Bytes
	}
	if !hexSHA256Re.MatchString(a.SHA256) || !hexSHA256Re.MatchString(a.SPKISHA256) {
		return nil, errors.New("anchor pins missing or malformed")
	}
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != a.SHA256 {
		return nil, fmt.Errorf("anchor %s: SHA-256 pin mismatch", a.SHA256)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("anchor %s: %w", a.SHA256, err)
	}
	spki := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(spki[:]) != a.SPKISHA256 {
		return nil, fmt.Errorf("anchor %s: SPKI pin mismatch", a.SHA256)
	}
	if !c.BasicConstraintsValid || !c.IsCA {
		return nil, fmt.Errorf("anchor %s: not a CA", a.SHA256)
	}
	return c, nil
}

func bytesTrimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == '\n' || b[0] == '\r' || b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// checkAmbiguity rejects two profiles of one provider that share an anchor
// key and a policy OID (step 4 could then match both).
func checkAmbiguity(es []*Enabled) error {
	for i, a := range es {
		for _, b := range es[i+1:] {
			if !sharesKey(a.Anchors, b.Anchors) {
				continue
			}
			for _, o := range a.Profile.PolicyOIDs {
				if slices.Contains(b.Profile.PolicyOIDs, o) {
					return fmt.Errorf("profiles: %s and %s share an anchor and policy %s", a.Profile.ID, b.Profile.ID, o)
				}
			}
		}
	}
	return nil
}

func sharesKey(a, b []*x509.Certificate) bool {
	for _, x := range a {
		for _, y := range b {
			if string(x.RawSubjectPublicKeyInfo) == string(y.RawSubjectPublicKeyInfo) {
				return true
			}
		}
	}
	return false
}

// Providers returns the enabled providers in display order; each Provider's
// Profiles lists only enabled profiles.
func (r *Registry) Providers() []Provider {
	out := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.info)
	}
	return out
}

// Provider returns an enabled provider.
func (r *Registry) Provider(id string) (Provider, bool) {
	p, ok := r.byID[id]
	if !ok || len(p.enabled) == 0 {
		return Provider{}, false
	}
	return p.info, true
}

// Enabled returns the enabled profiles of a provider, in declaration order.
func (r *Registry) Enabled(providerID string) []*Enabled {
	p, ok := r.byID[providerID]
	if !ok {
		return nil
	}
	return p.enabled
}

// ClientCAs returns the anchors and pinned intermediates of the provider's
// enabled profiles (sent as certificate_authorities in the TLS handshake).
func (r *Registry) ClientCAs(providerID string) (*x509.CertPool, error) {
	p, ok := r.byID[providerID]
	if !ok || len(p.enabled) == 0 {
		return nil, fmt.Errorf("profiles: unknown provider %q", providerID)
	}
	return p.clientCA.Clone(), nil
}

// AllAnchors returns the union of every enabled profile's anchors and pinned
// intermediates (used only to tell provider_mismatch from untrusted_issuer).
func (r *Registry) AllAnchors() (roots, intermediates *x509.CertPool) {
	return r.allRoots.Clone(), r.allInter.Clone()
}

// Reserved returns the reserved-identity registry.
func (r *Registry) Reserved() identity.Reserved { return r.reserved }
```

`certauth/profiles/providers.go` (complete data, load-tested with the 29 anchors):
```go
package profiles

import (
	"encoding/asn1"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Source digests: A = docs/research/appendix-a-fnmt-dnie-accv.md,
// B = appendix-b-idcat-izenpe-camerfirma.md, C = appendix-cde-other-providers.md.
// Specimen fingerprints: certauth/testdata/specimens/MANIFEST.md.

func anchor(sha, spki string) Anchor {
	return Anchor{File: "anchors/" + sha + ".pem", SHA256: sha, SPKISHA256: spki}
}

func fp(sha, file string) TestMarker {
	return TestMarker{SHA256: sha, Source: "certauth/testdata/specimens/" + file}
}

func oid(arcs ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(arcs) }

var (
	dniNIE  = []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}
	dniOnly = []identity.DocumentType{identity.DocumentDNI}
	nieOnly = []identity.DocumentType{identity.DocumentNIE}
	idces   = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: dniNIE}}
	bare    = []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniNIE}}
	noSAN   = identity.SANCheck{Kind: identity.SANNone}
)

// plain: IDCES-<DNI|NIE> in 2.5.4.5, GN 2.5.4.42, complete surnames in SN 2.5.4.4,
// no SAN check, no birth date, no organization.
func plain() identity.Adapter {
	return identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN, SAN: noSAN,
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone}
}

// sanAttrs declares SAN directoryName attributes that must agree with the subject.
func sanAttrs(docOID asn1.ObjectIdentifier, docRules []identity.DocumentRule, given, first, second asn1.ObjectIdentifier) identity.SANCheck {
	return identity.SANCheck{Kind: identity.SANAttributes, DocumentOID: docOID, DocumentRules: docRules,
		GivenNameOID: given, FirstSurnameOID: first, SecondSurnameOID: second}
}

func fnmt5734(n int) asn1.ObjectIdentifier { return oid(1, 3, 6, 1, 4, 1, 5734, 1, n) }

// fnmtSAN: 5734.1.4 document (encoding differs: citizen bare, representative IDCES-),
// .1.1 given, .1.2 first surname, .1.3 second surname; order-independent.
func fnmtSAN(doc []identity.DocumentRule) identity.SANCheck {
	return sanAttrs(fnmt5734(4), doc, fnmt5734(1), fnmt5734(2), fnmt5734(3))
}

// fp13177: Firmaprofesional SAN namespace, also used by SIGNE.
func fp13177() identity.SANCheck {
	n := func(i int) asn1.ObjectIdentifier { return oid(1, 3, 6, 1, 4, 1, 13177, 0, i) }
	return sanAttrs(nil, nil, n(1), n(2), n(3))
}

func policy(nonce bool, ocsp, crl []string) revocation.Policy {
	return revocation.Policy{OCSPHosts: ocsp, CRLHosts: crl, AllowCRL: len(crl) > 0, OCSPNonce: nonce}
}

func person(id, providerID, name string, anchors []Anchor, oids []string, a identity.Adapter, p revocation.Policy, markers ...TestMarker) Profile {
	return Profile{ID: id, ProviderID: providerID, Name: name, HolderRole: RoleNaturalPerson, Anchors: anchors,
		PolicyOIDs: oids, EKU: EKURequireClientAuth, Identity: a, Revocation: p, TestMarkers: markers}
}

// DefaultProviders returns the production providers in display order:
// standard first, then the Beta group. Each call returns a fresh copy.
func DefaultProviders() []Provider {
	return []Provider{
		fnmt(), idcat(), accv(), digitel(), bewor(), sectigo(),
		fnmtRepresentative(), fnmtEmployee(), firmaprofesional(), anf(), uanataca(), signe(), lleidanet(), dnie(),
	}
}

// fnmt: digest A fnmt-citizen-rsa / fnmt-citizen-g2; manifest G3-G6.
func fnmt() Provider {
	rsa := identity.Adapter{
		Documents: append(append([]identity.DocumentRule{}, idces...), bare...), // bare = May-2016 kit (AllowBare)
		Surnames:  identity.SurnamesFromSN, SAN: fnmtSAN(bare),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	g2 := rsa
	g2.Documents = idces
	return Provider{ID: "fnmt", Name: "FNMT – Persona Física",
		Description: "Certificado de Persona Física de la FNMT-RCM (AC FNMT Usuarios y AC USUARIOS G2)",
		Profiles: []Profile{
			person("fnmt-citizen-rsa", "fnmt", "FNMT Persona Física (AC FNMT Usuarios)",
				[]Anchor{anchor("601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869", "0b21720b91f0e45c43f2e7cb185f552eb7de7ed46b2ac172ee39b50841710a6f")},
				[]string{"1.3.6.1.4.1.5734.3.10.1"}, rsa,
				policy(true, []string{"ocspusu.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}),
				fp("71bdc889e9f46890999b47665259e10b97cf654e03a9474b6a24ab03f455142e", "fnmt-rsa-caducado-99999999R-2016.pem"),
				fp("bbb3fd5e64641122c5a6951c69fd7c2a35e90e92290d3d5cdd1fa2d0bb3950f5", "fnmt-rsa-legacy2016-activo-apellidounopf-pruebaspf.pem"),
				fp("442045710183f1bbfe78f63c992cd5139d30cc976e917c19d23bdb6f156467ba", "fnmt-rsa-legacy2016-revocado-apellidounorev-pruebaspf.pem"),
				fp("3533bc399e58b7072cc7cc3a9d19e4f2a955770dd4827e1f6abdd2a9ed00d2af", "fnmt-rsa-nosmime-activo-99999972C-2024.pem"),
				fp("278259d1098998c445e15fc011a5211c3f411096fb57fe41b948957cf916a8ed", "fnmt-rsa-nosmime-activo-99999999R-2024.pem"),
				fp("0bcf1dcc10ddb3e9a085420c94c543718fff037416eb048448dc05499240b0bc", "fnmt-rsa-nosmime-espanol-espanol-juan-00000000T-2023.pem"),
				fp("26fa9c9cc42b06e5a5a6abb1f6696ae4161c51e616dc943376cfeefd104a3469", "fnmt-rsa-nosmime-revocado-99999999R-2024.pem"),
				fp("a8f1eb76c810b373fa5b8f98006a7a0c190e9304935d6e3bf2ffa6f4c4bdfa92", "fnmt-rsa-revocado-pruebasrev-99999999R-2016.pem"),
				fp("a9d9a67e92c66c4d0ee25bc28e170a6ecde111adece30c4e9e83503500b182a6", "fnmt-rsa-smime-revocado-99999999R-2020.pem"),
				fp("cb2e6141218bb0c85c12012143711f91612ab94d3663c5036d720598fcb86024", "fnmt-rsa-supervisor-especimen-99949990V-2025.pem"),
				fp("e75503b06c03e99ecb94bb752b0e4b7fcc74a27637338dda6f4b8e5316c98623", "fnmt-rsa-supervisor-especimen-99949991H-2025.pem"),
				fp("51a72445a18c30d767a3c978005c917eb6f2bcd93ece4e00669a914bb0fa1e3e", "fnmt-rsa-supervisor-especimen-99949999A-2025.pem"),
			),
			person("fnmt-citizen-g2", "fnmt", "FNMT Persona Física (AC USUARIOS G2)",
				[]Anchor{anchor("283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89", "4a7bdf68ccebcdbfccfcdbe75ccb2d744e28be51a401fa34da558489696c807f")},
				[]string{"1.3.6.1.4.1.5734.3.20.1.0"}, g2,
				policy(true, []string{"ocspusug2.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}),
				fp("83f79619f52ab8f36755de28680685cfa4cefa5c44dad22397b04e70d506ec10", "fnmt-ecc-g2-activo-especimen-99949991H-2025.pem"),
				fp("d2dbabbb298198ac476d33a40933ce69c650b55f5c162e076edf72c58da9e7ba", "fnmt-ecc-g2-revocado-especimen-99949990V-2025.pem"),
			),
		}}
}

// idcat: digest B aoc-idcat-g2 / aoc-idcat-g3 (same OID, dispatched by anchor).
func idcat() Provider {
	g2 := plain()
	g2.CountryMatchesPrefix, g2.LegacyDNISuffix = true, true
	g3 := plain()
	g3.CountryMatchesPrefix = true
	hostsOCSP := []string{"ocsp.catcert.cat", "ocsp.aoc.cat"}
	hostsCRL := []string{"epscd.catcert.net", "epscd.aoc.cat"}
	p2 := person("aoc-idcat-g2", "idcat", "idCAT Certificat (EC-Ciutadania)",
		[]Anchor{anchor("0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6", "3761345542c20b314a744a7c54a82152a283be9cdcda233f050000c2d0e5070d")},
		[]string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, g2, policy(true, hostsOCSP, hostsCRL),
		fp("81ffa40e096b6cf32c3082454d22ace4f0bb009b99f26995eb59da36eae4482b", "idcat-g2-pf-peca-de-proves-00000000T.pem"),
		TestMarker{Subject: []AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}},
			Source: "AOC DPC v7.4 §1.1.3 production test certificate"},
	)
	p2.HandledCriticalExtensions = []string{"1.3.6.1.5.5.7.1.3"} // qcStatements, critical on leaves before profile v6.8
	p3 := person("aoc-idcat-g3", "idcat", "idCAT Certificat (SubCA CIUTADANIA Q (G3) A.2)",
		[]Anchor{anchor("e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735", "4da535844e847db014be7e842d7b243118f3d28ce487c32cb62e5a72c70b88c2")},
		[]string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, g3, policy(true, hostsOCSP, hostsCRL),
		TestMarker{Subject: []AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}},
			Source: "AOC DPC v7.4 §1.1.3 production test certificate"},
	)
	p3.Algorithms = AlgPolicy{MinRSABits: 3072} // DPC v7.4 §6.1.5
	return Provider{ID: "idcat", Name: "idCAT Certificat", Description: "Certificat idCAT del Consorci AOC",
		Profiles: []Profile{p2, p3}}
}

// accv: digest A accv-citizen-software-current (RSA1 and ECC1 CLIENTE).
func accv() Provider {
	a := identity.Adapter{
		Documents: bare, Surnames: identity.SurnamesFromSN,
		SAN:       identity.SANCheck{Kind: identity.SANPipeCN, DocumentOID: identity.OIDUID, DocumentRules: bare},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	p := person("accv-citizen-software-current", "accv", "ACCV Ciudadano en soporte software",
		[]Anchor{
			anchor("a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1", "03cd20b076b5b589a78efa46a09e6d1cc8ba5878088113749d16f7414cd9c1f1"),
			anchor("5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496", "73b39454c0f85a4f23e29e923073aa74f755934809e359f2ea87c9eebfa34b75"),
		},
		[]string{"1.3.6.1.4.1.8149.3.7.8.0"}, a,
		policy(true, []string{"ocsp.accv.es"}, []string{"www.accv.es"}))
	p.Algorithms = AlgPolicy{MinRSABits: 3072} // CP-07 v8.0.4 §6.1.5
	return Provider{ID: "accv", Name: "ACCV – Ciudadano (software)",
		Description: "Certificado cualificado de Ciudadano en soporte software de la ACCV", Profiles: []Profile{p}}
}

// digitel: digest C digitel-citizen-sw-g1.
func digitel() Provider {
	return Provider{ID: "digitel", Name: "DIGITEL ON – Ciudadano", Description: "Certificado cualificado de ciudadano DIGITEL (software)",
		Profiles: []Profile{person("digitel-citizen-sw-g1", "digitel", "DIGITEL Ciudadano software (QUALIFIED CA G1)",
			[]Anchor{anchor("86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61", "00600557c6552a65e2dd8dee34d7b674043fd1c5935562ded5f26e2e5777eabb")},
			[]string{"1.3.6.1.4.1.54225.10.3.1"}, plain(),
			policy(true, []string{"ocsp.digitelts.es"}, []string{"crl1.pki.digitelts.es", "crl2.pki.digitelts.es"}),
			fp("fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8", "digitel-ciudadanosw-99949996T.pem"),
		)}}
}

// bewor: digest C bewor-natural-person-sw (.1.1.1 centralised HSM is not listed).
func bewor() Provider {
	return Provider{ID: "bewor", Name: "Bewor – Persona Física", Description: "Certificado cualificado de persona física Bewor (software)",
		Profiles: []Profile{person("bewor-natural-person-sw", "bewor", "Bewor Persona Física software (BEWOR TECH CA1)",
			[]Anchor{anchor("8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d", "ba0331d2b536d13f5d8953475ae3b945764ed54b3788ba5bf4f4a7ee6e770003")},
			[]string{"1.3.6.1.4.1.55693.1.1.2"}, plain(),
			policy(true, []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, []string{"crl1.uanataca.com", "crl2.uanataca.com"}),
			fp("da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab", "bewor-pfsoftbt-99949999A.pem"),
			fp("52bef7a958c349ed0dc1881865c911820e9ef9f7b32741d67273a8f1ba527d92", "bewor-pfsoftbt-revocado-99999999R.pem"),
		)}}
}

// sectigo: digest C sectigo-citizen-local (R35 and E35); pre-generated OCSP, no nonce.
func sectigo() Provider {
	return Provider{ID: "sectigo", Name: "Sectigo – Ciudadano", Description: "Certificado cualificado de ciudadano Sectigo (no QSCD)",
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

// fnmtRepresentative (beta): digest A, three roles per CA generation.
func fnmtRepresentative() Provider {
	a := identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN, SAN: fnmtSAN(idces),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationFromSubject}
	rsa := person("fnmt-representative-rsa", "fnmt-representative", "FNMT Representante (AC Representación)",
		[]Anchor{anchor("8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b", "da576c79f49f91353b1865dfcf889888f9ce50391b2a261d51a3c677676ef044")},
		[]string{"1.3.6.1.4.1.5734.3.11.1", "1.3.6.1.4.1.5734.3.11.2", "1.3.6.1.4.1.5734.3.11.3"}, a,
		policy(false, []string{"ocsprep.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	g2 := person("fnmt-representative-g2", "fnmt-representative", "FNMT Representante (AC REPRESENTACIÓN G2)",
		[]Anchor{anchor("0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64", "66f3f2da778bf26070b42bc7accd97d9f188d25a15f1e2575603042618c13502")},
		[]string{"1.3.6.1.4.1.5734.3.21.1.0", "1.3.6.1.4.1.5734.3.21.2.0", "1.3.6.1.4.1.5734.3.21.3.0"}, a,
		policy(false, []string{"ocsprepg2.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	rsa.HolderRole, g2.HolderRole = RoleRepresentative, RoleRepresentative
	return Provider{ID: "fnmt-representative", Name: "FNMT – Representante", Beta: true,
		Description: "Certificado de Representante de la FNMT-RCM", Profiles: []Profile{rsa, g2}}
}

// fnmtEmployee (beta): digest A, software lanes only (17.2 and 23.1.0).
func fnmtEmployee() Provider {
	n := func(i int) asn1.ObjectIdentifier { return oid(2, 16, 724, 1, 3, 5, 7, 2, i) }
	a := identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN,
		SAN:       sanAttrs(n(4), bare, n(6), n(7), n(8)),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationFromSubject}
	rsa := person("fnmt-employee-rsa", "fnmt-employee", "FNMT Empleado Público (AC Sector Público)",
		[]Anchor{anchor("8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498", "68de305107cbd1889d7a9b039fdca503c1a88ad1f45d1752df8f50c72969d915")},
		[]string{"1.3.6.1.4.1.5734.3.17.2"}, a,
		policy(false, []string{"ocspsp.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	g2 := person("fnmt-employee-g2", "fnmt-employee", "FNMT Empleado Público (AC SECTOR PÚBLICO G2)",
		[]Anchor{anchor("983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe", "a1e3f004222a51998b97853b50fdbfbe9b3f932c3bd0b85737663bd19b33a906")},
		[]string{"1.3.6.1.4.1.5734.3.23.1.0"}, a,
		policy(false, []string{"ocspspg2.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	rsa.HolderRole, g2.HolderRole = RolePublicEmployee, RolePublicEmployee
	return Provider{ID: "fnmt-employee", Name: "FNMT – Empleado Público", Beta: true,
		Description: "Certificado de Empleado Público de la FNMT-RCM (software)", Profiles: []Profile{rsa, g2}}
}

// firmaprofesional (beta): digest C; CUALIFICADOS pinned once (alias 4ccf17c0 not loaded) plus ICA B01.
func firmaprofesional() Provider {
	a := plain()
	a.SAN = fp13177()
	return Provider{ID: "firmaprofesional", Name: "Firmaprofesional", Beta: true,
		Description: "Certificado Personal de Persona Física (sin DCCF)",
		Profiles: []Profile{person("firmaprofesional-personal-sw", "firmaprofesional", "Firmaprofesional Persona Física (sin DCCF)",
			[]Anchor{
				anchor("2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf", "c695bd5c40f753beb93f653202a3d6354ede0dd21295fd894a0869be366753e6"),
				anchor("4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1", "dab1f8803dcf0900d5810e5d9b598781a1f039b30bdf89ad241bfa3e358dd8f9"),
			},
			[]string{"1.3.6.1.4.1.13177.10.1.40.2"}, a,
			policy(false, []string{"ocsp.firmaprofesional.com"}, []string{"crl.firmaprofesional.com"}))}}
}

// anf (beta): digest C, two legal providers, one anchor each; private SAN ignored.
func anf() Provider {
	asoc := person("anf-asociacion-class2-sw", "anf", "ANF AC Clase 2 Persona Física (Asociación)",
		[]Anchor{anchor("b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23", "d1b4c6d6b4f387bd50f89359a11c3a07673effb796cbcecfd32219594362988c")},
		[]string{"1.3.6.1.4.1.18332.3.4.1.2.22"}, plain(),
		policy(false, []string{"ocsp.anf.es"}, []string{"crl.anf.es"}))
	sl := person("anf-sl-class2-sw", "anf", "ANF Clase 2 Persona Física (S.L.)",
		[]Anchor{anchor("5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a", "9992ddc44e5b001f31044fd4723e424e3e2509799b084211f660d321a2fea436")},
		[]string{"1.3.6.1.4.1.49201.3.4.1.2.22"}, plain(),
		policy(false, []string{"ocsp.anf.es"}, []string{"crl.anf.es"}))
	return Provider{ID: "anf", Name: "ANF AC", Beta: true,
		Description: "Certificado de Clase 2 de Persona Física (software)", Profiles: []Profile{asoc, sl}}
}

// uanataca (beta): digest C uanataca-citizen-sw, four issuing CAs.
func uanataca() Provider {
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
			policy(false, []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, []string{"crl1.uanataca.com", "crl2.uanataca.com"}))}}
}

// signe (beta): digest C; NIE as PNOES-<NIE> only here; leaf OCSP unknown, so CRL only.
func signe() Provider {
	a := plain()
	a.Documents = []identity.DocumentRule{
		{Encoding: identity.EncodingIDCES, Types: dniOnly},
		{Encoding: identity.EncodingPNOES, Types: nieOnly},
	}
	a.SAN = fp13177()
	return Provider{ID: "signe", Name: "SIGNE", Beta: true,
		Description: "Certificado Personal de Persona Física (otros dispositivos)",
		Profiles: []Profile{person("signe-personal-otros-dispositivos", "signe", "SIGNE Persona Física (otros dispositivos)",
			[]Anchor{
				anchor("b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea", "7988bdc1ad8ebd8bf150d25ffe876fb05bb3444e1c064bd13f2a57d82bb5f66f"),
				anchor("244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35", "6a30d221e4acfdae38d34006418094fa8337da2f30b9a99c04cfe7d98317dd70"),
			},
			[]string{"1.3.6.1.4.1.36035.1.3.2"}, a,
			policy(false, nil, []string{"www.signe.es"}))}}
}

// lleidanet (beta): digest C lleidanet-natural-person-sw.
func lleidanet() Provider {
	return Provider{ID: "lleidanet", Name: "Lleidanet / inDenova", Beta: true,
		Description: "Certificado de Persona Natural Software",
		Profiles: []Profile{person("lleidanet-natural-person-sw", "lleidanet", "Lleidanet Persona Natural Software",
			[]Anchor{anchor("3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25", "e0f0a51ac007c5ea964344e785c4ac005d8db0e8cd7a33943f726a46c0532d3e")},
			[]string{"1.3.6.1.4.1.49959.1.1.1.1.1"}, plain(),
			policy(false, []string{"ocsp2.esigna.es"}, []string{"crl1.esigna.es", "crl.esigna.es"}))}}
}

// dnie (beta): digest A dnie-auth plus the fixture manifest answers (G1).
func dnie() Provider {
	a := identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniOnly}},
		Surnames:  identity.SurnamesDNIeCN, SAN: noSAN,
		BirthDate: identity.BirthDateOptional, Organization: identity.OrganizationNone,
	}
	p := person("dnie-auth", "dnie", "DNIe Autenticación",
		[]Anchor{anchor("c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11", "4a5dc6f078372f3497d01ba654c902357b54a1c53387f8b3cf3b92749cdeb44b")},
		[]string{"2.16.724.1.2.2.2.4"}, a,
		// pki.policia.es serves the root ARL for the pinned intermediates; leaves have no CDP.
		policy(true, []string{"ocsp.dnie.es"}, []string{"pki.policia.es"}),
		fp("ce3dff1caf0b15381a97f428f8346a0d81fafc818402a096960a90ce8bac0059", "dnie-ac004-auth-activo.pem"),
		fp("c6caec7063ae8a37efb36d54086444812ccdf2e8d9ae81b2d68cfe53a315f554", "dnie-ac004-auth-caducado.pem"),
		fp("7059081d082e86bf2678f61ce9c818ee73adf9ff52dbc7dcbd1618bbc6359541", "dnie-ac004-auth-revocado.pem"),
		fp("767cdce2cb7e3e5c5ca13dfb6695535c0d3bc678fd6ac9bf8c02d83226b6d2d6", "dnie-ac004-firma-activo.pem"),
		fp("9ed5001c16deac81eca78ff293fd78a15362a13b9867558f645a1cab0c7f4df5", "dnie-ac004-firma-caducado.pem"),
		fp("6c3315c2f98c396314224970494df9d77f609ed30b61b70a261e51fbf8998ddf", "dnie-ac004-firma-revocado.pem"),
		fp("7a74251ea5ca45c971ba067fa1941fc128bb4a3e7b886b90754209b1ccc44815", "dnie-ac004-firmacentralizada-activo.pem"),
		fp("64412f7a0b4540b0ce57b47c2339319094a1efba35109860bc047ce060558a0f", "dnie-ac004-firmacentralizada-caducado.pem"),
		fp("21ad4a4966ef8ec6f7904718c509506542d6e4ed7baf4079f925b1fbcce97dc6", "dnie-ac004-firmacentralizada-revocado.pem"),
		fp("cde734ca6f58e7450ed58cef14357c619474c80930171880c69c284a238492b5", "dnie-ac001-auth-activo.pem"),
		fp("6af1aec2a3422648643a353e3baf5362d7a91797c904cf50fa97c7db4288efc0", "dnie-ac001-auth-revocado.pem"),
		fp("a7aebe5c4d5864733439327180108bf524962d71fee55da0dc79b585dc3ef02a", "dnie-ac001-firma-activo.pem"),
		fp("a22ef3464ab64708854b832eeb4004e4afe0b6fdba614cbe62f4afb9345092fe", "dnie-ac001-firma-revocado.pem"),
	)
	p.EKU = EKUAllowAbsent // "extKeyUsage: No se utilizará" (CPS v3.4)
	p.Intermediates = []Anchor{
		anchor("ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c", "1b5b9b72ed25bdab71a112d252c747f5961bfed9ad4bce77292af34b1146481f"), // AC DNIE 004
		anchor("828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828", "1f6b84c54a1824bdc0f639487dfaa29c7b2bc7fefe69499651eb2036fcf859a2"), // AC DNIE 005
		anchor("eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd", "60a9a73a0c25f1e14b44508554076c2c48ad32c503c9bc534c945a82a290cb97"), // AC DNIE 006
	}
	return Provider{ID: "dnie", Name: "DNIe (requires card reader)", Beta: true,
		Description: "Certificado de Autenticación del DNI electrónico; the browser must already be able to use the card",
		Profiles:    []Profile{p}}
}

// IntermediateExceptions are pinned intermediates that are not TSL service
// identities. Reviewed: official AIA downloads (anchors/SOURCES.md), verified
// against AC RAIZ DNIE 2.
var IntermediateExceptions = []string{
	"ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c",
	"828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828",
	"eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd",
}

// KnownAliases are TSL service identities deliberately not loaded because a
// pinned anchor has the same subject and key (crypto/tls would advertise the
// DN twice). Value: the pinned anchor.
var KnownAliases = map[string]string{
	"4ccf17c0c8c1c10d5876ec5e3280fe8d134df36aedd8444289b990bc3741e74f": "2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf",
}
```

Anchors:
- Copy byte for byte (`cp`, not re-encoded) into `certauth/profiles/anchors/<DER sha256>.pem`:
  - the 26 bundle PEMs from `/home/p4u/certificate_poc/docs/Vocdoni_CSP_Handoff/service-identities/<sha>.pem`;
  - the DNIe intermediates from `/home/p4u/.cache/cert-check/research/ca-downloads/dnie/AC00{4,5,6}.crt`.
    These are PEM, raw SHA-256 f368f0dc…ff33, 4e6e2467…6b89 and bf910f9e…f4a2; DER as in the table.
- `anchors/SOURCES.md` lists for each file: subject, source (bundle path or official URL
  `http://pki.policia.es/dnie/certs/AC00N.crt`, fetched 2026-10-30), file SHA-256, DER SHA-256,
  SPKI SHA-256, and TSL service status.
- Verified in planning: all 26 TSL anchors are `granted` CA/QC current in the inventory. The 3 DNIe
  intermediates are not in it and verify against AC RAIZ DNIE 2.
- Copy `spanish_tsl_inventory_2026-10-30.json` verbatim to `certauth/profiles/testdata/` and record
  its SHA-256 `647da585…a8b8` in `testdata/SOURCES.md`.

Run: `go test -race -count=1 ./certauth/profiles/...` →
`ok  github.com/vocdoni/cert-check/certauth/profiles`, then the Global Constraints checks.

Step 3: commit
`git commit -m "feat(profiles): add pinned provider registry with tsl cross-check" -- certauth/profiles`

Interfaces this task provides to later tasks:
- types: `Role*`, `Anchor`, `TestAnchor`, `KURule`, `EKURule*`, `AlgPolicy`, `AttributeMatch`,
  `TestMarker`, `Profile`, `Provider`, `ProviderInfo`, `ProfileInfo`;
- registry: `Config`, `New`, `Default`, `DefaultProviders`, `Registry` (`Providers`, `Provider`,
  `Enabled`, `ClientCAs`, `AllAnchors`, `Reserved`), `Enabled` (`IsFingerprintMarker`);
- data: `IntermediateExceptions`, `KnownAliases`, `AnchorsFS`.


### Task 7: `certauth`: Checker pipeline, typed errors, diagnostics
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `certauth/{types.go,diagnostics.go,checker.go}`;
- `certauth/{checker_test.go,pathmap_test.go,purpose_test.go,profiles_pipeline_test.go,specimens_pipeline_test.go,diagnostics_test.go,result_json_test.go}`.
  `certauth/specimens_test.go` from Task 1 stays.

Goal: AC3 (every ErrorCode path), AC5 (per-profile synthetic leaf through the full pipeline;
double rejection of each committed specimen), AC13 (diagnostics complete per path; the log
attributes carry no PII), and Goal 2. Spec "Validation pipeline" steps 1–9.

Behaviour notes:
- Step order is exactly the code. Algorithms (2) run before path (3), because Go reports a SHA-1
  leaf signature as `UnknownAuthorityError`. Identity (7/7b) runs before revocation (8).
- Step 2 applies the global floor. The profile's `MinRSABits` is applied right after step 4, still
  `weak_algorithm`, because the profile is unknown before step 4.
- Path-error ranking (`mapPathErrors`) for when no candidate verifies:
  `IncompatibleUsage` (→ `unsupported_purpose`) > `Expired` (→ `not_yet_valid`/`expired` by leaf
  dates, else `invalid_chain`) > `UnhandledCriticalExtension` (→ `invalid_chain`) > `UnknownAuthority`
  (→ `provider_mismatch` if the leaf verifies against the union pool, else `untrusted_issuer`) >
  other (→ `invalid_chain`).
  - Go rejects unhandled critical extensions before building chains. So for a candidate failing
    that way, a stripped copy is verified to learn whether this profile's anchor issued the leaf.
    That is classification only, never acceptance.
  - Measured outcomes:
    - critical qcStatements under idCAT G3 → `invalid_chain`;
    - under G2 → accepted;
    - an EKU of emailProtection only → `unsupported_purpose`;
    - another provider's leaf → `provider_mismatch`;
    - an unknown CA → `untrusted_issuer`.
  - An expired leaf from another provider reports `expired` (Go checks leaf dates before chain
    building). Accepted.
- Step 5 rejects a leaf with `BasicConstraints CA:TRUE` (`unsupported_purpose`). This is a defensive
  addition; no profile issues CA leaves.
- Diagnostics:
  - attached to every `Error` and to `Result`;
  - `DiagnosticID` is 16 random bytes in hex;
  - `TLS` is filled by tlsauth (Task 9);
  - `LogAttrs` is the only thing callers may log.
- `Result.Certificate.Issuer` is the issuer CN (spec struct comment). The JSON key is `issuer`.

Synthetic per-profile leaves (AC5). `TestProfilesPipeline` takes `profiles.DefaultProviders()` and,
for each of the 19 profiles:
- replaces `Anchors` with a testpki CA of the same key family (`profiles.TestAnchor`);
- for `dnie-auth`, replaces `Intermediates` with a testpki intermediate whose CDP points at the
  ARL URL;
- keeps `TestMarkers` (synthetic fingerprints never match), `PolicyOIDs`, `Identity` and
  `Revocation` as they are;
- serves the profile's real revocation hosts with `testpki.Net`, so the host allowlist is exercised
  too;
- uses the non-reserved identity `12345679S` / `X1234567L` (`JUAN` / `GARCÍA LÓPEZ`, accented on
  purpose).

Leaf shapes (from the fixtures and the digests):

| profile | key | subject (DER order) | SAN | KU / EKU | AIA OCSP / CDP |
|---|---|---|---|---|---|
| fnmt-citizen-rsa | RSA2048 | C(P)=ES, serialNumber(P)=IDCES-12345679S, GN, SN="GARCÍA LÓPEZ", CN | dirName 5734.1.4=12345679S, .1.3=LÓPEZ, .1.2=GARCÍA, .1.1=JUAN (UTF8, descending) | DS\|NR\|KE critical / clientAuth, 1.3.6.1.4.1.311.10.3.12, 1.2.840.113583.1.1.5 | http://ocspusu.cert.fnmt.es/ocspusu/OcspResponder / one DP: ldap://ldapusu.cert.fnmt.es/cn=CRLU1 + http://www.cert.fnmt.es/crlsacusu/CRLU1.crl |
| (same, bare variant) | RSA2048 | serialNumber=12345679S (May-2016 layout: C, serialNumber, SN, GN, CN) | same | same | LDAP-only CDP → OCSP only |
| fnmt-citizen-g2 | ECDSAP256 | C, serialNumber=IDCES-12345679S, GN, SN, CN | ascending .1.1…1.4 | DS\|NR / as RSA | http://ocspusug2.cert.fnmt.es/ocspusuG2/OcspResponder / http://www.cert.fnmt.es/crlacusuG2/CRL2.crl |
| aoc-idcat-g2 | RSA2048 | C=ES, OU, OU, SN, GN, serialNumber=IDCES-12345679S, CN | rfc822 only | DS\|NR\|KE / clientAuth, 1.2.840.113583.1.1.5; plus a variant with critical qcStatements | http://ocsp.catcert.cat / http://epscd.catcert.net/crl/ec-ciutadania.crl |
| aoc-idcat-g3 | ECDSAP384 | C=ES, SN, GN, serialNumber=IDCES-X1234567L, CN | — | DS\|NR / clientAuth | http://ocsp.aoc.cat / http://epscd.aoc.cat/crl/casub-a2.crl |
| accv-citizen-software-current | RSA3072 and ECDSAP256 (two runs) | C, serialNumber=12345679S, GN, SN, OU=CIUDADANOS, O=ACCV, CN | dirName CN="JUAN\|GARCÍA\|LÓPEZ", UID=12345679S | DS\|NR\|KE (RSA) / DS\|NR\|KA (ECC); clientAuth, Adobe | http://ocsp.accv.es / http://www.accv.es/gestcert/accv_rsa1_cliente.crl (302 → /fileadmin/Archivos/certificados/…) |
| digitel-citizen-sw-g1 | RSA3072 | C, serialNumber=IDCES-12345679S, SN, GN, CN | rfc822 | DS\|NR / clientAuth, emailProtection | http://ocsp.digitelts.es / crl1 + crl2 DPs |
| bewor-natural-person-sw | RSA2048 | C, SN, GN, serialNumber=IDCES-12345679S, CN | rfc822 | DS\|NR\|KE / clientAuth, emailProtection | http://ocsp1.uanataca.com/public/pki/ocsp/ + ocsp2 / crl1+crl2 bewor.crl |
| sectigo-citizen-local | RSA3072 (R35) and ECDSAP256 (E35) | C, serialNumber, SN, GN, CN | rfc822 | DS\|NR / clientAuth, emailProtection | http://ocsp.sectigo.com (no nonce; thisUpdate −3 d, nextUpdate +4 d) / http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAR35.crl |
| fnmt-representative-rsa / -g2 | RSA2048 / ECDSAP256 | C, serialNumber=IDCES-12345679S, GN, SN, CN, O=EMPRESA DEMO SL, 2.5.4.97=VATES-B00000000 | 5734.1.4=IDCES-12345679S, .1.1–.1.3 | DS\|NR\|KE / clientAuth, MS, Adobe | ocsprep(g2) / www.cert.fnmt.es/crlsrep(G2)/CRL1.crl |
| fnmt-employee-rsa / -g2 | RSA2048 / ECDSAP256 | C, serialNumber=IDCES-12345679S, GN, SN, CN, OU, O=AYUNTAMIENTO DEMO | 2.16.724.1.3.5.7.2.4=12345679S, .2.6, .2.7, .2.8, .2.3=P0000000J | DS\|NR\|KE / clientAuth, MS, Adobe, 1.3.6.1.4.1.311.20.2.2 | ocspsp(g2) / www.cert.fnmt.es/crlsp/CRL1.crl |
| firmaprofesional-personal-sw | RSA2048 / ECDSAP384 (two anchors) | C, serialNumber=IDCES-12345679S, GN, SN, CN | 13177.0.1=JUAN, .0.2=GARCÍA, .0.3=LÓPEZ | DS\|NR\|KE / clientAuth, Adobe | http://ocsp.firmaprofesional.com / http://crl.firmaprofesional.com/fpqualified.crl |
| anf-asociacion / anf-sl | RSA2048 | C, serialNumber=IDCES-12345679S, GN, SN, CN, OU | — | DS\|NR / clientAuth, emailProtection | http://ocsp.anf.es/spain/AV / http://crl.anf.es/crl/anf.crl |
| uanataca-citizen-sw | RSA2048 (one run per anchor) | C, serialNumber=IDCES-12345679S, GN, SN, CN | rfc822 | DS\|NR\|KE / clientAuth, emailProtection | ocsp1.uanataca.com / crl1.uanataca.com/public/pki/crl/CA1subordinada.crl |
| signe-personal-otros-dispositivos | RSA2048 | C, serialNumber=PNOES-X1234567L (run 1) / IDCES-12345679S (run 2), GN, SN, CN | 13177.0.1–0.3 | DS\|NR / clientAuth, Adobe | no AIA / http://www.signe.es/signe-ac/crl/signe-subca.crl |
| lleidanet-natural-person-sw | RSA4096 | C, serialNumber=IDCES-12345679S, GN, SN, CN, description, emailAddress (IA5) | — | DS\|NR / clientAuth, emailProtection | http://ocsp2.esigna.es / http://crl1.esigna.es/sub/indenova_pki_003.crl |
| dnie-auth | RSA2048 | C, serialNumber(P)=12345679S, SN=GARCÍA, GN=JOSÉ, CN="GARCÍA LÓPEZ, JOSÉ (AUTENTICACIÓN)"; SDA dateOfBirth 19800101120000Z | — | DS critical / no EKU | http://ocsp.dnie.es (good, no nextUpdate) / intermediate CDP http://pki.policia.es/dnie/crls/ARL.crl (302 → /dnie/arls/ARL.crl; critical IDP OnlyCA) |

Each run must return a `Result` with the expected profile ID, document, surnames (first/second
where the profile provides them), organization (rep/employee), birth date (DNIe), revocation method
(`crl` for SIGNE, otherwise `ocsp`), and at least one revocation attempt in diagnostics. Each OCSP
host also gets a CRL-fallback run: OCSP 503, then CRL good.

Step 1: write the failing tests:
- `checker_test.go`, `TestCheckCodes` (AC3, one row per code). Rows, with the expected code
  (verified in planning on the scratch pipeline):
  - ok;
  - expired → `expired`; not yet valid → `not_yet_valid`;
  - unknown CA → `untrusted_issuer`; another enabled provider's leaf → `provider_mismatch`;
  - no allowlisted policy → `unsupported_profile`; policy of another profile of the same provider
    → `unsupported_profile`;
  - KU without digitalSignature → `unsupported_purpose`; EKU emailProtection only →
    `unsupported_purpose`;
  - RSA-1024 → `weak_algorithm`; SHA-1 signature → `weak_algorithm`; P-224 → `weak_algorithm`;
    RSA-2048 under MinRSABits 3072 → `weak_algorithm`;
  - unknown critical extension → `invalid_chain`;
  - fingerprint marker → `test_certificate`; subject marker NOMDOS → `test_certificate`; reserved
    document → `test_certificate`; surname marker → `test_certificate`;
  - bad checksum → `identity_invalid`; `PASES-` → `identity_unsupported_document`;
  - OCSP revoked → `revoked`; OCSP unknown → `revocation_unknown`; OCSP down and no CRL →
    `revocation_unavailable` (Retryable true); context deadline → `internal` (Retryable);
  - chain of 11 → `invalid_chain`; a certificate over 16 KiB (a 17 KiB extra extension) →
    `invalid_chain`;
  - empty chain → `no_certificate`; nil leaf → `no_certificate`; unknown provider →
    `provider_mismatch`.
  Every row asserts `FailedStep`.
- `TestClientIntermediatesIgnored`:
  - chain `[leaf, subCA]`, where subCA is signed by the anchor but not pinned → `untrusted_issuer`,
    and 0 revocation requests;
  - chain `[leaf, forgedIssuer]` with the anchor's DN but an attacker key, where the OCSP server
    signs with the attacker key → never `good`. Revocation uses the verified chain[1], so the
    result is `revocation_unavailable`.
- `TestIntermediateRevocation` (DNIe shape): intermediate listed in the ARL → `revoked`; ARL down →
  `revocation_unavailable`.
- `pathmap_test.go`:
  - `TestCriticalExtensionCopy`: idCAT G2 leaf with critical qcStatements is accepted. The original
    `leaf.UnhandledCriticalExtensions` is unchanged after `Check`. The copy shares `Raw`. A copy
    with a tampered `RawTBSCertificate` fails `Verify`. Under G3 → `invalid_chain`. Malformed
    qcStatements under G2 → `invalid_chain` at step `purpose`.
  - `TestPathPriority`: IncompatibleUsage beats UnknownAuthority (two profiles); an expired anchor
    → `invalid_chain`; an expired leaf from another provider → `expired`.
- `purpose_test.go`. `TestPurposeRules`: KU absent → reject; EKU absent with RequireClientAuth →
  reject; EKU absent with AllowAbsent (DNIe) → ok; EKU only anyExtendedKeyUsage → reject; anyEKU
  plus clientAuth → ok (FNMT 2016 kit); CA:TRUE leaf → reject.
- `profiles_pipeline_test.go`. `TestProfilesPipeline`: the 19 profiles × the shapes above (AC5).
- `specimens_pipeline_test.go`. `TestSpecimensRejectedTwice` (AC5). For every committed specimen:
  clock = NotBefore+30m, registry `profiles.New` with `DefaultProviders()` at that clock, no
  revocation needed. Run 1 (production markers) and run 2 (all `TestMarkers` emptied) must give the
  manifest's expected codes. Run 1 detail: "known specimen fingerprint". Run 2 detail:
  "reserved identity: …".
- `diagnostics_test.go`:
  - `TestDiagnosticsComplete` (AC13). For every row of `TestCheckCodes`:
    - `DiagnosticID` matches `^[0-9a-f]{32}$`;
    - `Time` equals the clock;
    - `Provider`, `FailedStep`, `Code` and `TechnicalDetail` are non-empty;
    - `Certificate` is non-nil whenever a leaf was given;
    - `Chain` has one entry per received certificate;
    - `ProfileCandidates` is non-empty from step `path` on;
    - `RevocationAttempts` is non-empty at step `revocation`.
  - `TestLogAttrsNoPII`: build a success and a failure, render `LogAttrs` through
    `slog.NewJSONHandler`, and check none of the subject DN, given name, surnames, document number,
    leaf serial hex, leaf SHA-256 or OCSP URL path appears.
- `result_json_test.go`. `TestResultJSON`: marshal a `Result` and compare keys and types with the
  spec contract:
  - `provider{id,name}`, `profile{id,name,holderRole}`;
  - `identity{document{type,country,number,raw,source},givenNames,surnames,firstSurname,secondSurname,fullName,birthDate,sources}`;
  - `organization` null for natural persons;
  - `certificate{subject,issuer,serialHex,notBefore,notAfter,sha256,keyAlgorithm}`;
  - `revocation{status,method,checkedAt,thisUpdate,nextUpdate,source}`, with `nextUpdate` null when
    absent and `birthDate` null when absent;
  - `validatedAt`, `diagnostics`;
  - timestamps RFC 3339 UTC.

Run: `go test -race -count=1 ./certauth/...` → build failure.

Step 2: implement.

`certauth/types.go`:
```go
// Package certauth validates a TLS client-certificate chain against the
// pinned Spanish provider profiles and extracts the holder's typed identity.
// It is the importable entry point; see certauth/tlsauth for the HTTP/TLS glue.
package certauth

import (
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Identity and Document are the identity package's types.
type (
	Identity     = identity.Identity
	Document     = identity.Document
	Organization = identity.Organization
)

// ErrorCode is the typed failure reason shown to users.
type ErrorCode string

// Error codes (spec "Packages and public API").
const (
	CodeNoCertificate               ErrorCode = "no_certificate"
	CodeProviderMismatch            ErrorCode = "provider_mismatch"
	CodeUntrustedIssuer             ErrorCode = "untrusted_issuer"
	CodeInvalidChain                ErrorCode = "invalid_chain"
	CodeExpired                     ErrorCode = "expired"
	CodeNotYetValid                 ErrorCode = "not_yet_valid"
	CodeUnsupportedProfile          ErrorCode = "unsupported_profile"
	CodeUnsupportedPurpose          ErrorCode = "unsupported_purpose"
	CodeWeakAlgorithm               ErrorCode = "weak_algorithm"
	CodeTestCertificate             ErrorCode = "test_certificate"
	CodeIdentityInvalid             ErrorCode = "identity_invalid"
	CodeIdentityUnsupportedDocument ErrorCode = "identity_unsupported_document"
	CodeRevoked                     ErrorCode = "revoked"
	CodeRevocationUnknown           ErrorCode = "revocation_unknown"
	CodeRevocationUnavailable       ErrorCode = "revocation_unavailable"
	CodeInternal                    ErrorCode = "internal"
)

// Codes lists every ErrorCode (the server's message table must cover all).
var Codes = []ErrorCode{
	CodeNoCertificate, CodeProviderMismatch, CodeUntrustedIssuer, CodeInvalidChain, CodeExpired,
	CodeNotYetValid, CodeUnsupportedProfile, CodeUnsupportedPurpose, CodeWeakAlgorithm,
	CodeTestCertificate, CodeIdentityInvalid, CodeIdentityUnsupportedDocument, CodeRevoked,
	CodeRevocationUnknown, CodeRevocationUnavailable, CodeInternal,
}

// Retryable reports whether retrying later may succeed.
func (c ErrorCode) Retryable() bool { return c == CodeRevocationUnavailable || c == CodeInternal }

// Step is the pipeline step that failed.
type Step string

// Steps (diagnostics failedStep).
const (
	StepBounds     Step = "bounds"
	StepAlgorithms Step = "algorithms"
	StepPath       Step = "path"
	StepProfile    Step = "profile"
	StepPurpose    Step = "purpose"
	StepTestMarker Step = "test_marker"
	StepIdentity   Step = "identity"
	StepRevocation Step = "revocation"
)

// Error is the typed validation failure. Detail never contains identity data.
type Error struct {
	Code        ErrorCode
	Retryable   bool
	Detail      string
	Diagnostics Diagnostics
}

func (e *Error) Error() string { return "certauth: " + string(e.Code) + ": " + e.Detail }

// CertificateInfo describes the validated leaf.
type CertificateInfo struct {
	Subject      string    `json:"subject"` // RFC 4514
	Issuer       string    `json:"issuer"`  // issuer CN
	SerialHex    string    `json:"serialHex"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	SHA256       string    `json:"sha256"`
	KeyAlgorithm string    `json:"keyAlgorithm"` // e.g. "RSA-2048", "ECDSA-P256"
}

// RevocationInfo is the leaf's accepted revocation evidence.
type RevocationInfo struct {
	Status     revocation.Status `json:"status"` // always "good" in a Result
	Method     revocation.Method `json:"method"`
	CheckedAt  time.Time         `json:"checkedAt"`
	ThisUpdate time.Time         `json:"thisUpdate"`
	NextUpdate *time.Time        `json:"nextUpdate"`
	Source     string            `json:"source"` // host
}

// Result is a successful validation.
type Result struct {
	Provider     profiles.ProviderInfo  `json:"provider"`
	Profile      profiles.ProfileInfo   `json:"profile"`
	Identity     Identity               `json:"identity"`
	Organization *identity.Organization `json:"organization"`
	Certificate  CertificateInfo        `json:"certificate"`
	Revocation   RevocationInfo         `json:"revocation"`
	ValidatedAt  time.Time              `json:"validatedAt"`
	Diagnostics  Diagnostics            `json:"diagnostics"`
}
```

`certauth/diagnostics.go`:
```go
package certauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Diagnostics is the session-bound support report. It contains certificate
// details and is shown only to the browser that ran the transaction; use
// LogAttrs for logging.
type Diagnostics struct {
	DiagnosticID       string              `json:"diagnosticId"`
	Time               time.Time           `json:"time"`
	ServerVersion      string              `json:"serverVersion"`
	Provider           string              `json:"provider"`
	FailedStep         Step                `json:"failedStep"`
	Code               ErrorCode           `json:"code"`
	TechnicalDetail    string              `json:"technicalDetail"`
	TLS                *TLSInfo            `json:"tls"`
	Certificate        *CertificateDetails `json:"certificate"`
	Chain              []ChainEntry        `json:"chain"`
	ProfileCandidates  []CandidateResult   `json:"profileCandidates"`
	RevocationAttempts []RevocationAttempt `json:"revocationAttempts"`
}

// TLSInfo describes the handshake (filled by tlsauth).
type TLSInfo struct {
	Version                    string `json:"version"`
	CipherSuite                string `json:"cipherSuite"`
	SNI                        string `json:"sni"`
	ClientCertificatePresented bool   `json:"clientCertificatePresented"`
	ChainLength                int    `json:"chainLength"`
}

// CertificateDetails describes the presented leaf.
type CertificateDetails struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialHex          string    `json:"serialHex"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SHA256             string    `json:"sha256"`
	KeyAlgorithm       string    `json:"keyAlgorithm"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	KeyUsage           []string  `json:"keyUsage"`
	ExtKeyUsage        []string  `json:"extKeyUsage"`
	PolicyOIDs         []string  `json:"policyOids"`
	CriticalExtensions []string  `json:"criticalExtensions"`
	OCSPURLs           []string  `json:"ocspUrls"`
	CAIssuerURLs       []string  `json:"caIssuerUrls"`
	CDPURLs            []string  `json:"cdpUrls"`
}

// ChainEntry is the subject and issuer of one received certificate.
type ChainEntry struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// CandidateResult is the per-profile outcome of steps 3-4.
type CandidateResult struct {
	ProfileID string `json:"profileId"`
	Result    string `json:"result"`
}

// RevocationAttempt is revocation.Attempt in report form.
type RevocationAttempt struct {
	Method           revocation.Method `json:"method"`
	URL              string            `json:"url"`
	HTTPStatus       int               `json:"httpStatus"`
	DurationMS       int64             `json:"durationMs"`
	Outcome          revocation.Status `json:"outcome"`
	Detail           string            `json:"detail"`
	FromCache        bool              `json:"fromCache"`
	ProducedAt       *time.Time        `json:"producedAt"`
	ThisUpdate       *time.Time        `json:"thisUpdate"`
	NextUpdate       *time.Time        `json:"nextUpdate"`
	ResponderSubject string            `json:"responderSubject"`
	NonceSent        bool              `json:"nonceSent"`
	NonceEchoed      bool              `json:"nonceEchoed"`
}

// NewDiagnosticID returns 16 random bytes in hex.
func NewDiagnosticID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // since Go 1.24 crypto/rand.Read never returns an error (it crashes instead)
	return hex.EncodeToString(b)
}

// DescribeTLS builds TLSInfo from a connection state.
func DescribeTLS(cs *tls.ConnectionState) *TLSInfo {
	if cs == nil {
		return nil
	}
	return &TLSInfo{
		Version:                    tls.VersionName(cs.Version),
		CipherSuite:                tls.CipherSuiteName(cs.CipherSuite),
		SNI:                        cs.ServerName,
		ClientCertificatePresented: len(cs.PeerCertificates) > 0,
		ChainLength:                len(cs.PeerCertificates),
	}
}

func describeCertificate(c *x509.Certificate) *CertificateDetails {
	sum := sha256.Sum256(c.Raw)
	d := &CertificateDetails{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), SerialHex: fmt.Sprintf("%x", c.SerialNumber),
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, SHA256: hex.EncodeToString(sum[:]),
		KeyAlgorithm: keyAlgorithm(c), SignatureAlgorithm: c.SignatureAlgorithm.String(),
		OCSPURLs: c.OCSPServer, CAIssuerURLs: c.IssuingCertificateURL, CDPURLs: c.CRLDistributionPoints,
	}
	for bit, name := range []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"} {
		if c.KeyUsage&(1<<bit) != 0 {
			d.KeyUsage = append(d.KeyUsage, name)
		}
	}
	for _, e := range c.ExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, extKeyUsageName(e))
	}
	for _, o := range c.UnknownExtKeyUsage {
		d.ExtKeyUsage = append(d.ExtKeyUsage, o.String())
	}
	for _, p := range c.Policies {
		d.PolicyOIDs = append(d.PolicyOIDs, p.String())
	}
	for _, e := range c.Extensions {
		if e.Critical {
			d.CriticalExtensions = append(d.CriticalExtensions, e.Id.String())
		}
	}
	return d
}

func keyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	}
	return c.PublicKeyAlgorithm.String()
}

func extKeyUsageName(e x509.ExtKeyUsage) string {
	switch e {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	}
	return fmt.Sprintf("eku(%d)", e)
}

func reportAttempts(in []revocation.Attempt) []RevocationAttempt {
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return &t
	}
	out := make([]RevocationAttempt, 0, len(in))
	for _, a := range in {
		out = append(out, RevocationAttempt{
			Method: a.Method, URL: a.URL, HTTPStatus: a.HTTPStatus, DurationMS: a.Duration.Milliseconds(),
			Outcome: a.Outcome, Detail: a.Detail, FromCache: a.FromCache, ProducedAt: opt(a.ProducedAt),
			ThisUpdate: opt(a.ThisUpdate), NextUpdate: opt(a.NextUpdate), ResponderSubject: a.ResponderSubject,
			NonceSent: a.NonceSent, NonceEchoed: a.NonceEchoed,
		})
	}
	return out
}

// LogAttrs returns the non-PII fields allowed in logs: id, code, step,
// provider, candidates, issuer DN, policy OIDs, revocation host/status/
// duration, TLS version/cipher. Never subject, names, document, serial,
// leaf hash, URL paths or technicalDetail.
func (d Diagnostics) LogAttrs() []slog.Attr {
	attrs := []slog.Attr{
		slog.String("diagnosticId", d.DiagnosticID),
		slog.String("code", string(d.Code)),
		slog.String("step", string(d.FailedStep)),
		slog.String("provider", d.Provider),
	}
	var cands []string
	for _, c := range d.ProfileCandidates {
		cands = append(cands, c.ProfileID+":"+c.Result)
	}
	attrs = append(attrs, slog.Any("candidates", cands))
	if d.Certificate != nil {
		attrs = append(attrs, slog.String("issuer", d.Certificate.Issuer), slog.Any("policies", d.Certificate.PolicyOIDs))
	}
	var revs []string
	for _, a := range d.RevocationAttempts {
		host := ""
		if u, err := url.Parse(a.URL); err == nil {
			host = u.Host
		}
		revs = append(revs, fmt.Sprintf("%s %s %d %s %dms", a.Method, host, a.HTTPStatus, a.Outcome, a.DurationMS))
	}
	attrs = append(attrs, slog.Any("revocation", revs))
	if d.TLS != nil {
		attrs = append(attrs, slog.String("tlsVersion", d.TLS.Version), slog.String("cipher", d.TLS.CipherSuite))
	}
	return attrs
}
```

`certauth/checker.go`:
```go
package certauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Bounds.
const (
	DefaultMaxChainLen = 10
	MaxCertificateDER  = 16 << 10
)

var (
	oidExtKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// extensionParsers validate critical extensions a profile handles itself
// (spec step 5 exception mechanism). Every HandledCriticalExtensions entry
// must have a parser here; NewChecker enforces it.
var extensionParsers = map[string]func([]byte) error{
	"1.3.6.1.5.5.7.1.3": parseQCStatements,
}

// parseQCStatements: QCStatements ::= SEQUENCE OF SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }.
func parseQCStatements(der []byte) error {
	var stmts []struct {
		ID   asn1.ObjectIdentifier
		Info asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(der, &stmts)
	if err != nil || len(rest) != 0 || len(stmts) == 0 {
		return errors.New("malformed qcStatements")
	}
	return nil
}

// Options configures a Checker.
type Options struct {
	Registry    *profiles.Registry  // required
	Revocation  *revocation.Checker // required
	Now         func() time.Time    // nil = time.Now
	MaxChainLen int                 // 0 = 10
	Version     string              // reported as diagnostics serverVersion
}

// Checker runs the validation pipeline. Safe for concurrent use.
type Checker struct {
	reg     *profiles.Registry
	rev     *revocation.Checker
	now     func() time.Time
	maxLen  int
	version string
}

// NewChecker validates options.
func NewChecker(o Options) (*Checker, error) {
	if o.Registry == nil || o.Revocation == nil {
		return nil, errors.New("certauth: Registry and Revocation are required")
	}
	for _, p := range o.Registry.Providers() {
		for _, prof := range p.Profiles {
			for _, oid := range prof.HandledCriticalExtensions {
				if _, ok := extensionParsers[oid]; !ok {
					return nil, fmt.Errorf("certauth: profile %s handles %s without a parser", prof.ID, oid)
				}
			}
		}
	}
	c := &Checker{reg: o.Registry, rev: o.Revocation, now: o.Now, maxLen: o.MaxChainLen, version: o.Version}
	if c.now == nil {
		c.now = time.Now
	}
	if c.maxLen <= 0 {
		c.maxLen = DefaultMaxChainLen
	}
	return c, nil
}

// Providers returns the enabled providers in display order.
func (c *Checker) Providers() []profiles.Provider { return c.reg.Providers() }

// ClientCAs returns the CA pool advertised for a provider.
func (c *Checker) ClientCAs(providerID string) (*x509.CertPool, error) {
	return c.reg.ClientCAs(providerID)
}

// run carries one Check invocation.
type run struct {
	c     *Checker
	now   time.Time
	diag  Diagnostics
	chain []*x509.Certificate
}

func (r *run) fail(step Step, code ErrorCode, detail string) *Error {
	r.diag.FailedStep, r.diag.Code, r.diag.TechnicalDetail = step, code, detail
	return &Error{Code: code, Retryable: code.Retryable(), Detail: detail, Diagnostics: r.diag}
}

type candidate struct {
	e     *profiles.Enabled
	chain []*x509.Certificate
	err   error
}

// Check validates chain (as received: chain[0] is the leaf) for providerID.
// The returned error is always *Error.
func (c *Checker) Check(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error) {
	r := &run{c: c, now: c.now(), chain: chain}
	r.diag = Diagnostics{DiagnosticID: NewDiagnosticID(), Time: r.now.UTC(), ServerVersion: c.version, Provider: providerID}
	for _, cert := range chain {
		if cert != nil {
			r.diag.Chain = append(r.diag.Chain, ChainEntry{Subject: cert.Subject.String(), Issuer: cert.Issuer.String()})
		}
	}

	// 1. Bounds.
	prov, ok := c.reg.Provider(providerID)
	if !ok {
		return nil, r.fail(StepBounds, CodeProviderMismatch, "unknown provider")
	}
	if len(chain) == 0 || chain[0] == nil {
		return nil, r.fail(StepBounds, CodeNoCertificate, "no client certificate")
	}
	if len(chain) > c.maxLen {
		return nil, r.fail(StepBounds, CodeInvalidChain, fmt.Sprintf("chain length %d exceeds %d", len(chain), c.maxLen))
	}
	for i, cert := range chain {
		if cert == nil || len(cert.Raw) > MaxCertificateDER {
			return nil, r.fail(StepBounds, CodeInvalidChain, fmt.Sprintf("certificate %d missing or larger than %d bytes", i, MaxCertificateDER))
		}
	}
	leaf := chain[0]
	r.diag.Certificate = describeCertificate(leaf)

	// 2. Algorithms (before path building: Go reports a SHA-1 leaf signature as UnknownAuthorityError).
	if detail, ok := algorithmsOK(leaf, 2048); !ok {
		return nil, r.fail(StepAlgorithms, CodeWeakAlgorithm, detail)
	}

	// 3. Path, per enabled profile, with pinned roots and pinned intermediates only.
	var cands []candidate
	for _, e := range c.reg.Enabled(providerID) {
		chains, err := leafForProfile(leaf, e.Profile).Verify(verifyOptions(e.Roots, e.Inter, r.now))
		cand := candidate{e: e, err: err}
		if err == nil {
			cand.chain = chains[0]
		}
		cands = append(cands, cand)
	}
	var verified []candidate
	for _, cand := range cands {
		res := "path ok"
		if cand.err != nil {
			res = cand.err.Error()
		} else {
			verified = append(verified, cand)
		}
		r.diag.ProfileCandidates = append(r.diag.ProfileCandidates, CandidateResult{ProfileID: cand.e.Profile.ID, Result: res})
	}
	if len(verified) == 0 {
		code, detail := c.mapPathErrors(leaf, cands, r.now)
		return nil, r.fail(StepPath, code, detail)
	}

	// 4. Profile: exactly one verified profile whose exact OID the leaf asserts.
	var leafPolicies []string
	for _, p := range leaf.Policies {
		leafPolicies = append(leafPolicies, p.String())
	}
	var matched []candidate
	for _, cand := range verified {
		if slices.ContainsFunc(cand.e.Profile.PolicyOIDs, func(o string) bool { return slices.Contains(leafPolicies, o) }) {
			matched = append(matched, cand)
		}
	}
	switch len(matched) {
	case 0:
		var want []string
		for _, cand := range verified {
			want = append(want, cand.e.Profile.PolicyOIDs...)
		}
		return nil, r.fail(StepProfile, CodeUnsupportedProfile, fmt.Sprintf("policy OIDs present %v; expected one of %v", leafPolicies, want))
	case 1:
	default:
		return nil, r.fail(StepProfile, CodeInternal, "more than one profile matches (registry bug)")
	}
	m := matched[0]
	prof := m.e.Profile
	for i := range r.diag.ProfileCandidates {
		if r.diag.ProfileCandidates[i].ProfileID == prof.ID {
			r.diag.ProfileCandidates[i].Result = "path ok; policy match"
		}
	}
	if detail, ok := algorithmsOK(leaf, prof.Algorithms.MinRSABits); !ok {
		return nil, r.fail(StepAlgorithms, CodeWeakAlgorithm, detail)
	}

	// 5. Purpose.
	if detail, ok := purposeOK(leaf, prof); !ok {
		return nil, r.fail(StepPurpose, CodeUnsupportedPurpose, detail)
	}
	for _, oid := range prof.HandledCriticalExtensions {
		for _, ext := range leaf.Extensions {
			if ext.Id.String() == oid && ext.Critical {
				if err := extensionParsers[oid](ext.Value); err != nil {
					return nil, r.fail(StepPurpose, CodeInvalidChain, fmt.Sprintf("handled critical extension %s: %v", oid, err))
				}
			}
		}
	}

	// 6. Test certificates: fingerprint or documented subject marker combination.
	sum := sha256.Sum256(leaf.Raw)
	if m.e.IsFingerprintMarker(hex.EncodeToString(sum[:])) {
		return nil, r.fail(StepTestMarker, CodeTestCertificate, "known specimen fingerprint")
	}
	if subjectMarkerMatch(leaf, prof.TestMarkers) {
		return nil, r.fail(StepTestMarker, CodeTestCertificate, "documented test subject marker")
	}

	// 7. Identity.
	x, err := prof.Identity.Extract(leaf)
	switch {
	case errors.Is(err, identity.ErrUnsupportedDocument):
		return nil, r.fail(StepIdentity, CodeIdentityUnsupportedDocument, err.Error())
	case errors.Is(err, identity.ErrInvalid):
		return nil, r.fail(StepIdentity, CodeIdentityInvalid, err.Error())
	case err != nil:
		return nil, r.fail(StepIdentity, CodeInternal, err.Error())
	}
	// 7b. Reserved identities and name markers.
	if kind, hit := c.reg.Reserved().Match(x); hit {
		return nil, r.fail(StepTestMarker, CodeTestCertificate, "reserved identity: "+string(kind))
	}

	// 8. Revocation of chain[i] by chain[i+1], leaf first; anchors are governed by D1.
	var leafRev revocation.Result
	for i := 0; i < len(m.chain)-1; i++ {
		res, err := c.rev.Check(ctx, m.chain[i], m.chain[i+1], prof.Revocation)
		if err != nil {
			return nil, r.fail(StepRevocation, CodeInternal, err.Error())
		}
		r.diag.RevocationAttempts = append(r.diag.RevocationAttempts, reportAttempts(res.Attempts)...)
		if code, bad := revocationCode(res.Status); bad {
			if ctx.Err() != nil {
				return nil, r.fail(StepRevocation, CodeInternal, "validation deadline exceeded")
			}
			return nil, r.fail(StepRevocation, code, res.Detail)
		}
		if i == 0 {
			leafRev = res
		}
	}

	// 9. Result.
	var next *time.Time
	if !leafRev.NextUpdate.IsZero() {
		next = &leafRev.NextUpdate
	}
	return &Result{
		Provider:     profiles.ProviderInfo{ID: prov.ID, Name: prov.Name},
		Profile:      profiles.ProfileInfo{ID: prof.ID, Name: prof.Name, HolderRole: prof.HolderRole},
		Identity:     x.Identity,
		Organization: x.Organization,
		Certificate: CertificateInfo{
			Subject: leaf.Subject.String(), Issuer: leaf.Issuer.CommonName, SerialHex: fmt.Sprintf("%x", leaf.SerialNumber),
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, SHA256: hex.EncodeToString(sum[:]), KeyAlgorithm: keyAlgorithm(leaf),
		},
		Revocation: RevocationInfo{Status: leafRev.Status, Method: leafRev.Method, CheckedAt: leafRev.CheckedAt,
			ThisUpdate: leafRev.ThisUpdate, NextUpdate: next, Source: leafRev.Source},
		ValidatedAt: r.now.UTC(),
		Diagnostics: r.diag,
	}, nil
}

func verifyOptions(roots, inter *x509.CertPool, now time.Time) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

// leafForProfile returns the leaf, or a shallow copy whose
// UnhandledCriticalExtensions omits the profile's handled OIDs. Only that
// slice differs: Raw and RawTBSCertificate (the signature input) are shared.
func leafForProfile(leaf *x509.Certificate, p profiles.Profile) *x509.Certificate {
	if len(p.HandledCriticalExtensions) == 0 || len(leaf.UnhandledCriticalExtensions) == 0 {
		return leaf
	}
	cp := *leaf
	cp.UnhandledCriticalExtensions = nil
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !slices.Contains(p.HandledCriticalExtensions, oid.String()) {
			cp.UnhandledCriticalExtensions = append(cp.UnhandledCriticalExtensions, oid)
		}
	}
	return &cp
}

// pathRank orders candidate failures: a lower rank is more specific.
const (
	rankUsage = iota + 1
	rankExpired
	rankCritical
	rankUnknownAuthority
	rankOther
)

// mapPathErrors maps the candidates' x509 errors to one code. Priority:
// IncompatibleUsage > Expired > UnhandledCriticalExtension (when the leaf
// otherwise chains to that profile) > UnknownAuthority > other.
func (c *Checker) mapPathErrors(leaf *x509.Certificate, cands []candidate, now time.Time) (ErrorCode, string) {
	best, bestRank, detail := CodeInvalidChain, rankOther+1, ""
	consider := func(rank int, code ErrorCode, d string) {
		if rank < bestRank {
			best, bestRank, detail = code, rank, d
		}
	}
	for _, cand := range cands {
		err := cand.err
		if ucErr, ok := errors.AsType[x509.UnhandledCriticalExtension](err); ok {
			// Go rejects unhandled critical extensions before building chains, so
			// learn whether this profile's anchor issued the leaf (code choice only).
			stripped := *leaf
			stripped.UnhandledCriticalExtensions = nil
			_, err2 := stripped.Verify(verifyOptions(cand.e.Roots, cand.e.Inter, now))
			if _, unknown := errors.AsType[x509.UnknownAuthorityError](err2); unknown {
				err = err2
			} else {
				consider(rankCritical, CodeInvalidChain, fmt.Sprintf("%v %v", ucErr, leaf.UnhandledCriticalExtensions))
				continue
			}
		}
		if cie, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
			switch cie.Reason {
			case x509.IncompatibleUsage:
				consider(rankUsage, CodeUnsupportedPurpose, err.Error())
			case x509.Expired:
				switch {
				case now.Before(leaf.NotBefore):
					consider(rankExpired, CodeNotYetValid, err.Error())
				case now.After(leaf.NotAfter):
					consider(rankExpired, CodeExpired, err.Error())
				default:
					consider(rankExpired, CodeInvalidChain, "anchor or intermediate outside validity: "+err.Error())
				}
			default:
				consider(rankOther, CodeInvalidChain, err.Error())
			}
			continue
		}
		if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
			consider(rankUnknownAuthority, c.unknownAuthorityCode(leaf, now), err.Error())
			continue
		}
		consider(rankOther, CodeInvalidChain, fmt.Sprint(err))
	}
	return best, detail
}

// unknownAuthorityCode: provider_mismatch when the leaf verifies against the
// union of every enabled provider's pinned CAs, else untrusted_issuer.
func (c *Checker) unknownAuthorityCode(leaf *x509.Certificate, now time.Time) ErrorCode {
	roots, inter := c.reg.AllAnchors()
	probe := *leaf
	probe.UnhandledCriticalExtensions = nil // classification only, never acceptance
	_, err := probe.Verify(verifyOptions(roots, inter, now))
	if _, unknown := errors.AsType[x509.UnknownAuthorityError](err); err != nil && unknown {
		return CodeUntrustedIssuer
	}
	return CodeProviderMismatch
}

// algorithmsOK: RSA ≥ minRSA (floor 2048) or ECDSA P-256/P-384/P-521, and a
// SHA-256-or-stronger leaf signature.
func algorithmsOK(leaf *x509.Certificate, minRSA int) (string, bool) {
	minRSA = max(minRSA, 2048)
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSA {
			return fmt.Sprintf("RSA key %d bits; minimum %d", k.N.BitLen(), minRSA), false
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return "ECDSA curve " + k.Curve.Params().Name + " not allowed", false
		}
	default:
		return "key algorithm " + leaf.PublicKeyAlgorithm.String() + " not allowed", false
	}
	switch leaf.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return "", true
	}
	return "signature algorithm " + leaf.SignatureAlgorithm.String() + " not allowed", false
}

func hasExtension(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(c.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(oid) })
}

// purposeOK applies the profile's KU and EKU rules; a CA leaf is rejected.
func purposeOK(leaf *x509.Certificate, p profiles.Profile) (string, bool) {
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return "leaf is a CA certificate", false
	}
	if hasExtension(leaf, oidExtKeyUsage) {
		if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return "KeyUsage lacks digitalSignature", false
		}
	} else if !p.KeyUsage.AllowAbsent {
		return "KeyUsage extension absent", false
	}
	hasEKU := hasExtension(leaf, oidExtExtKeyUsage)
	clientAuth := slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	switch p.EKU {
	case profiles.EKURequireClientAuth:
		if !hasEKU || !clientAuth {
			return "ExtendedKeyUsage must be present and list clientAuth", false
		}
	case profiles.EKUAllowAbsent:
		if hasEKU && !clientAuth {
			return "ExtendedKeyUsage present without clientAuth", false
		}
	default:
		return "profile EKU rule unset", false
	}
	return "", true
}

func subjectMarkerMatch(leaf *x509.Certificate, markers []profiles.TestMarker) bool {
	for _, m := range markers {
		if len(m.Subject) == 0 {
			continue
		}
		name, err := identity.ParseName(leaf.RawSubject)
		if err != nil {
			return false
		}
		all := true
		for _, want := range m.Subject {
			v, ok, err := name.Field(want.OID, identity.KindSet{identity.KindUTF8, identity.KindPrintable, identity.KindBMP, identity.KindTeletex})
			if err != nil || !ok || !strings.EqualFold(identity.NormalizeName(v), identity.NormalizeName(want.Value)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// revocationCode maps a final revocation status; bad is false only for good.
func revocationCode(s revocation.Status) (ErrorCode, bool) {
	switch s {
	case revocation.StatusGood:
		return "", false
	case revocation.StatusRevoked:
		return CodeRevoked, true
	case revocation.StatusUnknown:
		return CodeRevocationUnknown, true
	}
	return CodeRevocationUnavailable, true // unavailable, stale, invalid_evidence, unsupported_method
}
```

Run: `go test -race -count=1 ./certauth/...` → `ok` for `certauth`, `certauth/identity`,
`certauth/profiles` and `certauth/revocation`. Then the Global Constraints checks, plus
`go list -deps ./certauth/... | grep -E 'cert-check/(internal|web)'` printing nothing (AC12).

Step 3: commit
`git commit -m "feat(certauth): add validation pipeline with typed errors and diagnostics" -- certauth/types.go certauth/diagnostics.go certauth/checker.go certauth/checker_test.go certauth/pathmap_test.go certauth/purpose_test.go certauth/profiles_pipeline_test.go certauth/specimens_pipeline_test.go certauth/diagnostics_test.go certauth/result_json_test.go`

Interfaces this task provides to later tasks:
- checker: `certauth.Checker` (`NewChecker(Options)`, `Providers`, `ClientCAs`,
  `Check(ctx, providerID, chain) (*Result, error)` where the error is always `*Error`), `Options`
  (including `Version`);
- results: `Result`, `CertificateInfo`, `RevocationInfo`, aliases `Identity`/`Document`/`Organization`;
- errors: `Error`, `ErrorCode` + `Codes`, `Step`;
- diagnostics: `Diagnostics` (`LogAttrs`), `TLSInfo`, `DescribeTLS`, `NewDiagnosticID`,
  `CertificateDetails`, `ChainEntry`, `CandidateResult`, `RevocationAttempt`.


### Task 8: `internal/config` and `internal/acme`
Model: sonnet   Repo: /home/p4u/certificate_poc/cert-check
Files: `internal/config/{config.go,config_test.go}`, `internal/acme/{acme.go,acme_test.go}`.

Goal: spec "Configuration" (validated environment, no secret logged) and "Certificates for the auth
host". Covers DNS-01 only, LE production or staging, storage under the data dir, optional
`OverrideDomain`, and a static certificate alternative. Supports AC10 and the "ACME failure at
boot" row: the process stays up and not ready, and retries with backoff.

Behaviour notes:
- `Load(getenv)` reports every problem at once (`errors.Join`). Error texts name variables and
  never values. `Secret` redacts itself in `%v`, `%s` and slog.
- `CERTCHECK_AUTH_PUBLIC_PORT` defaults to `$RAILWAY_TCP_PROXY_PORT` and is required (it builds
  `authUrl`).
- `CERTCHECK_PUBLIC_URL` must be an https origin. Plain http is allowed only for
  `localhost`/`127.0.0.1` (local runs and the e2e test).
- ACME:
  - `certmagic.New` with its own cache (no globals);
  - `FileStorage{Path: <data>/certmagic}`;
  - OCSP stapling disabled (LE no longer serves OCSP);
  - `ACMEIssuer` with `DisableHTTPChallenge`, `DisableTLSALPNChallenge`, and `DNS01Solver` backed by
    `libdns/cloudflare.Provider{APIToken}`, which makes DNS-01 the only solver;
  - `ManageSync` makes one interactive attempt without internal retries (certmagic
    `config.go:611`), so `Run` retries with backoff 1m, 5m, 15m, 30m, 1h. That stays under Let's
    Encrypt's 5 failed validations per hostname per hour.
- libdns/cloudflare v0.2.2 needs the single token to have **Zone:Read and Zone.DNS:Edit**
  (`README.md` of the module). Record this in the README (Task 13) and in the deploy step.
- certmagic logs through its own zap default logger. Importing zap would be a new direct dependency,
  so it is not done. certmagic log lines carry only domain names.

Step 1: write the failing tests:
- `config_test.go`:
  - `TestLoadDefaults`: minimal ACME env → Port 8080, AuthListen `:8443`, DataDir `/data`, ACMECA
    production, hops 1, LogLevel info, CertMode ACME.
  - `TestLoadErrors` table:
    - missing PUBLIC_URL; `http://example.org`; a URL with a path/query/fragment/userinfo;
    - AUTH_DOMAIN `Auth.Example.org` / `x` / empty;
    - port 0 / 70000 / `abc`;
    - auth port missing with no `RAILWAY_TCP_PROXY_PORT`;
    - static cert without key;
    - static plus ACME settings;
    - ACME without email or token;
    - bad override domain;
    - `CERTCHECK_ACME_CA=prod`; `CERTCHECK_AUTH_TLS13=yes`; hops −1 or 11; log level `trace`.
    Each error message names the variable. None contains the token value (set it to
    `tok-SECRET-123` and assert its absence).
  - `TestLoadRailwayPort`: auth port taken from `RAILWAY_TCP_PROXY_PORT`; the explicit variable
    wins.
  - `TestLoadStatic`: cert and key files → CertStatic.
  - `TestLoadLocalhostHTTP`: `http://127.0.0.1:8080` accepted.
  - `TestSecretRedaction`: `fmt.Sprint`, `%v`, `%+v` of the Config, and slog JSON, never show the
    token; `Reveal` returns it.
- `acme_test.go` (package `acme`, internal test; never calls Let's Encrypt):
  - `TestNewACMEValidation`: missing fields → error.
  - `TestNewACMEConfig`. Inspect `m.cfg.Issuers[0].(*certmagic.ACMEIssuer)`:
    - CA is the production URL by default and the staging URL with `Staging`;
    - `DisableHTTPChallenge` and `DisableTLSALPNChallenge` are true;
    - `DNS01Solver` is a `*certmagic.DNS01Solver` whose `DNSProvider` is a `*cloudflare.Provider`
      with the token, and whose `OverrideDomain` is passed through;
    - storage is `*certmagic.FileStorage` at `<dir>/certmagic`;
    - stapling is disabled;
    - the name is `*.<AuthDomain>`.
  - `TestRunRetriesWithBackoff`: `m.manage` fails twice then succeeds, with `m.backoff` = 1ms. Want
    3 calls, `Ready()` true, and nil returned.
  - `TestRunStopsOnCancel`: always failing, ctx cancelled → returns `context.Canceled`, `Ready()`
    false.
  - `TestStatic`:
    - `NewStatic(testpki.ServerTLS(...))` → `GetCertificate` returns it and `Ready()` is true;
    - an expired static leaf → `Ready()` false;
    - `LoadStatic` with files written to `t.TempDir()` → ok; a bad file → error.

Run: `go test -race -count=1 ./internal/config/... ./internal/acme/...` → build failure.

Step 2: implement.

`internal/config/config.go`:
```go
// Package config loads and validates the environment configuration.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Secret holds a sensitive value; it never prints or logs its content.
type Secret string

// String redacts the value.
func (Secret) String() string { return "[redacted]" }

// LogValue redacts the value in slog.
func (Secret) LogValue() slog.Value { return slog.StringValue("[redacted]") }

// Reveal returns the raw value (only for the Cloudflare client).
func (s Secret) Reveal() string { return string(s) }

// ACMECA selects the Let's Encrypt directory.
type ACMECA string

// ACME CAs.
const (
	ACMEProduction ACMECA = "production"
	ACMEStaging    ACMECA = "staging"
)

// CertMode is how the auth listener gets its certificate.
type CertMode int

// Certificate modes.
const (
	CertACME CertMode = iota + 1
	CertStatic
)

// Config is the validated configuration (spec "Configuration").
type Config struct {
	Port                  int      // PORT, default 8080
	PublicURL             *url.URL // CERTCHECK_PUBLIC_URL, required; https (http only for localhost/127.0.0.1)
	AuthDomain            string   // CERTCHECK_AUTH_DOMAIN, required, lowercase DNS name
	AuthPublicPort        int      // CERTCHECK_AUTH_PUBLIC_PORT, default $RAILWAY_TCP_PROXY_PORT; required
	AuthListen            string   // CERTCHECK_AUTH_LISTEN, default ":8443"
	DataDir               string   // CERTCHECK_DATA_DIR, default "/data"
	CertMode              CertMode
	ACMEEmail             string // CERTCHECK_ACME_EMAIL, required with ACME
	ACMECA                ACMECA // CERTCHECK_ACME_CA, default production
	CloudflareToken       Secret // CLOUDFLARE_API_TOKEN, required with ACME
	ACMEDNSOverrideDomain string // CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN, optional
	TLSCertFile           string // CERTCHECK_TLS_CERT_FILE (static mode, with _KEY_FILE)
	TLSKeyFile            string // CERTCHECK_TLS_KEY_FILE
	AuthTLS13             bool   // CERTCHECK_AUTH_TLS13, default false
	TrustedProxyHops      int    // CERTCHECK_TRUSTED_PROXY_HOPS, default 1, >= 0
	LogLevel              slog.Level
}

var dnsNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Load reads the configuration through getenv (os.Getenv in main). All
// problems are reported together; no secret value appears in errors.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	c := Config{AuthListen: ":8443", DataDir: "/data", ACMECA: ACMEProduction, TrustedProxyHops: 1, LogLevel: slog.LevelInfo}
	intVar := func(name, def string, min, max int, dst *int) {
		v := getenv(name)
		if v == "" {
			v = def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Errorf("%s must be an integer in [%d,%d]", name, min, max))
			return
		}
		*dst = n
	}
	intVar("PORT", "8080", 1, 65535, &c.Port)
	intVar("CERTCHECK_AUTH_PUBLIC_PORT", getenv("RAILWAY_TCP_PROXY_PORT"), 1, 65535, &c.AuthPublicPort)
	intVar("CERTCHECK_TRUSTED_PROXY_HOPS", "1", 0, 10, &c.TrustedProxyHops)

	if u, err := url.Parse(getenv("CERTCHECK_PUBLIC_URL")); err != nil || u.Host == "" || u.Path != "" && u.Path != "/" ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		!(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		errs = append(errs, errors.New("CERTCHECK_PUBLIC_URL must be an https origin (http only for localhost)"))
	} else {
		u.Path = ""
		c.PublicURL = u
	}
	c.AuthDomain = getenv("CERTCHECK_AUTH_DOMAIN")
	if !dnsNameRe.MatchString(c.AuthDomain) {
		errs = append(errs, errors.New("CERTCHECK_AUTH_DOMAIN must be a lowercase DNS name"))
	}
	if v := getenv("CERTCHECK_AUTH_LISTEN"); v != "" {
		c.AuthListen = v
	}
	if v := getenv("CERTCHECK_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	c.TLSCertFile, c.TLSKeyFile = getenv("CERTCHECK_TLS_CERT_FILE"), getenv("CERTCHECK_TLS_KEY_FILE")
	c.ACMEEmail, c.CloudflareToken = getenv("CERTCHECK_ACME_EMAIL"), Secret(getenv("CLOUDFLARE_API_TOKEN"))
	c.ACMEDNSOverrideDomain = getenv("CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN")
	switch {
	case c.TLSCertFile != "" || c.TLSKeyFile != "":
		c.CertMode = CertStatic
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			errs = append(errs, errors.New("CERTCHECK_TLS_CERT_FILE and CERTCHECK_TLS_KEY_FILE go together"))
		}
		if c.ACMEEmail != "" || c.CloudflareToken != "" || c.ACMEDNSOverrideDomain != "" {
			errs = append(errs, errors.New("static certificate files are mutually exclusive with ACME settings"))
		}
	default:
		c.CertMode = CertACME
		if c.ACMEEmail == "" || !strings.Contains(c.ACMEEmail, "@") {
			errs = append(errs, errors.New("CERTCHECK_ACME_EMAIL is required with ACME"))
		}
		if c.CloudflareToken == "" {
			errs = append(errs, errors.New("CLOUDFLARE_API_TOKEN is required with ACME"))
		}
		if d := c.ACMEDNSOverrideDomain; d != "" && !dnsNameRe.MatchString(strings.TrimPrefix(d, "_acme-challenge.")) {
			errs = append(errs, errors.New("CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN must be a DNS name"))
		}
	}
	switch v := ACMECA(getenv("CERTCHECK_ACME_CA")); v {
	case "":
	case ACMEProduction, ACMEStaging:
		c.ACMECA = v
	default:
		errs = append(errs, errors.New("CERTCHECK_ACME_CA must be production or staging"))
	}
	switch v := getenv("CERTCHECK_AUTH_TLS13"); v {
	case "", "false":
	case "true":
		c.AuthTLS13 = true
	default:
		errs = append(errs, errors.New("CERTCHECK_AUTH_TLS13 must be true or false"))
	}
	if v := getenv("CERTCHECK_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, errors.New("CERTCHECK_LOG_LEVEL must be debug, info, warn or error"))
		}
	}
	return c, errors.Join(errs...)
}
```

`internal/acme/acme.go`:
```go
// Package acme provides the auth listener's certificate: certmagic with the
// Cloudflare DNS-01 solver only (HTTP-01 and TLS-ALPN-01 disabled), storage
// under the data directory, or a static certificate for local runs and tests.
package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// Options configures the ACME manager.
type Options struct {
	AuthDomain      string // certificate name is "*.<AuthDomain>"
	DataDir         string // storage at <DataDir>/certmagic
	Email           string
	Staging         bool
	CloudflareToken string
	OverrideDomain  string // optional DNS-01 CNAME delegation target
	Logger          *slog.Logger
}

// Manager serves the auth certificate and reports readiness.
type Manager struct {
	name   string
	cfg    *certmagic.Config // nil in static mode
	cache  *certmagic.Cache
	static *tls.Certificate
	ready  atomic.Bool
	log    *slog.Logger
	// manage performs one obtain/load attempt (cfg.ManageSync); tests replace it.
	manage  func(context.Context, []string) error
	backoff []time.Duration
}

// NewACME builds a certmagic-backed manager. Call Start before serving.
func NewACME(o Options) (*Manager, error) {
	if o.AuthDomain == "" || o.DataDir == "" || o.Email == "" || o.CloudflareToken == "" {
		return nil, errors.New("acme: AuthDomain, DataDir, Email and CloudflareToken are required")
	}
	m := &Manager{name: "*." + o.AuthDomain, log: o.Logger}
	if m.log == nil {
		m.log = slog.Default()
	}
	var cfg *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return cfg, nil },
	})
	cfg = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: filepath.Join(o.DataDir, "certmagic")},
		OCSP:    certmagic.OCSPConfig{DisableStapling: true},
	})
	ca := certmagic.LetsEncryptProductionCA
	if o.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}
	issuer := certmagic.NewACMEIssuer(cfg, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   o.Email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider:    &cloudflare.Provider{APIToken: o.CloudflareToken},
			OverrideDomain: o.OverrideDomain,
		}},
	})
	cfg.Issuers = []certmagic.Issuer{issuer}
	m.cfg, m.cache, m.manage, m.backoff = cfg, cache, cfg.ManageSync, obtainBackoff
	return m, nil
}

// NewStatic serves a fixed certificate (CERTCHECK_TLS_CERT_FILE/_KEY_FILE or tests).
func NewStatic(cert tls.Certificate) *Manager {
	m := &Manager{static: &cert, log: slog.Default()}
	m.ready.Store(true)
	return m
}

// LoadStatic reads a PEM certificate chain and key.
func LoadStatic(certFile, keyFile string) (*Manager, error) {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("acme: static certificate: %w", err)
	}
	return NewStatic(c), nil
}

// Backoff between failed obtain attempts (Let's Encrypt allows 5 failed
// validations per hostname per hour; the process stays up and not ready).
var obtainBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

// Run obtains (or loads from storage) the certificate, retrying with backoff
// until it succeeds or ctx ends; certmagic then renews in the background.
// It returns nil once the certificate is ready (static mode: immediately).
func (m *Manager) Run(ctx context.Context) error {
	if m.cfg == nil {
		return nil
	}
	for i := 0; ; i++ {
		err := m.manage(ctx, []string{m.name}) // ManageSync: one interactive attempt, no internal retries
		if err == nil {
			m.ready.Store(true)
			m.log.Info("auth certificate ready", "name", m.name)
			return nil
		}
		wait := m.backoff[min(i, len(m.backoff)-1)]
		m.log.Error("auth certificate not obtained; retrying", "name", m.name, "error", err.Error(), "retryIn", wait.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// GetCertificate is the tls.Config hook.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.static != nil {
		return m.static, nil
	}
	return m.cfg.GetCertificate(hello)
}

// Ready reports whether a currently valid certificate is loaded.
func (m *Manager) Ready() bool {
	if !m.ready.Load() {
		return false
	}
	if m.static != nil {
		return m.static.Leaf == nil || time.Now().Before(m.static.Leaf.NotAfter)
	}
	for _, c := range m.cache.AllMatchingCertificates("readyz" + m.name[1:]) {
		if c.Leaf != nil && time.Now().Before(c.Leaf.NotAfter) {
			return true
		}
	}
	return false
}
```

Run: `go test -race -count=1 ./internal/config/... ./internal/acme/...` → two `ok` lines, then the
Global Constraints checks.

Step 3: commit
`git commit -m "feat(config): add validated environment config and dns-01 acme manager" -- internal/config internal/acme`

Interfaces this task provides to later tasks:
- config: `config.Config`, `config.Load`, `config.Secret` (`Reveal`), `config.CertMode`
  (`CertACME`/`CertStatic`), `config.ACMECA`;
- acme: `acme.Options`, `acme.NewACME`, `acme.NewStatic`, `acme.LoadStatic`, and `*acme.Manager`
  (`Run(ctx) error`, `GetCertificate`, `Ready`).


### Task 9: `certauth/tlsauth`, transaction store, HTTP helpers
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `certauth/tlsauth/{tlsauth.go,tlsauth_test.go}`;
- `internal/server/{txstore.go,txstore_test.go,http.go,http_test.go}`.

Goal: spec "TLS on the auth listener" (per-SNI config, `RequestClientCert`, `ClientCAs`, TLS 1.2
default, tickets off, http/1.1 only, unknown SNI fails the handshake, Host≠SNI → 421) and Goal 6
(the handler-like unit a CSP imports). Also spec "Authentication flow" and "Main listener":
- one-use state and code;
- the code is bound to the cookie, compared in constant time;
- 5-minute lifetime, capacity 10 000, janitor every 30 s;
- secrets stored only as SHA-256 hashes;
- cookie attributes, POST guards, rightmost-XFF client IP, per-IP limits.
Feeds AC6 and AC7.

Behaviour notes:
- `ServerConfig` builds every per-provider `tls.Config` once. `GetConfigForClient` does an exact,
  lowercased SNI lookup. An error from it makes Go send `internal_error` and abort the handshake.
- `Authenticate` resolves the provider only from `r.TLS.ServerName`, reads only
  `r.TLS.PeerCertificates`, re-runs the full pipeline on every request, and attaches `TLSInfo` to
  the diagnostics.
- Store semantics:
  - `ConsumeState` spends the state on every outcome, including the wrong-provider case.
  - `Redeem` spends the code on every attempt. On success the transaction is deleted. On a cookie
    mismatch the transaction stays, without a code, until the janitor removes it.
  - `Create` deletes the transaction named by the request's previous cookie.
  - Map lookups by SHA-256 of a 256-bit secret are not timing-sensitive. The cookie-to-transaction
    binding uses `subtle.ConstantTimeCompare`.
- The cookie is `__Host-certcheck_tx=<v>; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax`.
  Clearing sends `Max-Age=0`.
- Client IP: the rightmost `X-Forwarded-For` entry selected by `CERTCHECK_TRUSTED_PROXY_HOPS`
  (default 1). The leftmost entry is never trusted. With no header, or hops=0, it is the TCP peer.
  The header Railway actually sets is confirmed at rollout (Merge and release, step D9).

Step 1: write the failing tests:
- `tlsauth_test.go`. Build a Checker from a testpki registry with two providers, `alpha` and
  `beta`, under the auth domain `auth.test`:
  - `TestServerConfigPerProvider`. For `alpha.auth.test` and `ALPHA.Auth.Test`, the returned config
    has:
    - `ClientAuth == tls.RequestClientCert`;
    - `ClientCAs` equal to `checker.ClientCAs("alpha")` (compare the certificate sets);
    - `MinVersion`/`MaxVersion` both TLS 1.2;
    - `SessionTicketsDisabled`;
    - `NextProtos == ["http/1.1"]`;
    - the 6 suites and curves X25519/P-256/P-384;
    - `GetCertificate` set.
  - `TestServerConfigTLS13`: `AllowTLS13` → MaxVersion TLS 1.3.
  - `TestUnknownSNIRejected`: a real handshake over `net.Pipe` with SNI `gamma.auth.test`, and with
    no SNI, fails on both sides. The client error mentions `internal error`. A warn log carries the
    SNI.
  - `TestHandshakeAdvertisesProviderCAs`: the client's `GetClientCertificate` sees
    `AcceptableCAs` equal to alpha's anchor subjects only.
  - `TestNoResumptionNoH2`: the client offers `h2,http/1.1` with a `ClientSessionCache`. Two
    handshakes give `NegotiatedProtocol == "http/1.1"` and the second has `DidResume == false`.
  - `TestRequestClientCertOptional`: a handshake without a client certificate succeeds.
    `Authenticate` → `no_certificate`, with `Diagnostics.TLS.ClientCertificatePresented == false`.
  - `TestAuthenticateSuccessAndTLSInfo`: a valid testpki leaf through a real TLS server
    (`httptest.NewUnstartedServer` plus our config) → Result with TLS version `TLS 1.2` and the
    SNI recorded.
  - `TestAuthenticateRunsEveryRequest`: two requests on one keep-alive connection give two
    distinct `DiagnosticID`s.
  - `TestProvider` table: `alpha.auth.test` ok; `x.alpha.auth.test`, `auth.test`,
    `alpha.auth.test.evil` → false.
  - `TestCheckHost` table:
    - `alpha.auth.test:8443` vs SNI `alpha.auth.test` → nil;
    - case-insensitive → nil;
    - `beta.auth.test` → `ErrMisdirected`;
    - empty Host → `ErrMisdirected`;
    - `r.TLS == nil` → `ErrMisdirected`.
- `txstore_test.go` (injected clock):
  - `TestStoreFlow`: Create → ConsumeState → Complete → Redeem returns the outcome; Current goes
    pending → completed → none.
  - `TestStateReplay`; `TestStateWrongProvider` (consumed: the retry on the right provider fails);
    `TestStateExpired` (5m+1s).
  - `TestCodeReplay`.
  - `TestRedeemWrongCookie` (code spent; a retry with the right cookie fails);
    `TestRedeemMissingCookie`; `TestRedeemExpired`.
  - `TestCompleteAfterExpiry` → `ErrExpired`.
  - `TestCapacity`: 10 000 live → `ErrStoreFull`. After the clock passes expiry, Create sweeps and
    succeeds.
  - `TestCreateReplacesPrevious`.
  - `TestJanitor` with a short interval.
  - `TestMalformedSecrets`: wrong length, non-base64url, padding → invalid, no panic.
  - `TestNoRawSecretsRetained`: reflect over the Store. Map keys are `[32]byte`. No string field or
    key equals or contains a raw secret.
  - `TestSecretFormat`: 43 chars, base64url, 1 000 distinct.
  - `TestStoreConcurrent`: parallel flows under `-race`.
- `http_test.go`:
  - `TestTxCookie`: the exact `Set-Cookie` header string for set and clear.
  - `TestMainHeaders`: the exact CSP string, Referrer-Policy, nosniff, HSTS; `no-store` only on
    `/api/`.
  - `TestAuthHeaders`.
  - `TestPostGuard` table:
    - no Content-Type, `text/plain`, `application/json; charset=utf-8` (ok);
    - Sec-Fetch-Site `cross-site` and `same-site` → 403; `same-origin` and `none` → ok;
    - Origin mismatch → 403; Origin equal → ok; absent → ok.
  - `TestDecodeJSON`: unknown field, trailing data, 1025 bytes, wrong type → false.
  - `TestClientIP` table:
    - no XFF → RemoteAddr;
    - hops 1 with `1.1.1.1, 2.2.2.2` → `2.2.2.2`;
    - two headers;
    - hops 2 → `1.1.1.1`;
    - hops 3 with 2 entries → RemoteAddr;
    - invalid entry → RemoteAddr;
    - hops 0 → RemoteAddr;
    - IPv6 and `::ffff:` unmapping.
  - `TestIPLimiter`: 20 allowed, the 21st refused with `retryAfter` in (0, 3s]; another IP is
    independent; after 3s of fake time one more is allowed; pruning keeps the map bounded.

Run: `go test -race -count=1 ./certauth/tlsauth/... ./internal/server/...` → build failure.

Step 2: implement.

`certauth/tlsauth/tlsauth.go`:
```go
// Package tlsauth is the handler-like integration a CSP imports: a per-SNI
// tls.Config that requests client certificates with the provider's CA list,
// and Handler.Authenticate, which validates the peer chain of a request.
package tlsauth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/vocdoni/cert-check/certauth"
)

// ErrMisdirected: the request Host differs from the TLS SNI (answer 421).
var ErrMisdirected = errors.New("tlsauth: Host does not match the TLS server name")

// ConfigOptions configures ServerConfig.
type ConfigOptions struct {
	Checker        *certauth.Checker
	AuthDomain     string // e.g. "auth.cert-check.vocdoni.dev"; provider hosts are "<id>.<AuthDomain>"
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	AllowTLS13     bool         // CERTCHECK_AUTH_TLS13 (deviation D2); default TLS 1.2 only
	Logger         *slog.Logger // handshake-level warnings; nil = slog.Default()
}

var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// ServerConfig returns the auth listener's tls.Config. Its
// GetConfigForClient selects the provider config by exact, lowercased SNI
// "<id>.<AuthDomain>"; an unknown SNI is a handshake error (internal_error
// alert), so nothing is served without a provider.
func ServerConfig(o ConfigOptions) (*tls.Config, error) {
	if o.Checker == nil || o.GetCertificate == nil || o.AuthDomain == "" {
		return nil, errors.New("tlsauth: Checker, GetCertificate and AuthDomain are required")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	maxVersion := uint16(tls.VersionTLS12)
	if o.AllowTLS13 {
		maxVersion = tls.VersionTLS13
	}
	domain := strings.ToLower(o.AuthDomain)
	perSNI := map[string]*tls.Config{}
	for _, p := range o.Checker.Providers() {
		pool, err := o.Checker.ClientCAs(p.ID)
		if err != nil {
			return nil, err
		}
		perSNI[p.ID+"."+domain] = &tls.Config{
			MinVersion:             tls.VersionTLS12,
			MaxVersion:             maxVersion,
			CipherSuites:           tls12Suites,
			CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
			ClientAuth:             tls.RequestClientCert,
			ClientCAs:              pool,
			SessionTicketsDisabled: true,
			NextProtos:             []string{"http/1.1"},
			GetCertificate:         o.GetCertificate,
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := strings.ToLower(hello.ServerName)
			cfg, ok := perSNI[sni]
			if !ok {
				log.Warn("auth handshake rejected: unknown SNI", "sni", sni)
				return nil, fmt.Errorf("tlsauth: unknown server name %q", sni)
			}
			return cfg, nil
		},
	}, nil
}

// Handler validates the client certificate of requests served on the auth listener.
type Handler struct {
	checker *certauth.Checker
	suffix  string // "." + AuthDomain
}

// NewHandler returns a Handler for authDomain.
func NewHandler(c *certauth.Checker, authDomain string) *Handler {
	return &Handler{checker: c, suffix: "." + strings.ToLower(authDomain)}
}

// Provider returns the provider ID encoded in a TLS server name.
func (h *Handler) Provider(serverName string) (string, bool) {
	id, ok := strings.CutSuffix(strings.ToLower(serverName), h.suffix)
	if !ok || id == "" || strings.Contains(id, ".") {
		return "", false
	}
	return id, true
}

// CheckHost returns ErrMisdirected when r.Host (port stripped, lowercased)
// differs from r.TLS.ServerName.
func CheckHost(r *http.Request) error {
	if r.TLS == nil {
		return ErrMisdirected
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || !strings.EqualFold(host, r.TLS.ServerName) {
		return ErrMisdirected
	}
	return nil
}

// Authenticate validates r.TLS.PeerCertificates for the provider named by
// r.TLS.ServerName. Every call re-runs the full pipeline. The error is
// *certauth.Error (diagnostics include the TLS details).
func (h *Handler) Authenticate(r *http.Request) (*certauth.Result, error) {
	if r.TLS == nil {
		return nil, &certauth.Error{Code: certauth.CodeInternal, Retryable: true, Detail: "request without TLS state"}
	}
	providerID, _ := h.Provider(r.TLS.ServerName)
	res, err := h.checker.Check(r.Context(), providerID, r.TLS.PeerCertificates)
	tlsInfo := certauth.DescribeTLS(r.TLS)
	if err != nil {
		if e, ok := errors.AsType[*certauth.Error](err); ok {
			e.Diagnostics.TLS = tlsInfo
		}
		return nil, err
	}
	res.Diagnostics.TLS = tlsInfo
	return res, nil
}
```

`internal/server/txstore.go`:
```go
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/vocdoni/cert-check/certauth"
)

// Store limits (spec "Main listener", transaction store).
const (
	TxLifetime      = 5 * time.Minute
	TxCapacity      = 10_000
	JanitorInterval = 30 * time.Second
	secretBytes     = 32
)

// Store errors. Callers never reveal which one happened to the client.
var (
	ErrStoreFull    = errors.New("txstore: full")
	ErrInvalidState = errors.New("txstore: state unknown, expired, used or for another provider")
	ErrInvalidCode  = errors.New("txstore: code unknown or expired")
	ErrCookie       = errors.New("txstore: cookie missing or does not match")
	ErrExpired      = errors.New("txstore: transaction expired")
)

// Secret is a 32-byte random value, base64url without padding (43 chars).
type Secret string

// NewSecret returns a fresh secret from crypto/rand.
func NewSecret() Secret {
	b := make([]byte, secretBytes)
	_, _ = rand.Read(b) // never fails since Go 1.24 (crashes instead)
	return Secret(base64.RawURLEncoding.EncodeToString(b))
}

// hash returns SHA-256 of the decoded secret; ok is false for malformed input.
func (s Secret) hash() (h [32]byte, ok bool) {
	b, err := base64.RawURLEncoding.DecodeString(string(s))
	if err != nil || len(b) != secretBytes {
		return h, false
	}
	return sha256.Sum256(b), true
}

// TxStatus is the externally visible transaction status.
type TxStatus string

// Statuses for GET /api/v1/transactions/current.
const (
	TxPending   TxStatus = "pending"
	TxCompleted TxStatus = "completed"
	TxNone      TxStatus = "none"
)

// Outcome is the stored validation outcome: exactly one of Result, Err.
type Outcome struct {
	Result *certauth.Result
	Err    *certauth.Error
}

// TxRef identifies a transaction whose state was consumed (input to Complete).
type TxRef struct{ id [32]byte }

// Snapshot is the cookie-bound view of a transaction.
type Snapshot struct {
	Status    TxStatus
	Provider  string
	CreatedAt time.Time
}

type tx struct {
	id        [32]byte // = cookie hash
	provider  string
	createdAt time.Time
	expiresAt time.Time
	stateHash [32]byte
	stateUsed bool
	codeHash  [32]byte
	hasCode   bool
	completed bool
	outcome   Outcome
}

// Store is the in-memory transaction store. Secrets are never retained:
// maps are keyed by SHA-256 of the decoded secret.
type Store struct {
	mu       sync.Mutex
	byCookie map[[32]byte]*tx
	byState  map[[32]byte]*tx
	byCode   map[[32]byte]*tx
	capacity int
	now      func() time.Time
}

// NewStore returns an empty store. now is the clock (nil = time.Now).
func NewStore(capacity int, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	if capacity <= 0 {
		capacity = TxCapacity
	}
	return &Store{byCookie: map[[32]byte]*tx{}, byState: map[[32]byte]*tx{}, byCode: map[[32]byte]*tx{},
		capacity: capacity, now: now}
}

// Create starts a transaction for provider. prev, when it names an existing
// transaction (the request's old cookie), is deleted first.
func (s *Store) Create(provider string, prev Secret) (cookie, state Secret, expiresAt time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if h, ok := prev.hash(); ok {
		if old, found := s.byCookie[h]; found {
			s.deleteLocked(old)
		}
	}
	if len(s.byCookie) >= s.capacity {
		s.sweepLocked(now)
		if len(s.byCookie) >= s.capacity {
			return "", "", time.Time{}, ErrStoreFull
		}
	}
	cookie, state = NewSecret(), NewSecret()
	ch, _ := cookie.hash()
	sh, _ := state.hash()
	t := &tx{id: ch, provider: provider, createdAt: now, expiresAt: now.Add(TxLifetime), stateHash: sh}
	s.byCookie[ch], s.byState[sh] = t, t
	return cookie, state, t.expiresAt, nil
}

// ConsumeState atomically consumes state. It must exist, be unexpired and
// unused, and belong to provider; the state is spent on every outcome.
func (s *Store) ConsumeState(state Secret, provider string) (TxRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := state.hash()
	if !ok {
		return TxRef{}, ErrInvalidState
	}
	t, found := s.byState[h]
	if !found {
		return TxRef{}, ErrInvalidState
	}
	delete(s.byState, h)
	if t.stateUsed || !s.now().Before(t.expiresAt) || t.provider != provider {
		t.stateUsed = true
		return TxRef{}, ErrInvalidState
	}
	t.stateUsed = true
	return TxRef{id: t.id}, nil
}

// Complete stores the outcome and issues the one-use code.
func (s *Store) Complete(ref TxRef, o Outcome) (Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, found := s.byCookie[ref.id]
	if !found || !s.now().Before(t.expiresAt) {
		return "", ErrExpired
	}
	if t.completed || !t.stateUsed {
		return "", ErrInvalidState
	}
	code := NewSecret()
	h, _ := code.hash()
	t.codeHash, t.hasCode, t.completed, t.outcome = h, true, true, o
	s.byCode[h] = t
	return code, nil
}

// Redeem atomically consumes code and returns the outcome when the code's
// transaction is the cookie's transaction (constant-time comparison of the
// hashes). The code is spent on every attempt; on success the transaction is
// deleted.
func (s *Store) Redeem(code, cookie Secret) (Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := code.hash()
	if !ok {
		return Outcome{}, ErrInvalidCode
	}
	t, found := s.byCode[h]
	if !found {
		return Outcome{}, ErrInvalidCode
	}
	delete(s.byCode, h)
	t.hasCode = false
	if !s.now().Before(t.expiresAt) {
		s.deleteLocked(t)
		return Outcome{}, ErrInvalidCode
	}
	ch, ok := cookie.hash()
	if !ok || subtle.ConstantTimeCompare(ch[:], t.id[:]) != 1 {
		return Outcome{}, ErrCookie
	}
	o := t.outcome
	s.deleteLocked(t)
	return o, nil
}

// Current returns the cookie's transaction status.
func (s *Store) Current(cookie Secret) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := cookie.hash()
	if !ok {
		return Snapshot{Status: TxNone}
	}
	t, found := s.byCookie[h]
	if !found || !s.now().Before(t.expiresAt) {
		return Snapshot{Status: TxNone}
	}
	st := TxPending
	if t.completed {
		st = TxCompleted
	}
	return Snapshot{Status: st, Provider: t.provider, CreatedAt: t.createdAt}
}

// Len returns the number of live transactions.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byCookie)
}

// RunJanitor removes expired transactions every interval until ctx ends.
func (s *Store) RunJanitor(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			s.sweepLocked(s.now())
			s.mu.Unlock()
		}
	}
}

func (s *Store) sweepLocked(now time.Time) {
	for _, t := range s.byCookie {
		if !now.Before(t.expiresAt) {
			s.deleteLocked(t)
		}
	}
}

func (s *Store) deleteLocked(t *tx) {
	delete(s.byCookie, t.id)
	if !t.stateUsed {
		delete(s.byState, t.stateHash)
	}
	if t.hasCode {
		delete(s.byCode, t.codeHash)
	}
}
```

`internal/server/http.go`:
```go
package server

import (
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// CookieName is the transaction cookie (host-only, Secure, HttpOnly).
const CookieName = "__Host-certcheck_tx"

const (
	mainCSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	authCSP   = "default-src 'none'; frame-ancestors 'none'"
	maxBody   = 1 << 10
	hstsValue = "max-age=31536000"
)

// setTxCookie sets the transaction cookie: Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300.
func setTxCookie(w http.ResponseWriter, v Secret) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: string(v), Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(TxLifetime / time.Second)})
}

// clearTxCookie expires the cookie (Max-Age=0).
func clearTxCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func txCookie(r *http.Request) (Secret, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return Secret(c.Value), true
}

// mainHeaders sets the security headers on every main-listener response.
func mainHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", mainCSP)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", hstsValue)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// authHeaders sets the auth-listener headers (redirects and 404s alike).
func authHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", authCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", hstsValue)
	h.Set("Cache-Control", "no-store")
}

// postGuard enforces Content-Type: application/json (415) and, when present,
// Sec-Fetch-Site in {same-origin, none} and Origin == publicOrigin (403).
func postGuard(r *http.Request, publicOrigin string) (status int, code string) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return http.StatusUnsupportedMediaType, "unsupported_media_type"
	}
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return http.StatusForbidden, "forbidden"
	}
	if o := r.Header.Get("Origin"); o != "" && o != publicOrigin {
		return http.StatusForbidden, "forbidden"
	}
	return 0, ""
}

// decodeJSON reads at most 1 KiB into dst, rejecting unknown fields and trailing data.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || dec.More() {
		return false
	}
	return true
}

// clientIP returns the rightmost X-Forwarded-For entry selected by
// trustedHops (1 = the entry appended by the edge). The leftmost entry is
// never trusted. Without the header (or hops == 0) it is the TCP peer.
func clientIP(r *http.Request, trustedHops int) netip.Addr {
	remote := func() netip.Addr {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return netip.Addr{}
		}
		a, _ := netip.ParseAddr(host)
		return a.Unmap()
	}
	values := r.Header.Values("X-Forwarded-For")
	if trustedHops == 0 || len(values) == 0 {
		return remote()
	}
	var entries []string
	for _, v := range values {
		for e := range strings.SplitSeq(v, ",") {
			entries = append(entries, strings.TrimSpace(e))
		}
	}
	i := len(entries) - trustedHops
	if i < 0 {
		return remote()
	}
	a, err := netip.ParseAddr(entries[i])
	if err != nil {
		return remote()
	}
	return a.Unmap()
}

// ipLimiter is a per-IP token bucket with bounded memory.
type ipLimiter struct {
	mu      sync.Mutex
	perMin  int
	entries map[netip.Addr]*ipEntry
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

const maxLimiterEntries = 100_000

func newIPLimiter(perMinute int) *ipLimiter {
	return &ipLimiter{perMin: perMinute, entries: map[netip.Addr]*ipEntry{}}
}

// allow reports whether ip may proceed; when not, retryAfter is the wait.
func (l *ipLimiter) allow(ip netip.Addr, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, found := l.entries[ip]
	if !found {
		if len(l.entries) >= maxLimiterEntries {
			l.pruneLocked(now)
		}
		e = &ipEntry{lim: rate.NewLimiter(rate.Every(time.Minute/time.Duration(l.perMin)), l.perMin)}
		l.entries[ip] = e
	}
	e.seen = now
	res := e.lim.ReserveN(now, 1)
	if d := res.DelayFrom(now); d > 0 {
		res.CancelAt(now)
		return false, d
	}
	return true, 0
}

func (l *ipLimiter) pruneLocked(now time.Time) {
	for ip, e := range l.entries {
		if now.Sub(e.seen) > 10*time.Minute {
			delete(l.entries, ip)
		}
	}
}
```

Run: `go test -race -count=1 ./certauth/tlsauth/... ./internal/server/...` → two `ok` lines, then
the Global Constraints checks.

Step 3: commit
`git commit -m "feat(tlsauth): add per-sni tls config, transaction store and http guards" -- certauth/tlsauth internal/server/txstore.go internal/server/txstore_test.go internal/server/http.go internal/server/http_test.go`

Interfaces this task provides to later tasks:
- tlsauth: `ConfigOptions`, `ServerConfig`, `Handler` (`NewHandler`, `Provider`, `Authenticate`),
  `CheckHost`, `ErrMisdirected`;
- store: `server.Store` (`NewStore`, `Create`, `ConsumeState`, `Complete`, `Redeem`, `Current`,
  `Len`, `RunJanitor`), `Secret`/`NewSecret`, `Outcome`, `TxRef`, `Snapshot`, `TxStatus`, the
  `Err*` values, `TxLifetime`, `TxCapacity`, `JanitorInterval`;
- HTTP helpers: `CookieName`, `setTxCookie`, `clearTxCookie`, `txCookie`, `mainHeaders`,
  `authHeaders`, `postGuard`, `decodeJSON`, `clientIP`, `newIPLimiter`.


### Task 10: main and auth handlers, App wiring, `cmd/cert-check`
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `internal/server/{auth.go,api.go,app.go}`;
- `internal/server/{auth_test.go,api_test.go,app_test.go}`;
- `cmd/cert-check/{main.go,main_test.go}`.

Goal: the spec's main and auth listeners end to end (routes table, JSON contract, error statuses,
headers, health/readiness, auth 303 redirects, connection cap, validation slots and budget,
graceful shutdown). Also the process wiring. Feeds AC6, AC7, AC10 and AC13.

Behaviour notes:
- Auth listener:
  - Only `GET /v1/authenticate`; anything else → 404 with an empty body.
  - Host≠SNI → 421.
  - An unknown, expired, used or wrong-provider state → `303 <publicURL>/#error=invalid_state&diag=<id>`.
    A warn log line carries the diag ID, SNI and reason.
  - Otherwise: validate in a slot (32 slots, 10 s wait) with a 40 s budget detached from client
    disconnects, store the outcome, then `303 <publicURL>/#code=<code>`. The base is the configured
    origin, never the request. One info line per outcome uses `LogAttrs` only.
- Main listener:
  - routes as in the spec table, served behind `mainHeaders`;
  - the static UI comes from `web.FS()` with directory listings disabled (`noDirFS`);
  - POST guards, then the per-IP limit (20 creations, 60 redeems per minute), then a strict JSON
    decode;
  - the redeem error bodies follow the spec exactly, with minimal diagnostics on the 400 path;
  - the message table covers every `certauth.Codes` entry plus the server codes.
- Readiness: `/readyz` is 200 only when the main listener is serving, the auth listener is serving
  with a ready certificate, and at least one provider is enabled.
  - `Run` serves the main listener at once.
  - The auth listener starts when `CertSource.Ready()` turns true.
  - `cmd/cert-check` runs `acme.Manager.Run` in a goroutine, so a failed first issuance leaves the
    process up and 503 (spec failure-modes row) instead of crash-looping into Let's Encrypt limits.
- At debug level, `handleCreate` logs the names of the client-address headers present
  (`X-Forwarded-For`, `X-Real-IP`, `X-Envoy-External-Address`, `Forwarded`) and the XFF entry count,
  never values. Rollout step D10 uses it to confirm which header the Railway edge sets.
- Handshake errors reach slog at warn through `http.Server.ErrorLog`. Unknown SNI is logged with
  the SNI by tlsauth. For other handshake failures the SNI is not available at that layer; the log
  carries the error text only.

Step 1: write the failing tests:
- `api_test.go` (`httptest` against `App.MainHandler()`; Checker over a testpki registry):
  - `TestProvidersEndpoint`: order, `beta` flag, description; `Cache-Control: no-store`; the
    headers.
  - `TestCreate`:
    - 201;
    - `authUrl == https://alpha.auth.test:<port>/v1/authenticate?state=<43 chars>`;
    - `expiresAt` RFC 3339 UTC = now+5m;
    - the `Set-Cookie` attributes;
    - the store holds 1 transaction.
  - `TestCreateErrors`:
    - 415 without JSON Content-Type;
    - 403 `Sec-Fetch-Site: cross-site`;
    - 403 Origin mismatch;
    - 400 `unknown_provider`;
    - 400 malformed, unknown field, > 1 KiB;
    - 429 `rate_limited` with `Retry-After` on the 21st request from one IP, and the next IP still
      allowed;
    - 503 `store_full` with capacity forced to 1.
    Every body is `{"status":"error","error":{"code","message","retryable"}}`.
  - `TestRedeem`:
    - success with the cookie → 200 `{"status":"success","result":…}` with the identity, and the
      cookie is cleared (`Max-Age=0`);
    - validation error → 200 `{"status":"error","error":{…},"diagnostics":{…}}`;
    - no cookie → 400 with `technicalDetail` `cookie_missing`;
    - another valid cookie → `cookie_mismatch`;
    - unknown or replayed code → `code_unknown_or_expired`.
    The 400 bodies hold no identity value (search the body for the test DNI and names).
  - `TestCurrent`: none / pending / completed with `authHost` and `authPort`.
  - `TestHealthReady`: `/healthz` 200 always; `/readyz` 503 until both listeners run and the cert is
    ready, then 200 (use a fake `CertSource` with a toggle).
  - `TestStaticUI`: `GET /` → 200 HTML with the CSP header; `GET /fonts/` → 404 (no listing).
  - `TestMessagesCoverAllCodes`: every `certauth.Codes` entry and every server code has a non-empty
    message.
  - `TestForwardedHeadersDebugLog`: at debug level, one line lists the present header names and
    `xffEntries`. No IP value appears. At info level, no line.
- `auth_test.go` (a real TLS listener via `App.Run` on 127.0.0.1:0; client SNI `alpha.auth.test`):
  - `TestAuthNotFound`: `/`, `/favicon.ico`, `POST /v1/authenticate` → 404, empty body, CSP
    `default-src 'none'; frame-ancestors 'none'`, Referrer-Policy, nosniff, HSTS, no-store.
  - `TestAuthMisdirected`: Host `beta.auth.test` over SNI `alpha` → 421.
  - `TestAuthInvalidState`: missing, unknown, duplicated `state` parameter → 303 to
    `…/#error=invalid_state&diag=` plus 32 hex. The log line has the same diag ID and the SNI, and
    neither the state value nor the query.
  - `TestAuthSuccessRedirect`: 303 to `<publicURL>/#code=<43 chars>`. The store transaction is
    completed.
  - `TestAuthSlotsExhausted`: slots channel pre-filled, `slotWait` 10ms → the stored outcome is
    `internal`, retryable.
  - `TestAuthBudget`: OCSP server `Slow(1s)`, budget 100ms, no CRL → stored `internal` (deadline);
    the 303 is still sent.
  - `TestLimitListener`: with max 2, a third TCP connection is closed before any TLS byte, and
    capacity returns after a close.
  - `TestAuthServerHTTP11Only`: `newAuthServer(...).TLSNextProto` is non-nil and empty; the client
    sees `http/1.1`.
- `app_test.go`:
  - `TestRunShutdown`: cancelling the ctx makes `Run` return nil within 2 s; the listeners are
    closed.
  - `TestRunAuthWaitsForCert`: with `Ready()` false, the auth port accepts TCP but no handshake is
    served (client times out within 200 ms). After `Ready()` turns true the handshake succeeds.
- `main_test.go`. `TestRunConfigError`: `run(getenv)` with only `CLOUDFLARE_API_TOKEN=tok-SECRET-123`
  set returns an error naming `CERTCHECK_PUBLIC_URL`, `CERTCHECK_AUTH_DOMAIN` and
  `CERTCHECK_AUTH_PUBLIC_PORT`, and not containing the token.

Run: `go test -race -count=1 ./internal/server/... ./cmd/...` → build failure.

Step 2: implement.

`internal/server/auth.go`:
```go
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/tlsauth"
)

// Auth listener limits (spec "TLS on the auth listener", "Rate limiting").
const (
	AuthMaxConns         = 512
	ValidationSlots      = 32
	ValidationSlotWait   = 10 * time.Second
	ValidationBudget     = 40 * time.Second
	authenticatePath     = "/v1/authenticate"
	fragmentInvalidState = "/#error=invalid_state&diag="
)

// authHandler serves only GET /v1/authenticate on the auth listener.
type authHandler struct {
	store     *Store
	tls       *tlsauth.Handler
	publicURL string // fixed origin, never taken from the request
	slots     chan struct{}
	slotWait  time.Duration // ValidationSlotWait; tests shorten it
	budget    time.Duration // ValidationBudget; tests shorten it
	log       *slog.Logger
	version   string
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	if r.Method != http.MethodGet || r.URL.Path != authenticatePath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := tlsauth.CheckHost(r); err != nil {
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	provider, ok := a.tls.Provider(r.TLS.ServerName)
	states := r.URL.Query()["state"]
	var ref TxRef
	err := ErrInvalidState
	if ok && len(states) == 1 {
		ref, err = a.store.ConsumeState(Secret(states[0]), provider)
	}
	if err != nil {
		diag := certauth.NewDiagnosticID()
		a.log.Warn("auth state rejected", "diagnosticId", diag, "sni", r.TLS.ServerName, "reason", err.Error())
		http.Redirect(w, r, a.publicURL+fragmentInvalidState+diag, http.StatusSeeOther)
		return
	}

	outcome := a.validate(r)
	code, err := a.store.Complete(ref, outcome)
	if err != nil {
		diag := certauth.NewDiagnosticID()
		a.log.Warn("auth transaction expired during validation", "diagnosticId", diag, "sni", r.TLS.ServerName)
		http.Redirect(w, r, a.publicURL+fragmentInvalidState+diag, http.StatusSeeOther)
		return
	}
	a.logOutcome(outcome)
	http.Redirect(w, r, a.publicURL+"/#code="+string(code), http.StatusSeeOther)
}

// validate runs the checker in a bounded slot with a 40 s budget detached
// from client disconnects; a missed slot or the budget yields internal (retryable).
func (a *authHandler) validate(r *http.Request) Outcome {
	internal := func(detail string) Outcome {
		e := &certauth.Error{Code: certauth.CodeInternal, Retryable: true, Detail: detail}
		e.Diagnostics = certauth.Diagnostics{DiagnosticID: certauth.NewDiagnosticID(), Time: time.Now().UTC(),
			ServerVersion: a.version, Code: certauth.CodeInternal, TechnicalDetail: detail, TLS: certauth.DescribeTLS(r.TLS)}
		if p, ok := a.tls.Provider(r.TLS.ServerName); ok {
			e.Diagnostics.Provider = p
		}
		return Outcome{Err: e}
	}
	wait := time.NewTimer(a.slotWait)
	defer wait.Stop()
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	case <-wait.C:
		return internal("validation capacity exhausted")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), a.budget)
	defer cancel()
	res, err := a.tls.Authenticate(r.WithContext(ctx))
	if err != nil {
		if e, ok := errors.AsType[*certauth.Error](err); ok {
			return Outcome{Err: e}
		}
		return internal("unexpected validation error")
	}
	return Outcome{Result: res}
}

// logOutcome writes one line with non-PII fields only.
func (a *authHandler) logOutcome(o Outcome) {
	if o.Err != nil {
		a.log.LogAttrs(context.Background(), slog.LevelInfo, "authentication failed", o.Err.Diagnostics.LogAttrs()...)
		return
	}
	d := o.Result.Diagnostics
	attrs := append(d.LogAttrs(), slog.String("profile", o.Result.Profile.ID), slog.String("revocationMethod", string(o.Result.Revocation.Method)))
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "authentication succeeded", attrs...)
}

// limitListener closes connections beyond max before the TLS handshake.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, max int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, max)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
		default:
			_ = c.Close() // over capacity: drop before the handshake
		}
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// newAuthServer returns the auth http.Server: HTTP/1.1 only (empty
// TLSNextProto), spec timeouts, handshake errors logged at warn.
func newAuthServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}
```

`internal/server/api.go`:
```go
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/certauth"
)

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type providerJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Beta        bool   `json:"beta"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client went away; nothing to do
}

func writeError(w http.ResponseWriter, status int, code string, retryable bool) {
	writeJSON(w, status, map[string]any{"status": "error", "error": apiError{Code: code, Message: message(code), Retryable: retryable}})
}

// handleProviders: GET /api/v1/providers.
func (a *App) handleProviders(w http.ResponseWriter, _ *http.Request) {
	var out []providerJSON
	for _, p := range a.checker.Providers() {
		out = append(out, providerJSON{ID: p.ID, Name: p.Name, Description: p.Description, Beta: p.Beta})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreate: POST /api/v1/transactions {"provider":"<id>"}.
func (a *App) handleCreate(w http.ResponseWriter, r *http.Request) {
	if st, code := postGuard(r, a.publicOrigin); st != 0 {
		writeError(w, st, code, false)
		return
	}
	logForwardedHeaders(r, a.log)
	if ok, wait := a.createLimiter.allow(clientIP(r, a.cfg.TrustedProxyHops), a.now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", true)
		return
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if !decodeJSON(w, r, &body) {
		writeError(w, http.StatusBadRequest, "bad_request", false)
		return
	}
	if _, err := a.checker.ClientCAs(body.Provider); err != nil {
		writeError(w, http.StatusBadRequest, "unknown_provider", false)
		return
	}
	prev, _ := txCookie(r)
	cookie, state, expires, err := a.store.Create(body.Provider, prev)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_full", true)
		return
	}
	setTxCookie(w, cookie)
	authURL := "https://" + body.Provider + "." + a.cfg.AuthDomain + ":" + strconv.Itoa(a.cfg.AuthPublicPort) +
		"/v1/authenticate?state=" + string(state)
	writeJSON(w, http.StatusCreated, map[string]string{"authUrl": authURL, "expiresAt": expires.UTC().Format(time.RFC3339)})
}

// handleRedeem: POST /api/v1/transactions/redeem {"code":"…"} with the cookie.
func (a *App) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if st, code := postGuard(r, a.publicOrigin); st != 0 {
		writeError(w, st, code, false)
		return
	}
	if ok, wait := a.redeemLimiter.allow(clientIP(r, a.cfg.TrustedProxyHops), a.now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeError(w, http.StatusTooManyRequests, "rate_limited", true)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &body) {
		writeError(w, http.StatusBadRequest, "bad_request", false)
		return
	}
	invalid := func(technical string) {
		diag := certauth.Diagnostics{DiagnosticID: certauth.NewDiagnosticID(), Time: a.now().UTC(), ServerVersion: a.version,
			Code: "invalid_or_expired", TechnicalDetail: technical}
		a.log.Info("redeem rejected", "diagnosticId", diag.DiagnosticID, "reason", technical)
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error",
			"error": apiError{Code: "invalid_or_expired", Message: message("invalid_or_expired")}, "diagnostics": diag})
	}
	cookie, ok := txCookie(r)
	if !ok {
		invalid("cookie_missing")
		return
	}
	o, err := a.store.Redeem(Secret(body.Code), cookie)
	switch {
	case errors.Is(err, ErrCookie):
		invalid("cookie_mismatch")
		return
	case err != nil:
		invalid("code_unknown_or_expired")
		return
	}
	clearTxCookie(w)
	if o.Err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error",
			"error":       apiError{Code: string(o.Err.Code), Message: message(string(o.Err.Code)), Retryable: o.Err.Retryable},
			"diagnostics": o.Err.Diagnostics})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "result": o.Result})
}

// handleCurrent: GET /api/v1/transactions/current (cookie-bound).
func (a *App) handleCurrent(w http.ResponseWriter, r *http.Request) {
	snap := Snapshot{Status: TxNone}
	if c, ok := txCookie(r); ok {
		snap = a.store.Current(c)
	}
	out := map[string]any{"status": snap.Status, "provider": snap.Provider, "createdAt": nil,
		"authHost": "", "authPort": a.cfg.AuthPublicPort}
	if snap.Status != TxNone {
		out["createdAt"] = snap.CreatedAt.UTC().Format(time.RFC3339)
		out["authHost"] = snap.Provider + "." + a.cfg.AuthDomain
	}
	writeJSON(w, http.StatusOK, out)
}

// message is the single code → English message table.
func message(code string) string {
	if m, ok := messages[code]; ok {
		return m
	}
	return messages["internal"]
}

var messages = map[string]string{
	string(certauth.CodeNoCertificate):               "No certificate was presented.",
	string(certauth.CodeProviderMismatch):            "The certificate belongs to a different provider than the one selected.",
	string(certauth.CodeUntrustedIssuer):             "The certificate was not issued by a supported certification authority.",
	string(certauth.CodeInvalidChain):                "The certificate chain could not be validated.",
	string(certauth.CodeExpired):                     "The certificate has expired.",
	string(certauth.CodeNotYetValid):                 "The certificate is not valid yet.",
	string(certauth.CodeUnsupportedProfile):          "This type of certificate is not supported.",
	string(certauth.CodeUnsupportedPurpose):          "The certificate cannot be used for authentication.",
	string(certauth.CodeWeakAlgorithm):               "The certificate uses a key or signature algorithm that is too weak.",
	string(certauth.CodeTestCertificate):             "This is a test or specimen certificate.",
	string(certauth.CodeIdentityInvalid):             "The identity data in the certificate is not valid.",
	string(certauth.CodeIdentityUnsupportedDocument): "This certificate identifies the holder with a document other than a Spanish DNI/NIE.",
	string(certauth.CodeRevoked):                     "The certificate has been revoked or suspended.",
	string(certauth.CodeRevocationUnknown):           "The certification authority does not recognise this certificate.",
	string(certauth.CodeRevocationUnavailable):       "The revocation status could not be checked right now.",
	string(certauth.CodeInternal):                    "Something went wrong on our side.",
	"invalid_or_expired":                             "This authentication link is no longer valid. Please start again.",
	"unknown_provider":                               "Unknown certificate provider.",
	"unsupported_media_type":                         "Unsupported request format.",
	"rate_limited":                                   "Too many attempts. Please wait a moment.",
	"store_full":                                     "The service is busy. Please try again shortly.",
	"forbidden":                                      "Request not allowed.",
	"bad_request":                                    "Malformed request.",
	"invalid_state":                                  "This authentication link is no longer valid. Please start again.",
}

// logForwardedHeaders records, at debug level, which client-address headers
// the platform edge sets and how many X-Forwarded-For entries arrive. Never
// the values. Used once at rollout to confirm the header (spec rate limiting).
func logForwardedHeaders(r *http.Request, log *slog.Logger) {
	if !log.Enabled(r.Context(), slog.LevelDebug) {
		return
	}
	var present []string
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "X-Envoy-External-Address", "Forwarded"} {
		if r.Header.Get(h) != "" {
			present = append(present, h)
		}
	}
	entries := 0
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for range strings.SplitSeq(v, ",") {
			entries++
		}
	}
	log.Debug("forwarded headers", "present", present, "xffEntries", entries)
}
```

`internal/server/app.go`:
```go
// Package server wires the main listener (UI + JSON API) and the auth
// listener (TLS client authentication) around a shared transaction store.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/tlsauth"
	"github.com/vocdoni/cert-check/internal/config"
	"github.com/vocdoni/cert-check/web"
)

// CertSource provides the auth listener certificate (internal/acme.Manager).
// The auth listener starts serving only once Ready reports true.
type CertSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Ready() bool
}

// readyPoll is how often Run checks CertSource.Ready before serving auth.
const readyPoll = 500 * time.Millisecond

// Deps are the App's collaborators.
type Deps struct {
	Config  config.Config
	Checker *certauth.Checker
	Certs   CertSource
	Logger  *slog.Logger
	Version string
	Now     func() time.Time // store and limiter clock; nil = time.Now
}

// App is the running service.
type App struct {
	cfg           config.Config
	checker       *certauth.Checker
	certs         CertSource
	log           *slog.Logger
	version       string
	now           func() time.Time
	publicOrigin  string
	store         *Store
	createLimiter *ipLimiter
	redeemLimiter *ipLimiter
	mainUp        atomic.Bool
	authUp        atomic.Bool
	authTLS       *tls.Config
	auth          *authHandler
}

// New builds the App.
func New(d Deps) (*App, error) {
	if d.Checker == nil || d.Certs == nil || d.Logger == nil || d.Config.PublicURL == nil {
		return nil, errors.New("server: Checker, Certs, Logger and Config are required")
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	a := &App{cfg: d.Config, checker: d.Checker, certs: d.Certs, log: d.Logger, version: d.Version, now: now,
		publicOrigin: d.Config.PublicURL.Scheme + "://" + d.Config.PublicURL.Host,
		store:        NewStore(TxCapacity, now), createLimiter: newIPLimiter(20), redeemLimiter: newIPLimiter(60)}
	tcfg, err := tlsauth.ServerConfig(tlsauth.ConfigOptions{Checker: d.Checker, AuthDomain: d.Config.AuthDomain,
		GetCertificate: d.Certs.GetCertificate, AllowTLS13: d.Config.AuthTLS13, Logger: d.Logger})
	if err != nil {
		return nil, err
	}
	a.authTLS = tcfg
	a.auth = &authHandler{store: a.store, tls: tlsauth.NewHandler(d.Checker, d.Config.AuthDomain),
		publicURL: a.publicOrigin, slots: make(chan struct{}, ValidationSlots), slotWait: ValidationSlotWait,
		budget: ValidationBudget, log: d.Logger, version: d.Version}
	return a, nil
}

// MainHandler returns the main-listener routes behind the security headers.
func (a *App) MainHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(noDirFS{web.FS()}))
	mux.HandleFunc("GET /api/v1/providers", a.handleProviders)
	mux.HandleFunc("POST /api/v1/transactions", a.handleCreate)
	mux.HandleFunc("POST /api/v1/transactions/redeem", a.handleRedeem)
	mux.HandleFunc("GET /api/v1/transactions/current", a.handleCurrent)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.mainUp.Load() && a.authUp.Load() && a.certs.Ready() && len(a.checker.Providers()) > 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mainHeaders(mux)
}

// Run serves both listeners until ctx ends, then shuts down gracefully.
// mainLn is plain TCP (the platform edge terminates TLS); authLn is wrapped
// with the 512-connection cap and TLS here.
func (a *App) Run(ctx context.Context, mainLn, authLn net.Listener) error {
	mainSrv := &http.Server{Handler: a.MainHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(a.log.Handler(), slog.LevelWarn)}
	authSrv := newAuthServer(a.auth, a.log)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Go(func() { a.store.RunJanitor(ctx, JanitorInterval) })
	wg.Go(func() {
		a.mainUp.Store(true)
		if err := mainSrv.Serve(mainLn); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	})
	wg.Go(func() {
		t := time.NewTicker(readyPoll)
		defer t.Stop()
		for !a.certs.Ready() {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
		a.authUp.Store(true)
		if err := authSrv.Serve(tls.NewListener(newLimitListener(authLn, AuthMaxConns), a.authTLS)); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	})
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	a.mainUp.Store(false)
	a.authUp.Store(false)
	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer stop()
	runErr = errors.Join(runErr, mainSrv.Shutdown(shutdownCtx), authSrv.Shutdown(shutdownCtx))
	cancel()
	wg.Wait()
	return runErr
}

// noDirFS hides directories (no listings); "/" still serves index.html
// because FileServer opens index.html directly.
type noDirFS struct{ fs.FS }

func (f noDirFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := file.Stat(); err == nil && st.IsDir() && name != "." {
		_ = file.Close() // read-only embedded file
		return nil, fs.ErrNotExist
	}
	return file, nil
}
```

`cmd/cert-check/main.go`:
```go
// Command cert-check serves the Certificate Authentication Checker.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/internal/acme"
	"github.com/vocdoni/cert-check/internal/config"
	"github.com/vocdoni/cert-check/internal/server"
)

// version is set with -ldflags "-X main.version=<git describe>".
var version = "dev"

func main() {
	if err := run(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "cert-check:", err)
		os.Exit(1)
	}
}

// run wires and serves the service until SIGINT/SIGTERM.
func run(getenv func(string) string) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg, err := profiles.Default(time.Now(), log)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	rev, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/" + version, Logger: log})
	if err != nil {
		return err
	}
	checker, err := certauth.NewChecker(certauth.Options{Registry: reg, Revocation: rev, Version: version})
	if err != nil {
		return err
	}
	var certs *acme.Manager
	switch cfg.CertMode {
	case config.CertStatic:
		certs, err = acme.LoadStatic(cfg.TLSCertFile, cfg.TLSKeyFile)
	default:
		certs, err = acme.NewACME(acme.Options{AuthDomain: cfg.AuthDomain, DataDir: cfg.DataDir, Email: cfg.ACMEEmail,
			Staging: cfg.ACMECA == config.ACMEStaging, CloudflareToken: cfg.CloudflareToken.Reveal(),
			OverrideDomain: cfg.ACMEDNSOverrideDomain, Logger: log})
	}
	if err != nil {
		return err
	}
	app, err := server.New(server.Deps{Config: cfg, Checker: checker, Certs: certs, Logger: log, Version: version})
	if err != nil {
		return err
	}
	mainLn, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.Port))
	if err != nil {
		return err
	}
	authLn, err := net.Listen("tcp", cfg.AuthListen)
	if err != nil {
		return err
	}
	log.Info("cert-check starting", "version", version, "providers", len(checker.Providers()), "authDomain", cfg.AuthDomain)
	// The main listener serves at once (/readyz 503); the auth listener
	// starts when the certificate is ready. ACME retries with backoff.
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := certs.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("certificate manager stopped", "error", err.Error())
		}
	})
	err = app.Run(ctx, mainLn, authLn)
	stop() // ends certs.Run when Run returned on a listener error
	wg.Wait()
	return err
}
```

Run:
- `go test -race -count=1 ./internal/server/... ./cmd/...` → `ok` for both;
- `CGO_ENABLED=0 go build -trimpath -o ~/.cache/cert-check/bin/cert-check ./cmd/cert-check`
  succeeds;
- the Global Constraints checks.

Step 3: commit
`git commit -m "feat(server): add main and auth listeners, app wiring and entrypoint" -- internal/server/auth.go internal/server/api.go internal/server/app.go internal/server/auth_test.go internal/server/api_test.go internal/server/app_test.go cmd/cert-check`

Interfaces this task provides to later tasks:
- `server.Deps`, `server.New`, `(*App).MainHandler`, `(*App).Run(ctx, mainLn, authLn)`,
  `server.CertSource`;
- the auth constants `AuthMaxConns`, `ValidationSlots`, `ValidationSlotWait`, `ValidationBudget`;
- `CookieName`;
- the binary `cmd/cert-check` (`-ldflags "-X main.version=…"`).


### Task 11: `web/`: embedded UI, diagnostics report, dev server with fixtures
Model: sonnet   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `web/static/{index.html,app.js,styles.css,favicon.ico}`;
- `web/static/img/vocdoni-logo.svg`;
- `web/static/fonts/{fraunces-latin-full-normal.woff2,fraunces-latin-ext-full-normal.woff2,hanken-grotesk-latin-wght-normal.woff2,hanken-grotesk-latin-ext-wght-normal.woff2,OFL-Fraunces.txt,OFL-HankenGrotesk.txt,SOURCES.md}`;
- `web/testdata/fixtures/{providers.json,create.json,current-none.json,current-pending.json,redeem-success.json,redeem-success-dnie.json,redeem-error-revoked.json,redeem-error-no-certificate.json,redeem-invalid.json}`;
- `web/testdata/report-revoked.txt`;
- `web/web_test.go`, `web/internal/devserver/main.go`.

`web/embed.go` is unchanged (Task 1).

Goal: Goal 5 and AC9 (title, selector from the API, Authenticate button; Success and error views
render from fixtures; no external requests; accessibility), plus the UI half of AC13 (copy button;
report text matches the fixture). It runs in parallel with Tasks 2–10 against the spec's JSON
contract.

UI contract:
- One page, four views. Each is a `<section>` toggled with the `hidden` attribute:
  `#view-start`, `#view-working`, `#view-success`, `#view-error`. One `#status` element has
  `role="status" aria-live="polite"`. Every view switch moves focus to its `<h1>`/`<h2>`
  (`tabindex="-1"`).
- Start view:
  - logo `img/vocdoni-logo.svg` (alt "Vocdoni");
  - H1 "Certificate Authentication Checker";
  - the sentence "Check that your Spanish personal certificate works in this browser and see the
    identity data it carries.";
  - `<label for="provider">Certificate provider</label>` with `<select id="provider">`, filled from
    `GET /api/v1/providers`: standard entries first, then `<optgroup label="Beta">` for `beta:true`,
    in API order;
  - `#provider-hint`: for `dnie` only, "Requires a card reader and the DNIe software already
    working in this browser.";
  - `<button id="authenticate" class="pill primary">Authenticate</button>`;
  - privacy note, verbatim from the spec: "Your browser will ask you to choose a certificate.
    Nothing is uploaded and your private key never leaves your device."
- Authenticate:
  1. Disable the button and show Working ("Preparing…").
  2. `fetch('/api/v1/transactions', {method:'POST', headers:{'Content-Type':'application/json'},
     body: JSON.stringify({provider}), credentials:'same-origin'})`.
  3. On 201, save `sessionStorage['certcheck.pending'] = JSON.stringify({provider, providerName,
     createdAt: Date.now(), authUrl host and port, expiresAt})`, then
     `location.assign(authUrl)` (top-level navigation).
  4. On an API error, show the Error view with the server message.
- Page load:
  1. Read `location.hash`, then immediately `history.replaceState(null, '', '/')`.
  2. `#code=<code>` → Working ("Checking your certificate…") → `POST
     /api/v1/transactions/redeem {"code"}`:
     - `status:success` → Success;
     - `status:error` → Error with `diagnostics`;
     - HTTP 400 `invalid_or_expired` → Error with its minimal diagnostics.
     Then clear the pending entry.
  3. `#error=<code>&diag=<id>` → Error, built client-side from the pending entry (provider, auth
     host, port), the diag ID, now, the user agent and the server version from the last API reply
     (unknown if none).
  4. No hash and a pending entry younger than 5 minutes → `GET /api/v1/transactions/current`:
     - `pending` → the "never reached our server" Error variant;
     - `completed` → Error `invalid_or_expired` ("start again");
     - `none` → clear the entry and show Start.
  5. Otherwise Start. Parse the hash with `URLSearchParams(location.hash.slice(1))`. Unknown keys
     are ignored.
- Success view:
  - H1 "Success";
  - a `<dl id="result-list">` with, in order:
    - Full name; Given name(s);
    - Surname(s), plus "First surname" and "Second surname" when non-empty;
    - Document (`<type> <number>`);
    - Birth date (`YYYY-MM-DD` or "Not included in this certificate");
    - "Represents" (role `representative`) or "Employer" (role `public_employee`) with
      organization name and identifier, when present;
    - Certificate provider; Profile; Issuer; Valid until (`notAfter`, local date);
    - Revocation check (`OCSP`/`CRL`, checked at, source host);
  - `<button id="again" class="pill">Check another certificate</button>` → Start.
- Error view:
  - H2 "We could not authenticate this certificate";
  - `#error-message`: the server `message`, or the client text for `invalid_state` and
    never-reached;
  - `#error-guidance`: the per-code guidance list below;
  - `<details id="tech"><summary>Technical details</summary><pre id="report"></pre></details>`;
  - `<button id="copy-report">Copy diagnostic report</button>`. It uses
    `navigator.clipboard.writeText`; on failure it selects the `<pre>` contents and says "Press
    Ctrl+C to copy";
  - the notice, verbatim from the spec: "This report contains your certificate details (name and ID
    number). Share it only with Vocdoni support.";
  - `<button id="retry" class="pill primary">Start again</button>`.
- Guidance per code (English, short):
  - `no_certificate` and never-reached: choose a certificate when the browser asks; browsers may
    remember a choice, so close all browser windows and retry. Never-reached also lists: the
    selection was cancelled; the network may block port `<port>` (try another network); the browser
    could not use the key.
  - `provider_mismatch`: select the provider that issued your certificate.
  - `untrusted_issuer`, `unsupported_profile`, `unsupported_purpose`, `weak_algorithm`: this
    certificate type is not supported; try another certificate.
  - `expired` / `not_yet_valid`: renew the certificate or check the device clock.
  - `revoked`: the certificate is revoked or suspended; contact the issuer.
  - `revocation_unavailable`, `internal`, `rate_limited`, `store_full`: temporary; retry shortly.
  - `revocation_unknown`: the issuer does not recognise this certificate.
  - `identity_invalid`, `identity_unsupported_document`, `test_certificate`: explain, and suggest
    another certificate.
  - `invalid_or_expired`, `invalid_state`: the link expired; start again.
- Report text (plain, `\n`, built only from data). The first block, then a blank line, then the
  server diagnostics:
  ```
  Vocdoni Certificate Authentication Checker - diagnostic report
  Diagnostic ID: <diagnosticId>
  Time: <diagnostics.time or now, ISO 8601 UTC>
  Page: <location.origin + location.pathname>
  User agent: <navigator.userAgent>
  Server version: <serverVersion>

  Result: error <code> - <message>
  Failed step: <failedStep>
  Provider: <provider>
  Technical detail: <technicalDetail>
  TLS: <version> <cipherSuite> SNI=<sni> client certificate=<yes|no> chain length=<n>
  Certificate:
    Subject: …
    Issuer: …
    Serial: …
    Valid: <notBefore> to <notAfter>
    SHA-256: …
    Key: <keyAlgorithm>   Signature: <signatureAlgorithm>
    Key usage: a, b   Extended key usage: …
    Policies: …
    Critical extensions: …
    OCSP: …   CA issuers: …   CRL: …
  Chain received:
    [0] <subject> / issued by <issuer>
  Profile candidates:
    <profileId>: <result>
  Revocation attempts:
    <method> <url> HTTP <status> <durationMs> ms <outcome> <detail> thisUpdate=<…> nextUpdate=<…> responder=<…> nonce=<sent|not sent>/<echoed|not echoed>
  ```
  Absent sections are omitted. The never-reached report holds: the header, `Result: authentication
  step never reached the server`, `Auth host: <host>:<port>`, `Provider: <id>`, `Started: <ISO>`.
- Rendering: all API strings are inserted with `textContent` or `createTextNode`. `innerHTML`,
  `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` and `new Function` are never used.
  `app.js` is a single `<script src="/app.js" defer>`. There are no inline scripts or styles and no
  `style=` attributes (the CSP has `style-src 'self'`). `index.html` includes
  `<link rel="icon" href="/favicon.ico">` and `<meta name="viewport" content="width=device-width, initial-scale=1">`.
- Brand (from `/home/p4u/.cache/cert-check/brand/BRAND.md` and `DESIGN.md`):
  - colours: background `#FDFBF3`, text `#202019`, primary `#296948` with button text `#FCFAF1`,
    secondary `#E0F3E1`, accent `#F0EAD2`;
  - pill buttons (`border-radius: 9999px`);
  - headings in Fraunces 400 with `font-variation-settings: 'SOFT' 100, 'WONK' 0`, never bold; body
    in Hanken Grotesk;
  - `@font-face` in `styles.css` with `font-display: swap` and `unicode-range` for latin/latin-ext;
  - visible `:focus-visible` outline 3px `#296948`;
  - works at 320 px (single column; the select is 100% wide);
  - contrast AA (the above pairs pass: `#202019` on `#FDFBF3`, `#FCFAF1` on `#296948`).
- Assets:
  - logo and favicon: copy from `/home/p4u/.cache/cert-check/brand/vocdoni-logo.svg` (SHA-256
    b1891d74517bfb8807c7111bf537d613be714d25a585b8ea20de2f991d60c6ce) and `favicon.ico` (6aad61d0bb3a64a431679b938ea4290679ba2f10c647414485bfb4eaa9893380).
  - Fonts: download the npm tarballs of `@fontsource-variable/fraunces@5.3.0` and
    `@fontsource-variable/hanken-grotesk@5.3.0` (`https://registry.npmjs.org/@fontsource-variable/<name>/-/<name>-5.3.0.tgz`)
    into `~/.cache/cert-check/fonts/<name>/` (a new directory each). Verify the registry's `sha512`
    integrity. Extract only the four woff2 files listed and the `LICENSE` (OFL-1.1).
  - `fonts/SOURCES.md` records the tarball URL, its SHA-512 integrity and each file's SHA-256.
    For reference, the brand kit copies are: fraunces-latin 7e744849…b103, fraunces-latin-ext
    e9521563…76c9, hanken-latin e9201edd…a9d5, hanken-latin-ext 768af292…0a24. Note any
    difference; the npm release is the source of truth.
- `web/internal/devserver/main.go` (package `main`, for AC9 checks only; not shipped in the image):
  - serves `web.FS()` on `127.0.0.1:${PORT:-8090}`, behind the same security headers (copy the CSP
    string);
  - mocks the API from `web/testdata/fixtures`:
    - `GET /api/v1/providers` → `providers.json`;
    - `POST /api/v1/transactions` → 201 `create.json`, whose `authUrl` points back to
      `http://127.0.0.1:<port>/__auth?state=x`, plus a cookie;
    - `GET /__auth?state=x&result=<name>` → 303 to `/#code=<name>`, or `/#error=invalid_state&diag=0123…`
      for `result=invalid_state`;
    - `POST /api/v1/transactions/redeem {"code":"<name>"}` → the fixture `redeem-<name>.json` with
      its status;
    - `GET /api/v1/transactions/current` → `current-<pending|none>.json` per a query flag.
  - It imports only stdlib and `web`.
- Fixtures follow the spec JSON exactly. `redeem-success.json` holds a natural person (FNMT); the
  DNIe one adds `birthDate` and first/second surnames. `redeem-error-revoked.json` holds full
  diagnostics with 2 revocation attempts. `report-revoked.txt` is the exact report the UI must
  produce for that fixture, minus the `Page:` and `User agent:` lines. Fixture identities use
  `12345679S` / `JUAN GARCÍA LÓPEZ` (synthetic) and testpki-style DNs.

Step 1: write the failing tests. `web/web_test.go`:
- `TestEmbeddedFiles`: `web.FS()` contains every listed static file; `index.html` references only
  files that exist.
- `TestNoExternalReferences`: no `http://`, `https://` or `//host` URL in html/css/js. Data URIs are
  allowed only in CSS for icons.
- `TestNoUnsafeDOM`: `app.js` contains none of `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, `eval(`, `new Function`.
- `TestCSPCompatible`: `index.html` has no inline `<script>` without `src`, no `<style>` element,
  no `style=` attribute and no `on*=` handler attribute.
- `TestRequiredText`: the exact title, H1, button labels, privacy note, report notice and "Beta"
  optgroup label are present.
- `TestFontSources`: each font's SHA-256 equals `fonts/SOURCES.md`; the OFL texts are present.
- `TestFixturesMatchContract`: decode every fixture with `DisallowUnknownFields` into structs
  declared in the test from the spec's JSON contract (`<Result>`, the error body, `diagnostics`,
  providers, current). There is no `certauth` import, so this task stays independent. Task 12 adds
  the cross-check against the real `certauth` types.

Step 2: implement the files above.

Step 3: verify.
- Commands:
  - `go test -race -count=1 ./web/...` → `ok  github.com/vocdoni/cert-check/web`;
  - `go vet ./web/...`;
  - `go run ./web/internal/devserver` serves on 127.0.0.1:8090.
- Playwright (Playwright MCP, run by whoever has it; otherwise the controller in Task 12) against
  the dev server:
  1. `/` shows the title, the select with optgroup Beta, and the Authenticate button.
  2. Choose fnmt → Authenticate → `/__auth?result=success` → the Success view lists the fixture
     values.
  3. `result=error-revoked` → the Error view. The `#report` text equals `report-revoked.txt` (after
     removing the Page/User agent lines). The copy button exists.
  4. `result=invalid_state` → the Error view with the diag ID.
  5. A pending entry plus `current-pending` → the never-reached view with the port.
  6. At 320×640 the layout has no horizontal scroll.
  7. `browser_network_requests` shows only `127.0.0.1` URLs.
  8. axe-core 4.10.x, downloaded to `~/.cache/cert-check/tools/axe/` with its SHA-256 recorded and
     injected via `browser_evaluate` from the local file, reports 0 `serious`/`critical` violations
     on all four views.

Step 4: commit
`git commit -m "feat(web): add embedded vocdoni ui with diagnostics report and fixture dev server" -- web/static web/testdata web/web_test.go web/internal/devserver`

Interfaces this task provides to later tasks: the embedded UI under `web.FS()`; element IDs
`#provider`, `#authenticate`, `#view-*`, `#result-list`, `#error-message`, `#report`,
`#copy-report`, `#retry`, `#again`; the fixtures and `report-revoked.txt`; the dev server.


### Task 12: end-to-end tests, live checks, revocation probe
Model: opus   Repo: /home/p4u/certificate_poc/cert-check
Files:
- `internal/server/e2e_test.go`, `internal/server/live_test.go` (`//go:build live`),
  `internal/server/fixtures_contract_test.go`;
- `certauth/specimens_live_test.go` (`//go:build live`; only if R-P1 withheld the Bewor/Sectigo
  files);
- `internal/probe/{probe.go,targets.go,probe_test.go,live_test.go}` (`live_test.go` has `//go:build live`);
- `cmd/cert-check/main.go`: add the `probe` subcommand (a few lines).

Goal:
- AC6: real listeners on loopback, a synthetic provider, success plus all negatives.
- AC7: security headers on every response of both listeners; no identity in any log line.
- AC13 for the server side: log has the diagnostic ID and no identity fields.
- AC8: live revocation checks per enabled profile; live E2E with the official Bewor credential.
- The controller-run AC9 and AC13 UI checks against the real local binary.

The e2e harness (shared helper in `e2e_test.go`, package `server_test`):
- Fake network and CA:
  - `testpki.Net` serves `ocsp.test`;
  - a testpki CA with a delegated responder;
  - the `alpha` and `beta` providers (one profile each, policy `1.2.3.1`/`1.2.3.2`, OCSP host
    `ocsp.test`, nonce on), built through `profiles.New`.
- Server:
  - `revocation.NewChecker(Options{DialContext: net.DialContext})` and `certauth.NewChecker`;
  - main and auth listeners on `127.0.0.1:0`;
  - `config.Config{PublicURL: http://127.0.0.1:<main>, AuthDomain: "auth.test", AuthPublicPort: <auth port>, TrustedProxyHops: 1}`;
  - `acme.NewStatic(testpki.ServerTLS(t, "*.auth.test"))`;
  - an injected clock;
  - slog JSON into a buffer;
  - `App.Run` in a `wg.Go` bounded by `t.Context()`.
- Client:
  - an `http.Transport` whose `DialContext` always dials the auth listener and whose
    `TLSClientConfig.ServerName` is the authUrl host (the SNI);
  - `RootCAs` from `ServerTLS`;
  - `CheckRedirect` returns `http.ErrUseLastResponse`;
  - the main API is called with an explicit `Cookie: __Host-certcheck_tx=<v>` header, because
    `cookiejar` does not send Secure cookies over http (spec AC6).

Step 1: write the tests.
- `e2e_test.go`:
  - `TestE2ESuccess` (AC6): create → mTLS GET authUrl → 303 `#code=` → redeem with the cookie →
    200 success.
    - The identity, profile, revocation method `ocsp`, and the diagnostics TLS (`TLS 1.2`, SNI)
      are as expected.
    - The OCSP server saw one request with a nonce.
    - The cookie is cleared.
  - `TestE2ENoClientCertificate`: the handshake succeeds without a certificate → 303 code → redeem
    → `no_certificate` with diagnostics.
  - `TestE2EWrongSNIProvider`: alpha's state used on `beta.auth.test` → 303 `#error=invalid_state`.
    The state is spent: retrying on alpha fails too.
  - `TestE2EReplayedState`; `TestE2EReplayedCode` (second redeem → 400 `invalid_or_expired`).
  - `TestE2ERedeemWithoutCookie` / `TestE2ERedeemOtherCookie` → 400, `technicalDetail`
    `cookie_missing` / `cookie_mismatch`.
  - `TestE2EExpiredTransaction`: clock +5m1s before the auth GET → invalid_state. Before redeem
    (after auth) → 400.
  - `TestE2EUnknownSNI`: a handshake with `gamma.auth.test` fails with `internal error`. The log has
    a warn line with the SNI.
  - `TestE2EHostMismatch`: Host header `beta.auth.test` on an alpha connection → 421.
  - `TestE2EHTTP11NoResumption`: `NegotiatedProtocol == "http/1.1"` with h2 offered;
    `DidResume == false` on reconnect.
  - `TestE2ESecurityHeaders` (AC7). Every response of both listeners has its listener's CSP,
    `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and HSTS: main `/`,
    `/app.js`, every API route (success and error), `/healthz`, `/readyz`, and auth 303 (code),
    303 (error), 404, 421. `Cache-Control: no-store` is on `/api/*` and on every auth response.
  - `TestE2ELogsNoPII` (AC7/AC13). After running all flows above:
    - the log buffer contains each failure's `diagnosticId`;
    - it contains none of: the test DNI, given name, surnames, full name, subject DN, leaf serial
      hex, leaf SHA-256, any state/code/cookie value, or the string `state=`.
  - `TestE2EGracefulShutdown`: cancel → `Run` returns nil and the ports are closed.
- `fixtures_contract_test.go`. `TestUIFixturesDecodeIntoCertauth`: `web/testdata/fixtures/redeem-*.json`
  decode with `DisallowUnknownFields` into `struct{Status string; Result *certauth.Result; Error
  *apiError; Diagnostics *certauth.Diagnostics}`. A real redeem response from `TestE2ESuccess`
  decodes into the same shape and has the same key set as `redeem-success.json`.
- `internal/probe/probe.go`:
  ```
  Run(ctx context.Context, rc *revocation.Checker, targets []Target, now time.Time, w io.Writer) (Summary, error)
  ```
  For each target:
  - OCSP: send one request for a random 16-byte serial under the target anchor (CertID from the
    anchor as issuer), with a nonce when the profile says so, through `revocation.Fetcher`.
    `VerifyOCSP` must accept the answer; any certStatus is fine. A never-issued serial normally
    comes back `revoked`/certificateHold/1970 or `unknown`.
  - CRL: fetch each listed URL, `ParseCRL` against the anchor (the root for ARLs), and check
    thisUpdate ≤ now+5m ≤ nextUpdate.
  - Specimens: for specimen targets, run the full `rc.Check(specimen, anchor, profile policy)` and
    expect `good`.
  Print one line per endpoint: profile, method, host+path, HTTP status, ms, outcome, responder
  subject, nonce echoed, thisUpdate/nextUpdate.
  - `invalid_evidence`/`stale` count as FAIL;
  - `unavailable` counts as WARN;
  - the exit status is non-zero on any FAIL.
- `internal/probe/targets.go`: `DefaultTargets()` built from `profiles.DefaultProviders()` anchors
  plus this URL table (from the digests):

| profile | OCSP URL(s) (issuer = profile anchor) | CRL URL(s) |
|---|---|---|
| fnmt-citizen-rsa | http://ocspusu.cert.fnmt.es/ocspusu/OcspResponder | http://www.cert.fnmt.es/crlsacusu/CRLU1.crl |
| fnmt-citizen-g2 | http://ocspusug2.cert.fnmt.es/ocspusuG2/OcspResponder | http://www.cert.fnmt.es/crlacusuG2/CRL2.crl |
| aoc-idcat-g2 | http://ocsp.catcert.cat | http://epscd.catcert.net/crl/ec-ciutadania.crl (6.9 MB) |
| aoc-idcat-g3 | http://ocsp.aoc.cat | https://epscd.aoc.cat/crl/casub-a2.crl |
| accv-citizen-software-current | http://ocsp.accv.es (RSA1 and ECC1) | http://www.accv.es/gestcert/accv_rsa1_cliente.crl (13.6 MB), http://www.accv.es/gestcert/accv_ecc1_cliente.crl |
| digitel-citizen-sw-g1 | http://ocsp.digitelts.es (+ specimen fed45259…) | http://crl1.pki.digitelts.es/DTSQualifiedCAG1.crl |
| bewor-natural-person-sw | http://ocsp1.uanataca.com/public/pki/ocsp/ (+ specimen da5f38fb…) | http://crl1.uanataca.com/public/pki/crl/bewor.crl |
| sectigo-citizen-local | http://ocsp.sectigo.com (R35, E35; + specimen 88059e92…) | http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAR35.crl, …CAE35.crl |
| fnmt-representative-rsa / -g2 | http://ocsprep.cert.fnmt.es/ocsprep/OcspResponder, http://ocsprepg2.cert.fnmt.es/ocsprepG2/OcspResponder | — |
| fnmt-employee-rsa / -g2 | http://ocspsp.cert.fnmt.es/ocspsp/OcspResponder, http://ocspspg2.cert.fnmt.es/ocspspG2/OcspResponder | — |
| firmaprofesional-personal-sw | http://ocsp.firmaprofesional.com (both anchors) | — |
| anf-asociacion / anf-sl | http://ocsp.anf.es/spain/AV | — |
| uanataca-citizen-sw | http://ocsp1.uanataca.com/public/pki/ocsp/ (4 anchors) | http://crl1.uanataca.com/public/pki/crl/{CA1subordinada,CA2subordinada,2021CA1sub,2021CA2sub}.crl |
| signe-personal-otros-dispositivos | — | http://www.signe.es/signe-ac/crl/signe-subca.crl, https://www.signe.es/signe-ac/crl/signe2020.crl |
| lleidanet-natural-person-sw | http://ocsp2.esigna.es | http://crl1.esigna.es/sub/indenova_pki_003.crl |
| dnie-auth | http://ocsp.dnie.es (issuer AC DNIE 004/005/006) | http://pki.policia.es/dnie/crls/ARL.crl (CA scope, issuer root) |

  Hosts outside a profile's allowlist are a test failure in `probe_test.go` (`TestTargetsAllowlisted`).
- `probe_test.go`: `TestProbeAgainstFakeNetwork`. testpki responders on the fake net, with one bad
  signature and one down endpoint → output lines and summary counts (OK/WARN/FAIL) as expected;
  plus `TestTargetsAllowlisted`.
- `internal/probe/live_test.go` (`live`). `TestLiveProbe` runs `DefaultTargets()` with the real
  network and logs the report. It fails on any FAIL.
- `cmd/cert-check/main.go`: when `os.Args[1] == "probe"`, run `probe.Run` with `DefaultTargets()`
  and a `revocation.Checker` (no DialContext) and exit 0/1. No server, no configuration needed.
  Test: `TestProbeSubcommandDispatch` uses an injected runner.
- `internal/server/live_test.go` (`live`). `TestLiveBeworCredential` (AC8):
  - It reads `CERTCHECK_LIVE_BEWOR_CERT` and `CERTCHECK_LIVE_BEWOR_KEY`, PEM paths outside the
    repo, and `t.Fatal`s if they are unset. It must never skip silently, so it does not count
    under AC1.
  - Server: production `profiles.DefaultProviders()`, a real `revocation.Checker`, a static
    loopback TLS cert, the harness above.
  - Run 1: providers copied with every `TestMarkers` emptied and `Reserved` replaced by
    `identity.Reserved{}` → success. Identity `99949999A`, GN `NOMNUEVE`, SN
    `ESPECIMENNUEVE ESPECIMENNUEVE`, revocation `good` via `ocsp1/2.uanataca.com`, nonce echoed.
  - Run 2: production registry → `test_certificate`.

- `certauth/specimens_live_test.go` (`live`). `TestWithheldSpecimensRejectedTwice` runs the
  Task 7 double-rejection check on the withheld specimens read from
  `$CERTCHECK_LIVE_SPECIMENS_DIR` (`~/.cache/cert-check/live/specimens/`, copied there by the
  controller). Expected: `test_certificate` twice for Bewor ×2 and Sectigo citizen;
  `unsupported_profile` for Sectigo employee.

Run:
- `go test -race -count=1 ./internal/server/... ./internal/probe/... ./cmd/...` → `ok` for all;
- the Global Constraints checks;
- `go vet -tags live ./...`.

Step 2: controller-run live and browser checks (record the outputs in the ledger):
1. Prepare the Bewor credential, outside the repo. The P12 uses RC2-40, so `-legacy` is needed with
   OpenSSL 3. Verified in planning: the cert extracts to DER `da5f38fb…c8ab`.
   ```
   D=~/.cache/cert-check/live/bewor; mkdir -p "$D" && chmod 700 "$D"
   P=/home/p4u/.cache/cert-check/research/ca-downloads/bewor/x/set_certificado_pruebas_bewor
   export PASS="$(sed -n 's/^.*: *//p' "$P/credenciales/4763088_identity_PFsoftBT.txt" | tr -d '\r\n ')"
   openssl pkcs12 -legacy -in "$P/4763088_identity_PFsoftBT.p12" -nokeys -clcerts -passin env:PASS -out "$D/cert.pem"
   openssl pkcs12 -legacy -in "$P/4763088_identity_PFsoftBT.p12" -nocerts -nodes -passin env:PASS -out "$D/key.pem"
   unset PASS; chmod 600 "$D"/*.pem
   openssl x509 -in "$D/cert.pem" -outform der | sha256sum   # da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab
   ```
2. Run `CERTCHECK_LIVE_BEWOR_CERT=… CERTCHECK_LIVE_BEWOR_KEY=… go test -tags live -race -count=1 -run 'TestLive' -v ./internal/server/ ./internal/probe/`
   → `--- PASS: TestLiveBeworCredential`, `--- PASS: TestLiveProbe`. Paste the probe report into the
   ledger. Any responder failing `lacks id-pkix-ocsp-nocheck` or the signature algorithm → raise a
   ruling before the deploy.
3. Probe nonce echo. For each profile with `OCSPNonce:false` whose probe shows the nonce echoed
   (FNMT rep/employee, Uanataca, Lleidanet, Firmaprofesional, ANF), propose a ruling to flip the
   flag.
4. Local binary plus Playwright (AC9/AC13):
   - Start `cert-check` with `CERTCHECK_PUBLIC_URL=http://127.0.0.1:8080`,
     `CERTCHECK_AUTH_DOMAIN=auth.localtest.me`, `CERTCHECK_AUTH_PUBLIC_PORT=8443`, and a static
     cert/key from `testpki.ServerTLS` written to `~/.cache/cert-check/live/tls/`.
   - Run the Task 11 Playwright steps 1, 6 and 7 against it. Also run the Error path with the
     dev-server fixtures, and the axe-core check.

Step 3: commit
`git commit -m "test(e2e): add loopback mtls flow tests, live checks and revocation probe" -- internal/server/e2e_test.go internal/server/live_test.go internal/server/fixtures_contract_test.go internal/probe cmd/cert-check/main.go cmd/cert-check/main_test.go` (add `certauth/specimens_live_test.go` when present)

Interfaces this task provides to later tasks: `cert-check probe` (used from the deployment
network); `internal/probe` (`Target`, `DefaultTargets`, `Run`, `Summary`).


### Task 13: Dockerfile, CI on self-hosted runners, README with ops runbook
Model: sonnet   Repo: /home/p4u/certificate_poc/cert-check
Files: `Dockerfile`, `.dockerignore`, `.github/workflows/ci.yml`, `README.md`,
`internal/deps/deps.go` (delete), `go.mod`, `go.sum` (only if `go mod tidy` changes them, which it
should not).

Goal: AC1 and AC12 enforced in CI; the AC10 build artefacts; spec "Deployment" (Dockerfile,
self-hosted CI, Railway service settings recorded); the rollback runbook. Railway settings are
applied by CLI in "Merge and release" (ruling R-P2), so there is no `railway.json`.

`Dockerfile`. Pin both images by digest: resolve them with
`docker buildx imagetools inspect golang:1.27` and
`… gcr.io/distroless/static-debian12:nonroot`, and keep the tag in a comment.
```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.27@sha256:<digest> AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG RAILWAY_GIT_COMMIT_SHA=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${RAILWAY_GIT_COMMIT_SHA}" -o /out/cert-check ./cmd/cert-check

FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
COPY --from=build /out/cert-check /cert-check
EXPOSE 8080 8443
ENTRYPOINT ["/cert-check"]
```
`.dockerignore`: `.git`, `.delivery`, `docs`, `**/*_test.go` (tests are not needed in the image),
`web/internal`, `web/testdata`, `**/testdata`. The build does not need testdata, and the embedded
anchors are under `certauth/profiles/anchors` (not testdata), so they are kept.

`.github/workflows/ci.yml`. Pin the actions by full commit SHA and keep the tag in a comment;
resolve with `gh api repos/actions/checkout/git/ref/tags/<tag>`.
```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  ci:
    runs-on: [self-hosted, ci]
    timeout-minutes: 30
    env:
      CGO_ENABLED: "0"
      GOFLAGS: -mod=readonly
    steps:
      - uses: actions/checkout@<sha> # v5
      - uses: actions/setup-go@<sha> # v6
        with:
          go-version: "1.27.x"
          cache: true
      - name: gofmt
        run: test -z "$(gofmt -l .)" || (gofmt -l . && exit 1)
      - name: go mod tidy
        run: go mod tidy -diff
      - name: vet
        run: go vet ./... && go vet -tags live ./...
      - name: staticcheck
        run: go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
      - name: test
        run: |
          go test -race -count=1 -json ./... > test.json || (grep -E '"Action":"fail"' test.json | head -50; exit 1)
          test "$(grep -c '"Action":"skip"' test.json)" = "0"
      - name: govulncheck
        run: go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
      - name: fuzz smoke (30 s per target)
        run: |
          for t in FuzzParseName FuzzParseSANDirectoryNames FuzzParseDateOfBirth FuzzParseDocument; do
            go test -run '^$' -fuzz "^$t\$" -fuzztime 30s ./certauth/identity || exit 1
          done
          for t in FuzzParseResponse FuzzParseIDP FuzzParseCDP; do
            go test -run '^$' -fuzz "^$t\$" -fuzztime 30s ./certauth/revocation || exit 1
          done
      - name: AC12 certauth has no app dependencies
        run: |
          if go list -deps ./certauth/... | grep -E 'github.com/vocdoni/cert-check/(internal|web)'; then exit 1; fi
          if go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | grep -v '^github.com/vocdoni/cert-check/internal/testpki' | grep 'internal/testpki'; then exit 1; fi
      - name: docker build
        run: docker build --pull -t cert-check:ci .
```
Notes:
- The fuzz smoke writes any new corpus under `testdata/fuzz` only on failure, and the job fails
  then.
- The org runners `z4`, `z5`, `z7-2` carry the labels `self-hosted, Linux, X64, z, ci`. The repo
  must be allowed in runner group `Default`; Merge and release step D3 checks it.

`README.md` sections:
1. What it is: two listeners, the flow, the `certauth` packages for CSP reuse.
2. Local run with a static certificate. Create `*.auth.localtest.me` with `testpki` or `mkcert`
   under `~/.cache/cert-check/`. Set the env vars. Browser notes (client certificate prompt, port).
3. Configuration table (spec, plus the libdns/cloudflare token needing **Zone:Read + Zone.DNS:Edit**
   on `vocdoni.dev`).
4. Operations:
   - deploy flow: CI → Railway wait-for-CI → healthcheck `/readyz`;
   - first ACME issuance on staging, then production;
   - Let's Encrypt limits;
   - reading a support report: the diagnostic ID is in the logs, via `railway logs --filter <id>`;
   - the `cert-check probe` revocation check from the deployment network;
   - the Chrome restricted-port check.
5. Rollback (copied from Merge and release).
6. Registry maintenance:
   - adding or rotating an anchor: copy the PEM byte-identically, pin, update the TSL inventory,
     tests;
   - disabling a profile (remove it from `DefaultProviders`, redeploy);
   - refreshing specimens and markers;
   - re-checking `http://pki.policia.es/dnie/certs/` for AC DNIE 007+.
7. Security notes: TLS 1.2 default (D2); the zone-wide token risk accepted on 2026-10-31; no PII in
   logs.

Step 1: delete `internal/deps/deps.go`, then run `go mod tidy`. `git diff --stat go.mod go.sum` must
be empty, because every pinned dependency is imported by real code by now.
Step 2: write the files.
Step 3: verify locally:
- `go mod tidy -diff` → empty;
- every CI step run locally as listed (the fuzz loop takes about 3.5 min);
- `docker build -t cert-check:local .` → success;
- `docker run --rm -e CERTCHECK_PUBLIC_URL=… cert-check:local` with no ACME env → exits 1 with the
  config error message;
- `docker image inspect cert-check:local --format '{{.Config.User}}'` → `nonroot` (`65532`);
- `actionlint .github/workflows/ci.yml` → no findings (`~/go/bin/actionlint`).
Step 4: commit
`git commit -m "ci: add dockerfile, self-hosted ci workflow and ops readme" -- Dockerfile .dockerignore .github/workflows/ci.yml README.md internal/deps/deps.go go.mod go.sum`

Interfaces this task provides to later tasks: the image build used by Railway; the CI check name
`ci` (job `ci`) for branch protection and Railway wait-for-CI.


## Merge and release

1. **Full suites** on `feat/cert-check-v1` after Task 13, from the repo root, with TMPDIR/GOTMPDIR
   set:
   - `test -z "$(gofmt -l .)"`, `go mod tidy -diff`, `go vet ./...`, `go vet -tags live ./...` →
     no output.
   - `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...` → no output.
   - `go test -race -count=1 ./...` → `ok` for `certauth`, `certauth/identity`,
     `certauth/profiles`, `certauth/revocation`, `certauth/tlsauth`, `cmd/cert-check`,
     `internal/acme`, `internal/config`, `internal/probe`, `internal/server`, `internal/testpki`,
     `web`. `web/internal/devserver` reports `[no test files]`.
     `go test -race -count=1 -json ./... | grep -c '"Action":"skip"'` → `0` (AC1).
   - `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...` → "Your code is affected by 0
     vulnerabilities" (exit 0). The module-only GO-2026-5932 in x/crypto, which has no fix and is
     not called, is noted in the ledger.
   - The 7 fuzz targets, 30 s each → `PASS`.
   - AC12: `go list -deps ./certauth/... | grep -E 'cert-check/(internal|web)'` → no output.
   - The live run from Task 12 step 2 is repeated on the merged tree → `TestLiveProbe` and
     `TestLiveBeworCredential` PASS.
   - `docker build -t cert-check:rc .` → success.
2. **Gate audit** (Fable) of the full branch against the spec and this plan. Fold the rulings,
   re-review the fixes, and re-run step 1.
3. **Merge** `feat/cert-check-v1` → `main` locally (`git merge --no-ff feat/cert-check-v1`, message
   `chore(release): merge cert-check v1`). No push yet.
4. **Release tag** after AC11 passes (step D12): `git tag -a v0.1.0 -m "cert-check v0.1.0"`.
   **Owner OK required** to push the tag.

### Rollback (prepared before any deploy step)
- **R1 Bad application deployment.** In the Railway dashboard, Deployments → the previous
  successful deployment → Redeploy. Alternatively `git revert <sha>` on `main` and push
  (**Owner OK**), and Railway redeploys after CI. DNS, the volume and the ACME certificate in
  `/data/certmagic` are unaffected.
- **R2 Bad provider profile.** Remove the profile (or its provider) from `DefaultProviders()` and
  redeploy through PR → CI → main (**Owner OK** to push).
- **R3 ACME or Cloudflare failure.** The service stays up with `/readyz` 503, and the previous
  deployment keeps serving (healthcheck gate). Set `CERTCHECK_ACME_CA=staging` to debug without
  production limits, fix the token, then switch back.
- **R4 TCP proxy port on a browser-restricted list, or proxy broken.** Delete and recreate the
  proxy (`railway tcp-proxy delete … && railway tcp-proxy create --service cert-check --port 8443`).
  The owner updates the `*.auth.cert-check.vocdoni.dev` CNAME if the proxy host changed.
  `CERTCHECK_AUTH_PUBLIC_PORT` follows `RAILWAY_TCP_PROXY_PORT` automatically.
- **R5 Token leak.** The owner revokes `CLOUDFLARE_API_TOKEN` in Cloudflare at once, creates a new
  one (Zone:Read + Zone.DNS:Edit on `vocdoni.dev`), sets it as a sealed variable, and audits the
  `vocdoni.dev` DNS records.
- **R6 Withdraw the service.** Remove the custom domain and the TCP proxy (`railway domain delete
  cert-check.vocdoni.dev --service cert-check --yes`, `railway tcp-proxy delete …`). The owner
  removes the two DNS records. The project and volume are kept.

### Deploy (in order; outward-facing steps need the owner's OK)
- **D1. Owner OK required.** Create the private repo and push `main`:
  `gh repo create vocdoni/cert-check --private --source /home/p4u/certificate_poc/cert-check --remote origin`,
  then `git -C /home/p4u/certificate_poc/cert-check push -u origin main`.
- **D2. Owner OK required.** Branch protection, if the org plan allows it on private repos. Check
  with `gh api orgs/vocdoni --jq .plan.name`. If it does:
  `gh api -X PUT repos/vocdoni/cert-check/branches/main/protection --input <json>` requiring status
  check `ci` (strict), `enforce_admins: false`, `required_pull_request_reviews: null`,
  `restrictions: null`. If not, record that Railway's wait-for-CI is the only gate.
- **D3. CI on self-hosted runners.** Confirm runner group `Default` admits the repo:
  `gh api orgs/vocdoni/actions/runner-groups --jq '.runner_groups[]|{name,visibility,allows_public_repositories}'`.
  Watch the first run with `gh run list --repo vocdoni/cert-check` and `gh run view <id>`. The `ci`
  job must run on `z4`/`z5`/`z7-2` and pass.
- **D4. Owner OK required.** Railway:
  - The Railway GitHub app must have access to `vocdoni/cert-check`. The owner adds it in the org's
    app settings if the installation uses selected repositories.
  - Create project `CertificateCheck` (environment `production`).
  - Create service `cert-check` from GitHub repo `vocdoni/cert-check`, branch `main`.
  - Add a volume mounted at `/data` (dashboard, or the CLI volume command if available).
- **D5. Owner OK required.** Service settings by CLI (R-P2), each
  `railway environment edit --service-config cert-check <path> <value>`:
  - `build.builder DOCKERFILE`, `build.dockerfilePath Dockerfile`;
  - `deploy.healthcheckPath /readyz`, `deploy.healthcheckTimeout 600`;
  - `deploy.restartPolicyType ON_FAILURE`, `deploy.restartPolicyMaxRetries 10`;
  - `deploy.numReplicas 1`;
  - `source.branch main`, `source.checkSuites true` (wait for CI).
  Read back with `railway environment edit --json` / dashboard.
- **D6. Owner OK required.** Variables, with `railway variable set KEY=value --service cert-check`:
  - `RAILWAY_RUN_UID=0`
  - `PORT=8080`
  - `CERTCHECK_PUBLIC_URL=https://cert-check.vocdoni.dev`
  - `CERTCHECK_AUTH_DOMAIN=auth.cert-check.vocdoni.dev`
  - `CERTCHECK_ACME_EMAIL=<owner-provided>`
  - `CERTCHECK_ACME_CA=staging` (first issuance)
  - `CERTCHECK_TRUSTED_PROXY_HOPS=1`
  - `CERTCHECK_LOG_LEVEL=info`
  The **owner** enters `CLOUDFLARE_API_TOKEN` as a sealed variable in the dashboard; the agent never
  handles the value. Token permissions: Zone:Read and Zone.DNS:Edit on `vocdoni.dev`
  (libdns/cloudflare single-token mode). Zone-wide risk accepted on 2026-10-31.
- **D7. Owner OK required.** Networking:
  - `railway domain cert-check.vocdoni.dev --service cert-check --port 8080 --json` (record the
    CNAME target and any TXT), plus the generated `*.up.railway.app` domain
    (`railway domain --service cert-check --json`);
  - `railway tcp-proxy create --service cert-check --port 8443 --json` (record
    `<x>.proxy.rlwy.net:<port>`).
  - Check `<port>` against Chrome's restricted ports (`net/base/port_util.cc` kRestrictedPorts: 1, 7,
    9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95, 101, 102, 103,
    104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161, 179, 389, 427, 465, 512,
    513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995,
    1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665–6669, 6679, 6697, 10080)
    and Firefox's `network.security.ports.banned` defaults. Re-check the current Chromium list on
    the day. A hit → R4.
- **D8. Owner action** (Cloudflare, both records DNS-only/grey):
  - `cert-check.vocdoni.dev` CNAME → Railway's target (plus the TXT verification record if Railway
    shows one);
  - `*.auth.cert-check.vocdoni.dev` CNAME → `<x>.proxy.rlwy.net`.
  - Verify with `dig +short CNAME fnmt.auth.cert-check.vocdoni.dev` → proxy host. Also run
    `dig +short CAA cert-check.vocdoni.dev` and `dig +short CAA <railway target>`. If a CAA set
    excludes `letsencrypt.org`, the owner adds `auth.cert-check.vocdoni.dev CAA 0 issue
    "letsencrypt.org"` before D9.
- **D9. First deployment, staging certificate.** Railway builds `main` after CI. In
  `railway logs --service cert-check`, look for "auth certificate ready" (staging) and no ACME
  errors.
  - `curl -sS -o /dev/null -w '%{http_code}' https://cert-check.vocdoni.dev/readyz` → `200`. The
    certmagic storage `/data/certmagic` exists (its log line names the path); `railway ssh` is not
    available on distroless.
  - Then **Owner OK required**: set `CERTCHECK_ACME_CA=production`. The redeploy obtains the
    production certificate; `/readyz` → `200`.
- **D10. Smoke tests** (record the outputs):
  - `curl -sS https://cert-check.vocdoni.dev/api/v1/providers` → 14 providers in display order,
    beta flags as specified. `curl -sI https://cert-check.vocdoni.dev/` → CSP, Referrer-Policy,
    nosniff, HSTS.
  - For each provider id:
    `openssl s_client -connect <id>.auth.cert-check.vocdoni.dev:<port> -servername <id>.auth.cert-check.vocdoni.dev -tls1_2 -showcerts </dev/null`.
    Expect the Let's Encrypt production chain, `Verify return code: 0`, and "Acceptable client
    certificate CA names" listing exactly that provider's anchors (DNIe: the root plus AC DNIE
    004/005/006). `-tls1_3` fails (TLS 1.2 only).
  - `-servername nope.auth.cert-check.vocdoni.dev` → handshake alert `internal error`.
  - No-certificate path:
    1. `curl -c jar -H 'Content-Type: application/json' -d '{"provider":"fnmt"}' https://cert-check.vocdoni.dev/api/v1/transactions`;
    2. `curl -sS -o /dev/null -w '%{redirect_url}' "<authUrl>"` → `…/#code=…`;
    3. `curl -b jar -H 'Content-Type: application/json' -d '{"code":"…"}' …/redeem` →
       `no_certificate` with diagnostics.
  - Forwarded header: `railway variable set CERTCHECK_LOG_LEVEL=debug`, create one transaction,
    read the `forwarded headers` debug line (header names and the `xffEntries` count), then reset
    to `info`. If `X-Forwarded-For` is absent or `xffEntries` ≠ 1 for a direct client, raise a
    ruling: change the header or hops before go-live. Record the confirmed header in the spec's
    rate-limiting bullet (docs commit, **Owner OK** to push).
- **D11. Owner OK required.** AC8 from the deployment network:
  - add a temporary service `cert-check-probe` in the project, same repo, with
    `deploy.startCommand "/cert-check probe"` and `deploy.restartPolicyType NEVER`;
  - read `railway logs --service cert-check-probe` and paste the report into the ledger;
  - delete the service (`railway service delete --service cert-check-probe --environment production --yes`).
  - A FAIL line blocks go-live; a WARN line is noted.
- **D12.** AC11: the owner authenticates with a real idCAT or FNMT certificate at
  `https://cert-check.vocdoni.dev` in Chrome, Firefox and Safari/Edge as available. The owner checks
  the displayed data and records browser and OS versions in the ledger. On any failure, the owner
  sends the copied diagnostic report; the controller matches its ID in `railway logs`.
- **D13. Post-release checks.**
  - AC10 checklist: the project exists; deploys of `main` wait for CI; `/readyz` is healthy; the UI
    is served; each auth host presents a valid LE certificate and requests a client certificate
    with that provider's CAs; CI runs on the self-hosted runners.
  - Merge the ledger notes.
  - Tag push per step 4.
