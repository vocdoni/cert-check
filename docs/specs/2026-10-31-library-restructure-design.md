# Library-first restructure: design

Status: approved (2026-11-01)   Class: architectural
Owner decisions so far:
- 2026-10-31 (request): the repository becomes primarily a Go module that other Go programs import.
  - It should have an API similar to (not the same as) the blind-csp idCAT handler.
  - It defines an interface, and each certificate type (FNMT, idCAT, …) implements it, so a
    program only decides which certificate types it accepts.
  - Use the vocdoni-go skills; modular and clean.
  - The web UI and all Railway/deployment material move to a subdirectory (a testing UI) with its
    own README. The root README is rewritten for the Go package.
- All decisions of `docs/specs/2026-10-30-cert-check-design.md` stay in force. That covers
  pipeline semantics, trust anchors, provider scope, TLS 1.2 default, diagnostics and the
  deployment topology; this work changes structure, not behaviour.

## Problem

Today the repository is application-first:

- **The engine has no "certificate type" concept a program can pick.**
  - The engine is `certauth` (Checker, pipeline), `certauth/{identity,revocation,profiles,tlsauth}`.
  - A consumer builds a `certauth.Checker` from the monolithic `profiles.Default` registry and
    passes provider ID strings (`Check(ctx, "idcat", chain)`).
  - All 14 providers' data live in one file (`certauth/profiles/providers.go`).
- **The web app is mixed into the same module.**
  - `cmd/cert-check`, `internal/{server,acme,config,probe}`, `web/`, the Dockerfile and the CI
    docker step all sit beside the library.
  - The single `go.mod` therefore lists `github.com/caddyserver/certmagic`,
    `github.com/libdns/cloudflare`, zap (indirect) and `golang.org/x/time`, none of which a
    library consumer needs.
- **The README is an operations runbook** for the deployed checker, not package documentation.

The blind-csp `handlers.AuthHandler` interface is a reference for the shape a CSP expects:
`Name`, `RequireCertificate`, `Certificates() [][]byte`, `CertificateCheck(subject []byte) bool`,
`Auth(r *http.Request, …)` (`blind-csp/handlers/handlers.go`).

## Goals

1. **Root package `certcheck`** (module `github.com/vocdoni/cert-check`, import name `certcheck`)
   is the public API:
   - a small `Provider` interface;
   - the result, identity, error and diagnostics types (`ProviderRef` is the provider part of a
     `Result`; `NewDiagnosticID`, `DescribeTLS` and `DescribeCertificate` are exported for the
     testing UI);
   - functional options;
   - a blind-csp-like `Handler`, built with `NewHandler(providers, opts...)`, with `Auth`,
     `AuthAs`, `Verify`, `VerifyAs` and `TLSConfig`.
2. **One package per certificate issuer** under `providers/`. Each is a thin wrapper exposing
   constructors that return a `certcheck.Provider` (built with `engine.New` from the declarations
   in `internal/profiles`). A program picks certificate types by importing and constructing them,
   e.g. `idcat.New()`, `fnmt.New()`.
3. **Everything that is not public API moves under `internal/`.** That means the pipeline engine
   (`internal/engine`), the profile declarations and embedded anchors (`internal/profiles`),
   identity parsing, revocation (OCSP/CRL/fetcher/caches) and the synthetic test PKI. The public
   surface is exactly the list in AC4.
4. **No behaviour change.** The existing guarantees stay identical:
   - same pipeline order and checks;
   - byte-identical embedded anchors and the same profile data;
   - same `ErrorCode` values, `Error.Detail`/`Diagnostics.TechnicalDetail` strings and `Step`
     values; Go `error` string prefixes follow the new package names (`certcheck:`);
   - same `Diagnostics`/`Result` JSON;
   - same TLS policy.

   The existing test suites move with the code and keep passing; every pre-existing test name is
   still present (AC6).
5. **The testing UI and deployment move to `testui/` as a separate Go module**
   (`github.com/vocdoni/cert-check/testui`) with its own `go.mod`. It contains:
   - the server, ACME, config, probe and web UI;
   - the Dockerfile and its README (UI and Railway runbook).

   The library module's dependency graph contains no certmagic, libdns, zap or `x/time`.
6. **CI** builds, vets and tests both modules on the self-hosted runners. **Railway** builds
   `testui/Dockerfile` and the deployed service behaves exactly as before: same URLs, providers,
   flow and diagnostics.
7. **READMEs.** The root `README.md` documents the Go package: install, quick start, choosing
   certificate types, `Handler` and TLS configuration, results and error codes, revocation,
   security notes, supported providers table. `testui/README.md` documents the testing UI and
   its deployment.

## Non-goals

- Any change to validation semantics, provider scope, anchors, OIDs, revocation policy or the UI's
  look and behaviour.
- Backwards compatibility with the `certauth` import paths (v0, private, no external consumers).
- A drop-in adapter for blind-csp's exact `AuthHandler` signature (its types come from
  `go.vocdoni.io/dvote`); the `Handler` is similar in spirit only.
- New providers, live TSL import, census or credential issuance.

## Design

### Public API (root package `certcheck`)

Binding names and signatures (fields may grow; existing JSON tags are preserved):

```go
package certcheck

// Provider verifies client certificates of one certificate type (an issuer
// family such as FNMT citizen or idCAT). Implementations are safe for
// concurrent use; Handler relies only on this interface, so consumers may
// provide test doubles.
type Provider interface {
    // Info describes the provider (stable ID, display name, description, beta flag).
    Info() ProviderInfo
    // CAs returns the pinned CA certificates a TLS server should advertise
    // in its CertificateRequest for this provider (anchors and pinned
    // intermediates). The slice and the certificates are shared; callers
    // must not modify them. Handler builds its own pools from them.
    CAs() []*x509.Certificate
    // Verify runs the full validation pipeline on a client certificate chain
    // as received in tls.ConnectionState.PeerCertificates. chain is used as
    // received: chain[0] is the leaf; chain[1:] are never used for path
    // building. A standalone Verify (no Handler) answers untrusted_issuer for
    // any leaf that does not chain to its own CAs. On failure the error is
    // *Error. Verify performs network I/O (OCSP/CRL) bounded by ctx; callers
    // set a deadline (the testing UI uses 40 s). A deadline hit is
    // *Error{Code: internal, Retryable: true}.
    Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error)
}

// ProviderInfo describes a provider. ID is a DNS label and stable.
type ProviderInfo struct {
    ID          string // e.g. "idcat"
    Name        string // display name, e.g. "idCAT Certificat"
    Description string // one sentence, as shown by the testing UI
    Beta        bool
}

// ProviderRef is the provider part of a Result (JSON {"id","name"}, unchanged).
type ProviderRef struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

// Result, Identity, Document, Organization, CertificateInfo, RevocationInfo,
// Diagnostics, TLSInfo, Error, ErrorCode (and its constants), Step: as today in
// certauth, with identical JSON (the full exported list is AC4). They are
// declared in, or aliased into, package certcheck; consumers never import
// internal packages. Result.Provider is ProviderRef; ProviderInfo has no JSON
// tags and is never serialised by the library.

// Option configures providers and handlers.
type Option func(*opts.Settings) // opts = internal/opts: Revocation, Now, Logger, Version, MaxChainLen; applied by internal/engine

func WithRevocation(r *Revocation) Option // share one revocation checker across providers; default: process-wide singleton
func WithClock(now func() time.Time) Option // pipeline clock (anchor validity at construction, validation time); default time.Now
func WithLogger(l *slog.Logger) Option    // construction warnings; default slog.Default()
func WithVersion(v string) Option         // Diagnostics.serverVersion; default ""

func NewHandler(providers []Provider, opts ...Option) (*Handler, error) // ≥1 provider, unique IDs, no inert provider, no shared issuer (see Handler)

// Revocation is a shared OCSP/CRL checker with bounded caches. Create it with NewRevocation;
// the zero value is not usable.
type Revocation struct{ c *revocation.Checker }
func NewRevocation(o RevocationOptions) (*Revocation, error)
type RevocationOptions struct {
    UserAgent        string           // "" = "cert-check/dev" (today's fetcher default)
    Now              func() time.Time // evidence freshness clock; pass the WithClock clock in tests
    Logger           *slog.Logger
    OCSPTimeout      time.Duration    // 0 = 5 s
    CRLTimeout       time.Duration    // 0 = 15 s
    CRLCacheBytes    int64            // 0 = 128 MiB
    OCSPCacheEntries int              // 0 = today's default
}
```

- **Default revocation.** When no `WithRevocation` is given, providers use one process-wide
  default `*Revocation`, created lazily with `sync.OnceValues`. `idcat.New()` therefore works
  with no arguments, and all default-built providers share caches. The default uses the fetcher
  defaults (`UserAgent` `cert-check/dev`, wall clock); a program that needs another User-Agent or
  a fake clock passes `WithRevocation`.

### Certificate types (`providers/…`)

| Package | Constructors (each returns `certcheck.Provider`) | Profiles (unchanged data, declared in `internal/profiles`) |
|---|---|---|
| `providers/fnmt` | `New` (citizen RSA+G2), `NewRepresentative` (beta), `NewEmployee` (beta) | fnmt-citizen-rsa/-g2; representative rsa/g2; employee rsa/g2 |
| `providers/idcat` | `New` | aoc-idcat-g2, aoc-idcat-g3 |
| `providers/accv` | `New` | accv-citizen-software-current |
| `providers/dnie` | `New` (beta) | dnie-auth |
| `providers/digitel` | `New` | digitel-citizen-sw-g1 |
| `providers/bewor` | `New` | bewor-natural-person-sw |
| `providers/sectigo` | `New` | sectigo-citizen-local |
| `providers/firmaprofesional` | `New` (beta) | firmaprofesional-personal-sw |
| `providers/anf` | `New` (beta) | anf-asociacion-class2-sw, anf-sl-class2-sw |
| `providers/uanataca` | `New` (beta) | uanataca-citizen-sw |
| `providers/signe` | `New` (beta) | signe-personal-otros-dispositivos |
| `providers/lleidanet` | `New` (beta) | lleidanet-natural-person-sw |

- Profile declarations are data, and they stay internal. `internal/profiles` holds one file per
  provider (`fnmt.go`, `idcat.go`, …: the exact functions of today's `providers.go`, split by
  `git mv`-then-edit of one file is not possible, so this is the one documented copy-split), the
  profile/anchor types of today's `profiles/types.go`, the loader of `registry.go`, the embedded
  anchors (`internal/profiles/anchors/*.pem`, byte-identical, one directory, one `SOURCES.md`)
  and `Reserved`. It exports `All() []Provider` (today's `DefaultProviders`), `ByID`, and the
  loader. Every existing profiles/registry/TSL/specimen test moves there unchanged.
- `providers/<name>` is a thin public wrapper: `func New(opts ...certcheck.Option) certcheck.Provider`
  builds the provider through `engine.New` from `profiles.IDCAT()` and `opts` (a few lines per
  constructor, no data). AC4's "exports only constructors" holds.
- `internal/engine.New(cfg engine.Config) (*engine.Provider, error)` with
  `Config{Provider profiles.Provider; Revocation *revocation.Checker; Now func() time.Time;
  Logger *slog.Logger; Version string; MaxChainLen int}` is the construction path for every test
  in both modules (synthetic anchors, no-network `DialContext`, fixed clocks, emptied markers),
  exactly as `certauth.NewChecker`+`profiles.New` are today. The probe and the testui e2e/live
  tests import `internal/profiles`, `internal/engine` and `internal/revocation` from the root
  module (Go's `internal` rule is path-based and the nested module path is under the root; verified).
- Only `internal/profiles` embeds anchors. Per-provider embedding is dropped: it would split
  `SOURCES.md` (not byte-identical) and `TestAnchorFiles`/`TestAnchorsGrantedInTSL` for no gain.
- Each constructor validates the embedded data at construction. A pin mismatch, a non-CA anchor,
  a malformed declaration or a handled critical extension without a parser is a build-time
  invariant violation (the data is compiled in and tested): the constructor panics with the
  loader's message. Anchor and pinned-intermediate validity is **not** an invariant: as today, an
  anchor outside validity at construction is skipped with a warning on the `WithLogger` logger, a
  profile with no valid anchor (or no valid pinned intermediate) is disabled, and a provider with
  no enabled profile is **inert**: `Info()` is unchanged, `CAs()` is empty, `Verify` fails
  `provider_mismatch` at `StepBounds` with detail "provider has no enabled profile".
  `providers.All()`, `Standard()` and `ByID()` omit inert providers (today `Registry.Providers`
  and `Provider()`), and `NewHandler` returns an error for an inert provider so a CSP fails loudly
  at startup instead of advertising nothing. A test disables every anchor by clock and checks all
  of this (today `TestValidityDisables`).
- `providers` (aggregate package) provides convenience constructors in today's display order
  (inert providers omitted):
  - `All(opts ...certcheck.Option) []certcheck.Provider`
  - `Standard(…)` (non-beta)
  - `ByID(id string, opts ...certcheck.Option) (certcheck.Provider, bool)`

### Handler (blind-csp-like)

```go
// Handler authenticates HTTP requests that arrived over TLS with a client
// certificate, using a fixed set of certificate types. It is immutable and
// safe for concurrent use.
type Handler struct{ /* providers, CA index */ }

func NewHandler(providers []Provider, opts ...Option) (*Handler, error) // ≥1 provider, unique IDs, no inert provider, no shared issuer
// Name and RequireCertificate: constants provided for blind-csp-shaped adapters.
func (h *Handler) Name() string                         // "certcheck"
func (h *Handler) RequireCertificate() bool             // true
func (h *Handler) Certificates() [][]byte               // DER of every advertised CA (dedup); returns fresh copies
func (h *Handler) CertificateCheck(subject []byte) bool // DER subject is one of the advertised CAs
func (h *Handler) ClientCAs() *x509.CertPool            // pool for tls.Config.ClientCAs, built by the handler
func (h *Handler) Providers() []Provider                // returns fresh copies
func (h *Handler) TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), opts ...TLSOption) *tls.Config
func (h *Handler) Auth(r *http.Request) (*Result, error) // verifies r.TLS.PeerCertificates
func (h *Handler) AuthAs(r *http.Request, providerID string) (*Result, error) // VerifyAs on r.TLS.PeerCertificates
func (h *Handler) Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error)
func (h *Handler) VerifyAs(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error)
```

- **`TLSConfig`** produces today's auth-listener policy:
  - TLS 1.2 by default (`WithTLS13()` TLSOption allows 1.3), and today's cipher suites and
    curves;
  - `RequestClientCert` with `ClientCAs = h.ClientCAs()`;
  - session tickets disabled;
  - ALPN `http/1.1`.
- **`Verify` and `Auth`** select the candidate providers whose `CAs()` contain a certificate
  whose `RawSubject` equals the leaf's `RawIssuer` (byte equality; this is exactly the parent
  lookup `crypto/x509` performs, `cert_pool.go:148`, so no provider that could verify the leaf
  is ever skipped).
  - **`NewHandler` rejects ambiguity at construction**: it returns an error if two providers
    advertise CAs with the same `RawSubject`, or if two profiles of different providers share an
    anchor SPKI and a policy OID (today's `checkAmbiguity`, extended across providers). A
    handler therefore has at most one candidate per issuer and acceptance never depends on
    provider order. `providers.All()` satisfies this (test in `providers`).
  - None → `*Error{Code: untrusted_issuer, Step: path}` with `Diagnostics` filled as the engine
    fills them for any failure (`DiagnosticID`, `Time`, `ServerVersion` from the handler's
    `WithVersion`, `Provider: ""`, `Chain`, `Certificate`), via the exported
    `DescribeCertificate` (today's `describeCertificate`, exported next to `DescribeTLS`).
  - One → that provider's `Verify`, returned verbatim.
  - `Auth` fills `Diagnostics.TLS` from `r.TLS` on both paths (today's `tlsauth.Authenticate`,
    `tlsauth.go:136-151`, including the request-without-TLS `CodeInternal` error with empty
    `Diagnostics`).
- **`VerifyAs(ctx, providerID, chain)`** keeps today's per-provider semantics for the testing
  UI's per-SNI hosts:
  - unknown or disabled `providerID` → `provider_mismatch` at `StepBounds`, detail
    "unknown provider" (today `checker.go:136-139`);
  - otherwise the named provider's `Verify` runs. If it fails with `untrusted_issuer` at
    `StepPath`, the Handler re-classifies exactly as today's `unknownAuthorityCode`: it
    path-builds a copy of the leaf with `UnhandledCriticalExtensions` cleared against the union
    of the *other* providers' anchors (roots) and pinned intermediates with the same
    `VerifyOptions` (ClientAuth EKU, `CurrentTime` = the handler clock). If that chain builds,
    `Code` and `Diagnostics.Code` become `provider_mismatch`; nothing else in the error changes
    (step stays `path`, `ProfileCandidates` are the named provider's). No network, no acceptance.
  - A standalone `Provider.Verify` (no handler) answers `untrusted_issuer` for any leaf that does
    not chain to its own CAs; this is documented on the interface.
- This is the one declared logic move out of the pipeline: `unknownAuthorityCode` and
  `Registry.AllAnchors` are deleted from the engine, and `pathmap_test.go`'s
  provider-mismatch cases plus `checker_test.go:358-361,437` are re-pointed at
  `Handler.VerifyAs` with identical expectations. The gate audit reads this move as a diff.
- **`AuthAs(r *http.Request, providerID string) (*Result, error)`** is `VerifyAs` on
  `r.TLS.PeerCertificates` with `Diagnostics.TLS` filled from `r.TLS` on both paths; a request
  without TLS state answers the `CodeInternal` error with empty `Diagnostics` (today
  `tlsauth.Authenticate`). The testing UI's auth handler calls `AuthAs` with the provider decoded
  from the SNI.
- **Per-SNI dispatch stays in the testing UI**: `tlsauth.ServerConfig`'s `GetConfigForClient`
  (exact lowercased `<id>.<AuthDomain>`, unknown SNI → handshake error, 64-byte SNI cap in logs)
  and `Handler.Provider(serverName)` move by `git mv` to `testui/internal/server/tlsconfig.go`,
  with `TestServerConfigRequiresOptions`, `TestServerConfigPerProvider`, `TestServerConfigTLS13`,
  `TestUnknownSNIRejected`, `TestHandshakeAdvertisesProviderCAs`, `TestNoResumptionNoH2`,
  `TestRequestClientCertOptional` and `TestProvider`. Each per-provider `*tls.Config` is produced
  by `certcheck.Handler.TLSConfig` of a one-provider handler, so the TLS policy (versions, suites,
  curves, tickets off, `RequestClientCert`, `http/1.1`) exists once, in the library, and the
  outer config keeps today's `MinVersion`/`NextProtos`. `TestAuthenticate*` and `TestCheckHost`
  move to the root package against `AuthAs`/`CheckHost`.
- **`CheckHost`** (Host≠SNI → error) is a package function, as today in tlsauth.

### Internal packages

| Package | From | Role |
|---|---|---|
| `internal/engine` | `certauth/checker.go`, `types.go` engine parts, `diagnostics.go` engine parts; implements `certcheck.Provider` | `engine.New(Config)` builds a `certcheck.Provider` from one provider declaration; pipeline steps 1–9 unchanged, apart from the declared `provider_mismatch` move to `Handler.VerifyAs` |
| `internal/profiles` | `certauth/profiles`: declarations one file per provider, types, loader, embedded anchors, `Reserved` | Profile data and loader; `All`, `ByID`; the only package that embeds anchors |
| `internal/identity` | `certauth/identity` | unchanged code |
| `internal/revocation` | `certauth/revocation` | unchanged code |
| `internal/testpki` | `internal/testpki` | unchanged (root-module tests) |

- `certauth/tlsauth` is folded into the root package (`Handler`, `AuthAs`, `CheckHost`,
  `TLSConfig`); its per-SNI `ServerConfig` dispatch moves to the testing UI (see Handler).
- Reserved identities and name markers become an internal shared table (`Reserved` in
  `internal/profiles`) applied by every provider (today `profiles.Registry.Reserved`).
- Test markers (fingerprints) stay per profile.
- Import graph: `certcheck` imports `internal/identity` and `internal/revocation` only; those
  two never import `certcheck` (CI test: `go list -deps ./internal/identity ./internal/revocation`
  does not contain `github.com/vocdoni/cert-check`). `internal/engine` imports `certcheck`,
  `internal/identity`, `internal/revocation` and `internal/profiles`, and implements
  `certcheck.Provider` directly (`checker.go`'s `Check` becomes `(*Provider).Verify` returning
  `*certcheck.Result` / `*certcheck.Error`). `providers/*` import `certcheck` and
  `internal/engine`. No adapter layer.
- Types that internal packages own and the public surface shows are aliased in `certcheck`, so a
  consumer can name every field type: `Identity`, `Document`, `Organization`, `Date`,
  `DocumentType` (= `identity.*`), `RevocationStatus` (= `revocation.Status`),
  `RevocationMethod` (= `revocation.Method`), `Role`, `ProfileInfo` (= `profiles.*`). A test
  walks every exported type of `certcheck` with `reflect` and fails on an exported field whose
  type's `PkgPath` contains `/internal/` and has no alias in the package's `go doc` golden.

### Testing UI module (`testui/`)

```
testui/
  go.mod          module github.com/vocdoni/cert-check/testui
                  require github.com/vocdoni/cert-check v0.0.0
                  replace github.com/vocdoni/cert-check => ../
  go.sum          committed (covers the root module's dependencies through the replace)
  main.go         (today's cmd/cert-check, incl. the probe subcommand)
  internal/{config,acme,server,probe}/   (moved; server uses certcheck.Handler (AuthAs) and
                  providers.All; server/tlsconfig.go holds the per-SNI dispatch)
  web/            (moved UI; embed and dev server)
  Dockerfile      (build context = repository root: COPY the root module, build ./testui)
  .dockerignore   (at repository root, since the context is the root)
  README.md       (testing UI, configuration, Railway deployment, DNS, rollback, probe, live tests)
```

- The server keeps per-SNI provider hosts:
  - one `certcheck.Handler` holding all providers handles verification (`AuthAs`);
  - per-provider TLS configs come from `Handler.TLSConfig` of a one-provider `Handler` each (see
    Handler).
- `main.go` builds one `*certcheck.Revocation` with `UserAgent: "cert-check/"+version` and the
  JSON logger and passes `WithRevocation`, `WithLogger`, `WithVersion(version)` to `providers.All`,
  so the deployed User-Agent, warnings and `serverVersion` are unchanged (today `main.go:92-100`).
- All HTTP behaviour, JSON contracts, cookies, rate limits and headers are unchanged.
- The probe and the testui e2e/live tests import `internal/profiles`, `internal/engine` and
  `internal/revocation` from the root module (Go's `internal` rule is path-based and the nested
  module path is under the root; verified). The probe reads revocation endpoints from the profile
  data; there is no exported `Endpoints` description and no new public API.
- Live tests (`-tags live`) and the Bewor credential run move with their packages. They build
  providers through `internal/engine.New` over `internal/profiles` data (markers emptied), not
  through the public constructors.
- The plan lists every path-bearing file to update: `.gitattributes`, `.dockerignore`, `ci.yml`
  fuzz targets (`./internal/identity`, `./internal/revocation`, `./internal/engine`),
  `testui/internal/server/fixtures_contract_test.go` fixtures dir, comments in `probe/targets.go`
  and `internal/profiles/anchors/SOURCES.md`.
- `testui/go.sum` is committed; CI runs both modules with `-mod=readonly`.

### CI and deployment

- **CI** (`.github/workflows/ci.yml`, self-hosted runners) runs, for the root module and for
  `testui/`:
  - gofmt, `go mod tidy -diff`, vet (+ `-tags live`), staticcheck, `go test -race` with the R36
    skip check, govulncheck;
  - fuzz smoke (root module);
  - the docker build of `testui/Dockerfile`;
  - the `go doc` golden diff of the root package (AC4).

  The AC12-style dependency check becomes: `go list -deps ./...` in the root module contains no
  `certmagic`, `libdns`, `go.uber.org/zap` or `golang.org/x/time` package (the nested module is
  excluded from `./...` by construction).
- **Railway.** `source.rootDirectory` stays unset (the build context is the repository root, which
  `testui/Dockerfile` needs for the `replace ../`). Immediately before the merge, and in this
  order with nothing in between: (1) `railway environment edit --service-config cert-check
  build.dockerfilePath testui/Dockerfile`; (2) merge to `main`. Between (1) and the end of the
  resulting deploy, trigger no other build (no variable edits, no manual deploys). A failed
  build never replaces the running deployment and the `/readyz` healthcheck gates the swap, so
  a mistake in this window leaves production on the previous image. The README runbook line
  `build.dockerfilePath Dockerfile` becomes `testui/Dockerfile`. Variables, volume, domains, TCP
  proxy, healthcheck and wait-for-CI are unchanged.
- **Rollback.** First `railway redeploy` the previous successful deployment (its image is reused;
  no build, no setting change; expect the usual short outage of a volume-backed service). Only if
  `main` is reverted to the single-module layout, set `build.dockerfilePath` back to `Dockerfile`
  before the revert is pushed.

### Alternatives considered

| Option | Why not |
|---|---|
| Keep one module | Library consumers would inherit certmagic/libdns/zap/x-time requirements in their module graph |
| Provider as plain data + `Checker.Check(provider, chain)` | The owner asked for certificate types that implement an interface; a data-only design pushes plumbing onto every caller |
| Public `identity`/`revocation` packages | Larger API surface to keep stable, for no consumer need today; only `Revocation` (sharing caches) is exposed |
| One package per profile (fnmt-rsa, fnmt-g2…) | A program chooses certificate types, not CA generations; generations are an internal detail of a type |
| Exact blind-csp `AuthHandler` signature | Pulls `go.vocdoni.io/dvote` types into the library; similarity of shape is enough, and an adapter is a few lines in the CSP |

## Compatibility and rollout

- **Import paths change** (`certauth/...` → `certcheck` + `providers/...`). This is a breaking
  change accepted for v0, with no external consumers.
- **JSON contracts are byte-compatible.** The UI fixtures and contract tests continue to pass
  unchanged.

Rollout:
1. Feature branch with all tasks; full suites in both modules; gate audit.
2. Immediately before the merge: set Railway `build.dockerfilePath = testui/Dockerfile`
   (`source.rootDirectory` stays unset); no other builds in the window.
3. Merge/push `main` right after step 2 → CI → Railway deploys. Expect the usual short outage of a
   volume-backed service during the swap.
4. Smoke tests:
   - `/readyz`;
   - providers API with 14 providers;
   - per-SNI CA lists;
   - the no-certificate flow;
   - the Bewor production E2E (`test_certificate`).
5. Owner re-tests FNMT in the browser.

Rollback as in §CI and deployment: redeploy the previous successful deployment first; set
`build.dockerfilePath` back to `Dockerfile` only if `main` is reverted.

## Failure modes and security

- **The risk is regression through moving code.** Mitigations:
  - the security-relevant files (pipeline, OCSP, CRL, fetcher, identity, transaction store, TLS
    config) move with `git mv` plus renames only, and the plan forbids logic edits in them
    beyond import-path and identifier changes; the one declared exception is the
    `provider_mismatch` re-classification moving from the engine to `Handler.VerifyAs`;
  - every existing test moves with its code;
  - the goldens of AC6 (test names, specimen tuples, synthetic `Result` JSON, service goldens)
    are generated before any move and asserted after;
  - live tests and the probe run again;
  - the gate audit reads the moved security files as full diffs against their originals
    (`git diff -M`).
- **Default revocation singleton.** Shared caches across providers are already today's behaviour:
  one revocation checker for all profiles. Cache keys include the issuer, so there is no
  cross-provider poisoning. The per-provider profile ambiguity check (`checkAmbiguity`) moves with
  `internal/profiles`, and `NewHandler` extends it across providers.
- **Handler issuer selection.** It only chooses which pinned provider runs, and `NewHandler`
  rejects ambiguity so acceptance never depends on provider order. Acceptance still needs a full
  `Verify` under that provider's pinned roots, so a forged issuer DN cannot bypass validation.

## Acceptance criteria

- [ ] **AC1** Root module: gofmt, `go mod tidy -diff`, vet (+ live tag), staticcheck,
  `go test -race ./...` with 0 skipped tests, govulncheck; the fuzz targets run 30 s each.
- [ ] **AC2** `testui/` module: the same checks; e2e, fixture-contract and header tests pass;
  `docker build -f testui/Dockerfile .` succeeds.
- [ ] **AC3** Dependency isolation:
  - `cd <root> && go list -deps ./... | grep -E 'certmagic|libdns|go.uber.org/zap|golang.org/x/time'`
    prints nothing (the nested module is excluded from `./...` by construction);
  - the root `go.mod` requires only `golang.org/x/crypto`, `golang.org/x/text` and
    `golang.org/x/sync` directly.
- [ ] **AC4** Public API is exactly: `Provider`, `ProviderInfo`, `ProviderRef`, `Handler`,
  `NewHandler`, `Handler` methods as listed, `Revocation`, `NewRevocation`, `RevocationOptions`,
  `Option` and the `With*` options, `TLSOption` and `WithTLS13`, `CheckHost`, `ErrMisdirected`,
  the result types (`Result`, `Identity`, `Document`, `Organization`, `Date`, `DocumentType`,
  `ProfileInfo`, `Role`, `CertificateInfo`, `RevocationInfo`, `RevocationStatus`,
  `RevocationMethod`), the error types (`Error`, `ErrorCode` + constants, `Codes`,
  `(ErrorCode).Retryable`, `Step` + constants), the diagnostics types (`Diagnostics`,
  `TLSInfo`, `CertificateDetails`, `ChainEntry`, `CandidateResult`, `RevocationAttempt`,
  `(Diagnostics).LogAttrs`, `NewDiagnosticID`, `DescribeTLS`, `DescribeCertificate`) and the
  bounds `DefaultMaxChainLen`, `MaxCertificateDER`. `go doc` output is committed as a golden
  file and diffed in CI. Every `providers/<name>` package exports only constructors; `providers`
  exports `All`, `Standard` and `ByID`.
- [ ] **AC5** `Example` tests in the root package (compiled and run by `go test`) show:
  - choosing certificate types (`idcat.New()`, `fnmt.New()`);
  - building a `Handler`, `TLSConfig` and `Auth` in an `http.Server`;
  - reading `Result.Identity`;
  - handling `*Error`.
- [ ] **AC6** No behaviour change, proven by goldens generated **before** any move (task 0, on
  `main` at the recorded base) and asserted after:
  - `go test -list '.*' ./...` names (not counts) for both trees are diffed; every pre-existing
    name is present (renames are listed in the plan with old → new);
  - **specimen golden**: for every committed specimen and every production provider (built with
    `providers.All()`, a no-network revocation checker and the specimen's `NotBefore+30m` clock,
    through `internal/engine`), the tuple (`Code`, `Retryable`, `Step`, `Detail`,
    `Diagnostics.Provider`, `Diagnostics.ProfileCandidates`, `len(RevocationAttempts)`) equals the
    committed golden JSON;
  - **synthetic golden**: for every `TestProfilesPipeline` fixture the full `Result` JSON
    (`diagnosticId`/`time` masked) equals the committed golden;
  - **service golden**: the `/api/v1/providers` body and, for each of the 14 SNI hosts, the
    ordered `certificate_authorities` subject list observed in the handshake, equal the goldens
    captured on the pre-move server (e2e test on the real providers);
  - the live tests (Bewor credential: success with markers emptied, `test_certificate` with the
    production markers; withheld specimens; probe 0 FAIL) pass.
- [ ] **AC7** `Handler` tests: issuer selection; one candidate; no candidate →
  `untrusted_issuer` with diagnostics; `NewHandler` rejects a shared issuer subject, a
  cross-provider (anchor SPKI, policy OID) ambiguity and an inert provider; `VerifyAs` unknown
  provider and `provider_mismatch`; `Auth`/`AuthAs` (including a request without TLS state);
  `Certificates`/`CertificateCheck`/`ClientCAs` agree; `TLSConfig` policy (TLS 1.2 default, 1.3
  opt-in, tickets off, RequestClientCert, http/1.1).
- [ ] **AC8** READMEs: the root README is package documentation with a runnable quick start and a
  providers table; `testui/README.md` holds the UI and deployment runbook (moved and updated
  paths); no deployment content remains in the root README beyond a link.
- [ ] **AC9** After deploy:
  - CI is green for both modules;
  - Railway builds `testui/Dockerfile`, `/readyz` is 200 and the providers API is unchanged;
  - per-SNI CA lists are unchanged; the Bewor production E2E gives `test_certificate`;
  - the owner's FNMT login still succeeds.

## Constraints

Same as the original spec, plus:
- Use the vocdoni-go skills (`go-code-quality`, `go-modern`, `go-best-practices`): small
  interfaces, docs for users, functional options, typed errors, no stuttering names
  (`certcheck.Provider`, not `certcheck.CertcheckProvider`).
- Moves are done with `git mv` so history follows. Security-relevant files keep their logic
  byte-for-byte apart from package/import/identifier changes (and the declared
  `provider_mismatch` move).
- Commits: conventional commits `type(scope): lowercase summary`; no AI attribution and no
  `Co-Authored-By` trailers.

## Open questions

None after the audit.
