# Library-first restructure: design

Status: draft   Class: architectural
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
   - the result, identity, error and diagnostics types;
   - functional options;
   - a blind-csp-like `Handler`.
2. **One package per certificate issuer** under `providers/`. Each exposes constructors returning
   a `certcheck.Provider`. A program picks certificate types by importing and constructing them,
   e.g. `idcat.New()`, `fnmt.New()`.
3. **Everything that is not public API moves under `internal/`.** That means the pipeline engine,
   identity parsing, revocation (OCSP/CRL/fetcher/caches), anchor loading and the synthetic test
   PKI. The public surface is only what Goals 1–2 name.
4. **No behaviour change.** The existing guarantees stay identical:
   - same pipeline order and checks;
   - byte-identical embedded anchors and the same profile data;
   - same error codes and messages;
   - same `Diagnostics`/`Result` JSON;
   - same TLS policy.

   The existing test suites move with the code and keep passing with the same case counts or
   more.
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
// concurrent use.
type Provider interface {
    // Info describes the provider (stable ID, display name, beta flag).
    Info() ProviderInfo
    // CAs returns the pinned CA certificates a TLS server should advertise
    // in its CertificateRequest for this provider (anchors and pinned
    // intermediates). Callers must not modify them.
    CAs() []*x509.Certificate
    // Verify runs the full validation pipeline on a client certificate chain
    // as received in tls.ConnectionState.PeerCertificates (chain[0] is the
    // leaf). On failure the error is *Error.
    Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error)
}

type ProviderInfo struct {
    ID   string `json:"id"`   // DNS label, e.g. "idcat"; stable
    Name string `json:"name"` // display name, e.g. "idCAT Certificat"
    Beta bool   `json:"beta"`
}

// Result, Identity, Document, Organization, CertificateInfo, RevocationInfo,
// Diagnostics, TLSInfo, Error, ErrorCode (and its constants), Step: as today in
// certauth, with identical JSON. They are declared in, or aliased into, package
// certcheck; consumers never import internal packages.

// Option configures providers and handlers.
type Option func(*options)

func WithRevocation(r *Revocation) Option // share one revocation checker (caches) across providers
func WithClock(now func() time.Time) Option
func WithLogger(l *slog.Logger) Option
func WithVersion(v string) Option         // reported as Diagnostics.serverVersion

// Revocation is a shared OCSP/CRL checker with bounded caches. The zero
// configuration is production-ready.
type Revocation struct{ /* wraps internal/revocation.Checker */ }
func NewRevocation(o RevocationOptions) (*Revocation, error)
type RevocationOptions struct { UserAgent string; OCSPTimeout, CRLTimeout time.Duration; /* cache bounds */ }
```

- **Default revocation.** When no `WithRevocation` is given, providers use one process-wide
  default `*Revocation`, created lazily with `sync.OnceValues`. `idcat.New()` therefore works
  with no arguments, and all default-built providers share caches.

### Certificate types (`providers/…`)

| Package | Constructors (each returns `certcheck.Provider`) | Profiles (unchanged data) |
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

- Each constructor has signature `func New(opts ...certcheck.Option) certcheck.Provider`.
  Embedded anchors are validated (pins, CA flag, expiry) at construction. An invalid embedded
  anchor is a build-time invariant violation, so the constructor panics with a clear message:
  the data is compiled in and tested, which is the "unrecoverable startup failure" case of the
  vocdoni-go rules.
- Each provider package embeds only its own anchors (`anchors/*.pem` plus `SOURCES.md`,
  byte-identical to today's files) and declares its profiles with the internal profile types.
- `providers` (aggregate package) provides convenience constructors in today's display order:
  - `All(opts ...certcheck.Option) []certcheck.Provider`
  - `Standard(…)` (non-beta)
  - `ByID(id string, opts ...certcheck.Option) (certcheck.Provider, bool)`

### Handler (blind-csp-like)

```go
// Handler authenticates HTTP requests that arrived over TLS with a client
// certificate, using a fixed set of certificate types.
type Handler struct{ /* providers, CA index */ }

func NewHandler(providers ...Provider) (*Handler, error) // ≥1 provider, unique IDs
func (h *Handler) Name() string                         // "certcheck"
func (h *Handler) RequireCertificate() bool             // true
func (h *Handler) Certificates() [][]byte               // DER of every advertised CA (dedup)
func (h *Handler) CertificateCheck(subject []byte) bool // DER subject is one of the advertised CAs
func (h *Handler) ClientCAs() *x509.CertPool            // pool for tls.Config.ClientCAs
func (h *Handler) Providers() []Provider
func (h *Handler) TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), opts ...TLSOption) *tls.Config
func (h *Handler) Auth(r *http.Request) (*Result, error) // verifies r.TLS.PeerCertificates
func (h *Handler) Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error)
func (h *Handler) VerifyAs(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error)
```

- **`TLSConfig`** produces today's auth-listener policy:
  - TLS 1.2 by default (`WithTLS13()` TLSOption allows 1.3), and today's cipher suites and
    curves;
  - `RequestClientCert` with `ClientCAs = h.ClientCAs()`;
  - session tickets disabled;
  - ALPN `http/1.1`.
- **`Verify` and `Auth`** select the provider whose advertised CA subjects contain the leaf's
  `RawIssuer` (byte equality).
  - None → `untrusted_issuer`.
  - Several → each is tried in handler order; the first success wins. If none succeeds, the
    most specific error by the existing path-error rank is returned.
  - `Auth` fills `Diagnostics.TLS` from `r.TLS` (today's `tlsauth.Authenticate`).
- **`VerifyAs`** keeps today's per-provider semantics for the testing UI's per-SNI hosts. The
  leaf is verified by the named provider. If it does not verify there but verifies under another
  provider of the handler → `provider_mismatch`, as today.
- **`CheckHost`** (Host≠SNI → error) is a package function, as today in tlsauth.

### Internal packages

| Package | From | Role |
|---|---|---|
| `internal/engine` | `certauth/checker.go` pipeline + `certauth/profiles` types/registry logic | Implements `certcheck.Provider` from a list of profiles; pipeline steps 1–9 unchanged |
| `internal/identity` | `certauth/identity` | unchanged code |
| `internal/revocation` | `certauth/revocation` | unchanged code |
| `internal/testpki` | `internal/testpki` | unchanged (root-module tests) |

- `certauth/tlsauth` is folded into the root package (`Handler`, `CheckHost`, `TLSConfig`).
- Reserved identities and name markers become an internal shared table applied by every provider
  (today `profiles.Registry.Reserved`).
- Test markers (fingerprints) stay per profile.
- Import graph is acyclic: `certcheck` (public types + Handler) ← `internal/engine` ←
  `providers/*`. To avoid a cycle, internal packages must not import `certcheck`. Public types
  that internal packages need are declared in a leaf internal package and aliased into
  `certcheck`, or the engine returns internal types that `certcheck` adapts. The plan decides
  which, with a test that `go list -deps` of `internal/...` never contains the root package if
  that is the chosen direction.

### Testing UI module (`testui/`)

```
testui/
  go.mod          module github.com/vocdoni/cert-check/testui
                  require github.com/vocdoni/cert-check v0.0.0
                  replace github.com/vocdoni/cert-check => ../
  main.go         (today's cmd/cert-check, incl. the probe subcommand)
  internal/{config,acme,server,probe}/   (moved; server uses certcheck.Handler and providers.All)
  web/            (moved UI; embed and dev server)
  Dockerfile      (build context = repository root: COPY the root module, build ./testui)
  .dockerignore   (at repository root, since the context is the root)
  README.md       (testing UI, configuration, Railway deployment, DNS, rollback, probe, live tests)
```

- The server keeps per-SNI provider hosts:
  - one `certcheck.Handler` holding all providers handles verification (`VerifyAs`);
  - per-provider TLS configs come from a one-provider `Handler` each, or from `Provider.CAs()`.
- All HTTP behaviour, JSON contracts, cookies, rate limits and headers are unchanged.
- The probe reads revocation endpoints. It may import the root module's `internal/...` (allowed
  by Go's path-based `internal` rule) or use an exported `Endpoints` description; the plan
  decides, preferring no new public API.
- Live tests (`-tags live`) and the Bewor credential run move with their packages.

### CI and deployment

- **CI** (`.github/workflows/ci.yml`, self-hosted runners) runs, for the root module and for
  `testui/`:
  - gofmt, `go mod tidy -diff`, vet (+ `-tags live`), staticcheck, `go test -race` with the R36
    skip check, govulncheck;
  - fuzz smoke (root module);
  - the docker build of `testui/Dockerfile`.

  The AC12-style dependency check becomes: `go list -deps ./...` in the root module contains no
  `certmagic`, `libdns`, `go.uber.org/zap`, `golang.org/x/time`, or `/testui`.
- **Railway.** Before the restructure reaches `main`, the service's `build.dockerfilePath` is set
  to `testui/Dockerfile`; the build context stays the repository root. Variables, volume,
  domains, TCP proxy, healthcheck and wait-for-CI are unchanged.
- **Rollback:** redeploy the previous deployment and set `build.dockerfilePath` back to
  `Dockerfile`.

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
2. Set Railway `build.dockerfilePath = testui/Dockerfile`.
3. Push `main` → CI → Railway deploys.
4. Smoke tests:
   - `/readyz`;
   - providers API with 14 providers;
   - per-SNI CA lists;
   - the no-certificate flow;
   - the Bewor production E2E (`test_certificate`).
5. Owner re-tests FNMT in the browser.

Rollback as above.

## Failure modes and security

- **The risk is regression through moving code.** Mitigations:
  - the security-relevant files (pipeline, OCSP, CRL, fetcher, identity, transaction store, TLS
    config) move with `git mv` plus renames only, and the plan forbids logic edits in them
    beyond import-path and identifier changes;
  - every existing test moves with its code;
  - a cross-check test compares, for every committed specimen and every synthetic profile
    fixture, the `ErrorCode`/`Step`/identity from the new providers with the expected values
    already pinned in today's tests;
  - live tests and the probe run again;
  - the gate audit reads the moved security files as full diffs against their originals
    (`git diff -M`).
- **Default revocation singleton.** Shared caches across providers are already today's behaviour:
  one revocation checker for all profiles. Cache keys include the issuer, so there is no
  cross-provider poisoning, and the single-profile-per-issuer ambiguity check moves into the
  aggregate `providers` tests.
- **Handler issuer selection.** It only chooses which pinned provider runs. Acceptance still
  needs a full `Verify` under that provider's pinned roots, so a forged issuer DN cannot bypass
  validation.

## Acceptance criteria

- [ ] **AC1** Root module: gofmt, `go mod tidy -diff`, vet (+ live tag), staticcheck,
  `go test -race ./...` with 0 skipped tests, govulncheck; the fuzz targets run 30 s each.
- [ ] **AC2** `testui/` module: the same checks; e2e, fixture-contract and header tests pass;
  `docker build -f testui/Dockerfile .` succeeds.
- [ ] **AC3** Dependency isolation:
  - `cd <root> && go list -deps ./... | grep -E 'certmagic|libdns|go.uber.org/zap|golang.org/x/time|cert-check/testui'`
    prints nothing;
  - the root `go.mod` requires only `golang.org/x/crypto`, `golang.org/x/text` and
    `golang.org/x/sync` directly.
- [ ] **AC4** Public API is exactly Goals 1–2. `go doc github.com/vocdoni/cert-check` lists
  `Provider`, `ProviderInfo`, `Handler`, `NewHandler`, `Revocation`, `NewRevocation`, the options
  and the result/error types. Every `providers/<name>` package exports only constructors.
  `providers` exports `All`, `Standard` and `ByID`.
- [ ] **AC5** `Example` tests in the root package (compiled and run by `go test`) show:
  - choosing certificate types (`idcat.New()`, `fnmt.New()`);
  - building a `Handler`, `TLSConfig` and `Auth` in an `http.Server`;
  - reading `Result.Identity`;
  - handling `*Error`.
- [ ] **AC6** No behaviour change:
  - all pre-existing test cases are present (count ≥ before, recorded in the plan);
  - the specimen double-rejection and per-profile pipeline tests pass unchanged in expectations;
  - live tests (Bewor credential, withheld specimens, probe 0 FAIL) pass.
- [ ] **AC7** `Handler` tests: issuer selection; several candidates; no candidate →
  `untrusted_issuer`; `VerifyAs` provider_mismatch; `Certificates`/`CertificateCheck`/`ClientCAs`
  agree; `TLSConfig` policy (TLS 1.2 default, 1.3 opt-in, tickets off, RequestClientCert,
  http/1.1).
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
  byte-for-byte apart from package/import/identifier changes.
- Commits: conventional commits `type(scope): lowercase summary`; no AI attribution and no
  `Co-Authored-By` trailers.

## Open questions

None at draft time.
