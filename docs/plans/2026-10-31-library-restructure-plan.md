# Library-first restructure: implementation plan

Spec: docs/specs/2026-10-31-library-restructure-design.md (approved 2026-11-01; audit folded; rulings R1-R12)
Class: architectural
Repos and branches: /home/p4u/certificate_poc/cert-check → refactor/library-first (base: the plan commit, whose code is main 4770316)

Reference build. The end state of this plan was built and run in a throwaway copy of the repository
(`~/.cache/cert-check/scratch/restructure-plan/proto/`; non-binding, never copy it wholesale). Every Go
block below compiles there with go1.27.3. gofmt, `go mod tidy -diff`, vet (also `-tags live`),
staticcheck v0.8.2 and `go test -race` are clean in both modules with 0 skipped tests, and
`docker build -f testui/Dockerfile .` succeeds. The AC6 goldens were generated on a copy of the base
(`.../restructure-plan/base/`) with the Task 0 code below, and the prototype passes them unchanged:
812 specimen tuples (550 of them `provider_mismatch` answers that now come from `Handler.VerifyAs`),
60 masked synthetic Result JSONs, the declarations dump (the proof that the `providers.go` split moved
data only), the providers body and the 14 ordered per-SNI CA lists. The last two also match
production today (Task 4's deployed-service test was run against cert-check.vocdoni.dev).

Blocks are binding: implement identifiers, signatures and semantics as written. Any deviation needs a
controller ruling. Tests are listed by name and case. The implementer writes each test before the
code it covers (TDD). Task 0's golden tests and a few public tests are given in full.

## Global Constraints

From the spec:
- Go 1.27. Root module `github.com/vocdoni/cert-check`, package `certcheck` (import it as
  `certcheck "github.com/vocdoni/cert-check"`). Nested module `github.com/vocdoni/cert-check/testui`
  requires the root through `replace github.com/vocdoni/cert-check => ../`.
- Every decision of `docs/specs/2026-10-30-cert-check-design.md` stays in force: pipeline order and
  checks, anchors, OIDs, revocation policy, TLS 1.2 default, diagnostics, deployment topology. This work
  changes structure, not behaviour.
- Moves use `git mv` so history follows. Security-relevant files (pipeline, OCSP, CRL, fetcher,
  identity, transaction store, TLS config) keep their logic byte for byte. Each task lists the files
  that may change logic and the files that may change only package, import and identifier lines.
- Commits: conventional `type(scope): lowercase summary`. No AI attribution and no `Co-Authored-By`
  or similar trailers. Commit with explicit pathspecs (`git commit -m "..." -- <paths>`; for moves
  include both the old and the new directory). Never push.

Added by this plan:
- Before writing Go, invoke the skills `vocdoni-go:go-code-quality`, `vocdoni-go:go-modern` and
  `vocdoni-go:go-best-practices`. Target Go 1.27. Binding rules:
  - Godoc is for users: it states what a name does, its defaults and its errors. It never refers to
    spec sections, rulings, task numbers or unexported helpers.
  - Small consumer-side interfaces. `certcheck.Provider` has three methods and is not sealed. The one
    unexported interface, `pinnedProfiles` in handler.go, is an optional capability check, as
    `http.Flusher` is.
  - Functional options (`Option`, `TLSOption`). Constructors return concrete types, except the
    provider constructors, which return the `certcheck.Provider` interface by design (R1).
  - Typed errors: every verification failure is `*certcheck.Error` with a typed `ErrorCode` and
    `Step`. Construction errors are plain errors prefixed with the package name (`certcheck:`,
    `engine:`, `profiles:`, `server:`). `%w` is used only where the caller may inspect the wrapped error.
  - No stutter: `certcheck.Provider`, `certcheck.Handler`, `engine.New`, `engine.Config`,
    `server.AuthHosts`.
  - Panic only for build-time invariants. The provider constructors panic on corrupt embedded data
    (R5), and `WithRevocation` panics on a nil or zero `*Revocation` (a programmer error).
  - Use modern forms: `errors.AsType`, `slices`/`maps`, `t.Context()`, `wg.Go`, `new(v)`,
    `reflect.TypeFor`, `for range n`.
- Environment for every go and docker command. Never write to `/tmp`:
  `export TMPDIR=$HOME/.cache/cert-check/tmp GOTMPDIR=$HOME/.cache/cert-check/gotmp && mkdir -p "$TMPDIR" "$GOTMPDIR"`.
  Tag docker images `cert-check:task<N>` and remove them afterwards.
- Dependencies. The root `go.mod` requires only `golang.org/x/crypto`, `golang.org/x/sync` and
  `golang.org/x/text` (AC3). `testui/go.mod` is exactly the block in Task 1. Both `go.sum` files are
  committed and change only through `go mod tidy`. No new direct dependency. Tools run as
  `go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...` and
  `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`.
- Goldens. Task 0 writes `testdata/golden/*` once, on the base code, with `-update-golden`. After
  Task 0 nothing writes them again. A task that cannot pass a golden stops and reports; it never
  regenerates the golden. The gate checks `git diff <task-0 commit> HEAD -- testdata/golden` is empty.
- Interpretation of the spec, binding on every task (each item was checked in the prototype):
  - P1. `Handler.VerifyAs` re-classifies against the union of every provider in the handler, the
    named one included. That is today's `Registry.AllAnchors`. The spec text says "the other
    providers", but it also says "exactly as today's unknownAuthorityCode". This reading gives
    identical answers on all 812 specimen rows.
  - P2. The Handler needs the anchor/intermediate split and each profile's policy OIDs, which
    `Provider` does not expose. It gets them through the unexported optional interface
    `pinnedProfiles { EnabledProfiles() []*profiles.Enabled }`, which `*engine.Provider` implements. A
    consumer's test double without that method contributes every `CAs()` entry as a trust anchor, and
    only the shared-subject check applies to it. No public API is added.
  - P3. `certcheck` imports `internal/profiles` (for the `Role` and `ProfileInfo` aliases and
    `CheckAmbiguity`) and `internal/opts`, as well as `internal/identity` and `internal/revocation`.
    The CI import-graph check covers all four, and none of them imports the root.
  - P4. `engine.Config` has a `Reserved *identity.Reserved` field. nil means
    `identity.DefaultReserved()`; the markers-emptied runs pass `&identity.Reserved{}`.
  - P5. Engine step 1 answers `provider has no enabled profile` (inert provider, R5) where today's code
    answered `unknown provider`. `unknown provider` now comes only from `Handler.VerifyAs`.
  - P6. `Handler.Verify` on a chain without a leaf answers `no_certificate` at `bounds` with detail
    `no client certificate`. A leaf whose issuer no provider advertises answers `untrusted_issuer` at
    `path` with detail `no provider advertises the leaf's issuer`.
  - P7. The specimens move to `testdata/specimens/`. The only profile-data change is the prefix of the
    fingerprint markers' `Source` (`certauth/testdata/specimens/` becomes `testdata/specimens/`), which
    the declarations golden strips.
  - P8. `internal/profiles/anchors/` stays byte-identical, `SOURCES.md` included (100% renames). Its
    prose still names `providers.go` as the place of the pins; the root README explains the split.
  - P9. `Registry.AllAnchors` and its `allRoots`/`allInter` fields are deleted. `TestAllAnchors` keeps
    its name and its other checks and loses only the `AllAnchors` assertions.
  - P10. The testui e2e world gives `beta` its own CA, because `NewHandler` rejects two providers that
    advertise one CA. No e2e expectation changes.
  - P11. The testing UI refuses to start with zero providers. Today it started and stayed unready.
    This follows from R5, and every anchor would have to expire first.
  - P12. The synthetic golden masks `diagnosticId`, `serialHex`, `sha256` and `durationMs`, and writes
    every timestamp as an offset from the fixture clock: keys, serials and times differ on every run.
    Everything else is compared byte for byte, in encoder field order.
  - P13. Copy-splits. Git can follow only one destination per file, so four files split:
    - `providers.go` → 12 provider files (the split the spec documents);
    - `tlsauth.go` → `testui/internal/server/tlsconfig.go` by `git mv`, plus a copy of its TLS policy,
      `CheckHost` and `Authenticate` into the root `tls.go`;
    - `tlsauth_test.go` → `testui/.../tlsconfig_test.go` by `git mv`, plus five tests copied to the
      root `tls_test.go`;
    - `diagnostics.go` → root by `git mv`, plus `reportAttempts` and `keyAlgorithm` copied to
      `internal/engine/report.go`.
  - P14. The engine keeps the identifiers of the moved code through type and constant aliases in
    `internal/engine/compat.go`. A `git diff -M` of `checker.go` therefore shows only the declared
    changes.
  - P15. No top-level test is renamed: the old → new table is empty. Five tests move to the root
    package with their names. Subtests renamed: `TestNewCheckerOptions/no registry` →
    `invalid declaration`; `TestServerConfigRequiresOptions/no checker` → `no providers`;
    `TestNewRequiresDeps/no checker` → `no providers`.
  - P16. AC4 is exact. The aliased enum types (`Role`, `DocumentType`, `RevocationStatus`,
    `RevocationMethod`) get no re-exported constants. Examples and the README compare them through
    their string values.
- End-of-task checks, from the repository root, for the task's module set ("root" is `.`; "both" is
  `.` and `testui`):
  - `test -z "$(gofmt -l .)"`;
  - in each module: `go mod tidy -diff`; `go vet ./... && go vet -tags live ./...`; staticcheck;
    `go test -race -count=1 -json ./... > $TMPDIR/<module>.json`, then
    `grep -c '"Action":"fail"'` prints 0 and `grep '"Action":"skip"' | grep -c '"Test":'` prints 0;
  - when both modules compile (Tasks 0, 1, 4 and 5), the test-name check prints nothing:

    ```sh
    export LC_ALL=C
    list() { (cd "$1" && go test -list '.*' -tags live ./... | grep -E '^(Test|Fuzz|Example|Benchmark)'); }
    comm -23 <(cut -d' ' -f2 testdata/golden/test-names.txt | sort) \
             <(for m in . testui; do [ -f "$m/go.mod" ] && list "$m"; done | sort)
    ```

  After Task 2 and until Task 4 the testui module does not compile (its imports point at the removed
  `certauth`). This is expected. Tasks 2 and 3 run the checks on the root module only.
- Tests:
  - No network beyond loopback and `testpki.Net`. Live checks live only in `//go:build live` files.
    Clocks are fixed inside each fixture's validity.
  - Table-driven with got/want.
  - Never `t.Skip`: CI fails on any skipped test.
- Privacy: no certificate values in error strings, `Error.Detail` or logs. Logs carry only
  `Diagnostics.LogAttrs()`.

## Review Focus

The controller and the gate audit read these paths in full. "Base" is the plan commit.
- `internal/engine/checker.go` against base `certauth/checker.go`
  (`git diff -M <base> HEAD -- certauth/checker.go internal/engine/checker.go`). Allowed changes:
  package and imports; `Options`/`Checker`/`NewChecker` → `Config`/`Provider`/`New` (a one-provider
  registry, `Info`, `CAs`, `EnabledProfiles`); `Check(ctx, providerID, chain)` →
  `Verify(ctx, chain)` with `providerID := c.id`; the step 1 detail (P5); `ProviderRef` in the
  Result; `unknownAuthorityCode` deleted and `CodeUntrustedIssuer` at rank unknown-authority
  (base `checker.go:372-392`). Nothing in steps 2-9 changes.
- `handler.go`:
  - the `NewHandler` checks (at least one provider; no nil provider; unique IDs; no inert provider;
    no CA subject shared between providers; `profiles.CheckAmbiguity` over every provider's enabled
    profiles);
  - `Verify` issuer selection;
  - the `VerifyAs` re-classification and `chainsToPinnedCA`, which must match base
    `checker.go:381-392` line for line apart from the pools' origin (P1, P2);
  - `fail`, which fills Diagnostics as base `checker.go:124-133` does.
- `tls.go`:
  - `TLSConfig` against base `certauth/tlsauth/tlsauth.go:33-40,54-75`;
  - `Auth`/`AuthAs` against `tlsauth.go:136-151`;
  - `CheckHost` against `tlsauth.go:115-129`.
- `testui/internal/server/tlsconfig.go` against base `tlsauth.go:42-113`: `GetConfigForClient`, the
  unknown-SNI rejection, `maxLoggedSNI` and `AuthHosts.Provider` are unchanged, and each per-SNI
  config is `Handler.TLSConfig` of a one-provider handler.
- `testui/internal/server/auth.go` (`validate`, `serverError`) and `app.go` (handler construction,
  `/readyz`, the provider set used by create).
- `internal/revocation/**`, `internal/identity/**`, `testui/internal/server/{txstore,http}.go`,
  `internal/profiles/anchors/**`: renames only (`git diff -M --stat` shows `| 0` or 100%; `txstore.go`
  changes only `certauth.` → `certcheck.` qualifiers).
- `internal/profiles/{registry,types}.go` (declared edits only) and the 12 provider files (data equal
  to the declarations golden).
- `testui/main.go`: User-Agent `cert-check/<version>`, JSON logger and version still reach the
  revocation checker, the warnings and `serverVersion` (R7).
- `testdata/golden/**`: unchanged after Task 0.
- `testui/Dockerfile`, `.dockerignore`, `.github/workflows/ci.yml`.

## Task order and parallelism

| Task | Depends on | Repo/files | May run in parallel with |
|---|---|---|---|
| 0 Goldens on the base (opus) | none | `internal/testpki/golden.go`, three `golden_test.go`, `testdata/golden/*`, `.gitattributes` | none |
| 1 Move-only restructure, two commits (sonnet) | 0 | `certauth/{identity,revocation,profiles,testdata,tlsauth}` → `internal/`, `testdata/`, `testui/`; `cmd/`, `internal/{server,acme,config,probe}`, `web/` → `testui/`; go.mod files; Dockerfile; CI | none |
| 2 Library core (opus) | 1 | root `*.go` (types, diagnostics, doc, provider, options, revocation, handler), `internal/opts`, `internal/engine`, `internal/profiles/{registry,types}.go` | none |
| 3 Providers, options plumbing, TLS (opus) | 2 | `providers/**`, `internal/engine/options.go`, root `tls.go`, root `world_test.go`/`handler_test.go` (first tests) | 6 |
| 4 Testing UI on the new API (opus) | 3 | `testui/**` (Go only) | 6 |
| 5 Public tests, API golden, CI (opus) | 4 | root `*_test.go`, `testdata/godoc.golden`, `internal/opts/opts_test.go`, `testui/internal/server/tlsconfig_test.go`, `.github/workflows/ci.yml` | 6 |
| 6 READMEs (sonnet) | 3 | `README.md`, `testui/README.md` | 4, 5 (own worktree) |

Line budget, counting added and removed lines but not pure renames: Task 0 about 450 plus generated
goldens (about 510 KB, generated rather than reviewed line by line); Task 1 about 700; Task 2 about
1150; Task 3 about 900; Task 4 about 650; Task 5 about 1000; Task 6 about 700 of prose.

## Tasks

### Task 0: capture the AC6 goldens on the base

Model: opus   Repo: /home/p4u/certificate_poc/cert-check (branch `refactor/library-first`, base code)
Files: `internal/testpki/golden.go` (new), `certauth/golden_test.go` (new),
`certauth/profiles/golden_test.go` (new), `internal/server/golden_test.go` (new),
`testdata/golden/{synthetic.jsonl,specimens.jsonl,declarations.json,providers.json,certificate-authorities.json,test-names.txt}`
(generated), `.gitattributes` (+1 line).
Goal: AC6. Capture the no-behaviour-change baselines before any file moves: test names, specimen
tuples, synthetic Result JSON, the declarations dump, and the service goldens.

Logic changes allowed: none. The task only adds files, plus one `.gitattributes` line.

Step 1: add the golden helper. `testpki` is imported only by tests, and the AC12 CI step checks that.

```go
package testpki

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden rewrites the AC6 golden files. It is used once, on the base
// commit of the library restructure; afterwards the goldens never change.
var updateGolden = flag.Bool("update-golden", false, "rewrite the golden files under testdata/golden")

// Golden compares got with the golden file at path, or rewrites the file when
// the test binary runs with -update-golden. A mismatch reports the first
// differing line.
func Golden(t testing.TB, path string, got []byte) {
	t.Helper()
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v", path, err)
	}
	if bytes.Equal(got, want) {
		return
	}
	gotLines, wantLines := bytes.Split(got, []byte("\n")), bytes.Split(want, []byte("\n"))
	for i := range max(len(gotLines), len(wantLines)) {
		var g, w []byte
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if !bytes.Equal(g, w) {
			t.Fatalf("golden %s differs at line %d:\n got: %s\nwant: %s", path, i+1, g, w)
		}
	}
}
```

Step 2: add the pipeline goldens (package `certauth`, internal test). They reuse `newPPPKI`,
`ppShapes`, `p.check`, `tRegistry`, `tErr`, `tNow` and `tDiscard`.

```go
package certauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// AC6 goldens of the library restructure, captured on its base commit: the
// pipeline outcome of every committed specimen under every production
// provider, and the full Result JSON of every synthetic profile fixture.
const (
	goldenDir         = "../testdata/golden"
	goldenSpecimenDir = "testdata/specimens"
)

var (
	goldenTimeRe = regexp.MustCompile(`"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)"`)
	goldenMaskRe = regexp.MustCompile(`"(diagnosticId|serialHex|sha256)":"[0-9a-f]*"`)
	goldenDurRe  = regexp.MustCompile(`"durationMs":\d+`)
)

// goldenMask rewrites the values that change from run to run: random
// diagnostic IDs, serials and hashes, durations, and times (as offsets from
// the fixture clock). Everything else is compared byte for byte.
func goldenMask(raw []byte, now time.Time) string {
	s := goldenMaskRe.ReplaceAllString(string(raw), `"$1":"<masked>"`)
	s = goldenDurRe.ReplaceAllString(s, `"durationMs":0`)
	return goldenTimeRe.ReplaceAllStringFunc(s, func(m string) string {
		t, err := time.Parse(time.RFC3339Nano, strings.Trim(m, `"`))
		if err != nil {
			return m
		}
		d := t.Sub(now)
		if d < 0 {
			return `"now-` + (-d).String() + `"`
		}
		return `"now+` + d.String() + `"`
	})
}

// TestGoldenSynthetic: the masked Result (or *Error) JSON of every
// TestProfilesPipeline shape, with OCSP up and with OCSP down.
func TestGoldenSynthetic(t *testing.T) {
	now := tNow()
	p := newPPPKI(t, now)
	reg := tRegistry(t, p.providers, now)
	var (
		mu  sync.Mutex
		out = map[string]string{}
	)
	t.Run("shapes", func(t *testing.T) {
		for _, s := range ppShapes(t) {
			t.Run(s.name, func(t *testing.T) {
				t.Parallel()
				leaf := p.issue(t, s)
				for _, mode := range []struct {
					name string
					mode ppMode
				}{{"ocsp", ppOCSPUp}, {"ocsp-down", ppOCSPDown}} {
					res, err := p.check(t, reg, s, leaf, mode.mode, nil)
					var raw []byte
					var merr error
					if err != nil {
						raw, merr = json.Marshal(tErr(t, err))
					} else {
						raw, merr = json.Marshal(res)
					}
					if merr != nil {
						t.Fatal(merr)
					}
					mu.Lock()
					out[s.name+"|"+mode.name] = goldenMask(raw, now)
					mu.Unlock()
				}
			})
		}
	})
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(out)) {
		b.WriteString(`{"case":"` + k + `","json":` + out[k] + "}\n")
	}
	testpki.Golden(t, filepath.Join(goldenDir, "synthetic.jsonl"), []byte(b.String()))
}

// goldenSpecimen is one specimen golden row.
type goldenSpecimen struct {
	Case               string            `json:"case"` // file|provider|run
	Code               ErrorCode         `json:"code"`
	Retryable          bool              `json:"retryable"`
	Step               Step              `json:"step"`
	Detail             string            `json:"detail"`
	Provider           string            `json:"provider"`
	ProfileCandidates  []CandidateResult `json:"profileCandidates"`
	RevocationAttempts int               `json:"revocationAttempts"`
}

func goldenNoNetwork(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("golden: no network")
}

// TestGoldenSpecimens: every committed specimen presented to every
// production provider, clock at NotBefore+30m, no network; run "markers"
// uses the production test markers and reserved identities, run "emptied"
// empties both (the pipeline then reaches revocation).
func TestGoldenSpecimens(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(goldenSpecimenDir, "*.pem"))
	if err != nil || len(files) != 29 {
		t.Fatalf("specimens: %v (%d files, want 29)", err, len(files))
	}
	var b strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(raw)
		if blk == nil {
			t.Fatalf("%s: no PEM block", f)
		}
		leaf, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		clock := leaf.NotBefore.Add(30 * time.Minute)
		now := func() time.Time { return clock }
		for _, run := range []string{"markers", "emptied"} {
			decls, reserved := profiles.DefaultProviders(), identity.DefaultReserved()
			if run == "emptied" {
				for i := range decls {
					for j := range decls[i].Profiles {
						decls[i].Profiles[j].TestMarkers = nil
					}
				}
				reserved = identity.Reserved{}
			}
			rc, err := revocation.NewChecker(revocation.Options{DialContext: goldenNoNetwork, Now: now, Logger: tDiscard})
			if err != nil {
				t.Fatal(err)
			}
			reg, err := profiles.New(profiles.Config{Providers: decls, Reserved: reserved, Now: clock, Logger: tDiscard})
			if err != nil {
				t.Fatal(err)
			}
			chk, err := NewChecker(Options{Registry: reg, Revocation: rc, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range profiles.DefaultProviders() {
				res, err := chk.Check(t.Context(), d.ID, []*x509.Certificate{leaf})
				e, ok := errors.AsType[*Error](err)
				if !ok || res != nil {
					t.Fatalf("%s on %s (%s): (%v, %v), want *Error", filepath.Base(f), d.ID, run, res, err)
				}
				line, err := json.Marshal(goldenSpecimen{Case: filepath.Base(f) + "|" + d.ID + "|" + run, Code: e.Code,
					Retryable: e.Retryable, Step: e.Diagnostics.FailedStep, Detail: e.Detail, Provider: e.Diagnostics.Provider,
					ProfileCandidates: e.Diagnostics.ProfileCandidates, RevocationAttempts: len(e.Diagnostics.RevocationAttempts)})
				if err != nil {
					t.Fatal(err)
				}
				b.Write(line)
				b.WriteByte('\n')
			}
		}
	}
	testpki.Golden(t, filepath.Join(goldenDir, "specimens.jsonl"), []byte(b.String()))
}
```

Step 3: add the declarations golden. It is the proof for Task 1's copy-split.

```go
package profiles_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// specimenSource is the directory prefix of the fingerprint markers' Source,
// which follows the specimens when they move; the golden stores file names.
const specimenSource = "certauth/testdata/specimens/"

// TestGoldenDeclarations: every production declaration (AC6 golden of the
// restructure; it proves the providers.go split moved data only).
func TestGoldenDeclarations(t *testing.T) {
	decls := profiles.DefaultProviders()
	for i := range decls {
		for j := range decls[i].Profiles {
			for k := range decls[i].Profiles[j].TestMarkers {
				m := &decls[i].Profiles[j].TestMarkers[k]
				m.Source = strings.TrimPrefix(m.Source, specimenSource)
			}
		}
	}
	got, err := json.MarshalIndent(decls, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	testpki.Golden(t, filepath.Join("..", "..", "testdata", "golden", "declarations.json"), append(got, '\n'))
}
```

Step 4: add the service golden (package `server_test`). It reuses `startE2E`, `e2eLogs`, `e2eClock`,
`e2eVersion` and `e2eAuthDomain`.

```go
package server_test

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

const goldenDir = "../../testdata/golden"

// goldenCA is one certificate_authorities entry of a handshake.
type goldenCA struct {
	DER  string `json:"der"`  // hex of the DER distinguished name
	Name string `json:"name"` // RFC 4514, for readers
}

// TestGoldenService serves the production providers and records the
// providers API body and, for each provider host, the ordered
// certificate_authorities list of the CertificateRequest (AC6 golden).
func TestGoldenService(t *testing.T) {
	logs := &e2eLogs{}
	reg, err := profiles.Default(time.Now(), logs.logger())
	if err != nil {
		t.Fatalf("profiles.Default: %v", err)
	}
	rc, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/golden", Logger: logs.logger()})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	checker, err := certauth.NewChecker(certauth.Options{Registry: reg, Revocation: rc, Version: e2eVersion})
	if err != nil {
		t.Fatalf("certauth.NewChecker: %v", err)
	}
	s := startE2E(t, checker, logs, &e2eClock{t: time.Now()})

	resp, body := s.do(t, s.request(t, http.MethodGet, "/api/v1/providers", "", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/providers: %d", resp.StatusCode)
	}
	testpki.Golden(t, filepath.Join(goldenDir, "providers.json"), body)

	var providers []struct{ ID string }
	if err := json.Unmarshal(body, &providers); err != nil || len(providers) != 14 {
		t.Fatalf("providers body: %v (%d providers, want 14)", err, len(providers))
	}
	cas := map[string][]goldenCA{}
	for _, p := range providers {
		sni := p.ID + "." + e2eAuthDomain
		var got [][]byte
		conn, err := net.DialTimeout("tcp", s.authAddr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c := tls.Client(conn, &tls.Config{ServerName: sni, RootCAs: s.pool,
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				got = cri.AcceptableCAs
				return &tls.Certificate{}, nil
			}})
		if err := c.HandshakeContext(t.Context()); err != nil {
			t.Fatalf("handshake %s: %v", sni, err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("close %s: %v", sni, err)
		}
		if len(got) == 0 {
			t.Fatalf("%s: no certificate_authorities", sni)
		}
		for _, der := range got {
			var rdn pkix.RDNSequence
			if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) != 0 {
				t.Fatalf("%s: CA name: %v", sni, err)
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			cas[sni] = append(cas[sni], goldenCA{DER: hex.EncodeToString(der), Name: name.String()})
		}
	}
	got, err := json.MarshalIndent(cas, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	testpki.Golden(t, filepath.Join(goldenDir, "certificate-authorities.json"), append(got, '\n'))
}
```

Step 5: generate and assert:
- `go test -count=1 -run '^TestGolden' ./certauth/ ./certauth/profiles/ ./internal/server/ -update-golden`
  writes the five JSON goldens. Then run it twice without the flag, with `-race`: both runs pass.
- Generate the test names last, so that the four golden tests are protected too:

  ```sh
  export LC_ALL=C
  for p in $(go list ./...); do
    go test -list '.*' -tags live "$p" | grep -E '^(Test|Fuzz|Example|Benchmark)' | sed "s|^|$p |"
  done | sort > testdata/golden/test-names.txt
  ```

  Expected: 233 lines (229 base names plus the 4 golden tests). `specimens.jsonl` has 812 lines,
  `synthetic.jsonl` has 60, `providers.json` lists 14 providers, and `certificate-authorities.json`
  has 14 hosts.
- Add `testdata/** -text` to `.gitattributes` so the goldens are stored byte for byte.
- Run the end-of-task checks on the root module, and the test-name check.

Step 6: commit
`git commit -m "test(golden): capture restructure baselines on the base commit" -- internal/testpki/golden.go certauth/golden_test.go certauth/profiles/golden_test.go internal/server/golden_test.go testdata/golden .gitattributes`

Tests added: `TestGoldenSynthetic`, `TestGoldenSpecimens`, `TestGoldenDeclarations` and
`TestGoldenService` (AC6). Later tasks move them with their packages and change only their
construction lines and paths, as each task states.

Interfaces this task provides: `testpki.Golden(t, path, got)`, the `-update-golden` flag (Task 0
only), and the golden files.

### Task 1: move-only restructure (internal packages, specimens, testing UI module)

Model: sonnet   Repo: same branch
Goal: AC1, AC2, AC3 (module split). Moves only, with every importer fixed. The tree builds and
passes after each of the two commits: after (a) the single module, after (b) both modules.

Logic changes allowed: none. Allowed edits:
- package clauses, import paths and qualifiers;
- relative paths in tests;
- the exported names of the provider declarations;
- `ByID` (new, 9 lines) with its test;
- go.mod and go.sum files;
- the Dockerfile, `.dockerignore`, `.gitattributes` and CI path lines;
- doc-comment path mentions.

Every non-test `.go` file under `internal/identity` and `internal/revocation`, and every file under
`internal/profiles/anchors/`, must be a 100% rename.

Commit (a): internal packages and specimens.
1. Move:
   - `git mv certauth/identity internal/identity`
   - `git mv certauth/revocation internal/revocation`
   - `git mv certauth/profiles internal/profiles`
   - `git mv certauth/testdata/specimens testdata/specimens` (`certauth/testdata/` is then empty).
2. Rewrite imports in every `.go` file: `cert-check/certauth/identity` → `cert-check/internal/identity`,
   `.../certauth/revocation` → `.../internal/revocation`, `.../certauth/profiles` → `.../internal/profiles`.
   Run gofmt afterwards, because import order changes.
3. Split `internal/profiles/providers.go` (the documented copy-split). Move each function verbatim
   into its new file and export its name:
   - `fnmt.go`: `fnmt5734`, `fnmtSAN`, `fnmt` → `FNMT`, `fnmtRepresentative` → `FNMTRepresentative`,
     `fnmtEmployee` → `FNMTEmployee`;
   - `idcat.go`: `IDCAT`;
   - `accv.go`: `ACCV`;
   - `digitel.go`: `Digitel`;
   - `bewor.go`: `Bewor`;
   - `sectigo.go`: `Sectigo`;
   - `firmaprofesional.go`: `Firmaprofesional`, `KnownAliases`;
   - `anf.go`: `ANF`;
   - `uanataca.go`: `Uanataca`;
   - `signe.go`: `SIGNE`;
   - `lleidanet.go`: `Lleidanet`;
   - `dnie.go`: `DNIe`, `IntermediateExceptions`.

   Each function keeps its leading comment, with only the name changed.

   `providers.go` keeps:
   - the header comment, with the specimen path updated;
   - `anchor`, `fp`, `oid`, the `dniNIE`…`noSAN` vars, `plain`, `sanAttrs`, `fp13177`, `policy` and
     `person`;
   - `DefaultProviders`, renamed to `All` (same body, calling the exported names);
   - the new `ByID`:

   ```go
   // ByID returns the production provider declaration with the given ID.
   func ByID(id string) (Provider, bool) {
   	for _, p := range All() {
   		if p.ID == id {
   			return p, true
   		}
   	}
   	return Provider{}, false
   }
   ```
4. Update every caller of `profiles.DefaultProviders` to `profiles.All`: `registry.go` `Default`, the
   probe, and the tests.
5. Change the `fp()` marker prefix to `"testdata/specimens/"` (P7).
6. Path edits:
   - `certauth/specimens_test.go`: `specimenDir = "../testdata/specimens"`;
   - `certauth/pathmap_test.go`: `filepath.Join("..", "testdata", "specimens", "*.pem")`;
   - `certauth/golden_test.go`: `goldenSpecimenDir = "../testdata/specimens"`;
   - `internal/identity/specimens_test.go`: `specimenDir = "../../testdata/specimens"`;
   - `internal/profiles/specimens_test.go`: `specTDir = "../../testdata/specimens"`;
   - `internal/profiles/providers_test.go:530`: `"testdata/specimens/" + r.file`;
   - `internal/profiles/golden_test.go`: `specimenSource = "testdata/specimens/"`, `profiles.All()`;
   - `internal/probe/probe_test.go:396` and `internal/probe/live_test.go:29`:
     `"../../testdata/specimens"`.
7. Doc-line edits, comments only:
   - `internal/revocation/testdata/crl/SOURCES.md:4` (`internal/revocation/crl_test.go`);
   - `internal/profiles/testdata/SOURCES.md:1` (`# internal/profiles/testdata: SOURCES`);
   - `internal/identity/adapter_test.go:17` (`internal/profiles`);
   - `internal/probe/targets.go:115` and `internal/server/live_test.go:22`
     (`testdata/specimens/MANIFEST.md`).
8. `.gitattributes`:
   - replace the four `certauth/...` lines with `internal/profiles/anchors/** -text`,
     `internal/revocation/testdata/** -text` and `internal/profiles/testdata/** -text`;
   - `testdata/** -text` from Task 0 covers the specimens.
9. `ci.yml`:
   - the fuzz loops use `./internal/identity` and `./internal/revocation`;
   - the AC12 grep becomes `grep -E 'github.com/vocdoni/cert-check/(internal/(server|acme|config|probe)|web)'`.
10. New test `TestAllAndByID`, in `internal/profiles/providers_test.go`: `ByID` returns each `All()`
    entry with the same ID; `ByID("nope")` returns false.
11. Checks on the root module, and the test-name check. `TestGoldenDeclarations` must pass: that is
    the proof of the split.

Commit (a): `git commit -m "refactor(internal): move identity, revocation, profiles and specimens out of certauth" -- certauth internal testdata .gitattributes .github cmd`

Commit (b): the testing UI module.
1. Move:
   - `git mv cmd/cert-check/main.go testui/main.go` and `git mv cmd/cert-check/main_test.go testui/main_test.go`;
   - `git mv internal/server testui/internal/server`, and likewise `acme`, `config` and `probe`;
   - `git mv web testui/web`;
   - `git mv certauth/tlsauth/tlsauth.go testui/internal/server/tlsconfig.go`;
   - `git mv certauth/tlsauth/tlsauth_test.go testui/internal/server/tlsconfig_test.go`;
   - `git mv Dockerfile testui/Dockerfile`.
2. In `tlsconfig.go`, change only the package clause to `package server` and keep every identifier.
   In `app.go` and `auth.go`, drop the `tlsauth` import and the `tlsauth.` qualifiers.
   `tlsconfig_test.go` becomes `package server_test`: it imports
   `github.com/vocdoni/cert-check/testui/internal/server`, and `tlsauth.` becomes `server.`.
3. Rewrite imports `cert-check/internal/{server,acme,config,probe}` →
   `cert-check/testui/internal/...` and `cert-check/web` → `cert-check/testui/web`.
4. Path edits:
   - `testui/internal/server/golden_test.go`: `goldenDir = "../../../testdata/golden"`;
   - `testui/internal/probe/{probe,live}_test.go`: `"../../../testdata/specimens"`;
   - `fixtures_contract_test.go` keeps `../../web/testdata/fixtures`, which is still correct.
   - The `testui/web/internal/devserver/main.go` doc says "Run it from testui/:
     go run ./web/internal/devserver". The flag default is unchanged.
5. Modules:
   - write `testui/go.mod` exactly as below;
   - run `go mod tidy` in the root module: its `go.mod` then requires only x/crypto, x/sync and
     x/text, and `go.sum` shrinks;
   - run `(cd testui && go mod tidy)` to create `testui/go.sum`;
   - both `go mod tidy -diff` must be clean.

```text
module github.com/vocdoni/cert-check/testui

go 1.27

require (
	github.com/caddyserver/certmagic v0.25.6
	github.com/libdns/cloudflare v0.2.2
	github.com/vocdoni/cert-check v0.0.0
	golang.org/x/time v0.16.0
)

require (
	github.com/caddyserver/zerossl v0.1.6 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/mholt/acmez/v3 v3.1.7 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/vocdoni/cert-check => ../
```

6. Dockerfile (`testui/Dockerfile`; the build context is the repository root):

```dockerfile
# syntax=docker/dockerfile:1

# Build context: the repository root (Railway: source.rootDirectory unset,
# build.dockerfilePath testui/Dockerfile; locally: docker build -f testui/Dockerfile .).
# The testui module requires the root module through `replace => ../`.

# golang:1.27 (multi-arch index, resolved 2026-10-31 with `docker buildx imagetools inspect golang:1.27`)
FROM golang:1.27@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY testui/go.mod testui/go.sum ./testui/
WORKDIR /src/testui
RUN go mod download
WORKDIR /src
COPY . .
WORKDIR /src/testui
ARG RAILWAY_GIT_COMMIT_SHA=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${RAILWAY_GIT_COMMIT_SHA}" -o /out/cert-check .

# gcr.io/distroless/static-debian12:nonroot (multi-arch index, resolved 2026-10-31 with
# `docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot`)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/cert-check /cert-check
EXPOSE 8080 8443
ENTRYPOINT ["/cert-check"]
```

   `.dockerignore`:

```text
.git
.delivery
.claude
docs
**/*_test.go
**/testdata
testui/web/internal
```

   `.gitattributes`: `testui/web/static/fonts/** -text`, `testui/web/static/favicon.ico -text`.
7. `ci.yml`. Start from the final workflow in Task 5 and leave out three things that do not exist yet:
   - the `public API (AC4 go doc golden)` step;
   - the `test names (AC6 golden)` step;
   - the `go list -deps ./internal/identity ...` line of the dependency step.

   The QC fuzz line stays `./certauth` until Task 2. Concretely:
   - every module step loops over `$MODULES` (". testui");
   - `cache-dependency-path` lists both `go.sum` files;
   - the AC12 step becomes the AC3 dependency step: the root `go list -deps ./...` has no
     certmagic, libdns, zap or x/time, and the testpki import check runs in both modules;
   - docker builds `-f testui/Dockerfile .`.
8. Checks on both modules, the test-name check, and
   `docker build -f testui/Dockerfile -t cert-check:task1 . && docker image rm cert-check:task1`.

Commit (b): `git commit -m "refactor(testui): move the testing ui and its deployment into a nested module" -- cmd internal web certauth testui Dockerfile .dockerignore .gitattributes .github go.mod go.sum`

Reviewer commands:
- `git diff -M --stat HEAD~2 HEAD`;
- `git diff -M100% --name-status HEAD~2 HEAD -- internal/identity internal/revocation internal/profiles/anchors | grep -v '^R100'`:
  only test files with path edits;
- `git diff -M HEAD~2 HEAD -- certauth/profiles/providers.go internal/profiles/providers.go`;
- `git diff -M HEAD~1 HEAD -- certauth/tlsauth/tlsauth.go testui/internal/server/tlsconfig.go`: the
  package line only.

Tests: none new except `TestAllAndByID`. Every test passes unchanged in its new location.

Interfaces provided:
- `profiles.All()`, `profiles.ByID(id)`;
- `profiles.FNMT()`, `FNMTRepresentative()`, `FNMTEmployee()`, `IDCAT()`, `ACCV()`, `Digitel()`,
  `Bewor()`, `Sectigo()`, `Firmaprofesional()`, `ANF()`, `Uanataca()`, `SIGNE()`, `Lleidanet()`,
  `DNIe()`;
- the testui module layout.

### Task 2: library core (certcheck types and Handler, internal/opts, internal/engine)

Model: opus   Repo: same branch
Files:
- `git mv certauth/types.go types.go`, `git mv certauth/diagnostics.go diagnostics.go`,
  `git mv certauth/checker.go internal/engine/checker.go`;
- `git mv certauth/<each>_test.go internal/engine/` for checker, diagnostics, pathmap,
  profiles_pipeline, purpose, result_json, specimens, specimens_pipeline, specimens_live and golden;
- new: `doc.go`, `provider.go`, `options.go`, `revocation.go`, `handler.go`, `internal/opts/opts.go`,
  `internal/engine/{compat,report}.go`, `internal/engine/inert_test.go`;
- edited: `internal/profiles/{registry,types,registry_test}.go`, `testdata/specimens/MANIFEST.md`
  (lines 4 and 27), `.github/workflows/ci.yml` (fuzz path).

Goal: AC4 (most of the surface), AC6 (goldens through the new engine) and AC7 (`VerifyAs`). This is
the declared logic move (R4).

Logic changes allowed:
- `internal/engine/checker.go`: only the diff below;
- `handler.go` (new);
- `internal/profiles/registry.go`: rename `checkAmbiguity` → `CheckAmbiguity` (and its doc), delete
  `AllAnchors`, `allRoots` and `allInter` (P9);
- `internal/profiles/types.go`: delete `ProviderInfo`.

Names-only files:
- `types.go` and `diagnostics.go`: the diffs below, plus the doc-comment rewrites listed in step 2;
- the moved tests: the call-site changes listed in step 4.

Step 1: write the engine-level tests first (`internal/engine/inert_test.go`, package `engine`):
- `TestInertProvider`. The declaration has one profile whose anchor expired a day before the clock.
  `New` returns no error, and:
  - `Info()` is unchanged; `CAs()` and `EnabledProfiles()` are empty;
  - `Verify(ctx, nil)` and `Verify(ctx, [leaf])` both give `provider_mismatch` at `bounds`, detail
    `provider has no enabled profile`, `Diagnostics.Provider` = the ID, `ServerVersion` = Config.Version;
  - the logger got `anchor outside validity`, `profile disabled: no valid anchor` and
    `provider hidden` (capture with a `slog.NewTextHandler` over a buffer).
- `TestStandaloneVerifyUntrustedIssuer`: two declarations built with `New` (alpha under one testpki
  root, beta under another). `beta.Verify` of an alpha leaf gives `untrusted_issuer` at `path` with
  beta's single candidate. That is the interface contract (P1/R4).
- `TestKeyAlgorithmMatchesDescribe`: for leaves with RSA-2048, RSA-3072, P-256, P-384 and P-521 keys,
  `keyAlgorithm(c) == certcheck.DescribeCertificate(c).KeyAlgorithm`. It guards the copy in
  `report.go` (P13).

Run: `go test ./internal/engine -run 'Inert|Standalone|KeyAlgorithm'`. Expected: build failure
(undefined: New).

Step 2: implement.

`internal/opts/opts.go`:

```go
// Package opts holds the settings that the certcheck options configure. It
// exists so that package certcheck (which declares Option and the With*
// constructors) and internal/engine (which applies them) share one type
// without an import cycle.
package opts

import (
	"log/slog"
	"sync"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// Settings is what a certcheck.Option sets. The zero value means "all
// defaults".
type Settings struct {
	Revocation  *revocation.Checker // nil = DefaultRevocation()
	Now         func() time.Time    // nil = time.Now
	Logger      *slog.Logger        // nil = slog.Default()
	Version     string              // Diagnostics.ServerVersion
	MaxChainLen int                 // 0 = certcheck.DefaultMaxChainLen; no public option sets it
}

// Apply returns the settings produced by fns, in order.
func Apply[F ~func(*Settings)](fns ...F) Settings {
	var s Settings
	for _, f := range fns {
		if f != nil {
			f(&s)
		}
	}
	return s
}

// defaultRevocation is the process-wide checker shared by every provider
// built without WithRevocation: fetcher defaults (User-Agent
// "cert-check/dev"), wall clock, slog.Default() at first use.
var defaultRevocation = sync.OnceValues(func() (*revocation.Checker, error) {
	return revocation.NewChecker(revocation.Options{})
})

// DefaultRevocation returns the process-wide revocation checker, creating it
// on first use.
func DefaultRevocation() (*revocation.Checker, error) { return defaultRevocation() }
```

`doc.go`:

```go
// Package certcheck authenticates people by the client certificate their
// browser presents over TLS, for the Spanish certificate types it supports
// (FNMT, idCAT, ACCV, DNIe and others).
//
// A program picks the certificate types it accepts by constructing their
// providers (one package per issuer under providers/, for example
// idcat.New() or fnmt.New(), or providers.All()) and builds a Handler from
// them. The Handler supplies the tls.Config of the listener that requests the
// client certificate (TLSConfig) and verifies the certificate of each request
// (Auth). Verification checks the chain against pinned trust anchors only, the
// profile (exact policy OIDs), the key usage, test-certificate markers, the
// holder's identity and the revocation status (OCSP, then CRL), and fails
// closed. A success is a *Result with the typed Identity; a failure is an
// *Error with a typed ErrorCode and session-bound Diagnostics.
//
// Diagnostics contain certificate details: show them only to the browser that
// ran the check and log Diagnostics.LogAttrs instead.
package certcheck
```

`provider.go`:

```go
package certcheck

import (
	"context"
	"crypto/x509"
)

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

// ProviderRef is the provider part of a Result (JSON {"id","name"}).
type ProviderRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
```

`options.go`:

```go
package certcheck

import (
	"log/slog"
	"time"

	"github.com/vocdoni/cert-check/internal/opts"
)

// Option configures providers (the constructors under providers/) and
// NewHandler.
type Option func(*opts.Settings)

// WithRevocation makes providers share r for OCSP and CRL checks. Without
// it, every provider uses one process-wide default with the User-Agent
// "cert-check/dev" and the wall clock. r must come from NewRevocation.
func WithRevocation(r *Revocation) Option {
	if r == nil || r.c == nil {
		panic("certcheck: WithRevocation needs a Revocation from NewRevocation")
	}
	return func(s *opts.Settings) { s.Revocation = r.c }
}

// WithClock sets the pipeline clock: providers check anchor validity at
// construction and certificates at validation with it, and the Handler
// stamps its own errors with it. The default is time.Now. The revocation
// checker keeps its own clock (RevocationOptions.Now).
func WithClock(now func() time.Time) Option {
	return func(s *opts.Settings) { s.Now = now }
}

// WithLogger sets the logger of construction warnings (an anchor outside
// validity, a disabled profile). The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *opts.Settings) { s.Logger = l }
}

// WithVersion sets Diagnostics.ServerVersion. The default is "".
func WithVersion(v string) Option {
	return func(s *opts.Settings) { s.Version = v }
}
```

`revocation.go`:

```go
package certcheck

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// Revocation is a shared OCSP/CRL checker with bounded caches. Create it with
// NewRevocation and pass it to providers with WithRevocation; the zero value
// is not usable. It is safe for concurrent use.
type Revocation struct{ c *revocation.Checker }

// RevocationOptions configures NewRevocation. Zero values take the defaults.
type RevocationOptions struct {
	UserAgent        string           // "" = "cert-check/dev"
	Now              func() time.Time // evidence freshness clock; nil = time.Now; pass the WithClock clock in tests
	Logger           *slog.Logger     // rejected evidence warnings; nil = slog.Default()
	OCSPTimeout      time.Duration    // 0 = 5 s
	CRLTimeout       time.Duration    // 0 = 15 s
	CRLCacheBytes    int64            // parsed-CRL cache bound; 0 = 128 MiB
	OCSPCacheEntries int              // OCSP response cache bound; 0 = 4096
}

// NewRevocation returns a revocation checker. Negative timeouts or cache
// bounds are an error. Fetches go only to the hosts each profile allowlists
// and never to loopback, private or link-local addresses.
func NewRevocation(o RevocationOptions) (*Revocation, error) {
	c, err := revocation.NewChecker(revocation.Options{
		UserAgent: o.UserAgent, Now: o.Now, Logger: o.Logger, OCSPTimeout: o.OCSPTimeout, CRLTimeout: o.CRLTimeout,
		CRLCacheBytes: o.CRLCacheBytes, OCSPCacheEntries: o.OCSPCacheEntries,
	})
	if err != nil {
		return nil, fmt.Errorf("certcheck: %w", err)
	}
	return &Revocation{c: c}, nil
}
```

`handler.go` (security-relevant: `NewHandler` checks, issuer selection, the `VerifyAs`
re-classification):

```go
package certcheck

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/vocdoni/cert-check/internal/opts"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// Handler authenticates HTTP requests that arrived over TLS with a client
// certificate, using a fixed set of certificate types. It is immutable and
// safe for concurrent use.
type Handler struct {
	providers []Provider          // construction order
	byID      map[string]Provider // Info().ID
	byIssuer  map[string]Provider // RawSubject of each advertised CA (unique across providers)
	cas       []*x509.Certificate // advertised CAs, deduplicated, provider order
	pool      *x509.CertPool      // cas
	roots     *x509.CertPool      // trust anchors of every provider (provider_mismatch only)
	inter     *x509.CertPool      // pinned intermediates of every provider (provider_mismatch only)
	now       func() time.Time
	version   string
}

// pinnedProfiles is implemented by the providers that this module builds. It
// exposes the loaded profiles behind CAs: which CAs are trust anchors and
// which are pinned intermediates, and the policy OIDs of each profile. A
// Provider without it (a test double) contributes every CA as a trust anchor
// and is checked for shared CA subjects only.
type pinnedProfiles interface {
	EnabledProfiles() []*profiles.Enabled
}

// NewHandler returns a Handler for providers. It needs at least one provider,
// unique provider IDs, no inert provider (one whose CAs are empty because no
// profile is valid at construction) and no ambiguity: no CA subject may be
// advertised by two providers, and no two profiles of different providers may
// share an anchor key and a policy OID. Acceptance therefore never depends on
// the order of providers. NewHandler uses WithClock and WithVersion; other
// options are ignored.
func NewHandler(providers []Provider, options ...Option) (*Handler, error) {
	if len(providers) == 0 {
		return nil, errors.New("certcheck: NewHandler needs at least one provider")
	}
	s := opts.Apply(options...)
	h := &Handler{byID: map[string]Provider{}, byIssuer: map[string]Provider{}, pool: x509.NewCertPool(),
		roots: x509.NewCertPool(), inter: x509.NewCertPool(), now: s.Now, version: s.Version}
	if h.now == nil {
		h.now = time.Now
	}
	var enabled []*profiles.Enabled
	for i, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("certcheck: provider %d is nil", i)
		}
		id := p.Info().ID
		if _, dup := h.byID[id]; dup {
			return nil, fmt.Errorf("certcheck: duplicate provider %q", id)
		}
		cas := p.CAs()
		if len(cas) == 0 {
			return nil, fmt.Errorf("certcheck: provider %q has no enabled profile", id)
		}
		for _, c := range cas {
			if other, ok := h.byIssuer[string(c.RawSubject)]; ok && other.Info().ID != id {
				return nil, fmt.Errorf("certcheck: providers %q and %q both advertise the CA %q", other.Info().ID, id, c.Subject)
			}
			h.byIssuer[string(c.RawSubject)] = p
			if !slices.ContainsFunc(h.cas, c.Equal) {
				h.cas = append(h.cas, c)
				h.pool.AddCert(c)
			}
		}
		if pp, ok := p.(pinnedProfiles); ok {
			for _, e := range pp.EnabledProfiles() {
				enabled = append(enabled, e)
				for _, c := range e.Anchors {
					h.roots.AddCert(c)
				}
				for _, c := range e.Intermediates {
					h.inter.AddCert(c)
				}
			}
		} else {
			for _, c := range cas {
				h.roots.AddCert(c)
			}
		}
		h.byID[id] = p
		h.providers = append(h.providers, p)
	}
	if err := profiles.CheckAmbiguity(enabled); err != nil {
		return nil, fmt.Errorf("certcheck: %w", err)
	}
	return h, nil
}

// Name returns "certcheck", for adapters to blind-csp-shaped interfaces.
func (h *Handler) Name() string { return "certcheck" }

// RequireCertificate reports true: authentication needs a client
// certificate. (TLSConfig still requests the certificate without requiring
// it, so that a browser without one gets a no_certificate answer instead of
// a handshake failure.)
func (h *Handler) RequireCertificate() bool { return true }

// Certificates returns the DER of every advertised CA, deduplicated, in
// provider order. The slices are fresh copies.
func (h *Handler) Certificates() [][]byte {
	out := make([][]byte, 0, len(h.cas))
	for _, c := range h.cas {
		out = append(out, bytes.Clone(c.Raw))
	}
	return out
}

// CertificateCheck reports whether subject (a DER-encoded distinguished
// name) is the subject of an advertised CA.
func (h *Handler) CertificateCheck(subject []byte) bool {
	_, ok := h.byIssuer[string(subject)]
	return ok
}

// ClientCAs returns a fresh pool of the advertised CAs, for
// tls.Config.ClientCAs.
func (h *Handler) ClientCAs() *x509.CertPool { return h.pool.Clone() }

// Providers returns the providers in construction order (a fresh slice).
func (h *Handler) Providers() []Provider { return slices.Clone(h.providers) }

// Verify selects the provider whose CAs include the issuer of chain[0] (by
// exact subject bytes, as crypto/x509 finds parents) and returns its Verify
// verbatim. A chain without a leaf is no_certificate; a leaf whose issuer no
// provider advertises is untrusted_issuer at step path. The error is always
// *Error.
func (h *Handler) Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, h.fail(chain, "", StepBounds, CodeNoCertificate, "no client certificate")
	}
	p, ok := h.byIssuer[string(chain[0].RawIssuer)]
	if !ok {
		return nil, h.fail(chain, "", StepPath, CodeUntrustedIssuer, "no provider advertises the leaf's issuer")
	}
	return p.Verify(ctx, chain)
}

// VerifyAs verifies chain with the provider providerID, for servers that
// already know which certificate type the user chose (for example from the
// TLS server name). An unknown providerID is provider_mismatch at step
// bounds. When the provider answers untrusted_issuer at step path and the
// leaf chains to the pinned CAs of the handler's providers, the code becomes
// provider_mismatch: the user picked the wrong certificate type. That check
// builds a path only; it never accepts and makes no network request. The
// error is always *Error.
func (h *Handler) VerifyAs(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error) {
	p, ok := h.byID[providerID]
	if !ok {
		return nil, h.fail(chain, providerID, StepBounds, CodeProviderMismatch, "unknown provider")
	}
	res, err := p.Verify(ctx, chain)
	if e, ok := errors.AsType[*Error](err); ok && e.Code == CodeUntrustedIssuer && e.Diagnostics.FailedStep == StepPath &&
		len(chain) > 0 && chain[0] != nil && h.chainsToPinnedCA(chain[0]) {
		mismatch := *e
		mismatch.Code, mismatch.Diagnostics.Code = CodeProviderMismatch, CodeProviderMismatch
		return nil, &mismatch
	}
	return res, err
}

// chainsToPinnedCA is the former engine's unknownAuthorityCode: it reports
// whether the leaf, with UnhandledCriticalExtensions cleared, path-builds
// against the union of every provider's trust anchors and pinned
// intermediates. Classification only, never acceptance.
func (h *Handler) chainsToPinnedCA(leaf *x509.Certificate) bool {
	probe := *leaf
	probe.UnhandledCriticalExtensions = nil // classification only, never acceptance
	_, err := probe.Verify(x509.VerifyOptions{Roots: h.roots, Intermediates: h.inter, CurrentTime: h.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if _, unknown := errors.AsType[x509.UnknownAuthorityError](err); err != nil && unknown {
		return false
	}
	return true
}

// fail returns an *Error decided by the handler, with Diagnostics filled as
// a provider fills them for any failure.
func (h *Handler) fail(chain []*x509.Certificate, providerID string, step Step, code ErrorCode, detail string) *Error {
	d := Diagnostics{DiagnosticID: NewDiagnosticID(), Time: h.now().UTC(), ServerVersion: h.version, Provider: providerID,
		FailedStep: step, Code: code, TechnicalDetail: detail}
	for _, c := range chain {
		if c != nil {
			d.Chain = append(d.Chain, ChainEntry{Subject: c.Subject.String(), Issuer: c.Issuer.String()})
		}
	}
	if len(chain) > 0 && chain[0] != nil {
		d.Certificate = DescribeCertificate(chain[0])
	}
	return &Error{Code: code, Retryable: code.Retryable(), Detail: detail, Diagnostics: d}
}
```

`types.go` (git mv from `certauth/types.go`). The diff from the original is:

```diff
--- a/certauth/types.go (base)
+++ b/types.go
@@ -1,21 +1,31 @@
-// Package certauth validates a TLS client-certificate chain against the
-// pinned Spanish provider profiles and extracts the holder's typed identity.
-// It is the importable entry point; see certauth/tlsauth for the HTTP/TLS glue.
-package certauth
+package certcheck
 
 import (
 	"time"
 
-	"github.com/vocdoni/cert-check/certauth/identity"
-	"github.com/vocdoni/cert-check/certauth/profiles"
-	"github.com/vocdoni/cert-check/certauth/revocation"
+	"github.com/vocdoni/cert-check/internal/identity"
+	"github.com/vocdoni/cert-check/internal/profiles"
+	"github.com/vocdoni/cert-check/internal/revocation"
 )
 
-// Identity and Document are the identity package's types.
+// Field types owned by internal packages, aliased so that a program can name
+// every type of a Result.
 type (
-	Identity     = identity.Identity
-	Document     = identity.Document
-	Organization = identity.Organization
+	Identity         = identity.Identity
+	Document         = identity.Document
+	Organization     = identity.Organization
+	Date             = identity.Date
+	DocumentType     = identity.DocumentType
+	RevocationStatus = revocation.Status
+	RevocationMethod = revocation.Method
+	Role             = profiles.Role
+	ProfileInfo      = profiles.ProfileInfo
+)
+
+// Bounds applied to every chain before path building.
+const (
+	DefaultMaxChainLen = 10       // certificates in a received chain
+	MaxCertificateDER  = 16 << 10 // bytes of one received certificate
 )
 
 // ErrorCode is the typed failure reason shown to users.
@@ -75,7 +85,7 @@
 	Diagnostics Diagnostics
 }
 
-func (e *Error) Error() string { return "certauth: " + string(e.Code) + ": " + e.Detail }
+func (e *Error) Error() string { return "certcheck: " + string(e.Code) + ": " + e.Detail }
 
 // CertificateInfo describes the validated leaf.
 type CertificateInfo struct {
@@ -90,22 +100,22 @@
 
 // RevocationInfo is the leaf's accepted revocation evidence.
 type RevocationInfo struct {
-	Status     revocation.Status `json:"status"` // always "good" in a Result
-	Method     revocation.Method `json:"method"`
-	CheckedAt  time.Time         `json:"checkedAt"`
-	ThisUpdate time.Time         `json:"thisUpdate"`
-	NextUpdate *time.Time        `json:"nextUpdate"`
-	Source     string            `json:"source"` // host
+	Status     RevocationStatus `json:"status"` // always "good" in a Result
+	Method     RevocationMethod `json:"method"`
+	CheckedAt  time.Time        `json:"checkedAt"`
+	ThisUpdate time.Time        `json:"thisUpdate"`
+	NextUpdate *time.Time       `json:"nextUpdate"`
+	Source     string           `json:"source"` // host
 }
 
 // Result is a successful validation.
 type Result struct {
-	Provider     profiles.ProviderInfo  `json:"provider"`
-	Profile      profiles.ProfileInfo   `json:"profile"`
-	Identity     Identity               `json:"identity"`
-	Organization *identity.Organization `json:"organization"`
-	Certificate  CertificateInfo        `json:"certificate"`
-	Revocation   RevocationInfo         `json:"revocation"`
-	ValidatedAt  time.Time              `json:"validatedAt"`
-	Diagnostics  Diagnostics            `json:"diagnostics"`
+	Provider     ProviderRef     `json:"provider"`
+	Profile      ProfileInfo     `json:"profile"`
+	Identity     Identity        `json:"identity"`
+	Organization *Organization   `json:"organization"`
+	Certificate  CertificateInfo `json:"certificate"`
+	Revocation   RevocationInfo  `json:"revocation"`
+	ValidatedAt  time.Time       `json:"validatedAt"`
+	Diagnostics  Diagnostics     `json:"diagnostics"`
 }
```

`diagnostics.go` (git mv from `certauth/diagnostics.go`):
- package clause;
- `describeCertificate` → exported `DescribeCertificate` with the doc
  `// DescribeCertificate describes a received leaf for Diagnostics.Certificate.`;
- the `RevocationAttempt` field types `revocation.Method`/`revocation.Status` → `RevocationMethod`/`RevocationStatus`;
- `reportAttempts` deleted (copied to the engine) and the `revocation` import dropped.

`keyAlgorithm`, `extKeyUsageName`, `logSafe` and `LogAttrs` keep their bodies.

Doc-comment rewrites, comment lines only, so that godoc speaks to users:
- `types.go`:
  - `// Error codes (spec "Packages and public API").` → `// Error codes, carried by every *Error and its Diagnostics.`;
  - `// Codes lists every ErrorCode (the server's message table must cover all).` →
    `// Codes lists every ErrorCode, for tables keyed by code (user messages, metrics).`;
  - `// Steps (diagnostics failedStep).` → `// Pipeline steps, in order (Diagnostics.FailedStep).`;
- `diagnostics.go`:
  - `// TLSInfo describes the handshake (filled by tlsauth).` → `// TLSInfo describes the handshake (filled by Handler.Auth and Handler.AuthAs).`;
  - `// RevocationAttempt is revocation.Attempt in report form.` →
    `// RevocationAttempt is one OCSP or CRL fetch made for the verified chain.`;
  - `// NewDiagnosticID returns 16 random bytes in hex.` →
    `// NewDiagnosticID returns a new random diagnostic ID (32 lowercase hex digits), for errors a server decides itself.`;
  - in the `LogAttrs` doc, `(x509 error class only, see logSafe)` → `(x509 error class only)`.

`internal/engine/checker.go` (git mv from `certauth/checker.go`). The complete allowed diff:

```diff
--- a/certauth/checker.go (base)
+++ b/internal/engine/checker.go
@@ -1,4 +1,4 @@
-package certauth
+package engine
 
 import (
 	"context"
@@ -12,19 +12,15 @@
 	"encoding/hex"
 	"errors"
 	"fmt"
+	"log/slog"
 	"slices"
 	"strings"
 	"time"
 
-	"github.com/vocdoni/cert-check/certauth/identity"
-	"github.com/vocdoni/cert-check/certauth/profiles"
-	"github.com/vocdoni/cert-check/certauth/revocation"
-)
-
-// Bounds.
-const (
-	DefaultMaxChainLen = 10
-	MaxCertificateDER  = 16 << 10
+	certcheck "github.com/vocdoni/cert-check"
+	"github.com/vocdoni/cert-check/internal/identity"
+	"github.com/vocdoni/cert-check/internal/profiles"
+	"github.com/vocdoni/cert-check/internal/revocation"
 )
 
 var (
@@ -52,55 +48,86 @@
 	return nil
 }
 
-// Options configures a Checker.
-type Options struct {
-	Registry    *profiles.Registry  // required
+// Config configures New.
+type Config struct {
+	Provider    profiles.Provider   // the declaration of one certificate type
 	Revocation  *revocation.Checker // required
-	Now         func() time.Time    // nil = time.Now
-	MaxChainLen int                 // 0 = 10
+	Now         func() time.Time    // nil = time.Now; Now() at New is the load time
+	Logger      *slog.Logger        // load warnings; nil = slog.Default()
 	Version     string              // reported as diagnostics serverVersion
+	MaxChainLen int                 // 0 = 10
+	Reserved    *identity.Reserved  // nil = identity.DefaultReserved(); &identity.Reserved{} empties it
 }
 
-// Checker runs the validation pipeline. Safe for concurrent use.
-type Checker struct {
-	reg     *profiles.Registry
+// Provider runs the validation pipeline of one provider declaration. It
+// implements certcheck.Provider and is safe for concurrent use.
+type Provider struct {
+	reg     *profiles.Registry // holds this declaration only
+	id      string
+	info    certcheck.ProviderInfo
+	cas     []*x509.Certificate
 	rev     *revocation.Checker
 	now     func() time.Time
 	maxLen  int
 	version string
 }
 
-// NewChecker validates options.
-func NewChecker(o Options) (*Checker, error) {
-	if o.Registry == nil || o.Revocation == nil {
-		return nil, errors.New("certauth: Registry and Revocation are required")
+var _ certcheck.Provider = (*Provider)(nil)
+
+// New loads the declaration at Now() (pins checked; an anchor outside
+// validity is skipped with a warning) and returns its pipeline. A
+// declaration whose profiles are all disabled gives an inert Provider: CAs is
+// empty and Verify fails provider_mismatch at step bounds.
+func New(cfg Config) (*Provider, error) {
+	if cfg.Revocation == nil {
+		return nil, errors.New("engine: Revocation is required")
+	}
+	now := cfg.Now
+	if now == nil {
+		now = time.Now
+	}
+	reserved := identity.DefaultReserved()
+	if cfg.Reserved != nil {
+		reserved = *cfg.Reserved
+	}
+	reg, err := profiles.New(profiles.Config{Providers: []profiles.Provider{cfg.Provider}, Reserved: reserved, Now: now(), Logger: cfg.Logger})
+	if err != nil {
+		return nil, err
 	}
-	for _, p := range o.Registry.Providers() {
+	for _, p := range reg.Providers() {
 		for _, prof := range p.Profiles {
 			for _, oid := range prof.HandledCriticalExtensions {
 				if _, ok := extensionParsers[oid]; !ok {
-					return nil, fmt.Errorf("certauth: profile %s handles %s without a parser", prof.ID, oid)
+					return nil, fmt.Errorf("engine: profile %s handles %s without a parser", prof.ID, oid)
 				}
 			}
 		}
 	}
-	c := &Checker{reg: o.Registry, rev: o.Revocation, now: o.Now, maxLen: o.MaxChainLen, version: o.Version}
-	if c.now == nil {
-		c.now = time.Now
-	}
+	c := &Provider{reg: reg, id: cfg.Provider.ID, rev: cfg.Revocation, now: now, maxLen: cfg.MaxChainLen, version: cfg.Version,
+		info: certcheck.ProviderInfo{ID: cfg.Provider.ID, Name: cfg.Provider.Name, Description: cfg.Provider.Description, Beta: cfg.Provider.Beta}}
 	if c.maxLen <= 0 {
 		c.maxLen = DefaultMaxChainLen
 	}
+	for _, e := range reg.Enabled(c.id) {
+		for _, ca := range slices.Concat(e.Anchors, e.Intermediates) {
+			if !slices.ContainsFunc(c.cas, ca.Equal) {
+				c.cas = append(c.cas, ca)
+			}
+		}
+	}
 	return c, nil
 }
 
-// Providers returns the enabled providers in display order.
-func (c *Checker) Providers() []profiles.Provider { return c.reg.Providers() }
+// Info describes the provider.
+func (c *Provider) Info() certcheck.ProviderInfo { return c.info }
 
-// ClientCAs returns the CA pool advertised for a provider.
-func (c *Checker) ClientCAs(providerID string) (*x509.CertPool, error) {
-	return c.reg.ClientCAs(providerID)
-}
+// CAs returns the anchors and pinned intermediates of the enabled profiles,
+// in declaration order (the certificate_authorities list of a handshake).
+func (c *Provider) CAs() []*x509.Certificate { return c.cas }
+
+// EnabledProfiles returns the loaded profiles behind CAs (read-only). The
+// certcheck Handler uses it for its ambiguity check and for provider_mismatch.
+func (c *Provider) EnabledProfiles() []*profiles.Enabled { return c.reg.Enabled(c.id) }
 
 // run carries the diagnostics of one Check invocation.
 type run struct {
@@ -118,9 +145,10 @@
 	err   error
 }
 
-// Check validates chain (as received: chain[0] is the leaf) for providerID.
+// Verify validates chain (as received: chain[0] is the leaf).
 // The returned error is always *Error.
-func (c *Checker) Check(ctx context.Context, providerID string, chain []*x509.Certificate) (*Result, error) {
+func (c *Provider) Verify(ctx context.Context, chain []*x509.Certificate) (*Result, error) {
+	providerID := c.id
 	now := c.now()
 	r := &run{diag: Diagnostics{DiagnosticID: NewDiagnosticID(), Time: now.UTC(), ServerVersion: c.version, Provider: providerID}}
 	for _, cert := range chain {
@@ -135,7 +163,7 @@
 	// 1. Bounds.
 	prov, ok := c.reg.Provider(providerID)
 	if !ok {
-		return nil, r.fail(StepBounds, CodeProviderMismatch, "unknown provider")
+		return nil, r.fail(StepBounds, CodeProviderMismatch, "provider has no enabled profile")
 	}
 	if len(chain) == 0 || chain[0] == nil {
 		return nil, r.fail(StepBounds, CodeNoCertificate, "no client certificate")
@@ -280,7 +308,7 @@
 		next = new(leafRev.NextUpdate.UTC())
 	}
 	return &Result{
-		Provider:     profiles.ProviderInfo{ID: prov.ID, Name: prov.Name},
+		Provider:     ProviderRef{ID: prov.ID, Name: prov.Name},
 		Profile:      profiles.ProfileInfo{ID: prof.ID, Name: prof.Name, HolderRole: prof.HolderRole},
 		Identity:     x.Identity,
 		Organization: x.Organization,
@@ -329,7 +357,7 @@
 // mapPathErrors maps the candidates' x509 errors to one code. Priority:
 // IncompatibleUsage > Expired > UnhandledCriticalExtension (when the leaf
 // otherwise chains to that profile) > UnknownAuthority > other.
-func (c *Checker) mapPathErrors(leaf *x509.Certificate, cands []candidate, now time.Time) (ErrorCode, string) {
+func (c *Provider) mapPathErrors(leaf *x509.Certificate, cands []candidate, now time.Time) (ErrorCode, string) {
 	best, bestRank, detail := CodeInvalidChain, rankOther+1, ""
 	consider := func(rank int, code ErrorCode, d string) {
 		if rank < bestRank {
@@ -370,7 +398,7 @@
 			continue
 		}
 		if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
-			consider(rankUnknownAuthority, c.unknownAuthorityCode(leaf, now), err.Error())
+			consider(rankUnknownAuthority, CodeUntrustedIssuer, err.Error())
 			continue
 		}
 		consider(rankOther, CodeInvalidChain, fmt.Sprint(err))
@@ -378,19 +406,6 @@
 	return best, detail
 }
 
-// unknownAuthorityCode: provider_mismatch when the leaf verifies against the
-// union of every enabled provider's pinned CAs, else untrusted_issuer.
-func (c *Checker) unknownAuthorityCode(leaf *x509.Certificate, now time.Time) ErrorCode {
-	roots, inter := c.reg.AllAnchors()
-	probe := *leaf
-	probe.UnhandledCriticalExtensions = nil // classification only, never acceptance
-	_, err := probe.Verify(verifyOptions(roots, inter, now))
-	if _, unknown := errors.AsType[x509.UnknownAuthorityError](err); err != nil && unknown {
-		return CodeUntrustedIssuer
-	}
-	return CodeProviderMismatch
-}
-
 // algorithmsOK: RSA ≥ minRSA (floor 2048) or ECDSA P-256/P-384/P-521, and a
 // SHA-256-or-stronger leaf signature.
 func algorithmsOK(leaf *x509.Certificate, minRSA int) (string, bool) {
```

`internal/engine/compat.go` (P14):

```go
package engine

import (
	"crypto/tls"
	"crypto/x509"

	certcheck "github.com/vocdoni/cert-check"
)

// The pipeline (checker.go) and its tests moved here from package certauth,
// where these names were declared. They now live in package certcheck; the
// aliases keep the moved code byte-identical apart from the declared changes.
type (
	CandidateResult    = certcheck.CandidateResult
	CertificateDetails = certcheck.CertificateDetails
	CertificateInfo    = certcheck.CertificateInfo
	ChainEntry         = certcheck.ChainEntry
	Diagnostics        = certcheck.Diagnostics
	Error              = certcheck.Error
	ErrorCode          = certcheck.ErrorCode
	ProviderRef        = certcheck.ProviderRef
	Result             = certcheck.Result
	RevocationAttempt  = certcheck.RevocationAttempt
	RevocationInfo     = certcheck.RevocationInfo
	Step               = certcheck.Step
	TLSInfo            = certcheck.TLSInfo
)

// Bounds, error codes and steps of package certcheck.
const (
	DefaultMaxChainLen = certcheck.DefaultMaxChainLen
	MaxCertificateDER  = certcheck.MaxCertificateDER

	CodeNoCertificate               = certcheck.CodeNoCertificate
	CodeProviderMismatch            = certcheck.CodeProviderMismatch
	CodeUntrustedIssuer             = certcheck.CodeUntrustedIssuer
	CodeInvalidChain                = certcheck.CodeInvalidChain
	CodeExpired                     = certcheck.CodeExpired
	CodeNotYetValid                 = certcheck.CodeNotYetValid
	CodeUnsupportedProfile          = certcheck.CodeUnsupportedProfile
	CodeUnsupportedPurpose          = certcheck.CodeUnsupportedPurpose
	CodeWeakAlgorithm               = certcheck.CodeWeakAlgorithm
	CodeTestCertificate             = certcheck.CodeTestCertificate
	CodeIdentityInvalid             = certcheck.CodeIdentityInvalid
	CodeIdentityUnsupportedDocument = certcheck.CodeIdentityUnsupportedDocument
	CodeRevoked                     = certcheck.CodeRevoked
	CodeRevocationUnknown           = certcheck.CodeRevocationUnknown
	CodeRevocationUnavailable       = certcheck.CodeRevocationUnavailable
	CodeInternal                    = certcheck.CodeInternal

	StepBounds     = certcheck.StepBounds
	StepAlgorithms = certcheck.StepAlgorithms
	StepPath       = certcheck.StepPath
	StepProfile    = certcheck.StepProfile
	StepPurpose    = certcheck.StepPurpose
	StepTestMarker = certcheck.StepTestMarker
	StepIdentity   = certcheck.StepIdentity
	StepRevocation = certcheck.StepRevocation
)

// Codes is certcheck.Codes.
var Codes = certcheck.Codes

// NewDiagnosticID is certcheck.NewDiagnosticID.
func NewDiagnosticID() string { return certcheck.NewDiagnosticID() }

// DescribeTLS is certcheck.DescribeTLS.
func DescribeTLS(cs *tls.ConnectionState) *TLSInfo { return certcheck.DescribeTLS(cs) }

func describeCertificate(c *x509.Certificate) *CertificateDetails {
	return certcheck.DescribeCertificate(c)
}
```

`internal/engine/report.go` (P13; the bodies are byte-identical to the base `diagnostics.go`):

```go
package engine

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// keyAlgorithm and reportAttempts moved here from certauth/diagnostics.go
// (certcheck.DescribeCertificate keeps its own keyAlgorithm).

func keyAlgorithm(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	}
	return c.PublicKeyAlgorithm.String()
}

func reportAttempts(in []revocation.Attempt) []RevocationAttempt {
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return new(t.UTC())
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
```

`internal/profiles/registry.go`:
- delete the `allRoots`/`allInter` fields, their initialisation and the two `AddCert` calls into them,
  and the `AllAnchors` method;
- `checkAmbiguity` → `CheckAmbiguity`, with the doc
  `// CheckAmbiguity rejects two profiles that share an anchor key and a policy OID (step 4 could then match both). The loader applies it per provider; the certcheck Handler applies it across providers.`
  (wrapped).

`internal/profiles/types.go`: delete `ProviderInfo`.

Step 3: `.github/workflows/ci.yml`: the QC fuzz target runs on `./internal/engine`. The AC12 step's
`./certauth/...` part goes, because the AC3 step from Task 1 covers it.
`testdata/specimens/MANIFEST.md`:
- line 4 `(certauth/specimens_test.go)` → `(internal/engine/specimens_test.go)`;
- line 27 `certauth.ErrorCode` → `certcheck.ErrorCode`.

Step 4: move and re-point the tests (package `certauth` → `engine`, `certauth_test` → `engine_test`).
Expectations stay identical: every `provider_mismatch` case now goes through `Handler.VerifyAs`.
- `checker_test.go`:
  - `tChecker` is replaced by:

  ```go
  // tHandler builds one Provider per declaration, loaded at loadNow with the
  // production reserved identities and clocked at now afterwards, and a Handler
  // over the enabled ones (the registry hid the others). Handler.VerifyAs is
  // what Checker.Check was.
  func tHandler(t testing.TB, providers []profiles.Provider, loadNow, now time.Time, rc *revocation.Checker) *certcheck.Handler {
  	t.Helper()
  	var ps []certcheck.Provider
  	for _, d := range providers {
  		clock := loadNow // New reads the clock once, as the load time
  		p, err := New(Config{Provider: d, Revocation: rc, Now: func() time.Time { return clock }, Logger: tDiscard, Version: "test"})
  		if err != nil {
  			t.Fatalf("New(%s): %v", d.ID, err)
  		}
  		clock = now
  		if len(p.CAs()) > 0 {
  			ps = append(ps, p)
  		}
  	}
  	h, err := certcheck.NewHandler(ps, certcheck.WithClock(func() time.Time { return now }), certcheck.WithVersion("test"))
  	if err != nil {
  		t.Fatalf("NewHandler: %v", err)
  	}
  	return h
  }
  ```

  - `codeWorld.chk` becomes `*certcheck.Handler`: `w.chk = tHandler(t, providers, now, now, ...)`;
  - every `w.chk.Check(` / `chk.Check(` becomes `VerifyAs(` (same argument order);
  - the `Error()` expectation becomes `"certcheck: "+...`;
  - `TestNewCheckerOptions` is re-pointed at `New(Config)`, with these cases:
    - `invalid declaration`: `Config{Revocation: rc}` → an error containing `invalid provider`;
    - `no revocation` → `required`;
    - `handled extension without a parser` → `opt-a handles 1.3.6.1.4.1.99999.3.9 without a parser`;
    - `defaults`: `maxLen` 10, `now` set, `Info()` = `{opt, Opt, Opt provider, false}`, `CAs()` = the
      anchor.
- `pathmap_test.go`:
  - `tChecker(t, tRegistry(...))` → `tHandler(t, decls, now.Add(-48*time.Hour), now, rc)` (two places);
  - the specimen glob `filepath.Join("..", "..", "testdata", "specimens", "*.pem")`.
- `profiles_pipeline_test.go`:
  - `p.check(t, s, leaf, mode, arl)` drops the `reg` parameter and builds
    `tHandler(t, p.providers, p.now, p.now, rev)`;
  - the callers in `checker_test.go`, `pathmap_test.go` and `golden_test.go` follow.
- `diagnostics_test.go`, `purpose_test.go`, `result_json_test.go`: `.Check(` → `.VerifyAs(` only.
- `specimens_pipeline_test.go` and `specimens_live_test.go`:
  - `certauth.` → `certcheck.`;
  - the registry and checker construction becomes `specHandler(t, providers, now, rc).VerifyAs(...)`;
  - `specHandler` is defined in `specimens_pipeline_test.go`. It builds `engine.New` per declaration
    (default reserved identities), keeps the non-inert ones, and calls
    `certcheck.NewHandler(ps, certcheck.WithClock(now))`.
- `specimens_test.go`: `specimenDir = "../../testdata/specimens"`.
- `golden_test.go`:
  - `goldenDir = "../../testdata/golden"`, `goldenSpecimenDir = "../../testdata/specimens"`;
  - `TestGoldenSynthetic` calls `p.check(t, s, leaf, mode.mode, nil)`;
  - in `TestGoldenSpecimens`, for each declaration call
    `New(Config{Provider: d, Revocation: rc, Now: now, Logger: tDiscard, Reserved: &reserved})`, keep
    the non-inert ones, then `certcheck.NewHandler(enabled, certcheck.WithClock(now))` and
    `h.VerifyAs(t.Context(), d.ID, ...)` for every `d` in `profiles.All()`.
- `internal/profiles/registry_test.go` `TestAllAnchors` drops the two `AllAnchors` assertions and the
  copy check on its result (P9).

Run: checks on the root module. The four goldens pass unchanged and `git status` shows no change under
`testdata/golden`. The test-name check is skipped until Task 4 (testui does not compile).

Step 5: commit
`git commit -m "refactor(certcheck): add the public package, the provider engine and the handler" -- certauth types.go diagnostics.go doc.go provider.go options.go revocation.go handler.go internal testdata/specimens/MANIFEST.md .github`

Reviewer commands:
- `git diff -M HEAD~1 HEAD -- certauth/checker.go internal/engine/checker.go` equals the diff above;
- `git diff -M HEAD~1 HEAD -- certauth/types.go types.go certauth/diagnostics.go diagnostics.go`;
- `git diff -M HEAD~1 HEAD -- internal/profiles/registry.go`;
- `git diff -M --stat HEAD~1 HEAD -- internal/engine`: the ten moved tests appear as renames with
  small deltas.

Tests (AC mapping):
- AC6: all moved engine tests with identical expectations, plus the goldens.
- AC7: `VerifyAs` unknown provider (`TestCheckCodes/unknown provider`) and provider_mismatch
  (`TestCheckCodes/another provider's leaf`, `TestPathPriority/unhandled critical extension under another provider's anchor`).
- R5: inert behaviour.

Interfaces provided:
- `certcheck.{Provider, ProviderInfo, ProviderRef, Option, WithRevocation, WithClock, WithLogger, WithVersion, Revocation, RevocationOptions, NewRevocation, Handler, NewHandler, DescribeCertificate}`;
- the `Handler` methods `Name`, `RequireCertificate`, `Certificates`, `CertificateCheck`,
  `ClientCAs`, `Providers`, `Verify`, `VerifyAs`;
- `engine.Config`, `engine.New(Config) (*engine.Provider, error)`;
- `opts.Settings`, `opts.Apply`, `opts.DefaultRevocation`, `profiles.CheckAmbiguity`.

### Task 3: providers, option plumbing and the TLS side of the Handler

Model: opus   Repo: same branch
Files: `internal/engine/options.go`, `internal/engine/options_test.go`, `providers/providers.go`,
`providers/providers_test.go`, `providers/<12 names>/<name>.go`, `tls.go`, `world_test.go` (new;
shared root test world), `handler_test.go` (first two tests).
Goal: AC4 (constructors-only provider packages; `TLSOption`, `WithTLS13`, `TLSConfig`, `Auth`,
`AuthAs`, `CheckHost`, `ErrMisdirected`), AC7 (rejections, TLS policy) and R5 (inert providers
omitted).

Logic changes allowed: new files only. `tls.go` copies its policy, `CheckHost` and the Authenticate
logic from base `tlsauth.go` (P13), and the reviewer compares them line by line.

Step 1: write the tests first.
- `internal/engine/options_test.go` (package `engine`), `TestFromOptions`:
  - defaults: the provider's `rev` is `opts.DefaultRevocation()`, shared by two providers;
    `maxLen` 10; `version` "";
  - `WithVersion("v1")` reaches `Diagnostics.ServerVersion` of a failure;
  - `WithClock` sets `Diagnostics.Time` and the load time: a 2100 clock makes the provider inert, and
    `WithLogger` receives `anchor outside validity`;
  - `WithRevocation(r)` makes `rev` r's checker;
  - a declaration whose anchor pin is wrong panics with a message containing `certcheck: provider`
    and `pin mismatch`;
  - `WithRevocation(nil)` and `WithRevocation(&certcheck.Revocation{})` panic.
- `providers/providers_test.go` (package `providers_test`):
  - `TestAllMatchesDeclarations`:
    - `All()` has the IDs of `profiles.All()`, in order;
    - each `Info()` equals `{ID, Name, Description, Beta}` of its declaration;
    - each `CAs()` equals the enabled anchors then the intermediates of `profiles.Default`, in
      registry order;
    - `certcheck.NewHandler(All())` succeeds.
  - `TestStandardAndByID`: `Standard()` returns the non-beta IDs in order; `ByID` works for each
    ID; `ByID("nope")` gives `(nil, false)`.
  - `TestInertProviders` (the clock is 2100-01-01): `All`, `Standard` and `ByID` give nothing.
    `fnmt.New(clock)` keeps its `Info`, has 0 CAs and `Verify` → `provider_mismatch`/`bounds`/
    `provider has no enabled profile`, and `NewHandler([]{p})` errors.
  - `TestPackagesExportOnlyConstructors`: `go/parser.ParseFile` over `*/*.go`, without
    `ParseDir`, which is deprecated and flagged by staticcheck SA1019. Each of the 12 directories exports only
    functions `New...(...certcheck.Option) certcheck.Provider`, with no exported types, vars or
    consts.
- `world_test.go` (package `certcheck_test`): the shared world.
  - `hWorld` holds alpha (rootA, policy 1.3.6.1.4.1.99999.5.1) and beta (rootB, policy .5.2), one
    profile each, built with `engine.New`; alpha's OCSP answers good on a `testpki.Net`; rootU is
    pinned by nobody. The handler uses `WithClock(now)` and `WithVersion("handler-test")`.
  - Helpers: `hAdapter`, `hDecl`, `hProvider`, `newHWorld`, `(*hWorld).leaf`, `(*hWorld).issue`
    (returns `*testpki.Leaf` for TLS clients), `hErr`, and `fakeProvider{id, cas}` (a consumer test
    double).
  - The prototype has the full text of the world and its tests in `proto/handler_test.go`.
- `handler_test.go`:
  - `TestNewHandlerRejects`, one case each, the error containing the quoted text:
    - no providers: `at least one provider`;
    - nil provider: `provider 1 is nil`;
    - duplicate ID: `duplicate provider "alpha"`;
    - inert engine provider, anchor expired: `provider "delta" has no enabled profile`;
    - inert test double: `provider "empty" has no enabled profile`;
    - shared CA subject (a double advertising rootA): `both advertise the CA`;
    - shared anchor key and policy (gamma: another subject, rootA's key, alpha's policy):
      `share an anchor and policy 1.3.6.1.4.1.99999.5.1`.

    The same key under another policy is accepted.
  - `TestTLSConfig`:
    - default: TLS 1.2 only;
    - `WithTLS13()`: max 1.3;
    - in both: the six suites, curves [X25519, P-256, P-384], `RequestClientCert`, tickets disabled,
      `NextProtos` [http/1.1], `ClientCAs.Equal(h.ClientCAs())` and `GetCertificate` set.

Run: `go test ./internal/engine ./providers/... . -run 'FromOptions|AllMatches|StandardAndByID|Inert|ExportOnly|NewHandlerRejects|TLSConfig'`.
Expected: build failure (undefined: engine.FromOptions, providers.All, certcheck.WithTLS13).

Step 2: implement.

`internal/engine/options.go`:

```go
package engine

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/opts"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// FromOptions builds the provider of a public constructor (providers/...):
// it applies the certcheck options over the defaults (the process-wide
// revocation checker, time.Now, slog.Default()). The declaration is compiled
// in and tested, so a load error (pin mismatch, non-CA anchor, malformed
// declaration, handled extension without a parser) is a build-time invariant
// violation and panics with the loader's message. An anchor outside validity
// is not an error: the provider may be inert (see New).
func FromOptions(p profiles.Provider, options ...certcheck.Option) certcheck.Provider {
	s := opts.Apply(options...)
	rev := s.Revocation
	if rev == nil {
		var err error
		if rev, err = opts.DefaultRevocation(); err != nil {
			panic("certcheck: default revocation checker: " + err.Error())
		}
	}
	e, err := New(Config{Provider: p, Revocation: rev, Now: s.Now, Logger: s.Logger, Version: s.Version, MaxChainLen: s.MaxChainLen})
	if err != nil {
		panic("certcheck: provider " + p.ID + ": " + err.Error())
	}
	return e
}
```

Provider package shape, `providers/idcat/idcat.go`:

```go
// Package idcat provides the idCAT certificate type of the Consorci AOC
// (Catalonia). Pass its provider to certcheck.NewHandler.
package idcat

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/engine"
	"github.com/vocdoni/cert-check/internal/profiles"
)

// New returns the idCAT Certificat provider: citizen certificates issued by
// EC-Ciutadania (profile aoc-idcat-g2) and SubCA CIUTADANIA Q (G3) A.2
// (aoc-idcat-g3). opts are certcheck options. If no pinned anchor is valid
// at construction the provider is inert (no CAs) and certcheck.NewHandler
// rejects it.
func New(opts ...certcheck.Option) certcheck.Provider {
	return engine.FromOptions(profiles.IDCAT(), opts...)
}
```

The other packages follow the same shape: package doc, one constructor each, no data.

| Package | Doc subject | Constructors → declaration (profiles) |
|---|---|---|
| `providers/fnmt` | FNMT-RCM certificate types | `New` → `FNMT()` (fnmt-citizen-rsa, -g2); `NewRepresentative` (beta) → `FNMTRepresentative()`; `NewEmployee` (beta) → `FNMTEmployee()` |
| `providers/idcat` | Consorci AOC idCAT | `New` → `IDCAT()` |
| `providers/accv` | ACCV citizen software | `New` → `ACCV()` |
| `providers/dnie` | DNI electrónico (beta; the browser must reach the card) | `New` → `DNIe()` |
| `providers/digitel` | DIGITEL ON citizen software | `New` → `Digitel()` |
| `providers/bewor` | Bewor natural person software | `New` → `Bewor()` |
| `providers/sectigo` | Sectigo qualified citizen | `New` → `Sectigo()` |
| `providers/firmaprofesional` | Firmaprofesional natural person (beta) | `New` → `Firmaprofesional()` |
| `providers/anf` | ANF AC class 2 natural person (beta) | `New` → `ANF()` |
| `providers/uanataca` | Uanataca citizen software (beta) | `New` → `Uanataca()` |
| `providers/signe` | SIGNE natural person, other devices (beta) | `New` → `SIGNE()` |
| `providers/lleidanet` | Lleidanet / inDenova natural person software (beta) | `New` → `Lleidanet()` |

`providers/providers.go`:

```go
// Package providers builds every supported certificate type at once.
// Programs that accept only some types import their packages instead
// (providers/fnmt, providers/idcat, ...).
package providers

import (
	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/providers/accv"
	"github.com/vocdoni/cert-check/providers/anf"
	"github.com/vocdoni/cert-check/providers/bewor"
	"github.com/vocdoni/cert-check/providers/digitel"
	"github.com/vocdoni/cert-check/providers/dnie"
	"github.com/vocdoni/cert-check/providers/firmaprofesional"
	"github.com/vocdoni/cert-check/providers/fnmt"
	"github.com/vocdoni/cert-check/providers/idcat"
	"github.com/vocdoni/cert-check/providers/lleidanet"
	"github.com/vocdoni/cert-check/providers/sectigo"
	"github.com/vocdoni/cert-check/providers/signe"
	"github.com/vocdoni/cert-check/providers/uanataca"
)

// constructors lists every certificate type in display order: the standard
// ones first, then the beta group.
var constructors = []func(...certcheck.Option) certcheck.Provider{
	fnmt.New, idcat.New, accv.New, digitel.New, bewor.New, sectigo.New,
	fnmt.NewRepresentative, fnmt.NewEmployee, firmaprofesional.New, anf.New, uanataca.New, signe.New, lleidanet.New, dnie.New,
}

// All returns every supported certificate type in display order (standard
// first, then beta), built with opts. A type with no valid anchor at
// construction (inert) is omitted, so the result can be passed to
// certcheck.NewHandler as is.
func All(opts ...certcheck.Option) []certcheck.Provider {
	out := make([]certcheck.Provider, 0, len(constructors))
	for _, newProvider := range constructors {
		if p := newProvider(opts...); len(p.CAs()) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// Standard is All without the beta types.
func Standard(opts ...certcheck.Option) []certcheck.Provider {
	var out []certcheck.Provider
	for _, p := range All(opts...) {
		if !p.Info().Beta {
			out = append(out, p)
		}
	}
	return out
}

// ByID returns the certificate type whose Info().ID is id, built with opts.
// It reports false for an unknown ID and for an inert type.
func ByID(id string, opts ...certcheck.Option) (certcheck.Provider, bool) {
	for _, newProvider := range constructors {
		if p := newProvider(opts...); p.Info().ID == id {
			if len(p.CAs()) == 0 {
				return nil, false
			}
			return p, true
		}
	}
	return nil, false
}
```

`tls.go` (security-relevant; the policy, `CheckHost` and the TLS-diagnostics fill copied from base
`tlsauth.go`):

```go
package certcheck

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
)

// ErrMisdirected is returned by CheckHost when the request Host differs from
// the TLS server name (answer 421 Misdirected Request).
var ErrMisdirected = errors.New("certcheck: Host does not match the TLS server name")

// tls12Suites are the TLS 1.2 suites of TLSConfig: ECDHE with AEAD only.
var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// TLSOption configures Handler.TLSConfig.
type TLSOption func(*tlsSettings)

type tlsSettings struct{ tls13 bool }

// WithTLS13 allows TLS 1.3. Without it the configuration is TLS 1.2 only:
// TLS 1.3 needs an RSA-PSS CertificateVerify, which many smart cards, TPM
// keys and legacy Windows key stores cannot produce. The cost of TLS 1.2 is
// that the client certificate crosses the network unencrypted.
func WithTLS13() TLSOption { return func(s *tlsSettings) { s.tls13 = true } }

// TLSConfig returns the server configuration of a listener that
// authenticates with h: TLS 1.2 (see WithTLS13), ECDHE AEAD suites, curves
// X25519, P-256 and P-384, a client certificate requested but not required
// with h's CAs advertised, session tickets disabled (every connection
// presents its certificate again) and ALPN http/1.1 only. getCert supplies
// the server certificate; it may be nil when the caller sets Certificates.
func (h *Handler) TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), options ...TLSOption) *tls.Config {
	var s tlsSettings
	for _, o := range options {
		o(&s)
	}
	maxVersion := uint16(tls.VersionTLS12)
	if s.tls13 {
		maxVersion = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             maxVersion,
		CipherSuites:           slices.Clone(tls12Suites),
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		ClientAuth:             tls.RequestClientCert,
		ClientCAs:              h.ClientCAs(),
		SessionTicketsDisabled: true,
		NextProtos:             []string{"http/1.1"},
		GetCertificate:         getCert,
	}
}

// Auth verifies the client certificate chain of r (Verify on
// r.TLS.PeerCertificates) and adds the handshake details to the
// diagnostics. Every call runs the full pipeline. A request without TLS state
// is an internal error with empty Diagnostics. The error is always *Error.
func (h *Handler) Auth(r *http.Request) (*Result, error) {
	if r.TLS == nil {
		return nil, errNoTLS()
	}
	res, err := h.Verify(r.Context(), r.TLS.PeerCertificates)
	return withTLSInfo(r.TLS, res, err)
}

// AuthAs is Auth with the provider chosen by the caller (VerifyAs).
func (h *Handler) AuthAs(r *http.Request, providerID string) (*Result, error) {
	if r.TLS == nil {
		return nil, errNoTLS()
	}
	res, err := h.VerifyAs(r.Context(), providerID, r.TLS.PeerCertificates)
	return withTLSInfo(r.TLS, res, err)
}

func errNoTLS() *Error {
	return &Error{Code: CodeInternal, Retryable: true, Detail: "request without TLS state"}
}

func withTLSInfo(cs *tls.ConnectionState, res *Result, err error) (*Result, error) {
	info := DescribeTLS(cs)
	if err != nil {
		if e, ok := errors.AsType[*Error](err); ok {
			e.Diagnostics.TLS = info
		}
		return nil, err
	}
	res.Diagnostics.TLS = info
	return res, nil
}

// CheckHost returns ErrMisdirected when r.Host (port stripped, compared
// case-insensitively) differs from r.TLS.ServerName, or r has no TLS state.
// Call it before Auth on a listener that serves several names.
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
```

Run: checks on the root module.

Step 3: commit
`git commit -m "feat(providers): add per-issuer constructors and the handler tls glue" -- internal/engine providers tls.go world_test.go handler_test.go`

Reviewer commands:
- `git show <base>:certauth/tlsauth/tlsauth.go`, side by side with `tls.go`: the suites, the
  `tls.Config` literal, `CheckHost` and the TLS-info fill must match;
- `for p in $(go list ./providers/...); do go doc -short $p; done` lists only constructors.

Interfaces provided:
- `engine.FromOptions(profiles.Provider, ...certcheck.Option) certcheck.Provider`;
- `providers.{All, Standard, ByID}`;
- the 12 provider packages;
- `certcheck.{TLSOption, WithTLS13, ErrMisdirected, CheckHost}`, `Handler.{TLSConfig, Auth, AuthAs}`.

### Task 4: the testing UI on the new API

Model: opus   Repo: same branch
Files:
- `testui/internal/server/{tlsconfig,app,auth,api,txstore}.go`, `testui/main.go`;
- tests: `testui/internal/server/{tlsconfig,api,app,auth,e2e,live,golden,txstore,fixtures_contract}_test.go`,
  `testui/internal/server/deployed_test.go` (new, `-tags live`);
- `testui/internal/probe/*.go` and `testui/main_test.go` only if a qualifier still says `certauth`.

Goal: AC2, AC6 (service golden through the production construction path) and AC9 (deploy check
tooling). The module compiles and passes again.

Logic changes allowed:
- `tlsconfig.go`: the declared API change below. `GetConfigForClient` and `AuthHosts.Provider` keep
  their bodies.
- `app.go`: Handler construction, the provider ID set, `/readyz` on `len(a.providers) > 0`.
- `auth.go`: `validate(r, provider)` calls `handler.AuthAs`; `certcheck.CheckHost`.
- `api.go`: providers from `Info()`; create checks the ID set.
- `main.go`: provider construction (R7).

Names-only files: `txstore.go` and every other file (`certauth.` → `certcheck.`).

Step 1: re-point the tests first. They fail to compile until step 2.
- `tlsconfig_test.go`:
  - `world.checker` becomes `providers []certcheck.Provider` (built with `engine.New`, clock fixed)
    plus `handler *certcheck.Handler` (`WithClock`, `WithVersion("test")`);
  - `config()` passes `Providers: w.providers`;
  - new helper `(w *world) pool(t, id)`: the provider's CAs as a pool. It replaces
    `checker.ClientCAs(id)` in `TestServerConfigPerProvider`;
  - `TestServerConfigRequiresOptions` cases: `no providers` (renamed subtest), `no domain`,
    `no certificate source`;
  - `startServer` decodes the provider with `server.NewAuthHosts(authDomain).Provider(r.TLS.ServerName)`
    and calls `w.handler.AuthAs(r, id)`;
  - `TestAuthenticateWithoutTLS` calls `w.handler.AuthAs(req, "alpha")`;
  - `TestCheckHost` uses `certcheck.CheckHost`/`certcheck.ErrMisdirected`;
  - `TestProvider` uses `server.NewAuthHosts("Auth.Test")`.

  Every expectation stays the same. The five `TestAuthenticate*`/`TestCheckHost` tests stay here
  until Task 5 moves them.
- `api_test.go`:
  - `srvWorld.checker` becomes `providers` plus `handler`, both clocked at `now`;
  - `Deps.Providers`;
  - `TestRedeem` uses `w.handler.VerifyAs`;
  - the production list in `TestProvidersEndpoint` is
    `providers.All(certcheck.WithRevocation(rev), certcheck.WithLogger(srvDiscard), certcheck.WithVersion(srvVersion))`,
    with `rev` from `certcheck.NewRevocation(certcheck.RevocationOptions{UserAgent: "cert-check/test", Logger: srvDiscard})`.
- `app_test.go`: `Deps.Providers`; the subtest `no checker` becomes `no providers`.
- `auth_test.go`: `w.app.auth.validate(req, "alpha")`.
- `e2e_test.go`:
  - `e2ePKI.providers` from `engine.New` per declaration;
  - `e2eProviders(alphaCA, betaCA)` (P10): beta's profile anchors `betaCA`
    (`testpki.NewRoot(t, "E2E Beta Test CA", ...)`);
  - `startE2E(t, providers, logs, clk)`;
  - the doc comments say "one profile and one CA each".
- `live_test.go`:
  - run 1 builds `engine.New` per `profiles.All()` declaration, with `TestMarkers` nil,
    `Reserved: &identity.Reserved{}` and a live `revocation.NewChecker(UserAgent "cert-check/live-test")`,
    keeping the non-inert ones;
  - run 2 uses `providers.All(certcheck.WithRevocation(rev), certcheck.WithLogger(logs.logger()), certcheck.WithVersion(e2eVersion))`,
    the production path;
  - `liveBeworRedeem(t, providers, logs, cred)`.
- `golden_test.go`: `startE2E(t, providers.All(WithRevocation(NewRevocation UA "cert-check/golden"), WithLogger, WithVersion(e2eVersion)), ...)`.
  The golden files are untouched.
- New `deployed_test.go` (`//go:build live`). It never runs in CI (no env); the release runs it:

```go
//go:build live

package server_test

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDeployedServiceGolden (AC9) checks a deployed service against the AC6
// service goldens: the providers API body byte for byte, and the ordered
// certificate_authorities list of every provider host. It runs after a
// deploy, never in CI:
//
//	CERTCHECK_DEPLOYED_URL=https://cert-check.vocdoni.dev \
//	CERTCHECK_DEPLOYED_AUTH=auth.cert-check.vocdoni.dev:32931 \
//	go test -tags live -count=1 -run TestDeployedServiceGolden ./internal/server
func TestDeployedServiceGolden(t *testing.T) {
	base, auth := os.Getenv("CERTCHECK_DEPLOYED_URL"), os.Getenv("CERTCHECK_DEPLOYED_AUTH")
	authDomain, port, err := net.SplitHostPort(auth)
	if base == "" || err != nil {
		t.Fatalf("CERTCHECK_DEPLOYED_URL (https://<host>) and CERTCHECK_DEPLOYED_AUTH (<auth domain>:<port>) are required: %v", err)
	}
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(strings.TrimSuffix(base, "/") + "/api/v1/providers")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET providers: status %d, %v", resp.StatusCode, err)
	}
	want, err := os.ReadFile(filepath.Join(goldenDir, "providers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(want) {
		t.Errorf("providers body differs from the golden:\n got: %s\nwant: %s", body, want)
	}

	raw, err := os.ReadFile(filepath.Join(goldenDir, "certificate-authorities.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string][]goldenCA // keyed "<id>.auth.test"
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	for _, key := range slices.Sorted(maps.Keys(golden)) {
		id := strings.TrimSuffix(key, "."+e2eAuthDomain)
		sni := id + "." + authDomain
		t.Run(id, func(t *testing.T) {
			var got [][]byte
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(sni, port), &tls.Config{
				ServerName: sni, MaxVersion: tls.VersionTLS12,
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					got = cri.AcceptableCAs
					return &tls.Certificate{}, nil
				}})
			if err != nil {
				t.Fatalf("handshake %s: %v", sni, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			var names []goldenCA
			for _, der := range got {
				var rdn pkix.RDNSequence
				if _, err := asn1.Unmarshal(der, &rdn); err != nil {
					t.Fatal(err)
				}
				var n pkix.Name
				n.FillFromRDNSequence(&rdn)
				names = append(names, goldenCA{DER: hex.EncodeToString(der), Name: n.String()})
			}
			if !slices.Equal(names, golden[key]) {
				t.Errorf("certificate_authorities = %+v, want %+v", names, golden[key])
			}
		})
	}
}
```

Step 2: implement. `tlsconfig.go` (security-relevant; full text):

```go
package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	certcheck "github.com/vocdoni/cert-check"
)

// ConfigOptions configures ServerConfig.
type ConfigOptions struct {
	Providers      []certcheck.Provider // one auth host each
	AuthDomain     string               // e.g. "auth.cert-check.vocdoni.dev"; provider hosts are "<id>.<AuthDomain>"
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	AllowTLS13     bool         // CERTCHECK_AUTH_TLS13 (deviation D2); default TLS 1.2 only
	Logger         *slog.Logger // handshake-level debug lines; nil = slog.Default()
}

// maxLoggedSNI caps the client-chosen server name in logs and errors.
const maxLoggedSNI = 64

// ServerConfig returns the auth listener's tls.Config. Its
// GetConfigForClient selects the provider config by exact, lowercased SNI
// "<id>.<AuthDomain>"; an unknown SNI is a handshake error (internal_error
// alert), so nothing is served without a provider. Each provider config is
// the certcheck.Handler TLSConfig of a handler holding that provider alone.
func ServerConfig(o ConfigOptions) (*tls.Config, error) {
	if len(o.Providers) == 0 || o.GetCertificate == nil || o.AuthDomain == "" {
		return nil, errors.New("server: Providers, GetCertificate and AuthDomain are required")
	}
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	var tlsOpts []certcheck.TLSOption
	if o.AllowTLS13 {
		tlsOpts = append(tlsOpts, certcheck.WithTLS13())
	}
	domain := strings.ToLower(o.AuthDomain)
	perSNI := map[string]*tls.Config{}
	for _, p := range o.Providers {
		h, err := certcheck.NewHandler([]certcheck.Provider{p})
		if err != nil {
			return nil, err
		}
		perSNI[p.Info().ID+"."+domain] = h.TLSConfig(o.GetCertificate, tlsOpts...)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni := strings.ToLower(hello.ServerName)
			cfg, ok := perSNI[sni]
			if !ok {
				// Debug, not Warn: scanners reach the port with empty or
				// random SNI all the time. The client-chosen name is capped.
				shown := sni[:min(len(sni), maxLoggedSNI)]
				log.Debug("auth handshake rejected: unknown SNI", "sni", shown)
				return nil, fmt.Errorf("server: unknown server name %q", shown)
			}
			return cfg, nil
		},
	}, nil
}

// AuthHosts maps the auth listener's server names to provider IDs.
type AuthHosts struct {
	suffix string // "." + AuthDomain
}

// NewAuthHosts returns the AuthHosts of authDomain.
func NewAuthHosts(authDomain string) *AuthHosts {
	return &AuthHosts{suffix: "." + strings.ToLower(authDomain)}
}

// Provider returns the provider ID encoded in a TLS server name.
func (h *AuthHosts) Provider(serverName string) (string, bool) {
	id, ok := strings.CutSuffix(strings.ToLower(serverName), h.suffix)
	if !ok || id == "" || strings.Contains(id, ".") {
		return "", false
	}
	return id, true
}
```

`app.go`:
- `Deps.Checker` → `Providers []certcheck.Provider` ("display order; one auth host each"); the
  `Now` doc adds "and handler";
- `New` requires `len(d.Providers) > 0`, with the error
  `server: Providers, Certs, Logger and Config are required`;
- `New` builds
  `handler, err := certcheck.NewHandler(d.Providers, certcheck.WithClock(now), certcheck.WithVersion(d.Version))`;
- the `App` keeps `providers` and `providerIDs map[string]bool`;
- `ServerConfig(ConfigOptions{Providers: d.Providers, ...})`;
- `authHandler{hosts: NewAuthHosts(d.Config.AuthDomain), handler: handler, ...}`;
- `/readyz` checks `len(a.providers) > 0` where it checked `len(a.checker.Providers()) > 0`.

`auth.go`:
- the field `tls *tlsauth.Handler` becomes `hosts *AuthHosts` and `handler *certcheck.Handler`;
- `certcheck.CheckHost(r)`;
- `a.hosts.Provider(...)` (twice);
- `outcome := a.validate(r, provider)`;
- in `validate`, `res, err := a.handler.AuthAs(r.WithContext(ctx), provider)` (the comment says
  "AuthAs's request-without-TLS error carries no diagnostics");
- nothing else changes.

`api.go`:
- `handleProviders` ranges over `a.providers`, using `info := p.Info()`;
- `handleCreate` uses `if !a.providerIDs[body.Provider]` in place of the `ClientCAs` lookup;
- the message table (`certcheck.Code*`) is otherwise unchanged.

`main.go`, in place of `profiles.Default` + `revocation.NewChecker` + `certauth.NewChecker`:

```go
	rev, err := certcheck.NewRevocation(certcheck.RevocationOptions{UserAgent: "cert-check/" + version, Logger: log})
	if err != nil {
		return err
	}
	provs := providers.All(certcheck.WithRevocation(rev), certcheck.WithLogger(log), certcheck.WithVersion(version))
```

Then `server.Deps{..., Providers: provs, ...}`, and the start log line uses `"providers", len(provs)`.
`runProbe` keeps `revocation.NewChecker` (the probe needs the internal checker; R1).

Run:
- checks on both modules, and the test-name check: it prints nothing, since the five
  `TestAuthenticate*`/`TestCheckHost` are still in testui;
- `docker build -f testui/Dockerfile -t cert-check:task4 .`, then remove the image.

Step 3: commit
`git commit -m "refactor(testui): run the testing ui on certcheck providers and the handler" -- testui`

Reviewer commands:
- `git diff -M <base> HEAD -- certauth/tlsauth/tlsauth.go testui/internal/server/tlsconfig.go`;
- `git diff -M <base> HEAD -- internal/server/auth.go testui/internal/server/auth.go internal/server/app.go testui/internal/server/app.go internal/server/txstore.go testui/internal/server/txstore.go`;
- `git diff -M <base> HEAD -- cmd/cert-check/main.go testui/main.go`.

Tests (AC mapping):
- AC2: every testui test, e2e, the fixture contract, headers;
- AC6: `TestGoldenService`;
- AC9 tooling: `TestDeployedServiceGolden`.

### Task 5: public tests, API golden and CI

Model: opus   Repo: same branch
Files:
- `handler_test.go` (rest), `tls_test.go` (new), `example_test.go` (new), `api_test.go` (new),
  `testdata/godoc.golden` (generated);
- `internal/opts/opts_test.go`;
- `testui/internal/server/tlsconfig_test.go` (the five moved tests removed);
- `.github/workflows/ci.yml`.

Goal: AC4 (go doc golden, reflect test), AC5 (examples), AC7 (the rest) and AC1 (CI).

Logic changes allowed: none in production code. This is a test-only task, plus CI.

Tests:
- `handler_test.go`:
  - `TestHandlerVerifySelectsByIssuer`: an alpha leaf → a Result with provider `{alpha, ALPHA}` and
    the document; a beta leaf → beta's `revocation_unavailable` (no responder) with
    `Diagnostics.Provider` beta.
  - `TestHandlerVerifyNoCandidate`: a leaf under rootU (chain leaf+rootU):
    - `untrusted_issuer`, not retryable, at `path`;
    - `Diagnostics.Code`/`TechnicalDetail` equal Code/Detail;
    - a 32-hex ID; Time = clock; ServerVersion `handler-test`; Provider "";
    - 2 chain entries; `Certificate.SHA256` = the leaf's.

    `Verify(nil)` → `no_certificate` at `bounds`.
  - `TestHandlerVerifyAs`. In every case the diagnostics carry the named provider, an ID and the
    version, and path cases have the named provider's single candidate. Cases:
    - `unknown provider` (`nope`) → `provider_mismatch`/`bounds`/`unknown provider`;
    - `another provider's leaf` (alpha leaf as beta) → `provider_mismatch`/`path`, with detail and
      technicalDetail `x509: certificate signed by unknown authority`;
    - `unhandled critical extension under another provider` → `provider_mismatch`/`path`;
    - `unknown CA` → `untrusted_issuer`/`path`.

    Also `beta.Verify(alpha leaf)` → `untrusted_issuer` (standalone contract).
  - `TestHandlerAuthAs`. For `Auth` and for `AuthAs(r, "alpha")`, with `r.TLS` set by hand:
    - success: `Diagnostics.TLS == DescribeTLS(state)`;
    - failure (rootU leaf): TLS info is filled;
    - nil `r.TLS`: `internal`, retryable, detail `request without TLS state`, empty
      `DiagnosticID`.
  - `TestHandlerCAs`:
    - `Certificates()` is [rootA, rootB] DER, in order, deduplicated;
    - `CertificateCheck` is true for both subjects and false for rootU;
    - `ClientCAs()` equals the pool of both;
    - mutating a returned slice or the `Providers()` slice does not change the handler;
    - `Name() == "certcheck"`, `RequireCertificate()`.
- `tls_test.go`: moved, with the same names and assertions, from `tlsconfig_test.go` (P13).
  - Copy `authCall`, `authServer` (`client`, `get`), and `startServer` on `hWorld`, which serves
    `w.h.TLSConfig(getCert)` with a `testpki.ServerTLS(t, alphaHost, betaHost)` certificate and calls
    `w.h.AuthAs(r, <label before the first dot of the SNI>)`.
  - Then `TestAuthenticateSuccessAndTLSInfo`, `TestAuthenticateErrorCarriesTLS` (alpha leaf forced
    onto beta → `provider_mismatch`, SNI beta, Provider beta), `TestAuthenticateRunsEveryRequest`
    (one keep-alive connection, two distinct diagnostic IDs), `TestAuthenticateWithoutTLS` and
    `TestCheckHost` (all 11 cases, `certcheck.ErrMisdirected`).
  - Delete the same five from `testui/internal/server/tlsconfig_test.go`. Its `authServer` helpers
    stay for `TestRequestClientCertOptional`.
- `example_test.go` (AC5; compiled and run):

```go
package certcheck_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/providers/fnmt"
	"github.com/vocdoni/cert-check/providers/idcat"
)

// A program accepts the certificate types whose providers it constructs.
func Example() {
	h, err := certcheck.NewHandler([]certcheck.Provider{idcat.New(), fnmt.New()})
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range h.Providers() {
		fmt.Println(p.Info().ID, "-", p.Info().Name)
	}
	// Output:
	// idcat - idCAT Certificat
	// fnmt - FNMT - Persona Física
}

// The handler supplies the TLS configuration of the listener that asks for
// the client certificate, and verifies the certificate of each request.
func ExampleHandler_Auth() {
	h, err := certcheck.NewHandler([]certcheck.Provider{idcat.New(), fnmt.New()})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if err := certcheck.CheckHost(r); err != nil {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second) // OCSP and CRL fetches
		defer cancel()
		res, err := h.Auth(r.WithContext(ctx))
		if err != nil {
			if e, ok := errors.AsType[*certcheck.Error](err); ok {
				slog.Info("certificate rejected", slog.Any("diagnostics", e.Diagnostics.LogAttrs()))
				http.Error(w, string(e.Code), http.StatusForbidden)
			}
			return
		}
		fmt.Fprintf(w, "hello %s (%s %s)\n", res.Identity.FullName, res.Identity.Document.Type, res.Identity.Document.Number)
	})
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error) // e.g. from certmagic or autocert
	var protocols http.Protocols
	protocols.SetHTTP1(true) // the TLS configuration offers http/1.1 only
	srv := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: h.TLSConfig(getCertificate), Protocols: &protocols}
	// log.Fatal(srv.ListenAndServeTLS("", ""))
	fmt.Println(srv.TLSConfig.ClientAuth, srv.TLSConfig.MaxVersion == tls.VersionTLS12)
	// Output: RequestClientCert true
}

// A Result carries the provider, the profile and the holder's identity.
func ExampleResult() {
	const body = `{"provider":{"id":"fnmt","name":"FNMT - Persona Física"},
		"profile":{"id":"fnmt-citizen-rsa","name":"FNMT Persona Física (AC FNMT Usuarios)","holderRole":"natural_person"},
		"identity":{"document":{"type":"DNI","country":"ES","number":"12345679S","raw":"IDCES-12345679S"},
		"givenNames":"JUAN","surnames":"GARCÍA LÓPEZ","firstSurname":"GARCÍA","secondSurname":"LÓPEZ","fullName":"JUAN GARCÍA LÓPEZ"}}`
	var res certcheck.Result
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		log.Fatal(err)
	}
	id := res.Identity
	fmt.Println(id.Document.Type, id.Document.Number)
	fmt.Println(id.GivenNames, "/", id.FirstSurname, "/", id.SecondSurname)
	fmt.Println(res.Provider.ID, res.Profile.HolderRole)
	// Output:
	// DNI 12345679S
	// JUAN / GARCÍA / LÓPEZ
	// fnmt natural_person
}

// Every failure is an *Error with a typed code. FNMT publishes this specimen
// as a test certificate, so it is refused before any network access.
func ExampleError() {
	raw, err := os.ReadFile("testdata/specimens/fnmt-ecc-g2-activo-especimen-99949991H-2025.pem")
	if err != nil {
		log.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	clock := func() time.Time { return leaf.NotBefore.Add(time.Hour) } // the day it was issued
	h, err := certcheck.NewHandler([]certcheck.Provider{fnmt.New(certcheck.WithClock(clock))}, certcheck.WithClock(clock))
	if err != nil {
		log.Fatal(err)
	}
	_, err = h.Verify(context.Background(), []*x509.Certificate{leaf})
	if e, ok := errors.AsType[*certcheck.Error](err); ok {
		fmt.Println(e.Code, e.Diagnostics.FailedStep, e.Retryable)
	}
	// Output: test_certificate test_marker false
}
```

- `api_test.go` (AC4 and the R8 reflect test):

```go
package certcheck_test

import (
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	certcheck "github.com/vocdoni/cert-check"
)

// apiTypes maps every exported type of package certcheck to its reflect
// type. TestPublicFieldTypesNamed fails when testdata/godoc.golden declares a
// type that is missing here, so the map stays complete.
var apiTypes = map[string]reflect.Type{
	"CandidateResult":    reflect.TypeFor[certcheck.CandidateResult](),
	"CertificateDetails": reflect.TypeFor[certcheck.CertificateDetails](),
	"CertificateInfo":    reflect.TypeFor[certcheck.CertificateInfo](),
	"ChainEntry":         reflect.TypeFor[certcheck.ChainEntry](),
	"Date":               reflect.TypeFor[certcheck.Date](),
	"Diagnostics":        reflect.TypeFor[certcheck.Diagnostics](),
	"Document":           reflect.TypeFor[certcheck.Document](),
	"DocumentType":       reflect.TypeFor[certcheck.DocumentType](),
	"Error":              reflect.TypeFor[certcheck.Error](),
	"ErrorCode":          reflect.TypeFor[certcheck.ErrorCode](),
	"Handler":            reflect.TypeFor[certcheck.Handler](),
	"Identity":           reflect.TypeFor[certcheck.Identity](),
	"Option":             reflect.TypeFor[certcheck.Option](),
	"Organization":       reflect.TypeFor[certcheck.Organization](),
	"ProfileInfo":        reflect.TypeFor[certcheck.ProfileInfo](),
	"Provider":           reflect.TypeFor[certcheck.Provider](),
	"ProviderInfo":       reflect.TypeFor[certcheck.ProviderInfo](),
	"ProviderRef":        reflect.TypeFor[certcheck.ProviderRef](),
	"Result":             reflect.TypeFor[certcheck.Result](),
	"Revocation":         reflect.TypeFor[certcheck.Revocation](),
	"RevocationAttempt":  reflect.TypeFor[certcheck.RevocationAttempt](),
	"RevocationInfo":     reflect.TypeFor[certcheck.RevocationInfo](),
	"RevocationMethod":   reflect.TypeFor[certcheck.RevocationMethod](),
	"RevocationOptions":  reflect.TypeFor[certcheck.RevocationOptions](),
	"RevocationStatus":   reflect.TypeFor[certcheck.RevocationStatus](),
	"Role":               reflect.TypeFor[certcheck.Role](),
	"Step":               reflect.TypeFor[certcheck.Step](),
	"TLSInfo":            reflect.TypeFor[certcheck.TLSInfo](),
	"TLSOption":          reflect.TypeFor[certcheck.TLSOption](),
}

// TestPublicFieldTypesNamed walks the exported fields of every exported type
// and fails on a named type from an internal package that package certcheck
// does not alias: a program could not name it.
func TestPublicFieldTypesNamed(t *testing.T) {
	raw, err := os.ReadFile("testdata/godoc.golden")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	var declared []string
	for _, m := range regexp.MustCompile(`(?m)^type (\w+) `).FindAllStringSubmatch(doc, -1) {
		declared = append(declared, m[1])
	}
	for _, name := range declared {
		if _, ok := apiTypes[name]; !ok {
			t.Errorf("type %s is in testdata/godoc.golden but not in apiTypes", name)
		}
	}
	for name := range apiTypes {
		if !slices.Contains(declared, name) {
			t.Errorf("apiTypes lists %s, which testdata/godoc.golden does not declare", name)
		}
	}
	aliased := map[string]bool{} // "identity.Date" for "type Date = identity.Date"
	for _, m := range regexp.MustCompile(`(?m)^type \w+ = (\w+\.\w+)$`).FindAllStringSubmatch(doc, -1) {
		aliased[m[1]] = true
	}
	seen := map[reflect.Type]bool{}
	var walk func(where string, typ reflect.Type)
	walk = func(where string, typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		if typ.Name() != "" && strings.Contains(typ.PkgPath(), "/internal/") && !aliased[path.Base(typ.PkgPath())+"."+typ.Name()] {
			t.Errorf("%s has type %s.%s, which package certcheck does not alias", where, typ.PkgPath(), typ.Name())
		}
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(where, typ.Elem())
		case reflect.Map:
			walk(where, typ.Key())
			walk(where, typ.Elem())
		case reflect.Struct:
			for f := range typ.Fields() {
				if f.IsExported() {
					walk(where+"."+f.Name, f.Type)
				}
			}
		}
	}
	for name, typ := range apiTypes {
		walk(name, typ)
	}
}
```

- `testdata/godoc.golden`: generated with `go doc -all . > testdata/godoc.golden` after the doc
  comments are final. Review it as the public API list: every name of AC4, and nothing else.
- `internal/opts/opts_test.go`:
  - `TestApply`: later options win, nil functions are skipped, and the zero `Settings` holds nil
    defaults;
  - `TestDefaultRevocationShared`: two calls return the same pointer and a nil error.

CI (`.github/workflows/ci.yml`, final):

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
  # Only superseded pull request runs are cancelled: a cancelled run on main
  # would leave that commit without a green check, so Railway would never deploy it.
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  ci:
    runs-on: [self-hosted, ci]
    timeout-minutes: 40
    # No CGO_ENABLED=0 at job level: the race detector needs cgo. The pure-Go
    # build is checked by its own step and by the Dockerfile.
    env:
      GOFLAGS: -mod=readonly
      # The library is the root module; the testing UI is the nested module
      # testui/ (it requires the root through `replace => ../`).
      MODULES: ". testui"
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
      - uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16 # v6.5.0
        with:
          go-version: "1.27.x"
          cache: true
          cache-dependency-path: |
            go.sum
            testui/go.sum
      - name: gofmt
        run: test -z "$(gofmt -l .)" || (gofmt -l . && exit 1)
      - name: go mod tidy
        run: for m in $MODULES; do (cd "$m" && go mod tidy -diff); done
      - name: vet
        run: for m in $MODULES; do (cd "$m" && go vet ./... && go vet -tags live ./...); done
      - name: staticcheck
        run: for m in $MODULES; do (cd "$m" && go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...); done
      - name: build (pure Go, no cgo)
        run: for m in $MODULES; do (cd "$m" && CGO_ENABLED=0 go build -trimpath ./...); done
      - name: test
        run: |
          for m in $MODULES; do
            if ! (cd "$m" && go test -race -count=1 -json ./... > test.json); then
              grep -E '"Action":"fail"' "$m/test.json" | head -50
              exit 1
            fi
            skipped="$(grep '"Action":"skip"' "$m/test.json" | grep -c '"Test":' || true)"
            if [ "$skipped" != "0" ]; then
              echo "$m: $skipped skipped tests"
              exit 1
            fi
          done
      - name: govulncheck
        run: for m in $MODULES; do (cd "$m" && go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...); done
      - name: fuzz smoke (30 s per target)
        run: |
          for t in FuzzParseName FuzzParseSANDirectoryNames FuzzParseDateOfBirth FuzzParseDocument FuzzDateUnmarshalJSON; do
            go test -run '^$' -fuzz "^$t\$" -fuzztime 30s ./internal/identity
          done
          for t in FuzzParseResponse FuzzParseIDP FuzzParseCDP; do
            go test -run '^$' -fuzz "^$t\$" -fuzztime 30s ./internal/revocation
          done
          go test -run '^$' -fuzz '^FuzzParseQCStatements$' -fuzztime 30s ./internal/engine
      - name: public API (AC4 go doc golden)
        run: go doc -all . | diff -u testdata/godoc.golden -
      - name: test names (AC6 golden)
        run: |
          export LC_ALL=C
          list() { (cd "$1" && go test -list '.*' -tags live ./... | grep -E '^(Test|Fuzz|Example|Benchmark)'); }
          missing="$(comm -23 <(cut -d' ' -f2 testdata/golden/test-names.txt | sort) <(for m in $MODULES; do list "$m"; done | sort))"
          if [ -n "$missing" ]; then
            echo "tests of testdata/golden/test-names.txt missing from both modules:"
            echo "$missing"
            exit 1
          fi
      - name: dependency isolation (AC3) and import graph
        run: |
          if go list -deps ./... | grep -E 'certmagic|libdns|go\.uber\.org/zap|golang\.org/x/time'; then exit 1; fi
          if go list -deps ./internal/identity ./internal/revocation ./internal/profiles ./internal/opts | grep -x 'github.com/vocdoni/cert-check'; then exit 1; fi
          for m in $MODULES; do
            if (cd "$m" && go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./...) | grep -v '^github.com/vocdoni/cert-check/internal/testpki' | grep 'internal/testpki'; then exit 1; fi
          done
      - name: docker build
        run: |
          if ! command -v docker >/dev/null 2>&1; then
            echo "::warning title=docker build skipped::docker is not installed on this runner, so the image build was not checked"
            exit 0
          fi
          docker build --pull -f testui/Dockerfile -t cert-check:ci .
          docker image rm cert-check:ci
```

Run:
- checks on both modules and the test-name check;
- every new CI step locally:
  - `go doc -all . | diff -u testdata/godoc.golden -`;
  - the dependency step;
  - the 30 s fuzz smoke for `FuzzParseQCStatements` on `./internal/engine`;
  - the docker build.
- govulncheck on both modules.

Step: commit
`git commit -m "test(certcheck): cover the handler, examples and the public api golden" -- handler_test.go tls_test.go example_test.go api_test.go testdata/godoc.golden internal/opts testui/internal/server/tlsconfig_test.go .github`

Tests (AC mapping):
- AC4: `TestPublicFieldTypesNamed`, the go doc golden, `TestPackagesExportOnlyConstructors`;
- AC5: `Example`, `ExampleHandler_Auth`, `ExampleResult`, `ExampleError`;
- AC7: the handler and TLS tests above.

### Task 6: READMEs

Model: sonnet   Repo: same branch, own worktree if run in parallel with Tasks 4 and 5
Files: `git mv README.md testui/README.md` (then edit), new `README.md`.
Goal: AC8.

`testui/README.md` is today's runbook, moved. Update every path and command:
- `cd testui && go run .` and the local-run steps;
- `docker build -f testui/Dockerfile .`;
- `build.dockerfilePath testui/Dockerfile`, with `source.rootDirectory` unset (the build context is
  the repository root);
- the deploy flow, including the CI steps that now run per module;
- live tests per module: `go test -tags live ... ./...` in `.` for
  `TestWithheldSpecimensRejectedTwice`, and in `testui` for `TestLiveBeworCredential` and
  `TestLiveProbe`;
- the new `TestDeployedServiceGolden` under the smoke tests;
- the probe;
- rollback R1-R6. R2 names `internal/profiles` and `profiles.All`. Add the dockerfilePath rollback
  note from the spec.

The UI description and the listener table stay. The package table of section 1 is replaced by one
line linking to the root README. Section 6 (registry maintenance) moves to the root README.

The root `README.md` is package documentation, with no deployment content beyond one link to
`testui/README.md`:
1. What it is: one paragraph.
2. Install: `go get github.com/vocdoni/cert-check`. Set
   `GOPRIVATE=github.com/vocdoni/cert-check` while the repository is private.
3. Quick start: the runnable program below, verified in a scratch module with
   `replace => <repo>`, never in the repo. Explain `mkcert localhost` and opening
   https://localhost:8443/login in a browser that holds an idCAT or FNMT certificate.
4. Choosing certificate types: the 12 packages and 14 constructors with beta flags (the spec table),
   and `providers.All/Standard/ByID`.
5. Handler and TLS:
   - `TLSConfig` policy and why TLS 1.2 is the default (`WithTLS13`);
   - `http.Protocols` set to HTTP/1 only;
   - `RequestClientCert`; tickets off;
   - `Auth` vs `AuthAs` with `CheckHost` for per-host listeners;
   - `Certificates`/`CertificateCheck`/`Name`/`RequireCertificate` for blind-csp-shaped adapters,
     with a 10-line adapter sketch.
6. Results and errors:
   - the `Result` fields;
   - `Identity` (document type and number, names, birth date);
   - the 16 `ErrorCode`s in a table with meaning and retryable flag, and the steps;
   - `Diagnostics` are session-bound; log `LogAttrs()`.
7. Revocation and options:
   - the default checker (User-Agent `cert-check/dev`, wall clock);
   - `NewRevocation` + `WithRevocation` for the User-Agent, timeouts and cache bounds;
   - `WithClock`/`WithLogger`/`WithVersion`;
   - a context deadline bounds `Verify` (40 s in the testing UI).
8. Security notes:
   - pinned anchors only; client-sent intermediates are never used;
   - fail closed;
   - the TLS 1.2 trade-off (D2);
   - test-certificate markers and reserved identities;
   - inert providers and the `NewHandler` checks (startup fails loudly);
   - no PII in logs.
9. Supported providers: ID, name, constructor, beta.
10. Maintaining the trust set (moved from the old section 6, paths updated):
    - `internal/profiles/anchors/` + `SOURCES.md`;
    - the provider files `internal/profiles/<provider>.go` hold the pins (the anchors' `SOURCES.md`
      still says `providers.go`, P8);
    - the TSL inventory;
    - `testdata/specimens/MANIFEST.md`;
    - the DNIe intermediates.
11. Development:
    - both modules and the CI steps;
    - the AC6 goldens in `testdata/golden` are never regenerated;
    - after an intended API change, update `testdata/godoc.golden` with `go doc -all . > testdata/godoc.golden`.

Quick start (compiled against the prototype):

```go
// Command login greets the holder of an idCAT or FNMT client certificate at
// https://localhost:8443/login.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/providers/fnmt"
	"github.com/vocdoni/cert-check/providers/idcat"
)

func main() {
	h, err := certcheck.NewHandler([]certcheck.Provider{idcat.New(), fnmt.New()})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second) // bounds the OCSP and CRL fetches
		defer cancel()
		res, err := h.Auth(r.WithContext(ctx))
		if e, ok := errors.AsType[*certcheck.Error](err); ok {
			http.Error(w, fmt.Sprintf("%s (diagnostic %s)", e.Code, e.Diagnostics.DiagnosticID), http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "Hello %s (%s %s)\n", res.Identity.FullName, res.Identity.Document.Type, res.Identity.Document.Number)
	})
	var protocols http.Protocols
	protocols.SetHTTP1(true) // TLSConfig offers http/1.1 only
	srv := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: h.TLSConfig(nil), Protocols: &protocols,
		ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServeTLS("localhost.pem", "localhost-key.pem")) // e.g. from `mkcert localhost`
}
```

Step: commit `git commit -m "docs(readme): document the go package and move the runbook to testui" -- README.md testui/README.md`
Check: the quick start builds against this branch in a scratch module under
`~/.cache/cert-check/scratch/`, with `go vet` clean.

## Merge and release

Rollback comes first. Record the rollback target before any change:

```sh
railway deployment list --service cert-check --environment production --limit 5 --json
```

Note the ID of the newest `SUCCESS` deployment.
- If anything goes wrong after the deploy, redeploy that deployment from the dashboard
  (Deployments → that deployment → Redeploy). Its image is reused, so there is no build and no
  setting change. Expect the short outage of a volume-backed service.
- `railway redeploy` acts only on the latest deployment, so do not use it for this.
- A failed build or an unhealthy new deployment never replaces the running one: in that case do
  nothing beyond reading the build logs (`railway logs --service cert-check --build --lines 200 --json`).
- Only if `main` must be reverted to the single-module layout, first set
  `railway environment edit --service-config cert-check build.dockerfilePath Dockerfile`, then push
  the revert.

1. Full suites, on the branch head:
   - both modules: gofmt, `go mod tidy -diff`, vet (+live), staticcheck, `go test -race -count=1`
     with 0 FAIL and 0 skipped, govulncheck;
   - the four fuzz smokes;
   - `go doc` golden diff, test-name check, dependency/import-graph step;
   - `docker build -f testui/Dockerfile .`;
   - live (owner's machine, inputs outside the repo):
     - in `.`, `go test -tags live -race -count=1 -run 'Withheld' ./...`;
     - in `testui`, `go test -tags live -race -count=1 -run 'Live' ./...` with the Bewor variables
       (success with markers emptied; `test_certificate` with production markers; probe 0 FAIL).
2. Gate audit (Fable) on `refactor/library-first` against the plan commit. It reads in full:
   - `git diff -M --stat <base> HEAD`;
   - the Review Focus files as `git diff -M <base> HEAD -- <old> <new>` pairs;
   - `git diff <task-0 commit> HEAD -- testdata/golden` (must be empty);
   - `git diff -M100% --name-status <base> HEAD -- internal/identity internal/revocation internal/profiles/anchors`.

   Fixes are re-reviewed by the controller.
3. Owner OK required before each of:
   - (a) the Railway setting change;
   - (b) pushing `main`;
   - (c) any manual redeploy.
4. Merge locally:
   `git checkout main && git merge --no-ff refactor/library-first -m "refactor(cert-check): library-first restructure"`.
   Do not push yet.
5. Railway, in this order with nothing in between:
   1. `railway environment edit --service-config cert-check build.dockerfilePath testui/Dockerfile`.
      `source.rootDirectory` stays unset. Read it back with `railway environment edit --json` or in
      the dashboard. If this edit starts a build of the current `main`, that build fails (there is
      no `testui/Dockerfile` there yet) and production keeps its image: expected, do not retry it.
   2. `git push origin main` (owner OK).

   From step 1 until the new deployment ends, trigger no other build: no variable edits, no manual
   deploys.
6. Watch:
   - CI on the merge commit (`gh run list --branch main --limit 1`, `gh run watch <id>`);
   - then the deployment of that commit
     (`railway deployment list --service cert-check --environment production --limit 3 --json`)
     until `SUCCESS`, with the build logs if it fails.
7. Smoke tests (AC9):
   - `curl -sS -o /dev/null -w '%{http_code}\n' https://cert-check.vocdoni.dev/readyz` prints `200`.
   - Providers body and per-SNI CA lists against the goldens:

     ```sh
     cd testui && CERTCHECK_DEPLOYED_URL=https://cert-check.vocdoni.dev \
       CERTCHECK_DEPLOYED_AUTH=auth.cert-check.vocdoni.dev:<tcp proxy port, today 32931> \
       go test -tags live -count=1 -run TestDeployedServiceGolden -v ./internal/server
     ```

     All 14 subtests pass, and the body is byte-equal to `testdata/golden/providers.json`.
   - Headers: `curl -sI https://cert-check.vocdoni.dev/` shows CSP, Referrer-Policy, nosniff and HSTS.
   - TLS 1.3 refused: `openssl s_client -connect fnmt.auth.cert-check.vocdoni.dev:<port> -servername fnmt.auth.cert-check.vocdoni.dev -tls1_3 </dev/null`
     fails with protocol_version.
   - No-certificate flow (curl with a cookie jar under `~/.cache/cert-check/`):
     - `POST /api/v1/transactions {"provider":"fnmt"}` with `Origin: https://cert-check.vocdoni.dev`
       and `Sec-Fetch-Site: same-origin`;
     - GET the `authUrl` without a client certificate (`--tlsv1.2`), which answers 303 to `#code=...`;
     - `POST /api/v1/transactions/redeem {"code":...}` answers `no_certificate` with diagnostics that
       include `tls`.
   - Bewor production E2E: the same flow with `{"provider":"bewor"}`, GET the `authUrl` with
     `--cert ~/.cache/cert-check/live/bewor/cert.pem --key .../key.pem --tlsv1.2`, then redeem.
     Expected: `test_certificate` at `test_marker` (`known specimen fingerprint`) with no revocation
     attempts.
   - Logs: `railway logs --service cert-check --lines 100 --json` shows `cert-check starting` with
     `providers: 14`, and no `anchor outside validity` or `provider hidden` warnings.
8. Owner re-tests FNMT login in the browser (AC9). Record the result in the ledger.
9. Release: no tag in this delivery; `v0.1.0` stays pending the owner, as before. Delete
   `refactor/library-first` locally after the owner confirms.
