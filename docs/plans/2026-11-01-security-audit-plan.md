# Security and robustness audit: plan

Spec: inline below
Class: architectural (security-sensitive, production)
Repos and branches: /home/p4u/certificate_poc/cert-check → security/audit-2026-11 (base 8549907 = v0.1.0)

## Spec (inline)

Owner request (2026-11-01): a full security review of the implemented code, using Fable 5.1 and GPT
Astra reviewers on small pieces of code. Every finding is fixed. The implementation must not crash on
any input and must be production ready.

- **Goals**
  - Every production file of both modules (`.` and `testui/`) is reviewed for:
    - security (validation bypass, wrong identity, SSRF, injection, replay, session binding, PII
      leaks);
    - crash safety (panics on external input, nil dereferences, index/slice bounds, concurrent map
      access, goroutines without a stop path or recover where needed, unbounded memory or CPU);
    - production readiness (timeouts, limits, shutdown, logging, configuration validation,
      container/CI hygiene).

    The security-critical units get two independent reviews (Fable and GPT Astra).
  - Every accepted finding is fixed with a regression test. A test that crashed or failed before a
    fix must pass after it.
  - Behaviour stays unchanged except for the fixes:
    - the Task 0 goldens (`testdata/golden/*`) and the godoc golden change only where a ruling says
      so;
    - the live tests (Bewor credential, withheld specimens, probe 0 FAIL) still pass.
- **Non-goals:** new features, provider scope changes, design decisions already approved (TLS 1.2
  default, pinned anchors D1, non-443 port, in-memory single replica, no census).
- **Acceptance**
  - Both modules pass gofmt, tidy, vet (+live), staticcheck, race tests with 0 skips and
    govulncheck.
  - Every fuzz target passes a 2-minute run.
  - Every finding has a ruling and either a fix with a test or a reasoned rejection.
  - The final Fable gate audit says MERGE.
  - The deploy is healthy and the smoke tests pass.

## Review units

| Unit | Files | Reviewers |
|---|---|---|
| U1 | internal/revocation/fetcher.go, policy.go | Fable + Astra |
| U2 | internal/revocation/ocspcodec.go | Fable + Astra |
| U3 | internal/revocation/ocspverify.go, ocspcache.go | Fable + Astra |
| U4 | internal/revocation/crl.go | Fable + Astra |
| U5 | internal/revocation/checker.go, crlcache.go | Fable + Astra |
| U6 | internal/identity/name.go, extensions.go, document.go | Fable + Astra |
| U7 | internal/identity/adapter.go, reserved.go | Fable + Astra |
| U8 | internal/engine/*.go (checker, compat, options, report) | Fable + Astra |
| U9 | internal/profiles/*.go (registry, types, declarations) | Fable |
| U10 | root *.go (handler, tls, types, diagnostics, options, provider, revocation, doc), internal/opts, providers/** | Fable + Astra |
| U11 | testui/internal/server/{txstore,auth,tlsconfig,http}.go | Fable + Astra |
| U12 | testui/internal/server/{api,app}.go, testui/main.go, testui/internal/{config,acme}/*.go | Astra |
| U13 | testui/internal/probe/*.go, testui/Dockerfile, .dockerignore, .github/workflows/ci.yml | Fable |
| U14 | testui/web/static/{app.js,index.html,styles.css}, testui/web/embed.go, testui/web/internal/devserver/main.go | Astra |

## Process
1. Reviews in waves; reports in the workspace (`review-U<n>-<fable|astra>.md`).
2. The controller triages: deduplicates, rules on each finding (accept, amend or reject with
   evidence), and records the rulings in the ledger.
3. Fix tasks are grouped by package. Opus does every security fix, each test-first, on this branch.
   The controller reviews every diff.
4. Gate: full suites, 2-minute fuzzing, goldens, live tests, Fable gate audit.
5. Release: merge to main (owner OK), CI, Railway deploy, smoke tests, tag v0.1.1.
