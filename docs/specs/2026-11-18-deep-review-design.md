# Deep review of cert-check: design

Status: approved (2026-11-18, owner request)   Class: architectural (security library, public API, deployed testing UI)
Repo and branch: vocdoni/cert-check → `review/deep-review` (base `origin/main` beb3624)

## Goal

The owner asked for a deep review of the whole repository, run as a review-and-fix loop:
- **Reviewers:** each round, three independent reviewers.
  1. Architecture and design.
  2. Implementation and optimisation.
  3. Security.
- **Fixing:** the reviewers hand their findings to one implementer, who verifies each finding and
  fixes it with a regression test. When a finding is wrong, the implementer rejects it with evidence.
- **Stopping:** the loop repeats until a round in which no reviewer reports anything.

Scope: both modules. That is the library (`.`, including `providers/` and `internal/`) and the
testing UI (`testui/`, Go and its embedded web assets), plus CI, the Dockerfile and the docs as
they describe the code.

## What a finding is

A real defect, with evidence and a concrete fix:
- wrong behaviour, a security weakness, or a crash or panic on external input;
- unbounded resources, or a race;
- a design flaw that makes the code wrong or fragile, or measurably wasteful;
- a test that cannot catch the regression it claims to;
- documentation that contradicts the code.

These are not findings:
- style preferences;
- speculative refactors;
- re-opening decisions recorded in `docs/specs/2026-10-30-cert-check-design.md`,
  `docs/specs/2026-10-31-library-restructure-design.md` or
  `docs/plans/2026-11-01-security-audit-plan.md`. Examples are TLS 1.2 by default, pinned anchors,
  fail-closed revocation, provider scope, and the single-replica, in-memory testing UI.

## Constraints

- **Escalate, do not implement.** The implementer does **not** implement a finding that changes:
  - the public API (`testdata/godoc.golden`);
  - the accept or reject verdict of a published specimen or golden
    (`testdata/golden/*`, specimen tests);
  - the trust set or provider declarations;
  - the error codes;
  - the TLS policy.

  Such a finding is marked `needs-owner` with its evidence and a proposed fix. The controller takes
  it to the owner. Goldens are never regenerated to make a test pass.
- **Tests.** Every fix has a test that fails without it. Docs-only fixes need none. The existing
  checks stay green in both modules:
  - gofmt;
  - `go mod tidy -diff`;
  - vet, also with `-tags live`;
  - staticcheck;
  - `CGO_ENABLED=0` build;
  - `go test -race`;
  - the dependency isolation check;
  - the godoc golden diff.

  Tests that need the network (`-tags live`) are run when relevant and reported. Their absence is
  never treated as a pass.
- **Commits.**
  - Conventional commits (`type(scope): lowercase summary`, matching the repo history), with no AI
    attribution and no `Co-Authored-By` trailers.
  - Never signed: always `git -c commit.gpgsign=false commit`.
  - Explicit paths only.
  - No pushes. Merging to `main` redeploys the testing UI on Railway, so the merge and its PR wait
    for the owner's OK.
- **Build output** goes under `~/.cache/cert-check/`, never `/tmp`. Run tests with
  `TMPDIR=$HOME/.cache/cert-check/tmp`.

## Acceptance

- [ ] A review round from all three reviewers reports no findings.
- [ ] Every accepted finding has a commit, and a test where it applies.
- [ ] `needs-owner` findings are listed for the owner and are not implemented.
- [ ] Both modules' full checks are green, run by the controller.
- [ ] A gate audit of the whole branch is folded in.
