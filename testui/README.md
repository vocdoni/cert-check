# cert-check testing UI

The testing UI is a small web app that exercises the cert-check Go package. A user picks a Spanish
certificate provider, presents a client certificate in the browser, and the service shows the identity
it extracted (DNI/NIE, names, birth date when present) after checking the certificate chain, its purpose
and its revocation status. It runs at <https://cert-check.vocdoni.dev>.

It is a nested Go module, `github.com/vocdoni/cert-check/testui`, that requires the root module through
`replace github.com/vocdoni/cert-check => ../`. The package itself is documented in the
[root README](../README.md). This file covers the UI, its configuration and its deployment on Railway.

Design: `../docs/specs/2026-10-30-cert-check-design.md` (the service) and
`../docs/specs/2026-10-31-library-restructure-design.md` (the module layout). Implementation plans:
`../docs/plans/2026-10-30-cert-check-plan.md` and `../docs/plans/2026-10-31-library-restructure-plan.md`.

Contents: [What it is](#1-what-it-is) | [Local run](#2-local-run-with-a-static-certificate) |
[Configuration](#3-configuration) | [Operations](#4-operations) | [Rollback](#5-rollback) |
[Security notes](#6-security-notes)

## 1. What it is

One Go binary, two listeners, one in-memory transaction store.

| Listener | Default | Serves | TLS |
|---|---|---|---|
| main | `:8080` (`PORT`) | embedded UI (`web/`) and the JSON API under `/api/v1`, `/healthz`, `/readyz` | none; the Railway HTTP edge terminates it |
| auth | `:8443` (`CERTCHECK_AUTH_LISTEN`) | `GET /v1/authenticate` only, HTTP/1.1 only, no HTML | Go terminates TLS and requests a client certificate; reached through the Railway TCP proxy on a non-443 port |

Flow:

1. The UI loads `GET /api/v1/providers` and the user presses **Authenticate**.
2. `POST /api/v1/transactions {"provider":"<id>"}` creates a transaction, sets the
   `__Host-certcheck_tx` cookie and returns `authUrl`:
   `https://<id>.auth.<authDomain>:<port>/v1/authenticate?state=<state>`.
3. The browser navigates to `authUrl`. The SNI `<id>.auth.<authDomain>` selects the provider, the
   server advertises only that provider's CA names, and the browser shows its certificate picker.
4. The auth listener consumes the state, runs `certcheck.Handler.AuthAs` for the provider named by the
   SNI on the received chain, stores the result and answers `303` to `<publicURL>/#code=<code>` (or
   `#error=...&diag=<diagnosticId>`).
5. The UI redeems the code with `POST /api/v1/transactions/redeem` (the cookie must match) and shows
   the success page or the error view with a copyable diagnostic report.

The validation logic is the Go package at the repository root, documented in the
[root README](../README.md). This module builds one `certcheck.Handler` from `providers.All` and adds the
per-host dispatch, the transaction store, the ACME certificate and the UI.

Providers: 6 verified (FNMT, idCAT, ACCV, DIGITEL, Bewor, Sectigo) and 8 beta (FNMT representative and
public employee, Firmaprofesional, ANF, Uanataca, SIGNE, Lleidanet, DNIe). `GET /api/v1/providers`
lists what the running service enables. The revocation quirks of the CRL-only providers (Lleidanet and
SIGNE) are described under [Supported providers](../README.md#supported-providers) in the root README.

## 2. Local run with a static certificate

Locally there is no ACME: give the auth listener a static wildcard certificate for
`*.auth.localtest.me` (the `localtest.me` DNS zone resolves every name to `127.0.0.1`). Keep the files
outside the repository:

```sh
D=~/.cache/cert-check/local-tls && mkdir -p "$D"
# mkcert: the certificate is trusted by your browser after `mkcert -install`
mkcert -cert-file "$D/cert.pem" -key-file "$D/key.pem" '*.auth.localtest.me'
# or openssl: untrusted, enough for curl -k and for the container check below
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
  -subj '/CN=*.auth.localtest.me' -addext 'subjectAltName=DNS:*.auth.localtest.me' \
  -keyout "$D/key.pem" -out "$D/cert.pem"
chmod 600 "$D/key.pem"   # readable by you only; the container below runs as your UID
```

Run the service from the `testui` directory (the module that holds `main.go`):

```sh
export CERTCHECK_PUBLIC_URL=http://localhost:8080      # http is accepted for localhost and 127.0.0.1 only
export CERTCHECK_AUTH_DOMAIN=auth.localtest.me
export CERTCHECK_AUTH_PUBLIC_PORT=8443
export CERTCHECK_TLS_CERT_FILE="$D/cert.pem"
export CERTCHECK_TLS_KEY_FILE="$D/key.pem"
cd testui && go run .
```

`internal/testpki` (in the root module) builds throwaway CAs and server certificates for the Go tests.
The static-certificate variables are mutually exclusive with the ACME variables. The same image runs
locally. Build it from the repository root, because the build context must include the root module that
`testui` requires:

```sh
docker build -f testui/Dockerfile -t cert-check:local .
# --user: run as your UID so the static binary can read the 0600 key without loosening its mode
docker run --rm --user "$(id -u):$(id -g)" -p 8080:8080 -p 8443:8443 -v "$D":/certs:ro \
  -e CERTCHECK_PUBLIC_URL=http://localhost:8080 -e CERTCHECK_AUTH_DOMAIN=auth.localtest.me \
  -e CERTCHECK_AUTH_PUBLIC_PORT=8443 -e CERTCHECK_TLS_CERT_FILE=/certs/cert.pem \
  -e CERTCHECK_TLS_KEY_FILE=/certs/key.pem cert-check:local
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/readyz   # 200
```

Browser notes:

- Open exactly the origin in `CERTCHECK_PUBLIC_URL`. The POST handlers compare `Origin` with it, and the
  redirect after authentication returns there.
- The auth step is a top-level navigation to `https://<id>.auth.localtest.me:8443/...`. The browser only
  offers client certificates issued by the provider's advertised CAs. With none installed it sends no
  certificate and the UI shows `no_certificate`.
- Browsers can remember a client-certificate choice for a host during the session. To pick another
  certificate for the same provider, clear the browser's SSL state or use a fresh profile.
- Without mkcert's CA installed the browser stops at an untrusted-certificate warning for the auth host.
  Accept it once for each provider host, for example `https://fnmt.auth.localtest.me:8443`.
- TLS 1.2 is the default on the auth listener; set `CERTCHECK_AUTH_TLS13=true` to allow 1.3.
- The UI can be checked offline against canned API responses with `cd testui && go run ./web/internal/devserver`.

## 3. Configuration

All configuration is environment variables. Invalid or missing required values make startup fail with
a message that lists every problem and never prints a secret.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Main listener port (Railway sets it) |
| `CERTCHECK_PUBLIC_URL` | required | Fixed callback origin, e.g. `https://cert-check.vocdoni.dev`. https only, http for localhost and 127.0.0.1. No path other than `/`, no query, fragment or userinfo; the host is lowercased and a default port dropped |
| `CERTCHECK_AUTH_DOMAIN` | required | Lowercase DNS name whose wildcard hosts the providers, e.g. `auth.cert-check.vocdoni.dev` |
| `CERTCHECK_AUTH_PUBLIC_PORT` | `$RAILWAY_TCP_PROXY_PORT` | External auth port used in `authUrl`. Required: set it when `RAILWAY_TCP_PROXY_PORT` is absent |
| `CERTCHECK_AUTH_LISTEN` | `:8443` | Auth listener address, `host:port` with a numeric port between 1 and 65535 |
| `CERTCHECK_DATA_DIR` | `/data` | ACME storage: `<dir>/certmagic` (the Railway volume) |
| `CERTCHECK_ACME_EMAIL` | required with ACME | ACME account contact (a mailbox the owner controls) |
| `CERTCHECK_ACME_CA` | `production` | `production` or `staging` (Let's Encrypt) |
| `CLOUDFLARE_API_TOKEN` | required with ACME | DNS-01 token (secret). Permissions: **Zone:Read + Zone.DNS:Edit** on `vocdoni.dev` |
| `CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN` | unset | Optional CNAME delegation: the **full TXT record name** to write, including the `_acme-challenge.` label (certmagic `DNS01Solver.OverrideDomain` replaces the whole name) |
| `CERTCHECK_TLS_CERT_FILE` / `CERTCHECK_TLS_KEY_FILE` | unset | Static certificate and key instead of ACME; mutually exclusive with the three ACME variables above |
| `CERTCHECK_AUTH_TLS13` | `false` | Allow TLS 1.3 on the auth listener (see [Security notes](#6-security-notes)) |
| `CERTCHECK_TRUSTED_PROXY_HOPS` | `1` | Trusted proxy hops, 0 to 10. The client IP is the entry that many places from the right of `X-Forwarded-For` |
| `CERTCHECK_LOG_LEVEL` | `info` | slog level: `debug`, `info`, `warn`, `error` |
| `RAILWAY_RUN_UID` | set on the service: `0` | Platform setting, not read by the app. Railway mounts volumes as root, so the process must run as root to create `/data/certmagic` (accepted, see [Security notes](#6-security-notes)) |
| `RAILWAY_GIT_COMMIT_SHA` | `dev` | Docker build argument, injected by Railway; becomes the reported `serverVersion` |

The Docker image exposes `8080` and `8443` and runs the static binary in
`gcr.io/distroless/static-debian12:nonroot` (UID 65532 by default). On Railway, `RAILWAY_RUN_UID=0`
overrides that default and the process runs as root (see [Security notes](#6-security-notes)).

## 4. Operations

Production: Railway project `CertificateCheck`, environment `production`, service `cert-check`
(1 replica, volume at `/data`), domain `cert-check.vocdoni.dev`.

### Deploy flow

1. A pull request runs `.github/workflows/ci.yml` (job `ci`, check name `ci`) on the org's
   self-hosted runners (`runs-on: [self-hosted, ci]`; runners `z4`, `z5`, `z7-2`). The checks run once
   per module, in the root module (`.`) and in `testui`: gofmt, `go mod tidy -diff`, vet (also
   `-tags live`), staticcheck, a `CGO_ENABLED=0` build, tests with `-race` (any skipped test fails the
   job) and govulncheck. The job also runs a 30 s fuzz smoke per target (root module), the dependency
   isolation check (the root module's dependencies contain no certmagic, libdns, zap or `x/time`
   package), the `go doc` golden diff of the root package and a Docker build of `testui/Dockerfile`.
   The runner needs a C toolchain for `-race`, `jq` (a red test step prints the output of the failing
   packages with it), and Docker for the last step (the step warns and skips when Docker is missing).
2. Merging to `main` runs the same job. Railway deploys `main` only after the CI check passes
   ("wait for CI"). A cancelled `main` run would leave its commit undeployed, so only pull request
   runs are cancelled when superseded. Never push or merge to `main` with `[skip ci]`, `[ci skip]`,
   `[no ci]`, `[skip actions]` or `[actions skip]` in the commit message or squash title: GitHub then
   creates no `ci` run at all, and wait-for-CI, which blocks only on a failing run, deploys the commit
   untested. Merge pull requests whose own `ci` run is green.
3. Railway builds `testui/Dockerfile` with the repository root as the build context, starts the
   container and polls `/readyz` for up to 600 s. The new deployment takes over only when it returns
   200, that is when the providers are loaded, both listeners are up and the auth certificate is
   present and valid.
4. The runner group `Default` must admit the repository, otherwise the job queues forever:
   `gh api orgs/vocdoni/actions/runner-groups --jq '.runner_groups[]|{name,visibility,allows_public_repositories}'`.
   A `pull_request` run executes the workflow file of the pull request's head on these runners, with
   the Docker daemon (root on the host) and the Go caches that later `main` runs reuse, so nothing in
   `ci.yml` can protect them. The protection is these settings, all required:
   - runner group: `visibility` `selected`, listing this repository only, and
     `allows_public_repositories` `false`;
   - the repository stays private; in its Actions settings, running workflows from fork pull requests
     is disabled, and fork pull request workflows require approval for all outside collaborators;
   - runners are registered with `--ephemeral`, so every job starts with fresh `GOMODCACHE` and
     `GOCACHE` and no job can poison the caches of the next.
5. Branch protection (or a ruleset) on `main` requires the status check `ci`. Railway's wait-for-CI is
   the second gate, not a substitute: it never blocks a commit that has no `ci` run (step 2).

### Railway service settings

There is no `railway.json` (it is deprecated). The settings below are applied once with the CLI and
live only in Railway, so re-check them after any manual change in the dashboard. Each line is
`railway environment edit --service-config cert-check <path> <value>`:

- `build.builder DOCKERFILE`, `build.dockerfilePath testui/Dockerfile`
- `deploy.healthcheckPath /readyz`, `deploy.healthcheckTimeout 600`
- `deploy.restartPolicyType ON_FAILURE`, `deploy.restartPolicyMaxRetries 10`
- `deploy.numReplicas 1`
- `source.branch main`, `source.checkSuites true` (wait for CI)

Leave `source.rootDirectory` unset. The build context is the repository root, which `testui/Dockerfile`
needs because the `testui` module requires the root module through `replace => ../`. Setting a root
directory would cut the root module out of the build.

Read them back with `railway environment edit --json` or in the dashboard. The volume at `/data` and
the networking (HTTP domain `cert-check.vocdoni.dev` to port 8080, plus the generated
`*.up.railway.app` domain; TCP proxy to port 8443) are created in the dashboard or with
`railway domain` and `railway tcp-proxy create --service cert-check --port 8443`.

#### Changing `build.dockerfilePath`

Before the testing UI moved to `testui/`, the service built the `Dockerfile` at the repository root. The
switch to `testui/Dockerfile` is made once, immediately before the merge, in this order and with nothing
in between:

1. `railway environment edit --service-config cert-check build.dockerfilePath testui/Dockerfile`
2. Merge to `main`.

From step 1 until the resulting deploy has finished, trigger no other build: no variable edits and no
manual deploys. A failed build never replaces the running deployment and the `/readyz` healthcheck gates
the swap, so a mistake in this window leaves production on the previous image. Variables, volume, domains,
TCP proxy, healthcheck and wait-for-CI do not change. Rollback is described in R1 below.

Variables, with `railway variable set KEY=value --service cert-check`:

```
RAILWAY_RUN_UID=0
PORT=8080
CERTCHECK_PUBLIC_URL=https://cert-check.vocdoni.dev
CERTCHECK_AUTH_DOMAIN=auth.cert-check.vocdoni.dev
CERTCHECK_ACME_EMAIL=<ops mailbox>
CERTCHECK_ACME_CA=staging          # first issuance, then production
CERTCHECK_TRUSTED_PROXY_HOPS=2   # Railway edge: XFF = "<client>, <railway hop>" (confirmed 2026-10-31)
CERTCHECK_LOG_LEVEL=info
```

`CLOUDFLARE_API_TOKEN` is entered by the owner in the dashboard as a sealed variable. Nobody else
handles the value and it never appears in the repository, in logs or in a shell history.
`CERTCHECK_AUTH_PUBLIC_PORT` follows `RAILWAY_TCP_PROXY_PORT` automatically.

### DNS records

The owner creates both records in Cloudflare as "DNS only" (grey cloud). Neither the Railway TCP proxy
nor the Railway edge can sit behind the Cloudflare proxy.

| Name | Type | Target |
|---|---|---|
| `cert-check.vocdoni.dev` | CNAME | the Railway custom-domain target (`railway domain cert-check.vocdoni.dev --service cert-check --port 8080 --json`), plus the verification TXT record if Railway asks for one |
| `*.auth.cert-check.vocdoni.dev` | CNAME | `<x>.proxy.rlwy.net`, the host of the TCP proxy |

Verify with `dig +short CNAME fnmt.auth.cert-check.vocdoni.dev`. Also check
`dig +short CAA cert-check.vocdoni.dev` and the CAA records of the Railway target: if a CAA set
excludes `letsencrypt.org`, add `auth.cert-check.vocdoni.dev CAA 0 issue "letsencrypt.org"` before the
first issuance. If the proxy host changes (rollback R4), update the wildcard CNAME.

Optional delegation of the ACME challenge, instead of a zone-wide token (see the token section):

| Name | Type | Target |
|---|---|---|
| `_acme-challenge.auth.cert-check.vocdoni.dev` | CNAME | `_acme-challenge.cert-check.<acme-zone>` in a dedicated Cloudflare zone that holds nothing else |

With it, set `CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN=_acme-challenge.cert-check.<acme-zone>` and scope the
token to that zone only. The value is the complete TXT record name: certmagic writes the challenge
there and does not follow the CNAME, so omitting the `_acme-challenge.` label puts the record at the
wrong name and issuance fails.

### Cloudflare API token

The owner creates a single account-owned or user API token with these permissions on the zone
`vocdoni.dev`:

- **Zone: Zone: Read**
- **Zone: DNS: Edit**

(libdns/cloudflare, single-token mode.) The token is zone-wide. The owner chose this on 2026-10-31 and
accepted the risk, recorded below in [Security notes](#6-security-notes). Rotate it with rollback R5.

### First ACME issuance

The certificate is `*.auth.cert-check.vocdoni.dev`, issued through DNS-01 only and stored in
`/data/certmagic` so redeploys reuse it.

1. Start with `CERTCHECK_ACME_CA=staging`. Watch `railway logs --service cert-check` for
   `auth certificate ready`. No ACME error lines should appear.
2. The service stays up while the certificate does not exist yet. The main listener answers, the auth
   listener starts when the certificate is ready, and `/readyz` returns 503 until then. A failed
   attempt is retried in the background with backoff of 1, 5, 15, 30 and then 60 minutes. The log
   lines are `auth certificate not obtained; retrying` with the error and `retryIn`. Because Railway
   polls `/readyz` for 600 s, a deployment that cannot obtain its first certificate in that window is
   marked failed: fix the cause (DNS, token, CAA), then redeploy.
3. Check `curl -sS -o /dev/null -w '%{http_code}' https://cert-check.vocdoni.dev/readyz` returns `200`.
   The storage path `/data/certmagic` is named in the certmagic log line (the distroless image has no
   shell, so `railway ssh` does not help).
4. Switch to production with `railway variable set CERTCHECK_ACME_CA=production --service cert-check`.
   The redeploy obtains the production certificate. Staging and production certificates are stored
   separately.
5. Renewal is automatic. Every redeploy loads the stored certificate and does not re-issue.

Let's Encrypt limits that matter here (check <https://letsencrypt.org/docs/rate-limits/> for the
current values):

- 5 authorization failures per identifier, per account, per hour (refill 1 per 12 minutes). This is
  why the retry backoff is slow, and why a broken token or CNAME should be debugged on staging.
- 5 certificates per exact set of identifiers per 7 days. Do not wipe `/data/certmagic` or the volume
  without a reason.
- 50 certificates per registered domain (`vocdoni.dev`, shared with everything else under it) per 7
  days.
- 300 new orders per account per 3 hours.

Staging has far higher limits and issues an untrusted certificate, so use it for every experiment.

### Smoke tests after a deploy

- `curl -sS https://cert-check.vocdoni.dev/api/v1/providers` lists the 14 providers in display order.
  `curl -sI https://cert-check.vocdoni.dev/` shows the CSP, `Referrer-Policy`, `nosniff` and HSTS headers.
- For each provider id, `openssl s_client -connect <id>.auth.cert-check.vocdoni.dev:<port> -servername <id>.auth.cert-check.vocdoni.dev -tls1_2 -showcerts </dev/null`
  shows the Let's Encrypt chain, `Verify return code: 0`, and "Acceptable client certificate CA names"
  with exactly that provider's CAs. `-tls1_3` fails while `CERTCHECK_AUTH_TLS13` is `false`, and an
  unknown subdomain ends with the `internal error` alert.
- No-certificate path: `POST /api/v1/transactions`, follow the `authUrl` without a client certificate
  (a `303` to `#code=...`), then redeem the code: the answer is `no_certificate` with diagnostics.
- Client IP header: set `CERTCHECK_LOG_LEVEL=debug`, create one transaction, read the
  `forwarded headers` log line (header names and the `xffEntries` count), then reset to `info`. If
  `X-Forwarded-For` is absent or `xffEntries` is not 1 for a direct client, change the header or the
  hop count before going live.
- Service goldens. `TestDeployedServiceGolden` compares the deployed service with the goldens in
  `testdata/golden` (repository root): the providers API body byte for byte, and for each of the 14
  provider hosts the ordered `certificate_authorities` list of the handshake. It runs after a deploy,
  never in CI. `CERTCHECK_DEPLOYED_AUTH` is the auth domain and the external TCP proxy port, the same
  `<port>` as in the `authUrl`:

  ```sh
  cd testui
  CERTCHECK_DEPLOYED_URL=https://cert-check.vocdoni.dev \
  CERTCHECK_DEPLOYED_AUTH=auth.cert-check.vocdoni.dev:<port> \
  go test -tags live -count=1 -run TestDeployedServiceGolden ./internal/server
  ```

### Reading a support report

When authentication fails the UI shows a diagnostic report with a diagnostic ID (32 hex characters).
It is random, never derived from identity data, and the server logs one line per failure with the same
ID. Find it with:

```sh
railway logs --service cert-check --filter <diagnosticId>
```

The line holds the non-PII fields: error code, failed step, provider, profile candidates, issuer DN,
policy OIDs, the revocation URL host, status and duration, and the TLS version and cipher. The
subject, names, document number, serial and certificate hashes are never logged. The report itself
carries those details, so users are told to share it only with Vocdoni support. Compare the report's
`technicalDetail` and `revocationAttempts` with the log line to tell a bad certificate from a
responder outage.

### Revocation reachability probe

`cert-check probe [specimen-dir...]` checks every default OCSP responder and CRL endpoint from the
network it runs in. It needs no configuration and starts no server. For each enabled profile it asks
each responder about a never-issued serial, with a nonce only when the profile requires one, as the
checker does. It fetches each CRL, checks its signature against the pinned CA and evaluates it with
the checker's own rules: its dates and freshness, and its Issuing Distribution Point (the name must
include the CRL's URL, and no scope flag the checker rejects). For DNIe that means the root's
`CRL.crl` and `ARL.crl`, evaluated at CA scope because together they cover the pinned intermediates.
Each `specimen-dir` argument is a directory of `*.pem` files (regular files of at most 64 KiB). The
known live specimens found there get the full revocation check and must come back `good`; other
certificates are ignored, but a directory with no known live specimen is an error. The DIGITEL
specimen is committed in `testdata/specimens` (repository root). The Bewor and Sectigo specimens are
withheld and kept outside the repository.

It prints one line per target: verdict, profile, method, host and path, HTTP status, milliseconds,
outcome, responder or CRL issuer subject, nonce state, `thisUpdate` and `nextUpdate` (CRLs also print
`bytes`), and a detail. The nonce state is `required/` followed by `echoed`, `absent` or `mismatch`
when the profile requires a nonce, and `-` when none was sent. The last line is
`summary: N ok, N warn, N fail`, followed by `(no endpoint verified)` when no line is OK.

- **OK**: evidence the checker accepts. Any certStatus for the random serial counts, as does a
  correctly signed CRL the checker would use, or a specimen that comes back `good`.
- **WARN**: `unavailable`. The endpoint could not be reached, or it answered with an HTTP error or a
  non-successful OCSP `responseStatus`. The idCAT G3, Sectigo and Firmaprofesional responders answer
  `responseStatus 6` (unauthorized) for a never-issued serial, so their lines are WARN by design.
- **FAIL**: any other outcome. That is evidence the checker would reject (`invalid_evidence`,
  `stale`, `unsupported_method`), or a specimen that comes back `revoked` or `unknown`.

Exit codes: `0` when no line is FAIL and at least one is OK. `1` when any line is FAIL, when no line
is OK (every line WARN, for example without egress: nothing was verified), or when the probe cannot
run (a specimen directory that cannot be read or holds no known live specimen, a `*.pem` file that is
not a regular file, is larger than 64 KiB or holds no certificate, an interrupted run); the reason goes
to stderr.

Run it from the deployment network with a temporary service in the same project and repository. The
image carries no specimens, so this run covers the endpoints only:

```sh
# create service "cert-check-probe" from the repository, then:
railway environment edit --service-config cert-check-probe build.dockerfilePath testui/Dockerfile
railway environment edit --service-config cert-check-probe deploy.startCommand "/cert-check probe"
railway environment edit --service-config cert-check-probe deploy.restartPolicyType NEVER
railway logs --service cert-check-probe       # read the report
railway service delete --service cert-check-probe --environment production --yes
```

A new service builds the `Dockerfile` at the repository root unless told otherwise, and there is none
any more, so set `build.dockerfilePath` first. A FAIL line blocks go-live. A WARN line is noted. From a
workstation, `cd testui && go run . probe ../testdata/specimens ~/.cache/cert-check/live/specimens`
shows reachability from that network only, with the specimens included.

### Live tests

Three tests sit behind the `live` build tag, in two modules. They use the real network and inputs kept
outside the repository. Run each module's tests from its own directory:

```sh
# testui module: the Bewor credential and the probe
cd testui
CERTCHECK_LIVE_BEWOR_CERT=$HOME/.cache/cert-check/live/bewor/cert.pem \
CERTCHECK_LIVE_BEWOR_KEY=$HOME/.cache/cert-check/live/bewor/key.pem \
CERTCHECK_LIVE_SPECIMENS_DIR=$HOME/.cache/cert-check/live/specimens \
go test -tags live -race -count=1 -run 'TestLiveBeworCredential|TestLiveProbe' ./...

# root module: the withheld specimens
cd ..
CERTCHECK_LIVE_SPECIMENS_DIR=$HOME/.cache/cert-check/live/specimens \
go test -tags live -race -count=1 -run 'TestWithheldSpecimensRejectedTwice' ./...
```

- `TestLiveBeworCredential` (`testui/internal/server`) authenticates over loopback mTLS with the
  official Bewor test credential: the published P12 converted to PEM certificate and key files. It runs
  against the production providers and live OCSP. With the test markers emptied the result is
  success; with the production markers it is `test_certificate`.
- `TestLiveProbe` (`testui/internal/probe`) runs the probe above, with the committed DIGITEL specimen
  and the withheld Bewor and Sectigo specimens from `CERTCHECK_LIVE_SPECIMENS_DIR`. It fails on any FAIL
  line, or when no line is OK.
- `TestWithheldSpecimensRejectedTwice` (`internal/engine`, root module) checks that the withheld
  specimens are rejected with the codes in `testdata/specimens/MANIFEST.md`.

A missing variable fails the test; it never skips. Without `-tags live` none of these tests are built.
`TestDeployedServiceGolden`, also behind the tag, is described under
[Smoke tests after a deploy](#smoke-tests-after-a-deploy).

### Chrome restricted ports

The Railway TCP proxy assigns a port, and the browser refuses to connect to its restricted list
(`ERR_UNSAFE_PORT`). Check `<port>` against Chromium's `kRestrictedPorts` in `net/base/port_util.cc`
(current list on the day) and Firefox's `network.security.ports.banned` defaults. If it is
restricted, recreate the proxy (rollback R4).

## 5. Rollback

- **R1 Bad application deployment.** First redeploy the previous successful deployment: in the Railway
  dashboard open Deployments, pick it and Redeploy (or `railway redeploy`). Its image is reused, so
  nothing is built and no setting changes. Alternatively `git revert <sha>` on `main` and push, and
  Railway redeploys after CI. DNS, the volume and the ACME certificate in `/data/certmagic` are
  unaffected. Railway keeps one deployment active per service with a volume, so each redeploy has a
  short outage, even with a healthcheck. Only if `main` is reverted to the single-module layout (the
  `Dockerfile` back at the repository root), set `build.dockerfilePath` back to `Dockerfile` before the
  revert is pushed:
  `railway environment edit --service-config cert-check build.dockerfilePath Dockerfile`.
- **R2 Bad provider profile.** Remove the profile from its provider file in `internal/profiles/`, or the
  provider from `profiles.All` (`internal/profiles/providers.go`) and from the constructor list of
  `providers.All` (`providers/providers.go`), and redeploy through pull request, CI and `main`.
- **R3 ACME or Cloudflare failure.** The service stays up with `/readyz` 503 and keeps retrying (see
  First ACME issuance). Set `CERTCHECK_ACME_CA=staging` to debug without production limits, fix the
  token or DNS, then switch back to production. Staging and production certificates are stored
  separately, so each switch issues a new certificate. A certificate that is already stored is reused
  by redeploys and rollbacks (R1) without contacting the CA.
- **R4 TCP proxy port on a browser-restricted list, or proxy broken.** Delete and recreate the proxy:
  `railway tcp-proxy delete ... && railway tcp-proxy create --service cert-check --port 8443`. Update
  the `*.auth.cert-check.vocdoni.dev` CNAME if the proxy host changed.
  `CERTCHECK_AUTH_PUBLIC_PORT` follows `RAILWAY_TCP_PROXY_PORT` automatically.
- **R5 Token leak.** Revoke `CLOUDFLARE_API_TOKEN` in Cloudflare at once, create a new one
  (Zone:Read + Zone.DNS:Edit on `vocdoni.dev`), set it as a sealed variable and audit the
  `vocdoni.dev` DNS records.
- **R6 Withdraw the service.** Remove the custom domain and the TCP proxy
  (`railway domain delete cert-check.vocdoni.dev --service cert-check --yes`,
  `railway tcp-proxy delete ...`). The owner removes the two DNS records. The project and the volume
  are kept.

## 6. Security notes

The package's own security notes (pinned anchors, test markers, `NewHandler` checks) are in the
[root README](../README.md#security-notes). The notes below concern this deployment.

- **TLS 1.2 on the auth listener by default (deviation D2).** TLS 1.3 needs RSA-PSS for the client's
  CertificateVerify, which smart cards, TPM-backed keys and legacy Windows CAPI keys cannot sign, and
  there is no fallback. The cost: in TLS 1.2 the client certificate crosses the network unencrypted,
  so a passive observer on the path can read the holder's name and ID number. Set
  `CERTCHECK_AUTH_TLS13=true` once the client base is known to work.
- **Zone-wide Cloudflare token, accepted on 2026-10-31.** With `Zone:Read + Zone.DNS:Edit` on
  `vocdoni.dev`, a leaked token can rewrite every record in the zone. The owner accepted the risk. The
  CNAME delegation above removes it and is supported without code changes. The token is a sealed
  Railway variable that the code prints as `[redacted]`, and R5 is the response to a leak.
- **No PII in logs.** DNI/NIE, names, birth date, the subject DN, certificate bytes and hashes,
  and the state, code and cookie values are never logged, and the auth listener never logs a query
  string. Identity data lives only in the transaction's memory until it is redeemed or expires
  (5 minutes) and is never written to disk.
- **Fail closed.** Only the chain that `x509.Verify` builds from the pinned roots and intermediates is
  used, and only revocation status `good` passes. The certificates a client sends are never used for
  path building or revocation.
- **Root on Railway, accepted.** The image's default user is UID 65532 (`nonroot`), but Railway mounts
  the `/data` volume owned by root and its only documented workaround is `RAILWAY_RUN_UID=0`. In
  production the process, both listeners and the ACME client therefore run as UID 0 inside the
  container, and there is no in-process privilege drop. The accepted mitigations: a static Go binary
  (no cgo, no dynamic loader), a distroless image with no shell or package manager, and no privileged
  port needed (8080 and 8443).
- **CI runners.** The job runs repository code on org self-hosted runners. Keep the repository private,
  do not run workflows from forks, and keep the runner settings of [Deploy flow](#deploy-flow) step 4.
