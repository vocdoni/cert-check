# cert-check

cert-check is a Go package that authenticates people by the client certificate their browser presents
over TLS. It accepts Spanish certificates (FNMT, idCAT, ACCV, DNIe and others), checks them against
pinned trust anchors, and returns the holder's identity: document type and number (DNI or NIE), names
and, when the certificate carries it, the birth date. You choose which certificate types your program
accepts, build one `Handler` from them, and put its `TLSConfig` in an `http.Server`. The root module
depends only on `golang.org/x/crypto`, `golang.org/x/sync` and `golang.org/x/text`.

The repository also contains a testing UI, a small web app deployed on Railway that exercises the
package. It is a separate module and has its own README: [testui/README.md](testui/README.md).

Contents: [Install](#install) | [Quick start](#quick-start) | [Choosing certificate types](#choosing-certificate-types) |
[Handler and TLS](#handler-and-tls) | [Verifying without HTTP](#verifying-without-http) |
[Results and errors](#results-and-errors) | [Revocation and options](#revocation-and-options) |
[Security notes](#security-notes) | [Supported providers](#supported-providers) |
[Maintaining the trust set](#maintaining-the-trust-set) | [Development](#development)

## Install

```sh
go get github.com/vocdoni/cert-check
```

The module needs Go 1.27. While the repository is private, tell the go command to skip the public proxy
and checksum database for it:

```sh
export GOPRIVATE=github.com/vocdoni/cert-check
```

The package name is `certcheck`, so import it with that name:
`certcheck "github.com/vocdoni/cert-check"`.

## Quick start

This program accepts idCAT and FNMT certificates and greets the holder at `https://localhost:8443/login`.

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

To try it, create a server certificate for `localhost` with [mkcert](https://github.com/FiloSottile/mkcert),
then run the program from the directory that holds the two files:

```sh
mkcert -install    # once: makes your browser trust mkcert's CA
mkcert localhost   # writes localhost.pem and localhost-key.pem
go run .
```

Open <https://localhost:8443/login> in a browser that holds an idCAT or FNMT certificate. The browser
asks which certificate to present. It only offers certificates issued by the CAs the server advertises,
so a browser with no matching certificate sends none, and the answer is `no_certificate`. Browsers can
remember the choice for a host during a session; clear the SSL state or use a fresh profile to pick
another certificate.

## Choosing certificate types

A certificate type is a `certcheck.Provider`. Each issuer has a package under `providers/` whose
constructors return one, and your program accepts exactly the types you hand to `NewHandler`:

```go
func newHandler() (*certcheck.Handler, error) {
	return certcheck.NewHandler([]certcheck.Provider{
		idcat.New(),
		fnmt.New(),
		fnmt.NewEmployee(), // beta
	})
}
```

The 12 packages and their 14 constructors:

| Package | Constructors | Certificates |
|---|---|---|
| `providers/fnmt` | `New`, `NewRepresentative` (beta), `NewEmployee` (beta) | FNMT-RCM natural person (citizen), representative of an entity, public employee in software |
| `providers/idcat` | `New` | idCAT of the Consorci AOC (Catalonia), G2 and G3 |
| `providers/accv` | `New` | ACCV citizen in software |
| `providers/dnie` | `New` (beta) | DNIe authentication certificate |
| `providers/digitel` | `New` | DIGITEL ON citizen in software |
| `providers/bewor` | `New` | Bewor natural person in software |
| `providers/sectigo` | `New` | Sectigo qualified natural person (citizen) |
| `providers/firmaprofesional` | `New` (beta) | Firmaprofesional personal certificate |
| `providers/anf` | `New` (beta) | ANF AC class 2 natural person in software |
| `providers/uanataca` | `New` (beta) | Uanataca qualified citizen in software |
| `providers/signe` | `New` (beta) | SIGNE personal certificate |
| `providers/lleidanet` | `New` (beta) | Lleidanet / inDenova natural person in software |

The `providers` package builds several types at once, in display order (standard types first, then
beta): `providers.All()` returns every type, `providers.Standard()` leaves out the beta ones, and
`providers.ByID("idcat")` returns one type by its `Info().ID`. All of them, and every constructor, take
the same [options](#revocation-and-options). They omit a type that has no valid trust anchor (an
[inert provider](#security-notes)), so their result can go straight to `NewHandler`.

Beta types are implemented and tested like the others, but they have had less confirmation against
real holders' certificates. Try them with real users before you rely on them. `Info().Beta` reports the
flag and it changes no behavior. The [table below](#supported-providers) lists every type.

Build the providers and the `Handler` once at startup and share them: both are safe for concurrent use.

## Handler and TLS

`NewHandler(providers, options...)` returns an immutable `Handler`. It fails at construction, so a
misconfigured server does not start, if it gets no provider, a nil provider, two providers with the same
ID, an inert provider, or providers that overlap (see [Security notes](#security-notes)). Because of
those checks a leaf certificate has at most one candidate provider, and acceptance never depends on the
order of the list.

### TLSConfig

`h.TLSConfig(getCert, options...)` returns the `*tls.Config` of the listener that asks for the client
certificate. `getCert` supplies the server certificate and may be nil if you set `Certificates` on the
result. The policy:

- **TLS 1.2 only by default.** `certcheck.WithTLS13()` allows 1.3. TLS 1.3 requires an RSA-PSS
  signature for the client's CertificateVerify, which many smart cards, TPM-backed keys and legacy
  Windows CAPI keys cannot produce, and a client that cannot sign gets no fallback: it cannot
  authenticate at all. The price is that in TLS 1.2 the client certificate crosses the network
  unencrypted, so a passive observer on the path can read the holder's name and ID number. Enable 1.3
  once you know your users' keys work with it.
- **ECDHE with AEAD suites only** (AES-GCM and ChaCha20-Poly1305), curves X25519, P-256 and P-384.
- **`RequestClientCert`.** The client certificate is requested but not required, and the handler's CAs
  are advertised in the CertificateRequest so browsers offer only matching certificates. A browser with
  none completes the handshake, and `Auth` answers `no_certificate` instead of the browser showing a
  handshake error. The TLS layer proves that the client holds the private key but does not judge the
  chain. `Auth` and `Verify` do, so never trust `r.TLS.PeerCertificates` on its own.
- **Session tickets off.** Every connection presents its certificate again, so no resumed session
  skips the check.
- **ALPN `http/1.1` only.** `net/http` adds `h2` to a TLS server unless told otherwise, and HTTP/2 can
  reuse one connection for several hosts under a wildcard certificate. Set `http.Server.Protocols` to
  HTTP/1 only, as the quick start does. Authentication runs on every request.

### Auth and AuthAs

`h.Auth(r)` verifies `r.TLS.PeerCertificates` and picks the provider from the leaf's issuer: it is the
right call for a listener that accepts every type of the handler. It fills `Diagnostics.TLS` with the
handshake details. A request without TLS state is an `internal` error.

`h.AuthAs(r, providerID)` checks the certificate against the provider you name. Use it when the
listener already knows which type the user chose, for example one host per type
(`idcat.example.org`), and the type comes from the TLS server name. If the leaf is valid for another
type of the handler, the answer is `provider_mismatch`, so you can tell the user they picked the wrong
certificate. Call `CheckHost` first: it returns `ErrMisdirected` unless the request's `Host` equals
the TLS server name, so a client cannot present a certificate on one host and send the request to
another.

```go
// authAs serves a host that handles one certificate type, for example idcat.example.org.
func authAs(h *certcheck.Handler, providerID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := certcheck.CheckHost(r); err != nil {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest) // 421
			return
		}
		res, err := h.AuthAs(r, providerID)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprintln(w, res.Identity.FullName)
	}
}
```

For per-host listeners, give each host its own `tls.Config` from a `Handler` built with only that
host's provider, so it advertises only that provider's CAs, and verify with `AuthAs` on a `Handler`
built with all of them. The testing UI does this in `testui/internal/server/tlsconfig.go`.

### Adapters for blind-csp-shaped interfaces

The `Handler` has the methods a CSP integration usually asks for: `Name()` (always `"certcheck"`),
`RequireCertificate()` (always `true`), `Certificates()` (the DER of every advertised CA, as fresh
copies), `CertificateCheck(subject)` (is this DER subject one of the advertised CAs) and
`ClientCAs()`. `Providers()` returns the providers as a fresh slice. The `Auth` of your CSP's
interface has its own signature, so write it around `h.Auth`:

```go
// certAuth gets Name, RequireCertificate, Certificates and CertificateCheck from the Handler.
type certAuth struct{ *certcheck.Handler }

func (a certAuth) Auth(r *http.Request) (string, error) { // return what your CSP needs
	res, err := a.Handler.Auth(r)
	if err != nil {
		return "", err
	}
	return res.Identity.Document.Number, nil
}
```

## Verifying without HTTP

`Handler.Verify(ctx, chain)` takes the chain as `tls.ConnectionState.PeerCertificates` has it: `chain[0]`
is the leaf. The other certificates are ignored for path building, because only pinned CAs are trusted.
A single provider can also verify on its own, without a `Handler`: `idcat.New().Verify(ctx, chain)`. A
standalone provider answers `untrusted_issuer` for any leaf that does not chain to its own CAs.

```go
// Command verify checks the certificate chain in a PEM file, leaf first.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/providers/fnmt"
	"github.com/vocdoni/cert-check/providers/idcat"
)

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var chain []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		chain = append(chain, cert)
	}
	h, err := certcheck.NewHandler([]certcheck.Provider{idcat.New(), fnmt.New()})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := h.Verify(ctx, chain)
	if err != nil {
		log.Fatal(err) // *certcheck.Error: "certcheck: <code>: <detail>"
	}
	fmt.Println(res.Identity.FullName, res.Identity.Document.Number)
}
```

`VerifyAs(ctx, providerID, chain)` is the same call with the provider named, like `AuthAs`.

## Results and errors

A success is a `*certcheck.Result`. Every failure is a `*certcheck.Error` (from `Auth`, `AuthAs`,
`Verify`, `VerifyAs` and a provider's `Verify`), so `errors.AsType[*certcheck.Error](err)` always
succeeds on a non-nil error.

### Result

| Field | Type | Meaning |
|---|---|---|
| `Provider` | `ProviderRef` | `ID` and `Name` of the certificate type that accepted the certificate |
| `Profile` | `ProfileInfo` | `ID`, `Name` and `HolderRole` of the certificate profile that matched, for example `fnmt-citizen-g2` |
| `Identity` | `Identity` | the holder, below |
| `Organization` | `*Organization` | `Name` and `Identifier` of the entity a representative or public employee acts for. It is never the holder's identity, and it is nil for natural-person certificates |
| `Certificate` | `CertificateInfo` | subject (RFC 4514), issuer CN, serial, validity, SHA-256 and key algorithm of the leaf |
| `Revocation` | `RevocationInfo` | the evidence that was accepted: `Status` (always good in a `Result`), `Method`, `CheckedAt`, `ThisUpdate`, `NextUpdate` and the `Source` host |
| `ValidatedAt` | `time.Time` | validation time, UTC |
| `Diagnostics` | `Diagnostics` | the support report, filled on success as well |

`Identity` holds `Document` (`Type`, `Country` always `ES`, `Number` of 9 uppercase characters with
leading zeros kept, `Raw` as certified, `Source` for the certificate field it came from), `GivenNames`,
`Surnames`, `FirstSurname`, `SecondSurname`, `FullName`, `BirthDate` (a `*Date`, nil when the
certificate has none, JSON `YYYY-MM-DD`) and `Sources`, which names the certificate field each value
came from.

The `Role`, `DocumentType`, `RevocationStatus` and `RevocationMethod` values are exported constants:
`RoleNaturalPerson`, `RoleRepresentative`, `RolePublicEmployee`, `DocumentDNI`, `DocumentNIE`,
`RevocationStatusGood` and the other statuses, `RevocationMethodOCSP` and `RevocationMethodCRL`.
Compare fields with them:

```go
if res.Profile.HolderRole == certcheck.RoleRepresentative && res.Organization != nil {
	fmt.Println("acting for", res.Organization.Name)
}
if res.Identity.Document.Type == certcheck.DocumentNIE {
	fmt.Println("foreign national:", res.Identity.Document.Number)
}
if res.Identity.BirthDate != nil {
	fmt.Println("born", res.Identity.BirthDate.String())
}
```

### Errors

`Error` has `Code`, `Retryable`, `Detail` and `Diagnostics`. `Detail` never contains identity data or
certificate values. `Retryable` is true for `revocation_unavailable` and `internal`: retrying later may
succeed. For the others the certificate itself is the problem. `certcheck.Codes` lists all 16 codes,
for tables keyed by code such as user messages or metrics.

| Code | Step | Meaning | Retryable |
|---|---|---|---|
| `no_certificate` | `bounds` | The client sent no certificate | no |
| `provider_mismatch` | `bounds`, `path` | The provider ID is unknown, or the certificate belongs to another certificate type of the handler (`VerifyAs` and `AuthAs`) | no |
| `untrusted_issuer` | `path` | The leaf does not chain to the pinned CAs. From `Handler.Verify`: no provider advertises the leaf's issuer | no |
| `invalid_chain` | `bounds`, `path`, `purpose` | The chain is over 10 certificates, a certificate is over 16 KiB, an intermediate or anchor is outside its validity, or a critical extension is unhandled or malformed | no |
| `expired` | `path` | The leaf's validity has ended | no |
| `not_yet_valid` | `path` | The leaf's validity has not started | no |
| `unsupported_profile` | `profile` | The leaf chains to a pinned CA but asserts no policy OID of an enabled profile, for example another product of the same CA, such as a Sectigo employee certificate. Also a leaf that matches more than one profile: two profiles share a key under distinct OIDs and the leaf asserts both | no |
| `unsupported_purpose` | `path`, `purpose` | Key usage or extended key usage does not allow client authentication | no |
| `weak_algorithm` | `algorithms` | An RSA key under 2048 bits (a profile may require more), an ECDSA curve other than P-256, P-384 and P-521, or a signature weaker than SHA-256 | no |
| `test_certificate` | `test_marker` | A published specimen or a reserved test identity (see [Security notes](#security-notes)) | no |
| `identity_invalid` | `identity` | Name, document number or birth date is missing, malformed or inconsistent | no |
| `identity_unsupported_document` | `identity` | A well-formed identifier of a kind the profile does not accept, for example a foreign identity number | no |
| `revoked` | `revocation` | The issuer reports the certificate as revoked | no |
| `revocation_unknown` | `revocation` | The responder does not know the certificate | no |
| `revocation_unavailable` | `revocation` | No acceptable evidence: the endpoint is unreachable or answers an error, or the answer is stale or invalid | yes |
| `internal` | any | A failure that is not the certificate's: a deadline during revocation, a request without TLS state, a provider that misbehaves | yes |

`Verify` runs the steps in this order and stops at the first failure: `bounds` (chain length and
certificate size), `algorithms`, `path` (a chain from the leaf to a pinned anchor, client-authentication
purpose), `profile` (exactly one profile whose policy OID the leaf asserts), `purpose`, `test_marker`,
`identity` (strict parsing, then reserved identities), and `revocation` (OCSP, then CRL where the profile
allows it, for the leaf and every intermediate on the verified path). The failed step is
`Diagnostics.FailedStep`; the constants are `StepBounds`, `StepAlgorithms` and so on.

```go
res, err := h.Verify(ctx, chain)
if e, ok := errors.AsType[*certcheck.Error](err); ok {
	// LogAttrs holds only the fields that are safe to log.
	slog.LogAttrs(ctx, slog.LevelWarn, "certificate rejected", e.Diagnostics.LogAttrs()...)
	if e.Retryable {
		fmt.Println("try again later")
	}
	return
}
fmt.Println("accepted", res.Identity.FullName)
```

### Diagnostics

`Diagnostics` is the support report: a random `DiagnosticID` (32 hex digits, never derived from the
identity), the time, the failed step and code, a technical detail, the handshake (`TLS`), the leaf
(`Certificate`), the received `Chain`, each profile tried (`ProfileCandidates`) and every OCSP or CRL
fetch (`RevocationAttempts`). It has JSON tags. It is bound to the session of the person who ran the
check: it holds certificate details such as the subject and serial, so show it only to that browser.
Do not log it. Log `Diagnostics.LogAttrs()`, which leaves out the subject, names, document, serial,
leaf hash, URL paths and technical detail, and put the `DiagnosticID` in the page so a support request
can be matched to the log line. `NewDiagnosticID`, `DescribeTLS` and `DescribeCertificate` are exported
for servers that build their own `Error` or `Diagnostics`.

## Revocation and options

Revocation is checked with OCSP first, then CRL where the profile allows it, and only a `good` answer
passes. With no options, every provider shares one process-wide checker that is created on first use. It
sends the User-Agent `cert-check/dev` and uses the wall clock, with a 5 s OCSP timeout, a 15 s CRL
timeout, a 128 MiB parsed-CRL cache and a 4096-entry OCSP cache. It fetches only from the hosts each
profile allowlists, never from loopback, private or link-local addresses, and a redirect from `http` to
`https` is followed but a downgrade never is.

To set the User-Agent, the timeouts or the cache bounds, create one `Revocation` with `NewRevocation`
and pass it to every provider with `WithRevocation`. The caches are shared by everything that gets the
same `*Revocation`. A zero `Revocation` is not usable, and `WithRevocation` panics on one.
`CRLCacheBytes` also caps the size of a CRL: one whose parsed size would exceed it is refused, so a check
that needs it fails with `revocation_unavailable` when OCSP does not answer. Keep the bound above the
largest CRL of the providers you enable (about 160 bytes per entry).

```go
func newHandler() (*certcheck.Handler, error) {
	rev, err := certcheck.NewRevocation(certcheck.RevocationOptions{
		UserAgent:     "my-service/1.4",
		OCSPTimeout:   3 * time.Second,
		CRLTimeout:    10 * time.Second,
		CRLCacheBytes: 64 << 20,
	})
	if err != nil {
		return nil, err
	}
	opts := []certcheck.Option{
		certcheck.WithRevocation(rev),
		certcheck.WithLogger(slog.Default()),
		certcheck.WithVersion("1.4"),
	}
	return certcheck.NewHandler(providers.All(opts...), opts...)
}
```

The options:

- `WithRevocation(r)`: the shared revocation checker, as above.
- `WithClock(now)`: the pipeline clock. Providers check anchor validity at construction and certificate
  validity at verification with it, and the `Handler` stamps its own errors with it. The revocation
  checker keeps its own clock, `RevocationOptions.Now`, so set both in tests.
- `WithLogger(l)`: where construction warnings go (an anchor outside its validity, a disabled
  profile). The default is `slog.Default()`. Revocation warnings go to `RevocationOptions.Logger`
  instead (see [Security notes](#security-notes)).
- `WithVersion(v)`: the `Diagnostics.ServerVersion` value.

Pass the same options to the provider constructors and to `NewHandler`. The constructors use all of
them. `NewHandler` uses `WithClock` and `WithVersion` and ignores the rest.

`Verify`, `VerifyAs`, `Auth` and `AuthAs` make network requests, bounded only by the context you pass.
Always give it a deadline: the testing UI uses 40 s. When the deadline hits during revocation the
answer is `internal` and retryable. `Auth` takes the context from the request, so use
`r.WithContext(ctx)` as the quick start does.

## Security notes

- **Pinned anchors only.** The trust set is embedded in the module: the Spanish TSL service identities,
  plus a few intermediates pinned by hand. Nothing is fetched at runtime. The certificates a client
  sends after the leaf are never used for path building or revocation, so a client cannot bring its own
  CA or intermediate. A TSL withdrawal or a new CA key reaches you with a new version of the module.
- **Fail closed.** Any doubt is an error. Only the chain that `x509.Verify` builds from the pinned roots
  and intermediates counts, only revocation status `good` passes, and a `Result` exists only with good
  evidence for the leaf. Unknown, unavailable, stale and unsupported evidence all fail.
- **TLS 1.2 by default.** The trade-off is described under [Handler and TLS](#handler-and-tls): TLS 1.3
  breaks users whose keys cannot sign with RSA-PSS, and TLS 1.2 lets a passive observer read the
  certificate. The choice is yours through `WithTLS13`.
- **Test certificates and reserved identities.** Each profile lists the fingerprints of the
  specimen certificates the CAs publish, and a shared table lists reserved identities: test document
  numbers, placeholder surnames and given names such as `ESPECIMEN` and `PRUEBAS`, and a placeholder
  organization. A certificate that matches is rejected as `test_certificate` even when it chains to a
  real CA and is not revoked. Your own tests cannot use CA-published test certificates. Test against a
  small `certcheck.Provider` double instead; the interface has three methods.
- **Inert providers and the `NewHandler` checks.** A provider whose pinned anchors are all outside their
  validity when it is built is inert: `Info()` is unchanged, `CAs()` is empty, and `Verify` answers
  `provider_mismatch` with "provider has no enabled profile". `providers.All`, `Standard` and `ByID`
  omit inert providers, and `NewHandler` returns an error for one, so a server fails at startup instead
  of advertising no CA. `NewHandler` also rejects a nil provider, duplicate IDs, a CA subject
  advertised by two providers, and two profiles of different providers that share a pinned CA key
  (anchor or pinned intermediate) and a policy OID. The provider constructors panic on corrupt
  embedded data (a pin that does not match, a malformed declaration): that is a build-time error that
  the module's tests catch.
- **No PII in logs.** The package logs only warnings: at construction, through the `WithLogger` logger,
  and at verification, one per rejected piece of revocation evidence (the pinned CA's subject, method,
  outcome and host), through `RevocationOptions.Logger` (`slog.Default()` for the default checker).
  Neither carries client data.
  `Error.Detail` and `Diagnostics.LogAttrs()` never carry names, document numbers, subjects, serials or
  certificate hashes. Keep it that way in your own logging: log `LogAttrs()`, not `Diagnostics`.

## Supported providers

`ID` is `Info().ID`: the value for `AuthAs`, `VerifyAs` and `providers.ByID`. The rows are in display
order.

| ID | Name | Constructor | Beta |
|---|---|---|---|
| `fnmt` | FNMT - Persona Física | `fnmt.New` | no |
| `idcat` | idCAT Certificat | `idcat.New` | no |
| `accv` | ACCV - Ciudadano (software) | `accv.New` | no |
| `digitel` | DIGITEL ON - Ciudadano | `digitel.New` | no |
| `bewor` | Bewor - Persona Física | `bewor.New` | no |
| `sectigo` | Sectigo - Ciudadano | `sectigo.New` | no |
| `fnmt-representative` | FNMT - Representante | `fnmt.NewRepresentative` | yes |
| `fnmt-employee` | FNMT - Empleado Público | `fnmt.NewEmployee` | yes |
| `firmaprofesional` | Firmaprofesional | `firmaprofesional.New` | yes |
| `anf` | ANF AC | `anf.New` | yes |
| `uanataca` | Uanataca | `uanataca.New` | yes |
| `signe` | SIGNE | `signe.New` | yes |
| `lleidanet` | Lleidanet / inDenova | `lleidanet.New` | yes |
| `dnie` | DNIe (requires card reader) | `dnie.New` | yes |

Two types have revocation quirks. Lleidanet is CRL-only: the certificate of its OCSP responder
(`ocsp2.esigna.es`) lacks id-pkix-ocsp-nocheck, so its answers are never acceptable, and the OCSP URL in
the leaves is ignored. SIGNE is CRL-only too, and its `signe-subca.crl` answers 302 from
`http://www.signe.es` to `https://crl.firmaprofesional.com`, which is allowlisted for SIGNE. The fetcher
follows that `http` to `https` upgrade but never an `https` to `http` downgrade. The DNIe is checked
with OCSP, and its pinned intermediates through the root's CRLs. The browser must already be able to use
the card.

## Maintaining the trust set

The trust set is pinned in the repository, not fetched at runtime: anchors are the Spanish TSL service
identities from `TSL20260924` (sequence 189, next update 2027-03-21). A TSL withdrawal or a new CA key is
not picked up until the data is updated and released. Every change goes through pull request and CI, and
every file below has a SOURCES or MANIFEST table that a test recomputes.

- **Add or rotate an anchor.**
  1. Copy the PEM byte-identically (`cp`, never re-encode) to
     `internal/profiles/anchors/<sha256 of the DER>.pem`. Official downloads need their source URL and
     SHA-256 recorded.
  2. Add the row to `internal/profiles/anchors/SOURCES.md` (source, file, DER and SPKI SHA-256, TSL
     status).
  3. Pin it with `anchor(derSHA256, spkiSHA256)` under the right profile in the provider's file,
     `internal/profiles/<provider>.go`. (`SOURCES.md` still says `providers.go`: that was the one file
     holding every provider before it was split.) `registry.go` rechecks both pins when a provider is
     built, and a mismatch panics in the constructor.
  4. Refresh the TSL inventory in `internal/profiles/testdata/` (and its SHA-256 in `SOURCES.md`) when
     the TSL changed, so `TestAnchorsGrantedInTSL` checks the new anchor.
  5. Run the tests (`TestAnchorFiles`, `TestAnchorsGrantedInTSL`, `TestTSLInventorySource`) and the full
     CI checks. A profile whose anchors have all expired is disabled at construction with a warning, and
     a provider left without a profile is inert.
- **Disable a profile or provider.** Remove the profile from its provider's file in
  `internal/profiles/`. To remove a whole provider, also remove it from `All()` in
  `internal/profiles/providers.go` and from the constructor list in `providers/providers.go`.
- **Refresh specimens and markers.** Specimen certificates under `testdata/specimens/` are CA-published
  test certificates, one clean PEM block each, listed in `testdata/specimens/MANIFEST.md` with the
  SHA-256 of the DER (`TestSpecimenManifest` checks every row). Never commit a real person's
  certificate, or one whose SAN names an individual (see ruling R30 in the manifest). Test markers
  (`fp(...)` and `TestMarker` in the provider files) and the reserved identities and name markers
  (`identity.DefaultReserved()` in `internal/identity/reserved.go`) must follow any new specimen set a
  CA publishes.
- **DNIe intermediates.** AC DNIE 004, 005 and 006 are not TSL service identities. They are pinned
  separately (`IntermediateExceptions` in `internal/profiles/dnie.go`) from
  `http://pki.policia.es/dnie/certs/`. Re-check that directory for AC DNIE 007 or later; verify any new
  file against AC RAIZ DNIE 2 and pin it the same way.

## Development

The repository has two Go modules. The root module is the package and has no dependency outside
`golang.org/x`. `testui/` is the testing UI; it requires the root module through
`replace github.com/vocdoni/cert-check => ../` and is the only place that depends on certmagic, libdns,
zap and `golang.org/x/time`. Run the checks in each module, from its own directory:

```sh
test -z "$(gofmt -l .)"
go mod tidy -diff
go vet ./... && go vet -tags live ./...
go test -race -count=1 ./...
```

`-race` needs a C toolchain. Tests use no network beyond loopback and the synthetic PKI in
`internal/testpki`, and a skipped test fails CI. Checks that need the real network sit behind
`-tags live` and are described in [testui/README.md](testui/README.md).

`.github/workflows/ci.yml` runs for both modules gofmt, `go mod tidy -diff`, vet (also with `-tags
live`), staticcheck, a `CGO_ENABLED=0` build, `go test -race` with the skip check and govulncheck. It
also runs a 30 s fuzz smoke per target in the root module, the dependency isolation check, the Docker
build of `testui/Dockerfile` and the `go doc` golden diff of the root package.

- `testdata/golden/` holds the goldens captured before the package was restructured: test names,
  specimen verdicts, synthetic `Result` JSON, the provider declarations, and the providers API body and
  per-host CA lists of the testing UI. Tests assert them. They are never regenerated to make a test
  pass: a difference is a behavior change.
- `testdata/godoc.golden` is the committed `go doc` output of the public API, and CI diffs it. After an
  intended API change, update it with `go doc -all . > testdata/godoc.golden`.
