package web_test

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/testui/web"
)

// requiredStatic lists every file the UI ships (Task 11 file list).
var requiredStatic = []string{
	"index.html",
	"app.js",
	"i18n.js",
	"styles.css",
	"favicon.ico",
	"img/vocdoni-logo.svg",
	"fonts/fraunces-latin-full-normal.woff2",
	"fonts/fraunces-latin-ext-full-normal.woff2",
	"fonts/hanken-grotesk-latin-wght-normal.woff2",
	"fonts/hanken-grotesk-latin-ext-wght-normal.woff2",
	"fonts/OFL-Fraunces.txt",
	"fonts/OFL-HankenGrotesk.txt",
	"fonts/SOURCES.md",
}

func readStatic(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(web.FS(), name)
	if err != nil {
		t.Fatalf("read embedded %s: %v", name, err)
	}
	return string(b)
}

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel))
	if err != nil {
		t.Fatalf("read testdata %s: %v", rel, err)
	}
	return b
}

func TestEmbeddedFiles(t *testing.T) {
	fsys := web.FS()
	for _, name := range requiredStatic {
		info, err := fs.Stat(fsys, name)
		if err != nil {
			t.Errorf("embedded file %s: %v", name, err)
			continue
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			t.Errorf("embedded file %s: regular=%v size=%d, want a non-empty regular file", name, info.Mode().IsRegular(), info.Size())
		}
	}

	exists := func(ref, from string) {
		t.Helper()
		ref, _, _ = strings.Cut(ref, "#")
		ref, _, _ = strings.Cut(ref, "?")
		if ref == "" || strings.HasPrefix(ref, "#") {
			return
		}
		if !strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "//") {
			t.Errorf("%s: reference %q is not a same-origin absolute path", from, ref)
			return
		}
		if _, err := fs.Stat(fsys, strings.TrimPrefix(path.Clean(ref), "/")); err != nil {
			t.Errorf("%s references %q: %v", from, ref, err)
		}
	}

	attrRef := regexp.MustCompile(`(?i)\b(?:href|src)\s*=\s*"([^"]*)"`)
	for _, m := range attrRef.FindAllStringSubmatch(readStatic(t, "index.html"), -1) {
		exists(m[1], "index.html")
	}
	cssURL := regexp.MustCompile(`(?i)url\(\s*['"]?([^'")\s]+)['"]?\s*\)`)
	for _, m := range cssURL.FindAllStringSubmatch(readStatic(t, "styles.css"), -1) {
		exists(m[1], "styles.css")
	}
}

func TestNoExternalReferences(t *testing.T) {
	// Any scheme-qualified or protocol-relative URL. Comments in app.js
	// therefore keep a space after the slashes.
	external := regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9]`)
	for _, name := range []string{"index.html", "app.js", "i18n.js", "styles.css"} {
		src := readStatic(t, name)
		if loc := external.FindStringIndex(src); loc != nil {
			t.Errorf("%s: external reference near %q", name, src[loc[0]:min(len(src), loc[0]+40)])
		}
		if strings.Contains(src, "@import") {
			t.Errorf("%s: @import is not allowed", name)
		}
	}
	// Data URIs are allowed only in CSS (icons).
	for _, name := range []string{"index.html", "app.js", "i18n.js"} {
		if strings.Contains(readStatic(t, name), "data:") {
			t.Errorf("%s: data: URI is only allowed in CSS", name)
		}
	}
}

func TestNoUnsafeDOM(t *testing.T) {
	for _, name := range []string{"app.js", "i18n.js"} {
		js := readStatic(t, name)
		for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "Function(", "srcdoc"} {
			if strings.Contains(js, banned) {
				t.Errorf("%s contains %q", name, banned)
			}
		}
	}
}

func TestCSPCompatible(t *testing.T) {
	html := readStatic(t, "index.html")

	// The strings, then the app: deferred scripts run in document order.
	scripts := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(html, -1)
	wantSrc := []string{`src="/i18n.js"`, `src="/app.js"`}
	if len(scripts) != len(wantSrc) {
		t.Fatalf("index.html has %d script elements, want %d", len(scripts), len(wantSrc))
	}
	for i, script := range scripts {
		attrs, body := script[1], script[2]
		if strings.TrimSpace(body) != "" {
			t.Errorf("inline script body %q, want none", body)
		}
		for _, want := range []string{wantSrc[i], "defer"} {
			if !strings.Contains(attrs, want) {
				t.Errorf("script %d attributes %q lack %q", i, attrs, want)
			}
		}
	}

	checks := []struct {
		name string
		re   string
	}{
		{"style element", `(?i)<style\b`},
		{"style attribute", `(?i)\sstyle\s*=`},
		{"event handler attribute", `(?i)\son[a-z]+\s*=`},
		{"javascript: URL", `(?i)javascript:`},
	}
	for _, c := range checks {
		if loc := regexp.MustCompile(c.re).FindStringIndex(html); loc != nil {
			t.Errorf("index.html has a %s near %q", c.name, html[loc[0]:min(len(html), loc[0]+40)])
		}
	}

	for _, want := range []string{
		`<link rel="icon" href="/favicon.ico">`,
		`<meta name="viewport" content="width=device-width, initial-scale=1">`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}

	// Styling stays in the stylesheet: the CSP has style-src 'self'.
	for _, name := range []string{"app.js", "i18n.js"} {
		js := readStatic(t, name)
		for _, banned := range []string{".style.", ".style[", "cssText", "'style'", `"style"`, "javascript:"} {
			if strings.Contains(js, banned) {
				t.Errorf("%s contains %q", name, banned)
			}
		}
	}
}

// jsFunc returns the source of a function declared at the top level of app.js's wrapper.
func jsFunc(t *testing.T, js, name string) string {
	t.Helper()
	src := regexp.MustCompile(`(?ms)^  (?:async )?function ` + name + `\(.*?^  }$`).FindString(js)
	if src == "" {
		t.Fatalf("app.js has no function %s", name)
	}
	return src
}

// TestAppJSCodeTables covers U14-ASTRA-1. An error code from the URL fragment or from the API must
// never index a plain object: "__proto__" would return Object.prototype and "constructor" would
// return Object, and the error view would then fail to render. The table lookups are own-property
// only, so an unknown code falls back to the generic message and guidance. The same holds for the
// language dictionaries (AC7): a language code or a text key never indexes them directly.
func TestAppJSCodeTables(t *testing.T) {
	js := readStatic(t, "app.js")
	if loc := regexp.MustCompile(`\b(?:GUIDANCE|STRINGS|strings|text|messages|guidance)\s*\[`).FindStringIndex(js); loc != nil {
		t.Errorf("app.js indexes a code table directly near %q, want the own-property lookup", js[loc[0]:min(len(js), loc[0]+40)])
	}
	if lookup := jsFunc(t, js, "lookup"); !strings.Contains(lookup, "Object.prototype.hasOwnProperty.call(") {
		t.Errorf("lookup() = %q, want an Object.prototype.hasOwnProperty own-property check", lookup)
	}
	for _, fn := range []string{"t", "guidanceFor", "displayMessage", "reportMessage", "useLanguage"} {
		if src := jsFunc(t, js, fn); !strings.Contains(src, "lookup(") {
			t.Errorf("%s() does not use lookup() for its code table", fn)
		}
	}
}

// TestAppJSAPIDeadline covers U14-ASTRA-2. One AbortController deadline covers the request and the
// body read, a timeout is its own recoverable error, and nothing replays a request on its own (a
// redemption code is single use).
func TestAppJSAPIDeadline(t *testing.T) {
	js := readStatic(t, "app.js")

	m := regexp.MustCompile(`const API_TIMEOUT_MS = (\d+) \* 1000;`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("app.js has no API_TIMEOUT_MS constant in seconds")
	}
	if secs, _ := strconv.Atoi(m[1]); secs < 1 || secs > 30 {
		t.Errorf("API_TIMEOUT_MS = %s s, want 1 to 30 s (the server's write timeout is 30 s)", m[1])
	}

	// The timer starts before the request and stops only after the body was read.
	api := jsFunc(t, js, "api")
	at := 0
	for _, step := range []string{"new AbortController()", "signal: ", "setTimeout(", "await fetch(", "await res.text()", "clearTimeout("} {
		i := strings.Index(api[at:], step)
		if i < 0 {
			t.Errorf("api() lacks %q after the previous deadline step", step)
			continue
		}
		at += i + len(step)
	}
	if n := strings.Count(js, "fetch("); n != 1 {
		t.Errorf("app.js calls fetch( %d times, want the single deadline-bound call in api()", n)
	}
	if strings.Contains(api, "res.json()") {
		t.Error("api() reads the body with res.json(); a read failure must reject, not look like a bad reply")
	}

	// A timeout is a recoverable error with its own message and guidance.
	for _, want := range []string{"    timeout: TEMPORARY,", "'TimeoutError'"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %q for the timeout error", want)
		}
	}
	for lang, d := range readDictionaries(t) {
		if d.Messages["timeout"] == "" {
			t.Errorf("i18n.js %s has no timeout message", lang)
		}
	}
	for _, fn := range []string{"authenticate", "redeem"} {
		if src := jsFunc(t, js, fn); !strings.Contains(src, "failureCode(e)") {
			t.Errorf("%s() does not map a failed request through failureCode()", fn)
		}
	}

	// No automatic replay: one redemption call site and no timer besides the deadline.
	if n := strings.Count(js, "transactions/redeem"); n != 1 {
		t.Errorf("app.js names the redeem endpoint %d times, want exactly 1", n)
	}
	if n := strings.Count(js, "setTimeout("); n != 1 {
		t.Errorf("app.js has %d setTimeout( calls, want only the API deadline", n)
	}
}

// TestAppJSRepliesAreValidated covers U14-ASTRA-3. Reply envelopes and the members of their arrays
// are shape-checked before rendering, and any exception while handling a reply ends in the
// bad_response view instead of a stuck "Checking" view.
func TestAppJSRepliesAreValidated(t *testing.T) {
	js := readStatic(t, "app.js")

	for _, fn := range []string{"isObject", "isApiError", "isDiagnostics", "isRedeemReply", "isProviderList", "guard"} {
		jsFunc(t, js, fn)
	}
	// Array members of the diagnostics must be objects: a null entry in chain threw while the
	// report was built.
	diag := jsFunc(t, js, "isDiagnostics")
	for _, key := range []string{"tls", "certificate", "chain", "profileCandidates", "revocationAttempts"} {
		if !strings.Contains(diag, "'"+key+"'") {
			t.Errorf("isDiagnostics() does not check %q", key)
		}
	}
	for fn, check := range map[string]string{
		"redeem":        "isRedeemReply(",
		"authenticate":  "isApiError(",
		"loadProviders": "isProviderList(",
	} {
		if src := jsFunc(t, js, fn); !strings.Contains(src, check) {
			t.Errorf("%s() does not validate its reply with %s", fn, check)
		}
	}

	// Whatever the load logic or a click handler throws is routed to the bad_response view, and
	// when that view throws too, to the self-contained fallback.
	g := jsFunc(t, js, "guard")
	if !strings.Contains(g, "catch") || !strings.Contains(g, "code: 'bad_response'") {
		t.Errorf("guard() = %q, want a catch that renders bad_response", g)
	}
	if !regexp.MustCompile(`(?s)catch \(e\) \{\s*try \{\s*showClientError\(\{ code: 'bad_response' \}\);\s*\} catch \(\w+\) \{\s*showFatal\(\);\s*\}`).MatchString(g) {
		t.Errorf("guard() = %q, want showClientError in a try whose catch calls only showFatal()", g)
	}
	for _, want := range []string{"guard(authenticate)", "guard(init)"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js does not wrap its entry point with %s", want)
		}
	}
	// No entry point runs unguarded: init is only declared (once) and handed to guard.
	if strings.Contains(js, ", authenticate)") {
		t.Error("app.js registers authenticate without guard()")
	}
	if n := len(regexp.MustCompile(`\binit\(`).FindAllString(js, -1)); n != 1 {
		t.Errorf("app.js has %d init( occurrences, want only its declaration (callers use the guarded copy)", n)
	}
}

// TestAppJSOlderBrowsers covers U14-FABLE-1. The error paths use no API newer than Chrome 90,
// Firefox 90 and Safari 15: Object.hasOwn (Chrome 93, Firefox 92, Safari 15.4) threw in every
// lookup there, and abort(reason) (Chrome 98, Firefox 97, Safari 15.4) is ignored there, so the
// deadline is a plain abort() and a flag of our own.
func TestAppJSOlderBrowsers(t *testing.T) {
	js := readStatic(t, "app.js")
	// Newer than the Safari 15, Chrome 90 and Firefox 90 baseline (R14.1).
	for _, name := range []string{"app.js", "i18n.js"} {
		src := readStatic(t, name)
		for _, banned := range []string{"Object.hasOwn", ".at(", ".findLast", "structuredClone(", "Object.groupBy"} {
			if strings.Contains(src, banned) {
				t.Errorf("%s uses %s, which a browser of the baseline lacks", name, banned)
			}
		}
	}
	if loc := regexp.MustCompile(`\.abort\(\s*[^)\s]`).FindStringIndex(js); loc != nil {
		t.Errorf("app.js passes a reason to abort() near %q; older browsers ignore it", js[loc[0]:min(len(js), loc[0]+40)])
	}
	api := jsFunc(t, js, "api")
	for _, want := range []string{".abort()", "'TimeoutError'"} {
		if !strings.Contains(api, want) {
			t.Errorf("api() lacks %q: the deadline must reject with a TimeoutError on its own", want)
		}
	}
}

// TestAppJSFatalFallback covers U14-FABLE-1. The last resort of guard() must not depend on the
// helpers, tables or views it stands in for: it writes a fixed message and a reload control with
// plain DOM calls, inside a try.
func TestAppJSFatalFallback(t *testing.T) {
	js := readStatic(t, "app.js")
	fatal := jsFunc(t, js, "showFatal")
	body := strings.TrimSpace(fatal[strings.Index(fatal, "{")+1 : strings.LastIndex(fatal, "}")])
	if !strings.HasPrefix(body, "try {") || !strings.HasSuffix(body, "}") || !strings.Contains(body, "} catch (") {
		t.Errorf("showFatal() body is not one try statement:\n%s", body)
	}
	helper := regexp.MustCompile(`(?:^|[^\w$.])(\$|el|str|lookup|t|fill|format|showView|showWorking|renderError|showClientError|showServerError|guidanceFor|reportHeader|attemptLines)\(`)
	if m := helper.FindStringSubmatch(fatal); m != nil {
		t.Errorf("showFatal() calls %s(), one of the helpers it stands in for", m[1])
	}
	for _, banned := range []string{"replaceChildren(", ".append(", "await ", "setTimeout("} {
		if strings.Contains(fatal, banned) {
			t.Errorf("showFatal() uses %q", banned)
		}
	}
	// Its texts are plain reads from the active dictionary, so it speaks the chosen language.
	for _, want := range []string{"strings.text.error_heading", "strings.messages.bad_response", "strings.text.start_again", "location.reload()"} {
		if !strings.Contains(fatal, want) {
			t.Errorf("showFatal() lacks %q", want)
		}
	}
}

// TestWorkingViewExit covers U14-FABLE-2. The working view has a "Start again" pill that forgets the
// attempt and reloads the page. The reload cannot redeem a code again: init() replaces the URL with
// / before its first await.
func TestWorkingViewExit(t *testing.T) {
	html := readStatic(t, "index.html")
	working := regexp.MustCompile(`(?s)<section id="view-working"[^>]*>(.*?)</section>`).FindStringSubmatch(html)
	if working == nil || !strings.Contains(working[1], `<button id="cancel" class="pill" type="button" data-i18n="start_again">Start again</button>`) {
		t.Error(`the working view lacks <button id="cancel" class="pill" type="button" data-i18n="start_again">Start again</button>`)
	}
	js := readStatic(t, "app.js")
	if !strings.Contains(js, "$('cancel').addEventListener('click', startOver);") {
		t.Error("app.js does not wire the cancel button to startOver")
	}
	over := jsFunc(t, js, "startOver")
	for _, want := range []string{"clearPending()", "location.reload()"} {
		if !strings.Contains(over, want) {
			t.Errorf("startOver() lacks %q", want)
		}
	}
	if strings.Contains(over, "redeem") {
		t.Error("startOver() redeems; a redemption is never retried")
	}
	initSrc := jsFunc(t, js, "init")
	if r, a := strings.Index(initSrc, "history.replaceState(null, '', '/');"), strings.Index(initSrc, "await "); r < 0 || r > a {
		t.Error("init() does not replace the URL with / before its first await")
	}
}

func TestRequiredText(t *testing.T) {
	html := readStatic(t, "index.html")
	js := readStatic(t, "app.js")

	for _, want := range []string{
		`<html lang="en">`,
		`<title>Certificate Authentication Checker</title>`,
		`>Certificate Authentication Checker</h1>`,
		`Check that your Spanish personal certificate works in this browser and see the identity data it carries.`,
		`<label for="provider" data-i18n="provider_label">Certificate provider</label>`,
		`<select id="provider"`,
		`Requires a card reader and the DNIe software already working in this browser.`,
		`id="authenticate" class="pill primary"`,
		`>Authenticate</button>`,
		`Your browser will ask you to choose a certificate. Nothing is uploaded and your private key never leaves your device.`,
		`>Success</h1>`,
		`<dl id="result-list"`,
		`id="again" class="pill"`,
		`>Check another certificate</button>`,
		`>We could not authenticate this certificate</h1>`,
		`id="error-message"`,
		`id="error-guidance"`,
		`<details id="tech"><summary data-i18n="technical_details">Technical details</summary>`,
		`<p class="hint" data-i18n="report_language">The diagnostic report is in English so that Vocdoni support can read it.</p><pre id="report"`,
		`id="copy-report"`,
		`>Copy diagnostic report</button>`,
		`This report contains your certificate details (name and ID number). Share it only with Vocdoni support.`,
		`id="retry" class="pill primary"`,
		`>Start again</button>`,
		`id="status"`,
		`role="status"`,
		`aria-live="polite"`,
		`alt="Vocdoni"`,
		// The language selector (AC3), its accessible label and the languages by their own names.
		// It starts hidden: without JavaScript it would do nothing (app.js init shows it).
		`<div class="language" hidden>`,
		`<label for="language" class="sr-only" data-i18n="language_label">Language</label>`,
		`<select id="language">`,
		`<option value="en" lang="en">English</option>`,
		`<option value="es" lang="es">Español</option>`,
		`<option value="ca" lang="ca">Català</option>`,
		// One sentence per language for a browser without JavaScript (AC5).
		`<span lang="en">This page needs JavaScript to check a certificate.</span>`,
		`<span lang="es">Esta página necesita JavaScript para comprobar un certificado.</span>`,
		`<span lang="ca">Aquesta pàgina necessita JavaScript per comprovar un certificat.</span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if header := regexp.MustCompile(`(?s)<header class="site-header">(.*?)</header>`).FindStringSubmatch(html); header == nil || !strings.Contains(header[1], `<select id="language">`) {
		t.Error("the language selector is not in the site header")
	}

	// The required text in each language: formal register (usted, vostè) and the shared terms.
	dicts := readDictionaries(t)
	for _, c := range []struct{ section, key, en, es, ca string }{
		{"text", "title", "Certificate Authentication Checker",
			"Comprobador de autenticación con certificado", "Comprovador d'autenticació amb certificat"},
		{"text", "language_label", "Language", "Idioma", "Idioma"},
		{"text", "authenticate", "Authenticate", "Autenticarse", "Autenticar-se"},
		{"text", "start_note",
			"Your browser will ask you to choose a certificate. Nothing is uploaded and your private key never leaves your device.",
			"Su navegador le pedirá que elija un certificado. No se envía ningún archivo y su clave privada nunca sale de su dispositivo.",
			"El seu navegador li demanarà que triï un certificat. No s'envia cap fitxer i la seva clau privada no surt mai del seu dispositiu."},
		{"text", "provider_hint", "Requires a card reader and the DNIe software already working in this browser.",
			"Requiere un lector de tarjetas y que el software del DNIe ya funcione en este navegador.",
			"Cal un lector de targetes i que el programari del DNIe ja funcioni en aquest navegador."},
		{"text", "error_heading", "We could not authenticate this certificate",
			"No hemos podido autenticar este certificado", "No hem pogut autenticar aquest certificat"},
		{"text", "start_again", "Start again", "Volver a empezar", "Tornar a començar"},
		{"text", "report_language", "The diagnostic report is in English so that Vocdoni support can read it.",
			"El informe de diagnóstico está en inglés para que el equipo de soporte de Vocdoni pueda leerlo.",
			"L'informe de diagnòstic és en anglès perquè l'equip de suport de Vocdoni el pugui llegir."},
		{"text", "revocation_value", "{method}, checked {time}, source {source}",
			"{method}, consulta del {time} en {source}", "{method}, consulta del {time} a {source}"},
		{"messages", "never_reached", "The authentication step never reached our server.",
			"El paso de autenticación no ha llegado a nuestro servidor.", "El pas d'autenticació no ha arribat al nostre servidor."},
		{"messages", "store_full", "The service is busy. Please try again shortly.",
			"El servicio está saturado. Vuelva a intentarlo en unos instantes.", "El servei està saturat. Torni-ho a provar d'aquí a uns instants."},
		{"messages", "revoked", "The certificate has been revoked or suspended.",
			"El certificado ha sido revocado o suspendido.", "El certificat ha estat revocat o suspès."},
		{"messages", "expired", "The certificate has expired.", "El certificado ha caducado.", "El certificat ha caducat."},
		{"messages", "unsupported_media_type", "Unsupported request format.",
			"Formato de solicitud no admitido.", "Format de sol·licitud no admès."},
	} {
		for lang, want := range map[string]string{"en": c.en, "es": c.es, "ca": c.ca} {
			table := dicts[lang].Text
			if c.section == "messages" {
				table = dicts[lang].Messages
			}
			if got := table[c.key]; got != want {
				t.Errorf("i18n.js %s %s.%s = %q, want %q", lang, c.section, c.key, got, want)
			}
		}
	}
	for _, id := range []string{"view-start", "view-working", "view-success", "view-error"} {
		if !regexp.MustCompile(`<section id="` + id + `"[^>]*>`).MatchString(html) {
			t.Errorf("index.html lacks <section id=%q>", id)
		}
	}
	// Every view has exactly one h1 (axe page-has-heading-one) and no other heading level.
	for _, id := range []string{"view-start", "view-working", "view-success", "view-error"} {
		section := regexp.MustCompile(`(?s)<section id="` + id + `"[^>]*>(.*?)</section>`).FindStringSubmatch(html)
		if section == nil {
			continue // reported above
		}
		if n := strings.Count(section[1], "<h1 "); n != 1 {
			t.Errorf("%s has %d h1 elements, want exactly 1", id, n)
		}
		if strings.Contains(section[1], "<h2") {
			t.Errorf("%s contains an h2, want a single h1 heading", id)
		}
	}
	if n := strings.Count(html, `tabindex="-1"`); n < 4 {
		t.Errorf("index.html has %d focus-target headings (tabindex=-1), want at least 4", n)
	}
	if !strings.Contains(js, "group.label = t('beta');") {
		t.Errorf("app.js lacks the Beta optgroup label")
	}

	// Brand copy rules (ruling R34/R39): no en or em dash in any shipped
	// text, fixtures included; sentence case outside the three exceptions.
	for _, name := range []string{"index.html", "app.js", "i18n.js", "styles.css", "fonts/SOURCES.md"} {
		assertNoDashes(t, name, readStatic(t, name))
	}
	for _, m := range mustGlob(t, "testdata/fixtures/*.json") {
		assertNoDashes(t, m, string(readTestdata(t, strings.TrimPrefix(m, "testdata/"))))
	}
	assertNoDashes(t, "report-revoked.txt", string(readTestdata(t, "report-revoked.txt")))

	assertSentenceCase(t, "index.html", visibleText(html))
	assertSentenceCase(t, "app.js", stringLiterals(js))
	assertSentenceCase(t, "i18n.js", stringLiterals(readStatic(t, "i18n.js")))
}

func assertNoDashes(t *testing.T, name, src string) {
	t.Helper()
	if i := strings.IndexAny(src, "–—"); i >= 0 {
		t.Errorf("%s has an en or em dash character at byte %d", name, i)
	}
}

var (
	tagRE         = regexp.MustCompile(`(?s)<[^>]*>`)
	titleCasePair = regexp.MustCompile(`\b[A-Z][a-z]+ [A-Z][a-z]+\b`)
	literalRE     = regexp.MustCompile("(?s)'(?:[^'\\\\\\n]|\\\\.)*'|\"(?:[^\"\\\\\\n]|\\\\.)*\"|`[^`]*`")
)

// visibleText strips tags so the sentence-case check sees only prose.
func visibleText(html string) string {
	return tagRE.ReplaceAllString(html, "\n")
}

// stringLiterals joins the string literals of a JS source, one per line.
func stringLiterals(js string) string {
	return strings.Join(literalRE.FindAllString(js, -1), "\n")
}

// assertSentenceCase rejects Title Case word pairs. The exceptions are the
// owner's exact title, the report header that embeds it and the key name in the
// copy fallback ("Press Ctrl+C to copy", wording fixed by the brief, and its
// Spanish and Catalan forms).
func assertSentenceCase(t *testing.T, name, text string) {
	t.Helper()
	for _, allowed := range []string{
		"Vocdoni Certificate Authentication Checker",
		"Certificate Authentication Checker",
		"Press Ctrl+C to copy",
		"Pulse Ctrl+C para copiar",
		"Premi Ctrl+C per copiar",
	} {
		text = strings.ReplaceAll(text, allowed, "")
	}
	for _, m := range titleCasePair.FindAllString(text, -1) {
		t.Errorf("%s: %q is not sentence case", name, m)
	}
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil || len(m) == 0 {
		t.Fatalf("glob %s: %v (%d matches)", pattern, err, len(m))
	}
	return m
}

// dictionary is one language of i18n.js: the page texts by key, the error messages by code and the
// recovery guidance lines by name.
type dictionary struct {
	Text     map[string]string   `json:"text"`
	Messages map[string]string   `json:"messages"`
	Guidance map[string][]string `json:"guidance"`
}

var languages = []string{"en", "es", "ca"}

// readDictionaries decodes the strings of i18n.js, which are written as plain JSON, by language.
func readDictionaries(t *testing.T) map[string]dictionary {
	t.Helper()
	m := regexp.MustCompile(`(?s)\nconst CERTCHECK_STRINGS = (\{\n.*\n\});\n$`).FindStringSubmatch(readStatic(t, "i18n.js"))
	if m == nil {
		t.Fatal("i18n.js does not end with const CERTCHECK_STRINGS = {...};")
	}
	if key, err := duplicateKey(json.NewDecoder(strings.NewReader(m[1]))); err != nil || key != "" {
		t.Fatalf("i18n.js strings: duplicate key %q, error %v", key, err)
	}
	dec := json.NewDecoder(strings.NewReader(m[1]))
	dec.DisallowUnknownFields()
	var dicts map[string]dictionary
	if err := dec.Decode(&dicts); err != nil {
		t.Fatalf("i18n.js strings are not plain JSON of the expected shape: %v", err)
	}
	if got := slices.Sorted(maps.Keys(dicts)); !slices.Equal(got, []string{"ca", "en", "es"}) {
		t.Fatalf("i18n.js languages = %q, want ca, en and es", got)
	}
	return dicts
}

// duplicateKey returns a key that appears twice in one object of the next JSON value, or "". JSON
// and JavaScript both keep the last copy, so a repeated key would silently drop a text.
func duplicateKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	if tok != json.Delim('{') && tok != json.Delim('[') {
		return "", nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if tok == json.Delim('{') {
			key, err := dec.Token()
			if err != nil {
				return "", err
			}
			k, _ := key.(string)
			if seen[k] {
				return k, nil
			}
			seen[k] = true
		}
		if dup, err := duplicateKey(dec); err != nil || dup != "" {
			return dup, err
		}
	}
	_, err = dec.Token() // the closing delimiter
	return "", err
}

// flatten names every string of a dictionary: text.<key>, messages.<code> and guidance.<name>.<line>.
func flatten(d dictionary) map[string]string {
	out := map[string]string{}
	for k, v := range d.Text {
		out["text."+k] = v
	}
	for k, v := range d.Messages {
		out["messages."+k] = v
	}
	for k, lines := range d.Guidance {
		if len(lines) == 0 {
			out["guidance."+k] = ""
		}
		for i, v := range lines {
			out[fmt.Sprintf("guidance.%s.%d", k, i)] = v
		}
	}
	return out
}

// TestI18nDictionaries covers AC1. The three languages have exactly the same texts, none of them
// empty, with the same {placeholders}, and the Spanish and Catalan ones are translated. Every key
// index.html and app.js name exists, index.html holds the English text of each, and no text is
// unused.
func TestI18nDictionaries(t *testing.T) {
	dicts := readDictionaries(t)
	en := flatten(dicts["en"])
	placeholder := regexp.MustCompile(`\{[a-z]+\}`)
	english := regexp.MustCompile(`(?i)\b(?:the|your|please|certificate|browser|could|again)\b`)
	sameAsEnglish := map[string]bool{"es text.beta": true, "ca text.beta": true}
	for _, lang := range languages {
		got := flatten(dicts[lang])
		for _, key := range slices.Sorted(maps.Keys(en)) {
			if _, ok := got[key]; !ok {
				t.Errorf("i18n.js %s lacks %s", lang, key)
			}
		}
		for _, key := range slices.Sorted(maps.Keys(got)) {
			v := got[key]
			if strings.TrimSpace(v) == "" {
				t.Errorf("i18n.js %s %s is empty", lang, key)
			}
			want, ok := en[key]
			if !ok {
				t.Errorf("i18n.js %s has %s, which en lacks", lang, key)
				continue
			}
			if lang == "en" {
				continue
			}
			g := slices.Sorted(slices.Values(placeholder.FindAllString(v, -1)))
			if w := slices.Sorted(slices.Values(placeholder.FindAllString(want, -1))); !slices.Equal(g, w) {
				t.Errorf("i18n.js %s %s placeholders = %q, want %q", lang, key, g, w)
			}
			if v == want && !sameAsEnglish[lang+" "+key] {
				t.Errorf("i18n.js %s %s = %q is the English text", lang, key, v)
			}
			if m := english.FindString(v); m != "" {
				t.Errorf("i18n.js %s %s = %q has the English word %q", lang, key, v, m)
			}
		}
	}

	// index.html: every data-i18n element holds only the English text of its key.
	used := map[string]bool{}
	html := readStatic(t, "index.html")
	tagged := regexp.MustCompile(`<[a-z0-9]+\b[^>]*\sdata-i18n="([^"]*)"[^>]*>([^<]*)</`).FindAllStringSubmatch(html, -1)
	if n := strings.Count(html, "data-i18n="); n == 0 || n != len(tagged) {
		t.Errorf("index.html has %d data-i18n attributes and %d plain-text elements that carry one", n, len(tagged))
	}
	for _, m := range tagged {
		used[m[1]] = true
		if want, ok := dicts["en"].Text[m[1]]; !ok {
			t.Errorf("index.html data-i18n=%q is not an i18n.js text", m[1])
		} else if m[2] != want {
			t.Errorf("index.html data-i18n=%q holds %q, want the en text %q", m[1], m[2], want)
		}
	}

	// app.js: the keys it renders, and the guidance names its code tables list.
	js := readStatic(t, "app.js")
	for _, m := range regexp.MustCompile(`(?:\b(?:t|format|showWorking)\(|copyNote = )'([a-z_]+)'`).FindAllStringSubmatch(js, -1) {
		used[m[1]] = true
		if _, ok := dicts["en"].Text[m[1]]; !ok {
			t.Errorf("app.js renders the text %q, which i18n.js lacks", m[1])
		}
	}
	for _, key := range slices.Sorted(maps.Keys(dicts["en"].Text)) {
		if !used[key] {
			t.Errorf("i18n.js text %q is not used by index.html or app.js", key)
		}
	}
	tables := regexp.MustCompile(`(?s)\n  const TEMPORARY = .*?\n  const DEFAULT_GUIDANCE = [^\n]*\n`).FindString(js)
	if tables == "" {
		t.Fatal("app.js has no guidance tables from TEMPORARY to DEFAULT_GUIDANCE")
	}
	names := map[string]bool{}
	for _, list := range regexp.MustCompile(`\[([^\]]*)\]`).FindAllStringSubmatch(tables, -1) {
		for _, m := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(list[1], -1) {
			names[m[1]] = true
		}
	}
	if got, want := slices.Sorted(maps.Keys(names)), slices.Sorted(maps.Keys(dicts["en"].Guidance)); !slices.Equal(got, want) {
		t.Errorf("app.js guidance names = %q, want the i18n.js guidance %q", got, want)
	}

	// The DNIe entry's English parts that app.js replaces are the ones the API serves (AC5).
	providers := string(readTestdata(t, filepath.Join("..", "..", "..", "testdata", "golden", "providers.json")))
	for constant, key := range map[string]string{"DNIE_QUALIFIER": "dnie_qualifier", "DNIE_CLAUSE": "dnie_clause"} {
		m := regexp.MustCompile(`\n  const ` + constant + ` = '([^']+)';`).FindStringSubmatch(js)
		if m == nil {
			t.Errorf("app.js has no %s", constant)
			continue
		}
		if m[1] != dicts["en"].Text[key] || !strings.Contains(providers, m[1]) {
			t.Errorf("app.js %s = %q, want the en text %q and a part of the served providers", constant, m[1], dicts["en"].Text[key])
		}
	}
}

// TestI18nErrorCodes covers AC2. Every code the API can return (the server's messages table and the
// library's ErrorCodes) and every code app.js produces has a message in each language. The English
// message is the server's own text, so the English page reads as before.
func TestI18nErrorCodes(t *testing.T) {
	dicts := readDictionaries(t)
	library := libraryCodes(t)
	server := serverMessages(t, library)
	js := readStatic(t, "app.js")
	m := regexp.MustCompile(`\n  const CLIENT_CODES = \[([^\]]*)\];`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("app.js has no CLIENT_CODES list")
	}
	codes := map[string]bool{}
	client := map[string]bool{}
	for _, c := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(m[1], -1) {
		client[c[1]], codes[c[1]] = true, true
	}
	// The codes app.js hands to the error views itself are client codes.
	produced := regexp.MustCompile(`\bcode: '([a-z_]+)'`).FindAllStringSubmatch(js, -1)
	produced = append(produced, regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(jsFunc(t, js, "failureCode"), -1)...)
	for _, c := range produced {
		if !client[c[1]] {
			t.Errorf("app.js produces the code %q, which CLIENT_CODES lacks", c[1])
		}
	}
	for _, code := range library {
		codes[code] = true
	}
	for code := range server {
		codes[code] = true
	}
	for _, lang := range languages {
		for _, code := range slices.Sorted(maps.Keys(codes)) {
			if dicts[lang].Messages[code] == "" {
				t.Errorf("i18n.js %s has no message for the code %q", lang, code)
			}
		}
		for code := range dicts[lang].Messages {
			if !codes[code] {
				t.Errorf("i18n.js %s has a message for %q, which nothing produces", lang, code)
			}
		}
	}
	for code, msg := range server {
		if got := dicts["en"].Messages[code]; got != msg {
			t.Errorf("i18n.js en message for %q = %q, want the server's %q", code, got, msg)
		}
	}
}

// libraryCodes returns the root package's ErrorCode constants by name, read from types.go.
func libraryCodes(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "types.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		if typ, ok := spec.Type.(*ast.Ident); !ok || typ.Name != "ErrorCode" || len(spec.Values) != len(spec.Names) {
			return true
		}
		for i, name := range spec.Names {
			if lit, ok := spec.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				codes[name.Name], _ = strconv.Unquote(lit.Value)
			}
		}
		return true
	})
	if codes["CodeNoCertificate"] != "no_certificate" || codes["CodeInternal"] != "internal" {
		t.Fatalf("types.go ErrorCodes read as %v", codes)
	}
	return codes
}

// serverMessages returns the server's code to English message table, read from the source of
// ../internal/server/api.go, where it is unexported. library resolves string(certcheck.CodeX).
func serverMessages(t *testing.T, library map[string]string) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "internal", "server", "api.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var table *ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok && len(spec.Names) == 1 && spec.Names[0].Name == "messages" && len(spec.Values) == 1 {
			table, _ = spec.Values[0].(*ast.CompositeLit)
		}
		return table == nil
	})
	if table == nil {
		t.Fatal("api.go has no messages table")
	}
	out := map[string]string{}
	for i, elt := range table.Elts {
		var key, value string
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			switch k := kv.Key.(type) {
			case *ast.BasicLit:
				key, _ = strconv.Unquote(k.Value)
			case *ast.CallExpr: // string(certcheck.CodeX)
				if len(k.Args) == 1 {
					if sel, ok := k.Args[0].(*ast.SelectorExpr); ok {
						key = library[sel.Sel.Name]
					}
				}
			}
			if lit, ok := kv.Value.(*ast.BasicLit); ok {
				value, _ = strconv.Unquote(lit.Value)
			}
		}
		if key == "" || value == "" {
			t.Fatalf("api.go messages entry %d: cannot read its code or message", i)
		}
		out[key] = value
	}
	return out
}

// TestAppJSLanguage covers AC3, AC4 and AC7 in the source; TestBrowser runs them. A saved choice
// comes first, then the browser's languages in order, then Spanish. Every code from storage or the
// browser is checked against the three languages, storage errors are tolerated, and a switch
// re-renders in place and saves the choice.
func TestAppJSLanguage(t *testing.T) {
	js := readStatic(t, "app.js")
	for _, want := range []string{
		"const LANG_KEY = 'certcheck.lang';",
		"const LANGS = ['en', 'es', 'ca'];",
		"const FALLBACK_LANG = 'es';",
		"const SPANISH_TOO = ['gl', 'eu', 'ast', 'an', 'oc'];",
		"$('language').addEventListener('change', changeLanguage);",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %q", want)
		}
	}
	inOrder := func(fn string, steps ...string) {
		t.Helper()
		src, at := jsFunc(t, js, fn), 0
		for _, step := range steps {
			i := strings.Index(src[at:], step)
			if i < 0 {
				t.Errorf("%s() lacks %q after the previous step", fn, step)
				return
			}
			at += i + len(step)
		}
	}
	inOrder("detectLanguage", "readSavedLanguage()", "isLanguage(saved)", "navigator.languages", "[navigator.language]", "languageOf(", "return FALLBACK_LANG;")
	inOrder("languageOf", "toLowerCase()", "isLanguage(", "SPANISH_TOO")
	inOrder("readSavedLanguage", "try {", "localStorage.getItem(LANG_KEY)", "} catch (")
	inOrder("saveLanguage", "try {", "localStorage.setItem(LANG_KEY", "} catch (")
	inOrder("useLanguage", "lookup(STRINGS, code)", "document.documentElement.lang = code;", "document.title = t('title');", ".textContent = t(")
	inOrder("changeLanguage", "isLanguage(code)", "saveLanguage(code)", "useLanguage(code)", "renderProviders()", "} catch (", "showFatal()")
	inOrder("init", "history.replaceState(null, '', '/');", "useLanguage(detectLanguage());",
		"$('language').closest('.language').hidden = false;", "await ")
	if strings.Contains(jsFunc(t, js, "changeLanguage"), "reload") {
		t.Error("changeLanguage() reloads; a switch re-renders in place")
	}
}

func TestFontSources(t *testing.T) {
	sources := readStatic(t, "fonts/SOURCES.md")
	for _, want := range []string{"github.com/vocdoni/vocdoni.io", "public/fonts/files", "undercasetype/Fraunces", "marcologous/hanken-grotesk"} {
		if !strings.Contains(sources, want) {
			t.Errorf("fonts/SOURCES.md does not record %q", want)
		}
	}

	// Lines of the form "<sha256>  <path relative to web/static>".
	recorded := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^([0-9a-f]{64})  (\S+)$`).FindAllStringSubmatch(sources, -1) {
		recorded[m[2]] = m[1]
	}

	hashed := []string{
		"fonts/fraunces-latin-full-normal.woff2",
		"fonts/fraunces-latin-ext-full-normal.woff2",
		"fonts/hanken-grotesk-latin-wght-normal.woff2",
		"fonts/hanken-grotesk-latin-ext-wght-normal.woff2",
		"fonts/OFL-Fraunces.txt",
		"fonts/OFL-HankenGrotesk.txt",
		"favicon.ico",
	}
	for _, name := range hashed {
		want, ok := recorded[name]
		if !ok {
			t.Errorf("fonts/SOURCES.md records no SHA-256 for %s", name)
			continue
		}
		sum := sha256.Sum256([]byte(readStatic(t, name)))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s sha256 = %s, want %s (fonts/SOURCES.md)", name, got, want)
		}
	}

	// The brand-kit digests recorded by ruling R34.
	for name, prefix := range map[string]string{
		"fonts/fraunces-latin-full-normal.woff2":           "7e744849",
		"fonts/fraunces-latin-ext-full-normal.woff2":       "e9521563",
		"fonts/hanken-grotesk-latin-wght-normal.woff2":     "e9201edd",
		"fonts/hanken-grotesk-latin-ext-wght-normal.woff2": "768af292",
	} {
		if got := recorded[name]; !strings.HasPrefix(got, prefix) {
			t.Errorf("%s recorded digest = %s, want prefix %s (ruling R34)", name, got, prefix)
		}
	}

	for _, name := range []string{"fonts/OFL-Fraunces.txt", "fonts/OFL-HankenGrotesk.txt"} {
		if txt := readStatic(t, name); !strings.Contains(txt, "SIL OPEN FONT LICENSE Version 1.1") {
			t.Errorf("%s is not the SIL OFL 1.1 text", name)
		}
	}
}

// Contract types, declared from the binding JSON key contract (preflight F4,
// ruling R38). There is deliberately no certcheck import.
type (
	providerEntry struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Beta        bool   `json:"beta"`
	}
	providerRef struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	profileRef struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		HolderRole string `json:"holderRole"`
	}
	document struct {
		Type    string `json:"type"`
		Country string `json:"country"`
		Number  string `json:"number"`
		Raw     string `json:"raw"`
		Source  string `json:"source"`
	}
	identity struct {
		Document      document          `json:"document"`
		GivenNames    string            `json:"givenNames"`
		Surnames      string            `json:"surnames"`
		FirstSurname  string            `json:"firstSurname"`
		SecondSurname string            `json:"secondSurname"`
		FullName      string            `json:"fullName"`
		BirthDate     *string           `json:"birthDate"`
		Sources       map[string]string `json:"sources"`
	}
	organization struct {
		Name       string `json:"name"`
		Identifier string `json:"identifier"`
	}
	certificateInfo struct {
		Subject      string `json:"subject"`
		Issuer       string `json:"issuer"`
		SerialHex    string `json:"serialHex"`
		NotBefore    string `json:"notBefore"`
		NotAfter     string `json:"notAfter"`
		SHA256       string `json:"sha256"`
		KeyAlgorithm string `json:"keyAlgorithm"`
	}
	revocationInfo struct {
		Status     string  `json:"status"`
		Method     string  `json:"method"`
		CheckedAt  string  `json:"checkedAt"`
		ThisUpdate string  `json:"thisUpdate"`
		NextUpdate *string `json:"nextUpdate"`
		Source     string  `json:"source"`
	}
	tlsInfo struct {
		Version                    string `json:"version"`
		CipherSuite                string `json:"cipherSuite"`
		SNI                        string `json:"sni"`
		ClientCertificatePresented bool   `json:"clientCertificatePresented"`
		ChainLength                int    `json:"chainLength"`
	}
	certificateDetails struct {
		Subject            string   `json:"subject"`
		Issuer             string   `json:"issuer"`
		SerialHex          string   `json:"serialHex"`
		NotBefore          string   `json:"notBefore"`
		NotAfter           string   `json:"notAfter"`
		SHA256             string   `json:"sha256"`
		KeyAlgorithm       string   `json:"keyAlgorithm"`
		SignatureAlgorithm string   `json:"signatureAlgorithm"`
		KeyUsage           []string `json:"keyUsage"`
		ExtKeyUsage        []string `json:"extKeyUsage"`
		PolicyOIDs         []string `json:"policyOids"`
		CriticalExtensions []string `json:"criticalExtensions"`
		OCSPURLs           []string `json:"ocspUrls"`
		CAIssuerURLs       []string `json:"caIssuerUrls"`
		CDPURLs            []string `json:"cdpUrls"`
	}
	chainEntry struct {
		Subject string `json:"subject"`
		Issuer  string `json:"issuer"`
	}
	candidate struct {
		ProfileID string `json:"profileId"`
		Result    string `json:"result"`
	}
	attempt struct {
		Method           string  `json:"method"`
		URL              string  `json:"url"`
		HTTPStatus       int     `json:"httpStatus"`
		DurationMS       int64   `json:"durationMs"`
		Outcome          string  `json:"outcome"`
		Detail           string  `json:"detail"`
		FromCache        bool    `json:"fromCache"`
		ProducedAt       *string `json:"producedAt"`
		ThisUpdate       *string `json:"thisUpdate"`
		NextUpdate       *string `json:"nextUpdate"`
		ResponderSubject string  `json:"responderSubject"`
		NonceSent        bool    `json:"nonceSent"`
		NonceEchoed      bool    `json:"nonceEchoed"`
	}
	diagnostics struct {
		DiagnosticID       string              `json:"diagnosticId"`
		Time               string              `json:"time"`
		ServerVersion      string              `json:"serverVersion"`
		Provider           string              `json:"provider"`
		FailedStep         string              `json:"failedStep"`
		Code               string              `json:"code"`
		TechnicalDetail    string              `json:"technicalDetail"`
		TLS                *tlsInfo            `json:"tls"`
		Certificate        *certificateDetails `json:"certificate"`
		Chain              []chainEntry        `json:"chain"`
		ProfileCandidates  []candidate         `json:"profileCandidates"`
		RevocationAttempts []attempt           `json:"revocationAttempts"`
	}
	result struct {
		Provider     providerRef     `json:"provider"`
		Profile      profileRef      `json:"profile"`
		Identity     identity        `json:"identity"`
		Organization *organization   `json:"organization"`
		Certificate  certificateInfo `json:"certificate"`
		Revocation   revocationInfo  `json:"revocation"`
		ValidatedAt  string          `json:"validatedAt"`
		Diagnostics  diagnostics     `json:"diagnostics"`
	}
	apiError struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	}
	// redeemBody is the union of the success and error envelopes. The error
	// envelope keys "error" and "diagnostics" are absent from a success body
	// and vice versa, hence the separate key-set check below.
	redeemBody struct {
		Status      string       `json:"status"`
		Result      *result      `json:"result,omitempty"`
		Error       *apiError    `json:"error,omitempty"`
		Diagnostics *diagnostics `json:"diagnostics,omitempty"`
	}
	createBody struct {
		AuthURL   string `json:"authUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	currentBody struct {
		Status    string  `json:"status"`
		Provider  string  `json:"provider"`
		CreatedAt *string `json:"createdAt"`
		AuthHost  string  `json:"authHost"`
		AuthPort  int     `json:"authPort"`
	}
)

// strictDecode decodes with DisallowUnknownFields and then re-marshals the
// value: the round trip must equal the original document, which makes the
// fixture's key set exactly the key set Go marshals (no missing key either).
func strictDecode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var v T
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.More() {
		t.Fatalf("trailing data after the JSON value")
	}
	again, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("unmarshal original: %v", err)
	}
	if err := json.Unmarshal(again, &got); err != nil {
		t.Fatalf("unmarshal round trip: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("key set or null/zero shape differs from the contract:\n got %s\nwant %s", again, raw)
	}
	return v
}

func isRFC3339UTC(s string) bool {
	tm, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && strings.HasSuffix(s, "Z") && tm.UTC().Equal(tm)
}

func assertTimes(t *testing.T, name string, values ...string) {
	t.Helper()
	for _, v := range values {
		if !isRFC3339UTC(v) {
			t.Errorf("%s: %q is not an RFC 3339 UTC timestamp", name, v)
		}
	}
}

func optTimes(p *string) []string {
	if p == nil {
		return nil
	}
	return []string{*p}
}

func TestFixturesMatchContract(t *testing.T) {
	t.Run("providers", func(t *testing.T) {
		got := strictDecode[[]providerEntry](t, readTestdata(t, "fixtures/providers.json"))
		wantNames := []string{
			"FNMT - Persona Física", "idCAT Certificat", "ACCV - Ciudadano (software)", "DIGITEL ON - Ciudadano",
			"Bewor - Persona Física", "Sectigo - Ciudadano",
			"FNMT - Representante", "FNMT - Empleado Público", "Firmaprofesional", "ANF AC", "Uanataca", "SIGNE",
			"Lleidanet / inDenova", "DNIe (requires card reader)",
		}
		wantIDs := []string{
			"fnmt", "idcat", "accv", "digitel", "bewor", "sectigo",
			"fnmt-representative", "fnmt-employee", "firmaprofesional", "anf", "uanataca", "signe", "lleidanet", "dnie",
		}
		var names, ids []string
		for i, p := range got {
			names, ids = append(names, p.Name), append(ids, p.ID)
			if p.Beta != (i >= 6) {
				t.Errorf("provider %s beta = %v, want %v", p.ID, p.Beta, i >= 6)
			}
			if p.Description == "" {
				t.Errorf("provider %s has no description", p.ID)
			}
		}
		if !slices.Equal(names, wantNames) {
			t.Errorf("provider names = %q, want %q", names, wantNames)
		}
		if !slices.Equal(ids, wantIDs) {
			t.Errorf("provider ids = %q, want %q", ids, wantIDs)
		}
	})

	t.Run("create", func(t *testing.T) {
		got := strictDecode[createBody](t, readTestdata(t, "fixtures/create.json"))
		assertTimes(t, "create.json", got.ExpiresAt)
		u, err := url.Parse(got.AuthURL)
		if err != nil {
			t.Fatalf("authUrl %q: %v", got.AuthURL, err)
		}
		if u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Path != "/__auth" || u.Query().Get("state") != "x" {
			t.Errorf("authUrl = %q, want http://127.0.0.1:<port>/__auth?state=x", got.AuthURL)
		}
	})

	t.Run("current", func(t *testing.T) {
		for name, want := range map[string]string{"current-none.json": "none", "current-pending.json": "pending"} {
			got := strictDecode[currentBody](t, readTestdata(t, "fixtures/"+name))
			if got.Status != want {
				t.Errorf("%s status = %q, want %q", name, got.Status, want)
			}
			if got.AuthPort == 0 {
				t.Errorf("%s authPort = 0, want an integer port", name)
			}
			if want == "none" && (got.CreatedAt != nil || got.Provider != "" || got.AuthHost != "") {
				t.Errorf("%s: a none status carries createdAt/provider/authHost: %+v", name, got)
			}
			if want == "pending" {
				if got.CreatedAt == nil || got.Provider == "" || got.AuthHost == "" {
					t.Errorf("%s: a pending status needs createdAt, provider and authHost: %+v", name, got)
				} else {
					assertTimes(t, name, *got.CreatedAt)
				}
			}
		}
	})

	t.Run("redeem", func(t *testing.T) {
		matches := mustGlob(t, "testdata/fixtures/redeem-*.json")
		want := []string{"redeem-error-no-certificate", "redeem-error-revoked", "redeem-invalid", "redeem-success-dnie", "redeem-success"}
		var have []string
		for _, m := range matches {
			have = append(have, strings.TrimSuffix(filepath.Base(m), ".json"))
		}
		slices.Sort(have)
		slices.Sort(want)
		if !slices.Equal(have, want) {
			t.Fatalf("redeem fixtures = %q, want %q", have, want)
		}
		for _, name := range have {
			raw := readTestdata(t, "fixtures/"+name+".json")
			t.Run(name, func(t *testing.T) {
				got := strictDecode[redeemBody](t, raw)
				switch got.Status {
				case "success":
					if got.Result == nil || got.Error != nil || got.Diagnostics != nil {
						t.Fatalf("success body shape: result=%v error=%v diagnostics=%v", got.Result != nil, got.Error != nil, got.Diagnostics != nil)
					}
					checkSuccess(t, name, *got.Result)
				case "error":
					if got.Result != nil || got.Error == nil || got.Diagnostics == nil {
						t.Fatalf("error body shape: result=%v error=%v diagnostics=%v", got.Result != nil, got.Error != nil, got.Diagnostics != nil)
					}
					if got.Error.Message == "" || got.Error.Code != got.Diagnostics.Code {
						t.Errorf("error %+v vs diagnostics code %q", got.Error, got.Diagnostics.Code)
					}
					checkErrorDiagnostics(t, name, *got.Error, *got.Diagnostics)
				default:
					t.Fatalf("status = %q, want success or error", got.Status)
				}
			})
		}
	})
}

func checkSuccess(t *testing.T, name string, r result) {
	t.Helper()
	id := r.Identity
	if id.Document.Number != "12345679S" || id.Document.Type != "DNI" || id.Document.Country != "ES" {
		t.Errorf("%s document = %+v, want the synthetic DNI 12345679S", name, id.Document)
	}
	if id.FullName != "JUAN GARCÍA LÓPEZ" || id.GivenNames != "JUAN" || id.Surnames != "GARCÍA LÓPEZ" {
		t.Errorf("%s names = %q / %q / %q, want the synthetic JUAN GARCÍA LÓPEZ", name, id.FullName, id.GivenNames, id.Surnames)
	}
	if r.Revocation.Status != "good" || (r.Revocation.Method != "ocsp" && r.Revocation.Method != "crl") {
		t.Errorf("%s revocation = %+v, want a good ocsp or crl result", name, r.Revocation)
	}
	if d := r.Diagnostics; d.FailedStep != "" || d.Code != "" || d.TechnicalDetail != "" {
		t.Errorf("%s: a success Result needs empty failedStep/code/technicalDetail, got %q/%q/%q", name, d.FailedStep, d.Code, d.TechnicalDetail)
	}
	assertTimes(t, name, r.Certificate.NotBefore, r.Certificate.NotAfter, r.Revocation.CheckedAt, r.Revocation.ThisUpdate, r.ValidatedAt, r.Diagnostics.Time)
	assertTimes(t, name, optTimes(r.Revocation.NextUpdate)...)
	if id.BirthDate != nil && !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(*id.BirthDate) {
		t.Errorf("%s birthDate = %q, want YYYY-MM-DD", name, *id.BirthDate)
	}
	switch name {
	case "redeem-success":
		if id.BirthDate != nil || id.FirstSurname != "" || id.SecondSurname != "" || r.Organization != nil {
			t.Errorf("%s must be the FNMT natural person without birth date or split surnames: %+v", name, id)
		}
		if r.Provider.ID != "fnmt" || r.Profile.HolderRole != "natural_person" {
			t.Errorf("%s provider/role = %s/%s, want fnmt/natural_person", name, r.Provider.ID, r.Profile.HolderRole)
		}
	case "redeem-success-dnie":
		if id.BirthDate == nil || id.FirstSurname == "" || id.SecondSurname == "" {
			t.Errorf("%s must carry birthDate and first/second surnames: %+v", name, id)
		}
		if r.Provider.ID != "dnie" {
			t.Errorf("%s provider = %s, want dnie", name, r.Provider.ID)
		}
	}
}

func checkErrorDiagnostics(t *testing.T, name string, e apiError, d diagnostics) {
	t.Helper()
	assertTimes(t, name, d.Time)
	if d.DiagnosticID == "" || d.ServerVersion == "" {
		t.Errorf("%s: diagnosticId %q and serverVersion %q must be set", name, d.DiagnosticID, d.ServerVersion)
	}
	switch name {
	case "redeem-invalid":
		if e.Code != "invalid_or_expired" || e.Retryable {
			t.Errorf("%s error = %+v, want invalid_or_expired, not retryable", name, e)
		}
		// Minimal diagnostics: only these five fields are non-empty.
		rest := d
		rest.DiagnosticID, rest.Time, rest.ServerVersion, rest.Code, rest.TechnicalDetail = "", "", "", "", ""
		if !reflect.DeepEqual(rest, diagnostics{}) {
			t.Errorf("%s diagnostics beyond the minimal five fields: %+v", name, rest)
		}
		if d.TechnicalDetail == "" {
			t.Errorf("%s technicalDetail is empty", name)
		}
	case "redeem-error-revoked":
		if e.Code != "revoked" || d.FailedStep != "revocation" {
			t.Errorf("%s code/step = %s/%s, want revoked/revocation", name, e.Code, d.FailedStep)
		}
		if len(d.RevocationAttempts) != 2 {
			t.Errorf("%s has %d revocation attempts, want 2", name, len(d.RevocationAttempts))
		}
		if d.TLS == nil || d.Certificate == nil || len(d.Chain) == 0 || len(d.ProfileCandidates) == 0 {
			t.Errorf("%s must carry full diagnostics (tls, certificate, chain, candidates)", name)
		}
		for _, a := range d.RevocationAttempts {
			assertTimes(t, name, optTimes(a.ProducedAt)...)
			assertTimes(t, name, optTimes(a.ThisUpdate)...)
			assertTimes(t, name, optTimes(a.NextUpdate)...)
		}
		if d.Certificate != nil {
			assertTimes(t, name, d.Certificate.NotBefore, d.Certificate.NotAfter)
		}
	case "redeem-error-no-certificate":
		if e.Code != "no_certificate" || d.TLS == nil || d.TLS.ClientCertificatePresented || d.Certificate != nil {
			t.Errorf("%s: want no_certificate with a TLS block, no client certificate and no certificate details: %+v %+v", name, e, d.TLS)
		}
	}
}

// referenceReport renders the plain-text report exactly as app.js does, minus
// the Page and User agent lines (they depend on the browser). It exists so the
// golden file is checked by go test as well as by the Playwright run.
func referenceReport(e apiError, d diagnostics) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	list := func(v []string) string {
		if len(v) == 0 {
			return "none"
		}
		return strings.Join(v, ", ")
	}
	orNone := func(p *string) string {
		if p == nil || *p == "" {
			return "none"
		}
		return *p
	}
	yesNo := func(v bool, yes, no string) string {
		if v {
			return yes
		}
		return no
	}
	optional := func(label, v string) {
		if v != "" {
			line("%s: %s", label, v)
		}
	}

	line("Vocdoni Certificate Authentication Checker - diagnostic report")
	line("Diagnostic ID: %s", d.DiagnosticID)
	line("Time: %s", d.Time)
	line("Server version: %s", d.ServerVersion)
	line("")
	line("Result: error %s - %s", e.Code, e.Message)
	optional("Failed step", d.FailedStep)
	optional("Provider", d.Provider)
	optional("Technical detail", d.TechnicalDetail)
	if d.TLS != nil {
		line("TLS: %s %s SNI=%s client certificate=%s chain length=%d", d.TLS.Version, d.TLS.CipherSuite, d.TLS.SNI,
			yesNo(d.TLS.ClientCertificatePresented, "yes", "no"), d.TLS.ChainLength)
	}
	if c := d.Certificate; c != nil {
		line("Certificate:")
		line("  Subject: %s", c.Subject)
		line("  Issuer: %s", c.Issuer)
		line("  Serial: %s", c.SerialHex)
		line("  Valid: %s to %s", c.NotBefore, c.NotAfter)
		line("  SHA-256: %s", c.SHA256)
		line("  Key: %s   Signature: %s", c.KeyAlgorithm, c.SignatureAlgorithm)
		line("  Key usage: %s   Extended key usage: %s", list(c.KeyUsage), list(c.ExtKeyUsage))
		line("  Policies: %s", list(c.PolicyOIDs))
		line("  Critical extensions: %s", list(c.CriticalExtensions))
		line("  OCSP: %s   CA issuers: %s   CRL: %s", list(c.OCSPURLs), list(c.CAIssuerURLs), list(c.CDPURLs))
	}
	if len(d.Chain) > 0 {
		line("Chain received:")
		for i, c := range d.Chain {
			line("  [%d] %s / issued by %s", i, c.Subject, c.Issuer)
		}
	}
	if len(d.ProfileCandidates) > 0 {
		line("Profile candidates:")
		for _, c := range d.ProfileCandidates {
			line("  %s: %s", c.ProfileID, c.Result)
		}
	}
	if len(d.RevocationAttempts) > 0 {
		line("Revocation attempts:")
		for _, a := range d.RevocationAttempts {
			parts := []string{a.Method, a.URL, fmt.Sprintf("HTTP %d", a.HTTPStatus), fmt.Sprintf("%d ms", a.DurationMS), a.Outcome}
			if a.Detail != "" {
				parts = append(parts, a.Detail)
			}
			parts = append(parts,
				"thisUpdate="+orNone(a.ThisUpdate),
				"nextUpdate="+orNone(a.NextUpdate),
				"responder="+cmp.Or(a.ResponderSubject, "none"),
				"nonce="+yesNo(a.NonceSent, "sent", "not sent")+"/"+yesNo(a.NonceEchoed, "echoed", "not echoed"))
			if a.FromCache {
				parts = append(parts, "from cache")
			}
			line("  %s", strings.Join(parts, " "))
		}
	}
	return b.String()
}

func TestReportGolden(t *testing.T) {
	got := strictDecode[redeemBody](t, readTestdata(t, "fixtures/redeem-error-revoked.json"))
	if got.Error == nil || got.Diagnostics == nil {
		t.Fatal("redeem-error-revoked.json has no error or diagnostics")
	}
	want := string(readTestdata(t, "report-revoked.txt"))
	if report := referenceReport(*got.Error, *got.Diagnostics); report != want {
		t.Errorf("report-revoked.txt does not match the report rendered from redeem-error-revoked.json:\n got:\n%s\nwant:\n%s", report, want)
	}
	for _, line := range strings.Split(want, "\n") {
		if strings.HasPrefix(line, "Page: ") || strings.HasPrefix(line, "User agent: ") {
			t.Errorf("report-revoked.txt must not contain the browser-dependent line %q", line)
		}
	}
}
