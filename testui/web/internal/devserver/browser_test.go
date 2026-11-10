//go:build browser

package main

import (
	"bytes"
	"context"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/testui/web"
)

const (
	msgGeneric     = "Something went wrong."
	msgBadResponse = "The server sent a reply this page could not understand."
	msgLinkInvalid = "This authentication link is no longer valid. Please start again."
	msgRevoked     = "The certificate has been revoked or suspended."

	startAgain   = `>Start again</button>`
	authenticate = `<button id="authenticate" class="pill primary" type="button" data-i18n="authenticate">Authenticate</button>` // enabled

	// The diagnostic ID line of redeem-error-revoked.json's report, which stays in English.
	revokedReport = "Diagnostic ID: 7b1e4c0a92d84f36a5c1e0d3b8f26a49"
)

// malformed are redeem replies that the real API never sends. The mock serves each with HTTP 200
// for #code=<name>; redeem-server-error.json is a directory, which the mock answers with a plain
// text HTTP 500.
var malformed = map[string]string{
	"redeem-empty.json":           "",
	"redeem-html.json":            "<!doctype html><title>Bad gateway</title>\n",
	"redeem-array.json":           "[]\n",
	"redeem-string.json":          `"success"` + "\n",
	"redeem-chain-null.json":      `{"status":"error","error":{"code":"revoked","message":"x"},"diagnostics":{"chain":[null]}}` + "\n",
	"redeem-identity-string.json": `{"status":"success","result":{"identity":"JUAN"}}` + "\n",
}

// neverJS answers the auth step with 204, so the browser stays on the working view, and presses
// Authenticate once the providers are in; then it calls next().
const neverJS = `document.cookie = 'mock-result=never; path=/';
document.cookie = 'mock-current=pending; path=/';
const poll = setInterval(() => {
  const button = document.getElementById('authenticate');
  if (button.disabled) {
    return;
  }
  clearInterval(poll);
  button.click();
  setTimeout(next, 2000);
}, 50);
`

// testPages are copies of index.html with one more same-origin script, served at
// /__test/<name>.html. A "before" script runs ahead of app.js and removes a browser API, as an
// older browser lacks it; the others run after app.js and drive the page.
var testPages = map[string]struct {
	before bool
	js     string
}{
	"no-hasown":          {true, "delete Object.hasOwn;\n"},                     // Chrome < 93, Firefox < 92, Safari < 15.4
	"no-replacechildren": {true, "delete Element.prototype.replaceChildren;\n"}, // the error view throws while rendering
	"never":              {false, neverJS + "function next() {}\n"},
	"never-start-again":  {false, neverJS + "function next() { document.getElementById('cancel').click(); }\n"},
	"saved-ca":           {true, "localStorage.setItem('certcheck.lang', 'ca');\n"},
	"saved-bad":          {true, "localStorage.setItem('certcheck.lang', '__proto__');\n"},
	"switch-ca":          {false, switchJS("")},
	"switch-ca-broken":   {false, switchJS("delete Element.prototype.replaceChildren;")}, // the renderers throw
	"no-strings":         {false, ""},                                                    // serves index.html with i18n.js swapped for a 404
}

// stringsTag loads the dictionaries; the no-strings page points it at a missing file instead, as a
// dropped request would leave the page.
const stringsTag = `<script src="/i18n.js" defer></script>`

// switchJS chooses Catalan in the language selector, as a user would, once the page shows a view
// other than the working one. prepare runs just before the switch.
func switchJS(prepare string) string {
	return `const poll = setInterval(() => {
  const shown = document.querySelector('section[id^="view-"]:not([hidden])');
  if (!shown || shown.id === 'view-working') {
    return;
  }
  clearInterval(poll);
  ` + prepare + `
  const select = document.getElementById('language');
  select.value = 'ca';
  select.dispatchEvent(new Event('change'));
}, 50);
`
}

// TestBrowser covers U14-FABLE-4: headless Chrome loads the UI from the devserver and the test
// checks the view the page settles on. The cases are fragment codes that name Object.prototype
// members or nothing at all, the malformed replies the mock can serve, a browser without
// Object.hasOwn (U14-FABLE-1), an error view that throws (the guard() fallback) and an auth step
// that never arrives (U14-FABLE-2); they run in English. The language cases set the browser's
// languages, a saved choice or a switch in the selector, and check the language the page settles
// on. It runs only with -tags browser; CHROME names the browser binary when none of
// google-chrome, google-chrome-stable, chromium or chromium-browser is on PATH.
func TestBrowser(t *testing.T) {
	chrome := findChrome(t)
	base := startDevserver(t)
	cases := []struct {
		name, path string
		view       string   // the only visible view
		contains   []string // text of that view
	}{
		{"fragment __proto__", "/#error=__proto__", "error", []string{msgGeneric, startAgain}},
		{"fragment constructor", "/#error=constructor", "error", []string{msgGeneric, startAgain}},
		{"fragment unknown code", "/#error=no_such_code", "error", []string{msgGeneric, startAgain}},
		{"fragment invalid_state", "/#error=invalid_state&diag=" + diagInvalidState, "error", []string{msgLinkInvalid, diagInvalidState}},
		{"redeem success", "/#code=success", "success", []string{"JUAN GARCÍA LÓPEZ"}},
		{"redeem revoked", "/#code=error-revoked", "error", []string{msgRevoked}},
		{"redeem unknown code", "/#code=no-such-fixture", "error", []string{msgLinkInvalid}},
		{"redeem empty body", "/#code=empty", "error", []string{msgBadResponse}},
		{"redeem html body", "/#code=html", "error", []string{msgBadResponse}},
		{"redeem array body", "/#code=array", "error", []string{msgBadResponse}},
		{"redeem string body", "/#code=string", "error", []string{msgBadResponse}},
		{"redeem chain null", "/#code=chain-null", "error", []string{msgBadResponse}},
		{"redeem identity string", "/#code=identity-string", "error", []string{msgBadResponse}},
		{"redeem http 500 text", "/#code=server-error", "error", []string{msgBadResponse}},
		{"no Object.hasOwn invalid_state", "/__test/no-hasown.html#error=invalid_state&diag=" + diagInvalidState, "error", []string{msgLinkInvalid, startAgain}},
		{"no Object.hasOwn __proto__", "/__test/no-hasown.html#error=__proto__", "error", []string{msgGeneric, startAgain}},
		{"no Object.hasOwn revoked", "/__test/no-hasown.html#code=error-revoked", "error", []string{msgRevoked, startAgain}},
		{"error view throws", "/__test/no-replacechildren.html#error=invalid_state", "fatal", []string{msgBadResponse, startAgain}},
		{"auth never arrives", "/__test/never.html", "working", []string{startAgain}},
		{"auth never arrives, start again", "/__test/never-start-again.html", "start", []string{authenticate}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			checkView(t, dumpDOM(t, chrome, base+c.path, "en-US"), c.view, "en", c.contains)
		})
	}

	const (
		esStart   = `data-i18n="title">Comprobador de autenticación con certificado</h1>`
		caStart   = `data-i18n="title">Comprovador d'autenticació amb certificat</h1>`
		esRevoked = "El certificado ha sido revocado o suspendido."
		caRevoked = "El certificat ha estat revocat o suspès."
	)
	langCases := []struct {
		name, accept, path string // accept: the browser's preferred languages
		view, lang         string // the only visible view, and <html lang>
		contains           []string
	}{
		{"es-ES start", "es-ES", "/", "start", "es", []string{esStart, "DNIe (requiere lector de tarjetas)", `>Autenticarse</button>`}},
		{"es-ES invalid_state", "es-ES", "/#error=invalid_state&diag=" + diagInvalidState, "error", "es",
			[]string{"Este enlace de autenticación ya no es válido. Vuelva a empezar.", "El enlace ha caducado. Vuelva a empezar.", diagInvalidState}},
		{"es-ES success dnie", "es-ES", "/#code=success-dnie", "success", "es", []string{"Fecha de nacimiento", "DNIe (requiere lector de tarjetas)"}},
		{"ca-ES start", "ca-ES", "/", "start", "ca", []string{caStart, "DNIe (cal un lector de targetes)", `>Autenticar-se</button>`}},
		{"ca-ES revoked", "ca-ES", "/#code=error-revoked", "error", "ca", []string{caRevoked, "Posi's en contacte amb l'entitat que el va emetre.", revokedReport}},
		{"ca-ES success", "ca-ES", "/#code=success", "success", "ca", []string{"Nom complet", "JUAN GARCÍA LÓPEZ"}},
		{"fr-FR falls back to Spanish", "fr-FR", "/", "start", "es", []string{esStart}},
		{"fr-FR revoked in Spanish", "fr-FR", "/#code=error-revoked", "error", "es", []string{esRevoked, revokedReport}},
		{"first match wins: fr, ca", "fr-FR,ca-ES,es-ES", "/", "start", "ca", []string{caStart}},
		{"first match wins: de, en", "de-DE,en-GB,es-ES", "/", "start", "en", []string{authenticate}},
		{"galician reads Spanish", "gl-ES,en-US", "/", "start", "es", []string{esStart}},
		{"saved choice beats the browser", "es-ES", "/__test/saved-ca.html", "start", "ca", []string{caStart}},
		{"bad saved value is ignored", "en-US", "/__test/saved-bad.html", "start", "en", []string{authenticate}},
		{"switch on the error view", "es-ES", "/__test/switch-ca.html#code=error-revoked", "error", "ca", []string{caRevoked, revokedReport}},
		{"switch on the success view", "en-US", "/__test/switch-ca.html#code=success", "success", "ca", []string{"Nom complet", "JUAN GARCÍA LÓPEZ"}},
		{"switch on the start view", "en-US", "/__test/switch-ca.html", "start", "ca", []string{caStart, "DNIe (cal un lector de targetes)"}},
		// A renderer that throws during the switch leaves the shown result in place.
		{"switch that throws keeps the result", "en-US", "/__test/switch-ca-broken.html#code=success", "success", "ca", []string{"JUAN GARCÍA LÓPEZ", "Full name"}},
	}
	for _, c := range langCases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			checkView(t, dumpDOM(t, chrome, base+c.path, c.accept), c.view, c.lang, c.contains)
		})
	}

	// Without i18n.js app.js says so in the three languages, offers a reload and runs nothing
	// else: the selector stays hidden.
	t.Run("strings missing", func(t *testing.T) {
		t.Parallel()
		dom := dumpDOM(t, chrome, base+"/__test/no-strings.html#code=success", "es-ES")
		views := visibleViews(dom)
		if len(views) != 1 || views[0].name != "unloaded" {
			t.Fatalf("visible views = %v, want only the unloaded panel:\n%s", views, dom)
		}
		for _, want := range []string{
			`<p class="lede" lang="en">This page did not load completely.</p>`,
			`<p class="lede" lang="es">Esta página no se ha cargado por completo.</p>`,
			`<p class="lede" lang="ca">Aquesta pàgina no s'ha carregat del tot.</p>`,
			`<button class="pill primary" type="button">Reload / Recargar / Recarregar</button>`,
		} {
			if !strings.Contains(views[0].body, want) {
				t.Errorf("unloaded panel lacks %q:\n%s", want, views[0].body)
			}
		}
		if !strings.Contains(dom, `<div class="language" hidden`) {
			t.Error("the language selector is shown, but nothing can switch it")
		}
	})
}

var titles = map[string]string{
	"en": "Certificate Authentication Checker",
	"es": "Comprobador de autenticación con certificado",
	"ca": "Comprovador d'autenticació amb certificat",
}

// checkView checks that view is the only visible one and holds every text of contains, that the
// language selector is shown, and that the page is in lang: <html lang> and the title.
func checkView(t *testing.T, dom, view, lang string, contains []string) {
	t.Helper()
	views := visibleViews(dom)
	if len(views) != 1 || views[0].name != view {
		var names []string
		for _, v := range views {
			names = append(names, v.name)
		}
		t.Fatalf("visible views = %q, want [%q]", names, view)
	}
	for _, want := range contains {
		if !strings.Contains(views[0].body, want) {
			t.Errorf("view %s lacks %q:\n%s", view, want, views[0].body)
		}
	}
	if !strings.Contains(dom, `<div class="language">`) {
		t.Error("the language selector is still hidden")
	}
	if want := `<html lang="` + lang + `">`; !strings.Contains(dom, want) {
		t.Errorf("page lacks %s", want)
	}
	if want := "<title>" + titles[lang] + "</title>"; !strings.Contains(html.UnescapeString(dom), want) {
		t.Errorf("page lacks %s", want)
	}
}

func findChrome(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CHROME"); p != "" {
		return p
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Fatal("no Chrome or Chromium on PATH; set CHROME to the browser binary")
	return ""
}

// startDevserver serves the devserver handler on a free loopback port, with the real fixtures, the
// malformed replies and the test pages. It returns the base URL.
func startDevserver(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../testdata/fixtures")); err != nil {
		t.Fatal(err)
	}
	for name, body := range malformed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "redeem-server-error.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", newHandler(root, ln.Addr().(*net.TCPAddr).Port))
	mux.Handle("GET /__test/", web.SecurityHeaders(http.HandlerFunc(serveTestPage)))
	srv := newServer(mux)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func serveTestPage(w http.ResponseWriter, r *http.Request) {
	name, ext, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/__test/"), ".")
	page, ok := testPages[name]
	switch {
	case ok && ext == "js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = io.WriteString(w, page.js)
	case ok && ext == "html":
		index, err := fs.ReadFile(web.FS(), "index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		const app = `<script src="/app.js" defer></script>`
		extra := app + `<script src="/__test/` + name + `.js" defer></script>`
		if page.before {
			extra = `<script src="/__test/` + name + `.js"></script>` + app
		}
		if name == "no-strings" {
			index = bytes.Replace(index, []byte(stringsTag), []byte(`<script src="/__test/missing.js" defer></script>`), 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(bytes.Replace(index, []byte(app), []byte(extra), 1))
	default:
		http.NotFound(w, r)
	}
}

// dumpDOM loads url in a fresh headless profile whose preferred languages are accept (a
// comma-separated list) and returns the DOM once 10 s of virtual time have passed (virtual time
// stands still while a request is open). Headless Chrome takes navigator.languages from
// --accept-lang and ignores --lang, which sets the language of a headed browser.
func dumpDOM(t *testing.T, chrome, url, accept string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	first, _, _ := strings.Cut(accept, ",")
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
		"--lang="+first, "--accept-lang="+accept,
		"--user-data-dir="+t.TempDir(), "--virtual-time-budget=10000", "--dump-dom", url)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", chrome, err, stderr.Bytes())
	}
	return string(out)
}

type view struct{ name, body string }

var sectionRE = regexp.MustCompile(`(?s)<section id="view-([a-z]+)"([^>]*)>(.*?)</section>`)

// visibleViews returns the view sections without a hidden attribute, their text unescaped.
func visibleViews(dom string) []view {
	var views []view
	for _, m := range sectionRE.FindAllStringSubmatch(dom, -1) {
		if !strings.Contains(m[2], " hidden") {
			views = append(views, view{m[1], html.UnescapeString(m[3])})
		}
	}
	return views
}
