package web_test

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/web"
)

// requiredStatic lists every file the UI ships (Task 11 file list).
var requiredStatic = []string{
	"index.html",
	"app.js",
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
	for _, name := range []string{"index.html", "app.js", "styles.css"} {
		src := readStatic(t, name)
		if loc := external.FindStringIndex(src); loc != nil {
			t.Errorf("%s: external reference near %q", name, src[loc[0]:min(len(src), loc[0]+40)])
		}
		if strings.Contains(src, "@import") {
			t.Errorf("%s: @import is not allowed", name)
		}
	}
	// Data URIs are allowed only in CSS (icons).
	for _, name := range []string{"index.html", "app.js"} {
		if strings.Contains(readStatic(t, name), "data:") {
			t.Errorf("%s: data: URI is only allowed in CSS", name)
		}
	}
}

func TestNoUnsafeDOM(t *testing.T) {
	js := readStatic(t, "app.js")
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "Function(", "srcdoc"} {
		if strings.Contains(js, banned) {
			t.Errorf("app.js contains %q", banned)
		}
	}
}

func TestCSPCompatible(t *testing.T) {
	html := readStatic(t, "index.html")

	scripts := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(html, -1)
	if len(scripts) != 1 {
		t.Fatalf("index.html has %d script elements, want 1", len(scripts))
	}
	attrs, body := scripts[0][1], scripts[0][2]
	if strings.TrimSpace(body) != "" {
		t.Errorf("inline script body %q, want none", body)
	}
	for _, want := range []string{`src="/app.js"`, "defer"} {
		if !strings.Contains(attrs, want) {
			t.Errorf("script attributes %q lack %q", attrs, want)
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
	js := readStatic(t, "app.js")
	for _, banned := range []string{".style.", ".style[", "cssText", "'style'", `"style"`, "javascript:"} {
		if strings.Contains(js, banned) {
			t.Errorf("app.js contains %q", banned)
		}
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
		`<label for="provider">Certificate provider</label>`,
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
		`<details id="tech"><summary>Technical details</summary><pre id="report"`,
		`id="copy-report"`,
		`>Copy diagnostic report</button>`,
		`This report contains your certificate details (name and ID number). Share it only with Vocdoni support.`,
		`id="retry" class="pill primary"`,
		`>Start again</button>`,
		`id="status"`,
		`role="status"`,
		`aria-live="polite"`,
		`alt="Vocdoni"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %q", want)
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
	if !strings.Contains(js, `'Beta'`) && !strings.Contains(js, `"Beta"`) {
		t.Errorf("app.js lacks the Beta optgroup label")
	}

	// Brand copy rules (ruling R34/R39): no en or em dash in any shipped
	// text, fixtures included; sentence case outside the three exceptions.
	for _, name := range []string{"index.html", "app.js", "styles.css", "fonts/SOURCES.md"} {
		assertNoDashes(t, name, readStatic(t, name))
	}
	for _, m := range mustGlob(t, "testdata/fixtures/*.json") {
		assertNoDashes(t, m, string(readTestdata(t, strings.TrimPrefix(m, "testdata/"))))
	}
	assertNoDashes(t, "report-revoked.txt", string(readTestdata(t, "report-revoked.txt")))

	assertSentenceCase(t, "index.html", visibleText(html))
	assertSentenceCase(t, "app.js", stringLiterals(js))
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
// copy fallback ("Press Ctrl+C to copy", wording fixed by the brief).
func assertSentenceCase(t *testing.T, name, text string) {
	t.Helper()
	for _, allowed := range []string{
		"Vocdoni Certificate Authentication Checker",
		"Certificate Authentication Checker",
		"Press Ctrl+C to copy",
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
// ruling R38). There is deliberately no certauth import.
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
