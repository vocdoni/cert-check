// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command devserver serves the embedded UI with a mocked API backed by the JSON fixtures in
// web/testdata/fixtures. It exists for the offline UI checks (AC9: Playwright, axe) and is not
// part of the shipped image. Run it from testui/:
//
//	go run ./web/internal/devserver
//
// It listens on 127.0.0.1:$PORT (default 8090). Besides the mocked API it offers:
//
//	GET /__auth?state=x[&result=<name>]  303 to /#code=<name>, or to /#error=invalid_state&diag=<id>
//	                                     for result=invalid_state; result=never answers 204 so the
//	                                     browser stays on the page (an auth step that never arrives).
//	                                     Without result it falls back to the mock-result cookie, then
//	                                     to "success".
//	GET /__mock?result=<name>&current=<pending|none>
//	                                     sets the mock-result and mock-current cookies, 303 to /
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vocdoni/cert-check/testui/web"
)

const (
	cookieTx      = "certcheck_tx"
	cookieResult  = "mock-result"
	cookieCurrent = "mock-current"

	// diagInvalidState is the diagnostic ID the mock auth listener puts in #error=invalid_state.
	diagInvalidState = "0123456789abcdef0123456789abcdef"
)

// unknownProvider is the real API's answer for a missing or unknown provider.
const unknownProvider = `{"status":"error","error":{"code":"unknown_provider","message":"Unknown certificate provider.","retryable":false}}` + "\n"

// nameRE limits what reaches a fixture file name or a redirect fragment.
var nameRE = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devserver:", err)
		os.Exit(1)
	}
}

func run() error {
	fixturesDir := flag.String("fixtures", "web/testdata/fixtures", "directory holding the JSON fixtures")
	flag.Parse()

	port, err := strconv.Atoi(cmp.Or(os.Getenv("PORT"), "8090"))
	if err != nil || port < 1 || port > 65535 {
		return errors.New("PORT must be a number between 1 and 65535")
	}
	root, err := os.OpenRoot(*fixturesDir)
	if err != nil {
		return fmt.Errorf("open fixtures: %w", err)
	}
	defer root.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	srv := newServer(newHandler(root, port))

	slog.Info("devserver listening", "url", "http://"+ln.Addr().String(), "fixtures", *fixturesDir)
	var wg sync.WaitGroup
	errc := make(chan error, 1)
	wg.Go(func() { errc <- srv.Serve(ln) })

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	wg.Wait()
	return err
}

// newServer wraps h in an http.Server. The mock only serves small bodies on loopback, so every
// phase gets a short deadline and a stalled client cannot hold a connection open.
func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

type mock struct {
	fixtures *os.Root
	port     int
}

func newHandler(fixtures *os.Root, port int) http.Handler {
	m := &mock{fixtures: fixtures, port: port}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/providers", m.providers)
	mux.HandleFunc("POST /api/v1/transactions", m.create)
	mux.HandleFunc("POST /api/v1/transactions/redeem", m.redeem)
	mux.HandleFunc("GET /api/v1/transactions/current", m.current)
	mux.HandleFunc("GET /__auth", m.auth)
	mux.HandleFunc("GET /__mock", m.control)
	mux.Handle("GET /", http.FileServerFS(web.FS()))
	return web.SecurityHeaders(mux) // the production header set
}

func (m *mock) writeJSON(w http.ResponseWriter, status int, name string) {
	data, err := m.fixtures.ReadFile(name)
	if err != nil {
		slog.Error("read fixture", "name", name, "err", err)
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	writeBytes(w, status, data)
}

func writeBytes(w http.ResponseWriter, status int, data []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data) // the client went away; nothing to do
}

func (m *mock) providers(w http.ResponseWriter, _ *http.Request) {
	m.writeJSON(w, http.StatusOK, "providers.json")
}

// create answers 201 with create.json, pointing authUrl back at this server, and sets a cookie.
func (m *mock) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil || body.Provider == "" {
		writeBytes(w, http.StatusBadRequest, []byte(unknownProvider))
		return
	}
	raw, err := m.fixtures.ReadFile("create.json")
	if err != nil {
		slog.Error("read fixture", "name", "create.json", "err", err)
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	var created struct {
		AuthURL   string `json:"authUrl"`
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		slog.Error("decode fixture", "name", "create.json", "err", err)
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	created.AuthURL = fmt.Sprintf("http://127.0.0.1:%d/__auth?state=x", m.port)
	created.ExpiresAt = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	out, err := json.Marshal(created)
	if err != nil {
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieTx, Value: "mock", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	writeBytes(w, http.StatusCreated, out)
}

// redeem answers with redeem-<code>.json. The fixture redeem-invalid.json (and any unknown code)
// is served with HTTP 400, the others with 200.
func (m *mock) redeem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	status, name := http.StatusOK, "redeem-"+body.Code+".json"
	if !nameRE.MatchString(body.Code) || body.Code == "invalid" {
		status, name = http.StatusBadRequest, "redeem-invalid.json"
	}
	data, err := m.fixtures.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		status, name = http.StatusBadRequest, "redeem-invalid.json"
		data, err = m.fixtures.ReadFile(name)
	}
	if err != nil {
		slog.Error("read fixture", "name", name, "err", err)
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	writeBytes(w, status, data)
}

// current answers current-<pending|none>.json, chosen by ?state=, then by the mock-current cookie.
func (m *mock) current(w http.ResponseWriter, r *http.Request) {
	state := cmp.Or(r.URL.Query().Get("state"), cookieValue(r, cookieCurrent), "none")
	if state != "pending" {
		state = "none"
	}
	m.writeJSON(w, http.StatusOK, "current-"+state+".json")
}

func (m *mock) auth(w http.ResponseWriter, r *http.Request) {
	result := cmp.Or(r.URL.Query().Get("result"), cookieValue(r, cookieResult), "success")
	switch {
	case !nameRE.MatchString(result):
		http.Error(w, "bad result", http.StatusBadRequest)
	case result == "never":
		w.WriteHeader(http.StatusNoContent)
	case result == "invalid_state":
		http.Redirect(w, r, "/#error=invalid_state&diag="+diagInvalidState, http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/#code="+result, http.StatusSeeOther)
	}
}

// control stores the mock-result and mock-current choices in cookies, then redirects to /.
func (m *mock) control(w http.ResponseWriter, r *http.Request) {
	for param, cookie := range map[string]string{"result": cookieResult, "current": cookieCurrent} {
		v := r.URL.Query().Get(param)
		if v == "" {
			continue
		}
		if !nameRE.MatchString(v) {
			http.Error(w, "bad "+param, http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookie, Value: v, Path: "/", SameSite: http.SameSiteLaxMode})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
