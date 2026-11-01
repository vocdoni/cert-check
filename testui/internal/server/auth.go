package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	certcheck "github.com/vocdoni/cert-check"
)

// Auth listener limits (spec "TLS on the auth listener", "Rate limiting").
const (
	AuthMaxConns         = 512
	ValidationSlots      = 32
	ValidationSlotWait   = 10 * time.Second
	ValidationBudget     = 40 * time.Second
	authenticatePath     = "/v1/authenticate"
	fragmentInvalidState = "/#error=invalid_state&diag="
	fragmentInternal     = "/#error=internal&diag="
)

// authHandler serves only GET /v1/authenticate on the auth listener. Every
// response has an empty body: authHeaders fixes the Content-Type, so
// http.Redirect writes no HTML.
type authHandler struct {
	store     *Store
	hosts     *AuthHosts
	handler   *certcheck.Handler
	publicURL string // fixed origin, never taken from the request
	slots     chan struct{}
	slotWait  time.Duration   // ValidationSlotWait; tests shorten it
	budget    time.Duration   // ValidationBudget; tests shorten it
	service   context.Context // parent of every validation; cancelled when the shutdown drain expires
	log       *slog.Logger
	version   string
	now       func() time.Time // diagnostics time of server-made errors
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	var provider string // known after the SNI lookup
	defer func() {
		if v := recover(); v != nil {
			a.panicked(w, r, provider, v)
		}
	}()
	if r.Method != http.MethodGet || r.URL.Path != authenticatePath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := certcheck.CheckHost(r); err != nil {
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	provider, ok := a.hosts.Provider(r.TLS.ServerName)
	// ParseQuery, not URL.Query: a malformed pair (bad escape, ';') is an
	// error rather than silently dropped, so it cannot hide a second state.
	query, qerr := url.ParseQuery(r.URL.RawQuery)
	states := query["state"]
	var ref TxRef
	err := ErrInvalidState
	if ok && qerr == nil && len(states) == 1 {
		ref, err = a.store.ConsumeState(Secret(states[0]), provider)
	}
	if err != nil {
		// Info: a bad state is user error or scanner noise, not an operator event.
		diag := certcheck.NewDiagnosticID()
		a.log.Info("auth state rejected", "diagnosticId", diag, "sni", r.TLS.ServerName, "reason", err.Error())
		http.Redirect(w, r, a.publicURL+fragmentInvalidState+diag, http.StatusSeeOther)
		return
	}

	outcome := a.validate(r, provider)
	code, err := a.store.Complete(ref, outcome)
	a.logOutcome(outcome)
	if err != nil {
		diag := certcheck.NewDiagnosticID()
		a.log.Warn("auth transaction gone during validation", "diagnosticId", diag, "sni", r.TLS.ServerName,
			"outcomeDiagnosticId", outcome.diagnosticID(), "reason", err.Error())
		http.Redirect(w, r, a.publicURL+fragmentInvalidState+diag, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, a.publicURL+"/#code="+string(code), http.StatusSeeOther)
}

// panicked answers a panic recovered from ServeHTTP. net/http would log it
// only through the auth server's ErrorLog, at debug. The value may hold
// certificate data, so only its type is logged.
func (a *authHandler) panicked(w http.ResponseWriter, r *http.Request, provider string, v any) {
	if v == http.ErrAbortHandler {
		panic(v) // net/http's own abort, not a fault
	}
	diag := certcheck.NewDiagnosticID()
	a.log.Error("auth handler panic", "diagnosticId", diag, "provider", provider, "panicType", fmt.Sprintf("%T", v))
	http.Redirect(w, r, a.publicURL+fragmentInternal+diag, http.StatusSeeOther)
}

// validate runs the checker in a bounded slot with a 40 s budget on the
// service context: detached from client disconnects, cancelled when the
// shutdown drain expires.
// A missed slot or the budget yields internal (retryable).
func (a *authHandler) validate(r *http.Request, provider string) Outcome {
	wait := time.NewTimer(a.slotWait)
	defer wait.Stop()
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	case <-wait.C:
		return Outcome{Err: a.serverError(r, certcheck.CodeInternal, "validation capacity exhausted")}
	}
	ctx, cancel := context.WithTimeout(a.service, a.budget)
	defer cancel()
	res, err := a.handler.AuthAs(r.WithContext(ctx), provider)
	if err != nil {
		e, ok := errors.AsType[*certcheck.Error](err)
		if !ok {
			return Outcome{Err: a.serverError(r, certcheck.CodeInternal, "unexpected validation error")}
		}
		if e.Diagnostics.DiagnosticID == "" { // AuthAs's request-without-TLS error carries no diagnostics
			return Outcome{Err: a.serverError(r, e.Code, e.Detail)}
		}
		return Outcome{Err: e}
	}
	return Outcome{Result: res}
}

// serverError is an error decided by the server (not by the checker), with
// minimal diagnostics stamped by the injected clock.
func (a *authHandler) serverError(r *http.Request, code certcheck.ErrorCode, detail string) *certcheck.Error {
	d := certcheck.Diagnostics{DiagnosticID: certcheck.NewDiagnosticID(), Time: a.now().UTC(), ServerVersion: a.version,
		Code: code, TechnicalDetail: detail, TLS: certcheck.DescribeTLS(r.TLS)}
	if r.TLS != nil {
		if p, ok := a.hosts.Provider(r.TLS.ServerName); ok {
			d.Provider = p
		}
	}
	return &certcheck.Error{Code: code, Retryable: code.Retryable(), Detail: detail, Diagnostics: d}
}

// diagnosticID is the diagnostic ID stamped on the outcome.
func (o Outcome) diagnosticID() string {
	if o.Err != nil {
		return o.Err.Diagnostics.DiagnosticID
	}
	return o.Result.Diagnostics.DiagnosticID
}

// logOutcome writes one line with non-PII fields only.
func (a *authHandler) logOutcome(o Outcome) {
	if o.Err != nil {
		a.log.LogAttrs(context.Background(), slog.LevelInfo, "authentication failed", o.Err.Diagnostics.LogAttrs()...)
		return
	}
	attrs := append(o.Result.Diagnostics.LogAttrs(),
		slog.String("profile", o.Result.Profile.ID), slog.String("revocationMethod", string(o.Result.Revocation.Method)))
	a.log.LogAttrs(context.Background(), slog.LevelInfo, "authentication succeeded", attrs...)
}

// limitListener closes connections beyond its capacity before anything is
// read (on the auth listener, before the TLS handshake) and counts them.
type limitListener struct {
	net.Listener
	sem     chan struct{}
	dropped atomic.Int64 // connections closed over capacity; App.reportDrops resets it
}

func newLimitListener(l net.Listener, limit int) *limitListener {
	return &limitListener{Listener: l, sem: make(chan struct{}, limit)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
		default:
			l.dropped.Add(1)
			_ = c.Close() // over capacity: drop before the handshake; counted above
		}
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// newAuthServer returns the auth http.Server: HTTP/1.1 only (empty
// TLSNextProto) and the spec timeouts. ReadHeaderTimeout, the shortest, also
// bounds the TLS handshake: a silent connection holds a slot for 5 s. Its
// ErrorLog (TLS handshake errors, mostly scanners on a public port) goes to
// slog at debug (ruling R61); ServeHTTP logs its own panics.
// "OPTIONS *" reaches h (404 with the auth headers) instead of net/http's
// header-less 200.
func newAuthServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:                      h,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            5 * time.Second,
		ReadTimeout:                  30 * time.Second,
		WriteTimeout:                 60 * time.Second,
		IdleTimeout:                  30 * time.Second,
		MaxHeaderBytes:               16 << 10,
		TLSNextProto:                 map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:                     slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
}
