package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/tlsauth"
)

// Auth listener limits (spec "TLS on the auth listener", "Rate limiting").
const (
	AuthMaxConns         = 512
	ValidationSlots      = 32
	ValidationSlotWait   = 10 * time.Second
	ValidationBudget     = 40 * time.Second
	authenticatePath     = "/v1/authenticate"
	fragmentInvalidState = "/#error=invalid_state&diag="
)

// authHandler serves only GET /v1/authenticate on the auth listener. Every
// response has an empty body: authHeaders fixes the Content-Type, so
// http.Redirect writes no HTML.
type authHandler struct {
	store     *Store
	tls       *tlsauth.Handler
	publicURL string // fixed origin, never taken from the request
	slots     chan struct{}
	slotWait  time.Duration // ValidationSlotWait; tests shorten it
	budget    time.Duration // ValidationBudget; tests shorten it
	log       *slog.Logger
	version   string
	now       func() time.Time // diagnostics time of server-made errors
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeaders(w)
	if r.Method != http.MethodGet || r.URL.Path != authenticatePath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err := tlsauth.CheckHost(r); err != nil {
		w.WriteHeader(http.StatusMisdirectedRequest)
		return
	}
	provider, ok := a.tls.Provider(r.TLS.ServerName)
	states := r.URL.Query()["state"]
	var ref TxRef
	err := ErrInvalidState
	if ok && len(states) == 1 {
		ref, err = a.store.ConsumeState(Secret(states[0]), provider)
	}
	if err != nil {
		diag := certauth.NewDiagnosticID()
		a.log.Warn("auth state rejected", "diagnosticId", diag, "sni", r.TLS.ServerName, "reason", err.Error())
		http.Redirect(w, r, a.publicURL+fragmentInvalidState+diag, http.StatusSeeOther)
		return
	}

	outcome := a.validate(r)
	code, err := a.store.Complete(ref, outcome)
	if err != nil {
		diag := certauth.NewDiagnosticID()
		a.log.Warn("auth transaction expired during validation", "diagnosticId", diag, "sni", r.TLS.ServerName)
		http.Redirect(w, r, a.publicURL+fragmentInvalidState+diag, http.StatusSeeOther)
		return
	}
	a.logOutcome(outcome)
	http.Redirect(w, r, a.publicURL+"/#code="+string(code), http.StatusSeeOther)
}

// validate runs the checker in a bounded slot with a 40 s budget detached
// from client disconnects; a missed slot or the budget yields internal (retryable).
func (a *authHandler) validate(r *http.Request) Outcome {
	wait := time.NewTimer(a.slotWait)
	defer wait.Stop()
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	case <-wait.C:
		return Outcome{Err: a.serverError(r, certauth.CodeInternal, "validation capacity exhausted")}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), a.budget)
	defer cancel()
	res, err := a.tls.Authenticate(r.WithContext(ctx))
	if err != nil {
		e, ok := errors.AsType[*certauth.Error](err)
		if !ok {
			return Outcome{Err: a.serverError(r, certauth.CodeInternal, "unexpected validation error")}
		}
		if e.Diagnostics.DiagnosticID == "" { // Authenticate's request-without-TLS error carries no diagnostics
			return Outcome{Err: a.serverError(r, e.Code, e.Detail)}
		}
		return Outcome{Err: e}
	}
	return Outcome{Result: res}
}

// serverError is an error decided by the server (not by the checker), with
// minimal diagnostics stamped by the injected clock.
func (a *authHandler) serverError(r *http.Request, code certauth.ErrorCode, detail string) *certauth.Error {
	d := certauth.Diagnostics{DiagnosticID: certauth.NewDiagnosticID(), Time: a.now().UTC(), ServerVersion: a.version,
		Code: code, TechnicalDetail: detail, TLS: certauth.DescribeTLS(r.TLS)}
	if r.TLS != nil {
		if p, ok := a.tls.Provider(r.TLS.ServerName); ok {
			d.Provider = p
		}
	}
	return &certauth.Error{Code: code, Retryable: code.Retryable(), Detail: detail, Diagnostics: d}
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

// limitListener closes connections beyond its capacity before the TLS handshake.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, limit int) net.Listener {
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
			_ = c.Close() // over capacity: drop before the handshake; nothing to report
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
// TLSNextProto) and the spec timeouts. Its ErrorLog (TLS handshake errors,
// mostly scanners on a public port) goes to slog at debug (ruling R61).
// "OPTIONS *" reaches h (404 with the auth headers) instead of net/http's
// header-less 200.
func newAuthServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:                      h,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            10 * time.Second,
		ReadTimeout:                  30 * time.Second,
		WriteTimeout:                 60 * time.Second,
		IdleTimeout:                  30 * time.Second,
		MaxHeaderBytes:               16 << 10,
		TLSNextProto:                 map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:                     slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
}
