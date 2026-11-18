// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package server wires the main listener (UI + JSON API) and the auth
// listener (TLS client authentication) around a shared transaction store.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/testui/internal/config"
	"github.com/vocdoni/cert-check/testui/web"
)

// CertSource provides the auth listener certificate (internal/acme.Manager).
// The auth listener starts serving only once Ready reports true.
type CertSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Ready() bool
}

// readyPoll is how often Run checks CertSource.Ready before serving auth.
const readyPoll = 500 * time.Millisecond

// shutdownTimeout bounds the graceful shutdown of both listeners.
const shutdownTimeout = 15 * time.Second

// ErrDrainCutShort is wrapped by Run's error when ctx ended and the shutdown
// drain expired first: the requests still running were cancelled and their
// connections closed, as designed. No listener failed.
var ErrDrainCutShort = errors.New("shutdown drain cut short")

// MainMaxConns caps the main listener's open connections; beyond it a
// connection is closed before anything is read.
const MainMaxConns = 1024

// dropReportInterval is how often Run reports the connections both
// listeners closed over capacity (one Warn line, only after drops).
const dropReportInterval = time.Minute

// Deps are the App's collaborators.
type Deps struct {
	Config    config.Config
	Providers []certcheck.Provider // display order; one auth host each
	Certs     CertSource
	Logger    *slog.Logger
	Version   string
	Now       func() time.Time // store, limiter, auth-diagnostics and handler clock; nil = time.Now
}

// App is the running service.
type App struct {
	cfg           config.Config
	providers     []certcheck.Provider // display order
	providerIDs   map[string]bool      // Info().ID of providers
	certs         CertSource
	log           *slog.Logger
	version       string
	now           func() time.Time
	publicOrigin  string
	store         *Store
	createLimiter *ipLimiter
	redeemLimiter *ipLimiter
	mainConns     int                // MainMaxConns; tests shorten it
	shutdownWait  time.Duration      // shutdownTimeout; tests shorten it
	dropReport    time.Duration      // dropReportInterval; tests shorten it
	stopService   context.CancelFunc // cancels auth.service when the shutdown drain expires
	mainUp        atomic.Bool
	authUp        atomic.Bool
	authTLS       *tls.Config
	auth          *authHandler
}

// New builds the App.
func New(d Deps) (*App, error) {
	if len(d.Providers) == 0 || d.Certs == nil || d.Logger == nil || d.Config.PublicURL == nil {
		return nil, errors.New("server: Providers, Certs, Logger and Config are required")
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	handler, err := certcheck.NewHandler(d.Providers, certcheck.WithClock(now), certcheck.WithVersion(d.Version))
	if err != nil {
		return nil, err
	}
	a := &App{cfg: d.Config, providers: handler.Providers(), providerIDs: map[string]bool{}, certs: d.Certs, log: d.Logger, version: d.Version, now: now,
		publicOrigin: d.Config.PublicURL.Scheme + "://" + d.Config.PublicURL.Host,
		store:        NewStore(TxCapacity, now), createLimiter: newIPLimiter(createPerMinute), redeemLimiter: newIPLimiter(redeemPerMinute),
		mainConns: MainMaxConns, shutdownWait: shutdownTimeout, dropReport: dropReportInterval}
	for _, p := range a.providers {
		a.providerIDs[p.Info().ID] = true
	}
	tcfg, err := ServerConfig(ConfigOptions{Providers: a.providers, AuthDomain: d.Config.AuthDomain,
		GetCertificate: d.Certs.GetCertificate, AllowTLS13: d.Config.AuthTLS13, Logger: d.Logger})
	if err != nil {
		return nil, err
	}
	a.authTLS = tcfg
	service, stopService := context.WithCancel(context.Background())
	a.stopService = stopService
	a.auth = &authHandler{store: a.store, hosts: NewAuthHosts(d.Config.AuthDomain), handler: handler,
		publicURL: a.publicOrigin, slots: make(chan struct{}, ValidationSlots), slotWait: ValidationSlotWait,
		budget: ValidationBudget, service: service, log: d.Logger, version: d.Version, now: now}
	return a, nil
}

// MainHandler returns the main-listener routes behind the security headers.
func (a *App) MainHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(noDirFS{web.FS()}))
	mux.HandleFunc("GET /api/v1/providers", a.handleProviders)
	mux.HandleFunc("POST /api/v1/transactions", a.handleCreate)
	mux.HandleFunc("POST /api/v1/transactions/redeem", a.handleRedeem)
	mux.HandleFunc("GET /api/v1/transactions/current", a.handleCurrent)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.mainUp.Load() && a.authUp.Load() && a.certs.Ready() && len(a.providers) > 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mainHeaders(mux)
}

// newMainServer returns the main http.Server with the spec timeouts; its
// ErrorLog goes to slog at warn. "OPTIONS *" reaches h, so it carries the
// security headers.
func newMainServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:                      h,
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            10 * time.Second,
		ReadTimeout:                  15 * time.Second,
		WriteTimeout:                 30 * time.Second,
		IdleTimeout:                  60 * time.Second,
		MaxHeaderBytes:               16 << 10,
		ErrorLog:                     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Run serves both listeners until ctx ends, then shuts down gracefully.
// mainLn is plain TCP (the platform edge terminates TLS), wrapped with the
// MainMaxConns cap; authLn is wrapped with the 512-connection cap and TLS
// here, and served once the certificate is ready. Shutdown drains both
// servers concurrently for up to 15 s; when that expires it cancels the
// validations still running and closes the connections left; Run then
// returns an error wrapping ErrDrainCutShort, unless a listener failed
// first (that error is returned, joined with the drain's). Both listeners
// are closed when Run returns. Run is called once per App.
func (a *App) Run(ctx context.Context, mainLn, authLn net.Listener) error {
	mainSrv := newMainServer(a.MainHandler(), a.log)
	authSrv := newAuthServer(a.auth, a.log)
	authSrv.BaseContext = func(net.Listener) context.Context { return a.auth.service }
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mainLim, authLim := newLimitListener(mainLn, a.mainConns), newLimitListener(authLn, AuthMaxConns)
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Go(func() { a.store.RunJanitor(ctx, JanitorInterval) })
	wg.Go(func() { a.reportDrops(ctx, mainLim, authLim) })
	wg.Go(func() {
		a.mainUp.Store(true)
		if err := mainSrv.Serve(mainLim); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	})
	wg.Go(func() {
		t := time.NewTicker(readyPoll)
		defer t.Stop()
		for !a.certs.Ready() {
			select {
			case <-ctx.Done():
				_ = authLn.Close() // never served: release the port; nothing to report
				return
			case <-t.C:
			}
		}
		a.authUp.Store(true)
		if err := authSrv.Serve(tls.NewListener(authLim, a.authTLS)); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	})
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}
	a.mainUp.Store(false)
	a.authUp.Store(false)
	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), a.shutdownWait)
	defer stop()
	// In-flight validations may finish within the drain (a redeploy should
	// not fail them); those still running when it expires are cancelled.
	defer context.AfterFunc(shutdownCtx, a.stopService)()
	errs := make(chan error, 2)
	for _, srv := range []*http.Server{mainSrv, authSrv} {
		go func() { errs <- shutdown(shutdownCtx, srv) }()
	}
	drainErr := errors.Join(<-errs, <-errs)
	a.stopService() // nothing outlives Run
	cancel()
	wg.Wait()
	if runErr == nil && errors.Is(drainErr, context.DeadlineExceeded) { // asked to stop, and the drain expired
		return fmt.Errorf("%w after %v: %w", ErrDrainCutShort, a.shutdownWait, drainErr)
	}
	return errors.Join(runErr, drainErr)
}

// reportDrops logs, at most once per a.dropReport and only when some were
// dropped, how many connections each listener closed over capacity: a full
// listener otherwise looks like an idle service.
func (a *App) reportDrops(ctx context.Context, mainLn, authLn *limitListener) {
	t := time.NewTicker(a.dropReport)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if m, au := mainLn.dropped.Swap(0), authLn.dropped.Swap(0); m+au > 0 {
				a.log.Warn("connections dropped over capacity", "mainDropped", m, "authDropped", au)
			}
		}
	}
}

// shutdown drains srv until ctx ends, then closes the connections still
// open (requests slower than the drain).
func shutdown(ctx context.Context, srv *http.Server) error {
	err := srv.Shutdown(ctx)
	if err != nil {
		_ = srv.Close() // drain cut short: drop what is left; the Shutdown error says why
	}
	return err
}

// noDirFS hides directories (no listings); "/" still serves index.html
// because FileServer opens index.html directly.
type noDirFS struct{ fs.FS }

func (f noDirFS) Open(name string) (fs.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := file.Stat(); err == nil && st.IsDir() && name != "." {
		_ = file.Close() // read-only embedded file
		return nil, fs.ErrNotExist
	}
	return file, nil
}
