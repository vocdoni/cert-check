// Package server wires the main listener (UI + JSON API) and the auth
// listener (TLS client authentication) around a shared transaction store.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/tlsauth"
	"github.com/vocdoni/cert-check/internal/config"
	"github.com/vocdoni/cert-check/web"
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

// Deps are the App's collaborators.
type Deps struct {
	Config  config.Config
	Checker *certauth.Checker
	Certs   CertSource
	Logger  *slog.Logger
	Version string
	Now     func() time.Time // store, limiter and auth-diagnostics clock; nil = time.Now
}

// App is the running service.
type App struct {
	cfg           config.Config
	checker       *certauth.Checker
	certs         CertSource
	log           *slog.Logger
	version       string
	now           func() time.Time
	publicOrigin  string
	store         *Store
	createLimiter *ipLimiter
	redeemLimiter *ipLimiter
	mainUp        atomic.Bool
	authUp        atomic.Bool
	authTLS       *tls.Config
	auth          *authHandler
}

// New builds the App.
func New(d Deps) (*App, error) {
	if d.Checker == nil || d.Certs == nil || d.Logger == nil || d.Config.PublicURL == nil {
		return nil, errors.New("server: Checker, Certs, Logger and Config are required")
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	a := &App{cfg: d.Config, checker: d.Checker, certs: d.Certs, log: d.Logger, version: d.Version, now: now,
		publicOrigin: d.Config.PublicURL.Scheme + "://" + d.Config.PublicURL.Host,
		store:        NewStore(TxCapacity, now), createLimiter: newIPLimiter(createPerMinute), redeemLimiter: newIPLimiter(redeemPerMinute)}
	tcfg, err := tlsauth.ServerConfig(tlsauth.ConfigOptions{Checker: d.Checker, AuthDomain: d.Config.AuthDomain,
		GetCertificate: d.Certs.GetCertificate, AllowTLS13: d.Config.AuthTLS13, Logger: d.Logger})
	if err != nil {
		return nil, err
	}
	a.authTLS = tcfg
	a.auth = &authHandler{store: a.store, tls: tlsauth.NewHandler(d.Checker, d.Config.AuthDomain),
		publicURL: a.publicOrigin, slots: make(chan struct{}, ValidationSlots), slotWait: ValidationSlotWait,
		budget: ValidationBudget, log: d.Logger, version: d.Version, now: now}
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
		if a.mainUp.Load() && a.authUp.Load() && a.certs.Ready() && len(a.checker.Providers()) > 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	return mainHeaders(mux)
}

// newMainServer returns the main http.Server with the spec timeouts; its
// ErrorLog goes to slog at warn.
func newMainServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Run serves both listeners until ctx ends, then shuts down gracefully.
// mainLn is plain TCP (the platform edge terminates TLS); authLn is wrapped
// with the 512-connection cap and TLS here, and served once the certificate
// is ready. Both listeners are closed when Run returns.
func (a *App) Run(ctx context.Context, mainLn, authLn net.Listener) error {
	mainSrv := newMainServer(a.MainHandler(), a.log)
	authSrv := newAuthServer(a.auth, a.log)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Go(func() { a.store.RunJanitor(ctx, JanitorInterval) })
	wg.Go(func() {
		a.mainUp.Store(true)
		if err := mainSrv.Serve(mainLn); !errors.Is(err, http.ErrServerClosed) {
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
		if err := authSrv.Serve(tls.NewListener(newLimitListener(authLn, AuthMaxConns), a.authTLS)); !errors.Is(err, http.ErrServerClosed) {
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
	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer stop()
	runErr = errors.Join(runErr, mainSrv.Shutdown(shutdownCtx), authSrv.Shutdown(shutdownCtx))
	cancel()
	wg.Wait()
	return runErr
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
