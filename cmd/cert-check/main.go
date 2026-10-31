// Command cert-check serves the Certificate Authentication Checker.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/internal/acme"
	"github.com/vocdoni/cert-check/internal/config"
	"github.com/vocdoni/cert-check/internal/server"
)

// version is set with -ldflags "-X main.version=<git describe>".
var version = "dev"

func main() {
	if err := run(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "cert-check:", err)
		os.Exit(1)
	}
}

// run wires and serves the service until SIGINT/SIGTERM.
func run(getenv func(string) string) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg, err := profiles.Default(time.Now(), log)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	rev, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/" + version, Logger: log})
	if err != nil {
		return err
	}
	checker, err := certauth.NewChecker(certauth.Options{Registry: reg, Revocation: rev, Version: version})
	if err != nil {
		return err
	}
	var certs *acme.Manager
	switch cfg.CertMode {
	case config.CertStatic:
		certs, err = acme.LoadStatic(cfg.TLSCertFile, cfg.TLSKeyFile)
	default:
		certs, err = acme.NewACME(acme.Options{AuthDomain: cfg.AuthDomain, DataDir: cfg.DataDir, Email: cfg.ACMEEmail,
			Staging: cfg.ACMECA == config.ACMEStaging, CloudflareToken: cfg.CloudflareToken.Reveal(),
			OverrideDomain: cfg.ACMEDNSOverrideDomain, Logger: log})
	}
	if err != nil {
		return err
	}
	defer certs.Close() // stops certmagic's renewal; no-op in static mode
	app, err := server.New(server.Deps{Config: cfg, Checker: checker, Certs: certs, Logger: log, Version: version})
	if err != nil {
		return err
	}
	mainLn, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.Port))
	if err != nil {
		return err
	}
	authLn, err := net.Listen("tcp", cfg.AuthListen)
	if err != nil {
		_ = mainLn.Close() // never served; the listen error is what matters
		return err
	}
	log.Info("cert-check starting", "version", version, "providers", len(checker.Providers()), "authDomain", cfg.AuthDomain)
	// The main listener serves at once (/readyz 503); the auth listener
	// starts when the certificate is ready. ACME retries with backoff.
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := certs.Run(ctx); err != nil && ctx.Err() == nil {
			log.Error("certificate manager stopped", "error", err.Error())
		}
	})
	err = app.Run(ctx, mainLn, authLn)
	stop() // ends certs.Run when Run returned on a listener error
	wg.Wait()
	return err
}
