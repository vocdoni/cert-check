// Command cert-check serves the Certificate Authentication Checker.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/testui/internal/acme"
	"github.com/vocdoni/cert-check/testui/internal/config"
	"github.com/vocdoni/cert-check/testui/internal/probe"
	"github.com/vocdoni/cert-check/testui/internal/server"
)

// version is set with -ldflags "-X main.version=<git describe>".
var version = "dev"

func main() {
	os.Exit(dispatch(os.Args[1:], os.Getenv, runProbe, os.Stdout, os.Stderr))
}

// probeFunc runs the revocation probe, adding the live specimens found in
// specimenDirs, and writes the report to w.
type probeFunc func(ctx context.Context, specimenDirs []string, w io.Writer) (probe.Summary, error)

// dispatch runs `cert-check probe [specimen-dir...]` (exit 1 on any FAIL
// line) or, with any other arguments, the service. It returns the exit status.
func dispatch(args []string, getenv func(string) string, probeRun probeFunc, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "probe" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		sum, err := probeRun(ctx, args[1:], stdout)
		if err != nil {
			fmt.Fprintln(stderr, "cert-check probe:", err)
			return 1
		}
		if sum.Failed() {
			return 1
		}
		return 0
	}
	if err := run(getenv); err != nil {
		fmt.Fprintln(stderr, "cert-check:", err)
		return 1
	}
	return 0
}

// runProbe probes probe.DefaultTargets from this host's network with the
// production fetcher (no server, no configuration).
func runProbe(ctx context.Context, specimenDirs []string, w io.Writer) (probe.Summary, error) {
	targets, err := probe.DefaultTargets()
	if err != nil {
		return probe.Summary{}, err
	}
	for _, dir := range specimenDirs {
		sp, err := probe.LoadSpecimens(os.DirFS(dir))
		if err != nil {
			return probe.Summary{}, err
		}
		targets = append(targets, sp...)
	}
	rc, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/" + version})
	if err != nil {
		return probe.Summary{}, err
	}
	return probe.Run(ctx, rc, targets, time.Now(), w)
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
