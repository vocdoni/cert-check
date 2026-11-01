package engine

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/opts"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// mustPanic runs f and returns the recovered panic value as text, or stops
// the test when f returns normally.
func mustPanic(t *testing.T, f func()) (msg string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("no panic, want one")
		}
		msg = fmt.Sprint(r)
	}()
	f()
	return ""
}

// asEngine returns p as *Provider or stops the test.
func asEngine(t *testing.T, p certcheck.Provider) *Provider {
	t.Helper()
	e, ok := p.(*Provider)
	if !ok {
		t.Fatalf("FromOptions returned %T, want *Provider", p)
	}
	return e
}

func TestFromOptions(t *testing.T) {
	t.Parallel()
	now := tNow()
	root := testpki.NewRoot(t, "Options Root", testpki.CertSpec{Now: now, KeyPair: tKey(t, "options-root", testpki.ECDSAP256)})
	decl := profiles.Provider{ID: "opt", Name: "Opt", Description: "Opt provider",
		Profiles: []profiles.Profile{inertProfile("opt-a", "opt", root, cwPolicyA)}}
	quiet := certcheck.WithLogger(tDiscard)
	def, err := opts.DefaultRevocation()
	if err != nil {
		t.Fatalf("opts.DefaultRevocation: %v", err)
	}

	t.Run("defaults", func(t *testing.T) {
		a, b := asEngine(t, FromOptions(decl, quiet)), asEngine(t, FromOptions(decl, quiet))
		if a.rev != def || b.rev != def {
			t.Errorf("rev = %p and %p, want the process-wide default %p in both", a.rev, b.rev, def)
		}
		if a.maxLen != 10 || a.version != "" {
			t.Errorf("maxLen %d, version %q; want 10 and empty", a.maxLen, a.version)
		}
		if got, want := len(a.CAs()), 1; got != want {
			t.Errorf("CAs() has %d certificates, want %d", got, want)
		}
	})

	t.Run("WithVersion", func(t *testing.T) {
		_, err := FromOptions(decl, quiet, certcheck.WithVersion("v1")).Verify(t.Context(), nil)
		if got, want := tErr(t, err).Diagnostics.ServerVersion, "v1"; got != want {
			t.Errorf("Diagnostics.ServerVersion = %q, want %q", got, want)
		}
	})

	t.Run("WithClock", func(t *testing.T) {
		at := now.Add(time.Minute)
		p := FromOptions(decl, quiet, certcheck.WithClock(func() time.Time { return at }))
		_, err := p.Verify(t.Context(), nil)
		if got := tErr(t, err).Diagnostics.Time; !got.Equal(at) {
			t.Errorf("Diagnostics.Time = %v, want %v", got, at)
		}

		var logs bytes.Buffer
		future := certcheck.WithClock(func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) })
		inert := FromOptions(decl, future, certcheck.WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		if got := len(inert.CAs()); got != 0 {
			t.Errorf("CAs() loaded in 2100 has %d certificates, want 0 (inert)", got)
		}
		if want := "anchor outside validity"; !strings.Contains(logs.String(), want) {
			t.Errorf("logger output lacks %q:\n%s", want, logs.String())
		}
	})

	t.Run("WithRevocation", func(t *testing.T) {
		r, err := certcheck.NewRevocation(certcheck.RevocationOptions{})
		if err != nil {
			t.Fatalf("NewRevocation: %v", err)
		}
		a := asEngine(t, FromOptions(decl, quiet, certcheck.WithRevocation(r)))
		b := asEngine(t, FromOptions(decl, quiet, certcheck.WithRevocation(r)))
		c := asEngine(t, FromOptions(decl, quiet))
		if a.rev == nil || a.rev != b.rev {
			t.Errorf("rev = %p and %p, want one shared checker", a.rev, b.rev)
		}
		if a.rev == def {
			t.Errorf("rev = %p, want r's checker, not the default", a.rev)
		}
		if c.rev != def {
			t.Errorf("rev without WithRevocation = %p, want the default %p", c.rev, def)
		}
	})

	t.Run("pin mismatch panics", func(t *testing.T) {
		bad := decl
		bad.Profiles = []profiles.Profile{inertProfile("opt-a", "opt", root, cwPolicyA)}
		bad.Profiles[0].Anchors[0].SHA256 = strings.Repeat("0", 64)
		msg := mustPanic(t, func() { FromOptions(bad, quiet) })
		for _, want := range []string{"certcheck: provider", "pin mismatch"} {
			if !strings.Contains(msg, want) {
				t.Errorf("panic %q lacks %q", msg, want)
			}
		}
	})

	t.Run("WithRevocation rejects nil and zero", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			r    *certcheck.Revocation
		}{
			{"nil", nil},
			{"zero", &certcheck.Revocation{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				mustPanic(t, func() { certcheck.WithRevocation(tc.r) })
			})
		}
	})
}
