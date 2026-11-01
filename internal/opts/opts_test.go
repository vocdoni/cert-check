package opts_test

import (
	"log/slog"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/opts"
)

// option has the shape of certcheck.Option, whose underlying type is
// func(*opts.Settings).
type option func(*opts.Settings)

func version(v string) option { return func(s *opts.Settings) { s.Version = v } }

func TestApply(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	clock := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		options []option
		version string
		logger  *slog.Logger
		now     time.Time // zero: Now must be nil
	}{
		{name: "no options: the zero Settings, nil defaults"},
		{name: "nil options are skipped", options: []option{nil, version("a"), nil}, version: "a"},
		{name: "later options win", options: []option{version("a"), version("b")}, version: "b"},
		{name: "independent fields", version: "c", logger: logger, now: clock, options: []option{
			version("c"),
			func(s *opts.Settings) { s.Logger = logger },
			func(s *opts.Settings) { s.Now = func() time.Time { return clock } },
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := opts.Apply(tc.options...)
			if s.Version != tc.version || s.Logger != tc.logger {
				t.Errorf("Version %q, Logger %p; want %q, %p", s.Version, s.Logger, tc.version, tc.logger)
			}
			switch {
			case tc.now.IsZero() && s.Now != nil:
				t.Errorf("Now = %v, want nil", s.Now())
			case !tc.now.IsZero() && (s.Now == nil || !s.Now().Equal(tc.now)):
				t.Errorf("Now not set to the %v clock", tc.now)
			}
			if s.Revocation != nil || s.MaxChainLen != 0 {
				t.Errorf("Revocation %p, MaxChainLen %d; want nil, 0 (defaults)", s.Revocation, s.MaxChainLen)
			}
		})
	}
}

func TestDefaultRevocationShared(t *testing.T) {
	a, errA := opts.DefaultRevocation()
	b, errB := opts.DefaultRevocation()
	if errA != nil || errB != nil {
		t.Fatalf("DefaultRevocation errors = %v, %v; want nil", errA, errB)
	}
	if a == nil || a != b {
		t.Errorf("DefaultRevocation() = %p, %p; want the same non-nil checker", a, b)
	}
}
