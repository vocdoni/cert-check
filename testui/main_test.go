package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vocdoni/cert-check/testui/internal/probe"
)

func TestRunConfigError(t *testing.T) {
	const token = "tok-SECRET-123"
	env := map[string]string{"CLOUDFLARE_API_TOKEN": token}
	err := run(func(k string) string { return env[k] })
	if err == nil {
		t.Fatal("run = nil, want a configuration error")
	}
	msg := err.Error()
	for _, name := range []string{"CERTCHECK_PUBLIC_URL", "CERTCHECK_AUTH_DOMAIN", "CERTCHECK_AUTH_PUBLIC_PORT"} {
		if !strings.Contains(msg, name) {
			t.Errorf("error %q does not name %s", msg, name)
		}
	}
	if strings.Contains(msg, token) || strings.Contains(msg, "SECRET") {
		t.Errorf("error %q contains the token", msg)
	}
}

func TestProbeSubcommandDispatch(t *testing.T) {
	errProbe := errors.New("probe broke")
	cases := []struct {
		name     string
		args     []string
		sum      probe.Summary
		err      error
		wantCall bool
		wantDirs []string
		wantExit int
		wantErr  string // in stderr
	}{
		{"clean probe", []string{"probe"}, probe.Summary{OK: 3, Warn: 1}, nil, true, []string{}, 0, ""},
		{"specimen directories", []string{"probe", "dir-a", "dir-b"}, probe.Summary{OK: 1}, nil, true, []string{"dir-a", "dir-b"}, 0, ""},
		{"a FAIL line", []string{"probe"}, probe.Summary{OK: 2, Fail: 1}, nil, true, []string{}, 1, ""},
		{"only WARN lines: nothing verified", []string{"probe"}, probe.Summary{Warn: 2}, nil, true, []string{}, 1, ""},
		{"no target: nothing verified", []string{"probe"}, probe.Summary{}, nil, true, []string{}, 1, ""},
		{"cancelled during the last target", []string{"probe"}, probe.Summary{OK: 2}, context.Canceled, true, []string{}, 1, "context canceled"},
		{"probe error", []string{"probe"}, probe.Summary{}, errProbe, true, []string{}, 1, "probe broke"},
		{"no subcommand serves (configuration error)", nil, probe.Summary{}, nil, false, nil, 1, "configuration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var called bool
			var gotDirs []string
			var stdout, stderr strings.Builder
			runner := func(ctx context.Context, dirs []string, w io.Writer) (probe.Summary, error) {
				called, gotDirs = true, dirs
				if ctx == nil {
					t.Error("runner got a nil context")
				}
				if w != &stdout {
					t.Error("runner does not write to stdout")
				}
				return c.sum, c.err
			}
			got := dispatch(c.args, func(string) string { return "" }, runner, &stdout, &stderr)
			if got != c.wantExit {
				t.Errorf("exit = %d, want %d", got, c.wantExit)
			}
			if called != c.wantCall {
				t.Errorf("runner called = %v, want %v", called, c.wantCall)
			}
			if !slices.Equal(gotDirs, c.wantDirs) {
				t.Errorf("specimen dirs = %q, want %q", gotDirs, c.wantDirs)
			}
			if !strings.Contains(stderr.String(), c.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), c.wantErr)
			}
		})
	}
}

// TestProbeSpecimenDirErrors: a specimen directory that cannot be read or
// holds no known live specimen fails the probe before any target is probed
// (U13-FABLE-1), with the directory named on stderr.
func TestProbeSpecimenDirErrors(t *testing.T) {
	dir := t.TempDir()
	for name, d := range map[string]string{
		"missing directory": filepath.Join(dir, "missing"),
		"no known specimen": dir,
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if got := dispatch([]string{"probe", "../testdata/specimens", d}, func(string) string { return "" }, runProbe, &stdout, &stderr); got != 1 {
				t.Errorf("exit = %d, want 1", got)
			}
			if !strings.Contains(stderr.String(), d) {
				t.Errorf("stderr = %q, want it to name %s", stderr.String(), d)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing probed", stdout.String())
			}
		})
	}
}
