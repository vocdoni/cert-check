// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/identity"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// AC6 goldens of the library restructure, captured on its base commit: the
// pipeline outcome of every committed specimen under every production
// provider, and the full Result JSON of every synthetic profile fixture.
const (
	goldenDir         = "../../testdata/golden"
	goldenSpecimenDir = "../../testdata/specimens"
)

var (
	goldenTimeRe = regexp.MustCompile(`"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)"`)
	goldenMaskRe = regexp.MustCompile(`"(diagnosticId|serialHex|sha256)":"[0-9a-f]*"`)
	goldenDurRe  = regexp.MustCompile(`"durationMs":\d+`)
)

// goldenMask rewrites the values that change from run to run: random
// diagnostic IDs, serials and hashes, durations, and times (as offsets from
// the fixture clock). Everything else is compared byte for byte.
func goldenMask(raw []byte, now time.Time) string {
	s := goldenMaskRe.ReplaceAllString(string(raw), `"$1":"<masked>"`)
	s = goldenDurRe.ReplaceAllString(s, `"durationMs":0`)
	return goldenTimeRe.ReplaceAllStringFunc(s, func(m string) string {
		t, err := time.Parse(time.RFC3339Nano, strings.Trim(m, `"`))
		if err != nil {
			return m
		}
		d := t.Sub(now)
		if d < 0 {
			return `"now-` + (-d).String() + `"`
		}
		return `"now+` + d.String() + `"`
	})
}

// TestGoldenSynthetic: the masked Result (or *Error) JSON of every
// TestProfilesPipeline shape, with OCSP up and with OCSP down.
func TestGoldenSynthetic(t *testing.T) {
	now := tNow()
	p := newPPPKI(t, now)
	var (
		mu  sync.Mutex
		out = map[string]string{}
	)
	t.Run("shapes", func(t *testing.T) {
		for _, s := range ppShapes(t) {
			t.Run(s.name, func(t *testing.T) {
				t.Parallel()
				leaf := p.issue(t, s)
				for _, mode := range []struct {
					name string
					mode ppMode
				}{{"ocsp", ppOCSPUp}, {"ocsp-down", ppOCSPDown}} {
					res, err := p.check(t, s, leaf, mode.mode, nil)
					var raw []byte
					var merr error
					if err != nil {
						raw, merr = json.Marshal(tErr(t, err))
					} else {
						raw, merr = json.Marshal(res)
					}
					if merr != nil {
						t.Fatal(merr)
					}
					mu.Lock()
					out[s.name+"|"+mode.name] = goldenMask(raw, now)
					mu.Unlock()
				}
			})
		}
	})
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(out)) {
		b.WriteString(`{"case":"` + k + `","json":` + out[k] + "}\n")
	}
	testpki.Golden(t, filepath.Join(goldenDir, "synthetic.jsonl"), []byte(b.String()))
}

// goldenSpecimen is one specimen golden row.
type goldenSpecimen struct {
	Case               string            `json:"case"` // file|provider|run
	Code               ErrorCode         `json:"code"`
	Retryable          bool              `json:"retryable"`
	Step               Step              `json:"step"`
	Detail             string            `json:"detail"`
	Provider           string            `json:"provider"`
	ProfileCandidates  []CandidateResult `json:"profileCandidates"`
	RevocationAttempts int               `json:"revocationAttempts"`
}

func goldenNoNetwork(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("golden: no network")
}

// TestGoldenSpecimens: every committed specimen presented to every
// production provider, clock at NotBefore+30m, no network; run "markers"
// uses the production test markers and reserved identities, run "emptied"
// empties both (the pipeline then reaches revocation).
func TestGoldenSpecimens(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(goldenSpecimenDir, "*.pem"))
	if err != nil || len(files) != 29 {
		t.Fatalf("specimens: %v (%d files, want 29)", err, len(files))
	}
	var b strings.Builder
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(raw)
		if blk == nil {
			t.Fatalf("%s: no PEM block", f)
		}
		leaf, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		clock := leaf.NotBefore.Add(30 * time.Minute)
		now := func() time.Time { return clock }
		for _, run := range []string{"markers", "emptied"} {
			decls, reserved := profiles.All(), identity.DefaultReserved()
			if run == "emptied" {
				for i := range decls {
					for j := range decls[i].Profiles {
						decls[i].Profiles[j].TestMarkers = nil
					}
				}
				reserved = identity.Reserved{}
			}
			rc, err := revocation.NewChecker(revocation.Options{DialContext: goldenNoNetwork, Now: now, Logger: tDiscard})
			if err != nil {
				t.Fatal(err)
			}
			var enabled []certcheck.Provider
			for _, d := range decls {
				p, err := New(Config{Provider: d, Revocation: rc, Now: now, Logger: tDiscard, Reserved: &reserved})
				if err != nil {
					t.Fatal(err)
				}
				if len(p.CAs()) > 0 { // the registry hid providers without an enabled profile
					enabled = append(enabled, p)
				}
			}
			h, err := certcheck.NewHandler(enabled, certcheck.WithClock(now))
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range profiles.All() {
				res, err := h.VerifyAs(t.Context(), d.ID, []*x509.Certificate{leaf})
				e, ok := errors.AsType[*Error](err)
				if !ok || res != nil {
					t.Fatalf("%s on %s (%s): (%v, %v), want *Error", filepath.Base(f), d.ID, run, res, err)
				}
				line, err := json.Marshal(goldenSpecimen{Case: filepath.Base(f) + "|" + d.ID + "|" + run, Code: e.Code,
					Retryable: e.Retryable, Step: e.Diagnostics.FailedStep, Detail: e.Detail, Provider: e.Diagnostics.Provider,
					ProfileCandidates: e.Diagnostics.ProfileCandidates, RevocationAttempts: len(e.Diagnostics.RevocationAttempts)})
				if err != nil {
					t.Fatal(err)
				}
				b.Write(line)
				b.WriteByte('\n')
			}
		}
	}
	testpki.Golden(t, filepath.Join(goldenDir, "specimens.jsonl"), []byte(b.String()))
}
