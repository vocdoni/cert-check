//go:build live

package probe

import (
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// TestLiveProbe (AC8) probes every enabled profile's OCSP responders and
// CRLs over the real network, plus the live specimens: the committed DIGITEL
// one and the withheld Bewor and Sectigo ones from $CERTCHECK_LIVE_SPECIMENS_DIR.
// It logs the report and fails on any FAIL line.
func TestLiveProbe(t *testing.T) {
	dir := os.Getenv("CERTCHECK_LIVE_SPECIMENS_DIR")
	if dir == "" {
		t.Fatal("CERTCHECK_LIVE_SPECIMENS_DIR must name the directory with the withheld specimens (outside the repository)")
	}
	targets, err := DefaultTargets()
	if err != nil {
		t.Fatalf("DefaultTargets: %v", err)
	}
	found := map[string]bool{}
	for _, d := range []string{"../../testdata/specimens", dir} {
		sp, err := LoadSpecimens(os.DirFS(d))
		if err != nil {
			t.Fatalf("LoadSpecimens(%s): %v", d, err)
		}
		for _, tg := range sp {
			found[sha256Hex(tg.Specimen.Raw)] = true
		}
		targets = append(targets, sp...)
	}
	for sha, profile := range specimens {
		if !found[sha] {
			t.Errorf("specimen %s (%s) not found", sha[:16], profile)
		}
	}

	rc, err := revocation.NewChecker(revocation.Options{UserAgent: userAgent, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	var out strings.Builder
	sum, err := Run(t.Context(), rc, targets, time.Now(), &out)
	t.Logf("probe report (%d targets):\n%s", len(targets), out.String())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sum.Failed() {
		t.Errorf("%d FAIL lines", sum.Fail)
	}
}
