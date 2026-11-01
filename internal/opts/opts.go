// Package opts holds the settings that the certcheck options configure. It
// exists so that package certcheck (which declares Option and the With*
// constructors) and internal/engine (which applies them) share one type
// without an import cycle.
package opts

import (
	"log/slog"
	"sync"
	"time"

	"github.com/vocdoni/cert-check/internal/revocation"
)

// Settings is what a certcheck.Option sets. The zero value means "all
// defaults".
type Settings struct {
	Revocation  *revocation.Checker // nil = DefaultRevocation()
	Now         func() time.Time    // nil = time.Now
	Logger      *slog.Logger        // nil = slog.Default()
	Version     string              // Diagnostics.ServerVersion
	MaxChainLen int                 // 0 = certcheck.DefaultMaxChainLen; no public option sets it
}

// Apply returns the settings produced by fns, in order.
func Apply[F ~func(*Settings)](fns ...F) Settings {
	var s Settings
	for _, f := range fns {
		if f != nil {
			f(&s)
		}
	}
	return s
}

// defaultRevocation is the process-wide checker shared by every provider
// built without WithRevocation: fetcher defaults (User-Agent
// "cert-check/dev"), wall clock, slog.Default() at first use.
var defaultRevocation = sync.OnceValues(func() (*revocation.Checker, error) {
	return revocation.NewChecker(revocation.Options{})
})

// DefaultRevocation returns the process-wide revocation checker, creating it
// on first use.
func DefaultRevocation() (*revocation.Checker, error) { return defaultRevocation() }
