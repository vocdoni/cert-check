package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/testui/web"
)

// TestServerTimeouts covers U14-ASTRA-4: the dev server bounds every phase of a connection.
func TestServerTimeouts(t *testing.T) {
	srv := newServer(http.NotFoundHandler())
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	} {
		if d <= 0 || d > time.Minute {
			t.Errorf("%s = %v, want a finite deadline of at most a minute", name, d)
		}
	}
	if srv.ReadTimeout < srv.ReadHeaderTimeout {
		t.Errorf("ReadTimeout %v is shorter than ReadHeaderTimeout %v", srv.ReadTimeout, srv.ReadHeaderTimeout)
	}
}

// TestHeadersMatchProduction covers U14-FABLE-3: the dev server sends the production security
// headers (web.SecurityHeaders, which the main listener uses), so the offline UI checks run under
// the deployed CSP.
func TestHeadersMatchProduction(t *testing.T) {
	root, err := os.OpenRoot("../../testdata/fixtures")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	h := newHandler(root, 8090)
	production := web.SecurityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, target := range []string{"/", "/app.js", "/api/v1/providers", "/api/v1/transactions/current", "/__auth?state=x"} {
		t.Run(target, func(t *testing.T) {
			got, want := httptest.NewRecorder(), httptest.NewRecorder()
			h.ServeHTTP(got, httptest.NewRequest(http.MethodGet, target, nil))
			production.ServeHTTP(want, httptest.NewRequest(http.MethodGet, target, nil))
			for _, k := range []string{"Content-Security-Policy", "Referrer-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "Cache-Control"} {
				if g, w := got.Header().Values(k), want.Header().Values(k); !slices.Equal(g, w) {
					t.Errorf("%s = %q, want %q (production)", k, g, w)
				}
			}
		})
	}
}
