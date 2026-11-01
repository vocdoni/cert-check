package main

import (
	"net/http"
	"testing"
	"time"
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
