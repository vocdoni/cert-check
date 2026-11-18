// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package testpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Net is a fake network: DNS names map to in-process httptest servers.
// Its DialContext is meant for revocation.Options.DialContext in tests.
type Net struct {
	mu    sync.Mutex
	hosts map[string]string // "host:port" -> listener address
}

// NewNet returns an empty fake network.
func NewNet() *Net { return &Net{hosts: make(map[string]string)} }

// Serve starts an HTTP server for host (plain HTTP, port 80) and registers it.
// The server is closed when the test ends.
func (n *Net) Serve(t testing.TB, host string, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hosts[net.JoinHostPort(host, "80")] = srv.Listener.Addr().String()
	return srv
}

// DialContext routes registered "host:port" pairs to their servers and fails
// for anything else.
func (n *Net) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	target, ok := n.hosts[addr]
	n.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("testpki: no route to %s", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

// Bytes returns a handler serving body with contentType.
func Bytes(contentType string, body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	})
}

// Redirect returns a handler answering 302 to location.
func Redirect(location string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, location, http.StatusFound)
	})
}

// Slow returns a handler that waits d (or until the request is cancelled) before h.
func Slow(d time.Duration, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(d):
			h.ServeHTTP(w, r)
		case <-r.Context().Done():
		}
	})
}

// ServerTLS returns a TLS server certificate for the given DNS names, issued
// by a fresh root, and a pool holding that root (for test clients).
func ServerTLS(t testing.TB, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	root := NewRoot(t, "testpki server root", CertSpec{})
	tpl := CertSpec{
		Subject:     Name{UTF8(OIDCommonName, names[0])},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SANRaw:      dnsSAN(names),
	}
	leaf := root.Leaf(t, tpl)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	return tls.Certificate{Certificate: [][]byte{leaf.Cert.Raw}, PrivateKey: leaf.Key, Leaf: leaf.Cert}, pool
}

func dnsSAN(names []string) []byte {
	var gns [][]byte
	for _, n := range names {
		gns = append(gns, ctx(2, false, []byte(n)))
	}
	return seq(gns...)
}
