package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRunShutdown(t *testing.T) {
	cases := []struct {
		name  string
		ready bool // false: the certificate never becomes ready (ruling R42)
	}{
		{"serving", true},
		{"certificate never ready", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newSrvWorld(t, srvOptions{notReady: !c.ready})
			mainLn, authLn := srvListen(t), srvListen(t)
			mainAddr, authAddr := mainLn.Addr().String(), authLn.Addr().String()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			var wg sync.WaitGroup
			wg.Go(func() { done <- w.app.Run(ctx, mainLn, authLn) })
			defer wg.Wait()

			// Wait until the main listener serves (and, when ready, until /readyz is 200).
			client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			want := http.StatusServiceUnavailable
			if c.ready {
				want = http.StatusOK
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				resp, err := client.Get("http://" + mainAddr + "/readyz")
				if err == nil {
					_ = resp.Body.Close() // empty body
					if resp.StatusCode == want {
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatalf("/readyz did not answer %d within 5s (last error %v)", want, err)
				}
				time.Sleep(20 * time.Millisecond)
			}

			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run = %v, want nil", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Run did not return within 2s of cancel")
			}
			for name, addr := range map[string]string{"main": mainAddr, "auth": authAddr} {
				if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
					_ = conn.Close() // the listener should not exist
					t.Errorf("%s listener %s still accepts connections after Run returned", name, addr)
				}
			}
		})
	}
}

func TestRunAuthWaitsForCert(t *testing.T) {
	w := newSrvWorld(t, srvOptions{notReady: true})
	run := w.start(t)
	cfg := &tls.Config{ServerName: srvAlphaHost, RootCAs: w.serverPool}
	handshake := func(t *testing.T, timeout time.Duration) error {
		t.Helper()
		conn, err := net.DialTimeout("tcp", run.authAddr, time.Second)
		if err != nil {
			t.Fatalf("the auth port does not accept TCP: %v", err)
		}
		defer func() { _ = conn.Close() }() // test connection
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		return tls.Client(conn, cfg).HandshakeContext(t.Context())
	}

	err := handshake(t, 200*time.Millisecond)
	if ne, ok := errors.AsType[net.Error](err); !ok || !ne.Timeout() {
		t.Fatalf("handshake before the certificate is ready = %v, want a client timeout", err)
	}
	w.certs.ready.Store(true)
	if err := handshake(t, 5*time.Second); err != nil {
		t.Fatalf("handshake after the certificate is ready: %v", err)
	}
}

// TestRunMainConnectionCap: the main listener holds at most mainConns
// connections; one more is closed before anything is read (U12-ASTRA-1).
func TestRunMainConnectionCap(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	if w.app.mainConns != MainMaxConns {
		t.Fatalf("mainConns = %d, want MainMaxConns (%d)", w.app.mainConns, MainMaxConns)
	}
	const capacity = 2
	w.app.mainConns = capacity
	run := w.start(t)
	dial := func(t *testing.T) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", run.mainAddr, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() }) // test teardown; a second Close is harmless
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		return c
	}
	// healthz sends one keep-alive request on c and returns the status.
	healthz := func(c net.Conn) (int, error) {
		if _, err := io.WriteString(c, "GET /healthz HTTP/1.1\r\nHost: check.test\r\n\r\n"); err != nil {
			return 0, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close() // empty body
		return resp.StatusCode, nil
	}

	held := make([]net.Conn, capacity)
	for i := range held {
		held[i] = dial(t)
		if st, err := healthz(held[i]); err != nil || st != http.StatusOK {
			t.Fatalf("connection %d: /healthz = (%d, %v), want 200", i+1, st, err)
		}
	}
	extra := dial(t)
	if n, err := extra.Read(make([]byte, 1)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection %d: Read = (%d, %v), want (0, EOF or reset) before any byte", capacity+1, n, err)
	}

	// A released slot serves a new connection (the server notices the close asynchronously).
	_ = held[0].Close() // frees a slot
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := healthz(dial(t))
		if err == nil && st == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection served within 5s of freeing a slot (last: %d, %v)", st, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNewRequiresDeps(t *testing.T) {
	w := newSrvWorld(t, srvOptions{})
	full := Deps{Config: srvConfig(t), Providers: w.providers, Certs: w.certs, Logger: srvDiscard, Version: srvVersion}
	cases := []struct {
		name string
		mod  func(*Deps)
	}{
		{"no providers", func(d *Deps) { d.Providers = nil }},
		{"no certificate source", func(d *Deps) { d.Certs = nil }},
		{"no logger", func(d *Deps) { d.Logger = nil }},
		{"no public URL", func(d *Deps) { d.Config.PublicURL = nil }},
		{"no auth domain", func(d *Deps) { d.Config.AuthDomain = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := full
			c.mod(&d)
			if app, err := New(d); err == nil || app != nil {
				t.Errorf("New = (%v, %v), want (nil, error)", app, err)
			}
		})
	}
	if _, err := New(full); err != nil {
		t.Errorf("New(full deps) = %v, want nil", err)
	}
}
