package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
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
