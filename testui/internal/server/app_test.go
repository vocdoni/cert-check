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

// TestRunShutdownSlowRequests: shutdown cancels in-flight auth validations,
// drains both listeners concurrently under one deadline and closes what is
// left when it expires (U12-ASTRA-3).
func TestRunShutdownSlowRequests(t *testing.T) {
	w := newSrvWorld(t, srvOptions{ocspDelay: 3 * time.Second}) // the validation waits on OCSP
	const drain = 500 * time.Millisecond
	w.app.shutdownWait = drain
	mainLn, authLn := srvListen(t), srvListen(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() { done <- w.app.Run(ctx, mainLn, authLn) })
	waitFor := func(t *testing.T, what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("%s did not happen within 5s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Slow auth request: its validation holds a slot while OCSP stalls.
	authURL, cookie := w.createTx(t, "alpha")
	c := w.authClient(t, authLn.Addr().String(), w.leafCert())
	type authResult struct {
		resp *http.Response
		err  error
		at   time.Time
	}
	authDone := make(chan authResult, 1)
	wg.Go(func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
		if err != nil {
			authDone <- authResult{err: err}
			return
		}
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close() // empty body
		}
		authDone <- authResult{resp, err, time.Now()}
	})
	waitFor(t, "the auth validation", func() bool { return len(w.app.auth.slots) == 1 })

	// Slow main request: the handler waits for a body that never comes.
	slow, err := net.DialTimeout("tcp", mainLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial main: %v", err)
	}
	defer func() { _ = slow.Close() }() // test teardown
	if _, err := io.WriteString(slow, "POST /api/v1/transactions HTTP/1.1\r\nHost: check.test\r\n"+
		"Content-Type: application/json\r\nContent-Length: 64\r\n\r\n{"); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, "the main request", func() bool {
		w.app.createLimiter.mu.Lock()
		defer w.app.createLimiter.mu.Unlock()
		return len(w.app.createLimiter.entries) == 2 // createTx's client and this one
	})

	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Run = %v, want the main drain deadline exceeded", err)
		}
		if d := time.Since(start); d > drain+2*time.Second {
			t.Errorf("Run returned %v after cancel, want about the %v drain", d, drain)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of cancel")
	}
	// The drain deadline closed the slow main connection.
	if err := slow.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := slow.Read(make([]byte, 512)); n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("slow main connection: Read = (%d, %v), want (0, EOF or reset): closed at the deadline", n, err)
	}
	// The auth validation was cancelled when shutdown started: its 303
	// carries a code whose outcome is a retryable error.
	r := <-authDone
	if r.err != nil {
		t.Fatalf("auth request: %v", r.err)
	}
	if d := r.at.Sub(start); d > time.Second {
		t.Errorf("the auth 303 came %v after cancel, want the validation cancelled at once", d)
	}
	m := codeLocationRe.FindStringSubmatch(r.resp.Header.Get("Location"))
	if r.resp.StatusCode != http.StatusSeeOther || m == nil {
		t.Fatalf("auth response = %d %q, want 303 with a code", r.resp.StatusCode, r.resp.Header.Get("Location"))
	}
	if o := w.storedOutcome(t, Secret(m[1]), cookie); o.Err == nil || !o.Err.Retryable {
		t.Errorf("outcome = %+v, want a retryable error", o)
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
