package main

import (
	"strings"
	"testing"
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
