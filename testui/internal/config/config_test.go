package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

const testToken = "tok-SECRET-123"

// acmeEnv is a minimal valid ACME environment.
func acmeEnv() map[string]string {
	return map[string]string{
		"CERTCHECK_PUBLIC_URL":       "https://cert.example.org",
		"CERTCHECK_AUTH_DOMAIN":      "auth.example.org",
		"CERTCHECK_AUTH_PUBLIC_PORT": "443",
		"CERTCHECK_ACME_EMAIL":       "ops@example.org",
		"CLOUDFLARE_API_TOKEN":       testToken,
	}
}

// staticEnv is a minimal valid static-certificate environment.
func staticEnv(dir string) map[string]string {
	env := acmeEnv()
	delete(env, "CERTCHECK_ACME_EMAIL")
	delete(env, "CLOUDFLARE_API_TOKEN")
	env["CERTCHECK_TLS_CERT_FILE"] = filepath.Join(dir, "cert.pem")
	env["CERTCHECK_TLS_KEY_FILE"] = filepath.Join(dir, "key.pem")
	return env
}

// withVar returns a builder for an ACME environment with one variable set.
func withVar(k, v string) func() map[string]string {
	return func() map[string]string {
		env := acmeEnv()
		env[k] = v
		return env
	}
}

// without returns a builder for an ACME environment with one variable removed.
func without(k string) func() map[string]string {
	return func() map[string]string {
		env := acmeEnv()
		delete(env, k)
		return env
	}
}

func getenvFrom(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(getenvFrom(acmeEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"Port", c.Port, 8080},
		{"AuthListen", c.AuthListen, ":8443"},
		{"DataDir", c.DataDir, "/data"},
		{"ACMECA", c.ACMECA, ACMEProduction},
		{"TrustedProxyHops", c.TrustedProxyHops, 1},
		{"LogLevel", c.LogLevel, slog.LevelInfo},
		{"CertMode", c.CertMode, CertACME},
		{"AuthTLS13", c.AuthTLS13, false},
		{"AuthPublicPort", c.AuthPublicPort, 443},
		{"AuthDomain", c.AuthDomain, "auth.example.org"},
		{"PublicURL", c.PublicURL.String(), "https://cert.example.org"},
		{"ACMEEmail", c.ACMEEmail, "ops@example.org"},
		{"CloudflareToken", c.CloudflareToken.Reveal(), testToken},
		{"ACMEDNSOverrideDomain", c.ACMEDNSOverrideDomain, ""},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestLoadOverrides(t *testing.T) {
	env := acmeEnv()
	env["PORT"] = "9090"
	env["CERTCHECK_AUTH_LISTEN"] = "127.0.0.1:9443"
	env["CERTCHECK_DATA_DIR"] = "/var/lib/cert-check"
	env["CERTCHECK_ACME_CA"] = "staging"
	env["CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN"] = "_acme-challenge.delegate.example.net"
	env["CERTCHECK_AUTH_TLS13"] = "true"
	env["CERTCHECK_TRUSTED_PROXY_HOPS"] = "0"
	env["CERTCHECK_LOG_LEVEL"] = "debug"
	c, err := Load(getenvFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"Port", c.Port, 9090},
		{"AuthListen", c.AuthListen, "127.0.0.1:9443"},
		{"DataDir", c.DataDir, "/var/lib/cert-check"},
		{"ACMECA", c.ACMECA, ACMEStaging},
		{"ACMEDNSOverrideDomain", c.ACMEDNSOverrideDomain, "_acme-challenge.delegate.example.net"},
		{"AuthTLS13", c.AuthTLS13, true},
		{"TrustedProxyHops", c.TrustedProxyHops, 0},
		{"LogLevel", c.LogLevel, slog.LevelDebug},
	}
	for _, tc := range checks {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		env  func() map[string]string
		want string // variable the error must name
	}{
		{"missing public url", without("CERTCHECK_PUBLIC_URL"), "CERTCHECK_PUBLIC_URL"},
		{"plain http public url", withVar("CERTCHECK_PUBLIC_URL", "http://example.org"), "CERTCHECK_PUBLIC_URL"},
		{"public url with path", withVar("CERTCHECK_PUBLIC_URL", "https://example.org/app"), "CERTCHECK_PUBLIC_URL"},
		{"public url with query", withVar("CERTCHECK_PUBLIC_URL", "https://example.org?a=1"), "CERTCHECK_PUBLIC_URL"},
		{"public url with fragment", withVar("CERTCHECK_PUBLIC_URL", "https://example.org#f"), "CERTCHECK_PUBLIC_URL"},
		{"public url with userinfo", withVar("CERTCHECK_PUBLIC_URL", "https://user:pw@example.org"), "CERTCHECK_PUBLIC_URL"},
		{"public url without host", withVar("CERTCHECK_PUBLIC_URL", "https:///"), "CERTCHECK_PUBLIC_URL"},
		{"public url unsupported scheme", withVar("CERTCHECK_PUBLIC_URL", "ftp://example.org"), "CERTCHECK_PUBLIC_URL"},
		{"http on a lookalike host", withVar("CERTCHECK_PUBLIC_URL", "http://localhost.example.org"), "CERTCHECK_PUBLIC_URL"},
		{"public url port zero", withVar("CERTCHECK_PUBLIC_URL", "https://example.org:0"), "CERTCHECK_PUBLIC_URL"},
		{"public url port too large", withVar("CERTCHECK_PUBLIC_URL", "https://example.org:65536"), "CERTCHECK_PUBLIC_URL"},
		{"public url empty port", withVar("CERTCHECK_PUBLIC_URL", "https://example.org:"), "CERTCHECK_PUBLIC_URL"},
		{"public url port not a number", withVar("CERTCHECK_PUBLIC_URL", "https://example.org:abc"), "CERTCHECK_PUBLIC_URL"},
		{"public url with empty query", withVar("CERTCHECK_PUBLIC_URL", "https://example.org/?"), "CERTCHECK_PUBLIC_URL"},
		{"public url with empty userinfo", withVar("CERTCHECK_PUBLIC_URL", "https://@example.org"), "CERTCHECK_PUBLIC_URL"},
		{"auth domain uppercase", withVar("CERTCHECK_AUTH_DOMAIN", "Auth.Example.org"), "CERTCHECK_AUTH_DOMAIN"},
		{"auth domain single label", withVar("CERTCHECK_AUTH_DOMAIN", "x"), "CERTCHECK_AUTH_DOMAIN"},
		{"auth domain empty", withVar("CERTCHECK_AUTH_DOMAIN", ""), "CERTCHECK_AUTH_DOMAIN"},
		{"port zero", withVar("PORT", "0"), "PORT"},
		{"port too large", withVar("PORT", "70000"), "PORT"},
		{"port not a number", withVar("PORT", "abc"), "PORT"},
		{"auth port zero", withVar("CERTCHECK_AUTH_PUBLIC_PORT", "0"), "CERTCHECK_AUTH_PUBLIC_PORT"},
		{"auth port too large", withVar("CERTCHECK_AUTH_PUBLIC_PORT", "70000"), "CERTCHECK_AUTH_PUBLIC_PORT"},
		{"auth port not a number", withVar("CERTCHECK_AUTH_PUBLIC_PORT", "abc"), "CERTCHECK_AUTH_PUBLIC_PORT"},
		{"auth port missing", without("CERTCHECK_AUTH_PUBLIC_PORT"), "CERTCHECK_AUTH_PUBLIC_PORT"},
		{"auth listen port zero", withVar("CERTCHECK_AUTH_LISTEN", ":0"), "CERTCHECK_AUTH_LISTEN"},
		{"auth listen empty port", withVar("CERTCHECK_AUTH_LISTEN", "127.0.0.1:"), "CERTCHECK_AUTH_LISTEN"},
		{"auth listen port too large", withVar("CERTCHECK_AUTH_LISTEN", ":65536"), "CERTCHECK_AUTH_LISTEN"},
		{"auth listen port not a number", withVar("CERTCHECK_AUTH_LISTEN", ":https"), "CERTCHECK_AUTH_LISTEN"},
		{"auth listen signed port", withVar("CERTCHECK_AUTH_LISTEN", ":+8443"), "CERTCHECK_AUTH_LISTEN"},
		{"auth listen without port", withVar("CERTCHECK_AUTH_LISTEN", "8443"), "CERTCHECK_AUTH_LISTEN"},
		{"static cert without key", func() map[string]string {
			env := staticEnv(dir)
			delete(env, "CERTCHECK_TLS_KEY_FILE")
			return env
		}, "CERTCHECK_TLS_KEY_FILE"},
		{"static key without cert", func() map[string]string {
			env := staticEnv(dir)
			delete(env, "CERTCHECK_TLS_CERT_FILE")
			return env
		}, "CERTCHECK_TLS_CERT_FILE"},
		{"static with acme email", func() map[string]string {
			env := staticEnv(dir)
			env["CERTCHECK_ACME_EMAIL"] = "ops@example.org"
			return env
		}, "CERTCHECK_ACME_EMAIL"},
		{"static with cloudflare token", func() map[string]string {
			env := staticEnv(dir)
			env["CLOUDFLARE_API_TOKEN"] = testToken
			return env
		}, "CLOUDFLARE_API_TOKEN"},
		{"static with override domain", func() map[string]string {
			env := staticEnv(dir)
			env["CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN"] = "delegate.example.net"
			return env
		}, "CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN"},
		{"acme without email", without("CERTCHECK_ACME_EMAIL"), "CERTCHECK_ACME_EMAIL"},
		{"acme email without at", withVar("CERTCHECK_ACME_EMAIL", "ops.example.org"), "CERTCHECK_ACME_EMAIL"},
		{"acme without token", without("CLOUDFLARE_API_TOKEN"), "CLOUDFLARE_API_TOKEN"},
		{"bad override domain", withVar("CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN", "not a domain"), "CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN"},
		{"bad acme ca", withVar("CERTCHECK_ACME_CA", "prod"), "CERTCHECK_ACME_CA"},
		{"bad tls13", withVar("CERTCHECK_AUTH_TLS13", "yes"), "CERTCHECK_AUTH_TLS13"},
		{"negative hops", withVar("CERTCHECK_TRUSTED_PROXY_HOPS", "-1"), "CERTCHECK_TRUSTED_PROXY_HOPS"},
		{"too many hops", withVar("CERTCHECK_TRUSTED_PROXY_HOPS", "11"), "CERTCHECK_TRUSTED_PROXY_HOPS"},
		{"bad log level", withVar("CERTCHECK_LOG_LEVEL", "trace"), "CERTCHECK_LOG_LEVEL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(getenvFrom(tc.env()))
			if err == nil {
				t.Fatalf("Load succeeded, want an error naming %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error = %q, must not contain the token value", err)
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	env := map[string]string{"PORT": "abc", "CERTCHECK_LOG_LEVEL": "trace", "CERTCHECK_ACME_CA": "prod"}
	_, err := Load(getenvFrom(env))
	if err == nil {
		t.Fatal("Load succeeded on a broken environment")
	}
	for _, v := range []string{
		"PORT", "CERTCHECK_AUTH_PUBLIC_PORT", "CERTCHECK_PUBLIC_URL", "CERTCHECK_AUTH_DOMAIN",
		"CERTCHECK_ACME_EMAIL", "CLOUDFLARE_API_TOKEN", "CERTCHECK_ACME_CA", "CERTCHECK_LOG_LEVEL",
	} {
		if !strings.Contains(err.Error(), v) {
			t.Errorf("error = %q, want it to name %s", err, v)
		}
	}
}

func TestLoadRailwayPort(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		railway  string
		want     int
	}{
		{"railway only", "", "12345", 12345},
		{"explicit wins", "443", "12345", 443},
		{"explicit only", "8443", "", 8443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := acmeEnv()
			delete(env, "CERTCHECK_AUTH_PUBLIC_PORT")
			if tc.explicit != "" {
				env["CERTCHECK_AUTH_PUBLIC_PORT"] = tc.explicit
			}
			if tc.railway != "" {
				env["RAILWAY_TCP_PROXY_PORT"] = tc.railway
			}
			c, err := Load(getenvFrom(env))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if c.AuthPublicPort != tc.want {
				t.Errorf("AuthPublicPort = %d, want %d", c.AuthPublicPort, tc.want)
			}
		})
	}
}

func TestLoadStatic(t *testing.T) {
	env := staticEnv(t.TempDir())
	c, err := Load(getenvFrom(env))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CertMode != CertStatic {
		t.Errorf("CertMode = %v, want CertStatic (%v)", c.CertMode, CertStatic)
	}
	if c.TLSCertFile != env["CERTCHECK_TLS_CERT_FILE"] || c.TLSKeyFile != env["CERTCHECK_TLS_KEY_FILE"] {
		t.Errorf("TLS files = %q, %q, want %q, %q", c.TLSCertFile, c.TLSKeyFile,
			env["CERTCHECK_TLS_CERT_FILE"], env["CERTCHECK_TLS_KEY_FILE"])
	}
}

func TestLoadLocalhostHTTP(t *testing.T) {
	tests := []struct {
		raw      string
		wantHost string
	}{
		{"http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"http://localhost:8080", "localhost:8080"},
		{"http://localhost:8080/", "localhost:8080"},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			c, err := Load(getenvFrom(withVar("CERTCHECK_PUBLIC_URL", tc.raw)()))
			if err != nil {
				t.Fatalf("Load(%q): %v", tc.raw, err)
			}
			if c.PublicURL.Path != "" {
				t.Errorf("PublicURL.Path = %q, want empty", c.PublicURL.Path)
			}
			if c.PublicURL.Host != tc.wantHost {
				t.Errorf("PublicURL.Host = %q, want %q", c.PublicURL.Host, tc.wantHost)
			}
		})
	}
}

// TestLoadPublicURLNormalised: the public URL is the origin a browser sends
// (lowercase host, no default port), so the Origin check can compare it
// exactly (U12-ASTRA-4).
func TestLoadPublicURLNormalised(t *testing.T) {
	tests := []struct{ raw, want string }{
		{"https://cert.example.org", "https://cert.example.org"},
		{"https://Cert.Example.ORG", "https://cert.example.org"},
		{"https://cert.example.org:443", "https://cert.example.org"},
		{"https://cert.example.org:443/", "https://cert.example.org"},
		{"https://cert.example.org:0443", "https://cert.example.org"},
		{"https://cert.example.org:8443", "https://cert.example.org:8443"},
		{"https://cert.example.org:08443", "https://cert.example.org:8443"},
		{"HTTPS://cert.example.org", "https://cert.example.org"},
		{"https://[2001:DB8::1]:443", "https://[2001:db8::1]"},
		{"https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"},
		{"http://LOCALHOST:8080", "http://localhost:8080"},
		{"http://localhost:80", "http://localhost"},
		{"http://127.0.0.1:80/", "http://127.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			c, err := Load(getenvFrom(withVar("CERTCHECK_PUBLIC_URL", tc.raw)()))
			if err != nil {
				t.Fatalf("Load(%q): %v", tc.raw, err)
			}
			if got := c.PublicURL.Scheme + "://" + c.PublicURL.Host; got != tc.want {
				t.Errorf("origin = %q, want %q", got, tc.want)
			}
			if got := c.PublicURL.String(); got != tc.want {
				t.Errorf("PublicURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLoadAuthListen(t *testing.T) {
	for _, v := range []string{":8443", "127.0.0.1:1", "[::1]:65535", "localhost:9443"} {
		t.Run(v, func(t *testing.T) {
			c, err := Load(getenvFrom(withVar("CERTCHECK_AUTH_LISTEN", v)()))
			if err != nil {
				t.Fatalf("Load(%q): %v", v, err)
			}
			if c.AuthListen != v {
				t.Errorf("AuthListen = %q, want %q", c.AuthListen, v)
			}
		})
	}
}

func TestSecretRedaction(t *testing.T) {
	c, err := Load(getenvFrom(acmeEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var jsonLog, textLog bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonLog, nil)).Info("loaded", "token", c.CloudflareToken, "config", c)
	slog.New(slog.NewTextHandler(&textLog, nil)).Info("loaded", "token", c.CloudflareToken, "config", c)
	marshaled, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	outputs := map[string]string{
		"Sprint(Config)":  fmt.Sprint(c),
		"Sprint(Secret)":  fmt.Sprint(c.CloudflareToken),
		"%v Config":       fmt.Sprintf("%v", c),
		"%+v Config":      fmt.Sprintf("%+v", c),
		"%#v Config":      fmt.Sprintf("%#v", c),
		"%s Secret":       fmt.Sprintf("secret=%s", c.CloudflareToken),
		"%q Secret":       fmt.Sprintf("%q", c.CloudflareToken),
		"slog json":       jsonLog.String(),
		"slog text":       textLog.String(),
		"json.Marshal(c)": string(marshaled),
	}
	for name, got := range outputs {
		if strings.Contains(got, testToken) {
			t.Errorf("%s shows the token: %s", name, got)
		}
	}
	if got, want := fmt.Sprint(c.CloudflareToken), "[redacted]"; got != want {
		t.Errorf("Sprint(Secret) = %q, want %q", got, want)
	}
	if got, want := c.CloudflareToken.Reveal(), testToken; got != want {
		t.Errorf("Reveal() = %q, want %q", got, want)
	}
}
