// Package config loads and validates the environment configuration.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// redacted is what a Secret prints in place of its content.
const redacted = "[redacted]"

// Secret holds a sensitive value; it never prints or logs its content.
type Secret string

// String redacts the value.
func (Secret) String() string { return redacted }

// GoString redacts the value for %#v.
func (Secret) GoString() string { return redacted }

// LogValue redacts the value in slog.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText redacts the value for encoding/json and other text encoders.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Reveal returns the raw value (only for the Cloudflare client).
func (s Secret) Reveal() string { return string(s) }

// ACMECA selects the Let's Encrypt directory.
type ACMECA string

// ACME CAs.
const (
	ACMEProduction ACMECA = "production"
	ACMEStaging    ACMECA = "staging"
)

// CertMode is how the auth listener gets its certificate.
type CertMode int

// Certificate modes.
const (
	CertACME CertMode = iota + 1
	CertStatic
)

// Config is the validated configuration (spec "Configuration").
type Config struct {
	Port                  int      // PORT, default 8080
	PublicURL             *url.URL // CERTCHECK_PUBLIC_URL, required; https (http only for localhost/127.0.0.1)
	AuthDomain            string   // CERTCHECK_AUTH_DOMAIN, required, lowercase DNS name
	AuthPublicPort        int      // CERTCHECK_AUTH_PUBLIC_PORT, default $RAILWAY_TCP_PROXY_PORT; required
	AuthListen            string   // CERTCHECK_AUTH_LISTEN, default ":8443"
	DataDir               string   // CERTCHECK_DATA_DIR, default "/data"
	CertMode              CertMode
	ACMEEmail             string // CERTCHECK_ACME_EMAIL, required with ACME
	ACMECA                ACMECA // CERTCHECK_ACME_CA, default production
	CloudflareToken       Secret // CLOUDFLARE_API_TOKEN, required with ACME
	ACMEDNSOverrideDomain string // CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN, optional
	TLSCertFile           string // CERTCHECK_TLS_CERT_FILE (static mode, with _KEY_FILE)
	TLSKeyFile            string // CERTCHECK_TLS_KEY_FILE
	AuthTLS13             bool   // CERTCHECK_AUTH_TLS13, default false
	TrustedProxyHops      int    // CERTCHECK_TRUSTED_PROXY_HOPS, default 1, >= 0
	LogLevel              slog.Level
}

var dnsNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Load reads the configuration through getenv (os.Getenv in main). All
// problems are reported together; no secret value appears in errors.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	c := Config{AuthListen: ":8443", DataDir: "/data", ACMECA: ACMEProduction, TrustedProxyHops: 1, LogLevel: slog.LevelInfo}
	intVar := func(name, def string, lo, hi int, dst *int) {
		v := getenv(name)
		if v == "" {
			v = def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			errs = append(errs, fmt.Errorf("%s must be an integer in [%d,%d]", name, lo, hi))
			return
		}
		*dst = n
	}
	intVar("PORT", "8080", 1, 65535, &c.Port)
	intVar("CERTCHECK_AUTH_PUBLIC_PORT", getenv("RAILWAY_TCP_PROXY_PORT"), 1, 65535, &c.AuthPublicPort)
	intVar("CERTCHECK_TRUSTED_PROXY_HOPS", "1", 0, 10, &c.TrustedProxyHops)

	if u, ok := parsePublicURL(getenv("CERTCHECK_PUBLIC_URL")); ok {
		c.PublicURL = u
	} else {
		errs = append(errs, errors.New("CERTCHECK_PUBLIC_URL must be an https origin (http only for localhost)"))
	}
	c.AuthDomain = getenv("CERTCHECK_AUTH_DOMAIN")
	if !dnsNameRe.MatchString(c.AuthDomain) {
		errs = append(errs, errors.New("CERTCHECK_AUTH_DOMAIN must be a lowercase DNS name"))
	}
	if v := getenv("CERTCHECK_AUTH_LISTEN"); v != "" {
		c.AuthListen = v
	}
	if v := getenv("CERTCHECK_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	c.TLSCertFile, c.TLSKeyFile = getenv("CERTCHECK_TLS_CERT_FILE"), getenv("CERTCHECK_TLS_KEY_FILE")
	c.ACMEEmail, c.CloudflareToken = getenv("CERTCHECK_ACME_EMAIL"), Secret(getenv("CLOUDFLARE_API_TOKEN"))
	c.ACMEDNSOverrideDomain = getenv("CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN")
	switch {
	case c.TLSCertFile != "" || c.TLSKeyFile != "":
		c.CertMode = CertStatic
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			errs = append(errs, errors.New("CERTCHECK_TLS_CERT_FILE and CERTCHECK_TLS_KEY_FILE go together"))
		}
		if c.ACMEEmail != "" || c.CloudflareToken != "" || c.ACMEDNSOverrideDomain != "" {
			errs = append(errs, errors.New("CERTCHECK_TLS_CERT_FILE and CERTCHECK_TLS_KEY_FILE are mutually exclusive with "+
				"CERTCHECK_ACME_EMAIL, CLOUDFLARE_API_TOKEN and CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN"))
		}
	default:
		c.CertMode = CertACME
		if c.ACMEEmail == "" || !strings.Contains(c.ACMEEmail, "@") {
			errs = append(errs, errors.New("CERTCHECK_ACME_EMAIL is required with ACME"))
		}
		if c.CloudflareToken == "" {
			errs = append(errs, errors.New("CLOUDFLARE_API_TOKEN is required with ACME"))
		}
		if d := c.ACMEDNSOverrideDomain; d != "" && !dnsNameRe.MatchString(strings.TrimPrefix(d, "_acme-challenge.")) {
			errs = append(errs, errors.New("CERTCHECK_ACME_DNS_OVERRIDE_DOMAIN must be a DNS name"))
		}
	}
	switch v := ACMECA(getenv("CERTCHECK_ACME_CA")); v {
	case "":
	case ACMEProduction, ACMEStaging:
		c.ACMECA = v
	default:
		errs = append(errs, errors.New("CERTCHECK_ACME_CA must be production or staging"))
	}
	switch v := getenv("CERTCHECK_AUTH_TLS13"); v {
	case "", "false":
	case "true":
		c.AuthTLS13 = true
	default:
		errs = append(errs, errors.New("CERTCHECK_AUTH_TLS13 must be true or false"))
	}
	if v := getenv("CERTCHECK_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, errors.New("CERTCHECK_LOG_LEVEL must be debug, info, warn or error"))
		}
	}
	return c, errors.Join(errs...)
}

// parsePublicURL accepts an https origin, or an http one for localhost and
// 127.0.0.1 only. A trailing "/" is dropped; any other path, a query, a
// fragment or userinfo is rejected.
func parsePublicURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, false
	}
	if u.Path != "" && u.Path != "/" {
		return nil, false
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && (u.Scheme != "http" || !local) {
		return nil, false
	}
	u.Path = ""
	return u, true
}
