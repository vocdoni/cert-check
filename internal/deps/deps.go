//go:build tools

// Package deps pins the allowed direct dependencies until every one is
// imported by real code (removed in Task 13).
package deps

import (
	_ "github.com/caddyserver/certmagic"
	_ "github.com/libdns/cloudflare"
	_ "golang.org/x/crypto/cryptobyte"
	_ "golang.org/x/sync/singleflight"
	_ "golang.org/x/text/unicode/norm"
	_ "golang.org/x/time/rate"
)
