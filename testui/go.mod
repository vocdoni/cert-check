module github.com/vocdoni/cert-check/testui

go 1.27

toolchain go1.27.4

require (
	github.com/caddyserver/certmagic v0.25.6
	github.com/libdns/cloudflare v0.2.2
	github.com/vocdoni/cert-check v0.0.0
	go.uber.org/zap v1.28.0
	golang.org/x/time v0.16.0
)

require (
	github.com/caddyserver/zerossl v0.1.6 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/mholt/acmez/v3 v3.1.7 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/vocdoni/cert-check => ../
