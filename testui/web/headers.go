// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
)

// CSP is the main listener's Content-Security-Policy (spec, "Main listener"). The UI loads only
// its own files and has no inline script or style.
const CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// HSTS is the Strict-Transport-Security value of both listeners.
const HSTS = "max-age=31536000"

// SecurityHeaders sets the main listener's security headers on every response, and
// Cache-Control: no-store on the API. The production server and the devserver both serve
// through it, so the offline UI checks run under the deployed policy.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Strict-Transport-Security", HSTS)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
