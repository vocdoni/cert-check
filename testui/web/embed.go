// Package web holds the embedded static UI (no build step).
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var static embed.FS

// FS returns the UI files rooted at static/.
func FS() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic("web: embedded static directory missing: " + err.Error()) // build-time invariant
	}
	return sub
}
