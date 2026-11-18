// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package server

import (
	"testing"
	"time"
)

// SetHandshakeBudget sets the known-SNI handshake budget of the ServerConfig
// calls made during the test.
func SetHandshakeBudget(t testing.TB, d time.Duration) {
	old := handshakeBudget
	handshakeBudget = d
	t.Cleanup(func() { handshakeBudget = old })
}
