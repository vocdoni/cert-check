// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/testpki"
)

// specimenSource is the directory prefix of the fingerprint markers' Source,
// which follows the specimens when they move; the golden stores file names.
const specimenSource = "testdata/specimens/"

// TestGoldenDeclarations: every production declaration (AC6 golden of the
// restructure; it proves the providers.go split moved data only).
func TestGoldenDeclarations(t *testing.T) {
	decls := profiles.All()
	for i := range decls {
		for j := range decls[i].Profiles {
			for k := range decls[i].Profiles[j].TestMarkers {
				m := &decls[i].Profiles[j].TestMarkers[k]
				m.Source = strings.TrimPrefix(m.Source, specimenSource)
			}
		}
	}
	got, err := json.MarshalIndent(decls, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	testpki.Golden(t, filepath.Join("..", "..", "testdata", "golden", "declarations.json"), append(got, '\n'))
}
