package testpki

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden rewrites the AC6 golden files. It is used once, on the base
// commit of the library restructure; afterwards the goldens never change.
var updateGolden = flag.Bool("update-golden", false, "rewrite the golden files under testdata/golden")

// Golden compares got with the golden file at path, or rewrites the file when
// the test binary runs with -update-golden. A mismatch reports the first
// differing line.
func Golden(t testing.TB, path string, got []byte) {
	t.Helper()
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v", path, err)
	}
	if bytes.Equal(got, want) {
		return
	}
	gotLines, wantLines := bytes.Split(got, []byte("\n")), bytes.Split(want, []byte("\n"))
	for i := range max(len(gotLines), len(wantLines)) {
		var g, w []byte
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if !bytes.Equal(g, w) {
			t.Fatalf("golden %s differs at line %d:\n got: %s\nwant: %s", path, i+1, g, w)
		}
	}
}
