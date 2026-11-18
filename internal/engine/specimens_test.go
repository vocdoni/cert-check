// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package engine_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// specimenDir holds the CA-published test leaves and their MANIFEST.md.
const specimenDir = "../../testdata/specimens"

// specimenStatus is the MANIFEST.md "status" column.
type specimenStatus string

const (
	// specimenCommitted rows have their PEM file in specimenDir.
	specimenCommitted specimenStatus = "committed"
	// specimenWithheld rows are pinned by fingerprint only (ruling R30): the
	// file must not be in the repository.
	specimenWithheld specimenStatus = "withheld (R-P1)"
)

func (s specimenStatus) valid() bool {
	return s == specimenCommitted || s == specimenWithheld
}

// specimenRow is one row of testdata/specimens/MANIFEST.md.
type specimenRow struct {
	File     string
	Status   specimenStatus
	SHA256   string // lowercase hex SHA-256 of the DER
	IssuerCN string
	Validity string // "YYYY-MM-DD..YYYY-MM-DD" (UTC dates of notBefore..notAfter)
	Source   string
	Expected string
	// Run1 and Run2 are the expected pipeline codes with production markers
	// and with the test markers emptied (the first word of each half of
	// Expected, split on " / ").
	Run1, Run2 string
}

// specimenManifestColumns is the number of cells in a MANIFEST.md table row.
const specimenManifestColumns = 7

var (
	specimenSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	specimenCodeRe   = regexp.MustCompile(`^[a-z][a-z_]*$`)
)

// readSpecimenManifest parses the MANIFEST.md table rows whose first cell
// names a .pem file.
func readSpecimenManifest(t *testing.T) []specimenRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specimenDir, "MANIFEST.md"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var rows []specimenRow
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i, c := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(c, "`", ""))
		}
		if !strings.HasSuffix(cells[0], ".pem") {
			continue // header, separator or another table
		}
		if len(cells) != specimenManifestColumns {
			t.Fatalf("manifest row %q: got %d cells, want %d", cells[0], len(cells), specimenManifestColumns)
		}
		row := specimenRow{
			File:     cells[0],
			Status:   specimenStatus(cells[1]),
			SHA256:   cells[2],
			IssuerCN: cells[3],
			Validity: cells[4],
			Source:   cells[5],
			Expected: cells[6],
		}
		run1, run2, ok := strings.Cut(row.Expected, " / ")
		if ok {
			row.Run1, _, _ = strings.Cut(strings.TrimSpace(run1), " ")
			row.Run2, _, _ = strings.Cut(strings.TrimSpace(run2), " ")
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		t.Fatal("manifest has no specimen rows")
	}
	return rows
}

func TestSpecimenManifest(t *testing.T) {
	rows := readSpecimenManifest(t)

	listed := make(map[string]specimenRow, len(rows))
	for _, r := range rows {
		if _, dup := listed[r.File]; dup {
			t.Errorf("%s: listed twice", r.File)
		}
		listed[r.File] = r
		if filepath.Base(r.File) != r.File {
			t.Errorf("%s: file must be a bare name", r.File)
		}
		if !r.Status.valid() {
			t.Errorf("%s: status %q, want %q or %q", r.File, r.Status, specimenCommitted, specimenWithheld)
		}
		if !specimenSHA256Re.MatchString(r.SHA256) {
			t.Errorf("%s: sha256 %q is not 64 lowercase hex digits", r.File, r.SHA256)
		}
		if r.IssuerCN == "" || r.Source == "" {
			t.Errorf("%s: issuer CN and source must be filled", r.File)
		}
		if !specimenCodeRe.MatchString(r.Run1) || !specimenCodeRe.MatchString(r.Run2) {
			t.Errorf("%s: expected result %q, want \"<code> ... / <code> ...\"", r.File, r.Expected)
		}
	}

	for _, r := range rows {
		path := filepath.Join(specimenDir, r.File)
		if r.Status == specimenWithheld {
			if _, err := os.Stat(path); err == nil {
				t.Errorf("%s: withheld specimen is present in %s; it must not be committed (R30)", r.File, specimenDir)
			}
			continue
		}
		t.Run(r.File, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----\n")) {
				t.Errorf("file does not start with a PEM CERTIFICATE header (no leading text allowed)")
			}
			block, rest := pem.Decode(raw)
			if block == nil {
				t.Fatal("no PEM block")
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				t.Errorf("PEM block type %q with %d headers, want CERTIFICATE without headers", block.Type, len(block.Headers))
			}
			if len(bytes.TrimSpace(rest)) != 0 {
				t.Errorf("%d bytes after the PEM block, want exactly one block", len(rest))
			}
			sum := sha256.Sum256(block.Bytes)
			if got := hex.EncodeToString(sum[:]); got != r.SHA256 {
				t.Errorf("DER sha256 = %s, want %s", got, r.SHA256)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if got := cert.Issuer.CommonName; got != r.IssuerCN {
				t.Errorf("issuer CN = %q, want %q", got, r.IssuerCN)
			}
			validity := cert.NotBefore.UTC().Format(time.DateOnly) + ".." + cert.NotAfter.UTC().Format(time.DateOnly)
			if validity != r.Validity {
				t.Errorf("validity = %s, want %s", validity, r.Validity)
			}
		})
	}

	entries, err := os.ReadDir(specimenDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		if r, ok := listed[e.Name()]; !ok || r.Status != specimenCommitted {
			t.Errorf("%s: present in %s but not listed as %q in MANIFEST.md", e.Name(), specimenDir, specimenCommitted)
		}
	}
}
