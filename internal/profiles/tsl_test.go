// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package profiles_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/vocdoni/cert-check/internal/profiles"
)

const (
	tslTFile = "spanish_tsl_inventory_2026-10-30.json"
	// tslTSHA256 is the SHA-256 of the research-bundle inventory
	// (docs/Vocdoni_CSP_Handoff/spanish_tsl_inventory_2026-10-30.json).
	tslTSHA256 = "647da585e4949b6e6a14d7190dc7dead70a60e60b46b051d7de7829a9175a8b8"

	tslTGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	tslTCAQC    = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
)

// tslTInventory is the part of the TSL inventory the cross-check reads.
type tslTInventory struct {
	Providers []struct {
		Services []tslTService `json:"services"`
	} `json:"providers"`
}

type tslTService struct {
	ServiceType       string `json:"service_type"`
	Status            string `json:"status"`
	CurrentGrantedQC  bool   `json:"current_granted_CA_QC"`
	ServiceIdentities []struct {
		SHA256     string `json:"sha256"`
		SPKISHA256 string `json:"spki_sha256"`
	} `json:"service_identity_certificates"`
}

func (s tslTService) granted() bool {
	return s.Status == tslTGranted && s.ServiceType == tslTCAQC && s.CurrentGrantedQC
}

// tslTIdentity is one service identity occurrence in the inventory.
type tslTIdentity struct {
	spki    string
	granted bool
}

// tslTLoad indexes every service identity certificate by DER SHA-256.
func tslTLoad(t *testing.T) map[string][]tslTIdentity {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", tslTFile))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var inv tslTInventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	idx := map[string][]tslTIdentity{}
	for _, p := range inv.Providers {
		for _, s := range p.Services {
			for _, c := range s.ServiceIdentities {
				idx[c.SHA256] = append(idx[c.SHA256], tslTIdentity{spki: c.SPKISHA256, granted: s.granted()})
			}
		}
	}
	if len(idx) == 0 {
		t.Fatal("inventory has no service identity certificates")
	}
	return idx
}

func TestTSLInventorySource(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", tslTFile))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != tslTSHA256 {
		t.Errorf("inventory SHA-256 = %s, want %s", got, tslTSHA256)
	}
	sources, err := os.ReadFile(filepath.Join("testdata", "SOURCES.md"))
	if err != nil {
		t.Fatalf("read SOURCES.md: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\| ` + regexp.QuoteMeta(tslTFile) + ` \|.*\| ([0-9a-f]{64}) \|$`)
	m := re.FindSubmatch(sources)
	if m == nil {
		t.Fatalf("testdata/SOURCES.md has no row for %s with a SHA-256", tslTFile)
	}
	if got := string(m[1]); got != tslTSHA256 {
		t.Errorf("SOURCES.md records %s, want %s", got, tslTSHA256)
	}
}

// TestAnchorsGrantedInTSL (AC5): every pinned anchor is a granted, current
// CA/QC service identity with the pinned SPKI; every pinned intermediate is a
// reviewed exception absent from the inventory; every known alias is granted
// and shares its key with the anchor it stands for.
func TestAnchorsGrantedInTSL(t *testing.T) {
	idx := tslTLoad(t)
	pinnedAnchors := map[string]string{} // DER -> SPKI
	pinnedInter := map[string]bool{}     // DER
	for _, p := range profiles.All() {
		for _, prof := range p.Profiles {
			for _, a := range prof.Anchors {
				pinnedAnchors[a.SHA256] = a.SPKISHA256
				entries := idx[a.SHA256]
				if len(entries) == 0 {
					t.Errorf("%s: anchor %s is not a TSL service identity", prof.ID, a.SHA256)
					continue
				}
				if !slices.ContainsFunc(entries, func(e tslTIdentity) bool { return e.granted }) {
					t.Errorf("%s: anchor %s has no current granted CA/QC service", prof.ID, a.SHA256)
				}
				for _, e := range entries {
					if e.spki != a.SPKISHA256 {
						t.Errorf("%s: anchor %s: inventory SPKI %s, pin %s", prof.ID, a.SHA256, e.spki, a.SPKISHA256)
					}
				}
				if slices.Contains(profiles.IntermediateExceptions, a.SHA256) {
					t.Errorf("%s: anchor %s is listed in IntermediateExceptions", prof.ID, a.SHA256)
				}
			}
			for _, in := range prof.Intermediates {
				pinnedInter[in.SHA256] = true
				if !slices.Contains(profiles.IntermediateExceptions, in.SHA256) {
					t.Errorf("%s: intermediate %s is not in IntermediateExceptions", prof.ID, in.SHA256)
				}
				if _, ok := idx[in.SHA256]; ok {
					t.Errorf("%s: intermediate %s is a TSL service identity; pin it as an anchor instead", prof.ID, in.SHA256)
				}
			}
		}
	}
	if len(pinnedAnchors) != 26 || len(pinnedInter) != 3 {
		t.Errorf("pinned %d anchors and %d intermediates, want 26 and 3", len(pinnedAnchors), len(pinnedInter))
	}
	for _, sha := range profiles.IntermediateExceptions {
		if !pinnedInter[sha] {
			t.Errorf("IntermediateExceptions entry %s is not a pinned intermediate", sha)
		}
	}
	if len(profiles.KnownAliases) == 0 {
		t.Error("KnownAliases is empty, want the Firmaprofesional CUALIFICADOS alias")
	}
	for alias, pinned := range profiles.KnownAliases {
		spki, ok := pinnedAnchors[pinned]
		if !ok {
			t.Errorf("alias %s stands for %s, which is not a pinned anchor", alias, pinned)
			continue
		}
		if _, loaded := pinnedAnchors[alias]; loaded || pinnedInter[alias] {
			t.Errorf("alias %s is pinned; aliases must not be loaded", alias)
		}
		if _, err := fs.Stat(profiles.AnchorsFS(), "anchors/"+alias+".pem"); err == nil {
			t.Errorf("alias %s is embedded under anchors/", alias)
		}
		entries := idx[alias]
		if !slices.ContainsFunc(entries, func(e tslTIdentity) bool { return e.granted }) {
			t.Errorf("alias %s has no current granted CA/QC service", alias)
		}
		for _, e := range entries {
			if e.spki != spki {
				t.Errorf("alias %s: inventory SPKI %s, want the pinned anchor's %s", alias, e.spki, spki)
			}
		}
	}
}
