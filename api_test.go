// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package certcheck_test

import (
	"os"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	certcheck "github.com/vocdoni/cert-check"
)

// apiTypes maps every exported type of package certcheck to its reflect
// type. TestPublicFieldTypesNamed fails when testdata/godoc.golden declares a
// type that is missing here, so the map stays complete.
var apiTypes = map[string]reflect.Type{
	"CandidateResult":    reflect.TypeFor[certcheck.CandidateResult](),
	"CertificateDetails": reflect.TypeFor[certcheck.CertificateDetails](),
	"CertificateInfo":    reflect.TypeFor[certcheck.CertificateInfo](),
	"ChainEntry":         reflect.TypeFor[certcheck.ChainEntry](),
	"Date":               reflect.TypeFor[certcheck.Date](),
	"Diagnostics":        reflect.TypeFor[certcheck.Diagnostics](),
	"Document":           reflect.TypeFor[certcheck.Document](),
	"DocumentType":       reflect.TypeFor[certcheck.DocumentType](),
	"Error":              reflect.TypeFor[certcheck.Error](),
	"ErrorCode":          reflect.TypeFor[certcheck.ErrorCode](),
	"Handler":            reflect.TypeFor[certcheck.Handler](),
	"Identity":           reflect.TypeFor[certcheck.Identity](),
	"Option":             reflect.TypeFor[certcheck.Option](),
	"Organization":       reflect.TypeFor[certcheck.Organization](),
	"ProfileInfo":        reflect.TypeFor[certcheck.ProfileInfo](),
	"Provider":           reflect.TypeFor[certcheck.Provider](),
	"ProviderInfo":       reflect.TypeFor[certcheck.ProviderInfo](),
	"ProviderRef":        reflect.TypeFor[certcheck.ProviderRef](),
	"Result":             reflect.TypeFor[certcheck.Result](),
	"Revocation":         reflect.TypeFor[certcheck.Revocation](),
	"RevocationAttempt":  reflect.TypeFor[certcheck.RevocationAttempt](),
	"RevocationInfo":     reflect.TypeFor[certcheck.RevocationInfo](),
	"RevocationMethod":   reflect.TypeFor[certcheck.RevocationMethod](),
	"RevocationOptions":  reflect.TypeFor[certcheck.RevocationOptions](),
	"RevocationStatus":   reflect.TypeFor[certcheck.RevocationStatus](),
	"Role":               reflect.TypeFor[certcheck.Role](),
	"Step":               reflect.TypeFor[certcheck.Step](),
	"TLSInfo":            reflect.TypeFor[certcheck.TLSInfo](),
	"TLSOption":          reflect.TypeFor[certcheck.TLSOption](),
}

// The enum constants carry the aliased types.
var (
	_ certcheck.Role             = certcheck.RoleNaturalPerson
	_ certcheck.DocumentType     = certcheck.DocumentDNI
	_ certcheck.RevocationStatus = certcheck.RevocationStatusGood
	_ certcheck.RevocationMethod = certcheck.RevocationMethodOCSP
)

// TestPublicFieldTypesNamed walks the exported fields of every exported type
// and fails on a named type from an internal package that package certcheck
// does not alias: a program could not name it.
func TestPublicFieldTypesNamed(t *testing.T) {
	raw, err := os.ReadFile("testdata/godoc.golden")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	var declared []string
	for _, m := range regexp.MustCompile(`(?m)^type (\w+) `).FindAllStringSubmatch(doc, -1) {
		declared = append(declared, m[1])
	}
	for _, name := range declared {
		if _, ok := apiTypes[name]; !ok {
			t.Errorf("type %s is in testdata/godoc.golden but not in apiTypes", name)
		}
	}
	for name := range apiTypes {
		if !slices.Contains(declared, name) {
			t.Errorf("apiTypes lists %s, which testdata/godoc.golden does not declare", name)
		}
	}
	aliased := map[string]bool{} // "identity.Date" for "type Date = identity.Date"
	for _, m := range regexp.MustCompile(`(?m)^type \w+ = (\w+\.\w+)$`).FindAllStringSubmatch(doc, -1) {
		aliased[m[1]] = true
	}
	seen := map[reflect.Type]bool{}
	var walk func(where string, typ reflect.Type)
	walk = func(where string, typ reflect.Type) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		if typ.Name() != "" && strings.Contains(typ.PkgPath(), "/internal/") && !aliased[path.Base(typ.PkgPath())+"."+typ.Name()] {
			t.Errorf("%s has type %s.%s, which package certcheck does not alias", where, typ.PkgPath(), typ.Name())
		}
		switch typ.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(where, typ.Elem())
		case reflect.Map:
			walk(where, typ.Key())
			walk(where, typ.Elem())
		case reflect.Struct:
			for f := range typ.Fields() {
				if f.IsExported() {
					walk(where+"."+f.Name, f.Type)
				}
			}
		}
	}
	for name, typ := range apiTypes {
		walk(name, typ)
	}
}
