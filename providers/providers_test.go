package providers_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/providers"
	"github.com/vocdoni/cert-check/providers/fnmt"
)

// loadedAt is a day on which every embedded anchor is valid, so that the
// tests do not depend on the calendar.
var loadedAt = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

var (
	discard = certcheck.WithLogger(slog.New(slog.DiscardHandler))
	atLoad  = certcheck.WithClock(func() time.Time { return loadedAt })
)

func ids(ps []certcheck.Provider) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Info().ID)
	}
	return out
}

// TestAllMatchesDeclarations: All is profiles.All in display order, each
// provider's Info and CAs come from its declaration, and a Handler accepts
// the whole set (no shared CA subject, no anchor key and policy shared
// across providers).
func TestAllMatchesDeclarations(t *testing.T) {
	t.Parallel()
	all := providers.All(atLoad, discard)
	decls := profiles.All()
	var declIDs []string
	for _, d := range decls {
		declIDs = append(declIDs, d.ID)
	}
	if got := ids(all); !slices.Equal(got, declIDs) {
		t.Fatalf("All() IDs = %v, want %v", got, declIDs)
	}
	reg, err := profiles.Default(loadedAt, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("profiles.Default: %v", err)
	}
	for i, p := range all {
		d := decls[i]
		if got, want := p.Info(), (certcheck.ProviderInfo{ID: d.ID, Name: d.Name, Description: d.Description, Beta: d.Beta}); got != want {
			t.Errorf("All()[%d].Info() = %+v, want %+v", i, got, want)
		}
		var want []string
		for _, e := range reg.Enabled(d.ID) {
			for _, c := range slices.Concat(e.Anchors, e.Intermediates) {
				want = append(want, string(c.Raw))
			}
		}
		var got []string
		for _, c := range p.CAs() {
			got = append(got, string(c.Raw))
		}
		if len(got) == 0 || !slices.Equal(got, want) {
			t.Errorf("%s: CAs() (%d) differ from the enabled anchors then intermediates (%d), in order", d.ID, len(got), len(want))
		}
	}
	if _, err := certcheck.NewHandler(all); err != nil {
		t.Errorf("NewHandler(All()) = %v, want nil", err)
	}
}

func TestStandardAndByID(t *testing.T) {
	t.Parallel()
	var want []string
	for _, d := range profiles.All() {
		if !d.Beta {
			want = append(want, d.ID)
		}
	}
	if got := ids(providers.Standard(atLoad, discard)); !slices.Equal(got, want) {
		t.Errorf("Standard() = %v, want %v", got, want)
	}
	for _, d := range profiles.All() {
		p, ok := providers.ByID(d.ID, atLoad, discard)
		if !ok || p == nil || p.Info().ID != d.ID {
			t.Errorf("ByID(%q) = (%v, %v), want that provider", d.ID, p, ok)
		}
	}
	if p, ok := providers.ByID("nope", atLoad, discard); ok || p != nil {
		t.Errorf("ByID(nope) = (%v, %v), want (nil, false)", p, ok)
	}
}

// TestInertProviders loads every declaration in 2100, when every embedded
// anchor has expired.
func TestInertProviders(t *testing.T) {
	t.Parallel()
	future := certcheck.WithClock(func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) })
	if got := providers.All(future, discard); len(got) != 0 {
		t.Errorf("All() in 2100 = %v, want none", ids(got))
	}
	if got := providers.Standard(future, discard); len(got) != 0 {
		t.Errorf("Standard() in 2100 = %v, want none", ids(got))
	}
	for _, d := range profiles.All() {
		if p, ok := providers.ByID(d.ID, future, discard); ok || p != nil {
			t.Errorf("ByID(%q) in 2100 = (%v, %v), want (nil, false)", d.ID, p, ok)
		}
	}
	p := fnmt.New(future, discard)
	if got := p.Info(); got.ID != "fnmt" || got.Name != "FNMT - Persona Física" {
		t.Errorf("inert fnmt Info() = %+v, want its declaration", got)
	}
	if got := len(p.CAs()); got != 0 {
		t.Errorf("inert fnmt CAs() has %d certificates, want 0", got)
	}
	res, err := p.Verify(t.Context(), nil)
	e, ok := errors.AsType[*certcheck.Error](err)
	if !ok || res != nil {
		t.Fatalf("inert Verify = (%v, %v), want (nil, *certcheck.Error)", res, err)
	}
	if e.Code != certcheck.CodeProviderMismatch || e.Diagnostics.FailedStep != certcheck.StepBounds || e.Detail != "provider has no enabled profile" {
		t.Errorf("inert Verify = %s at %s, %q; want %s at %s, %q", e.Code, e.Diagnostics.FailedStep, e.Detail,
			certcheck.CodeProviderMismatch, certcheck.StepBounds, "provider has no enabled profile")
	}
	if h, err := certcheck.NewHandler([]certcheck.Provider{p}); err == nil || h != nil {
		t.Errorf("NewHandler(inert) = (%v, %v), want an error", h, err)
	}
}

// TestPackagesExportOnlyConstructors: every providers/<name> package exports
// only functions New...(...certcheck.Option) certcheck.Provider.
func TestPackagesExportOnlyConstructors(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	dirs := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		dirs[filepath.Dir(name)] = true
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			if d, ok := decl.(*ast.FuncDecl); ok {
				if d.Name.IsExported() && (d.Recv != nil || !strings.HasPrefix(d.Name.Name, "New") ||
					fieldTypes(d.Type.Params) != "...certcheck.Option" || fieldTypes(d.Type.Results) != "certcheck.Provider") {
					t.Errorf("%s: %s is not func New...(...certcheck.Option) certcheck.Provider", name, d.Name)
				}
				continue
			}
			for _, spec := range decl.(*ast.GenDecl).Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						t.Errorf("%s exports type %s", name, s.Name)
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.IsExported() {
							t.Errorf("%s exports %s", name, n)
						}
					}
				}
			}
		}
	}
	if got, want := len(dirs), 12; got != want {
		t.Errorf("%d provider packages, want %d", got, want)
	}
}

// fieldTypes renders a parameter or result list such as "...certcheck.Option".
func fieldTypes(fl *ast.FieldList) string {
	if fl == nil {
		return ""
	}
	var out []string
	for _, f := range fl.List {
		out = append(out, exprString(f.Type))
	}
	return strings.Join(out, ",")
}

func exprString(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ellipsis:
		return "..." + exprString(e.Elt)
	case *ast.SelectorExpr:
		return exprString(e.X) + "." + e.Sel.Name
	case *ast.Ident:
		return e.Name
	}
	return "?"
}
