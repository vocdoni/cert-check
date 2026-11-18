// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package identity_test

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vocdoni/cert-check/internal/identity"
)

// specimenDir holds the CA-published test leaves (see its MANIFEST.md).
const specimenDir = "../../testdata/specimens"

func loadSpecimen(tb testing.TB, file string) *x509.Certificate {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join(specimenDir, file))
	if err != nil {
		tb.Fatalf("read specimen: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		tb.Fatalf("%s: no PEM CERTIFICATE block", file)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		tb.Fatalf("%s: parse: %v", file, err)
	}
	return cert
}

// specimenFiles lists every committed specimen (MANIFEST.md "committed").
func specimenFiles(tb testing.TB) []string {
	tb.Helper()
	files, err := filepath.Glob(filepath.Join(specimenDir, "*.pem"))
	if err != nil || len(files) == 0 {
		tb.Fatalf("glob specimens: %d files, %v", len(files), err)
	}
	for i, f := range files {
		files[i] = filepath.Base(f)
	}
	return files
}

func TestSpecimenIdentities(t *testing.T) {
	rsa, g2, dnie, plain := shapeFNMTCitizenRSA(), shapeFNMTCitizenG2(), shapeDNIe(), shapePlain()
	idcatBare := shapeIDCATG2()
	idcatBare.Documents = bareRules

	fnmt := func(number, raw, given, first, second string) identity.Identity {
		return fnmtIdentity(dniDoc(number, raw), given, first+" "+second, first, second)
	}
	const (
		pruebas = "PRUEBAS"
		eidas   = "EIDAS"
		cert    = "CERTIFICADO"
		uno     = "ESPECIMEN UÑO"
		guenos  = "ESPECIMEN DE LOS GÜENOS"
	)
	diez := fnmtIdentity(dniDoc("99949990V", "IDCES-99949990V"), "NOM D'DIEZ", "ESPECIMENDIEZ ESPECIMEN-DIEZ", "ESPECIMENDIEZ", "ESPECIMEN-DÍEZ")
	ficticio := func(number, second string) identity.Identity {
		return dnieIdentity(dniDoc(number, number), "Ciudadano", "Ficticio "+second, "Ficticio", second)
	}

	tests := []struct {
		file    string
		adapter identity.Adapter
		want    identity.Identity
		wantErr error
	}{
		// FNMT AC FNMT Usuarios (RSA).
		{file: "fnmt-rsa-nosmime-activo-99999999R-2024.pem", adapter: rsa, want: fnmt("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		{file: "fnmt-rsa-nosmime-revocado-99999999R-2024.pem", adapter: rsa, want: fnmt("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		{file: "fnmt-rsa-nosmime-activo-99999972C-2024.pem", adapter: rsa, want: fnmt("99999972C", "IDCES-99999972C", pruebas, eidas, cert)},
		{file: "fnmt-rsa-caducado-99999999R-2016.pem", adapter: rsa, want: fnmt("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		{file: "fnmt-rsa-revocado-pruebasrev-99999999R-2016.pem", adapter: rsa, want: fnmt("99999999R", "IDCES-99999999R", "PRUEBASREV", eidas, cert)},
		{file: "fnmt-rsa-smime-revocado-99999999R-2020.pem", adapter: rsa, want: fnmt("99999999R", "IDCES-99999999R", pruebas, eidas, cert)},
		{file: "fnmt-rsa-nosmime-espanol-espanol-juan-00000000T-2023.pem", adapter: rsa, want: fnmt("00000000T", "IDCES-00000000T", "JUAN", "ESPAÑOL", "ESPAÑOL")},
		{file: "fnmt-rsa-legacy2016-activo-apellidounopf-pruebaspf.pem", adapter: rsa, want: fnmt("00000000T", "00000000T", "PRUEBASPF", "APELLIDOUNOPF", "APELLIDODOSPF")},
		{file: "fnmt-rsa-legacy2016-revocado-apellidounorev-pruebaspf.pem", adapter: rsa, want: fnmt("00000000T", "00000000T", "PRUEBASPF", "APELLIDOUNOREVPF", "APELLIDODOSREVPF")},
		{file: "fnmt-rsa-supervisor-especimen-99949990V-2025.pem", adapter: rsa, want: diez},
		{file: "fnmt-rsa-supervisor-especimen-99949991H-2025.pem", adapter: rsa, want: fnmt("99949991H", "IDCES-99949991H", "NOM UN O", uno, guenos)},
		{file: "fnmt-rsa-supervisor-especimen-99949999A-2025.pem", adapter: rsa, want: fnmt("99949999A", "IDCES-99949999A", "NOMNUEVE", "ESPECIMENNUEVE", "ESPECIMENNUEVE")},
		// FNMT AC USUARIOS G2 (SAN ascending).
		{file: "fnmt-ecc-g2-activo-especimen-99949991H-2025.pem", adapter: g2, want: fnmt("99949991H", "IDCES-99949991H", "NOM UN O", uno, guenos)},
		{file: "fnmt-ecc-g2-revocado-especimen-99949990V-2025.pem", adapter: g2, want: diez},
		// The 2016 bare kit is not accepted by the G2 grammar.
		{file: "fnmt-rsa-legacy2016-activo-apellidounopf-pruebaspf.pem", adapter: g2, wantErr: identity.ErrInvalid},
		// DNIe authentication certificates (AC DNIE 004 unaccented, AC DNIE 001 accented suffix).
		{file: "dnie-ac004-auth-activo.pem", adapter: dnie, want: ficticio("00000000T", "Activo")},
		{file: "dnie-ac004-auth-caducado.pem", adapter: dnie, want: ficticio("00000000T", "Caducado")},
		{file: "dnie-ac004-auth-revocado.pem", adapter: dnie, want: ficticio("00000000T", "Revocado")},
		{file: "dnie-ac001-auth-activo.pem", adapter: dnie, want: ficticio("99999018D", "Activo")},
		{file: "dnie-ac001-auth-revocado.pem", adapter: dnie, want: ficticio("99999018D", "Revocado")},
		// DNIe signature certificates fail the authentication CN grammar.
		{file: "dnie-ac001-firma-activo.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac001-firma-revocado.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac004-firma-activo.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac004-firma-caducado.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac004-firma-revocado.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac004-firmacentralizada-activo.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac004-firmacentralizada-caducado.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		{file: "dnie-ac004-firmacentralizada-revocado.pem", adapter: dnie, wantErr: identity.ErrInvalid},
		// DIGITEL (plain).
		{file: "digitel-ciudadanosw-99949996T.pem", adapter: plain,
			want: plainIdentity(dniDoc("99949996T", "IDCES-99949996T"), "NOMSEIS", "ESPECIMENSEIS ESPECIMENSEIS")},
		// idCAT 2015 (bare serialNumber): rejected by the IDCES-only grammar, read by a bare one.
		{file: "idcat-g2-pf-peca-de-proves-00000000T.pem", adapter: shapeIDCATG2(), wantErr: identity.ErrInvalid},
		{file: "idcat-g2-pf-peca-de-proves-00000000T.pem", adapter: idcatBare,
			want: plainIdentity(dniDoc("00000000T", "00000000T"), "Persona Física", "de la Peça de Proves")},
	}

	reserved := identity.DefaultReserved()
	covered := map[string]bool{}
	for _, tc := range tests {
		covered[tc.file] = true
		t.Run(tc.file, func(t *testing.T) {
			got, err := tc.adapter.Extract(loadSpecimen(t, tc.file))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Extract err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Extract err = %v, want nil", err)
			}
			if !reflect.DeepEqual(got.Identity, tc.want) {
				t.Errorf("Identity:\n got %+v\nwant %+v", got.Identity, tc.want)
			}
			if got.Organization != nil || len(got.Notes) != 0 {
				t.Errorf("Organization = %+v, Notes = %q; want nil and none", got.Organization, got.Notes)
			}
			if kind, hit := reserved.Match(got); !hit || kind != identity.MarkerDocument {
				t.Errorf("DefaultReserved().Match = (%q, %v), want (%q, true)", kind, hit, identity.MarkerDocument)
			}
		})
	}
	for _, f := range specimenFiles(t) {
		if !covered[f] {
			t.Errorf("specimen %s has no row in TestSpecimenIdentities", f)
		}
	}
}
