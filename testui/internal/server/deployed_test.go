//go:build live

package server_test

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDeployedServiceGolden (AC9) checks a deployed service against the AC6
// service goldens: the providers API body byte for byte, and the ordered
// certificate_authorities list of every provider host. It runs after a
// deploy, never in CI:
//
//	CERTCHECK_DEPLOYED_URL=https://cert-check.vocdoni.dev \
//	CERTCHECK_DEPLOYED_AUTH=auth.cert-check.vocdoni.dev:32931 \
//	go test -tags live -count=1 -run TestDeployedServiceGolden ./internal/server
func TestDeployedServiceGolden(t *testing.T) {
	base, auth := os.Getenv("CERTCHECK_DEPLOYED_URL"), os.Getenv("CERTCHECK_DEPLOYED_AUTH")
	authDomain, port, err := net.SplitHostPort(auth)
	if base == "" || err != nil {
		t.Fatalf("CERTCHECK_DEPLOYED_URL (https://<host>) and CERTCHECK_DEPLOYED_AUTH (<auth domain>:<port>) are required: %v", err)
	}
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(strings.TrimSuffix(base, "/") + "/api/v1/providers")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET providers: status %d, %v", resp.StatusCode, err)
	}
	want, err := os.ReadFile(filepath.Join(goldenDir, "providers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(want) {
		t.Errorf("providers body differs from the golden:\n got: %s\nwant: %s", body, want)
	}

	raw, err := os.ReadFile(filepath.Join(goldenDir, "certificate-authorities.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string][]goldenCA // keyed "<id>.auth.test"
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	for _, key := range slices.Sorted(maps.Keys(golden)) {
		id := strings.TrimSuffix(key, "."+e2eAuthDomain)
		sni := id + "." + authDomain
		t.Run(id, func(t *testing.T) {
			var got [][]byte
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", net.JoinHostPort(sni, port), &tls.Config{
				ServerName: sni, MaxVersion: tls.VersionTLS12,
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					got = cri.AcceptableCAs
					return &tls.Certificate{}, nil
				}})
			if err != nil {
				t.Fatalf("handshake %s: %v", sni, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			var names []goldenCA
			for _, der := range got {
				var rdn pkix.RDNSequence
				if _, err := asn1.Unmarshal(der, &rdn); err != nil {
					t.Fatal(err)
				}
				var n pkix.Name
				n.FillFromRDNSequence(&rdn)
				names = append(names, goldenCA{DER: hex.EncodeToString(der), Name: n.String()})
			}
			if !slices.Equal(names, golden[key]) {
				t.Errorf("certificate_authorities = %+v, want %+v", names, golden[key])
			}
		})
	}
}
