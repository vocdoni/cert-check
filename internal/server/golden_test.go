package server_test

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/vocdoni/cert-check/certauth"
	"github.com/vocdoni/cert-check/certauth/profiles"
	"github.com/vocdoni/cert-check/certauth/revocation"
	"github.com/vocdoni/cert-check/internal/testpki"
)

const goldenDir = "../../testdata/golden"

// goldenCA is one certificate_authorities entry of a handshake.
type goldenCA struct {
	DER  string `json:"der"`  // hex of the DER distinguished name
	Name string `json:"name"` // RFC 4514, for readers
}

// TestGoldenService serves the production providers and records the
// providers API body and, for each provider host, the ordered
// certificate_authorities list of the CertificateRequest (AC6 golden).
func TestGoldenService(t *testing.T) {
	logs := &e2eLogs{}
	reg, err := profiles.Default(time.Now(), logs.logger())
	if err != nil {
		t.Fatalf("profiles.Default: %v", err)
	}
	rc, err := revocation.NewChecker(revocation.Options{UserAgent: "cert-check/golden", Logger: logs.logger()})
	if err != nil {
		t.Fatalf("revocation.NewChecker: %v", err)
	}
	checker, err := certauth.NewChecker(certauth.Options{Registry: reg, Revocation: rc, Version: e2eVersion})
	if err != nil {
		t.Fatalf("certauth.NewChecker: %v", err)
	}
	s := startE2E(t, checker, logs, &e2eClock{t: time.Now()})

	resp, body := s.do(t, s.request(t, http.MethodGet, "/api/v1/providers", "", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/providers: %d", resp.StatusCode)
	}
	testpki.Golden(t, filepath.Join(goldenDir, "providers.json"), body)

	var providers []struct{ ID string }
	if err := json.Unmarshal(body, &providers); err != nil || len(providers) != 14 {
		t.Fatalf("providers body: %v (%d providers, want 14)", err, len(providers))
	}
	cas := map[string][]goldenCA{}
	for _, p := range providers {
		sni := p.ID + "." + e2eAuthDomain
		var got [][]byte
		conn, err := net.DialTimeout("tcp", s.authAddr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c := tls.Client(conn, &tls.Config{ServerName: sni, RootCAs: s.pool,
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				got = cri.AcceptableCAs
				return &tls.Certificate{}, nil
			}})
		if err := c.HandshakeContext(t.Context()); err != nil {
			t.Fatalf("handshake %s: %v", sni, err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("close %s: %v", sni, err)
		}
		if len(got) == 0 {
			t.Fatalf("%s: no certificate_authorities", sni)
		}
		for _, der := range got {
			var rdn pkix.RDNSequence
			if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) != 0 {
				t.Fatalf("%s: CA name: %v", sni, err)
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			cas[sni] = append(cas[sni], goldenCA{DER: hex.EncodeToString(der), Name: name.String()})
		}
	}
	got, err := json.MarshalIndent(cas, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	testpki.Golden(t, filepath.Join(goldenDir, "certificate-authorities.json"), append(got, '\n'))
}
