package probe

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/vocdoni/cert-check/internal/profiles"
	"github.com/vocdoni/cert-check/internal/revocation"
)

// Pinned CAs (DER SHA-256, as in internal/profiles) that issue
// the probed certificates (OCSP) or sign the probed CRLs.
const (
	caFNMTUsuarios       = "601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869" // AC FNMT Usuarios
	caFNMTUsuariosG2     = "283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89" // AC USUARIOS G2
	caECCiutadania       = "0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6" // EC-Ciutadania
	caAOCSubA2           = "e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735" // SubCA CIUTADANIA Q (G3) A.2
	caACCVRSA1           = "a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1" // ACCV RSA1 CLIENTE
	caACCVECC1           = "5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496" // ACCV ECC1 CLIENTE
	caDigitelG1          = "86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61" // DIGITEL TS QUALIFIED CA G1
	caBeworCA1           = "8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d" // BEWOR TECH CA1
	caSectigoR35         = "ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde" // Sectigo Qualified Natural Person CA R35
	caSectigoE35         = "53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9" // Sectigo Qualified Natural Person CA E35
	caFNMTRepresentacion = "8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b" // AC Representación
	caFNMTRepG2          = "0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64" // AC REPRESENTACIÓN G2
	caFNMTSectorPublico  = "8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498" // AC Sector Público
	caFNMTSectorPubG2    = "983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe" // AC SECTOR PÚBLICO G2
	caFPCualificados     = "2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf" // AC Firmaprofesional - CUALIFICADOS
	caFPICAB01           = "4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1" // FIRMAPROFESIONAL ICA B01 QUALIFIED 2022
	caANFAsociacion      = "b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23" // ANF AC Qualified Certificates for eSignature
	caANFSL              = "5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a" // ANF Qualified for eSignature CA
	caUanatacaCA1v2016   = "35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f" // UANATACA CA1 2016
	caUanatacaCA2v2016   = "00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909" // UANATACA CA2 2016
	caUanatacaCA1v2021   = "9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a" // UANATACA CA1 2021
	caUanatacaCA2v2021   = "15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a" // UANATACA CA2 2021
	caSIGNE2020          = "b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea" // SIGNE Autoridad de Certificacion - 2020
	caSIGNESubCA2024     = "244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35" // SIGNE SUBCA 2024
	caInDenova003        = "3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25" // inDenova SUB CA 003
	caDNIeRoot2          = "c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11" // AC RAIZ DNIE 2
	caDNIe004            = "ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c" // AC DNIE 004
	caDNIe005            = "828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828" // AC DNIE 005
	caDNIe006            = "eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd" // AC DNIE 006
)

// endpoint is one row of the probe table (from the research digests).
type endpoint struct {
	profile string
	kind    Kind
	url     string
	issuer  string // pinned CA: issues the certificates (OCSP) or signs the CRL
	scope   revocation.Scope
	covers  []string // pinned intermediates the CRL is judged for (Target.Covers)
}

func ocsp(profile, url string, issuers ...string) []endpoint {
	out := make([]endpoint, 0, len(issuers))
	for _, iss := range issuers {
		out = append(out, endpoint{profile: profile, kind: KindOCSP, url: url, issuer: iss})
	}
	return out
}

func crl(profile, url, issuer string) []endpoint {
	return []endpoint{{profile: profile, kind: KindCRL, url: url, issuer: issuer, scope: revocation.ScopeLeaf}}
}

// caCRL is a CRL row evaluated at CA scope for the pinned intermediates it
// covers, those whose CDP names url.
func caCRL(profile, url, issuer string, covers ...string) []endpoint {
	return []endpoint{{profile: profile, kind: KindCRL, url: url, issuer: issuer, scope: revocation.ScopeCA, covers: covers}}
}

// endpoints is the Task 12 URL table: one OCSP row per (responder, issuing
// CA) and one row per CRL. The DNIe root CRL and ARL are signed by the root
// and cover the pinned intermediates (a CA-scope check consults both), so
// they are evaluated at CA scope for each intermediate whose CDP names them:
// AC DNIE 004 names ARL.crl only, AC DNIE 005 and 006 name both.
var endpoints = slices.Concat(
	ocsp("fnmt-citizen-rsa", "http://ocspusu.cert.fnmt.es/ocspusu/OcspResponder", caFNMTUsuarios),
	crl("fnmt-citizen-rsa", "http://www.cert.fnmt.es/crlsacusu/CRLU1.crl", caFNMTUsuarios),
	ocsp("fnmt-citizen-g2", "http://ocspusug2.cert.fnmt.es/ocspusuG2/OcspResponder", caFNMTUsuariosG2),
	crl("fnmt-citizen-g2", "http://www.cert.fnmt.es/crlacusuG2/CRL2.crl", caFNMTUsuariosG2),
	ocsp("aoc-idcat-g2", "http://ocsp.catcert.cat", caECCiutadania),
	crl("aoc-idcat-g2", "http://epscd.catcert.net/crl/ec-ciutadania.crl", caECCiutadania),
	ocsp("aoc-idcat-g3", "http://ocsp.aoc.cat", caAOCSubA2),
	crl("aoc-idcat-g3", "https://epscd.aoc.cat/crl/casub-a2.crl", caAOCSubA2),
	ocsp("accv-citizen-software-current", "http://ocsp.accv.es", caACCVRSA1, caACCVECC1),
	crl("accv-citizen-software-current", "http://www.accv.es/gestcert/accv_rsa1_cliente.crl", caACCVRSA1),
	crl("accv-citizen-software-current", "http://www.accv.es/gestcert/accv_ecc1_cliente.crl", caACCVECC1),
	ocsp("digitel-citizen-sw-g1", "http://ocsp.digitelts.es", caDigitelG1),
	crl("digitel-citizen-sw-g1", "http://crl1.pki.digitelts.es/DTSQualifiedCAG1.crl", caDigitelG1),
	ocsp("bewor-natural-person-sw", "http://ocsp1.uanataca.com/public/pki/ocsp/", caBeworCA1),
	crl("bewor-natural-person-sw", "http://crl1.uanataca.com/public/pki/crl/bewor.crl", caBeworCA1),
	ocsp("sectigo-citizen-local", "http://ocsp.sectigo.com", caSectigoR35, caSectigoE35),
	crl("sectigo-citizen-local", "http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAR35.crl", caSectigoR35),
	crl("sectigo-citizen-local", "http://crl.sectigo.com/SectigoQualifiedNaturalPersonCAE35.crl", caSectigoE35),
	ocsp("fnmt-representative-rsa", "http://ocsprep.cert.fnmt.es/ocsprep/OcspResponder", caFNMTRepresentacion),
	ocsp("fnmt-representative-g2", "http://ocsprepg2.cert.fnmt.es/ocsprepG2/OcspResponder", caFNMTRepG2),
	ocsp("fnmt-employee-rsa", "http://ocspsp.cert.fnmt.es/ocspsp/OcspResponder", caFNMTSectorPublico),
	ocsp("fnmt-employee-g2", "http://ocspspg2.cert.fnmt.es/ocspspG2/OcspResponder", caFNMTSectorPubG2),
	ocsp("firmaprofesional-personal-sw", "http://ocsp.firmaprofesional.com", caFPCualificados, caFPICAB01),
	ocsp("anf-asociacion-class2-sw", "http://ocsp.anf.es/spain/AV", caANFAsociacion),
	ocsp("anf-sl-class2-sw", "http://ocsp.anf.es/spain/AV", caANFSL),
	ocsp("uanataca-citizen-sw", "http://ocsp1.uanataca.com/public/pki/ocsp/",
		caUanatacaCA1v2016, caUanatacaCA2v2016, caUanatacaCA1v2021, caUanatacaCA2v2021),
	crl("uanataca-citizen-sw", "http://crl1.uanataca.com/public/pki/crl/CA1subordinada.crl", caUanatacaCA1v2016),
	crl("uanataca-citizen-sw", "http://crl1.uanataca.com/public/pki/crl/CA2subordinada.crl", caUanatacaCA2v2016),
	crl("uanataca-citizen-sw", "http://crl1.uanataca.com/public/pki/crl/2021CA1sub.crl", caUanatacaCA1v2021),
	crl("uanataca-citizen-sw", "http://crl1.uanataca.com/public/pki/crl/2021CA2sub.crl", caUanatacaCA2v2021),
	crl("signe-personal-otros-dispositivos", "http://www.signe.es/signe-ac/crl/signe-subca.crl", caSIGNESubCA2024),
	crl("signe-personal-otros-dispositivos", "https://www.signe.es/signe-ac/crl/signe2020.crl", caSIGNE2020),
	crl("lleidanet-natural-person-sw", "http://crl1.esigna.es/sub/indenova_pki_003.crl", caInDenova003),
	ocsp("dnie-auth", "http://ocsp.dnie.es", caDNIe004, caDNIe005, caDNIe006),
	caCRL("dnie-auth", "http://pki.policia.es/dnie/crls/CRL.crl", caDNIeRoot2, caDNIe005, caDNIe006),
	caCRL("dnie-auth", "http://pki.policia.es/dnie/crls/ARL.crl", caDNIeRoot2, caDNIe004, caDNIe005, caDNIe006),
)

// specimens are live CA-published test certificates whose revocation status
// is expected to be good (fingerprints from testdata/specimens/MANIFEST.md;
// the Bewor and Sectigo files are withheld from the repository, ruling R30).
var specimens = map[string]string{
	"fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8": "digitel-citizen-sw-g1",
	"da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab": "bewor-natural-person-sw",
	"88059e9240bb96734d0a0c07d27a9fbd2741ebbdd49c08004b14b443962f2c30": "sectigo-citizen-local",
}

// enabledProfiles loads the production registry (pins checked) and returns
// its enabled profiles by ID.
func enabledProfiles() (map[string]*profiles.Enabled, error) {
	reg, err := profiles.Default(time.Now(), nil)
	if err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}
	out := map[string]*profiles.Enabled{}
	for _, p := range reg.Providers() {
		for _, e := range reg.Enabled(p.ID) {
			out[e.Profile.ID] = e
		}
	}
	return out, nil
}

// DefaultTargets returns the OCSP and CRL targets of every enabled
// production profile, with the issuers (and the intermediates a CRL covers)
// taken from the pinned anchors and intermediates of profiles.All. A row
// naming an unknown profile or a CA the profile does not pin is an error.
func DefaultTargets() ([]Target, error) {
	enabled, err := enabledProfiles()
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, p := range profiles.All() {
		for _, pr := range p.Profiles {
			known[pr.ID] = true
		}
	}
	out := make([]Target, 0, len(endpoints))
	for _, e := range endpoints {
		if !known[e.profile] {
			return nil, fmt.Errorf("probe: unknown profile %s", e.profile)
		}
		p, ok := enabled[e.profile]
		if !ok {
			continue // disabled (expired anchors): nothing to probe
		}
		issuer := pinnedCA(p, e.issuer)
		if issuer == nil {
			return nil, fmt.Errorf("probe: profile %s does not pin CA %s", e.profile, e.issuer)
		}
		var covers []*x509.Certificate
		for _, sha := range e.covers {
			c := pinnedCA(p, sha)
			if c == nil {
				return nil, fmt.Errorf("probe: profile %s does not pin CA %s", e.profile, sha)
			}
			covers = append(covers, c)
		}
		out = append(out, Target{Profile: e.profile, Kind: e.kind, URL: e.url, Issuer: issuer, Policy: p.Profile.Revocation, Scope: e.scope, Covers: covers})
	}
	return out, nil
}

// pinnedCA returns the profile's anchor or pinned intermediate with DER SHA-256 sha.
func pinnedCA(p *profiles.Enabled, sha string) *x509.Certificate {
	for _, c := range slices.Concat(p.Anchors, p.Intermediates) {
		if sha256Hex(c.Raw) == sha {
			return c
		}
	}
	return nil
}

// maxSpecimenBytes caps the read of one specimen file (a PEM certificate is a few KiB).
const maxSpecimenBytes = 64 << 10

// maxSpecimenEntries caps the entries of a specimen directory.
const maxSpecimenEntries = 1024

// LoadSpecimens reads the *.pem files of fsys (one certificate each) and
// returns a KindSpecimen target for every known live specimen among them,
// once each, with the issuing anchor of its profile. Other certificates are
// ignored. A directory that cannot be read or has more than
// maxSpecimenEntries entries, a *.pem that is not a regular file or is
// larger than maxSpecimenBytes is an error.
func LoadSpecimens(fsys fs.FS) ([]Target, error) {
	enabled, err := enabledProfiles()
	if err != nil {
		return nil, err
	}
	entries, err := readSpecimenDir(fsys)
	if err != nil {
		return nil, fmt.Errorf("probe: specimen directory: %w", err)
	}
	var out []Target
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".pem") {
			continue
		}
		raw, err := readSpecimen(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("probe: %s: %w", name, err)
		}
		blk, _ := pem.Decode(raw)
		if blk == nil || blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("probe: %s: no PEM certificate", name)
		}
		sha := sha256Hex(blk.Bytes)
		profile, ok := specimens[sha]
		if !ok || seen[sha] {
			continue
		}
		seen[sha] = true
		p, ok := enabled[profile]
		if !ok {
			return nil, fmt.Errorf("probe: %s: profile %s is not enabled", name, profile)
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("probe: %s: %w", name, err)
		}
		issuer := issuingCA(p, cert)
		if issuer == nil {
			return nil, fmt.Errorf("probe: %s: not issued by a CA pinned for %s", name, profile)
		}
		out = append(out, Target{Profile: profile, Kind: KindSpecimen, Issuer: issuer, Specimen: cert, Policy: p.Profile.Revocation})
	}
	return out, nil
}

// readSpecimenDir returns the entries of fsys's root, sorted by name, and
// stops with an error past maxSpecimenEntries. It reads the directory
// itself, not with fs.Glob, which ignores I/O errors (an unreadable
// directory would look empty), nor fs.ReadDir, which reads it whole.
func readSpecimenDir(fsys fs.FS) ([]fs.DirEntry, error) {
	f, err := fsys.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only; the read error is what matters
	d, ok := f.(fs.ReadDirFile)
	if !ok {
		return nil, errors.New("not a directory")
	}
	var entries []fs.DirEntry
	for {
		batch, err := d.ReadDir(maxSpecimenEntries + 1 - len(entries))
		entries = append(entries, batch...)
		switch {
		case len(entries) > maxSpecimenEntries:
			return nil, fmt.Errorf("more than %d entries, not a specimen directory", maxSpecimenEntries)
		case errors.Is(err, io.EOF):
			slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
			return entries, nil
		case err != nil:
			return nil, err
		}
	}
}

// readSpecimen reads name, a regular file of at most maxSpecimenBytes. It
// is checked with Stat before Open: opening a FIFO blocks.
func readSpecimen(fsys fs.FS, name string) ([]byte, error) {
	fi, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only; the read error is what matters
	raw, err := io.ReadAll(io.LimitReader(f, maxSpecimenBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSpecimenBytes {
		return nil, fmt.Errorf("larger than %d bytes, not a specimen", maxSpecimenBytes)
	}
	return raw, nil
}

// issuingCA returns the pinned CA of p that signed cert.
func issuingCA(p *profiles.Enabled, cert *x509.Certificate) *x509.Certificate {
	for _, c := range slices.Concat(p.Anchors, p.Intermediates) {
		if bytes.Equal(cert.RawIssuer, c.RawSubject) && cert.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
