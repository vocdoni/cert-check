package profiles

import (
	"encoding/asn1"

	"github.com/vocdoni/cert-check/certauth/identity"
	"github.com/vocdoni/cert-check/certauth/revocation"
)

// Source digests: A = docs/research/appendix-a-fnmt-dnie-accv.md,
// B = appendix-b-idcat-izenpe-camerfirma.md, C = appendix-cde-other-providers.md.
// Specimen fingerprints: certauth/testdata/specimens/MANIFEST.md.

func anchor(sha, spki string) Anchor {
	return Anchor{File: "anchors/" + sha + ".pem", SHA256: sha, SPKISHA256: spki}
}

func fp(sha, file string) TestMarker {
	return TestMarker{SHA256: sha, Source: "certauth/testdata/specimens/" + file}
}

func oid(arcs ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(arcs) }

var (
	dniNIE  = []identity.DocumentType{identity.DocumentDNI, identity.DocumentNIE}
	dniOnly = []identity.DocumentType{identity.DocumentDNI}
	nieOnly = []identity.DocumentType{identity.DocumentNIE}
	idces   = []identity.DocumentRule{{Encoding: identity.EncodingIDCES, Types: dniNIE}}
	bare    = []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniNIE}}
	noSAN   = identity.SANCheck{Kind: identity.SANNone}
)

// plain: IDCES-<DNI|NIE> in 2.5.4.5, GN 2.5.4.42, complete surnames in SN 2.5.4.4,
// no SAN check, no birth date, no organization.
func plain() identity.Adapter {
	return identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN, SAN: noSAN,
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone}
}

// sanAttrs declares SAN directoryName attributes that must agree with the subject.
func sanAttrs(docOID asn1.ObjectIdentifier, docRules []identity.DocumentRule, given, first, second asn1.ObjectIdentifier) identity.SANCheck {
	return identity.SANCheck{Kind: identity.SANAttributes, DocumentOID: docOID, DocumentRules: docRules,
		GivenNameOID: given, FirstSurnameOID: first, SecondSurnameOID: second}
}

func fnmt5734(n int) asn1.ObjectIdentifier { return oid(1, 3, 6, 1, 4, 1, 5734, 1, n) }

// fnmtSAN: 5734.1.4 document (encoding differs: citizen bare, representative IDCES-),
// .1.1 given, .1.2 first surname, .1.3 second surname; order-independent.
func fnmtSAN(doc []identity.DocumentRule) identity.SANCheck {
	return sanAttrs(fnmt5734(4), doc, fnmt5734(1), fnmt5734(2), fnmt5734(3))
}

// fp13177: Firmaprofesional SAN namespace, also used by SIGNE.
func fp13177() identity.SANCheck {
	n := func(i int) asn1.ObjectIdentifier { return oid(1, 3, 6, 1, 4, 1, 13177, 0, i) }
	return sanAttrs(nil, nil, n(1), n(2), n(3))
}

func policy(nonce bool, ocsp, crl []string) revocation.Policy {
	return revocation.Policy{OCSPHosts: ocsp, CRLHosts: crl, AllowCRL: len(crl) > 0, OCSPNonce: nonce}
}

func person(id, providerID, name string, anchors []Anchor, oids []string, a identity.Adapter, p revocation.Policy, markers ...TestMarker) Profile {
	return Profile{ID: id, ProviderID: providerID, Name: name, HolderRole: RoleNaturalPerson, Anchors: anchors,
		PolicyOIDs: oids, EKU: EKURequireClientAuth, Identity: a, Revocation: p, TestMarkers: markers}
}

// DefaultProviders returns the production providers in display order:
// standard first, then the Beta group. Each call returns a fresh copy.
func DefaultProviders() []Provider {
	return []Provider{
		fnmt(), idcat(), accv(), digitel(), bewor(), sectigo(),
		fnmtRepresentative(), fnmtEmployee(), firmaprofesional(), anf(), uanataca(), signe(), lleidanet(), dnie(),
	}
}

// fnmt: digest A fnmt-citizen-rsa / fnmt-citizen-g2; manifest G3-G6.
func fnmt() Provider {
	rsa := identity.Adapter{
		Documents: append(append([]identity.DocumentRule{}, idces...), bare...), // bare = May-2016 kit (AllowBare)
		Surnames:  identity.SurnamesFromSN, SAN: fnmtSAN(bare),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	g2 := rsa
	g2.Documents = idces
	return Provider{ID: "fnmt", Name: "FNMT - Persona Física",
		Description: "Certificado de Persona Física de la FNMT-RCM (AC FNMT Usuarios y AC USUARIOS G2)",
		Profiles: []Profile{
			person("fnmt-citizen-rsa", "fnmt", "FNMT Persona Física (AC FNMT Usuarios)",
				[]Anchor{anchor("601293ca20b09a03295d196256c6953ff9eba811db8e3ce140413c1bffe9a869", "0b21720b91f0e45c43f2e7cb185f552eb7de7ed46b2ac172ee39b50841710a6f")},
				[]string{"1.3.6.1.4.1.5734.3.10.1"}, rsa,
				policy(true, []string{"ocspusu.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}),
				fp("71bdc889e9f46890999b47665259e10b97cf654e03a9474b6a24ab03f455142e", "fnmt-rsa-caducado-99999999R-2016.pem"),
				fp("bbb3fd5e64641122c5a6951c69fd7c2a35e90e92290d3d5cdd1fa2d0bb3950f5", "fnmt-rsa-legacy2016-activo-apellidounopf-pruebaspf.pem"),
				fp("442045710183f1bbfe78f63c992cd5139d30cc976e917c19d23bdb6f156467ba", "fnmt-rsa-legacy2016-revocado-apellidounorev-pruebaspf.pem"),
				fp("3533bc399e58b7072cc7cc3a9d19e4f2a955770dd4827e1f6abdd2a9ed00d2af", "fnmt-rsa-nosmime-activo-99999972C-2024.pem"),
				fp("278259d1098998c445e15fc011a5211c3f411096fb57fe41b948957cf916a8ed", "fnmt-rsa-nosmime-activo-99999999R-2024.pem"),
				fp("0bcf1dcc10ddb3e9a085420c94c543718fff037416eb048448dc05499240b0bc", "fnmt-rsa-nosmime-espanol-espanol-juan-00000000T-2023.pem"),
				fp("26fa9c9cc42b06e5a5a6abb1f6696ae4161c51e616dc943376cfeefd104a3469", "fnmt-rsa-nosmime-revocado-99999999R-2024.pem"),
				fp("a8f1eb76c810b373fa5b8f98006a7a0c190e9304935d6e3bf2ffa6f4c4bdfa92", "fnmt-rsa-revocado-pruebasrev-99999999R-2016.pem"),
				fp("a9d9a67e92c66c4d0ee25bc28e170a6ecde111adece30c4e9e83503500b182a6", "fnmt-rsa-smime-revocado-99999999R-2020.pem"),
				fp("cb2e6141218bb0c85c12012143711f91612ab94d3663c5036d720598fcb86024", "fnmt-rsa-supervisor-especimen-99949990V-2025.pem"),
				fp("e75503b06c03e99ecb94bb752b0e4b7fcc74a27637338dda6f4b8e5316c98623", "fnmt-rsa-supervisor-especimen-99949991H-2025.pem"),
				fp("51a72445a18c30d767a3c978005c917eb6f2bcd93ece4e00669a914bb0fa1e3e", "fnmt-rsa-supervisor-especimen-99949999A-2025.pem"),
			),
			person("fnmt-citizen-g2", "fnmt", "FNMT Persona Física (AC USUARIOS G2)",
				[]Anchor{anchor("283a9f9fe9674f67efd6e27bb543e0ec192cbeff20fc836c2243654744c5af89", "4a7bdf68ccebcdbfccfcdbe75ccb2d744e28be51a401fa34da558489696c807f")},
				[]string{"1.3.6.1.4.1.5734.3.20.1.0"}, g2,
				policy(true, []string{"ocspusug2.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}),
				fp("83f79619f52ab8f36755de28680685cfa4cefa5c44dad22397b04e70d506ec10", "fnmt-ecc-g2-activo-especimen-99949991H-2025.pem"),
				fp("d2dbabbb298198ac476d33a40933ce69c650b55f5c162e076edf72c58da9e7ba", "fnmt-ecc-g2-revocado-especimen-99949990V-2025.pem"),
			),
		}}
}

// idcat: digest B aoc-idcat-g2 / aoc-idcat-g3 (same OID, dispatched by anchor).
func idcat() Provider {
	g2 := plain()
	g2.CountryMatchesPrefix, g2.LegacyDNISuffix = true, true
	g3 := plain()
	g3.CountryMatchesPrefix = true
	hostsOCSP := []string{"ocsp.catcert.cat", "ocsp.aoc.cat"}
	hostsCRL := []string{"epscd.catcert.net", "epscd.aoc.cat"}
	p2 := person("aoc-idcat-g2", "idcat", "idCAT Certificat (EC-Ciutadania)",
		[]Anchor{anchor("0fd99aae1ffcd5d9f0ad76edddcbef6b884cc85c16bfcfa4b5246155d6597ed6", "3761345542c20b314a744a7c54a82152a283be9cdcda233f050000c2d0e5070d")},
		[]string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, g2, policy(true, hostsOCSP, hostsCRL),
		fp("81ffa40e096b6cf32c3082454d22ace4f0bb009b99f26995eb59da36eae4482b", "idcat-g2-pf-peca-de-proves-00000000T.pem"),
		TestMarker{Subject: []AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}},
			Source: "AOC DPC v7.4 §1.1.3 production test certificate"},
	)
	p2.HandledCriticalExtensions = []string{"1.3.6.1.5.5.7.1.3"} // qcStatements, critical on leaves before profile v6.8
	p3 := person("aoc-idcat-g3", "idcat", "idCAT Certificat (SubCA CIUTADANIA Q (G3) A.2)",
		[]Anchor{anchor("e6dc96bb0dbcb242490fdf348cb8c9ec012e9cb959ff4458bb503e5efb1e1735", "4da535844e847db014be7e842d7b243118f3d28ce487c32cb62e5a72c70b88c2")},
		[]string{"1.3.6.1.4.1.15096.1.3.2.86.2"}, g3, policy(true, hostsOCSP, hostsCRL),
		TestMarker{Subject: []AttributeMatch{{OID: identity.OIDGivenName, Value: "NOMDOS"}, {OID: identity.OIDSurname, Value: "ESPECIMENDOS ESPECIMENDOS"}},
			Source: "AOC DPC v7.4 §1.1.3 production test certificate"},
	)
	return Provider{ID: "idcat", Name: "idCAT Certificat", Description: "Certificat idCAT del Consorci AOC",
		Profiles: []Profile{p2, p3}}
}

// accv: digest A accv-citizen-software-current (RSA1 and ECC1 CLIENTE).
func accv() Provider {
	a := identity.Adapter{
		Documents: bare, Surnames: identity.SurnamesFromSN,
		SAN:       identity.SANCheck{Kind: identity.SANPipeCN, DocumentOID: identity.OIDUID, DocumentRules: bare},
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationNone,
	}
	p := person("accv-citizen-software-current", "accv", "ACCV Ciudadano en soporte software",
		[]Anchor{
			anchor("a66b485645a5d66a5714a360e02ddf3ab71875e77db198ba321a8f62ff01d7e1", "03cd20b076b5b589a78efa46a09e6d1cc8ba5878088113749d16f7414cd9c1f1"),
			anchor("5caf44b2923b146cb575ab2ab9a0a293a134602335d97e579c44493532f48496", "73b39454c0f85a4f23e29e923073aa74f755934809e359f2ea87c9eebfa34b75"),
		},
		[]string{"1.3.6.1.4.1.8149.3.7.8.0"}, a,
		policy(true, []string{"ocsp.accv.es"}, []string{"www.accv.es"}))
	return Provider{ID: "accv", Name: "ACCV - Ciudadano (software)",
		Description: "Certificado cualificado de Ciudadano en soporte software de la ACCV", Profiles: []Profile{p}}
}

// digitel: digest C digitel-citizen-sw-g1.
func digitel() Provider {
	return Provider{ID: "digitel", Name: "DIGITEL ON - Ciudadano", Description: "Certificado cualificado de ciudadano DIGITEL (software)",
		Profiles: []Profile{person("digitel-citizen-sw-g1", "digitel", "DIGITEL Ciudadano software (QUALIFIED CA G1)",
			[]Anchor{anchor("86a62f63dcabec9f3d50beb185f43ba0f44253d67cd23b6c7959117ac550ba61", "00600557c6552a65e2dd8dee34d7b674043fd1c5935562ded5f26e2e5777eabb")},
			[]string{"1.3.6.1.4.1.54225.10.3.1"}, plain(),
			policy(true, []string{"ocsp.digitelts.es"}, []string{"crl1.pki.digitelts.es", "crl2.pki.digitelts.es"}),
			fp("fed45259637950d331447a9e4d12c20ae95411cb8553c7f3dd02fc7df54e8ec8", "digitel-ciudadanosw-99949996T.pem"),
		)}}
}

// bewor: digest C bewor-natural-person-sw (.1.1.1 centralised HSM is not listed).
// The specimen files are withheld (ruling R30); their fingerprints stay pinned.
func bewor() Provider {
	return Provider{ID: "bewor", Name: "Bewor - Persona Física", Description: "Certificado cualificado de persona física Bewor (software)",
		Profiles: []Profile{person("bewor-natural-person-sw", "bewor", "Bewor Persona Física software (BEWOR TECH CA1)",
			[]Anchor{anchor("8a386ed1c0932603d3b5f4789b7fcb33cf09c81a56de97fc826747956c2e786d", "ba0331d2b536d13f5d8953475ae3b945764ed54b3788ba5bf4f4a7ee6e770003")},
			[]string{"1.3.6.1.4.1.55693.1.1.2"}, plain(),
			policy(true, []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, []string{"crl1.uanataca.com", "crl2.uanataca.com"}),
			fp("da5f38fbaa6afdeca3666108eb24e6e6355b5558ab5e36c5a555e262da0bc8ab", "bewor-pfsoftbt-99949999A.pem"),
			fp("52bef7a958c349ed0dc1881865c911820e9ef9f7b32741d67273a8f1ba527d92", "bewor-pfsoftbt-revocado-99999999R.pem"),
		)}}
}

// sectigo: digest C sectigo-citizen-local (R35 and E35); pre-generated OCSP, no nonce.
// The specimen files are withheld (ruling R30); their fingerprints stay pinned.
func sectigo() Provider {
	return Provider{ID: "sectigo", Name: "Sectigo - Ciudadano", Description: "Certificado cualificado de ciudadano Sectigo (no QSCD)",
		Profiles: []Profile{person("sectigo-citizen-local", "sectigo", "Sectigo Qualified Natural Person (Citizen)",
			[]Anchor{
				anchor("ac866830d7b8d71273c7cde057a8d53e934c4e6f16947d138a123cbec8c63bde", "eb9f35a491f478c19fc0cdc02a8a5d54df26ed3b248f587459539bc2a48f6a24"),
				anchor("53b24005fd13671f549989c8c669059eabe77ad19ddee1e70f72c9fbb3c0d9f9", "8e351d9cb41b50d077af2842b9faf748c4269ea6cf01e34d29f1f83c85edf983"),
			},
			[]string{"1.3.6.1.4.1.6449.1.2.1.7.1"}, plain(),
			policy(false, []string{"ocsp.sectigo.com"}, []string{"crl.sectigo.com"}),
			fp("88059e9240bb96734d0a0c07d27a9fbd2741ebbdd49c08004b14b443962f2c30", "sectigo-citizen-99949990V.pem"),
			fp("5afc90f8e6a60ce17fc4bb80f11ce1e897565cf8d870e96eeeeaaa9c224df187", "sectigo-employee-99949993C.pem"),
		)}}
}

// fnmtRepresentative (beta): digest A, three roles per CA generation. The
// responders echo the OCSP nonce (live probe, R65).
func fnmtRepresentative() Provider {
	a := identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN, SAN: fnmtSAN(idces),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationFromSubject}
	rsa := person("fnmt-representative-rsa", "fnmt-representative", "FNMT Representante (AC Representación)",
		[]Anchor{anchor("8fd16a179944d5d1d420af09405eda7abf2a9c742883e8c2f89e0d90afaf754b", "da576c79f49f91353b1865dfcf889888f9ce50391b2a261d51a3c677676ef044")},
		[]string{"1.3.6.1.4.1.5734.3.11.1", "1.3.6.1.4.1.5734.3.11.2", "1.3.6.1.4.1.5734.3.11.3"}, a,
		policy(true, []string{"ocsprep.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	g2 := person("fnmt-representative-g2", "fnmt-representative", "FNMT Representante (AC REPRESENTACIÓN G2)",
		[]Anchor{anchor("0df2883b6074d5b7d7940b69ca658a3a9a747a8e171f653ad4ce0230087d9d64", "66f3f2da778bf26070b42bc7accd97d9f188d25a15f1e2575603042618c13502")},
		[]string{"1.3.6.1.4.1.5734.3.21.1.0", "1.3.6.1.4.1.5734.3.21.2.0", "1.3.6.1.4.1.5734.3.21.3.0"}, a,
		policy(true, []string{"ocsprepg2.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	rsa.HolderRole, g2.HolderRole = RoleRepresentative, RoleRepresentative
	return Provider{ID: "fnmt-representative", Name: "FNMT - Representante", Beta: true,
		Description: "Certificado de Representante de la FNMT-RCM", Profiles: []Profile{rsa, g2}}
}

// fnmtEmployee (beta): digest A, software lanes only (17.2 and 23.1.0). The
// responders echo the OCSP nonce (live probe, R65).
func fnmtEmployee() Provider {
	n := func(i int) asn1.ObjectIdentifier { return oid(2, 16, 724, 1, 3, 5, 7, 2, i) }
	a := identity.Adapter{Documents: idces, Surnames: identity.SurnamesFromSN,
		SAN:       sanAttrs(n(4), bare, n(6), n(7), n(8)),
		BirthDate: identity.BirthDateNone, Organization: identity.OrganizationFromSubject}
	rsa := person("fnmt-employee-rsa", "fnmt-employee", "FNMT Empleado Público (AC Sector Público)",
		[]Anchor{anchor("8265756dd5cd8a37ee61e40351288e4b16a89dd248c1ec4eba25aaf161abf498", "68de305107cbd1889d7a9b039fdca503c1a88ad1f45d1752df8f50c72969d915")},
		[]string{"1.3.6.1.4.1.5734.3.17.2"}, a,
		policy(true, []string{"ocspsp.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	g2 := person("fnmt-employee-g2", "fnmt-employee", "FNMT Empleado Público (AC SECTOR PÚBLICO G2)",
		[]Anchor{anchor("983329b00c3052d7eccd46bf2cf3e29d05ae93d1aa146bd5078c3726ae8271fe", "a1e3f004222a51998b97853b50fdbfbe9b3f932c3bd0b85737663bd19b33a906")},
		[]string{"1.3.6.1.4.1.5734.3.23.1.0"}, a,
		policy(true, []string{"ocspspg2.cert.fnmt.es"}, []string{"www.cert.fnmt.es"}))
	rsa.HolderRole, g2.HolderRole = RolePublicEmployee, RolePublicEmployee
	return Provider{ID: "fnmt-employee", Name: "FNMT - Empleado Público", Beta: true,
		Description: "Certificado de Empleado Público de la FNMT-RCM (software)", Profiles: []Profile{rsa, g2}}
}

// firmaprofesional (beta): digest C; CUALIFICADOS pinned once (alias 4ccf17c0 not loaded) plus ICA B01.
func firmaprofesional() Provider {
	a := plain()
	a.SAN = fp13177()
	return Provider{ID: "firmaprofesional", Name: "Firmaprofesional", Beta: true,
		Description: "Certificado Personal de Persona Física (sin DCCF)",
		Profiles: []Profile{person("firmaprofesional-personal-sw", "firmaprofesional", "Firmaprofesional Persona Física (sin DCCF)",
			[]Anchor{
				anchor("2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf", "c695bd5c40f753beb93f653202a3d6354ede0dd21295fd894a0869be366753e6"),
				anchor("4a86f3337cec89a67896b8a6cbbada84ac181eb009679e1504156c34bc9f8aa1", "dab1f8803dcf0900d5810e5d9b598781a1f039b30bdf89ad241bfa3e358dd8f9"),
			},
			[]string{"1.3.6.1.4.1.13177.10.1.40.2"}, a,
			policy(false, []string{"ocsp.firmaprofesional.com"}, []string{"crl.firmaprofesional.com"}))}}
}

// anf (beta): digest C, two legal providers, one anchor each; private SAN
// ignored. The responder echoes the OCSP nonce (live probe, R65).
func anf() Provider {
	asoc := person("anf-asociacion-class2-sw", "anf", "ANF AC Clase 2 Persona Física (Asociación)",
		[]Anchor{anchor("b7cdf23a73a2da1b515a64403e90a3b90c45ddfbb2558bc1c12fb9bcfa2e5a23", "d1b4c6d6b4f387bd50f89359a11c3a07673effb796cbcecfd32219594362988c")},
		[]string{"1.3.6.1.4.1.18332.3.4.1.2.22"}, plain(),
		policy(true, []string{"ocsp.anf.es"}, []string{"crl.anf.es"}))
	sl := person("anf-sl-class2-sw", "anf", "ANF Clase 2 Persona Física (S.L.)",
		[]Anchor{anchor("5999789a17df8674d098db057df8ed3764e96529d4a0eb56246de3c46fb0e28a", "9992ddc44e5b001f31044fd4723e424e3e2509799b084211f660d321a2fea436")},
		[]string{"1.3.6.1.4.1.49201.3.4.1.2.22"}, plain(),
		policy(true, []string{"ocsp.anf.es"}, []string{"crl.anf.es"}))
	return Provider{ID: "anf", Name: "ANF AC", Beta: true,
		Description: "Certificado de Clase 2 de Persona Física (software)", Profiles: []Profile{asoc, sl}}
}

// uanataca (beta): digest C uanataca-citizen-sw, four issuing CAs. The
// responders echo the OCSP nonce (live probe, R65).
func uanataca() Provider {
	return Provider{ID: "uanataca", Name: "Uanataca", Beta: true,
		Description: "Certificado cualificado de Persona Física Ciudadano en software",
		Profiles: []Profile{person("uanataca-citizen-sw", "uanataca", "Uanataca Ciudadano en software",
			[]Anchor{
				anchor("35a99284a220789ba0e062eeff1b5f2f74be43754469977cb318c7c86ad48f9f", "c886cd88edc69bffba28dcc5ba092fa5906742ce4712ddfc71e4e5851fa51f26"),
				anchor("00ff2ff2efba98c6b023ad1035559a606dd9fc48a39d3407cc07a678379a7909", "fac53d2ea5667fa530415045aa563d293ed0de542e26a0607f31a480c695fe75"),
				anchor("9b083dc45b1bec211f93098f915d3d5ee2d7dfa93720fed4e286b83c1ef4469a", "12093d696c24875b59dbc44b2ac814961b8bc73b870310f6cecd5d21a4e6787a"),
				anchor("15ceab339144d48d352eef1c227f4d2ef4fc1756dead602c22be32d52100e69a", "5f78b32f4a4770c8676ac81b467005ce22dde8f2613c5acca3612bcf6029a9b6"),
			},
			[]string{"1.3.6.1.4.1.47286.1.1.1.1"}, plain(),
			policy(true, []string{"ocsp1.uanataca.com", "ocsp2.uanataca.com"}, []string{"crl1.uanataca.com", "crl2.uanataca.com"}))}}
}

// signe (beta): digest C; NIE as PNOES-<NIE> only here; leaf OCSP unknown, so CRL only.
// signe-subca.crl answers 302 to https://crl.firmaprofesional.com (R64).
func signe() Provider {
	a := plain()
	a.Documents = []identity.DocumentRule{
		{Encoding: identity.EncodingIDCES, Types: dniOnly},
		{Encoding: identity.EncodingPNOES, Types: nieOnly},
	}
	a.SAN = fp13177()
	return Provider{ID: "signe", Name: "SIGNE", Beta: true,
		Description: "Certificado Personal de Persona Física (otros dispositivos)",
		Profiles: []Profile{person("signe-personal-otros-dispositivos", "signe", "SIGNE Persona Física (otros dispositivos)",
			[]Anchor{
				anchor("b8df384f1fcd6ecb3f4d7dd6380e54d354c61256560a599d80453247d93af5ea", "7988bdc1ad8ebd8bf150d25ffe876fb05bb3444e1c064bd13f2a57d82bb5f66f"),
				anchor("244166240947c4074418df2606fc3ebf5a765f6b9692185fc091ea669986da35", "6a30d221e4acfdae38d34006418094fa8337da2f30b9a99c04cfe7d98317dd70"),
			},
			[]string{"1.3.6.1.4.1.36035.1.3.2"}, a,
			policy(false, nil, []string{"www.signe.es", "crl.firmaprofesional.com"}))}}
}

// lleidanet (beta): digest C lleidanet-natural-person-sw. CRL only (R63): the
// ocsp2.esigna.es responder certificate lacks id-pkix-ocsp-nocheck, so its
// answers are never acceptable; the leaves' AIA OCSP URL is ignored.
func lleidanet() Provider {
	return Provider{ID: "lleidanet", Name: "Lleidanet / inDenova", Beta: true,
		Description: "Certificado de Persona Natural Software",
		Profiles: []Profile{person("lleidanet-natural-person-sw", "lleidanet", "Lleidanet Persona Natural Software",
			[]Anchor{anchor("3452e96743442607f21d85084c3db897e37549fed23f135cdbd202e690d52e25", "e0f0a51ac007c5ea964344e785c4ac005d8db0e8cd7a33943f726a46c0532d3e")},
			[]string{"1.3.6.1.4.1.49959.1.1.1.1.1"}, plain(),
			policy(false, nil, []string{"crl1.esigna.es", "crl.esigna.es"}))}}
}

// dnie (beta): digest A dnie-auth plus the fixture manifest answers (G1).
func dnie() Provider {
	a := identity.Adapter{
		Documents: []identity.DocumentRule{{Encoding: identity.EncodingBare, Types: dniOnly}},
		Surnames:  identity.SurnamesDNIeCN, SAN: noSAN,
		BirthDate: identity.BirthDateOptional, Organization: identity.OrganizationNone,
	}
	p := person("dnie-auth", "dnie", "DNIe Autenticación",
		[]Anchor{anchor("c5c380eb9240fb36a16e15f5d6bad0bf611f6d03f0ef24229919e7d2d8126c11", "4a5dc6f078372f3497d01ba654c902357b54a1c53387f8b3cf3b92749cdeb44b")},
		[]string{"2.16.724.1.2.2.2.4"}, a,
		// pki.policia.es serves the root ARL for the pinned intermediates; leaves have no CDP.
		policy(true, []string{"ocsp.dnie.es"}, []string{"pki.policia.es"}),
		fp("ce3dff1caf0b15381a97f428f8346a0d81fafc818402a096960a90ce8bac0059", "dnie-ac004-auth-activo.pem"),
		fp("c6caec7063ae8a37efb36d54086444812ccdf2e8d9ae81b2d68cfe53a315f554", "dnie-ac004-auth-caducado.pem"),
		fp("7059081d082e86bf2678f61ce9c818ee73adf9ff52dbc7dcbd1618bbc6359541", "dnie-ac004-auth-revocado.pem"),
		fp("767cdce2cb7e3e5c5ca13dfb6695535c0d3bc678fd6ac9bf8c02d83226b6d2d6", "dnie-ac004-firma-activo.pem"),
		fp("9ed5001c16deac81eca78ff293fd78a15362a13b9867558f645a1cab0c7f4df5", "dnie-ac004-firma-caducado.pem"),
		fp("6c3315c2f98c396314224970494df9d77f609ed30b61b70a261e51fbf8998ddf", "dnie-ac004-firma-revocado.pem"),
		fp("7a74251ea5ca45c971ba067fa1941fc128bb4a3e7b886b90754209b1ccc44815", "dnie-ac004-firmacentralizada-activo.pem"),
		fp("64412f7a0b4540b0ce57b47c2339319094a1efba35109860bc047ce060558a0f", "dnie-ac004-firmacentralizada-caducado.pem"),
		fp("21ad4a4966ef8ec6f7904718c509506542d6e4ed7baf4079f925b1fbcce97dc6", "dnie-ac004-firmacentralizada-revocado.pem"),
		fp("cde734ca6f58e7450ed58cef14357c619474c80930171880c69c284a238492b5", "dnie-ac001-auth-activo.pem"),
		fp("6af1aec2a3422648643a353e3baf5362d7a91797c904cf50fa97c7db4288efc0", "dnie-ac001-auth-revocado.pem"),
		fp("a7aebe5c4d5864733439327180108bf524962d71fee55da0dc79b585dc3ef02a", "dnie-ac001-firma-activo.pem"),
		fp("a22ef3464ab64708854b832eeb4004e4afe0b6fdba614cbe62f4afb9345092fe", "dnie-ac001-firma-revocado.pem"),
	)
	p.EKU = EKUAllowAbsent // "extKeyUsage: No se utilizará" (CPS v3.4)
	p.Intermediates = []Anchor{
		anchor("ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c", "1b5b9b72ed25bdab71a112d252c747f5961bfed9ad4bce77292af34b1146481f"), // AC DNIE 004
		anchor("828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828", "1f6b84c54a1824bdc0f639487dfaa29c7b2bc7fefe69499651eb2036fcf859a2"), // AC DNIE 005
		anchor("eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd", "60a9a73a0c25f1e14b44508554076c2c48ad32c503c9bc534c945a82a290cb97"), // AC DNIE 006
	}
	return Provider{ID: "dnie", Name: "DNIe (requires card reader)", Beta: true,
		Description: "Certificado de Autenticación del DNI electrónico; the browser must already be able to use the card",
		Profiles:    []Profile{p}}
}

// IntermediateExceptions are pinned intermediates that are not TSL service
// identities. Reviewed: official AIA downloads (anchors/SOURCES.md), verified
// against AC RAIZ DNIE 2.
var IntermediateExceptions = []string{
	"ebae99303045630764dc5cf9d5af9dc009354d8729c407b6bf9a136208046f6c",
	"828a22ff05932483c9e8d252399ba115a57da75869d204422951ffa14c8ee828",
	"eda47e8a12d7e8a72721c220069807523e746b48c2441443177b5fbc58103bbd",
}

// KnownAliases are TSL service identities deliberately not loaded because a
// pinned anchor has the same subject and key (crypto/tls would advertise the
// DN twice). Value: the pinned anchor.
var KnownAliases = map[string]string{
	"4ccf17c0c8c1c10d5876ec5e3280fe8d134df36aedd8444289b990bc3741e74f": "2b75cc4f36759cfc4c6637b1e0e54359457db57e74de4d2dc5d02cddff2960cf",
}
