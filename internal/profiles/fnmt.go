package profiles

import (
	"encoding/asn1"

	"github.com/vocdoni/cert-check/internal/identity"
)

func fnmt5734(n int) asn1.ObjectIdentifier { return oid(1, 3, 6, 1, 4, 1, 5734, 1, n) }

// fnmtSAN: 5734.1.4 document (encoding differs: citizen bare, representative IDCES-),
// .1.1 given, .1.2 first surname, .1.3 second surname; order-independent.
func fnmtSAN(doc []identity.DocumentRule) identity.SANCheck {
	return sanAttrs(fnmt5734(4), doc, fnmt5734(1), fnmt5734(2), fnmt5734(3))
}

// FNMT: digest A fnmt-citizen-rsa / fnmt-citizen-g2; manifest G3-G6.
func FNMT() Provider {
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

// FNMTRepresentative (beta): digest A, three roles per CA generation. The
// responders echo the OCSP nonce (live probe, R65).
func FNMTRepresentative() Provider {
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

// FNMTEmployee (beta): digest A, software lanes only (17.2 and 23.1.0). The
// responders echo the OCSP nonce (live probe, R65).
func FNMTEmployee() Provider {
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
