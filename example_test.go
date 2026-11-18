// Copyright (C) 2026 Synergize S.L. <https://synergize.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later

package certcheck_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	certcheck "github.com/vocdoni/cert-check"
	"github.com/vocdoni/cert-check/providers/fnmt"
	"github.com/vocdoni/cert-check/providers/idcat"
)

// A program accepts the certificate types whose providers it constructs.
func Example() {
	h, err := certcheck.NewHandler([]certcheck.Provider{idcat.New(), fnmt.New()})
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range h.Providers() {
		fmt.Println(p.Info().ID, "-", p.Info().Name)
	}
	// Output:
	// idcat - idCAT Certificat
	// fnmt - FNMT - Persona Física
}

// The handler supplies the TLS configuration of the listener that asks for
// the client certificate, and verifies the certificate of each request.
func ExampleHandler_Auth() {
	h, err := certcheck.NewHandler([]certcheck.Provider{idcat.New(), fnmt.New()})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if err := certcheck.CheckHost(r); err != nil {
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second) // OCSP and CRL fetches
		defer cancel()
		res, err := h.Auth(r.WithContext(ctx))
		if err != nil {
			if e, ok := errors.AsType[*certcheck.Error](err); ok {
				slog.Info("certificate rejected", slog.Any("diagnostics", e.Diagnostics.LogAttrs()))
				http.Error(w, string(e.Code), http.StatusForbidden)
			}
			return
		}
		fmt.Fprintf(w, "hello %s (%s %s)\n", res.Identity.FullName, res.Identity.Document.Type, res.Identity.Document.Number)
	})
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error) // e.g. from certmagic or autocert
	var protocols http.Protocols
	protocols.SetHTTP1(true) // HTTP/1 only, or net/http adds h2 (see TLSConfig)
	srv := &http.Server{Addr: ":8443", Handler: mux, TLSConfig: h.TLSConfig(getCertificate), Protocols: &protocols}
	// log.Fatal(srv.ListenAndServeTLS("", ""))
	fmt.Println(srv.TLSConfig.ClientAuth, srv.TLSConfig.MaxVersion == tls.VersionTLS12, srv.Protocols.HTTP2())
	// Output: RequestClientCert true false
}

// A Result carries the provider, the profile and the holder's identity.
func ExampleResult() {
	const body = `{"provider":{"id":"fnmt","name":"FNMT - Persona Física"},
		"profile":{"id":"fnmt-citizen-rsa","name":"FNMT Persona Física (AC FNMT Usuarios)","holderRole":"natural_person"},
		"identity":{"document":{"type":"DNI","country":"ES","number":"12345679S","raw":"IDCES-12345679S"},
		"givenNames":"JUAN","surnames":"GARCÍA LÓPEZ","firstSurname":"GARCÍA","secondSurname":"LÓPEZ","fullName":"JUAN GARCÍA LÓPEZ"}}`
	var res certcheck.Result
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		log.Fatal(err)
	}
	id := res.Identity
	fmt.Println(id.Document.Type, id.Document.Number)
	fmt.Println(id.GivenNames, "/", id.FirstSurname, "/", id.SecondSurname)
	fmt.Println(res.Provider.ID, res.Profile.HolderRole)
	fmt.Println(res.Profile.HolderRole == certcheck.RoleNaturalPerson, id.Document.Type == certcheck.DocumentDNI)
	// Output:
	// DNI 12345679S
	// JUAN / GARCÍA / LÓPEZ
	// fnmt natural_person
	// true true
}

// Every failure is an *Error with a typed code. FNMT publishes this specimen
// as a test certificate, so it is refused before any network access.
func ExampleError() {
	raw, err := os.ReadFile("testdata/specimens/fnmt-ecc-g2-activo-especimen-99949991H-2025.pem")
	if err != nil {
		log.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	clock := func() time.Time { return leaf.NotBefore.Add(time.Hour) } // the day it was issued
	h, err := certcheck.NewHandler([]certcheck.Provider{fnmt.New(certcheck.WithClock(clock))}, certcheck.WithClock(clock))
	if err != nil {
		log.Fatal(err)
	}
	_, err = h.Verify(context.Background(), []*x509.Certificate{leaf})
	if e, ok := errors.AsType[*certcheck.Error](err); ok {
		fmt.Println(e.Code, e.Diagnostics.FailedStep, e.Retryable)
	}
	// Output: test_certificate test_marker false
}
