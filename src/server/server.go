// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	sal "github.com/salrashid123/signer/tpm"

	"golang.org/x/net/http2"
)

var (
	cfg = &argConfig{}
)

type argConfig struct {
	flCA               string
	flPort             string
	flServerCert       string
	flTPMDevice        string
	flPersistentHandle uint
}

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")

	state := r.TLS
	log.Print(">>>>>>>>>>>>>>>> State <<<<<<<<<<<<<<<<")

	log.Printf("Version: %x", state.Version)
	log.Printf("HandshakeComplete: %t", state.HandshakeComplete)
	log.Printf("DidResume: %t", state.DidResume)
	log.Printf("CipherSuite: %x", state.CipherSuite)
	log.Printf("NegotiatedProtocol: %s", state.NegotiatedProtocol)
	log.Printf("NegotiatedProtocolIsMutual: %t", state.NegotiatedProtocolIsMutual)

	log.Print("Certificate chain:")
	for i, cert := range state.PeerCertificates {
		subject := cert.Subject
		issuer := cert.Issuer
		log.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", i, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
		log.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
	}

	fmt.Fprint(w, "ok")
}

func main() {

	flag.StringVar(&cfg.flCA, "cacert", "certs/CA_crt.pem", "path-to-cacert")
	flag.StringVar(&cfg.flPort, "port", ":8081", "listen port (:8081)")
	flag.StringVar(&cfg.flServerCert, "servercert", "certs/server.crt", "Server certificate (x509)")
	flag.StringVar(&cfg.flTPMDevice, "tpmdevice", "/dev/tpm0", "TPM Device to use")
	flag.UintVar(&cfg.flPersistentHandle, "persistentHandle", 0x81008000, "Handle value")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		log.Fatalf("Invalid Argument error: "+s, v...)
	}
	if cfg.flCA == "" {
		argError("-cacert not specified")
	}

	caCert, err := ioutil.ReadFile(cfg.flCA)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice:          cfg.flTPMDevice,
		TpmHandle:          uint32(cfg.flPersistentHandle),
		PublicCertFile:     cfg.flServerCert,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			ServerName: "server.domain.com",
			RootCAs:    caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", fronthandler)

	var server *http.Server
	server = &http.Server{
		Addr:      cfg.flPort,
		TLSConfig: r.TLSConfig(),
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Fatalf("Unable to start Server %v", err)
}
