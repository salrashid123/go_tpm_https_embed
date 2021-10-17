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
	flCA         string
	flPort       string
	flServerCert string
	flTPMDevice  string
	flTPMFile    string
}

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	fmt.Fprint(w, "ok")
}

func main() {

	flag.StringVar(&cfg.flCA, "cacert", "certs/CA_crt.pem", "path-to-cacert")
	flag.StringVar(&cfg.flPort, "port", ":8081", "listen port (:8081)")
	flag.StringVar(&cfg.flServerCert, "servercert", "certs/server.crt", "Server certificate (x509)")
	flag.StringVar(&cfg.flTPMDevice, "tpmdevice", "/dev/tpm0", "TPM Device to use")
	flag.StringVar(&cfg.flTPMFile, "tpmfile", "k.bin", "TPM File to use")

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
		TpmHandleFile:      cfg.flTPMFile,
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
