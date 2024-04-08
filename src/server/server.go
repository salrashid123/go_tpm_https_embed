// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/signer/tpm"

	"golang.org/x/net/http2"
)

var (
	cfg         = &argConfig{}
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}
)

type argConfig struct {
	flCA               string
	flPort             string
	flServerCert       string
	flTPMDevice        string
	flPersistentHandle uint
	flFlushHandles     bool
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
	flag.BoolVar(&cfg.flFlushHandles, "flush", false, "FlushHandles")

	flag.Parse()

	log.Printf("======= Init  ========")

	rwc, err := tpm2.OpenTPM(cfg.flTPMDevice)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", cfg.flTPMDevice, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", cfg.flTPMDevice, err)
		}
	}()

	if cfg.flFlushHandles {
		totalHandles := 0
		for _, handleType := range handleNames["all"] {
			handles, err := client.Handles(rwc, handleType)
			if err != nil {
				log.Fatalf("getting handles: %v", err)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					log.Fatalf("flushing handle 0x%x: %v", handle, err)
				}
				log.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}
		log.Printf("%d handles flushed\n", totalHandles)
	}

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		log.Fatalf("Invalid Argument error: "+s, v...)
	}
	if cfg.flCA == "" {
		argError("-cacert not specified")
	}

	caCert, err := os.ReadFile(cfg.flCA)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(cfg.flPersistentHandle), nil)
	if err != nil {
		log.Printf("ERROR:  could not initialize Key: %v", err)
		return
	}

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice:      rwc,
		Key:            k,
		PublicCertFile: cfg.flServerCert,
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
