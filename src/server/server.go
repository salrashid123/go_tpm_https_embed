// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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
	flFlushHandles     bool
}

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
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

	log.Printf("======= Init  ========")

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

	// managed by library
	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmPath:        cfg.flTPMDevice,
		KeyHandle:      tpm2.TPMHandle(cfg.flPersistentHandle).HandleValue(),
		PCRs:           []uint{},
		AuthPassword:   []byte(""),
		PublicCertFile: cfg.flServerCert,
	})

	// end internally managed

	// start externally managed
	// managed externally, this will block all other access to the tpm
	// rwc, err := OpenTPM(cfg.flTPMDevice)
	// if err != nil {
	// 	log.Fatalf("can't open TPM %q: %v", cfg.flTPMDevice, err)
	// }
	// defer func() {
	// 	if err := rwc.Close(); err != nil {
	// 		log.Fatalf("can't close TPM %q: %v", cfg.flTPMDevice, err)
	// 	}
	// }()
	// rwr := transport.FromReadWriter(rwc)
	// pub, err := tpm2.ReadPublic{
	// 	ObjectHandle: tpm2.TPMHandle(cfg.flPersistentHandle),
	// }.Execute(rwr)
	// if err != nil {
	// 	log.Fatalf("error executing tpm2.ReadPublic %v", err)
	// }

	// r, err := sal.NewTPMCrypto(&sal.TPM{
	// 	TpmDevice: rwc,
	// 	AuthHandle: &tpm2.AuthHandle{
	// 		Handle: tpm2.TPMHandle(cfg.flPersistentHandle),
	// 		Name:   pub.Name,
	// 		Auth:   tpm2.PasswordAuth([]byte("")),
	// 	},
	// 	PublicCertFile: cfg.flServerCert,
	// })

	// end externally managed

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", fronthandler)

	tcrt, err := r.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	var server *http.Server
	server = &http.Server{
		Addr: cfg.flPort,
		TLSConfig: &tls.Config{
			ServerName:   "server.domain.com",
			RootCAs:      caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caCertPool,
			Certificates: []tls.Certificate{tcrt},
		},
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Fatalf("Unable to start Server %v", err)
}
