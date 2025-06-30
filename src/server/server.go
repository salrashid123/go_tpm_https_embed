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

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/signer/tpm"
	"golang.org/x/net/http2"
)

var (
	cacert           = flag.String("cacert", "certs/CA_crt.pem", "RootCA")
	port             = flag.String("port", ":8081", "listen port (:8081)")
	servercert       = flag.String("servercert", "certs/server.crt", "Server certificate (x509)")
	severkey         = flag.String("severkey", "certs/server_key.pem", "TPM based private key")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	tpmPath          = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
)

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
	log.Println("/index.html called")

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
	flag.Parse()

	log.Printf("======= Init  ========")

	caCert, err := os.ReadFile(*cacert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// start externally managed
	// managed externally, this will block all other access to the tpm
	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()
	rwr := transport.FromReadWriter(rwc)

	c, err := os.ReadFile(*severkey)
	if err != nil {
		log.Fatalf("can't load keys %q: %v", *tpmPath, err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("can't decode keys %q: %v", *tpmPath, err)
	}

	// specify its parent directly
	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: key.Parent,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// now the actual key can get loaded from that parent
	rsaKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		log.Fatalf("can't load  hmacKey : %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: rsaKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	flushContextCmd := tpm2.FlushContext{
		FlushHandle: primaryKey.ObjectHandle,
	}
	_, _ = flushContextCmd.Execute(rwr)

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice:      rwc,
		Handle:         rsaKey.ObjectHandle,
		PublicCertFile: *servercert,
	})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/index.html", fronthandler)

	tcrt, err := r.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr: *port,
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
