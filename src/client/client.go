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
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	sal "github.com/salrashid123/signer/tpm"
)

var (
	cacert           = flag.String("cacert", "certs/CA_crt.pem", "RootCA")
	address          = flag.String("address", "", "Address of server")
	pubCert          = flag.String("pubCert", "certs/kclient.crt", "Public Cert file")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
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

func main() {
	flag.Parse()

	log.Printf("======= Init  ========")

	caCert, err := os.ReadFile(*cacert)
	if err != nil {
		log.Println(err)
		return
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// clientCerts, err := tls.LoadX509KeyPair(
	// 	"certs/client.crt",
	// 	"certs/client.key",
	// )
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

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
	pub, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(*persistentHandle),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing tpm2.ReadPublic %v", err)
	}

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice: rwc,
		AuthHandle: &tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(*persistentHandle),
			Name:   pub.Name,
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		PublicCertFile: *cacert,
	})

	if err != nil {
		log.Fatal(err)
	}

	tcrt, err := r.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caCertPool,
			ServerName:   "server.domain.com",
			Certificates: []tls.Certificate{tcrt},
		},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s:8081", *address))
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
