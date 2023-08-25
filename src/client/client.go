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
)

var (
	cacert           = flag.String("cacert", "certs/CA_crt.pem", "RootCA")
	address          = flag.String("address", "", "Address of server")
	pubCert          = flag.String("pubCert", "certs/kclient.crt", "Public Cert file")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
)

func main() {
	flag.Parse()

	caCert, err := ioutil.ReadFile(*cacert)
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

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice:          *tpmPath,
		TpmHandle:          uint32(*persistentHandle),
		PublicCertFile:     *pubCert,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			ServerName: "server.domain.com",
			RootCAs:    caCertPool,
			ClientCAs:  caCertPool,
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		// TLSClientConfig: &tls.Config{
		// 	RootCAs:      caCertPool,
		// 	ServerName:   "server.domain.com",
		// 	Certificates: []tls.Certificate{clientCerts},
		// },
		TLSClientConfig: r.TLSConfig(),
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://%s:8081", *address))
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
