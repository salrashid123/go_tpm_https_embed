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
	"os"

	sal "github.com/salrashid123/signer/tpm"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	cacert           = flag.String("cacert", "certs/CA_crt.pem", "RootCA")
	address          = flag.String("address", "", "Address of server")
	pubCert          = flag.String("pubCert", "certs/kclient.crt", "Public Cert file")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	flush            = flag.Bool("flush", false, "flushHandles")

	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
		"none":      {},
	}
)

func main() {
	flag.Parse()

	log.Printf("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	if *flush {
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

	k, err := client.LoadCachedKey(rwc, tpmutil.Handle(*persistentHandle), nil)
	if err != nil {
		log.Printf("ERROR:  could not initialize Key: %v", err)
		return
	}

	r, err := sal.NewTPMCrypto(&sal.TPM{
		TpmDevice:      rwc,
		Key:            k,
		PublicCertFile: *pubCert,
	})

	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caCertPool,
			ServerName:   "server.domain.com",
			Certificates: []tls.Certificate{r.TLSCertificate()},
		},
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
