// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/pem"
	"io/ioutil"

	"crypto/x509"
	"crypto/x509/pkix"
	"flag"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
)

const ()

var (
	cfg = &certGenConfig{}
)

type certGenConfig struct {
	flCN       string
	flFileName string
	flSNI      string
}

/*

go run src/csr/csr.go  -v 20 -alsologtostderr

*/

var (
	tpmPath    = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	san        = flag.String("dnsSAN", "server.domain.com", "DNS SAN Value for cert")
	pemCSRFile = flag.String("pemCSRFile", "certs/client.csr", "CSR File to write to")
	keyFile    = flag.String("keyFile", "k.bin", "TPM KeyFile")

	handleNames = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}
	unrestrictedKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSAPSS,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()
	glog.V(2).Infof("======= Init  ========")

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames["all"] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			glog.Fatalf("getting handles: %v", err)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				glog.Fatalf("flushing handle 0x%x: %v", handle, err)
			}
			glog.V(2).Infof("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	glog.V(2).Infof("%d handles flushed\n", totalHandles)

	k, err := client.NewKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams)
	if err != nil {
		glog.Fatalf("can't create SRK %q: %v", tpmPath, err)
	}

	kh := k.Handle()
	glog.V(2).Infof("======= ContextSave (k) ========")
	khBytes, err := tpm2.ContextSave(rwc, kh)
	if err != nil {
		glog.Fatalf("ContextSave failed for ekh: %v", err)
	}
	err = ioutil.WriteFile("k.bin", khBytes, 0644)
	if err != nil {
		glog.Fatalf("ContextSave failed for ekh: %v", err)
	}
	tpm2.FlushContext(rwc, kh)

	glog.V(2).Infof("======= ContextLoad (k) ========")
	khBytes, err = ioutil.ReadFile(*keyFile)
	if err != nil {
		glog.Fatalf("ContextLoad failed for ekh: %v", err)
	}
	kh, err = tpm2.ContextLoad(rwc, khBytes)
	if err != nil {
		glog.Fatalf("ContextLoad failed for kh: %v", err)
	}
	kk, err := client.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, kh)
	s, err := kk.GetSigner()
	if err != nil {
		glog.Fatalf("can't getSigner %q: %v", tpmPath, err)
	}

	glog.V(2).Infof("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         *san,
		},
		DNSNames:           []string{*san},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, s)
	if err != nil {
		glog.Fatalf("Failed to create CSR: %s", err)
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		},
	)
	glog.V(2).Infof("CSR \b%s\n", string(pemdata))

	err = ioutil.WriteFile(*pemCSRFile, pemdata, 0644)
	if err != nil {
		glog.Fatalf("Could not write file %v", err)
	}
	glog.V(2).Infof("CSR written to: %s", *pemCSRFile)

}
