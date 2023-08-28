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
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	cfg = &certGenConfig{}
)

type certGenConfig struct {
	flCN       string
	flFileName string
	flSNI      string
}

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	san              = flag.String("dnsSAN", "server.domain.com", "DNS SAN Value for cert")
	pemCSRFile       = flag.String("pemCSRFile", "certs/client.csr", "CSR File to write to")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")
	evict            = flag.Bool("evict", false, "delete persistent handle")
	handleNames      = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
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
		glog.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("\ncan't close TPM %q: %v", *tpmPath, err)
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

	k, err := client.NewKey(rwc, tpm2.HandleOwner, unrestrictedKeyParams)
	if err != nil {
		glog.Fatalf("can't create SRK %q: %v", *tpmPath, err)
	}

	kh := k.Handle()

	kk, err := client.NewCachedKey(rwc, tpm2.HandleOwner, unrestrictedKeyParams, kh)
	s, err := kk.GetSigner()
	if err != nil {
		glog.Fatalf("can't getSigner %q: %v", *tpmPath, err)
	}

	pHandle := tpmutil.Handle(*persistentHandle)
	if *evict {
		err = tpm2.EvictControl(rwc, defaultPassword, tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			glog.Fatalf("Error  evicting key  %v\n", err)
		}
	}
	err = tpm2.EvictControl(rwc, defaultPassword, tpm2.HandleOwner, kh, pHandle)
	if err != nil {
		glog.Fatalf("Error  persisting  key  %v\n", err)

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
