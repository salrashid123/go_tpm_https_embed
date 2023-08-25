// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

var (
	tpmPath          = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	san              = flag.String("dnsSAN", "server.domain.com", "DNS SAN Value for cert")
	pemCSRFile       = flag.String("pemCSRFile", "csr.pem", "CSR File to write to")
	mode             = flag.String("mode", "flush", "either flush or evict")
	persistentHandle = flag.Uint("persistentHandle", 0x81008000, "Handle value")

	handleNames = map[string][]tpm2.HandleType{
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
		glog.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			glog.Fatalf("%v\ncan't close TPM %q: %v", tpmPath, err)
		}
	}()

	if *mode == "flush" {
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
	} else if *mode == "evict" {

		glog.V(2).Infof("======= Evict (k) ========")
		pHandle := tpmutil.Handle(*persistentHandle)
		err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, pHandle, pHandle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error  evicting key  %v\n", err)
			os.Exit(1)
		}

	} else {
		glog.V(2).Infof("do nothing")
	}

}
