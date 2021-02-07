// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpm

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"sync"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

const ()

var (
	x509Certificate x509.Certificate
	publicKey       crypto.PublicKey
	clientCAs       *x509.CertPool
	clientAuth      *tls.ClientAuthType
	//rwc             io.ReadWriteCloser

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

type TPM struct {
	s crypto.Signer

	PublicCertFile string
	ExtTLSConfig   *tls.Config

	TpmHandleFile string
	TpmDevice     string
	refreshMutex  sync.Mutex
	k             *tpm2tools.Key
}

func NewTPMCrypto(conf *TPM) (TPM, error) {

	var err error
	rwc, err := tpm2.OpenTPM(conf.TpmDevice)
	if err != nil {
		return TPM{}, fmt.Errorf("google: Public: Unable to Open TPM: %v", err)
	}
	defer rwc.Close()

	khBytes, err := ioutil.ReadFile(conf.TpmHandleFile)
	if err != nil {

		return TPM{}, fmt.Errorf("ContextLoad failed for kh: %v", err)
	}
	kh, err := tpm2.ContextLoad(rwc, khBytes)
	if err != nil {
		return TPM{}, fmt.Errorf("ContextLoad failed for kh: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)
	conf.k, err = tpm2tools.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, kh)
	if err != nil {
		return TPM{}, fmt.Errorf("Couldnot load CachedKey: %v", err)
	}

	if conf.ExtTLSConfig != nil {
		if len(conf.ExtTLSConfig.Certificates) > 0 {
			return TPM{}, fmt.Errorf("Certificates value in ExtTLSConfig Ignored")
		}

		if len(conf.ExtTLSConfig.CipherSuites) > 0 {
			return TPM{}, fmt.Errorf("CipherSuites value in ExtTLSConfig Ignored")
		}
	}

	return *conf, nil
}

func (t TPM) TLSCertificate() tls.Certificate {

	if t.PublicCertFile == "" {
		log.Fatalf("Public X509 certificate not specified")
	}

	pubPEM, err := ioutil.ReadFile(t.PublicCertFile)
	if err != nil {
		log.Fatalf("Unable to read keys %v", err)
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		log.Fatalf("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse public key: " + err.Error())
	}

	x509Certificate = *pub
	var privKey crypto.PrivateKey = t
	return tls.Certificate{
		PrivateKey:  privKey,
		Leaf:        &x509Certificate,
		Certificate: [][]byte{x509Certificate.Raw},
	}
}

func (t TPM) TLSConfig() *tls.Config {

	return &tls.Config{
		Certificates: []tls.Certificate{t.TLSCertificate()},

		RootCAs:    t.ExtTLSConfig.RootCAs,
		ClientCAs:  t.ExtTLSConfig.ClientCAs,
		ClientAuth: t.ExtTLSConfig.ClientAuth,
		ServerName: t.ExtTLSConfig.ServerName,

		// CipherSuites: []uint16{
		// 	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		// 	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		// 	tls.TLS_AES_2,
		// },
		// MaxVersion: tls.VersionTLS12,
	}
}

func (t TPM) Public() crypto.PublicKey {
	if publicKey == nil {
		t.refreshMutex.Lock()
		defer t.refreshMutex.Unlock()
		var err error
		rwc, err := tpm2.OpenTPM(t.TpmDevice)
		if err != nil {
			return nil
		}
		defer rwc.Close()

		khBytes, err := ioutil.ReadFile(t.TpmHandleFile)
		if err != nil {

			return nil
		}
		kh, err := tpm2.ContextLoad(rwc, khBytes)
		if err != nil {
			return nil
		}
		defer tpm2.FlushContext(rwc, kh)
		t.k, err = tpm2tools.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, kh)
		if err != nil {
			return nil
		}

		publicKey = t.k.PublicKey()
	}
	return publicKey
}

func (t TPM) Sign(rr io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	t.refreshMutex.Lock()
	defer t.refreshMutex.Unlock()

	var err error
	rwc, err := tpm2.OpenTPM(t.TpmDevice)
	if err != nil {
		return []byte(""), fmt.Errorf("google: Public: Unable to Open TPM: %v", err)
	}
	defer rwc.Close()

	khBytes, err := ioutil.ReadFile(t.TpmHandleFile)
	if err != nil {

		return []byte(""), fmt.Errorf("ContextLoad read file for kh: %v", err)
	}
	kh, err := tpm2.ContextLoad(rwc, khBytes)
	if err != nil {
		return []byte(""), fmt.Errorf("ContextLoad failed for kh: %v", err)
	}
	defer tpm2.FlushContext(rwc, kh)
	t.k, err = tpm2tools.NewCachedKey(rwc, tpm2.HandleEndorsement, unrestrictedKeyParams, kh)
	if err != nil {
		return []byte(""), fmt.Errorf("Couldnot load CachedKey: %v", err)
	}

	s, err := t.k.GetSigner()
	if err != nil {
		return []byte(""), fmt.Errorf("Couldnot get Signer: %v", err)
	}

	opts = &rsa.PSSOptions{
		Hash:       crypto.SHA256,
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	return s.Sign(rr, digest, opts)
}
