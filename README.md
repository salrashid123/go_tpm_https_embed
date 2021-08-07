### mTLS with TPM bound private key

Simple http client/server in golang where the private key used in the connection is generated and embedded within a Trusted Platform Module.

Earlier this year I wrote a similar flow that involved mTLS with TPM based against other targets but in this repo specifically, we will use
[go-tpm-tools](https://github.com/google/go-tpm-tools) to generate the key _on the TPM_ directly.  This is in contrast with the links shown below where a private key is first generated outside the
TPM and then embedded within it.  Its preferable to generate the key on the TPM directly so as to minimize key compromise.

This repo uses the `crypto.Signer` implementation from[go-tpm-tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key.GetSigner) and not my own [TPM TokenSource](https://github.com/salrashid123/oauth2#usage-tpmtokensource)


The steps here will create two GCP VMs that have TPM modules that act as mTLS client/server.   A utility program will create a private key on the TPM, then issue a CSR using that key.   A sample CA is provided in this repo to sign the CSRs and produce TLS certificates.  These certificates and TPM private keys will be used to establish the connection

>> NOTE: this repo is not supported by Google


NOTE:

- The TPM is a device so concurrent access (eg via goroutines) will result in exceptions:
  `Unable to Open TPM: open /dev/tpm0: device or resource busy`

---

Other references:

- [golang TLS with Trusted Platform Module (TPM) based keys](https://github.com/salrashid123/go_tpm_https)
- [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)
- [Docker daemon mTLS with Trusted Platform Module](https://github.com/salrashid123/docker_daemon_tpm)
- TPM TLS with nginx, openssl:  [https://github.com/salrashid123/go_tpm_https#nginx](https://github.com/salrashid123/go_tpm_https#nginx)]


### Server

First create a server and install golang 1.13:

```bash
gcloud compute  instances create   ts-server     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image=debian-10-buster-v20200805 --image-project=debian-cloud

gcloud compute firewall-rules create allow-https-tpm --action=ALLOW --rules=tcp:8081 --source-ranges=0.0.0.0/0 --target-tags=tpm

gcloud compute ssh ts-server

# in vm:
sudo su -
apt-get update
apt-get install wget git

wget https://golang.org/dl/go1.13.15.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.13.15.linux-amd64.tar.gz

# get the source repo
git clone https://github.com/salrashid123/go_tpm_https_embed.git
cd go_tpm_https_embed

# generate CSR
go run src/csr/csr.go --pemCSRFile certs/server.csr --dnsSAN server.domain.com  -v 20 -alsologtostderr

# generate the server certificate 
cd certs/
mkdir new_certs
openssl ca     -config openssl.conf     -in server.csr     -out server.crt     -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=server.domain.com"


# run the server
go run src/server/server.go -cacert certs/CA_crt.pem -servercert certs/server.crt -tpmfile k.bin -port :8081
```


### curl mTLS

You can test the config locally using the pre-generated client certificates provided in this repo


```bash
export SERVER_IP=`gcloud compute instances describe ts-server --format="value(networkInterfaces.accessConfigs[0].natIP)"`

curl -v -H "Host: server.domain.com"  --resolve  server.domain.com:8081:$SERVER_IP --cert certs/client.crt --key certs/client.key --cacert certs/CA_crt.pem https://server.domain.com:8081/
```


### Client

```bash
gcloud compute  instances create   ts-client     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image=debian-10-buster-v20200805 --image-project=debian-cloud

gcloud compute ssh ts-client

sudo su -
apt-get update
apt-get install wget git

wget https://golang.org/dl/go1.13.15.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.13.15.linux-amd64.tar.gz

# get the source repo
git clone https://github.com/salrashid123/go_tpm_https_embed.git
cd go_tpm_https_embed

# generate the client cert csr

go run src/csr/csr.go --pemCSRFile certs/kclient.csr --dnsSAN client.domain.com  -v 20 -alsologtostderr

cd certs/
mkdir new_certs
openssl ca     -config openssl.conf     -in kclient.csr     -out kclient.crt     -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=client.domain.com"

# run the client using the server's IPaddress

echo $SERVER_IP
go run src/client/client.go -cacert certs/CA_crt.pem -tpmfile k.bin --address $SERVER_IP
```

At this point, you should see a simple 'ok' from the sever

### TLS-TPM crypto.Signer

This repo includes a TLS wrapper function that uses the tpm crypto.Signer.

At the core is a `Sign()` function which loads the TPM and signs. As mentioned, its serial access to `/dev/tpm0` so the code loads it every invocation (i know, it crappy)

We also utilize RSA-PSS Algorithm here for TLS 1.3:
 - [Issue 967](https://github.com/golang/go/issues/9671)

```golang
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

```

Which also means the default Key Template we use in generating the CSR and Cert will utilize RSA-PSS

- `src/csr/csr.go`:
```golang
var (
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

/// ...

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

```

Also included are two utility functions to flush all TPM handles (incase you've used up all of them)
```bash
go run src/util/util.go  --mode flush -v 20 -alsologtostderr
```

And a a function to print the public RSA key for a given key  (you can ofcourse also derive that from the certificate or csr)

```bash
go run src/util/util.go  --mode print --keyfile k.bin -v 20 -alsologtostderr
```

