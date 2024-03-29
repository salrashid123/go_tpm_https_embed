### mTLS with TPM bound private key

Simple http client/server in golang where the private key used in the connection is generated and embedded within a [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/).

This repo mostly uses the `crypto.Signer` implementation from my own library implementing that interface for TPM`("github.com/salrashid123/signer/tpm"`) and not the one from  from[go-tpm-tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key.GetSigner). 

The steps here will create two GCP VMs with TPMs create TPM based RSA keys, generate a CSR using those keys, then an external CA will issue an x509 cert using that csr.

Finally, the client will establish an mTLS https connection to the server

---

* **update `7/17/23`**:  This sample use RSA keys involves several steps and a custom `crypto.signer`.   If you want to see one-way TLS where the server's private key is embedded in a TPM and the private key is cryptographically verified (tpm remote attestation), please instead see [https://github.com/salrashid123/tls_ak](https://github.com/salrashid123/tls_ak)

---

>> NOTE: this repo is not supported by Google


NOTE:

- The TPM is a device so concurrent access (eg via goroutines) will result in exceptions:
  `Unable to Open TPM: open /dev/tpm0: device or resource busy`

---
### Server

First create a server and install golang `go version go1.16.5 linux/amd64`

```bash
gcloud compute  instances create   ts-server     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image=debian-10-buster-v20210916 --image-project=debian-cloud

gcloud compute firewall-rules create allow-https-tpm --action=ALLOW --rules=tcp:8081 --source-ranges=0.0.0.0/0 --target-tags=tpm

gcloud compute ssh ts-server

# in vm:
sudo su -
apt-get update
apt-get install wget git

wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# get the source repo
git clone https://github.com/salrashid123/go_tpm_https_embed.git
cd go_tpm_https_embed

# generate CSR (note, this will by default not evict any handle at 0x81008000 if you need that use --evict)
go run src/csr/csr.go --pemCSRFile certs/server.csr --dnsSAN server.domain.com  --persistentHandle=0x81008000 -v 20 -alsologtostderr

# generate the server certificate 
cd certs/
export SAN=DNS:server.domain.com
openssl ca  -config single-root-ca.conf -in server.csr -out server.crt  -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=server.domain.com"  -extensions server_ext

# run the server
go run src/server/server.go -cacert certs/ca/root-ca.crt -servercert certs/server.crt  --persistentHandle=0x81008000 -port :8081
```


### curl mTLS

You can test the config locally using the pre-generated client certificates provided in this repo


```bash
export SERVER_IP=`gcloud compute instances describe ts-server --format="value(networkInterfaces.accessConfigs[0].natIP)"`

curl -v -H "Host: server.domain.com"  --resolve  server.domain.com:8081:$SERVER_IP --cert certs/certs/user10.crt --key certs/certs/user10.key --cacert certs/ca/root-ca.crt https://server.domain.com:8081/
```

### Client

```bash
gcloud compute  instances create   ts-client     \
   --zone=us-central1-a --machine-type=n1-standard-1 \
   --tags tpm       --no-service-account  --no-scopes  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring  \
   --image=debian-10-buster-v20210916 --image-project=debian-cloud

gcloud compute ssh ts-client

sudo su -
apt-get update
apt-get install wget git

wget https://go.dev/dl/go1.21.1.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.1.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# get the source repo
git clone https://github.com/salrashid123/go_tpm_https_embed.git
cd go_tpm_https_embed

# generate the client cert csr

go run src/csr/csr.go --pemCSRFile certs/kclient.csr --dnsSAN client.domain.com  --persistentHandle=0x81008000 -v 20 -alsologtostderr

cd certs/
export SAN=DNS:client.domain.com
openssl ca  -config single-root-ca.conf -in kclient.csr -out kclient.crt  -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=client.domain.com"  -extensions client_reqext

# run the client using the server's IPaddress or just connect to the internal dns alias
# echo $SERVER_IP
go run src/client/client.go -cacert certs/ca/root-ca.crt --persistentHandle=0x81008000 --address ts-server
```

At this point, you should see a simple 'ok' from the sever

### TLS-TPM crypto.Signer

This repo includes a TLS wrapper function that uses the tpm crypto.Signer from [crypto.Signer, implementations for Google Cloud KMS and Trusted Platform Modules](https://github.com/salrashid123/signer).   This repo used to use the [go-tpm-tools/client.GetSigner()](https://pkg.go.dev/github.com/google/go-tpm-tools/client#Key.GetSigner) but i revered it in a CL.


```

### References

Other references:

- [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)
- [Docker daemon mTLS with Trusted Platform Module](https://github.com/salrashid123/docker_daemon_tpm)
- TPM TLS with nginx, openssl:  [https://github.com/salrashid123/go_tpm_https#nginx](https://github.com/salrashid123/go_tpm_https#nginx)]

RSA-PSS padding:
- [Synthesized PSS support](https://github.com/tpm2-software/tpm2-pkcs11/issues/417)
- [PSS advertising during TLS handshake for TPM signing ](https://chromium-review.googlesource.com/c/chromium/src/+/2984231)
- [TLS salt length auto detection, switch from DIGEST to AUTO](http://openssl.6102.n7.nabble.com/RFC-TLS-salt-length-auto-detection-switch-from-DIGEST-to-AUTO-td78057.html)
