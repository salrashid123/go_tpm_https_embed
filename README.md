### mTLS with TPM bound private key

Simple http client/server in golang where the private key used in the connection is generated and embedded within a [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/).

This repo mostly uses the `crypto.Signer` implementation from my own library implementing that interface for TPM (`"github.com/salrashid123/signer/tpm"`) and not the one from  from [go-tpm-tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key.GetSigner). 

The steps here will create a client and server using a local software tpm `swtpm`. On that TPM, create two RSA keys, generate a CSR using those keys, then an external CA will issue an x509 cert using that csr.

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
## if you'd rather use a software tpm than a real one
# rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
# sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear
# export TPM2TOOLS_TCTI="swtpm:port=2321" 

# tpm2_flushcontext -t -s -l
# tpm2_evictcontrol -C o -c 0x81008001
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc -g sha256  -c rprimary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null -g sha256 -u rkey.pub -r rkey.priv -C rprimary.ctx
tpm2_flushcontext -t
tpm2_load -C rprimary.ctx -u rkey.pub -r rkey.priv -c rkey.ctx
tpm2_evictcontrol -C o -c rkey.ctx 0x81008001
tpm2_flushcontext -t

# create a csr using the tpm key...i have it in this repo:
git clone https://github.com/salrashid123/signer.git
cd signer/util
go run csrgen/csrgen.go --filename /tmp/server.csr \
    --sni server.domain.com  --persistentHandle=0x81008001 -tpm-path="/dev/tpmrm0"

openssl req -in /tmp/server.csr -noout -text

# switch to this repo's root; generate the server certificate 
# 
cd go_tpm_https_embed/certs/
export SAN=DNS:server.domain.com
openssl ca  -config single-root-ca.conf -in /tmp/server.csr -out server.crt  -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=server.domain.com"  -extensions server_ext 

# run the server
go run src/server/server.go -cacert certs/ca/root-ca.crt -servercert certs/server.crt \
    --persistentHandle=0x81008001 -port :8081  -tpmdevice="/dev/tpmrm0"
```

### curl mTLS

You can test the config locally using the pre-generated client certificates provided in this repo


```bash
curl -v -H "Host: server.domain.com"  --resolve  server.domain.com:8081:127.0.0.1 \
   --cert certs/certs/user10.crt --key certs/certs/user10.key \
    --cacert certs/ca/root-ca.crt https://server.domain.com:8081/
```

### Client

```bash
## again with a software tpm
# export TPM2TOOLS_TCTI="swtpm:port=2321" 
# tpm2_flushcontext -t -s -l
# tpm2_evictcontrol -C o -c 0x81008000
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc -g sha256  -c rprimary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null  -g sha256 -u rkey.pub -r rkey.priv -C rprimary.ctx
tpm2_flushcontext -t
tpm2_load -C rprimary.ctx -u rkey.pub -r rkey.priv -c rkey.ctx
tpm2_evictcontrol -C o -c rkey.ctx 0x81008000
tpm2_flushcontext -t

# get the source repo
git clone https://github.com/salrashid123/signer.git
cd signer/util

go run csrgen/csrgen.go --filename /tmp/kclient.csr --sni server.domain.com  --persistentHandle=0x81008000 -tpm-path="/dev/tpmrm0"

## switch back to the root of this repo
cd go_tpm_https_embed/certs/
export SAN=DNS:client.domain.com
openssl ca  -config single-root-ca.conf -in /tmp/kclient.csr -out kclient.crt  \
   -subj "/C=US/ST=California/L=Mountain View/O=Google/OU=Enterprise/CN=client.domain.com"  -extensions client_reqext

# run the client using the server's IPaddress or just connect to the internal dns alias
# echo $SERVER_IP
go run src/client/client.go -cacert certs/ca/root-ca.crt --persistentHandle=0x81008000 --address localhost -tpm-path="/dev/tpmrm0"
```

At this point, you should see a simple 'ok' from the sever

### References

Other references:

- [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)
- [Docker daemon mTLS with Trusted Platform Module](https://github.com/salrashid123/docker_daemon_tpm)
- TPM TLS with nginx, openssl:  [https://github.com/salrashid123/go_tpm_https#nginx](https://github.com/salrashid123/go_tpm_https#nginx)]

RSA-PSS padding:
- [Synthesized PSS support](https://github.com/tpm2-software/tpm2-pkcs11/issues/417)
- [PSS advertising during TLS handshake for TPM signing ](https://chromium-review.googlesource.com/c/chromium/src/+/2984231)
- [TLS salt length auto detection, switch from DIGEST to AUTO](http://openssl.6102.n7.nabble.com/RFC-TLS-salt-length-auto-detection-switch-from-DIGEST-to-AUTO-td78057.html)
