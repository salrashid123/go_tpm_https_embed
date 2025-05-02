### mTLS with TPM bound private key

Simple http client/server in golang where the private key used in the connection is generated and embedded within a [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/).

This repo mostly uses the `crypto.Signer` implementation from my own library implementing that interface for TPM (`"github.com/salrashid123/signer/tpm"`) and not the one from  from [go-tpm-tools](https://godoc.org/github.com/google/go-tpm-tools/tpm2tools#Key.GetSigner). 

The steps here will create a client and server using a local software tpm `swtpm`. On that TPM, create two RSA keys, generate a CSR using those keys, then an external CA will issue an x509 cert using that csr.

Finally, the client will establish an mTLS https connection to the server

---

* **update `7/17/23`**:  This sample use RSA keys involves several steps and a custom `crypto.signer`.   If you want to see one-way TLS where the server's private key is embedded in a TPM and the private key is cryptographically verified (tpm remote attestation), please instead see [https://github.com/salrashid123/tls_ak](https://github.com/salrashid123/tls_ak)

for python, see [Python mTLS client/server with TPM based key](https://gist.github.com/salrashid123/4cb714d800c9e8777dfbcd93ff076100)

---

>> NOTE: this repo is not supported by Google

To use this sample, you'll need:

* golang
* openssl v3 (with [https://github.com/tpm2-software/tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl))
* software tpm ([https://github.com/stefanberger/swtpm](https://github.com/stefanberger/swtpm))

The TPM based private keys conforms to [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) which in its basic mode is compatible with openssl

### QuickStart

if you want to use the keys provided in this repo, just startup software TPMs:

The following will startup two software TPMs where the client and server keys reside

- Server:

```bash
cd certs/
swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/   # or wherever tpm2.so sits, eg /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so


$ openssl list  -provider tpm2  -provider default  --providers
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.2.0
    status: active
  tpm2
    name: TPM 2.0 Provider
    version: 1.2.0-25-g87082a3
    status: active

$ openssl rsa -provider tpm2  -provider default -in server_key.pem --text
```


```bash
### test with openssl server
cd certs/
openssl s_server  -provider tpm2  -provider default  \
        -cert server.crt \
      -key server_key.pem \
      -port 8081 \
      -CAfile ca/root-ca.crt \
      -tlsextdebug \
      -tls1_3  \
      -trace \
      -WWW

## or golang server
go run src/server/server.go -cacert certs/ca/root-ca.crt \
   -servercert certs/server.crt \
    --severkey=certs/server_key.pem -port :8081 \
      --tpm-path="127.0.0.1:2321"
```

You can test the config locally using the pre-generated client certificates provided in this repo

```bash
curl -v -H "Host: server.domain.com"  --resolve  server.domain.com:8081:127.0.0.1 \
   --cert certs/user10.crt --key certs/user10.key \
    --cacert ca/root-ca.crt https://server.domain.com:8081/index.html
```

- Client:

```bash
cd certs/
swtpm socket --tpmstate dir=myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
export TPM2TSSENGINE_TCTI="swtpm:port=2341"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/ 

go run src/client/client.go -cacert certs/ca/root-ca.crt \
  --clientkey=certs/client_key.pem --pubCert=certs/client.crt  \
   --address localhost --tpm-path="127.0.0.1:2341"
```

---

### Appendix

The following sewts up your own certs and software TPMs

####  Server

The following will setup a server cert where the private key is on a TPM

```bash
## if you'd rather use a software tpm than a real one, set the following and use --tpm-path="127.0.0.1:2321"

mkdir myvtpm
sudo swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/   # or wherever tpm2.so sits, eg /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so
# export TSS2_LOG=esys+debug

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc -g sha256  -c rprimary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null -g sha256 -u server.pub -r server.priv -C rprimary.ctx
tpm2_load -C rprimary.ctx -u server.pub -r server.priv -c server.ctx

## convert rkey.pub rkey.priv to PEM format
tpm2_encodeobject -C primary.ctx -u server.pub -r server.priv -o server_key.pem

# create a csr using the tpm key...i have it in this repo:
openssl rsa -provider tpm2  -provider default -in server_key.pem --text

export SAN="DNS:server.domain.com"
openssl req -new  -provider tpm2  -provider default    -config server.conf \
  -out server.csr  \
  -key server_key.pem  -reqexts server_reqext   \
  -subj "/C=US/O=Google/OU=Enterprise/CN=server.domain.com" 

openssl req -in server.csr -noout -text

openssl ca \
    -config single-root-ca.conf \
    -in server.csr \
    -out server.crt  \
    -extensions server_ext

cd certs/
openssl s_server  -provider tpm2  -provider default  \
        -cert server.crt \
      -key server_key.pem \
      -port 8081 \
      -CAfile ca/root-ca.crt \
      -tlsextdebug \
      -tls1_3  \
      -trace \
      -WWW

# run the server as go
go run src/server/server.go -cacert certs/ca/root-ca.crt \
   -servercert certs/server.crt \
    --severkey=certs/server_key.pem -port :8081 \
      --tpm-path="127.0.0.1:2321"
```


### Client

For the client,

```bash
mkdir myvtpm2
sudo swtpm_setup --tpmstate myvtpm2 --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
export TPM2TSSENGINE_TCTI="swtpm:port=2341"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/   # or wherever tpm2.so sits, eg /usr/lib/x86_64-linux-gnu/ossl-modules/tpm2.so

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc -g sha256  -c rcprimary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null -g sha256 -u client.pub -r client.priv -C rcprimary.ctx
tpm2_load -C rcprimary.ctx -u client.pub -r client.priv -c client.ctx

tpm2_encodeobject -C rcprimary.ctx -u client.pub -r client.priv -o client_key.pem

# create a csr using the tpm key...i have it in this repo:
openssl rsa -provider tpm2  -provider default -in client_key.pem --text

export SAN="DNS:client.domain.com"
openssl req -new  -provider tpm2  -provider default    -config client.conf \
  -out client.csr  \
  -key client_key.pem  -reqexts client_reqext   \
  -subj "/C=US/O=Google/OU=Enterprise/CN=client.domain.com" 

openssl req -in client.csr -noout -text

openssl ca \
    -config single-root-ca.conf \
    -in client.csr \
    -out client.crt  \
    -extensions client_ext

go run src/client/client.go -cacert certs/ca/root-ca.crt \
  --clientkey=certs/client_key.pem --pubCert=certs/client.crt  \
   --address localhost --tpm-path="127.0.0.1:2341"
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
