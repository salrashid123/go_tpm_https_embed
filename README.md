### mTLS with TPM bound private key

Simple http client/server in golang where the private key used in the connection is generated and embedded within a [Trusted Platform Module](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/).

The steps here will create a client and server using a local software tpm `swtpm`. On that TPM, create two RSA keys, generate a CSR using those keys, then an external CA will issue an x509 cert using that csr.

Finally, the client will establish an mTLS https connection to the server

---

* If you want to see one-way TLS where the server's private key is embedded in a TPM and the private key is cryptographically verified (tpm remote attestation), please instead see [https://github.com/salrashid123/tls_ak](https://github.com/salrashid123/tls_ak)

for python, see [Python mTLS client/server with TPM based key](https://gist.github.com/salrashid123/4cb714d800c9e8777dfbcd93ff076100)

---

>> NOTE: this repo is not supported by Google

To use this sample, you'll need:

* golang
* `tpm2_tools`
* openssl3 (with [tpm2-openssl](https://github.com/tpm2-software/tpm2-openssl))
* software tpm ([swtpm](https://github.com/stefanberger/swtpm))

The TPM based private keys conforms to [ASN.1 Specification for TPM 2.0 Key Files](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html) which in its basic mode is compatible with openssl

### QuickStart

if you want to use the keys provided in this repo, you just need `swtpm`

#### Start swtpm

Start two software TPMs on different ports to simulate the client and server's TPMs

```bash
cd certs/
## tpm for server
swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

## in a new window, start tpm for the client
swtpm socket --tpmstate dir=myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2
```

##### Start Server

To start the server using the built in demo `swtpm`
```bash
go run src/server/server.go -cacert certs/ca/root-ca.crt \
   -servercert certs/server.crt \
    --severkey=certs/server_key.pem -port :8081 \
      --tpm-path="127.0.0.1:2321"
```

You can test the config locally using the pre-generated client certificates provided in this repo

(the following uses curl and ordinary (non-tpm) client certifcates)

```bash
curl -v -H "Host: server.domain.com"  --resolve  server.domain.com:8081:127.0.0.1 \
   --cert certs/user10.crt --key certs/user10.key \
    --cacert certs/ca/root-ca.crt https://server.domain.com:8081/index.html
```

##### Start Client

Run the client which uses TPM-based client certificates,  in a new window:

```bash
go run src/client/client.go -cacert certs/ca/root-ca.crt \
  --clientkey=certs/client_key.pem --pubCert=certs/client.crt  \
   --address localhost --tpm-path="127.0.0.1:2341"
```

WHat this shows is mTLS where both ends have the TLS private key on the TPM.

---

### Appendix

The following sets up your own certs and software or real TPMs.

If you want to use a real TPM, you need openssl tpm support but you don't need to export the `TPM2*`  environment variables.  For a real tpm, you'll also need to speicfy `--tpm-path=/dev/tpmrm0`

####  Server

The following will setup a server cert where the private key is on a TPM.  For this you need to install openssl tpm support and `tpm2_tools`

if you'd rather use a real tpm than a sotware one, dont' export the TPM* env variables or start the swtpms.

Finally, while running the client or server set `--tpm-path="/dev/tpmrm0"`


For a swtpm:

```bash
mkdir myvtpm
sudo swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
# export TSS2_LOG=esys+debug


### first verify you have openssl installed and configured for TPM:
openssl list  -provider tpm2  -provider default  --providers

  Providers:
    default
      name: OpenSSL Default Provider
      version: 3.5.0
      status: active
    tpm2
      name: TPM 2.0 Provider
      version: 1.3.0
      status: active

cd certs/
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc -g sha256  -c rprimary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null -g sha256 -u server.pub -r server.priv -C rprimary.ctx
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
# tpm2_load -C rprimary.ctx -u server.pub -r server.priv -c server.ctx

## convert rkey.pub rkey.priv to PEM format
## note, you may need to add a -p parameter to tpm2_encodeobject if the version of tpm2_tools does not include (https://github.com/tpm2-software/tpm2-tools/issues/3458)
tpm2_encodeobject -C rprimary.ctx -u server.pub -r server.priv -o server_key.pem

### you'll know if you need to if you run the following and it prompts for a password
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

# run the server as go
go run src/server/server.go -cacert certs/ca/root-ca.crt \
   -servercert certs/server.crt \
    --severkey=certs/server_key.pem -port :8081 \
      --tpm-path="127.0.0.1:2321"
```


#### Client

For the client,

```bash
mkdir myvtpm2
sudo swtpm_setup --tpmstate myvtpm2 --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
export TPM2TSSENGINE_TCTI="swtpm:port=2341"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc -g sha256  -c rcprimary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -G rsa2048:rsapss:null -g sha256 -u client.pub -r client.priv -C rcprimary.ctx
tpm2_load -C rcprimary.ctx -u client.pub -r client.priv -c client.ctx

## note, you may need to add a -p parameter to tpm2_encodeobject (https://github.com/tpm2-software/tpm2-tools/issues/3458)
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

#### Openssl

If you would rather test the client/server using openssl

```bash
swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

openssl s_server  -provider tpm2  -provider default  \
        -cert server.crt \
      -key server_key.pem \
      -port 8081 \
      -CAfile ca/root-ca.crt \
      -tlsextdebug \
      -tls1_3  \
      -trace \
      -WWW
```

```bash
swtpm socket --tpmstate dir=myvtpm2 --tpm2 --server type=tcp,port=2341 --ctrl type=tcp,port=2342 --flags not-need-init,startup-clear --log level=2

export TPM2TOOLS_TCTI="swtpm:port=2341"
export TPM2OPENSSL_TCTI="swtpm:port=2341"
export TPM2TSSENGINE_TCTI="swtpm:port=2341"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l

## in new window
go run src/client/client.go -cacert certs/ca/root-ca.crt \
  --clientkey=certs/client_key.pem --pubCert=certs/client.crt  \
   --address localhost --tpm-path="127.0.0.1:2341"
```

### References

Other references:

- [Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault](https://github.com/salrashid123/vault_mtls_tpm)
- TPM TLS with nginx, openssl:  [https://github.com/salrashid123/go_tpm_https#nginx](https://github.com/salrashid123/go_tpm_https#nginx)]

RSA-PSS padding:
- [Synthesized PSS support](https://github.com/tpm2-software/tpm2-pkcs11/issues/417)
- [PSS advertising during TLS handshake for TPM signing ](https://chromium-review.googlesource.com/c/chromium/src/+/2984231)
- [TLS salt length auto detection, switch from DIGEST to AUTO](http://openssl.6102.n7.nabble.com/RFC-TLS-salt-length-auto-detection-switch-from-DIGEST-to-AUTO-td78057.html)
