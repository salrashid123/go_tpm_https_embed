module main

go 1.15

require (
	github.com/google/go-tpm v0.3.1 // indirect
	github.com/google/go-tpm-tools v0.2.0 // indirect
	github.com/salrashid123/signer/tpm v0.0.0
)

replace github.com/salrashid123/signer/tpm => "./src/tpm/"