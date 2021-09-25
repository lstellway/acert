package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
)

// Parses certificate signing request flag set
func csrParseFlags(flags ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("ca", flag.ExitOnError)

	// Add general crypto flags
	cryptoParseFlags(cmd)

	cmd.Parse(flags)
	args = cmd.Args()

	return cmd
}

// Generate certificate signing request
func csrBuild() (crypto.PrivateKey, []byte) {
	// Generate private key
	privateKey, err := GenerateKey(bits, curve)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}

	template := buildCertificateRequest()

	// Build certificate signing request
	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate signing request: ", err)
	}

	return privateKey, csr
}

// Initializes the certificate signing request subcommand
func Csr(args ...string) {
	cmd := csrParseFlags(args...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		key, ca := csrBuild()

		SaveFile(getOutputPath(commonName+".CSR.key"), PemEncode("PRIVATE KEY", PrivateKeyPkcs(key)), 0600, true)
		SaveFile(getOutputPath(commonName+".CSR.pem"), PemEncode("CERTIFICATE REQUEST", ca), 0600, true)
	}
}
