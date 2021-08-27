package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
)

// Parses certificate signing request flag set
func parseCsr(input ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("ca", flag.ExitOnError)
	parseCrypto(cmd)

	cmd.Parse(input)
	args = flag.Args()

	return cmd
}

// Generate certificate signing request
func generateCsr() (crypto.PrivateKey, []byte) {
	// Generate private key
	privateKey, err := GenerateKey(bits)
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
func csr(args ...string) {
	parseCsr(args...)

	switch getArg() {
	default:
		key, ca := generateCsr()
		filePath := getOutputPath()
		SaveFile(filePath + ".CSR.key", PemEncode("RSA PRIVATE KEY", PrivateKeyPkcs(key)), 0600, true)
		SaveFile(filePath + ".CSR.pem", PemEncode("CERTIFICATE REQUEST", ca), 0600, true)
	}
}
