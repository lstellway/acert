package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
)

// Parses certificate signing request flag set
func parseCsr(args ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("ca", flag.ExitOnError)
	parseCrypto(cmd)

	cmd.Parse(args)
	args = flag.Args()

	return cmd
}

// Generate certificate signing request
func generateCsr() (crypto.PrivateKey, []byte) {
	// Generate private key
	privateKey, err := GenerateKey(bits)
	if err != nil {
		fmt.Println("Error occurred while generating private key:")
		fmt.Println(err)
		os.Exit(1)
	}

	template := buildCertificateRequest()

	// Build certificate signing request
    csr, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		fmt.Println("Error occurred while generating certificate signing request:")
		fmt.Println(err)
		os.Exit(1)
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
