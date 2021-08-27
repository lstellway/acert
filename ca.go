package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
)

// Parses certificate authority flag set
func parseCa(input ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("ca", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate")
	cmd.StringVar(&rootCert, "root", "", "Root certificate used to sign certificate")

	// Add general crypto flags
	parseCrypto(cmd)

	cmd.Parse(input)
	args = cmd.Args()

	return cmd
}

// Generates a new certificate authority
func generateCa() (crypto.PrivateKey, []byte) {
	var parent *x509.Certificate

	// Generate private key
	privateKey, err := GenerateKey(bits)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Generate certificate
	cert := buildCertificate(true)

	// Get parent certificate
	if rootCert != "" {
		parent = ParsePemCertificate(rootCert)
	} else {
		parent = &cert
	}

	// Create certificate
	ca, err := x509.CreateCertificate(rand.Reader, &cert, parent, publicKey, privateKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate authority: ", err)
	}

	return privateKey, ca
}

// Initializes the certificate signing request subcommand
func Ca(args ...string) {
	cmd := parseCa(args...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		key, ca := generateCa()

		// Save pem-encoded files to the filesystem
		SaveFile(getOutputPath(commonName + ".CA.key"), PemEncode("RSA PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(getOutputPath(commonName + ".CA.pem"), PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(getOutputPath(commonName + ".CA.pem"))
		}
	}
}
