package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
)

// Parses certificate authority flag set
func parseCert(input ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("cert", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate\n(default false)")
	cmd.StringVar(&rootCert, "root", "", "Root certificate used to sign certificate")

	// Add general crypto flags
	parseCrypto(cmd)

	cmd.Parse(input)
	args = cmd.Args()

	return cmd
}

// Generates a new certificate authority
func generateCert() (crypto.PrivateKey, []byte) {
	// Get root signing certificate
	if rootCert == "" {
		exit(1, "No root certificate was specified. Use the `--root` option to specify a signing certificate.")
	}
	parent := ParsePemCertificate(rootCert)

	// Build private key
	privateKey, err := GenerateKey(bits)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Create certificate
	cert := buildCertificate(false)
	ca, err := x509.CreateCertificate(rand.Reader, &cert, parent, publicKey, privateKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate authority:")
	}

	return privateKey, ca
}

// Initializes the certificate signing request subcommand
func cert(args ...string) {
	cmd := parseCert(args...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		key, ca := generateCert()

		// Save pem-encoded files to the filesystem
		SaveFile(getOutputPath(commonName + ".key"), PemEncode("RSA PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(getOutputPath(commonName + ".pem"), PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(getOutputPath(commonName + ".pem"))
		}
	}
}
