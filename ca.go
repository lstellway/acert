package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
)

// Parses certificate authority flag set
func caParse(input ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("ca", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate")
	cmd.StringVar(&authority, "authority", "", "Path to PEM-encoded authority certificate used to sign certificate")
	cmd.StringVar(&authorityKey, "authorityKey", "", "Path to PEM-encoded authority key used to sign certificate")

	// Add general crypto flags
	parseCrypto(cmd)

	cmd.Parse(input)
	args = cmd.Args()

	// Ensure required values are set
	if authority != "" {
		RequireFileValue(&authorityKey, "authorityKey")
	}

	return cmd
}

// Generates a new certificate authority
func caGenerate() (crypto.PrivateKey, []byte) {
	var (
		parent    *x509.Certificate
		parentKey crypto.PrivateKey
	)

	// Generate private key
	privateKey, err := GenerateKey(bits)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Generate certificate
	cert := buildCertificate(true)

	// Determine parent certificate and key
	if authority != "" && authorityKey != "" {
		parent = ParsePemCertificate(authority)
		parentKey = ParsePemCertificate(authorityKey)
	} else {
		parent = &cert
		parentKey = privateKey
	}

	// Create certificate
	ca, err := x509.CreateCertificate(rand.Reader, &cert, parent, publicKey, parentKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate authority: ", err)
	}

	return privateKey, ca
}

// Initializes the certificate signing request subcommand
func Ca(args ...string) {
	cmd := caParse(args...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		key, ca := caGenerate()

		// Save pem-encoded files to the filesystem
		SaveFile(getOutputPath(commonName+".CA.key"), PemEncode("PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(getOutputPath(commonName+".CA.pem"), PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(getOutputPath(commonName + ".CA.pem"))
		}
	}
}
