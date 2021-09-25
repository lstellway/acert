package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
)

// Parses certificate authority flag set
func certParse(input ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("cert", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate\n(default false)")
	cmd.StringVar(&authority, "authority", "", "Path to PEM-encoded authority certificate used to sign certificate")
	cmd.StringVar(&authorityKey, "authorityKey", "", "Path to PEM-encoded authority key used to sign certificate")

	// Add general crypto flags
	parseCrypto(cmd)

	cmd.Parse(input)
	args = cmd.Args()

	// Ensure required values are set
	RequireFileValue(&authority, "authority")
	RequireFileValue(&authorityKey, "authorityKey")

	return cmd
}

// Generates a new certificate
func certGenerate() (crypto.PrivateKey, []byte) {
	parent := ParsePemCertificate(authority)
	parentKey := ParsePemPrivateKey(authorityKey)

	// Build private key
	privateKey, err := GenerateKey(bits)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Create certificate
	cert := buildCertificate(false)
	ca, err := x509.CreateCertificate(rand.Reader, &cert, parent, publicKey, parentKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate: ", err)
	}

	return privateKey, ca
}

// Initializes the certificate signing request subcommand
func Cert(args ...string) {
	cmd := certParse(args...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		key, ca := certGenerate()

		// Save pem-encoded files to the filesystem
		SaveFile(getOutputPath(commonName+".key"), PemEncode("PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(getOutputPath(commonName+".pem"), PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(getOutputPath(commonName + ".pem"))
		}
	}
}
