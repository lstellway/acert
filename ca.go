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
	parseCrypto(cmd)

	cmd.Parse(input)
	args = flag.Args()

	return cmd
}

// Generates a new certificate authority
func generateCa() (crypto.PrivateKey, []byte) {
	privateKey, err := GenerateKey(bits)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}

	publicKey := privateKey.(crypto.Signer).Public()
	cert := buildCertificate(true)

	// Create certificate
	ca, err := x509.CreateCertificate(rand.Reader, &cert, &cert, publicKey, privateKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate authority: ", err)
	}

	return privateKey, ca
}

// Initializes the certificate signing request subcommand
func ca(args ...string) {
	cmd := parseCa(args...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		key, ca := generateCa()
		filePath := getOutputPath()

		// Save pem-encoded files to the filesystem
		SaveFile(filePath + ".CA.key", PemEncode("RSA PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(filePath + ".CA.pem", PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(filePath + ".CA.pem")
		}
	}
}
