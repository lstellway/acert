package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
)

// Parses certificate authority flag set
func parseCert(args ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("cert", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate\n(default false)")
	cmd.StringVar(&signWith, "csr", "", "Certificate signing request used to sign the certificate (required)")
	cmd.StringVar(&signWith, "sign-with", "", "Parent certificate used to sign certificate")
	parseCrypto(cmd)

	cmd.Parse(args)
	args = flag.Args()

	ForceString(&signWith, "Path to parent signing certificate: ")

	return cmd
}

// Generates a new certificate authority
func generateCert() (crypto.PrivateKey, []byte) {
	// Decode signing certificate
	parent, err := x509.ParseCertificate(PemDecodeFile(signWith))
	if err != nil {
		fmt.Println("Invalid certificate", signWith)
		fmt.Println(err)
		os.Exit(1)
	}

	// Build private key
	privateKey, err := GenerateKey(bits)
	if err != nil {
		fmt.Println("Error occurred while generating private key:")
		fmt.Println(err)
		os.Exit(1)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Create certificate
	cert := buildCertificate(false)
	ca, err := x509.CreateCertificate(rand.Reader, &cert, parent, publicKey, privateKey)
	if err != nil {
		fmt.Println("Error occurred while generating certificate authority:")
		fmt.Println(err)
		os.Exit(1)
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
		filePath := getOutputPath()

		// Save pem-encoded files to the filesystem
		SaveFile(filePath + ".key", PemEncode("RSA PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(filePath + ".pem", PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(filePath + ".pem")
		}
	}
}
