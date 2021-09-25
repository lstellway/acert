package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
)

// Parses certificate authority flag set
func caParseFlags(flags ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("ca", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.IntVar(&pathLenConstraint, "pathLenConstraint", 0, "Maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate")
	cmd.StringVar(&authority, "authority", "", "Path to PEM-encoded authority certificate used to sign certificate")
	cmd.StringVar(&authorityKey, "authorityKey", "", "Path to PEM-encoded authority key used to sign certificate")

	// Add general crypto flags
	cryptoParseFlags(cmd)

	cmd.Parse(flags)
	args = cmd.Args()

	// Ensure required values are set
	if authority != "" {
		RequireFileValue(&authority, "authorityKey")
		RequireFileValue(&authorityKey, "authorityKey")
	}

	return cmd
}

// Generates a new certificate authority
func caBuild() (crypto.PrivateKey, []byte) {
	var (
		parent    *x509.Certificate
		parentKey crypto.PrivateKey
	)

	// Generate private key
	privateKey, err := GenerateKey(bits, curve)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Generate certificate
	cert := buildCertificate(true)

	// Determine parent certificate and key
	if authority != "" && authorityKey != "" {
		parent = ParsePemCertificate(authority)
		parentKey = ParsePemPrivateKey(authorityKey)
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
func Ca(flags ...string) {
	cmd := caParseFlags(flags...)

	switch getArg() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		key, ca := caBuild()

		// Save pem-encoded files to the filesystem
		SaveFile(getOutputPath(commonName+".CA.key"), PemEncode("PRIVATE KEY", PrivateKeyPkcs(key)), 0644, true)
		SaveFile(getOutputPath(commonName+".CA.pem"), PemEncode("CERTIFICATE", ca), 0644, true)

		if trust {
			fmt.Println("Adding trusted certificate...")
			Trust(getOutputPath(commonName + ".CA.pem"))
		}
	}
}
