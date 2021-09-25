package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
)

// Parses certificate authority flag set
func certificateParseFlags(flags ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("cert", flag.ExitOnError)
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate\n(default false)")
	cmd.StringVar(&authority, "authority", "", "Path to PEM-encoded authority certificate used to sign certificate")
	cmd.StringVar(&authorityKey, "authorityKey", "", "Path to PEM-encoded authority key used to sign certificate")

	// Add general crypto flags
	cryptoParseFlags(cmd)

	cmd.Parse(flags)
	args = cmd.Args()

	// Ensure required values are set
	RequireFileValue(&authority, "authority")
	RequireFileValue(&authorityKey, "authorityKey")

	return cmd
}

// Generates a new certificate
func certificateBuild() (crypto.PrivateKey, []byte) {
	parent := ParsePemCertificate(authority)
	parentKey := ParsePemPrivateKey(authorityKey)

	// Build private key
	privateKey, err := GenerateKey(bits, curve)
	if err != nil {
		exit(1, "Error occurred while generating private key: ", err)
	}
	publicKey := privateKey.(crypto.Signer).Public()

	// Create certificate
	certificate := buildCertificate(false)
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificate, parent, publicKey, parentKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate: ", err)
	}

	return privateKey, certificateBytes
}

// Initializes the certificate signing request subcommand
func Certificate(flags ...string) {
	cmd := certificateParseFlags(flags...)

	switch getArgument() {
	case "help":
		cmd.Usage()
	default:
		// Generate certificate authority
		privateKey, certificate := certificateBuild()

		// PEM-encode
		privateKeyPem := PemEncode("PRIVATE KEY", PrivateKeyPkcs(privateKey))
		certificatePem := PemEncode("CERTIFICATE", certificate)
		chainPem := ReadFile(authority)
		fullchainPem := append(certificatePem, chainPem...)

		// Save files
		SaveFile(getOutputPath(commonName+".key.pem"), privateKeyPem, 0644, true)
		SaveFile(getOutputPath(commonName+".cert.pem"), certificatePem, 0644, true)
		SaveFile(getOutputPath(commonName+".chain.pem"), chainPem, 0644, true)
		SaveFile(getOutputPath(commonName+".fullchain.pem"), fullchainPem, 0644, true)

		// Trust
		if trust {
			TrustCertificate(getOutputPath(commonName + ".pem"))
		}
	}
}
