package main

import (
	"flag"
)

var (
	// General
	bits, days, pathLenConstraint int
	trust                         bool

	// Elliptic curve cryptography
	isEcdsa, isEd25519 bool
	curve              string

	// File paths
	parent, key, csr string

	// Certificate subject
	country, province, locality, streetAddress, postalCode string
	organization, organizationalUnit                       string
	commonName, email                                      string
	san                                                    string

	// Verify options
	host, root, intermediate string
)

// Flags used to build the certificate subject
func certificateSubjectFlags(cmd *flag.FlagSet) {
	cmd.StringVar(&country, "country", "", "Country Name (2 letter ISO-3166 code)")
	cmd.StringVar(&province, "province", "", "State or Province Name (full name)")
	cmd.StringVar(&locality, "locality", "", "Locality Name (eg, city)")
	cmd.StringVar(&streetAddress, "streetAddress", "", "Street Address\n(eg: 123 Fake Street)")
	cmd.StringVar(&postalCode, "postalCode", "", "Postal Code (eg, 94016)")
	cmd.StringVar(&organization, "organization", "", "Organization Name (eg, company)")
	cmd.StringVar(&organizationalUnit, "organizationUnit", "", "Organizational Unit Name (eg, section)")
	cmd.StringVar(&commonName, "commonName", "", "Certificate common name (required)")
	cmd.StringVar(&email, "email", "", "Email Address")
	cmd.StringVar(&san, "san", "", "Comma-delimited Subject Alternative Names (DNS, Email, IP, URI)")
}

// Parses generic cryptography flags
func certificateKeyFlags(cmd *flag.FlagSet) {
	cmd.IntVar(&bits, "bits", 2048, "The size of the key to generate in bits")
	cmd.BoolVar(&isEd25519, "ed25519", false, "Generate keys using ED25519 signature algorithm")
	cmd.BoolVar(&isEcdsa, "ecdsa", false, "Generate keys using ECDSA elliptic curve signature algorithm")
	cmd.StringVar(&curve, "curve", "P256", "Elliptic curve used to generate private key (P224, P256, P384, P521)")
}

// Flags to sign a certificate using parent certificate
func certificateBuildFlags(cmd *flag.FlagSet) {
	cmd.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	cmd.BoolVar(&trust, "trust", false, "Trust generated certificate\n(default false)")
	cmd.StringVar(&parent, "parent", "", "Path to PEM-encoded certificate used to sign certificate (authority or intermediate certificate)")
	cmd.StringVar(&key, "key", "", "Path to PEM-encoded private key used to sign certificate")
}

// Build certificate
func Certificate(flags ...string) {
	// Parse command flags
	cmd := parseFlags("cert", func(cmd *flag.FlagSet) {
		certificateSubjectFlags(cmd)
		certificateKeyFlags(cmd)
		certificateBuildFlags(cmd)
	}, flags...)

	switch flags[0] {
	case "help":
		cmd.Usage()
	default:
		buildCertificate(false, false)
	}
}
