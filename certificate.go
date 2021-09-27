package main

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
func certificateSubjectFlags(h *CommandSection) {
	h.StringVar(&country, "country", "", "Country Name (2 letter ISO-3166 code)")
	h.StringVar(&province, "province", "", "State or Province Name (full name)")
	h.StringVar(&locality, "locality", "", "Locality Name (eg, city)")
	h.StringVar(&streetAddress, "streetAddress", "", "Street Address (eg, 123 Fake Street)")
	h.StringVar(&postalCode, "postalCode", "", "Postal Code (eg, 94016)")
	h.StringVar(&organization, "organization", "", "Organization Name (eg, company)")
	h.StringVar(&organizationalUnit, "organizationUnit", "", "Organizational Unit Name (eg, section)")
	h.StringVar(&commonName, "commonName", "", "Certificate common name")
	h.StringVar(&email, "email", "", "Email Address")
	h.StringVar(&san, "san", "", "Comma-delimited Subject Alternative Name(s) (DNS, Email, IP, URI)")
}

// Parses generic cryptography flags
func certificateKeyFlags(h *CommandSection) {
	h.IntVar(&bits, "bits", 2048, "The size of the key to generate in bits")
	h.BoolVar(&isEd25519, "ed25519", false, "Generate keys using ED25519 signature algorithm")
	h.BoolVar(&isEcdsa, "ecdsa", false, "Generate keys using ECDSA elliptic curve signature algorithm")
	h.StringVar(&curve, "curve", "P256", "Elliptic curve used to generate key (P224, P256, P384, P521)")
}

// Flags to sign a certificate using parent certificate
func certificateBuildFlags(h *CommandSection) {
	h.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	h.BoolVar(&trust, "trust", false, "Trust generated certificate")
	h.StringVar(&parent, "parent", "", "Path to PEM-encoded certificate used to sign certificate (authority or intermediate certificate)")
	h.StringVar(&key, "key", "", "Path to PEM-encoded private key used to sign certificate")
}

// Build certificate
func Certificate(flags ...string) {
	// Initialize command
	cmd, args = NewCommand(commandName("certificate"), "Create a PKI certificate", func(h *Command) {
		h.AddSection("Subject Name Options", func(s *CommandSection) {
			certificateSubjectFlags(s)
		})
		h.AddSection("Private Key Options", func(s *CommandSection) {
			certificateKeyFlags(s)
		})
		h.AddSection("Certificate Options", func(s *CommandSection) {
			certificateBuildFlags(s)
		})
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		buildCertificate(false, false)
	}
}
