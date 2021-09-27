package main

// Initializes the certificate signing request subcommand
func CertificateRequest(flags ...string) {
	// Initialize command
	cmd, args = NewCommand(commandName("request"), "Create a PKI certificate signing request", func(h *Command) {
		h.AddSection("Subject Name Options", func(s *CommandSection) {
			certificateSubjectFlags(s)
		})
		h.AddSection("Private Key Options", func(s *CommandSection) {
			certificateKeyFlags(s)
		})

		h.AddSubcommand("sign", "Create a PKI certificate from a signing request")
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	case "sign":
		// Initialize command
		cmd, args = NewCommand(commandName("request sign"), "Create a PKI certificate from a signing request", func(h *Command) {
			h.AddSection("Certificate", func(s *CommandSection) {
				certificateBuildFlags(s)
				s.IntVar(&pathLenConstraint, "pathLength", 0, "Maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path (for certificate chaining)")
			})
		}, args...)

		// First argument should be path to signing request file
		csr = getArgument(true)
		buildCertificate(false, true)
	default:
		privateKey, request := buildCertificateRequest()

		// PEM-encode
		privateKeyPem := PemEncode("PRIVATE KEY", PrivateKeyPkcs(privateKey))
		requestPem := PemEncode("CERTIFICATE REQUEST", request)

		// Save files
		SaveFile(getOutputPath(commonName+".key.pem"), privateKeyPem, 0644, true)
		SaveFile(getOutputPath(commonName+".csr.pem"), requestPem, 0644, true)
	}
}
