package main

// Initializes the certificate signing request subcommand
func CertificateAuthority(flags ...string) {
	// Initialize command
	cmd, args = NewCommand(commandName("authority"), "Create a PKI certificate authority", func(h *Command) {
		h.AddSection("Subject Name Options", func(s *CommandSection) {
			certificateSubjectFlags(s)
		})
		h.AddSection("Private Key Options", func(s *CommandSection) {
			certificateKeyFlags(s)
		})
		h.AddSection("Certificate Options", func(s *CommandSection) {
			certificateBuildFlags(s)
			s.IntVar(&pathLenConstraint, "pathLength", 0, "Maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path (for certificate chaining)")
		})
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		buildCertificate(true, false)
	}
}
