package acert

import "github.com/lstellway/go/command"

// CertificateAuthority handles command-line input arguments to create a PKI certificate authority.
func CertificateAuthority(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("authority"), "Create a PKI certificate authority", func(h *command.Command) {
		h.AddSection("Subject Name Options", func(s *command.CommandSection) {
			certificateSubjectFlags(s)
		})
		h.AddSection("Private Key Options", func(s *command.CommandSection) {
			certificateKeyFlags(s)
		})
		h.AddSection("Certificate Options", func(s *command.CommandSection) {
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
