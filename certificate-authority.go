package main

import (
	"flag"
)

// Initializes the certificate signing request subcommand
func CertificateAuthority(flags ...string) {
	// Parse command flags
	cmd := parseFlags("authority", func(cmd *flag.FlagSet) {
		certificateSubjectFlags(cmd)
		certificateKeyFlags(cmd)
		certificateBuildFlags(cmd)
		cmd.IntVar(&pathLenConstraint, "pathLength", 0, "Maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path (for certificate chaining)")
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		buildCertificate(true, false)
	}
}
