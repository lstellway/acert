package main

import (
	"flag"
)

// Initializes the certificate signing request subcommand
func CertificateAuthority(flags ...string) {
	// Parse command flags
	cmd := parseFlags("ca", func(cmd *flag.FlagSet) {
		certificateSubjectFlags(cmd)
		certificateKeyFlags(cmd)
		certificateGenerateFlags(cmd)
		cmd.IntVar(&pathLenConstraint, "pathLenConstraint", 0, "Maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path")
	}, flags...)

	switch flags[0] {
	case "help":
		cmd.Usage()
	default:
		buildCertificate(true, false)
	}
}
