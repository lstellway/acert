package main

import (
	"flag"
)

// Build certificate
func Certificate(flags ...string) {
	// Parse command flags
	cmd := parseFlags("cert", func(cmd *flag.FlagSet) {
		certificateSubjectFlags(cmd)
		certificateKeyFlags(cmd)
		certificateGenerateFlags(cmd)
	}, flags...)

	switch flags[0] {
	case "help":
		cmd.Usage()
	case "sign":
		// Parse command flags
		parseFlags("sign", func(cmd *flag.FlagSet) {
			certificateGenerateFlags(cmd)
			cmd.StringVar(&csr, "csr", "", "Path to PEM-encoded authority key used to sign certificate")
		}, flags[1:]...)

		buildCertificate(false, true)
	default:
		buildCertificate(false, false)
	}
}
