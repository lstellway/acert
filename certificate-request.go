package main

import (
	"flag"
)

// Initializes the certificate signing request subcommand
func CertificateRequest(flags ...string) {
	// Parse command flags
	cmd := parseFlags("request", func(cmd *flag.FlagSet) {
		certificateSubjectFlags(cmd)
		certificateKeyFlags(cmd)
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	case "sign":
		// Parse command flags
		parseFlags("sign", func(cmd *flag.FlagSet) {
			certificateBuildFlags(cmd)
		}, flags[1:]...)

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
