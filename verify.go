package main

import (
	"crypto/x509"
	"flag"
)

// Verify a certificate with configured options
func verify(file string) {
	certificate := ParsePemCertificate(file)
	options := x509.VerifyOptions{}

	if host != "" {
		options.DNSName = host
	}

	if root != "" {
		rootCert := ParsePemCertificate(root)
		rootPool := x509.NewCertPool()
		rootPool.AddCert((rootCert))
		options.Roots = rootPool
	}

	if intermediate != "" {
		intermediateCert := ParsePemCertificate(intermediate)
		intermediatePool := x509.NewCertPool()
		intermediatePool.AddCert((intermediateCert))
		options.Intermediates = intermediatePool
	}

	_, err := certificate.Verify(options)
	exitOnError(err, "Certificate could not be verified.", err)
	log("Certificate verified successfully")
}

// Verify a certificate
func VerifyCertificate(flags ...string) {
	// Parse command flags
	cmd := parseFlags("verify", func(cmd *flag.FlagSet) {
		cmd.StringVar(&host, "host", "", "Host name to verify")
		cmd.StringVar(&root, "root", "", "Trusted root certificate")
		cmd.StringVar(&intermediate, "intermediate", "", "Intermediate certificate")
	}, flags...)

	arg := getArgument(true)
	switch arg {
	case "", "help":
		cmd.Usage()
	default:
		verify(arg)
	}
}
