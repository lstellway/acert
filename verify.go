package main

import (
	"crypto/x509"
	"flag"
)

// Parse flags for Verify subcommand
func verifyParseFlags(flags ...string) *flag.FlagSet {
	cmd := flag.NewFlagSet("cert", flag.ExitOnError)
	cmd.StringVar(&host, "host", "", "Host name to verify")
	cmd.StringVar(&root, "root", "", "Trusted root certificate")
	cmd.StringVar(&intermediate, "intermediate", "", "Intermediate certificate")

	cmd.Parse(flags)
	args = cmd.Args()

	return cmd
}

// Verify a certificate with configured options
func verifyCertificate(file string) {
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
	if err != nil {
		exit(1, "Certificate could not be verified.", err)
	}
	exit(0, "Certificate verified successfully")
}

// Verify a certificate
func Verify(flags ...string) {
	cmd := verifyParseFlags(flags...)
	arg := getArg()

	switch arg {
	case "help":
		cmd.Usage()
	default:
		verifyCertificate(arg)
	}
}
