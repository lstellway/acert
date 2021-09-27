package main

import (
	"crypto/x509"
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
	// Initialize command
	cmd, args = NewCommand(commandName("verify"), "Verify a PKI certificate", func(h *Command) {
		h.AddSection("Options", func(s *CommandSection) {
			s.StringVar(&host, "host", "", "Host name to verify")
			s.StringVar(&root, "root", "", "Trusted root certificate")
			s.StringVar(&intermediate, "intermediate", "", "Intermediate certificate")
		})

		h.AddExample("Verify a certificate authority named 'local.ca.cert.pem'", "local.ca.cert.pem")
	}, flags...)

	arg := getArgument(true)
	switch arg {
	case "", "help":
		cmd.Usage()
	default:
		verify(arg)
	}
}
