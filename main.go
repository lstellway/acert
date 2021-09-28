package main

import (
	"os"

	"github.com/lstellway/go/command"
)

func main() {
	cmd, args = command.NewCommand(basename, "", func(h *command.Command) {
		h.AddSubcommand("authority", "Create a PKI certificate authority")
		h.AddSubcommand("certificate", "Create a PKI certificate")
		h.AddSubcommand("request", "Create a PKI certificate signing request")
		h.AddSubcommand("trust", "Trust a PKI certificate")
		h.AddSubcommand("verify", "Verify a PKI certificate")
	}, os.Args[1:]...)

	switch getArgument(true) {
	case "ca", "authority":
		CertificateAuthority(args...)
	case "cert", "certificate":
		Certificate(args...)
	case "csr", "request":
		CertificateRequest(args...)
	case "trust":
		TrustCertificate(args...)
	case "verify":
		VerifyCertificate(args...)
	default:
		cmd.Usage()
	}
}
