package main

import (
	"os"
)

func main() {
	args = os.Args[1:]

	switch getArgument() {
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
		// Help
	}
}
