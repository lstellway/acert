package main

import (
	"os"
)

func main() {
	args = os.Args[1:]

	switch getArgument() {
	case "ca":
		CertificateAuthority(args...)
	case "csr":
		CertificateSigningRequest(args...)
	case "cert":
		Certificate(args...)
	case "trust":
		TrustCertificate(args...)
	case "verify":
		VerifyCertificate(args...)
	default:
		// Help
	}
}
