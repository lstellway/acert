/*
	acert is a command-line utility for managing PKI certificates written in Go

	Features

	Perform many common tasks necessary for setting up your PKI infrastructure.

		✓ Generate signing requests
		✓ Generate authority certificates
		✓ Generate client certificates
		✓ Build certificate chains
		✓ Verify certificate root, chain & hosts
		✓ Trust certificates

	Simple, Intuitive API

	A goal of this project is to make PKI simple and approachable.

	Please don't hesitate to submit an issue or open a PR with your suggestions:
	https://github.com/lstellway/acert/issues

	ECDSA Elliptic Curve Support

	Certificates can be signed using ECDSA Elliptic Curves:
	https://pkg.go.dev/crypto/ecdsa

	The P-224, P-256, P-384 and P-521 standards are all included as part of the package:
	https://pkg.go.dev/crypto/elliptic

	ED25519 Support

	A certificate can be signed with a key using the ED25519 signature algorithm:
	https://pkg.go.dev/crypto/ed25519

	Note:

	Be sure to check if your use case supports ED25519.
	For example, ED25519 was introduced in TLS v1.3, which is only supported by a subset of browsers.
*/
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
	case "cert", "certificate", "client":
		certificate(args...)
	case "ca", "authority":
		certificateAuthority(args...)
	case "csr", "request":
		certificateRequest(args...)
	case "trust":
		trustCertificates(args...)
	case "verify":
		verifyCertificate(args...)
	default:
		cmd.Usage()
	}
}
