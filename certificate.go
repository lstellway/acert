package main

import (
	"github.com/lstellway/go/command"
)

// buildAcertCertificate configures an Acert object,
// builds a certificate and saves the resulting files
func buildAcertCertificate(a *Acert, isCa bool) {
	// Wire up CLI options
	configureAcert(a)

	// Build certificate and save PEM files
	bytes := a.BuildCertificate(isCa)
	savePrivateKeyPem(commonName, a.PrivateKey)
	saveCertificatePem(commonName, bytes, trust)
}

// certificateCommandOptions wires up common options for
// commands that are used to build a certificate.
func certificateCommandOptions(h *command.Command, isCa bool, isCsr bool) {
	h.AddSection("Subject Name Options", func(s *command.CommandSection) {
		certificateSubjectFlags(s)
	})
	h.AddSection("Private Key Options", func(s *command.CommandSection) {
		certificateKeyFlags(s)
	})

	if !isCsr {
		h.AddSection("Certificate Options", func(s *command.CommandSection) {
			certificateBuildFlags(s)
			if isCa {
				s.IntVar(&pathLenConstraint, "pathLength", 0, "Maximum number of non-self-issued intermediate certificates that may follow this certificate in a valid certification path (for certificate chaining)")
			}
		})
	}
}

// certificate handles command-line input arguments to create a PKI certificate
func certificate(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("certificate"), "Create a PKI certificate", func(h *command.Command) {
		certificateCommandOptions(h, false, false)
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		// Validations
		requireFileValue(&key, "key")
		requireFileValue(&parent, "parent")

		buildAcertCertificate(&Acert{
			RootPrivateKey:  parsePemPrivateKey(key),
			RootCertificate: *parsePemCertificate(parent),
		}, false)
	}
}

// certificateAuthority handles command-line input arguments to create a PKI certificate authority.
func certificateAuthority(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("authority"), "Create a PKI certificate authority", func(h *command.Command) {
		certificateCommandOptions(h, true, false)
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		a := Acert{}

		// Configure parent certificate
		if key != "" || parent != "" {
			a.RootPrivateKey = parsePemPrivateKey(key)
			a.RootCertificate = *parsePemCertificate(parent)
		}

		buildAcertCertificate(&a, true)
	}
}

// CertificateRequest handles command-line input arguments
// to build a certificate signing request.
func certificateRequest(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("request"), "Create a PKI certificate signing request", func(h *command.Command) {
		certificateCommandOptions(h, false, true)
		h.AddSubcommand("sign", "Create a PKI certificate from a signing request")
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	case "sign":
		// Initialize command
		cmd, args = command.NewCommand(commandName("request sign"), "Create a PKI certificate from a signing request", func(h *command.Command) {
			h.AddSection("Certificate", func(s *command.CommandSection) {
				certificateBuildFlags(s)
			})
		}, args...)

		// Sign a certificate using a signing request
		buildAcertCertificate(&Acert{
			RootPrivateKey:  parsePemPrivateKey(key),
			RootCertificate: *parsePemCertificate(parent),
			Request:         *parsePemCertificateRequest(getArgument(true)),
		}, false)
	default:
		// Build certificate signing request
		a := Acert{}
		configureAcert(&a)
		request := a.BuildCertificateRequest()
		savePrivateKeyPem(commonName, a.PrivateKey)
		saveCertificateRequestPem(commonName, request)
	}
}

// VerifyCertificate validates a certificate root, chain and/or host name.
func verifyCertificate(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("verify"), "Verify a PKI certificate", func(h *command.Command) {
		h.AddSection("Options", func(s *command.CommandSection) {
			s.StringVar(&hosts, "hosts", "", "Host names to verify")
			s.StringVar(&root, "root", "", "Trusted root certificate")
			s.StringVar(&intermediate, "intermediate", "", "Intermediate certificate")
		})

		h.AddArgument("CERTIFICATE_FILE")

		h.AddExample("Verify certificate hosts for a certificate named 'test.com.cert.pem'", "-hosts test.com test.com.cert.pem")
		h.AddExample("Verify a certificate root", "-root root.ca.cert.pem test.com.cert.pem")
		h.AddExample("Verify a certificate chain", "-root root.ca.cert.pem -intermediate intermediate.ca.cert.pem test.com.cert.pem")
	}, flags...)

	// Get first argument
	arg := getArgument(true)

	switch arg {
	case "", "help":
		cmd.Usage()
	default:
		requireFileValue(&arg, "certificate")
		a := Acert{
			Certificate: *parsePemCertificate(arg),
		}

		// Hosts
		if hosts != "" {
			a.Hosts = splitValue(hosts, ",")
		}

		// Root certificate
		if root != "" {
			a.RootCertificate = *parsePemCertificate(root)
		}

		// Intermediate certificate
		if intermediate != "" {
			a.RootCertificate = *parsePemCertificate(intermediate)
		}

		err := a.Verify()
		exitOnError(err, "Certificate could not be validate.", err)
		log("Certificate successfully validated")
	}
}
