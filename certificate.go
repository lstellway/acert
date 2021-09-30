package main

import (
	"github.com/lstellway/go/command"
)

// buildAcertCertificate configures an Acert object,
// builds a certificate and saves the resulting files
func buildAcertCertificate(a *Acert, isCa bool) {
	// Validate output directory
	requireFileValue(&outputDirectory, "output")

	// Map CLI options
	configureAcert(a)

	// Build certificate and save certificate PEM files
	bytes := a.BuildCertificate(isCa)
	saveCertificatePem(a.Subject.CommonName, bytes, trust)

	// Private key may be nil when signing a request
	// If there is a private key, save the PEM file
	if a.PrivateKey != nil {
		savePrivateKeyPem(a.Subject.CommonName, a.PrivateKey)
	}
}

// certificateCommandOptions wires up common options for
// commands that are used to build a certificate.
func certificateCommandOptions(h *command.Command, isCa bool, isCsr bool) {
	h.AddSection("General Options", func(s *command.CommandSection) {
		generalFlags(s)
	})
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
		h.AddSubcommand("help", "Display this help screen")
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		buildAcertCertificate(&Acert{}, false)
	}
}

// certificateAuthority handles command-line input arguments to create a PKI certificate authority.
func certificateAuthority(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("authority"), "Create a PKI certificate authority", func(h *command.Command) {
		certificateCommandOptions(h, true, false)
		h.AddSubcommand("help", "Display this help screen")
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	default:
		buildAcertCertificate(&Acert{}, true)
	}
}

// CertificateRequest handles command-line input arguments
// to build a certificate signing request.
func certificateRequest(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("request"), "Create a PKI certificate signing request", func(h *command.Command) {
		certificateCommandOptions(h, false, true)

		h.AddSubcommand("help", "Display this help screen")
		h.AddSubcommand("sign", "Create a PKI certificate from a signing request")
	}, flags...)

	switch getArgument(true) {
	case "help":
		cmd.Usage()
	case "sign":
		// Initialize command
		cmd, args = command.NewCommand(commandName("request sign"), "Create a PKI certificate from a signing request", func(h *command.Command) {
			h.AddSection("General Options", func(s *command.CommandSection) {
				generalFlags(s)
			})
			h.AddSection("Certificate", func(s *command.CommandSection) {
				certificateBuildFlags(s)
			})

			h.AddArgument("SIGNING_REQUEST")
			h.AddSubcommand("help", "Display this help screen")
		}, args...)

		// Requires parent certificate to sign request
		arg := getArgument(true)

		switch arg {
		case "", "help":
			cmd.Usage()
		default:
			requireFileValue(&arg, "SIGNING_REQUEST")
			requireFileValue(&parent, "parent")
			requireFileValue(&key, "key")

			// Sign a certificate using a signing request
			buildAcertCertificate(&Acert{
				Request: *parsePemCertificateRequest(arg),
			}, false)
		}
	default:
		// Validate output directory
		requireFileValue(&outputDirectory, "output")

		// Build certificate signing request
		a := Acert{}
		configureAcert(&a)
		request := a.BuildCertificateRequest()
		savePrivateKeyPem(a.Subject.CommonName, a.PrivateKey)
		saveCertificateRequestPem(a.Subject.CommonName, request)
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

		h.AddSubcommand("help", "Display this help screen")
	}, flags...)

	// Get first argument
	arg := getArgument(true)

	switch arg {
	case "", "help":
		cmd.Usage()
	default:
		// Validate required files are set
		requireFileValue(&arg, "CERTIFICATE_FILE")
		requireFileValue(&root, "root")

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
