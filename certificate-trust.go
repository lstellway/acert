package main

import (
	"fmt"
	"os/exec"
	"path"
	"runtime"
	"time"

	"github.com/lstellway/go/command"
)

// TrustDarwin trust a PKI certificate on macOS (Darwin)
func TrustDarwin(cert string) {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert)
	cmd.Run()
}

// TrustLinux trust a PKI certificate on Linux
func TrustLinux(cert string) {
	var (
		command []string
		file    string
	)

	switch {
	case fileExists("/etc/pki/ca-trust/source/anchors/"):
		command = []string{"update-ca-trust", "extract"}
		file = "/etc/pki/ca-trust/source/anchors/%s-%d.pem"
	case fileExists("/usr/local/share/ca-certificates/"):
		command = []string{"update-ca-certificates"}
		file = "/usr/local/share/ca-certificates/%s-%d.crt"
	case fileExists("/etc/ca-certificates/trust-source/anchors/"):
		command = []string{"trust", "extract-compat"}
		file = "/etc/ca-certificates/trust-source/anchors/%s-%d.crt"
	case fileExists("/usr/share/pki/trust/anchors/"):
		command = []string{"update-ca-certificates"}
		file = "/usr/share/pki/trust/anchors/%s-%d.pem"
	default:
		exit(1, "Supported certificate management not found.")
	}

	// Build file path
	file = fmt.Sprintf(file, path.Base(cert), time.Now().Unix())

	// Copy certificate
	cmd := exec.Command("sudo", "cp", cert, file)
	err := cmd.Run()
	exitOnError(err, err)
	fmt.Printf("Certificate copied to '%s'", file)

	// Trust certificate
	cmd = exec.Command("sudo", command...)
	err = cmd.Run()
	exitOnError(err, err)
}

// TrustWindows trust a PKI certificate on Windows
func TrustWindows(cert string) {
	command, err := exec.LookPath("certutil")
	exitOnError(err, "Could not find 'certutil' command")

	cmd := exec.Command(command, "-addstore", "-f", "ROOT", cert)
	err = cmd.Run()
	exitOnError(err, err)
}

// TrustCertificate trusts a PKI certificate.
// The method used to trust is determined based on the operating system
// and available tools installed on the machine.
func Trust(cert string) {
	requireFileValue(&cert, "certificate")

	// Execute trust strategy based on OS
	switch runtime.GOOS {
	case "darwin":
		TrustDarwin(cert)
	case "linux":
		TrustLinux(cert)
	case "windows":
		TrustWindows(cert)
	default:
		exit(1, fmt.Sprintf("The operating system '%s' is currently unsupported.\n", runtime.GOOS))
	}
}

// trustCertificate defines the CLI command to trust a PKI certificate.
func trustCertificates(flags ...string) {
	// Initialize command
	cmd, args = command.NewCommand(commandName("trust"), "Trust PKI certificates", func(h *command.Command) {
		h.AddArgument("CERTIFICATE_FILES...")

		h.AddExample("Trust a single certificate", "test.com.csr.pem")
		h.AddExample("Trust multiple certificates", "local-root.ca.cert.pem remote.ca.cert.pem test.com.csr.pem")

		h.AddSubcommand("help", "Display this help screen")
	}, flags...)

	switch getArgument(true) {
	case "", "help":
		cmd.Usage()
	default:
		log("Sudo permissions are required to trust certificates")
		for _, cert := range flags {
			Trust(cert)
		}
	}
}
