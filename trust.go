package main

import (
	"fmt"
	"os/exec"
	"path"
	"runtime"
	"time"
)

// Trust a certificate on Darwin (MacOS)
func TrustDarwin(cert string) {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert)
	cmd.Run()
}

// Trust a certificate on Linux
func TrustLinux(cert string) {
	var (
		command []string
		file    string
	)

	switch {
	case FileExists("/etc/pki/ca-trust/source/anchors/"):
		command = []string{"update-ca-trust", "extract"}
		file = "/etc/pki/ca-trust/source/anchors/%s-%d.pem"
	case FileExists("/usr/local/share/ca-certificates/"):
		command = []string{"update-ca-certificates"}
		file = "/usr/local/share/ca-certificates/%s-%d.crt"
	case FileExists("/etc/ca-certificates/trust-source/anchors/"):
		command = []string{"trust", "extract-compat"}
		file = "/etc/ca-certificates/trust-source/anchors/%s-%d.crt"
	case FileExists("/usr/share/pki/trust/anchors/"):
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

// Trust a certificate on Windows
func TrustWindows(cert string) {
	command, err := exec.LookPath("certutil")
	exitOnError(err, "Could not find 'certutil' command")

	cmd := exec.Command(command, "-addstore", "-f", "ROOT", cert)
	err = cmd.Run()
	exitOnError(err, err)
}

// Trust a certificate
func TrustCertificate(flags ...string) {
	// Initialize command
	cmd, args = NewCommand(commandName("trust"), "Trust a PKI certificate", func(h *Command) {
		h.AddArgument("FILE")
		h.AddExample("Trust a signing request file named 'test.com.csr.pem'", "test.com.csr.pem")
	}, flags...)

	// Check if file exists
	cert := getArgument(true)
	RequireFileValue(&cert, "certificate")

	// Execute trust strategy based on OS
	log("Sudo permissions are required to trust certificates")
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
