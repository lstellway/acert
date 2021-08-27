package main

import (
	"fmt"
	"os/exec"
	"path"
	"runtime"
	"time"
)

// Parse "trust" command flags
func parseTrust(input ...string) {
	args = input
}

// Trust a certificate on Darwin (MacOS)
func TrustDarwin(cert string) {
	cmd := exec.Command("sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert)
	cmd.Run()
}

// Trust a certificate on Linux
func TrustLinux(cert string) {
	var (
		command []string
		file string
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

	// Copy certificate
	file = fmt.Sprintf(file, path.Base(cert), time.Now().Unix())
	cmd := exec.Command("sudo", "cp", cert, file)
	if err := cmd.Run(); err != nil {
		exit(1, err)
	} else {
		fmt.Printf("Certificate copied to '%s'", file)
	}

	// Trust certificate
	cmd = exec.Command("sudo", command...)
	if err := cmd.Run(); err != nil {
		exit(1, err)
	}
}

// Trust a certificate on Windows
func TrustWindows(cert string) {
	command, err := exec.LookPath("certutil")
	if err != nil {
		exit(1, "Could not find 'certutil' command")
	}

	cmd := exec.Command(command, "-addstore", "-f", "ROOT", cert)
	if err = cmd.Run(); err != nil {
		exit(1, err)
	}
}

// Trust a certificate
func Trust(args ...string) {
	parseTrust(args...)
	cert := getArg()

	// Check if file exists
	if FileExists(cert) == false {
		exit(1, "The specified certificate could not be found.")
	}

	// Execute trust strategy based on OS
	fmt.Println("Sudo permissions are required to trust certificates")
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
