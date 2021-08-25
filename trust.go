package main

import (
	"fmt"
	"os/exec"
	"os"
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
		fmt.Println("Supported certificate management not found.")
		os.Exit(1)
	}

	// Copy certificate
	file = fmt.Sprintf(file, path.Base(cert), time.Now().Unix())
	cmd := exec.Command("sudo", "cp", cert, file)
	if err := cmd.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		fmt.Printf("Certificate copied to '%s'", file)
	}

	// Trust certificate
	cmd = exec.Command("sudo", command...)
	if err := cmd.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Trust a certificate on Windows
func TrustWindows(cert string) {
	command, err := exec.LookPath("certutil")
	if err != nil {
		fmt.Println("Could not find 'certutil' command")
		os.Exit(1)
	}

	cmd := exec.Command(command, "-addstore", "-f", "ROOT", cert)
	if err = cmd.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Trust a certificate
func Trust(cert string) {
	// Check if file exists
	if exists := FileExists(cert); exists == false {
		fmt.Println("The specified certificate could not be found.")
		os.Exit(1)
	}

	fmt.Println("Sudo permissions are required to trust a certificate.")

	// Execute trust strategy based on OS
	switch runtime.GOOS {
	case "darwin":
		TrustDarwin(cert)
	case "linux":
		TrustLinux(cert)
	case "windows":
		TrustWindows(cert)
	default:
		fmt.Printf("The operating system '%s' is currently unsupported.\n", runtime.GOOS)
		os.Exit(1)
	}
}
