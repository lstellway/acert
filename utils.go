package main

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/lstellway/go/command"
)

var (
	basename            = "acert"
	args                []string
	cmd                 command.Command
	now                 = time.Now()
	outputDirectory     string
	workingDirectory, _ = os.Getwd()
)

// Package logger
func log(messages ...interface{}) {
	fmt.Println(messages...)
}

// Exit program with message
func exit(code int, messages ...interface{}) {
	log(messages...)
	os.Exit(code)
}

// Exit program if there is an error
func exitOnError(err error, messages ...interface{}) {
	if err != nil {
		exit(1, messages...)
	}
}

// Get the next argument
func getArgument(remove bool) string {
	arg := ""

	if len(args) > 0 {
		arg = args[0]

		if remove {
			args = args[1:]
		}
	}

	return arg
}

// Build command name
func commandName(name string) string {
	return fmt.Sprintf("%s %s", basename, name)
}

// Builds path in output directory
func getOutputPath(name string) string {
	return path.Join(outputDirectory, name)
}

// FileExists checks if a file exists
func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// RequireFileValue checks that a string variable contains a path
// to a file that exists on the filesystem.
func requireFileValue(value *string, name string) {
	*value = strings.TrimSpace(*value)

	if *value == "" || !fileExists(*value) {
		message := fmt.Sprintf("File for '%s' argument not found: %s", name, *value)
		exit(1, message)
	}
}

// SaveFile saves a file to the filesystem with a specified name
// and specified permissions.
// There is an option to determine whether or not to report success.
func saveFile(name string, data []byte, permissions os.FileMode, report bool) {
	// Write to filesystem
	err := os.WriteFile(name, data, permissions)
	exitOnError(err, "Could not save file:", name)

	if report {
		log("Saved file:", name)
	}
}

// SplitValue splits a string value by a delimiter and returns a string array with the values.
// Values are trimmed of whitespace and empty values are ignored.
func splitValue(value string, delimiter string) []string {
	var values []string

	for _, val := range strings.Split(value, delimiter) {
		val = strings.TrimSpace(val)
		if val != "" {
			values = append(values, val)
		}
	}

	return values
}

// PromptForInput prints a message to the console.
// The script will then return the user's input from stdin.
func promptForInput(message string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	return reader.ReadString('\n')
}

// ForceStringInput will repeatedly prompt a user for input
// until a non-empty string value is inputted.
func forceStringInput(variable *string, message string) string {
	val := ""

	for strings.TrimSpace(*variable) == "" {
		val, _ := promptForInput(message)
		*variable = strings.TrimSpace(val)
	}

	return val
}

// ReadFile returns the byte contents of a specified file
func readFile(file string) []byte {
	data, err := os.ReadFile(file)
	exitOnError(err, "Could not read file:", file)
	return data
}

// PemEncode PEM-encodes an input byte array of a specified type.
func pemEncode(name string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  name,
		Bytes: data,
	})
}

// PemDecode decodes a PEM-encoded file of a specified type.
// Multiple types can be passed, each of which is considered valid.
func pemDecode(bytes []byte, types ...string) []byte {
	// Decode PEM
	data, _ := pem.Decode(bytes)
	if data == nil {
		exit(1, "Could not parse PEM data")
	}

	// Ensure PEM file is of expected type
	if len(types) > 0 {
		isValid := false
		for _, name := range types {
			if data.Type == name {
				isValid = true
			}
		}

		if !isValid {
			message := fmt.Sprintf("Unexpected PEM format '%s'. Expecting %s", data.Type, strings.Join(types, " or "))
			exit(1, message)
		}
	}

	return data.Bytes
}

// ParsePemFile parses the contents of specified PEM-encoded file
func parsePemFile(file string, types ...string) []byte {
	pem := readFile(file)
	return pemDecode(pem, types...)
}

// ParsePemCertificate reads a specified PEM-encoded
// certificate file and parses it into a x509.Certificate object
func parsePemCertificate(file string) *x509.Certificate {
	data := parsePemFile(file, "CERTIFICATE")
	cert, err := x509.ParseCertificate(data)
	exitOnError(err, "Invalid certificate: ", file)
	return cert
}

// ParsePemCertificateRequest reads a specified PEM-encoded
// certificate request file and parses it into a x509.CertificateRequest object
func parsePemCertificateRequest(file string) *x509.CertificateRequest {
	data := parsePemFile(file, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	cert, err := x509.ParseCertificateRequest(data)
	exitOnError(err, "Invalid certificate request file: ", file)
	return cert
}

// ParsePemPrivateKey reads a specified PEM-encoded
// private key file and parses it into a crypto.PrivateKey object
func parsePemPrivateKey(file string) crypto.PrivateKey {
	data := parsePemFile(file, "PRIVATE KEY")
	cert, err := x509.ParsePKCS8PrivateKey(data)
	exitOnError(err, "Invalid private key file: ", file)
	return cert
}

// Get private key PKCS #8
func privateKeyPkcs(privateKey crypto.PrivateKey) []byte {
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	exitOnError(err, "Error occurred while getting ca private key PKCS #8. ", err)
	return key
}

// Save PEM-encoded file
func savePemFile(name string, data []byte) {
	saveFile(getOutputPath(name), data, 0644, true)
}

// saveCertificateFiles saves PEM-encoded certificate files
func saveCertificatePem(name string, bytes []byte, trust bool) {
	certificatePem := pemEncode("CERTIFICATE", bytes)
	savePemFile(name+".cert.pem", certificatePem)

	if parent != "" {
		// Save chain
		chainPem := readFile(parent)
		savePemFile(name+".chain.pem", chainPem)

		// Save full-chain
		fullchainPem := append(certificatePem, chainPem...)
		savePemFile(name+".fullchain.pem", fullchainPem)
	}

	// Trust certificate
	if trust {
		Trust(getOutputPath(name + ".cert.pem"))
	}
}

// saveCertificateRequestFile saves PEM-encoded certificate request file
func saveCertificateRequestPem(name string, request []byte) {
	pem := pemEncode("CERTIFICATE REQUEST", request)
	savePemFile(name+".csr.pem", pem)
}

// savePrivateKeyFile saves PEM-encoded private key file
func savePrivateKeyPem(name string, privateKey crypto.PrivateKey) {
	pem := pemEncode("PRIVATE KEY", privateKeyPkcs(privateKey))
	savePemFile(name+".key.pem", pem)
}
