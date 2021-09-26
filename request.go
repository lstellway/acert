package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
)

// Parse a pem-encoded certificate file
func ParsePemCertificateRequest(file string) *x509.CertificateRequest {
	// Decode signing certificate
	pem := ReadFile(file)
	data := PemDecode(pem)
	cert, err := x509.ParseCertificateRequest(data)

	if err != nil {
		exit(1, "Invalid private key file: ", file)
	}

	return cert
}

// Generate certificate signing request
func buildCertificateRequest() (crypto.PrivateKey, []byte) {
	// Generate private key
	privateKey := GenerateKey(bits, curve)

	// Build request template
	certificate := buildCertificateWithSan()
	request := x509.CertificateRequest{
		Subject:        buildSubject(),
		DNSNames:       certificate.DNSNames,
		IPAddresses:    certificate.IPAddresses,
		EmailAddresses: certificate.EmailAddresses,
		URIs:           certificate.URIs,
	}

	// Build certificate signing request
	csr, err := x509.CreateCertificateRequest(rand.Reader, &request, privateKey)
	if err != nil {
		exit(1, "Error occurred while generating certificate signing request: ", err)
	}

	return privateKey, csr
}

// Initializes the certificate signing request subcommand
func CertificateRequest(args ...string) {
	// Parse command flags
	cmd := parseFlags("csr", func(cmd *flag.FlagSet) {
		certificateSubjectFlags(cmd)
		certificateKeyFlags(cmd)
	}, args...)

	switch getArgument() {
	case "help":
		cmd.Usage()
	default:
		privateKey, request := buildCertificateRequest()

		// PEM-encode
		privateKeyPem := PemEncode("PRIVATE KEY", PrivateKeyPkcs(privateKey))
		requestPem := PemEncode("CERTIFICATE REQUEST", request)

		// Save files
		SaveFile(getOutputPath(commonName+".key.pem"), privateKeyPem, 0644, true)
		SaveFile(getOutputPath(commonName+".csr.pem"), requestPem, 0644, true)
	}
}
