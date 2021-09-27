package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// Parse a pem-encoded certificate file
func ParsePemCertificate(file string) *x509.Certificate {
	data := ParsePemFile(file, "CERTIFICATE")
	cert, err := x509.ParseCertificate(data)
	exitOnError(err, "Invalid certificate: ", file)
	return cert
}

// Parse a pem-encoded certificate file
func ParsePemCertificateRequest(file string) *x509.CertificateRequest {
	data := ParsePemFile(file, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
	cert, err := x509.ParseCertificateRequest(data)
	exitOnError(err, "Invalid certificate request file: ", file)
	return cert
}

// Parse a pem-encoded certificate file
func ParsePemPrivateKey(file string) crypto.PrivateKey {
	data := ParsePemFile(file, "PRIVATE KEY")
	cert, err := x509.ParsePKCS8PrivateKey(data)
	exitOnError(err, "Invalid private key file: ", file)
	return cert
}

// Get private key PKCS #8
func PrivateKeyPkcs(privateKey crypto.PrivateKey) []byte {
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	exitOnError(err, "Error occurred while getting ca private key PKCS #8. ", err)
	return key
}

// Build subject alternative name data
func ParseSanHosts(hosts []string) x509.Certificate {
	template := x509.Certificate{}

	// Parse subject alternative name data
	for _, value := range hosts {
		if ip := net.ParseIP(value); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(value); err == nil && email.Address == value {
			template.EmailAddresses = append(template.EmailAddresses, email.Address)
		} else if uri, err := url.Parse(value); err == nil && uri.Scheme != "" && uri.Host != "" {
			template.URIs = append(template.URIs, uri)
		} else {
			template.DNSNames = append(template.DNSNames, value)
		}
	}

	return template
}

// Generate a private key
func GenerateKey(bits int, standard string) crypto.PrivateKey {
	var (
		privateKey crypto.PrivateKey
		err        error
	)

	switch {
	case isEd25519:
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	case isEcdsa:
		var curve elliptic.Curve
		standard = strings.ToLower(strings.TrimSpace(standard))

		switch standard {
		case "p224":
			curve = elliptic.P224()
		case "p384":
			curve = elliptic.P384()
		case "p521":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}

		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	}

	exitOnError(err, "Error occurred while generating private key: ", err)
	return privateKey
}

// Generate serial number
func GenerateSerialNumber() *big.Int {
	// Set limit
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	// Generate serial
	serial, err := rand.Int(rand.Reader, limit)
	exitOnError(err, "Could not generate serial number.", err)
	return serial
}

// Build certificate from signing request
func DecorateCertificateFromRequest(certificate *x509.Certificate, request x509.CertificateRequest) {
	certificate.Subject = request.Subject
	certificate.Extensions = request.Extensions
	certificate.ExtraExtensions = request.ExtraExtensions

	// SAN
	for _, value := range request.DNSNames {
		certificate.DNSNames = append(certificate.DNSNames, value)
	}
	for _, value := range request.IPAddresses {
		certificate.IPAddresses = append(certificate.IPAddresses, value)
	}
	for _, value := range request.EmailAddresses {
		certificate.EmailAddresses = append(certificate.EmailAddresses, value)
	}
	for _, value := range request.URIs {
		certificate.URIs = append(certificate.URIs, value)
	}
}

// Run before building a certificate
func buildCertificateSan() x509.Certificate {
	// Make sure subject alternative names are set
	ForceStringInput(&san, "Subject Alternative Name(s) (e.g. subdomains) []: ")

	// Get SAN hosts
	hosts := SplitValue(san, ",")

	// Default commonName to first SAN host
	if commonName == "" && len(hosts) > 0 {
		commonName = hosts[0]
	}

	return ParseSanHosts(hosts)
}

// Build certificate subject
func buildSubject() pkix.Name {
	name := pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{},
	}

	if country != "" {
		name.Country = []string{country}
	}
	if province != "" {
		name.Province = []string{province}
	}
	if locality != "" {
		name.Locality = []string{locality}
	}
	if streetAddress != "" {
		name.StreetAddress = []string{streetAddress}
	}
	if postalCode != "" {
		name.PostalCode = []string{postalCode}
	}
	if organization != "" {
		name.Organization = []string{organization}
	}
	if organizationalUnit != "" {
		name.OrganizationalUnit = []string{organizationalUnit}
	}
	if commonName != "" {
		name.CommonName = commonName
	}

	// Add email
	// Thank you: https://stackoverflow.com/a/50394867/4612530
	if email != "" {
		// TODO: Read https://www.pkisolutions.com/object-identifiers-oid-in-pki/
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
			Value: asn1.RawValue{
				Tag:   asn1.TagIA5String,
				Bytes: []byte(email),
			},
		})
	}

	return name
}

// Generate certificate signing request
func buildCertificateRequest() (crypto.PrivateKey, []byte) {
	// Generate private key
	privateKey := GenerateKey(bits, curve)

	// Build request template
	certificate := buildCertificateSan()
	request := x509.CertificateRequest{
		Subject:        buildSubject(),
		DNSNames:       certificate.DNSNames,
		IPAddresses:    certificate.IPAddresses,
		EmailAddresses: certificate.EmailAddresses,
		URIs:           certificate.URIs,
	}

	// Build certificate signing request
	csr, err := x509.CreateCertificateRequest(rand.Reader, &request, privateKey)
	exitOnError(err, "Error occurred while generating certificate signing request: ", err)
	return privateKey, csr
}

// Trust the saved certificate
func buildCertificate(isCa bool, isFromCsr bool) {
	var (
		publicKey                crypto.PublicKey
		privateKey, authorityKey crypto.PrivateKey
		authority                *x509.Certificate
		certificate              x509.Certificate
	)

	// Validations
	if !isCa {
		RequireFileValue(&parent, "parent")
		RequireFileValue(&key, "key")
	}
	if isFromCsr {
		RequireFileValue(&csr, "csr")
	}

	if isFromCsr {
		// Initialize certificate from signing request
		request := ParsePemCertificateRequest(csr)
		certificate = x509.Certificate{}
		DecorateCertificateFromRequest(&certificate, *request)

		// Use request public key
		publicKey = request.PublicKey
	} else {
		// Initialize certificate from command arguments
		certificate = buildCertificateSan()
		certificate.Subject = buildSubject()

		// Build private and public key
		privateKey = GenerateKey(bits, curve)
		publicKey = privateKey.(crypto.Signer).Public()
	}

	// Other certificate properties
	certificate.SerialNumber = GenerateSerialNumber()
	certificate.NotBefore = now
	certificate.IsCA = isCa

	// Add expiration date based on the configured number of days
	if days > 0 {
		if days > 825 {
			log("Warning: iOS and macOS certificates must have a validity period of 825 days or fewer")
			log("Reference: https://support.apple.com/en-us/HT210176")
		}
		certificate.NotAfter = now.Add(time.Hour * 24 * time.Duration(days))
	}

	// Certificate key usage
	if isCa {
		certificate.BasicConstraintsValid = true
		certificate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		certificate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature

		// Extended key usage server auth
		if len(certificate.IPAddresses) > 0 || len(certificate.DNSNames) > 0 || len(certificate.URIs) > 0 {
			// TODO: are there any issues with always using "x509.ExtKeyUsageClientAuth"?
			certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		}

		// Extended key usage email protection
		if len(certificate.EmailAddresses) > 0 {
			certificate.ExtKeyUsage = append(certificate.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		}
	}

	// Path length constraint for building certificate chain
	if isCa && pathLenConstraint > 0 {
		certificate.MaxPathLen = pathLenConstraint
		certificate.MaxPathLenZero = false
	} else {
		certificate.MaxPathLenZero = true
	}

	// Parent
	if parent != "" && key != "" {
		authority = ParsePemCertificate(parent)
		authorityKey = ParsePemPrivateKey(key)
	} else {
		authority = &certificate
		authorityKey = privateKey
	}

	// Build and save certificate
	name := commonName
	if isCa {
		name = name + ".ca"
	}

	// Build certificate
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &certificate, authority, publicKey, authorityKey)
	exitOnError(err, "Error occurred while generating certificate: ", err)

	// Save PEM-encoded certificate
	certificatePem := PemEncode("CERTIFICATE", certificateBytes)
	SaveFile(getOutputPath(name+".cert.pem"), certificatePem, 0644, true)

	// Save chain files
	if parent != "" {
		chainPem := ReadFile(parent)
		fullchainPem := append(certificatePem, chainPem...)
		SaveFile(getOutputPath(name+".chain.pem"), chainPem, 0644, true)
		SaveFile(getOutputPath(name+".fullchain.pem"), fullchainPem, 0644, true)
	}

	// Save PEM-encoded private key file
	if privateKey != nil {
		privateKeyPem := PemEncode("PRIVATE KEY", PrivateKeyPkcs(privateKey))
		SaveFile(getOutputPath(name+".key.pem"), privateKeyPem, 0644, true)
	}

	// Trust certificate
	if trust {
		TrustCertificate(getOutputPath(name + ".cert.pem"))
	}
}
