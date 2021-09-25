package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

var (
	// General
	bits, days, pathLenConstraint int
	trust                         bool

	// Elliptic curve cryptography
	isEcdsa bool
	curve   string

	// Signing certificate authority file paths
	authority, authorityKey string

	// Certificate subject
	country, province, locality, streetAddress, postalCode string
	organization, organizationalUnit                       string
	commonName, email                                      string

	// Subject alternative names
	san string

	// Verify options
	host, root, intermediate string
)

// Parses arguments related to certificate requests
func cryptoParseFlags(cmd *flag.FlagSet) {
	cmd.IntVar(&bits, "bits", 2048, "The size of the key to generate in bits")
	cmd.BoolVar(&isEcdsa, "ecdsa", false, "Generate keys using ECDSA elliptic curve")
	cmd.StringVar(&curve, "curve", "P256", "Elliptic curve used to generate private key (P224, P256, P384, P521)")

	cmd.StringVar(&country, "country", "", "Country Name (2 letter ISO-3166 code)")
	cmd.StringVar(&province, "province", "", "State or Province Name (full name)")
	cmd.StringVar(&locality, "locality", "", "Locality Name (eg, city)")
	cmd.StringVar(&streetAddress, "streetAddress", "", "Street Address\n(eg: 123 Fake Street)")
	cmd.StringVar(&postalCode, "postalCode", "", "Postal Code (eg, 94016)")
	cmd.StringVar(&organization, "organization", "", "Organization Name (eg, company)")
	cmd.StringVar(&organizationalUnit, "organizationUnit", "", "Organizational Unit Name (eg, section)")
	cmd.StringVar(&commonName, "commonName", "", "Certificate common name (required)")
	cmd.StringVar(&email, "email", "", "Email Address")
	cmd.StringVar(&san, "san", "", "Comma-delimited Subject Alternative Names (DNS, Email, IP, URI)")
}

// Build subject alternative name data
func ParseSANHosts(hosts []string) x509.Certificate {
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
func GenerateKey(bits int, standard string) (crypto.PrivateKey, error) {
	switch {
	case isEcdsa:
		var curve elliptic.Curve

		switch strings.ToLower(standard) {
		case "p224":
			curve = elliptic.P224()
		case "p384":
			curve = elliptic.P384()
		case "p521":
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}

		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return rsa.GenerateKey(rand.Reader, bits)
	}
}

// Generate serial number
func GenerateSerialNumber() *big.Int {
	// Set limit
	limit := new(big.Int).Lsh(big.NewInt(1), 128)

	// Generate serial
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		exit(1, "Could not generate serial number.", err)
	}

	return serial
}

// Run before building a certificate
func initializeCertificate() x509.Certificate {
	// Make sure subject alternative names are set
	ForceString(&san, "Subject Alternative Name(s) (e.g. subdomains) []: ")

	// Get SAN hosts
	hosts := SplitValue(san, ",")

	// Default commonName to first SAN host
	if commonName == "" && len(hosts) > 0 {
		commonName = hosts[0]
	}

	return ParseSANHosts(hosts)
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

// Builds certificate signing request template
func buildCertificateRequest() x509.CertificateRequest {
	initial := initializeCertificate()

	request := x509.CertificateRequest{
		Subject:            buildSubject(),
		SignatureAlgorithm: x509.SHA256WithRSA,
		// SAN
		DNSNames:       initial.DNSNames,
		IPAddresses:    initial.IPAddresses,
		EmailAddresses: initial.EmailAddresses,
		URIs:           initial.URIs,
	}

	return request
}

// Build x509 certificate
func buildCertificate(ca bool) x509.Certificate {
	// Initialize certificate (includes SAN hosts)
	certificate := initializeCertificate()
	certificate.Subject = buildSubject()
	certificate.SerialNumber = GenerateSerialNumber()
	certificate.NotBefore = now
	certificate.IsCA = ca
	certificate.MaxPathLen = 1

	// Add expiration date based on the configured number of days
	if days > 0 {
		certificate.NotAfter = now.Add(time.Hour * 24 * time.Duration(days))
	}

	// Key usage
	if ca {
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
	if ca && pathLenConstraint > 0 {
		certificate.MaxPathLen = pathLenConstraint
		certificate.MaxPathLenZero = false
	} else {
		certificate.MaxPathLenZero = true
	}

	return certificate
}

// Parse a pem-encoded certificate file
func ParsePemCertificate(file string) *x509.Certificate {
	// Decode signing certificate
	bytes := PemDecodeFile(file)
	cert, err := x509.ParseCertificate(bytes)

	if err != nil {
		exit(1, "Invalid certificate: ", file)
	}

	return cert
}

// Parse a pem-encoded certificate file
func ParsePemPrivateKey(file string) crypto.PrivateKey {
	// Decode signing certificate
	bytes := PemDecodeFile(file)
	cert, err := x509.ParsePKCS8PrivateKey(bytes)

	if err != nil {
		exit(1, "Invalid private key file: ", file)
	}

	return cert
}

// Get private key PKCS #8
func PrivateKeyPkcs(privateKey crypto.PrivateKey) []byte {
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)

	if err != nil {
		exit(1, "Error occurred while getting ca private key PKCS #8. ", err)
	}

	return key
}
