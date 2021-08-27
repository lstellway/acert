package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"math/big"
	"path"
	"strings"
	"time"
)

var (
	// General
	bits, days int
	trust bool

	// Signers
	rootCert string

	// Certificate subject
	country, province, locality, streetAddress, postalCode string
	organization, organizationalUnit string
	commonName, email string

	// Subject alternative names
	sanDns, sanEmail, sanIp, sanUri string
)

// Parses arguments related to certificate requests
func parseCrypto(cmd *flag.FlagSet) {
	cmd.IntVar(&bits, "bits", 4096, "The size of the key to generate in bits")

	cmd.StringVar(&country, "country", "", "Country Name (2 letter ISO-3166 code)")
	cmd.StringVar(&province, "province", "", "State or Province Name (full name)")
	cmd.StringVar(&locality, "locality", "", "Locality Name (eg, city)")
	cmd.StringVar(&streetAddress, "streetAddress", "", "Street Address\n(eg: 123 Fake Street)")
	cmd.StringVar(&postalCode, "postalCode", "", "Postal Code (eg, 94016)")
	cmd.StringVar(&organization, "organization", "", "Organization Name (eg, company)")
	cmd.StringVar(&organizationalUnit, "organization-unit", "", "Organizational Unit Name (eg, section)")
	cmd.StringVar(&commonName, "common-name", "", "Certificate common name (required)")
	cmd.StringVar(&email, "email", "", "Email Address")

	cmd.StringVar(&sanDns, "san-dns", "", "Comma-delimited Subject Alternative Names (domain names)")
	cmd.StringVar(&sanEmail, "san-email", "", "Comma-delimited Subject Alternative Names (email addresses)")
	cmd.StringVar(&sanIp, "san-ip", "", "Comma-delimited Subject Alternative Names (ip addresses)")
	cmd.StringVar(&sanUri, "san-uri", "", "Comma-delimited Subject Alternative Names (uniform resource identifier)")
}

// Gets the output file name without an extension attached
func getOutputPath() string {
	return path.Join(outputDirectory, commonName)
}

// Generate a private key
func GenerateKey(bits int) (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// Run before building a certificate
func preCertificate() {
	// Make sure subject alternative names are set
	ForceString(&sanDns, "Subject Alternative Name(s) (e.g. subdomains) []: ")

	// Add common name if not set
	if strings.TrimSpace(commonName) == "" {
		commonName = SplitValue(sanDns, ",")[0]
	}
}

// Build certificate subject
func buildSubject() (pkix.Name) {
	name := pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{},
	}

	if country != "" { name.Country = []string{country} }
	if province != "" { name.Province = []string{province} }
	if locality != "" { name.Locality = []string{locality} }
	if streetAddress != "" { name.StreetAddress = []string{streetAddress} }
	if postalCode != "" { name.PostalCode = []string{postalCode} }
	if organization != "" { name.Organization = []string{organization} }
	if organizationalUnit != "" { name.OrganizationalUnit = []string{organizationalUnit} }
	if commonName != "" { name.CommonName = commonName }

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

// buildSanData builds a struct full of subject alternative name info
func buildSanData() SanObject {
	template := SanObject{}

	// SAN - Email addresses
	if strings.TrimSpace(sanEmail) != "" { template.EmailAddresses = SplitValue(sanEmail, ",") }

	// SAN - IP Addresses
	if strings.TrimSpace(sanIp) != "" {
		for _, val := range SplitValue(sanIp, ",") {
			if ip := ParseIPAddress(val); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			}
		}
	}

	// SAN - Universal resource identifiers
	if strings.TrimSpace(sanUri) != "" {
		for _, val := range SplitValue(sanUri, ",") {
			if uri, err := ParseUri(val); err != nil {
				template.URIs = append(template.URIs, uri)
			}
		}
	}

	return template
}

// Builds certificate signing request template
func buildCertificateRequest() x509.CertificateRequest {
	preCertificate()

	template := x509.CertificateRequest{
        Subject: buildSubject(),
        SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames: SplitValue(sanDns, ","),
    }

	// Attach subject alternative name values
	san := buildSanData()
	if len(san.EmailAddresses) > 0 { template.EmailAddresses = san.EmailAddresses }
	if len(san.IPAddresses) > 0 { template.IPAddresses = san.IPAddresses }
	if len(san.URIs) > 0 { template.URIs = san.URIs }

	return template
}

// Build x509 certificate
func buildCertificate(ca bool) x509.Certificate {
	preCertificate()

	template := x509.Certificate{
		Subject: buildSubject(),
		SerialNumber: big.NewInt(2019),
		NotBefore: now,
		IsCA: ca,
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: SplitValue(sanDns, ","),
	}

	// Expiration
	if days > 0 { template.NotAfter = now.Add(time.Hour * 24 * time.Duration(days)) }

	// Key usage
	if ca { template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign }

	// Attach subject alternative name values
	san := buildSanData()
	if len(san.EmailAddresses) > 0 { template.EmailAddresses = san.EmailAddresses }
	if len(san.IPAddresses) > 0 { template.IPAddresses = san.IPAddresses }
	if len(san.URIs) > 0 { template.URIs = san.URIs }

	return template
}

// Parse a pem-encoded certificate file
func parsePemCertificate(file string) *x509.Certificate {
	// Decode signing certificate
	cert, err := x509.ParseCertificate(PemDecodeFile(file))

	if err != nil {
		exit(1, "Invalid certificate: ", file)
	}

	return cert
}

// Get private key PKCS #8
func PrivateKeyPkcs(privateKey crypto.PrivateKey) ([]byte) {
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)

	if err != nil {
		exit(1, "Error occurred while getting ca private key PKCS #8. ", err)
	}

	return key
}
