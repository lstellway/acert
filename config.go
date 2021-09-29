package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"

	"github.com/lstellway/go/command"
)

var (
	// General
	bits, days, pathLenConstraint int
	trust                         bool

	// Elliptic curve cryptography
	isEcdsa, isEd25519 bool
	curve              string

	// File paths
	parent, key, csr string

	// Certificate subject
	country, province, locality, streetAddress, postalCode string
	organization, organizationalUnit                       string
	commonName, email                                      string
	san                                                    string

	// Verify options
	hosts, root, intermediate string
)

// Flags used to build the certificate subject
func certificateSubjectFlags(h *command.CommandSection) {
	h.StringVar(&country, "country", "", "Country Name (2 letter ISO-3166 code)")
	h.StringVar(&province, "province", "", "State or Province Name (full name)")
	h.StringVar(&locality, "locality", "", "Locality Name (eg, city)")
	h.StringVar(&streetAddress, "streetAddress", "", "Street Address (eg, 123 Fake Street)")
	h.StringVar(&postalCode, "postalCode", "", "Postal Code (eg, 94016)")
	h.StringVar(&organization, "organization", "", "Organization Name (eg, company)")
	h.StringVar(&organizationalUnit, "organizationUnit", "", "Organizational Unit Name (eg, section)")
	h.StringVar(&commonName, "commonName", "", "Certificate common name")
	h.StringVar(&email, "email", "", "Email Address")
	h.StringVar(&san, "san", "", "Comma-delimited Subject Alternative Name(s) (DNS, Email, IP, URI)")
}

// Parses generic cryptography flags
func certificateKeyFlags(h *command.CommandSection) {
	h.IntVar(&bits, "bits", 2048, "The number of bits used to generate an RSA key")
	h.BoolVar(&isEd25519, "ed25519", false, "Generate keys using ED25519 signature algorithm")
	h.BoolVar(&isEcdsa, "ecdsa", false, "Generate keys using ECDSA elliptic curve signature algorithm")
	h.StringVar(&curve, "curve", "P256", "Elliptic curve used to generate key (P224, P256, P384, P521)")
}

// Flags to sign a certificate using parent certificate
func certificateBuildFlags(h *command.CommandSection) {
	h.IntVar(&days, "days", 90, "Number of days generated certificates should be valid for")
	h.BoolVar(&trust, "trust", false, "Trust generated certificate")
	h.StringVar(&parent, "parent", "", "Path to PEM-encoded certificate used to sign certificate (authority or intermediate certificate)")
	h.StringVar(&key, "key", "", "Path to PEM-encoded private key used to sign certificate")
}

// buildSubject builds a PKIX subject name using input variables.
func buildSubject() pkix.Name {
	name := pkix.Name{}

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

// configureAcert applies configuration values from the CLI input to the Acert object
func configureAcert(a *Acert) {
	// If not configuring with a signing request
	if a.Request.Raw == nil {
		// Hosts
		forceStringInput(&san, "Subject Alternative Name(s) (e.g. subdomains) []: ")
		a.Hosts = splitValue(san, ",")
		if len(a.Hosts) > 0 && commonName == "" {
			commonName = a.Hosts[0]
		}

		// Subject
		a.Subject = buildSubject()

		// Private Key
		a.Options.Bits = bits
		var algorithm string
		switch {
		case isEd25519:
			algorithm = "ed25519"
		case isEcdsa:
			algorithm = strings.Join([]string{"ecdsa", curve}, "-")
		default:
			algorithm = "rsa"
		}
		a.Options.Algorithm = algorithm
	}

	// Certificate
	a.Options.Days = days
	a.Options.PathLenConstraint = pathLenConstraint
}
