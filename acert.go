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
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// AcertOptions holds extra configuration options used
// when generating private keys and building certificates.
type AcertOptions struct {
	// Certificate
	Days int

	// Path length is used for certificate chaining
	// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
	PathLenConstraint int

	// Private key
	Algorithm string
	Bits      int
}

// Acert is the primary object used to perform PKI operations.
type Acert struct {
	// Configuration
	Hosts   []string
	Options AcertOptions

	// Inputs
	RootPrivateKey          crypto.PrivateKey
	RootCertificate         x509.Certificate
	IntermediateCertificate x509.Certificate
	Subject                 pkix.Name

	// Outputs
	PrivateKey  crypto.PrivateKey
	PublicKey   crypto.PublicKey
	Certificate x509.Certificate
	Request     x509.CertificateRequest
}

// BuildCertificate builds a PKI certificate
func (a *Acert) BuildCertificate(isCa bool) []byte {
	if a.Request.Raw != nil {
		// Initialize certificate from signing request
		a.DecorateCertificateFromRequest()
		a.PublicKey = a.Request.PublicKey
	} else {
		// Parse configured hosts
		a.Certificate.Subject = a.Subject
		a.ParseSubjectAlternativeNames()

		// Require private key for request
		a.requirePrivateKey()
		a.PublicKey = a.PrivateKey.(crypto.Signer).Public()
	}

	// Other certificate properties
	a.GenerateSerialNumber()
	a.Certificate.NotBefore = now
	a.Certificate.IsCA = isCa

	// Add expiration date based on the configured number of days
	if a.Options.Days > 0 {
		if a.Options.Days > 825 {
			log("Warning: iOS and macOS certificates must have a validity period of 825 days or fewer")
			log("Reference: https://support.apple.com/en-us/HT210176")
		}
		a.Certificate.NotAfter = now.Add(time.Hour * 24 * time.Duration(a.Options.Days))
	}

	// Key usage
	if isCa {
		a.Certificate.BasicConstraintsValid = true
		a.Certificate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		a.Certificate.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		if len(a.Certificate.IPAddresses) > 0 || len(a.Certificate.DNSNames) > 0 || len(a.Certificate.URIs) > 0 {
			a.Certificate.ExtKeyUsage = append(a.Certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
		}

		// Email protection
		if len(a.Certificate.EmailAddresses) > 0 {
			a.Certificate.ExtKeyUsage = append(a.Certificate.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		}
	}

	// Path length for certificate chaining
	if a.Options.PathLenConstraint > 0 {
		a.Certificate.MaxPathLen = a.Options.PathLenConstraint
		a.Certificate.MaxPathLenZero = false
	} else {
		a.Certificate.MaxPathLenZero = true
	}

	// Create self-signed certificate if root is not set
	if a.RootCertificate.SerialNumber == nil || a.RootPrivateKey == nil {
		a.RootCertificate = a.Certificate
		a.RootPrivateKey = a.PrivateKey
	}

	// Build certificate
	certificateBytes, err := x509.CreateCertificate(rand.Reader, &a.Certificate, &a.RootCertificate, a.PublicKey, a.RootPrivateKey)

	if err != nil {
		panic(err)
	}

	return certificateBytes
}

// BuildCertificateRequest generates a certificate signing request
func (a *Acert) BuildCertificateRequest() []byte {
	// Require private key for request
	a.requirePrivateKey()

	// Build request template
	a.ParseSubjectAlternativeNames()
	a.Request.Subject = a.Subject
	a.Request.DNSNames = a.Certificate.DNSNames
	a.Request.IPAddresses = a.Certificate.IPAddresses
	a.Request.EmailAddresses = a.Certificate.EmailAddresses
	a.Request.URIs = a.Certificate.URIs

	// Build certificate signing request
	csr, err := x509.CreateCertificateRequest(rand.Reader, &a.Request, a.PrivateKey)

	if err != nil {
		panic(err)
	}

	return csr
}

// DecorateCertificateFromRequest populates an x509 certificate
// with values from a certificate signing request.
func (a *Acert) DecorateCertificateFromRequest() {
	a.Certificate.Subject = a.Request.Subject
	a.Certificate.Extensions = a.Request.Extensions
	a.Certificate.ExtraExtensions = a.Request.ExtraExtensions

	// SAN
	for _, value := range a.Request.DNSNames {
		a.Certificate.DNSNames = append(a.Certificate.DNSNames, value)
	}
	for _, value := range a.Request.IPAddresses {
		a.Certificate.IPAddresses = append(a.Certificate.IPAddresses, value)
	}
	for _, value := range a.Request.EmailAddresses {
		a.Certificate.EmailAddresses = append(a.Certificate.EmailAddresses, value)
	}
	for _, value := range a.Request.URIs {
		a.Certificate.URIs = append(a.Certificate.URIs, value)
	}
}

// GenerateKey builds a key with the specified algorithm.
// The number of bits can be specified for the default RSA algorithm.
//
// Valid algorithm names are
//     ed25519
//     ecdsa-p224
//     ecdsa-p256
//     ecdsa-p384
//     ecdsa-p521
//     rsa
func (a *Acert) GenerateKey(algorithm string, bits int) {
	var (
		// Parse algorithm
		kind = strings.Split(strings.ToLower(strings.TrimSpace(algorithm)), "-")

		err        error
		privateKey crypto.PrivateKey
	)

	switch kind[0] {
	case "ed25519":
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		// Get curve type
		name := ""
		if len(kind) > 1 {
			name = kind[1]
		}

		var curve elliptic.Curve

		switch name {
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

	if err != nil {
		panic(err)
	}

	a.PrivateKey = privateKey
}

// GenerateSerialNumber creates a random serial number.
// This function is used to generate serial numbers for x509 certificates.
func (a *Acert) GenerateSerialNumber() {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)

	if err != nil {
		panic(err)
	}

	a.Certificate.SerialNumber = serial
}

// ParseSanHosts takes a string array and
// returns a new x509.Certificate populated with parsed
// subject alternative name values
func (a *Acert) ParseSubjectAlternativeNames() {
	for _, value := range a.Hosts {
		if ip := net.ParseIP(value); ip != nil {
			a.Certificate.IPAddresses = append(a.Certificate.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(value); err == nil && email.Address == value {
			a.Certificate.EmailAddresses = append(a.Certificate.EmailAddresses, email.Address)
		} else if uri, err := url.Parse(value); err == nil && uri.Scheme != "" && uri.Host != "" {
			a.Certificate.URIs = append(a.Certificate.URIs, uri)
		} else {
			a.Certificate.DNSNames = append(a.Certificate.DNSNames, value)
		}
	}
}

// Require a private key to be set
func (a *Acert) requirePrivateKey() {
	if a.PrivateKey == nil {
		a.GenerateKey(a.Options.Algorithm, a.Options.Bits)
	}
}

// Verify validates a certificate root, chain and/or host names
func (a *Acert) Verify() error {
	var err error

	options := x509.VerifyOptions{}

	// Add root certificate
	if a.RootCertificate.SerialNumber != nil {
		rootPool := x509.NewCertPool()
		rootPool.AddCert(&a.RootCertificate)
		options.Roots = rootPool
	}

	// Add intermediate certificate
	if a.IntermediateCertificate.SerialNumber != nil {
		intermediatePool := x509.NewCertPool()
		intermediatePool.AddCert(&a.IntermediateCertificate)
		options.Intermediates = intermediatePool
	}

	if len(a.Hosts) > 0 {
		for _, host := range a.Hosts {
			options.DNSName = host
			_, err = a.Certificate.Verify(options)
		}
	} else {
		_, err = a.Certificate.Verify(options)
	}

	return err
}
