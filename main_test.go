package acert

import "fmt"

// Generate a private key using the ED25519 signing algorithm
func ExampleGenerateKey_ed25519() {
	GenerateKey("ed25519", 0, "")
}

// Generate a private key using the ECDSA signing algorithm
// with the P-256 elliptic curve standard
func ExampleGenerateKey_ecdsa() {
	GenerateKey("ecdsa", 0, "p256")
}

// Generate a private key using the RSA signing algorithm
// with a 2048 bit key size.
func ExampleGenerateKey_rsa() {
	GenerateKey("ed25519", 2048, "")
}

// Prompt a user for their name and print the input value.
func ExamplePromptForInput() {
	value, _ := PromptForInput("What is your name? ")
	fmt.Printf(value)
}

// Copy the contents of a file named "test.txt" into a file named "test2.txt"
// using the package's SaveFile() function.
func ExampleReadFile() {
	data := ReadFile("test.txt")
	SaveFile("test2.txt", data, 0644, false)
}

// Require a file named "test.txt" to exist in the filesystem.
func ExampleRequireFileValue() {
	file := "test.txt"
	RequireFileValue(&file, "file")
}

// Create a file named "text.txt" file and report the output to the console.
func ExampleSaveFile() {
	data := []byte("Hello, world!")
	SaveFile("test.txt", data, 0644, true)
}

// Split a string by comma.
// Empty values are not included in the result set.
func ExampleSplitValue() {
	SplitValue("one, , two, three, wowee", ",")
	// returns []string{"one", "two", "three", "wowee"}
}

// Trust a certificate authority named "example-root.ca.cert.pem".
// The script will determine the operating system and method
// used to trust the certificate.
func ExampleTrustCertificate() {
	TrustCertificate("example-root.ca.cert.pem")
}

// Trust a certificate authority named "example-root.ca.cert.pem" on macOS (Darwin)
func ExampleTrustDarwin() {
	TrustDarwin("example-root.ca.cert.pem")
}

// Trust a certificate authority named "example-root.ca.cert.pem" on Linux
func ExampleTrustLinux() {
	TrustLinux("example-root.ca.cert.pem")
}

// Trust a certificate authority named "example-root.ca.cert.pem" on Windows
func ExampleTrustWindows() {
	TrustWindows("example-root.ca.cert.pem")
}

// Verify a certificate is a child of a specified root certificate
func ExampleVerifyCertificate_root() {
	VerifyCertificate("-root", "example-root.ca.cert.pem", "example.com.cert.pem")
}

// Verify a certificate chain of a child certificate by specifying a root certificate and an intermediate certificate.
func ExampleVerifyCertificate_chain() {
	VerifyCertificate("-root", "example-root.ca.cert.pem", "-intermediate", "example-intermediate.ca.cert.pem", "example.com.cert.pem")
}

// Verify a host name is configured for a child certificate
func ExampleVerifyCertificate_host() {
	VerifyCertificate("-host", "example.com", "example.com.cert.pem")
}
