package acert

import (
	"bufio"
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
func FileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// RequireFileValue checks that a string variable contains a path
// to a file that exists on the filesystem.
func RequireFileValue(value *string, name string) {
	*value = strings.TrimSpace(*value)

	if *value == "" || !FileExists(*value) {
		message := fmt.Sprintf("File for '%s' argument not found: %s", name, *value)
		exit(1, message)
	}
}

// SaveFile saves a file to the filesystem with a specified name
// and specified permissions.
// There is an option to determine whether or not to report success.
func SaveFile(name string, data []byte, permissions os.FileMode, report bool) {
	// Write to filesystem
	err := os.WriteFile(name, data, permissions)
	exitOnError(err, "Could not save file:", name)

	if report {
		log("Saved file:", name)
	}
}

// SplitValue splits a string value by a delimiter and returns a string array with the values.
// Values are trimmed of whitespace and empty values are ignored.
func SplitValue(value string, delimiter string) []string {
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
func PromptForInput(message string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	return reader.ReadString('\n')
}

// ForceStringInput will repeatedly prompt a user for input
// until a non-empty string value is inputted.
func ForceStringInput(variable *string, message string) string {
	val := ""

	for strings.TrimSpace(*variable) == "" {
		val, _ := PromptForInput(message)
		*variable = strings.TrimSpace(val)
	}

	return val
}

// ReadFile returns the byte contents of a specified file
func ReadFile(file string) []byte {
	data, err := os.ReadFile(file)
	exitOnError(err, "Could not read file:", file)
	return data
}

// PemEncode PEM-encodes an input byte array of a specified type.
func PemEncode(name string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  name,
		Bytes: data,
	})
}

// PemDecode decodes a PEM-encoded file of a specified type.
// Multiple types can be passed, each of which is considered valid.
func PemDecode(bytes []byte, types ...string) []byte {
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
func ParsePemFile(file string, types ...string) []byte {
	pem := ReadFile(file)
	return PemDecode(pem, types...)
}
