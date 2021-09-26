package main

import (
	"bufio"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

var (
	args                []string
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

// Builds path in output directory
func getOutputPath(name string) string {
	return path.Join(outputDirectory, name)
}

// Utility to build a flag set with command options
func parseFlags(name string, apply func(cmd *flag.FlagSet), flags ...string) *flag.FlagSet {
	// Create a new flag set
	flagSet := flag.NewFlagSet(name, flag.ExitOnError)

	// Callback function to modify flag set
	apply(flagSet)

	// Parse flags and update arguments
	flagSet.Parse(flags)
	args = flagSet.Args()

	return flagSet
}

// Get the next argument
func getArgument() string {
	if len(args) > 0 {
		arg := args[0]
		args = args[1:]
		return arg
	}
	return ""
}

// Checks if a file exists
func FileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// Require a string value from standard input
func RequireFileValue(value *string, name string) {
	*value = strings.TrimSpace(*value)

	if *value == "" || !FileExists(*value) {
		message := fmt.Sprintf("File for '%s' not found: %s", name, *value)
		exit(1, message)
	}
}

// Saves file
func SaveFile(name string, data []byte, permissions os.FileMode, report bool) {
	// Write to filesystem
	err := os.WriteFile(name, data, permissions)
	exitOnError(err, "Could not save file: ", name)

	if report {
		log("Saved file: ", name)
	}
}

// Split value by delimiter
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

// Prompt for user input
func PromptForInput(message string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	return reader.ReadString('\n')
}

// Force user to provide common name value
func ForceStringInput(variable *string, message string) string {
	val := ""

	for strings.TrimSpace(*variable) == "" {
		val, _ := PromptForInput(message)
		*variable = strings.TrimSpace(val)
	}

	return val
}

// Read file contents
func ReadFile(file string) []byte {
	data, err := os.ReadFile(file)
	exitOnError(err, "Could not read file: ", file)
	return data
}

// Pem encode data
func PemEncode(name string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  name,
		Bytes: data,
	})
}

// Decode pem-encoded bytes
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
			exit(1, "PEM file using ")
		}
	}

	return data.Bytes
}

// Helper to parse contents of a PEM-encoded file
func ParsePemFile(file string, types ...string) []byte {
	pem := ReadFile(file)
	return PemDecode(pem, types...)
}
