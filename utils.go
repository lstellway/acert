package main

import (
	"bufio"
	"encoding/pem"
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

// Exit program with message
func exit(code int, message ...interface{}) {
	fmt.Println(message...)
	os.Exit(code)
}

// Builds path in output directory
func getOutputPath(name string) string {
	return path.Join(outputDirectory, name)
}

// Get the next argument
func getArg() string {
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

// Require a string value
func RequireFileValue(value *string, name string) {
	*value = strings.TrimSpace(*value)

	if *value == "" || !FileExists(*value) {
		exit(1, fmt.Sprintf("File for '%s' not found: %s", name, *value))
	}
}

// Saves file
func SaveFile(name string, data []byte, permissions os.FileMode, report bool) {
	if err := os.WriteFile(name, data, permissions); err != nil {
		exit(1, "Could not save file: ", name)
	}

	if report {
		fmt.Println("Saved file: ", name)
	}
}

// Split value by delimiter
func SplitValue(value string, delimiter string) []string {
	var values []string

	// Trim whitespace
	value = strings.TrimSpace(value)

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
func ForceString(variable *string, message string) string {
	val := ""
	for strings.TrimSpace(*variable) == "" {
		val, _ := PromptForInput(message)
		*variable = strings.TrimSpace(val)
	}
	return val
}

// Decode pem-encoded bytes
func PemDecode(bytes []byte) []byte {
	data, _ := pem.Decode(bytes)
	if data == nil {
		exit(1, "Could not parse PEM data")
	}

	return data.Bytes
}

// Pem decode data
func PemDecodeFile(file string) []byte {
	// Read file contents
	data, err := os.ReadFile(file)
	if err != nil {
		exit(1, "Could not read file: ", file)
	}

	return PemDecode(data)
}

// Pem encode data
func PemEncode(name string, data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  name,
		Bytes: data,
	})
}
