package main

import (
	"bufio"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	args []string
	now = time.Now()
	outputDirectory string
	workingDirectory, _ = os.Getwd()
)

// Subject alternative names object
type SanObject struct {
	EmailAddresses []string
	IPAddresses []net.IP
	URIs []*url.URL
}

// Get the next argument
func getArg() (string) {
	if len(args) > 0 {
		arg := args[0]
		args = args[1:]
		return arg
	}
	return ""
}

// Checks if a file exists
func FileExists(name string) bool {
	if _, err := os.Stat(name); err == nil {
		return true
	} else if os.IsNotExist(err) {
		fmt.Printf("File not found: (%s)\n", name)
		fmt.Println(err)
		os.Exit(1)
	} else {
		fmt.Printf("File not found: (%s)\n", name)
		fmt.Println(err)
		os.Exit(1)
	}

	return true
}

// Saves file
func SaveFile(name string, data []byte, permissions os.FileMode, report bool) {
	if err := os.WriteFile(name, data, permissions); err != nil {
		fmt.Println("Could not save file: ", name)
		os.Exit(1)
	}

	if report {
		fmt.Println("Saved file:", name)
	}
}

// Split value by delimiter
func SplitValue(value string, delimiter string) []string {
    var values []string

	for _, val := range strings.Split(value, delimiter) {
		val = strings.TrimSpace(val)
        if val != "" { values = append(values, val) }
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

// Parse IP address
func ParseIPAddress(ip string) net.IP {
	return net.ParseIP(ip)
}

// Parse URL
func ParseUri(uri string) (*url.URL, error) {
	return url.Parse(uri)
}

// Decode pem-encoded bytes
func PemDecode(bytes []byte) []byte {
	data, _ := pem.Decode(bytes)
	if data == nil {
		fmt.Println("Could not parse PEM data")
		os.Exit(1)
	}

	return data.Bytes
}

// Pem decode data
func PemDecodeFile(file string) []byte {
	// Read file contents
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("Could not read file:", file)
		os.Exit(1)
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
