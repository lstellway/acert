package main

import (
	"os"
)

func main() {
	args = os.Args[1:]

	switch getArg() {
	case "ca":
		ca(args...)
	case "csr":
		csr(args...)
	case "cert":
		cert(args...)
	case "trust":
		if file := getArg(); file != "" {
			Trust(file)
		} else {
			// TODO: Show help
		}
	default:
		// Help
	}
}
