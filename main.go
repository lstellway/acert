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
		Trust(args...)
	default:
		// Help
	}
}
