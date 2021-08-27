package main

import (
	"os"
)

func main() {
	args = os.Args[1:]

	switch getArg() {
	case "ca":
		Ca(args...)
	case "csr":
		Csr(args...)
	case "cert":
		Cert(args...)
	case "trust":
		Trust(args...)
	default:
		// Help
	}
}
