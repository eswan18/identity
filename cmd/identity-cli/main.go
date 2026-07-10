package main

import (
	"os"

	"github.com/eswan18/identity/cmd/identity-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
