package main

import (
	"os"

	"github.com/lamb-systems/dottie/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
