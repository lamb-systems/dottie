package cli

import (
	"fmt"
	"io"
	"os"
)

const help = `Dottie — directory-first preference sync for Linux and GNOME

Usage:
  dottie help
  dottie version
  dottie targets list
  dottie targets add [--id ID] [--mode MODE] [--exclude PATTERN]... <absolute-path>
  dottie targets remove <id>
  dottie targets mode <id> <auto-apply|review|backup-only>

This is a scaffold, not a working synchronizer.
Account linking, capture, restore, encryption, and the background service
are not implemented. Target selections and consent policy are persisted locally.
Capture, apply and synchronization are not implemented.

See README.md for build instructions and current status.
`

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printOutput(stdout, stderr, help)
	}
	if args[0] == "targets" {
		return runTargets(args[1:], stdout, stderr, os.Getenv)
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "dottie: expected one command; run 'dottie help'")
		return 2
	}

	switch args[0] {
	case "help", "--help", "-h":
		return printOutput(stdout, stderr, help)
	case "version", "--version":
		return printOutput(stdout, stderr, "dottie dev (scaffold)\n")
	default:
		fmt.Fprintf(stderr, "dottie: unsupported command %q; run 'dottie help'\n", args[0])
		return 2
	}
}

func printOutput(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		fmt.Fprintln(stderr, "dottie: cannot write command output")
		return 1
	}
	return 0
}
