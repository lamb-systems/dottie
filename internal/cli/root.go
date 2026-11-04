package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/lamb-systems/dottie/internal/platform"
)

const help = `Dottie — directory-first preference sync for Linux and GNOME

Usage:
  dottie help
  dottie version
  dottie targets list
  dottie targets add [--id ID] [--mode MODE] [--exclude PATTERN]... <absolute-path>
  dottie targets remove <id>
  dottie targets mode <id> <auto-apply|review|backup-only>
  dottie plan --from FILE [--json]
  dottie status
  dottie history [--did DID | --handle HANDLE] [--vault HEX] [--device-id ID]
  dottie export --out FILE --kit-file FILE (--did DID | --handle HANDLE) [--vault HEX] [--anchor HEX] [--overwrite]
  dottie import --archive FILE --kit-file FILE --anchor HEX --vault HEX
  dottie pull (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]
  dottie push (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]
  dottie sync (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]
  dottie devices list (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]
  dottie devices enroll --request FILE --kit-file FILE --bundle-out FILE [--vault HEX] [--root-device-id ID] (--did DID | --handle HANDLE) [--overwrite]
  dottie devices revoke --device-id ID --kit-file FILE [--confirm HEX] [--bundle-out FILE] [--vault HEX] [--root-device-id ID] (--did DID | --handle HANDLE) [--overwrite]
  dottie preview --target ID (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]
  dottie restore --target ID [--confirm DIGEST] (--did DID | --handle HANDLE) [--vault HEX] [--device-id ID]
  dottie recover
  dottie account login --handle HANDLE [--no-browser] [--timeout DURATION]
  dottie account status (--did DID | --handle HANDLE) [--refresh]
  dottie account logout (--did DID | --handle HANDLE) [--remote]
  dottie account bootstrap --vault-name NAME --device-id ID
  dottie account enroll --vault HEX --device-id ID --role publisher|restore_only [--confirm HEX] [--request FILE]
  dottie account import-bundle --bundle FILE --anchor HEX [--vault HEX]

Push publishes the reconciled snapshot for selected local targets; sync verifies a pull, reports downloads pending
for explicit restore review, then pushes local changes. Push and sync never apply downloads or settings.
For push, sync and device operations, exit codes are: 0 means committed/no-op success; 2 means usage error; 3 means refusal/conflict/rejection; exit 4 means queued,
starved, fence-lost, superseded, unavailable or another partial/non-success outcome. Push never treats a queued or
indeterminate publication as success. History is local-only without --did/--handle; with an account selector it attempts a verified read and reports unavailable or auth-expired distinctly while still succeeding. History output is redacted and contains no content or absolute paths.
Export writes a complete ciphertext-only archive atomically through the guarded writer; an existing output requires --overwrite. Export authenticates its checkpoint with a regular owner-only kit file decoding to exactly 32 bytes; the kit is cleared and never stored or archived. Export completeness requires retained authenticated history on the exporting machine; v1 count-only attestations with nonzero recovery-point counts cannot be enumerated and refuse export. Import requires independent --vault, --anchor and kit inputs and is validation-only; it changes no state or preferences. Import validates ciphertext without decrypting content or establishing global freshness.
Device enrollment/revocation require the selected root device and a 32-byte
recovery kit in a regular, user-only-readable --kit-file (use chmod 600); the kit is never saved by Dottie. Revocation
requires a second invocation with the fingerprint-bound --confirm printed by its verified-read transcript. Bundle
outputs are public, refuse overwrite unless --overwrite is supplied, and do not contain the recovery kit. Revocation
cannot erase historical ciphertext. Import requires an independently supplied --anchor and the first pull
re-authenticates the imported chain. Restore remains explicit.

Manual read, preview, restore and recovery operations are coordinated with local state and journaled apply.
They require a locally recorded vault selection and trust checkpoint; remote apply is refused unless the
checkpoint is current or a verified descendant. Review-mode restore requires the candidate digest printed by
preview. Account bootstrap generates a fresh recovery kit and vault on every invocation; it is not idempotent.
Explicit --vault selection is required when more than one local vault is configured. Remote reads do not establish
global freshness; unverifiable state is inspection-only.

See README.md for build instructions and current status.
`

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printOutput(stdout, stderr, help)
	}
	if args[0] == "targets" {
		return runTargets(args[1:], stdout, stderr, os.Getenv)
	}
	switch args[0] {
	case "status", "history", "preview", "pull", "restore", "recover", "export", "import":
		return runManual(args, stdout, stderr, func() (accountKeyring, error) { return platform.NewKeyring() }, os.Getenv)
	case "push", "sync", "devices":
		return runOrchestration(args, stdout, stderr, func() (accountKeyring, error) { return platform.NewKeyring() }, os.Getenv)
	}
	if args[0] == "plan" {
		return runPlan(args[1:], stdout, stderr)
	}
	if args[0] == "account" {
		return runAccount(args[1:], stdout, stderr, func() (accountKeyring, error) {
			return platform.NewKeyring()
		})
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
