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
  dottie position status --did DID --vault HEX
  dottie push --did DID [--vault HEX] [--device-id ID] [--confirm HEX]
  dottie pull --did DID [--vault HEX] [--confirm HEX]
  dottie sync --did DID [--vault HEX] [--confirm HEX]
  dottie account login --handle HANDLE [--no-browser] [--timeout DURATION]
  dottie account status (--did DID | --handle HANDLE) [--refresh]
  dottie account logout (--did DID | --handle HANDLE) [--remote]
  dottie account bootstrap --vault-name NAME --device-id ID (--did DID | --handle HANDLE)
  dottie account finalize --vault HEX (--did DID | --handle HANDLE)

Push publishes the reconciled snapshot for selected local targets through the v2 publication profile. The first
invocation prepares one retained proposal, prints its confirmation and summary, and publishes nothing; repeat it
with --confirm HEX to publish exactly that reviewed proposal; a pre-submission failure abandons its own attempt automatically.
Pull authenticates the session and the v2 publication scope before any discovery, compares the provider's validated
position with the locally recorded accepted floor, prints one finding, and optionally applies one reviewed plan.
Sync is the reconciled path: it prints the pull apply plan, prepares the push half from the post-pull state, and
binds both into one confirmation token. The unconfirmed run changes nothing. The confirmed run applies and accepts
the pull half first, then recomposes the push candidate from the accepted floor; a changed candidate, review or
provider view refuses before anything is published. Pull refusals stop sync before any publication, and a push
refusal after a successful pull half exits 4 with the files applied and the floor advanced. For push, pull and
sync, exit codes are:
0 means committed/no-op success; 2 means usage error; 3 means refusal/conflict/rejection; exit 4 means queued,
starved, fence-lost, superseded, unavailable or another partial/non-success outcome. Push never treats a queued or
indeterminate publication as success.

Status is local-only and writes nothing: it reports each selected target with its journal item count and state.

Position status inspects the local publication position store and is read-only: it prints the accepted floor or an
empty marker, refuses an absent or unsafe store, and never prints the account DID, vault, repository, CIDs, absolute
paths, counts, tokens or payload bytes. Refusals exit 3; exit 2 is usage only.

Account login, status and logout manage the OAuth session in the desktop Secret Service keyring; they never touch
target data. Account bootstrap requires a signed-in account and a verified empty repository, mints device keys,
stores them in Secret Service, prints no secret, and records trust atomically after verified publication. Account
finalize verifies the published position with the retained device keys and records local trust when bootstrap could
not. An account can hold only one published Dottie vault because genesis requires an empty repository.

This tree has no cross-machine recovery path and no offline anchor: recovering a vault on another machine without a
live PDS is not supported, bootstrap mints no recovery kit, and nothing Dottie writes can restore data without a
surviving device key. Authenticity is repo-scoped through the account's own AT Protocol repository; Dottie adds no
vault signature over a published position. V2 publication through push, pull and sync is the supported path, and a
publication position store must already exist because bootstrap publishes the genesis vault records that the v2
publication profile rejects as a legacy record set.

See README.md for build instructions and current status.
`

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return printOutput(stdout, stderr, help)
	}
	if args[0] == "targets" {
		return runTargets(args[1:], stdout, stderr, os.Getenv)
	}
	if args[0] == "position" {
		return runPosition(args[1:], stdout, stderr, os.Getenv)
	}
	switch args[0] {
	case "status":
		return runManual(args, stdout, stderr, os.Getenv)
	case "pull":
		return runPull(args, stdout, stderr, func() (accountKeyring, error) { return platform.NewKeyring() }, os.Getenv)
	case "push":
		return runPush(args, stdout, stderr, func() (accountKeyring, error) { return platform.NewKeyring() }, os.Getenv)
	case "sync":
		return runSync(args, stdout, stderr, func() (accountKeyring, error) { return platform.NewKeyring() }, os.Getenv)
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
		switch args[0] {
		case "help", "--help", "-h", "version", "--version":
			fmt.Fprintln(stderr, "dottie: expected one command; run 'dottie help'")
		default:
			fmt.Fprintf(stderr, "dottie: unsupported command %q; run 'dottie help'\n", args[0])
		}
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
