package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	urfave "github.com/urfave/cli/v3"

	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publicationstate"
)

func runPosition(
	args []string,
	stdout, stderr io.Writer,
	env func(string) string,
	openKeyring accountKeyringFactory,
) int {
	exitCode := 0
	command := newPositionCommand(stdout, stderr, &exitCode, env, productionSessionDIDSource(openKeyring, env))
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && exitCode == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return exitCode
}

func newPositionCommand(
	stdout, stderr io.Writer,
	exitCode *int,
	env func(string) string,
	dids sessionDIDSource,
) *urfave.Command {
	configure := func(command *urfave.Command) *urfave.Command {
		command.Suggest = false
		command.DefaultCommand = ""
		command.UseShortOptionHandling = false
		command.EnableShellCompletion = false
		command.ReadArgsFromStdin = false
		command.OnUsageError = func(_ context.Context, _ *urfave.Command, err error, _ bool) error {
			return urfave.Exit("usage: "+escapeField(err.Error()), 2)
		}
		return command
	}
	status := configure(&urfave.Command{
		Name:  "status",
		Usage: "inspect the local publication position store",
		Flags: []urfave.Flag{
			&urfave.StringFlag{Name: "did", Usage: "signed-in account DID", OnlyOnce: true},
			&urfave.StringFlag{
				Name:     "vault",
				Usage:    "vault fingerprint (64 hexadecimal characters); defaults to the recorded binding",
				OnlyOnce: true,
			},
		},
		Action: func(ctx context.Context, command *urfave.Command) error {
			return runPositionStatus(ctx, command, env, dids)
		},
	})
	root := configure(&urfave.Command{
		Name:     "dottie position",
		Usage:    "inspect the local publication position store",
		Commands: []*urfave.Command{status},
		Action: func(context.Context, *urfave.Command) error {
			return usageExit("expected position status")
		},
		Writer:    stdout,
		ErrWriter: stderr,
	})
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		if exitError, ok := errors.AsType[urfave.ExitCoder](err); ok {
			code = exitError.ExitCode()
		}
		if code != 2 && code != 3 {
			code = 1
		}
		*exitCode = code
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
	}
	return root
}

func runPositionStatus(
	ctx context.Context,
	command *urfave.Command,
	env func(string) string,
	dids sessionDIDSource,
) error {
	if command.NArg() != 0 {
		return usageExit("position status takes no positional arguments")
	}
	resolved, err := resolveAccountDID(ctx, command, dids)
	if err != nil {
		return accountDIDRefusal("position status", err)
	}
	if err := writeResolvedAccount(command, resolved); err != nil {
		return err
	}
	did, err := syntax.ParseDID(command.String("did"))
	if err != nil {
		return usageExit("--did must be a valid account DID")
	}
	vault := [32]byte{}
	if command.IsSet("vault") {
		parsed, parseErr := parseVaultFingerprint(command.String("vault"))
		if parseErr != nil || parsed == [32]byte{} {
			return usageExit("--vault must be a 32-byte hexadecimal identifier")
		}
		vault = parsed
	}
	paths, err := platform.Resolve(env)
	if err != nil {
		return refused(errors.New("publication state location is unavailable"))
	}
	if vault == ([32]byte{}) {
		stored, bindingErr := publicationstate.ReadBinding(paths.PublicationStateDir())
		if bindingErr != nil {
			return refused(bindingErr)
		}
		vault = stored.Vault
	}
	binding := publicationstate.Binding{
		AccountDID: did.String(),
		Backend:    publicationstate.BackendPublicRepo,
		Repository: "at://" + did.String(),
		Vault:      vault,
	}
	inspection, err := publicationstate.Inspect(ctx, paths.PublicationStateDir(), binding)
	if err != nil {
		return refused(err)
	}
	return writeCommandOutput(command, renderInspection(inspection))
}

func renderInspection(inspection publicationstate.Inspection) string {
	if !inspection.Present {
		return "position: empty\n"
	}
	provenance := "first"
	if inspection.Floor.Provenance == publicationstate.ProvenanceReplace {
		provenance = "replace"
	}
	return fmt.Sprintf(
		"position: revision=%d generation=%d provenance=%s sequence=%d\n",
		inspection.Floor.Revision,
		inspection.Floor.Generation,
		provenance,
		inspection.Floor.Sequence,
	)
}
