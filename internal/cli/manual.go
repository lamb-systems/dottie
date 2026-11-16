package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/state"
)

type statusCoordinatorFactory func() (*service.Coordinator, func(), error)

func runManual(args []string, stdout, stderr io.Writer, env func(string) string) int {
	code := 0
	command := newManualCommand(stdout, stderr, &code, func() (*service.Coordinator, func(), error) {
		return productionStatusCoordinator(env)
	})
	arguments := append([]string{"dottie"}, args...)
	ctx := context.Background()
	if err := command.Run(ctx, arguments); err != nil && code == 0 {
		command.ExitErrHandler(ctx, command, err)
	}
	return code
}

func newManualCommand(stdout, stderr io.Writer, exitCode *int, factory statusCoordinatorFactory) *urfave.Command {
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
	status := configure(&urfave.Command{Name: "status", Action: func(ctx context.Context, command *urfave.Command) error {
		coordinator, closeResources, err := factory()
		if err != nil {
			return refused(err)
		}
		defer closeResources()
		result, err := coordinator.Status(ctx)
		if err != nil {
			return refused(err)
		}
		return writeCommandOutput(command, renderManualStatus(result))
	}})
	root := configure(&urfave.Command{Name: "dottie", Commands: []*urfave.Command{status}, Writer: stdout, ErrWriter: stderr})
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		var exitError urfave.ExitCoder
		if errors.As(err, &exitError) {
			code = exitError.ExitCode()
		}
		if code >= 3 && code <= 4 {
			*exitCode = code
		} else if code == 2 {
			*exitCode = 2
		} else {
			*exitCode = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
	}
	return root
}

func refused(err error) error {
	return urfave.Exit(escapeErrorMessage(err.Error()), 3)
}

func productionStatusCoordinator(env func(string) string) (*service.Coordinator, func(), error) {
	paths, err := platform.Resolve(env)
	if err != nil {
		return nil, func() {}, err
	}
	store, err := state.Open(paths)
	if err != nil {
		return nil, func() {}, err
	}
	closeStore := func() { _ = store.Close() }
	coordinator, err := service.NewCoordinator(service.Dependencies{
		Config: service.FileConfigPort{Paths: paths}, State: store, Settings: manualGNOMESettings(), Paths: paths, Clock: time.Now,
	})
	if err != nil {
		closeStore()
		return nil, func() {}, err
	}
	return coordinator, closeStore, nil
}

func renderManualStatus(status service.Status) string {
	var output strings.Builder
	for _, selection := range status.Vaults {
		fmt.Fprintf(&output, "vault\t%s\tdevice=%s\n", escapeField(hex.EncodeToString(selection.Vault[:])), escapeField(selection.DeviceID))
	}
	if len(status.Vaults) == 0 {
		output.WriteString("no vault selection recorded\n")
	}
	for _, target := range status.Targets {
		fmt.Fprintf(&output, "%s\t%s\t%s\t%s\titems=%d", escapeField(target.ID), escapeField(target.Source), escapeField(string(target.Mode)), escapeField(string(target.State)), target.Items)
		if target.Reason != "" {
			fmt.Fprintf(&output, "\treason=%s", escapeField(target.Reason))
		}
		output.WriteByte('\n')
	}
	if len(status.Targets) == 0 {
		output.WriteString("no targets selected\n")
	}
	return output.String()
}
