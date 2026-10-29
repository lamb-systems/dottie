package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
)

func runTargets(args []string, stdout, stderr io.Writer, env func(string) string) int {
	exitCode := 0
	root := newTargetsCommand(stdout, stderr, env, &exitCode)
	arguments := append([]string{"targets"}, args...)
	ctx := context.Background()
	if err := root.Run(ctx, arguments); err != nil && exitCode == 0 {
		root.ExitErrHandler(ctx, root, err)
	}
	return exitCode
}

func newTargetsCommand(stdout, stderr io.Writer, env func(string) string, exitCode *int) *urfave.Command {
	usageHandler := func(_ context.Context, _ *urfave.Command, err error, _ bool) error {
		return urfave.Exit("usage: "+escapeField(err.Error()), 2)
	}
	commandOptions := func(command *urfave.Command) *urfave.Command {
		command.Suggest = false
		command.DefaultCommand = ""
		command.UseShortOptionHandling = false
		command.EnableShellCompletion = false
		command.ReadArgsFromStdin = false
		command.OnUsageError = usageHandler
		return command
	}

	idFlag := &urfave.StringFlag{Name: "id", Usage: "target identifier", OnlyOnce: true}
	modeFlag := &urfave.StringFlag{Name: "mode", Usage: "target consent mode", OnlyOnce: true}
	excludeFlag := &urfave.StringSliceFlag{Name: "exclude", Usage: "file exclusion pattern"}

	list := commandOptions(&urfave.Command{
		Name: "list",
		Action: func(_ context.Context, command *urfave.Command) error {
			if command.NArg() != 0 {
				return usageExit("targets list takes no arguments")
			}
			_, current, err := loadTargetsConfig(env)
			if err != nil {
				return err
			}
			return writeCommandOutput(command, listTargets(current))
		},
	})

	add := commandOptions(&urfave.Command{
		Name:                      "add",
		Flags:                     []urfave.Flag{idFlag, modeFlag, excludeFlag},
		DisableSliceFlagSeparator: true,
		Action: func(_ context.Context, command *urfave.Command) error {
			options := addOptions{
				id:       command.String("id"),
				idSet:    command.IsSet("id"),
				mode:     config.Mode(command.String("mode")),
				modeSet:  command.IsSet("mode"),
				excludes: command.StringSlice("exclude"),
			}
			if options.idSet && options.id == "" {
				return usageExit("missing value for --id")
			}
			if options.modeSet && options.mode == "" {
				return usageExit("missing value for --mode")
			}
			for _, exclude := range options.excludes {
				if exclude == "" {
					return usageExit("missing value for --exclude")
				}
			}
			if options.modeSet && !validMode(options.mode) {
				return urfave.Exit(modeError{value: string(options.mode)}.Error(), 1)
			}
			if command.NArg() != 1 {
				return usageExit("targets add requires exactly one selection path")
			}
			selectionPath := command.Args().First()
			if !filepath.IsAbs(selectionPath) {
				return usageExit("selection path must be absolute")
			}
			paths, current, err := loadTargetsConfig(env)
			if err != nil {
				return err
			}
			output, err := addTarget(options, selectionPath, paths, current)
			if err != nil {
				return err
			}
			return writeCommandOutput(command, output)
		},
	})

	remove := commandOptions(&urfave.Command{
		Name: "remove",
		Action: func(_ context.Context, command *urfave.Command) error {
			if command.NArg() != 1 || command.Args().First() == "" {
				return usageExit("usage: dottie targets remove <id>")
			}
			paths, current, err := loadTargetsConfig(env)
			if err != nil {
				return err
			}
			output, err := removeTarget(command.Args().First(), paths, current)
			if err != nil {
				return err
			}
			return writeCommandOutput(command, output)
		},
	})

	mode := commandOptions(&urfave.Command{
		Name: "mode",
		Action: func(_ context.Context, command *urfave.Command) error {
			if command.NArg() != 2 || command.Args().First() == "" || command.Args().Get(1) == "" {
				return usageExit("usage: dottie targets mode <id> <auto-apply|review|backup-only>")
			}
			paths, current, err := loadTargetsConfig(env)
			if err != nil {
				return err
			}
			output, err := setTargetMode(command.Args().First(), config.Mode(command.Args().Get(1)), paths, current)
			if err != nil {
				return err
			}
			return writeCommandOutput(command, output)
		},
	})

	root := commandOptions(&urfave.Command{
		Name:     "targets",
		Commands: []*urfave.Command{list, add, remove, mode},
		Action: func(_ context.Context, _ *urfave.Command) error {
			return usageExit("expected list, add, remove or mode")
		},
		Writer:    stdout,
		ErrWriter: stderr,
	})
	root.Writer = stdout
	root.ErrWriter = stderr
	root.ExitErrHandler = func(_ context.Context, command *urfave.Command, err error) {
		code := 1
		var exitError urfave.ExitCoder
		if errors.As(err, &exitError) {
			code = exitError.ExitCode()
		}
		if code >= 3 {
			code = 2
		}
		if code != 1 && code != 2 {
			code = 1
		}
		if message := escapeErrorMessage(err.Error()); message != "" {
			fmt.Fprintf(command.ErrWriter, "dottie: %s\n", message)
		}
		*exitCode = code
	}
	return root
}

func usageExit(message string) error {
	return urfave.Exit("usage: "+message, 2)
}

func writeCommandOutput(command *urfave.Command, output string) error {
	if _, err := io.WriteString(command.Root().Writer, output); err != nil {
		return urfave.Exit("cannot write command output", 1)
	}
	return nil
}

func loadTargetsConfig(env func(string) string) (platform.Paths, config.Config, error) {
	paths, err := platform.Resolve(env)
	if err != nil {
		return platform.Paths{}, config.Config{}, urfave.Exit(err.Error(), 1)
	}
	current, err := config.Load(paths)
	if err != nil {
		return platform.Paths{}, config.Config{}, urfave.Exit(err.Error(), 1)
	}
	return paths, current, nil
}

func listTargets(current config.Config) string {
	if len(current.Targets) == 0 {
		return "no targets selected\n"
	}
	var output strings.Builder
	for _, target := range current.Targets {
		selector := "gnome"
		count := 0
		if target.Source == model.SourceFiles && target.Root != nil {
			selector = "files:" + string(target.Root.Base)
			if target.Root.Path != "." {
				selector += "/" + target.Root.Path
			}
			count = len(target.Root.Exclude)
		}
		fmt.Fprintf(&output, "%s\t%s\t%s\texcludes=%d\n", escapeField(target.ID), escapeField(string(target.ModeOrDefault(current.Defaults))), escapeField(selector), count)
	}
	return output.String()
}

func addTarget(options addOptions, selectionPath string, paths platform.Paths, current config.Config) (string, error) {
	root, err := config.ResolveSelection(paths, selectionPath)
	if err != nil {
		return "", urfave.Exit(err.Error(), 1)
	}
	root.Exclude = append([]string(nil), options.excludes...)
	root.Exclude = uniqueStrings(root.Exclude)
	id := options.id
	if !options.idSet {
		id = config.DeriveID(root.Base, root.Path)
	}
	target := config.Target{ID: id, Source: model.SourceFiles, Root: &root}
	if options.modeSet {
		target.Mode = options.mode
	}
	if err := (config.Config{Version: config.Version, Targets: []config.Target{target}}).Validate(); err != nil {
		return "", urfave.Exit(err.Error(), 1)
	}
	for _, existing := range current.Targets {
		if !sameRoot(existing.Root, target.Root) {
			continue
		}
		if (options.idSet && options.id != existing.ID) || (options.modeSet && options.mode != existing.Mode) || (len(options.excludes) > 0 && !sameStrings(uniqueStrings(options.excludes), existingExcludes(existing.Root))) {
			return "", urfave.Exit(fmt.Sprintf("selection already belongs to %s; use 'targets mode' or 'targets remove' to change it", escapeField(existing.ID)), 1)
		}
		return "already selected " + escapeField(existing.ID) + "\n", nil
	}
	if err := config.CheckAddition(current, paths, target); err != nil {
		return "", urfave.Exit(err.Error(), 1)
	}
	current.Targets = append(current.Targets, target)
	if err := config.Save(paths, current); err != nil {
		return "", urfave.Exit(err.Error(), 1)
	}
	selector := "files:" + string(root.Base) + "/" + root.Path
	mode := target.ModeOrDefault(current.Defaults)
	return fmt.Sprintf("added %s (%s, mode %s)\n", escapeField(id), escapeField(selector), escapeField(string(mode))), nil
}

type modeError struct{ value string }

func (e modeError) Error() string {
	return "invalid mode \"" + escapeField(e.value) + "\""
}

type addOptions struct {
	id       string
	idSet    bool
	mode     config.Mode
	modeSet  bool
	excludes []string
}

func validMode(mode config.Mode) bool {
	return mode == config.AutoApply || mode == config.Review || mode == config.BackupOnly
}

func removeTarget(id string, paths platform.Paths, current config.Config) (string, error) {
	index := -1
	for i, target := range current.Targets {
		if target.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return "", urfave.Exit("unknown target "+escapeField(id), 1)
	}
	current.Targets = append(current.Targets[:index], current.Targets[index+1:]...)
	if err := config.Save(paths, current); err != nil {
		return "", urfave.Exit(err.Error(), 1)
	}
	return "removed " + escapeField(id) + "\n", nil
}

func setTargetMode(id string, mode config.Mode, paths platform.Paths, current config.Config) (string, error) {
	if !validMode(mode) {
		return "", urfave.Exit("invalid target mode "+escapeField(string(mode)), 1)
	}
	for i := range current.Targets {
		if current.Targets[i].ID != id {
			continue
		}
		current.Targets[i].Mode = mode
		if err := config.Save(paths, current); err != nil {
			return "", urfave.Exit(err.Error(), 1)
		}
		return fmt.Sprintf("mode for %s set to %s\n", escapeField(id), escapeField(string(mode))), nil
	}
	return "", urfave.Exit("unknown target "+escapeField(id), 1)
}

func escapeErrorMessage(value string) string {
	var escaped strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			fmt.Fprintf(&escaped, "\\x%02X", r)
		} else {
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}

func escapeField(value string) string {
	var escaped strings.Builder
	for _, r := range value {
		switch {
		case r == '\\':
			escaped.WriteString("\\\\")
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&escaped, "\\x%02X", r)
		default:
			escaped.WriteRune(r)
		}
	}
	return escaped.String()
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameRoot(a, b *config.Root) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Base == b.Base && a.Path == b.Path && a.Kind == b.Kind
}

func existingExcludes(root *config.Root) []string {
	if root == nil {
		return nil
	}
	return root.Exclude
}
