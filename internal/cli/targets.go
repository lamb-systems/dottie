package cli

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/dottorblaster/dottie/internal/config"
	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
)

func runTargets(args []string, stdout, stderr io.Writer, env func(string) string) int {
	if len(args) == 0 {
		return usageError(stderr, "expected list, add, remove or mode")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return usageError(stderr, "targets list takes no arguments")
		}
	case "add":
		if _, _, err := parseAddArgs(args[1:]); err != nil {
			return reportAddError(stderr, err)
		}
	case "remove":
		if len(args) != 2 || args[1] == "" || strings.HasPrefix(args[1], "--") {
			return usageError(stderr, "usage: dottie targets remove <id>")
		}
	case "mode":
		if len(args) != 3 || args[1] == "" || args[2] == "" || strings.HasPrefix(args[1], "--") || strings.HasPrefix(args[2], "--") {
			return usageError(stderr, "usage: dottie targets mode <id> <auto-apply|review|backup-only>")
		}
	default:
		return usageError(stderr, "unknown targets command")
	}
	paths, err := platform.Resolve(env)
	if err != nil {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	current, err := config.Load(paths)
	if err != nil {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	switch args[0] {
	case "list":
		return listTargets(current, stdout, stderr)
	case "add":
		return addTarget(args[1:], paths, current, stdout, stderr)
	case "remove":
		return removeTarget(args[1], paths, current, stdout, stderr)
	case "mode":
		return setTargetMode(args[1], config.Mode(args[2]), paths, current, stdout, stderr)
	}
	return usageError(stderr, "unknown targets command")
}

func listTargets(current config.Config, stdout, stderr io.Writer) int {
	if len(current.Targets) == 0 {
		return printOutput(stdout, stderr, "no targets selected\n")
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
	return printOutput(stdout, stderr, output.String())
}

func addTarget(args []string, paths platform.Paths, current config.Config, stdout, stderr io.Writer) int {
	options, path, err := parseAddArgs(args)
	if err != nil {
		return reportAddError(stderr, err)
	}
	root, err := config.ResolveSelection(paths, path)
	if err != nil {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
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
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	for _, existing := range current.Targets {
		if !sameRoot(existing.Root, target.Root) {
			continue
		}
		if (options.idSet && options.id != existing.ID) || (options.modeSet && options.mode != existing.Mode) || (len(options.excludes) > 0 && !sameStrings(uniqueStrings(options.excludes), existingExcludes(existing.Root))) {
			fmt.Fprintf(stderr, "dottie: selection already belongs to %s; use 'targets mode' or 'targets remove' to change it\n", escapeField(existing.ID))
			return 1
		}
		return printOutput(stdout, stderr, "already selected "+escapeField(existing.ID)+"\n")
	}
	if err := config.CheckAddition(current, paths, target); err != nil {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	current.Targets = append(current.Targets, target)
	if err := config.Save(paths, current); err != nil {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	selector := "files:" + string(root.Base) + "/" + root.Path
	mode := target.ModeOrDefault(current.Defaults)
	return printOutput(stdout, stderr, fmt.Sprintf("added %s (%s, mode %s)\n", escapeField(id), escapeField(selector), escapeField(string(mode))))
}

type modeError struct{ value string }

func (e modeError) Error() string {
	return "invalid mode \"" + escapeField(e.value) + "\""
}

func reportAddError(stderr io.Writer, err error) int {
	var invalidMode modeError
	if errors.As(err, &invalidMode) {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	return usageError(stderr, err.Error())
}

type addOptions struct {
	id       string
	idSet    bool
	mode     config.Mode
	modeSet  bool
	excludes []string
}

func parseAddArgs(args []string) (addOptions, string, error) {
	var options addOptions
	positionals := make([]string, 0, 1)
	optionsEnded := false
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if argument == "--" {
			return options, "", errors.New("-- is not supported")
		}
		if strings.HasPrefix(argument, "--") {
			if optionsEnded {
				return options, "", errors.New("flags must precede the selection path")
			}
			name, value, hasEqual := strings.Cut(argument, "=")
			switch name {
			case "--id", "--mode", "--exclude":
			default:
				return options, "", fmt.Errorf("unknown flag %q", escapeField(argument))
			}
			if !hasEqual {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
					return options, "", fmt.Errorf("missing value for %s", name)
				}
				i++
				value = args[i]
			}
			if value == "" {
				return options, "", fmt.Errorf("missing value for %s", name)
			}
			switch name {
			case "--id":
				if options.idSet {
					return options, "", errors.New("--id may be specified only once")
				}
				options.id, options.idSet = value, true
			case "--mode":
				if options.modeSet {
					return options, "", errors.New("--mode may be specified only once")
				}
				options.mode, options.modeSet = config.Mode(value), true
			case "--exclude":
				options.excludes = append(options.excludes, value)
			}
			continue
		}
		optionsEnded = true
		positionals = append(positionals, argument)
	}
	if options.modeSet && options.mode != config.AutoApply && options.mode != config.Review && options.mode != config.BackupOnly {
		return options, "", modeError{value: string(options.mode)}
	}
	if len(positionals) != 1 {
		return options, "", errors.New("targets add requires exactly one selection path")
	}
	if !filepath.IsAbs(positionals[0]) {
		return options, "", errors.New("selection path must be absolute")
	}
	return options, positionals[0], nil
}

func removeTarget(id string, paths platform.Paths, current config.Config, stdout, stderr io.Writer) int {
	index := -1
	for i, target := range current.Targets {
		if target.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		fmt.Fprintf(stderr, "dottie: unknown target %s\n", escapeField(id))
		return 1
	}
	current.Targets = append(current.Targets[:index], current.Targets[index+1:]...)
	if err := config.Save(paths, current); err != nil {
		fmt.Fprintf(stderr, "dottie: %v\n", err)
		return 1
	}
	return printOutput(stdout, stderr, "removed "+escapeField(id)+"\n")
}

func setTargetMode(id string, mode config.Mode, paths platform.Paths, current config.Config, stdout, stderr io.Writer) int {
	if mode != config.AutoApply && mode != config.Review && mode != config.BackupOnly {
		fmt.Fprintf(stderr, "dottie: invalid target mode %s\n", escapeField(string(mode)))
		return 1
	}
	for i := range current.Targets {
		if current.Targets[i].ID != id {
			continue
		}
		current.Targets[i].Mode = mode
		if err := config.Save(paths, current); err != nil {
			fmt.Fprintf(stderr, "dottie: %v\n", err)
			return 1
		}
		return printOutput(stdout, stderr, fmt.Sprintf("mode for %s set to %s\n", escapeField(id), escapeField(string(mode))))
	}
	fmt.Fprintf(stderr, "dottie: unknown target %s\n", escapeField(id))
	return 1
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "dottie: usage: %s\n", escapeField(message))
	return 2
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
