package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	urfave "github.com/urfave/cli/v3"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
)

func cliEnvironment(t *testing.T) (platform.Paths, func(string) string) {
	t.Helper()
	root := t.TempDir()
	paths := platform.Paths{
		Home:       filepath.Join(root, "home"),
		ConfigHome: filepath.Join(root, "config"),
		StateHome:  filepath.Join(root, "state"),
		CacheHome:  filepath.Join(root, "cache"),
		DataHome:   filepath.Join(root, "data"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	environment := map[string]string{
		"HOME":            paths.Home,
		"XDG_CONFIG_HOME": paths.ConfigHome,
		"XDG_STATE_HOME":  paths.StateHome,
		"XDG_CACHE_HOME":  paths.CacheHome,
		"XDG_DATA_HOME":   paths.DataHome,
	}
	return paths, func(key string) string { return environment[key] }
}

func invokeTargets(env func(string) string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runTargets(args, &stdout, &stderr, env)
	return code, stdout.String(), stderr.String()
}

func TestTargetsListEmptyAndPopulatedWithoutRootProbes(t *testing.T) {
	paths, env := cliEnvironment(t)
	code, out, stderr := invokeTargets(env, "list")
	require.Equal(t, 0, code, "empty list exit code")
	assert.Equal(t, "no targets selected\n", out, "empty list output")
	assert.Empty(t, stderr, "empty list error")
	_, err := os.Lstat(paths.AppConfigDir())
	assert.True(t, os.IsNotExist(err), "list created config state: %v", err)

	current := config.Default()
	current.Targets = []config.Target{
		{ID: "offline", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "does-not-exist", Kind: model.SelectionDirectory, Exclude: []string{".git", ".git/**"}}},
		{ID: "desktop", Source: model.SourceGNOME},
		{ID: "line\nbreak", Source: model.SourceGNOME, Mode: config.BackupOnly},
	}
	require.NoError(t, config.Save(paths, current))

	code, out, stderr = invokeTargets(env, "list")
	require.Equal(t, 0, code, "populated list exit code")
	assert.Empty(t, stderr, "populated list error")
	want := "offline\treview\tfiles:home/does-not-exist\texcludes=2\n" +
		"desktop\treview\tgnome\texcludes=0\n" +
		"line\\x0Abreak\tbackup-only\tgnome\texcludes=0\n"
	assert.Equal(t, want, out, "list output")
}

func TestTargetsAddNoOverrideAndIdenticalNoOp(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "dotfiles")
	require.NoError(t, os.Mkdir(selected, 0o700))

	code, out, stderr := invokeTargets(env, "add", "--exclude", ".git", "--exclude=.git/**", selected)
	require.Equal(t, 0, code, "add exit code")
	assert.Empty(t, stderr, "add error")
	assert.True(t, strings.HasPrefix(out, "added home-dotfiles (files:home/dotfiles, mode review)\n"), "add output = %q", out)

	stored, err := config.Load(paths)
	require.NoError(t, err)
	require.Len(t, stored.Targets, 1, "stored targets")
	assert.Empty(t, stored.Targets[0].Mode, "add without --mode stored an override")
	assert.Len(t, stored.Targets[0].Root.Exclude, 2, "stored excludes")

	configPath := filepath.Join(paths.AppConfigDir(), config.FileName)
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(before), "mode ="), "add without --mode serialized an override: %s", before)

	code, out, stderr = invokeTargets(env, "add", selected)
	require.Equal(t, 0, code, "identical add exit code")
	assert.Equal(t, "already selected home-dotfiles\n", out, "identical add output")
	assert.Empty(t, stderr, "identical add error")

	after, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "identical add rewrote config")
}

func TestTargetsAddConsentDivergenceRejected(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "config-dir")
	require.NoError(t, os.Mkdir(selected, 0o700))

	code, _, stderr := invokeTargets(env, "add", "--id", "chosen", "--mode", "auto-apply", "--exclude", "private", selected)
	require.Equal(t, 0, code, "initial add exit code")
	assert.Empty(t, stderr, "initial add error")

	for _, flags := range [][]string{{"--id", "other"}, {"--mode", "review"}, {"--exclude", "different"}} {
		args := append([]string{"add"}, flags...)
		args = append(args, selected)
		code, _, stderr := invokeTargets(env, args...)
		assert.Equal(t, 1, code, "diverging add %v exit code", flags)
		assert.Contains(t, stderr, "targets mode", "diverging add %v error", flags)
	}
}

func TestTargetsRejectWholeHomeSelfCaptureAndOverlap(t *testing.T) {
	paths, env := cliEnvironment(t)
	for _, candidate := range []string{paths.Home, paths.AppConfigDir()} {
		if strings.HasSuffix(candidate, "dottie") {
			require.NoError(t, os.MkdirAll(candidate, 0o700))
		}
		code, _, stderr := invokeTargets(env, "add", candidate)
		assert.Equal(t, 1, code, "add %q exit code: %s", candidate, stderr)
	}

	parent := filepath.Join(paths.Home, "parent")
	require.NoError(t, os.MkdirAll(filepath.Join(parent, "child"), 0o700))

	code, _, stderr := invokeTargets(env, "add", parent)
	require.Equal(t, 0, code, "add parent exit code: %s", stderr)

	code, _, stderr = invokeTargets(env, "add", filepath.Join(parent, "child"))
	require.Equal(t, 1, code, "add overlapping child exit code: %s", stderr)
	assert.Contains(t, stderr, "overlaps", "add overlapping child error")
}

func TestTargetsModeInheritanceAndRemoveDoesNotDeleteFiles(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "single-file")
	require.NoError(t, os.WriteFile(selected, []byte("preserve"), 0o600))

	code, _, stderr := invokeTargets(env, "add", "--id=custom", selected)
	require.Equal(t, 0, code, "add exit code: %s", stderr)

	code, out, stderr := invokeTargets(env)
	require.Equal(t, 2, code, "targets without a subcommand exit code")
	assert.Empty(t, out, "targets without a subcommand output")
	assert.Equal(t, "dottie: usage: expected list, add, remove or mode\n", stderr, "targets without a subcommand error")

	code, out, stderr = invokeTargets(env, "mode", "custom", "backup-only")
	require.Equal(t, 0, code, "mode set exit code")
	assert.Equal(t, "mode for custom set to backup-only\n", out, "mode set output")
	assert.Empty(t, stderr, "mode set error")

	current, err := config.Load(paths)
	require.NoError(t, err)
	current.Defaults.Mode = config.AutoApply
	require.NoError(t, config.Save(paths, current))

	current, err = config.Load(paths)
	require.NoError(t, err)
	assert.Equal(t, config.BackupOnly, current.Targets[0].ModeOrDefault(current.Defaults), "mode override inherited defaults")

	code, out, stderr = invokeTargets(env, "remove", "custom")
	require.Equal(t, 0, code, "remove exit code")
	assert.Equal(t, "removed custom\n", out, "remove output")
	assert.Empty(t, stderr, "remove error")

	content, err := os.ReadFile(selected)
	require.NoError(t, err)
	assert.Equal(t, "preserve", string(content), "remove touched selected file")
}

func TestTargetsUsageErrors(t *testing.T) {
	_, env := cliEnvironment(t)
	tests := [][]string{
		{"list", "extra"},
		{"add"},
		{"add", "relative"},
		{"add", "--"},
		{"add", "--unknown", "x", "/tmp/path"},
		{"add", "--id", "/tmp/path"},
		{"add", "--id=", "/tmp/path"},
		{"add", "--mode=", "/tmp/path"},
		{"add", "--id", "x", "--id", "y", "/tmp/path"},
		{"add", "--mode", "review", "--mode", "backup-only", "/tmp/path"},
		{"add", "/tmp/path", "/tmp/extra"},
		{"remove"},
		{"remove", "x", "extra"},
		{"mode", "x"},
		{"mode", "x", "review", "extra"},
	}
	for _, args := range tests {
		code, out, stderr := invokeTargets(env, args...)
		assert.Equal(t, 2, code, "args %v exit code", args)
		assert.Empty(t, out, "args %v output", args)
		assert.Contains(t, stderr, "usage:", "args %v error", args)
	}
}

func TestTargetsAddFlagsMayFollowSelectionPath(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "after-flags")
	require.NoError(t, os.Mkdir(selected, 0o700))

	code, out, stderr := invokeTargets(env, "add", selected, "--mode", "backup-only")
	require.Equal(t, 0, code, "add with flags after path exit code: %s", stderr)
	assert.Equal(t, "added home-after-flags (files:home/after-flags, mode backup-only)\n", out, "add with flags after path output")
	assert.Empty(t, stderr, "add with flags after path error")

	stored, err := config.Load(paths)
	require.NoError(t, err)
	require.Len(t, stored.Targets, 1, "stored targets")
	assert.Equal(t, config.BackupOnly, stored.Targets[0].Mode, "mode after path was not applied")
}

func TestTargetsAddExcludeEqualsPreservesComma(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "comma-pattern")
	require.NoError(t, os.Mkdir(selected, 0o700))

	code, _, stderr := invokeTargets(env, "add", "--exclude=a,b", selected)
	require.Equal(t, 0, code, "add comma pattern exit code: %s", stderr)
	assert.Empty(t, stderr, "add comma pattern error")

	stored, err := config.Load(paths)
	require.NoError(t, err)
	require.Len(t, stored.Targets, 1, "stored targets")
	assert.Equal(t, []string{"a,b"}, stored.Targets[0].Root.Exclude, "comma pattern was split")
}

func TestTargetsRemoveHyphenatedIDAfterTerminator(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "hyphenated-id")
	require.NoError(t, os.Mkdir(selected, 0o700))

	code, _, stderr := invokeTargets(env, "add", "--id=-custom", selected)
	require.Equal(t, 0, code, "add hyphenated ID exit code: %s", stderr)
	assert.Empty(t, stderr, "add hyphenated ID error")

	code, out, stderr := invokeTargets(env, "remove", "--", "-custom")
	require.Equal(t, 0, code, "remove hyphenated ID exit code: %s", stderr)
	assert.Equal(t, "removed -custom\n", out, "remove hyphenated ID output")
	assert.Empty(t, stderr, "remove hyphenated ID error")

	stored, err := config.Load(paths)
	require.NoError(t, err)
	assert.Empty(t, stored.Targets, "hyphenated ID was not removed")
}

func TestTargetsHelpCommands(t *testing.T) {
	_, env := cliEnvironment(t)
	for _, args := range [][]string{{"list", "--help"}, {"add", "--help"}, {"remove", "--help"}, {"mode", "--help"}, {"help"}} {
		code, out, stderr := invokeTargets(env, args...)
		assert.Equal(t, 0, code, "args %v help exit code", args)
		assert.NotEmpty(t, out, "args %v help output", args)
		assert.Empty(t, stderr, "args %v help error", args)
	}
}

func TestTargetsUnknownTokenAndFlagErrorsEscapeControls(t *testing.T) {
	_, env := cliEnvironment(t)
	code, out, stderr := invokeTargets(env, "unknown\x1b")
	require.Equal(t, 2, code, "unknown targets command exit code")
	assert.Empty(t, out, "unknown targets command output")
	assert.Equal(t, "dottie: usage: expected list, add, remove or mode\n", stderr, "unknown targets command error")

	for _, args := range [][]string{{"--bad\x1b"}, {"list", "--bad\x1b"}} {
		code, out, stderr = invokeTargets(env, args...)
		assert.Equal(t, 2, code, "args %q flag error exit code", args)
		assert.Empty(t, out, "args %q flag error output", args)
		assert.NotContains(t, stderr, "\x1b", "args %q flag error contains raw terminal control", args)
		assert.True(t, strings.HasPrefix(stderr, "dottie: usage: "), "args %q flag error prefix = %q", args, stderr)
		assert.Contains(t, stderr, "flag provided but not defined", "args %q urfave error wording", args)
		assert.Equal(t, 1, strings.Count(stderr, "\n"), "args %q flag error line count", args)
	}
}

func TestTargetsRejectShellCompletionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"targets", "--generate-shell-completion"}, &stdout, &stderr)
	assert.Equal(t, 2, code, "shell completion exit code")
	assert.Empty(t, stdout.String(), "shell completion output")
	assert.True(t, strings.HasPrefix(stderr.String(), "dottie: usage: "), "shell completion error = %q", stderr.String())
	assert.Equal(t, 1, strings.Count(stderr.String(), "\n"), "shell completion error line count")
}

func TestTargetsCommandDisablesImplicitInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := 0
	root := newTargetsCommand(&stdout, &stderr, func(string) string { return "" }, &exitCode)
	assert.Same(t, &stdout, root.Writer, "root output writer")
	assert.Same(t, &stderr, root.ErrWriter, "root error writer")

	var check func(*urfave.Command)
	check = func(command *urfave.Command) {
		assert.False(t, command.Suggest, "%s suggestions", command.Name)
		assert.Empty(t, command.DefaultCommand, "%s default command", command.Name)
		assert.False(t, command.UseShortOptionHandling, "%s short option handling", command.Name)
		assert.False(t, command.EnableShellCompletion, "%s shell completion", command.Name)
		assert.False(t, command.ReadArgsFromStdin, "%s stdin args", command.Name)
		assert.NotNil(t, command.OnUsageError, "%s usage handler", command.Name)
		for _, flag := range command.Flags {
			switch typed := flag.(type) {
			case *urfave.StringFlag:
				assert.Empty(t, typed.Sources.Chain, "%s --%s sources", command.Name, typed.Name)
			case *urfave.StringSliceFlag:
				assert.Empty(t, typed.Sources.Chain, "%s --%s sources", command.Name, typed.Name)
			default:
				t.Fatalf("unexpected flag type %T on %s", flag, command.Name)
			}
		}
		for _, child := range command.Commands {
			check(child)
		}
	}
	check(root)
	add := root.Command("add")
	require.NotNil(t, add, "add command")
	assert.True(t, add.DisableSliceFlagSeparator, "add slice separator")
}

func TestTargetsAddEmptyAndRepeatedFlagsAreUsageErrors(t *testing.T) {
	_, env := cliEnvironment(t)
	for _, args := range [][]string{
		{"add", "--id=", "/tmp/path"},
		{"add", "--mode=", "/tmp/path"},
		{"add", "--id", "x", "--id", "y", "/tmp/path"},
	} {
		code, out, stderr := invokeTargets(env, args...)
		assert.Equal(t, 2, code, "args %q exit code", args)
		assert.Empty(t, out, "args %q output", args)
		assert.True(t, strings.HasPrefix(stderr, "dottie: usage: "), "args %q error = %q", args, stderr)
		assert.Equal(t, 1, strings.Count(stderr, "\n"), "args %q error line count", args)
		if len(args) > 3 {
			assert.Contains(t, stderr, "can't duplicate this flag", "repeated flag urfave wording")
		}
	}
}

func TestTargetsMapFrameworkExitCodesToUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := 0
	root := newTargetsCommand(&stdout, &stderr, func(string) string { return "" }, &exitCode)
	root.ExitErrHandler(context.Background(), root, urfave.Exit("framework failure", 3))
	assert.Equal(t, 2, exitCode, "mapped framework exit code")
	assert.Equal(t, "dottie: framework failure\n", stderr.String(), "mapped framework error output")

	stderr.Reset()
	root.ExitErrHandler(context.Background(), root, urfave.Exit("line\nbreak \\x1B", 1))
	assert.Equal(t, "dottie: line\\x0Abreak \\x1B\n", stderr.String(), "single-line error output")
	assert.Equal(t, 1, strings.Count(stderr.String(), "\n"), "error output line count")
}

func TestTargetsAddInvalidModeUsesActionableMessage(t *testing.T) {
	_, env := cliEnvironment(t)
	code, out, stderr := invokeTargets(env, "add", "--mode", "bogus", filepath.Join(t.TempDir(), "unused"))
	require.Equal(t, 1, code, "invalid add mode exit code")
	assert.Empty(t, out, "invalid add mode output")
	assert.Equal(t, "dottie: invalid mode \"bogus\"\n", stderr, "invalid add mode error")
}

func TestTargetsAddInvalidModePrecedesConfigRead(t *testing.T) {
	paths, env := cliEnvironment(t)
	require.NoError(t, os.MkdirAll(paths.AppConfigDir(), 0o700))
	broken := filepath.Join(paths.AppConfigDir(), config.FileName)
	require.NoError(t, os.WriteFile(broken, []byte("config_version = 1\nhook = \"x\"\n"), 0o600))

	code, out, stderr := invokeTargets(env, "add", "--mode", "bogus", filepath.Join(t.TempDir(), "unused"))
	require.Equal(t, 1, code, "invalid add mode exit code")
	assert.Empty(t, out, "invalid add mode output")
	assert.Equal(t, "dottie: invalid mode \"bogus\"\n", stderr, "invalid add mode error with broken config")
}

func TestTargetsConfigurationErrorsUseExitOne(t *testing.T) {
	paths, env := cliEnvironment(t)

	code, _, stderr := invokeTargets(env, "remove", "missing")
	require.Equal(t, 1, code, "unknown remove exit code")
	assert.Contains(t, stderr, "unknown target", "unknown remove error")

	code, _, stderr = invokeTargets(env, "mode", "missing", "review")
	require.Equal(t, 1, code, "unknown mode exit code")
	assert.Contains(t, stderr, "unknown target", "unknown mode error")

	code, _, stderr = invokeTargets(env, "mode", "missing", "invalid")
	require.Equal(t, 1, code, "invalid mode exit code")
	assert.Contains(t, stderr, "invalid", "invalid mode error")

	badConfig := filepath.Join(t.TempDir(), "config-file")
	require.NoError(t, os.WriteFile(badConfig, []byte("x"), 0o600))
	paths.ConfigHome = badConfig
	badEnv := func(key string) string {
		switch key {
		case "HOME":
			return paths.Home
		case "XDG_CONFIG_HOME":
			return paths.ConfigHome
		case "XDG_STATE_HOME":
			return paths.StateHome
		case "XDG_CACHE_HOME":
			return paths.CacheHome
		case "XDG_DATA_HOME":
			return paths.DataHome
		default:
			return ""
		}
	}
	code, _, stderr = invokeTargets(badEnv, "list")
	require.Equal(t, 1, code, "unwritable config path exit code")
	assert.NotEmpty(t, stderr, "unwritable config path error")
}

func TestTargetsNoPathLeakAndControlEscaping(t *testing.T) {
	paths, env := cliEnvironment(t)
	name := "name\twith\rcontrols"
	selected := filepath.Join(paths.Home, name)
	require.NoError(t, os.Mkdir(selected, 0o700))

	code, out, stderr := invokeTargets(env, "add", "--id", "id\nline", selected)
	require.Equal(t, 0, code, "escaped add exit code")
	assert.Empty(t, stderr, "escaped add error")
	assert.Contains(t, out, "id\\x0Aline", "escaped add output")
	assert.True(t, strings.HasSuffix(out, "\n"), "escaped add output missing trailing newline: %q", out)
	for index, r := range out {
		assert.False(t, unicode.IsControl(r) && !(r == '\n' && index == len(out)-1), "escaped add output contains raw control character %U: %q", r, out)
	}

	code, out, stderr = invokeTargets(env, "list")
	require.Equal(t, 0, code, "escaped list exit code")
	assert.Empty(t, stderr, "escaped list error")
	assert.NotContains(t, out, "name\twith", "escaped list leaked a raw control character")
	assert.Contains(t, out, "name\\x09with\\x0Dcontrols", "escaped list output")
	assert.Contains(t, out, "id\\x0Aline", "escaped list output")

	stored, err := config.Load(paths)
	require.NoError(t, err)
	resolved, err := stored.Targets[0].ResolvedPath(paths)
	require.NoError(t, err)
	assert.Equal(t, selected, resolved, "stored selector resolution")
}
