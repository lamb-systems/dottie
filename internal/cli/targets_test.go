package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dottorblaster/dottie/internal/config"
	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
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

	code, out, stderr := invokeTargets(env, "targets")
	require.Equal(t, 2, code, "nested target command dispatch exit code")
	assert.Empty(t, out, "nested target command dispatch output")
	assert.NotEmpty(t, stderr, "nested target command dispatch error")

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
		{"add", "--id", "x", "--id", "y", "/tmp/path"},
		{"add", "--mode", "review", "--mode", "backup-only", "/tmp/path"},
		{"add", "/tmp/path", "--mode", "review"},
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
