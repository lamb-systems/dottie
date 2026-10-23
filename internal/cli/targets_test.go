package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

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
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
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
	if code, out, err := invokeTargets(env, "list"); code != 0 || out != "no targets selected\n" || err != "" {
		t.Fatalf("empty list = (%d, %q, %q)", code, out, err)
	}
	if _, err := os.Lstat(paths.AppConfigDir()); !os.IsNotExist(err) {
		t.Fatalf("list created config state: %v", err)
	}
	current := config.Default()
	current.Targets = []config.Target{
		{ID: "offline", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "does-not-exist", Kind: model.SelectionDirectory, Exclude: []string{".git", ".git/**"}}},
		{ID: "desktop", Source: model.SourceGNOME},
		{ID: "line\nbreak", Source: model.SourceGNOME, Mode: config.BackupOnly},
	}
	if err := config.Save(paths, current); err != nil {
		t.Fatal(err)
	}
	code, out, err := invokeTargets(env, "list")
	if code != 0 || err != "" {
		t.Fatalf("populated list = (%d, %q, %q)", code, out, err)
	}
	want := "offline\treview\tfiles:home/does-not-exist\texcludes=2\n" +
		"desktop\treview\tgnome\texcludes=0\n" +
		"line\\x0Abreak\tbackup-only\tgnome\texcludes=0\n"
	if out != want {
		t.Fatalf("list = %q, want %q", out, want)
	}
}

func TestTargetsAddNoOverrideAndIdenticalNoOp(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "dotfiles")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, stderrText := invokeTargets(env, "add", "--exclude", ".git", "--exclude=.git/**", selected)
	if code != 0 || stderrText != "" || !strings.HasPrefix(out, "added home-dotfiles (files:home/dotfiles, mode review)\n") {
		t.Fatalf("add = (%d, %q, %q)", code, out, stderrText)
	}
	stored, loadErr := config.Load(paths)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(stored.Targets) != 1 || stored.Targets[0].Mode != "" || len(stored.Targets[0].Root.Exclude) != 2 {
		t.Fatalf("stored target = %#v", stored.Targets)
	}
	configPath := filepath.Join(paths.AppConfigDir(), config.FileName)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(before), "mode =") != 1 {
		t.Fatalf("add without --mode serialized an override: %s", before)
	}
	code, out, stderrText = invokeTargets(env, "add", selected)
	if code != 0 || out != "already selected home-dotfiles\n" || stderrText != "" {
		t.Fatalf("identical add = (%d, %q, %q)", code, out, stderrText)
	}
	after, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("identical add rewrote config: %v", err)
	}
}

func TestTargetsAddConsentDivergenceRejected(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "config-dir")
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invokeTargets(env, "add", "--id", "chosen", "--mode", "auto-apply", "--exclude", "private", selected); code != 0 || stderr != "" {
		t.Fatalf("initial add: %d %q", code, stderr)
	}
	for _, flags := range [][]string{{"--id", "other"}, {"--mode", "review"}, {"--exclude", "different"}} {
		args := append([]string{"add"}, flags...)
		args = append(args, selected)
		code, _, stderr := invokeTargets(env, args...)
		if code != 1 || !strings.Contains(stderr, "targets mode") {
			t.Errorf("diverging add %v = %d %q", flags, code, stderr)
		}
	}
}

func TestTargetsRejectWholeHomeSelfCaptureAndOverlap(t *testing.T) {
	paths, env := cliEnvironment(t)
	for _, candidate := range []string{paths.Home, paths.AppConfigDir()} {
		if strings.HasSuffix(candidate, "dottie") {
			if err := os.MkdirAll(candidate, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		code, _, stderr := invokeTargets(env, "add", candidate)
		if code != 1 {
			t.Errorf("add %q returned %d: %s", candidate, code, stderr)
		}
	}
	parent := filepath.Join(paths.Home, "parent")
	if err := os.MkdirAll(filepath.Join(parent, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invokeTargets(env, "add", parent); code != 0 {
		t.Fatalf("add parent: %d %s", code, stderr)
	}
	if code, _, stderr := invokeTargets(env, "add", filepath.Join(parent, "child")); code != 1 || !strings.Contains(stderr, "overlaps") {
		t.Fatalf("add overlapping child: %d %s", code, stderr)
	}
}

func TestTargetsModeInheritanceAndRemoveDoesNotDeleteFiles(t *testing.T) {
	paths, env := cliEnvironment(t)
	selected := filepath.Join(paths.Home, "single-file")
	if err := os.WriteFile(selected, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := invokeTargets(env, "add", "--id=custom", selected); code != 0 || stderr != "" {
		t.Fatalf("add: %d %s", code, stderr)
	}
	if code, out, stderr := invokeTargets(env, "targets"); code != 2 || out != "" || stderr == "" {
		t.Fatalf("nested target command dispatch = %d %q %q", code, out, stderr)
	}
	code, out, stderr := invokeTargets(env, "mode", "custom", "backup-only")
	if code != 0 || out != "mode for custom set to backup-only\n" || stderr != "" {
		t.Fatalf("mode set = %d %q %q", code, out, stderr)
	}
	current, loadErr := config.Load(paths)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	current.Defaults.Mode = config.AutoApply
	if err := config.Save(paths, current); err != nil {
		t.Fatal(err)
	}
	current, loadErr = config.Load(paths)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if got := current.Targets[0].ModeOrDefault(current.Defaults); got != config.BackupOnly {
		t.Fatalf("mode override inherited defaults: %q", got)
	}
	code, out, stderr = invokeTargets(env, "remove", "custom")
	if code != 0 || out != "removed custom\n" || stderr != "" {
		t.Fatalf("remove = %d %q %q", code, out, stderr)
	}
	content, err := os.ReadFile(selected)
	if err != nil || string(content) != "preserve" {
		t.Fatalf("remove touched selected file: %q %v", content, err)
	}
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
		if code != 2 || out != "" || !strings.Contains(stderr, "usage:") {
			t.Errorf("args %v = (%d, %q, %q)", args, code, out, stderr)
		}
	}
}

func TestTargetsAddInvalidModeUsesActionableMessage(t *testing.T) {
	_, env := cliEnvironment(t)
	code, out, stderr := invokeTargets(env, "add", "--mode", "bogus", filepath.Join(t.TempDir(), "unused"))
	if code != 1 || out != "" || stderr != "dottie: invalid mode \"bogus\"\n" {
		t.Fatalf("invalid add mode = (%d, %q, %q)", code, out, stderr)
	}
}

func TestTargetsAddInvalidModePrecedesConfigRead(t *testing.T) {
	paths, env := cliEnvironment(t)
	if err := os.MkdirAll(paths.AppConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(paths.AppConfigDir(), config.FileName)
	if err := os.WriteFile(broken, []byte("config_version = 1\nhook = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := invokeTargets(env, "add", "--mode", "bogus", filepath.Join(t.TempDir(), "unused"))
	if code != 1 || out != "" || stderr != "dottie: invalid mode \"bogus\"\n" {
		t.Fatalf("invalid add mode with broken config = (%d, %q, %q)", code, out, stderr)
	}
}

func TestTargetsConfigurationErrorsUseExitOne(t *testing.T) {
	paths, env := cliEnvironment(t)
	if code, _, stderr := invokeTargets(env, "remove", "missing"); code != 1 || !strings.Contains(stderr, "unknown target") {
		t.Fatalf("unknown remove = %d %q", code, stderr)
	}
	if code, _, stderr := invokeTargets(env, "mode", "missing", "review"); code != 1 || !strings.Contains(stderr, "unknown target") {
		t.Fatalf("unknown mode = %d %q", code, stderr)
	}
	if code, _, stderr := invokeTargets(env, "mode", "missing", "invalid"); code != 1 || !strings.Contains(stderr, "invalid") {
		t.Fatalf("invalid mode = %d %q", code, stderr)
	}
	badConfig := filepath.Join(t.TempDir(), "config-file")
	if err := os.WriteFile(badConfig, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
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
	if code, _, stderr := invokeTargets(badEnv, "list"); code != 1 || stderr == "" {
		t.Fatalf("unwritable config path = %d %q", code, stderr)
	}
}

func TestTargetsNoPathLeakAndControlEscaping(t *testing.T) {
	paths, env := cliEnvironment(t)
	name := "name\twith\rcontrols"
	selected := filepath.Join(paths.Home, name)
	if err := os.Mkdir(selected, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := invokeTargets(env, "add", "--id", "id\nline", selected)
	if code != 0 || stderr != "" {
		t.Fatalf("escaped add output = %d %q %q", code, out, stderr)
	}
	if !strings.Contains(out, "id\\x0Aline") || !strings.HasSuffix(out, "\n") {
		t.Fatalf("escaped add output = %q, want escaped id and trailing newline", out)
	}
	for index, r := range out {
		if unicode.IsControl(r) && !(r == '\n' && index == len(out)-1) {
			t.Fatalf("escaped add output contains raw control character %U: %q", r, out)
		}
	}
	code, out, stderr = invokeTargets(env, "list")
	if code != 0 || stderr != "" || strings.Contains(out, "name\twith") || !strings.Contains(out, "name\\x09with\\x0Dcontrols") || !strings.Contains(out, "id\\x0Aline") {
		t.Fatalf("escaped list = %d %q %q", code, out, stderr)
	}
	stored, loadErr := config.Load(paths)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	resolved, resolveErr := stored.Targets[0].ResolvedPath(paths)
	if resolveErr != nil || resolved != selected {
		t.Fatalf("stored selector resolution = %q %v", resolved, resolveErr)
	}
}
