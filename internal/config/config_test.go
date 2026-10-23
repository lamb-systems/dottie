package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
)

func testPaths(t *testing.T) platform.Paths {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configHome := filepath.Join(root, "xdg-config")
	stateHome := filepath.Join(root, "xdg-state")
	cacheHome := filepath.Join(root, "xdg-cache")
	dataHome := filepath.Join(root, "xdg-data")
	for _, directory := range []string{home, configHome, stateHome, cacheHome, dataHome} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return platform.Paths{Home: home, ConfigHome: configHome, StateHome: stateHome, CacheHome: cacheHome, DataHome: dataHome}
}

func filesTarget(id string, base model.RootBase, path string, kind model.SelectionKind) Target {
	return Target{ID: id, Source: model.SourceFiles, Root: &Root{Base: base, Path: path, Kind: kind}}
}

func writeRawConfig(t *testing.T, paths platform.Paths, text string) {
	t.Helper()
	if err := os.MkdirAll(paths.AppConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.AppConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAbsentDefaultModeResolvesToReview(t *testing.T) {
	current := Config{Version: Version, Targets: []Target{filesTarget("target", model.RootHome, "dotfiles", model.SelectionDirectory)}}
	if err := current.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := current.Targets[0].ModeOrDefault(current.Defaults); got != Review {
		t.Fatalf("mode without a default = %q, want review", got)
	}
}

func TestLoadAbsentDoesNotCreateState(t *testing.T) {
	paths := testPaths(t)
	got, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != Version || got.Defaults.Mode != Review || len(got.Targets) != 0 {
		t.Fatalf("Load() = %#v", got)
	}
	if _, err := os.Lstat(paths.AppConfigDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load created config directory: %v", err)
	}
}

func TestLoadSymlinkedRegularConfig(t *testing.T) {
	paths := testPaths(t)
	if err := os.Mkdir(paths.AppConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "config.toml")
	content := []byte("config_version = 1\n[defaults]\nmode = 'backup-only'\n[[targets]]\nid = 'saved'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = 'dotfiles'\nkind = 'directory'\n")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(paths.AppConfigDir(), FileName)); err != nil {
		t.Fatal(err)
	}
	got, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != Version || got.Defaults.Mode != BackupOnly || len(got.Targets) != 1 || got.Targets[0].ID != "saved" || got.Targets[0].Source != model.SourceFiles || got.Targets[0].Root == nil || got.Targets[0].Root.Base != model.RootHome || got.Targets[0].Root.Path != "dotfiles" || got.Targets[0].Root.Kind != model.SelectionDirectory {
		t.Fatalf("Load through symlink = %#v", got)
	}
}

func TestLoadRefusesDanglingSymlink(t *testing.T) {
	paths := testPaths(t)
	if err := os.Mkdir(paths.AppConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing.toml"), configPath); err != nil {
		t.Fatal(err)
	}
	_, err := Load(paths)
	if err == nil || !strings.Contains(err.Error(), "symbolic link whose target cannot be resolved") || strings.Contains(err.Error(), configPath) {
		t.Fatalf("Load dangling symlink error = %v", err)
	}
}

func TestLoadRefusesDirectoryAndFIFO(t *testing.T) {
	for _, test := range []struct {
		name string
		make func(string) error
		want string
	}{
		{name: "directory", make: func(path string) error { return os.Mkdir(path, 0o700) }, want: "configuration path is a directory"},
		{name: "fifo", make: func(path string) error { return syscall.Mkfifo(path, 0o600) }, want: "configuration path is not a regular file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := testPaths(t)
			if err := os.Mkdir(paths.AppConfigDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(paths.AppConfigDir(), FileName)
			if err := test.make(configPath); err != nil {
				t.Fatal(err)
			}
			_, err := Load(paths)
			if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), configPath) {
				t.Fatalf("Load error = %v, want %q without path", err, test.want)
			}
		})
	}
}

func TestLoadClosedSchemaAndValidation(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "unknown key", text: "config_version = 1\n[[targets]]\nid='x'\nsource='files'\n[targets.root]\nbase='home'\npath='x'\nkind='directory'\nhook=true\n", want: "targets.root.hook"},
		{name: "missing version", text: "[defaults]\nmode = 'review'\n", want: "version"},
		{name: "unsupported version", text: "config_version = 2\n", want: "version"},
		{name: "wrong type", text: "config_version = 'one'\n", want: "decode"},
		{name: "duplicate id", text: "config_version = 1\n[[targets]]\nid='same'\nsource='gnome'\n[[targets]]\nid='same'\nsource='gnome'\n", want: "duplicate"},
		{name: "bad mode", text: "config_version=1\n[defaults]\nmode='prompt'\n", want: "mode"},
		{name: "bad base", text: "config_version=1\n[[targets]]\nid='x'\nsource='files'\n[targets.root]\nbase='tmp'\npath='x'\nkind='directory'\n", want: "base"},
		{name: "bad path", text: "config_version=1\n[[targets]]\nid='x'\nsource='files'\n[targets.root]\nbase='home'\npath='../x'\nkind='directory'\n", want: "path"},
		{name: "whole base", text: "config_version=1\n[[targets]]\nid='x'\nsource='files'\n[targets.root]\nbase='home'\npath='.'\nkind='directory'\n", want: "whole base"},
		{name: "bad kind", text: "config_version=1\n[[targets]]\nid='x'\nsource='files'\n[targets.root]\nbase='home'\npath='x'\nkind='socket'\n", want: "kind"},
		{name: "bad exclude", text: "config_version=1\n[[targets]]\nid='x'\nsource='files'\n[targets.root]\nbase='home'\npath='x'\nkind='directory'\nexclude=['../secret']\n", want: "exclude"},
		{name: "gnome root", text: "config_version=1\n[[targets]]\nid='x'\nsource='gnome'\n[targets.root]\nbase='home'\npath='x'\nkind='directory'\n", want: "GNOME"},
		{name: "files without root", text: "config_version=1\n[[targets]]\nid='x'\nsource='files'\n", want: "requires a root"},
		{name: "unknown source", text: "config_version=1\n[[targets]]\nid='x'\nsource='remote'\n", want: "source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := testPaths(t)
			writeRawConfig(t, paths, tt.text)
			_, err := Load(paths)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.want)) {
				t.Fatalf("Load error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestSaveLoadPermissionsAndCanonicalExcludes(t *testing.T) {
	paths := testPaths(t)
	if err := os.Mkdir(paths.AppConfigDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.AppConfigDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	c := Default()
	target := filesTarget("nvim", model.RootXDGConfig, "nvim", model.SelectionDirectory)
	target.Mode = AutoApply
	target.Root.Exclude = []string{".git", ".git/**", ".git"}
	c.Targets = []Target{target, {ID: "desktop", Source: model.SourceGNOME}}
	if err := Save(paths, c); err != nil {
		t.Fatal(err)
	}
	if len(c.Targets[0].Root.Exclude) != 3 {
		t.Fatalf("Save mutated the caller's excludes: %#v", c.Targets[0].Root.Exclude)
	}
	info, err := os.Stat(paths.AppConfigDir())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("config dir mode = %04o, want 0700", info.Mode().Perm())
	}
	file := filepath.Join(paths.AppConfigDir(), FileName)
	info, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode = %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Targets) != 2 || loaded.Targets[0].Mode != AutoApply || loaded.Targets[1].Mode != "" {
		t.Fatalf("round trip lost overrides: %#v", loaded.Targets)
	}
	if got := loaded.Targets[0].Root.Exclude; len(got) != 2 || got[0] != ".git" || got[1] != ".git/**" {
		t.Fatalf("excludes = %#v", got)
	}
}

func TestSaveRefusesUnsafePaths(t *testing.T) {
	t.Run("non-directory app path", func(t *testing.T) {
		paths := testPaths(t)
		if err := os.WriteFile(paths.AppConfigDir(), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Save(paths, Default()); err == nil || !strings.Contains(err.Error(), "directory") {
			t.Fatalf("Save error = %v", err)
		}
	})
	t.Run("symlink config file", func(t *testing.T) {
		paths := testPaths(t)
		if err := os.Mkdir(paths.AppConfigDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(t.TempDir(), "victim")
		original := []byte("do not replace\n")
		if err := os.WriteFile(victim, original, 0o600); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(paths.AppConfigDir(), FileName)
		if err := os.Symlink(victim, configPath); err != nil {
			t.Fatal(err)
		}
		linkBefore, err := os.Readlink(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := Save(paths, Default()); err == nil || !strings.Contains(err.Error(), "configuration file is a symbolic link") || !strings.Contains(err.Error(), "Dottie will not replace") || !strings.Contains(err.Error(), "moving the file or removing the link") {
			t.Fatalf("Save error = %v", err)
		}
		linkAfter, linkErr := os.Readlink(configPath)
		got, readErr := os.ReadFile(victim)
		if linkErr != nil || linkAfter != linkBefore || readErr != nil || !bytes.Equal(got, original) {
			t.Fatalf("symlink or target changed: link %q -> %q (%v), target %q (%v)", linkBefore, linkAfter, linkErr, got, readErr)
		}
	})
}

func TestSaveCommitPointFailures(t *testing.T) {
	for _, stage := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			paths := testPaths(t)
			old := Default()
			old.Targets = []Target{filesTarget("one", model.RootHome, "old", model.SelectionDirectory)}
			if err := Save(paths, old); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(paths.AppConfigDir(), FileName)
			oldBytes, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			changed := Default()
			changed.Targets = []Target{filesTarget("one", model.RootHome, "old", model.SelectionDirectory)}
			changed.Targets[0].Mode = BackupOnly
			originalRename, originalSyncFile, originalSyncDir := renameFile, syncFile, syncDir
			t.Cleanup(func() { renameFile, syncFile, syncDir = originalRename, originalSyncFile, originalSyncDir })
			switch stage {
			case "file-sync":
				syncFile = func(*os.File) error { return errors.New("injected file sync") }
			case "rename":
				renameFile = func(string, string) error { return errors.New("injected rename") }
			case "directory-sync":
				syncDir = func(string) error { return errors.New("injected directory sync") }
			}
			err = Save(paths, changed)
			if err == nil {
				t.Fatal("Save succeeded with injected failure")
			}
			if stage == "directory-sync" {
				if !strings.Contains(err.Error(), "durability uncertain") {
					t.Fatalf("post-commit error = %v", err)
				}
				loaded, loadErr := Load(paths)
				if loadErr != nil || loaded.Targets[0].Mode != BackupOnly {
					t.Fatalf("new value not visible after commit: %#v %v", loaded, loadErr)
				}
			} else {
				got, readErr := os.ReadFile(configPath)
				if readErr != nil || !bytes.Equal(got, oldBytes) {
					t.Fatalf("pre-commit failure changed old bytes: %q, %v", got, readErr)
				}
				loaded, loadErr := Load(paths)
				if loadErr != nil || loaded.Targets[0].Mode != "" {
					t.Fatalf("old value not preserved: %#v %v", loaded, loadErr)
				}
			}
			entries, err := os.ReadDir(paths.AppConfigDir())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".config.toml.tmp-") {
					t.Fatalf("temporary file remains: %s", entry.Name())
				}
			}
		})
	}
}

func TestTargetModelConversion(t *testing.T) {
	files := filesTarget("portable-id", model.RootXDGConfig, "nvim", model.SelectionDirectory)
	files.Mode = AutoApply
	files.Root.Exclude = []string{".git"}
	got, err := files.Model()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != files.ID || got.Source != model.SourceFiles || got.SourceVersion != 1 || got.Root == nil || got.Root.Base != model.RootXDGConfig || got.Root.Path != "nvim" || got.Root.Kind != model.SelectionDirectory {
		t.Fatalf("file model conversion = %#v", got)
	}
	gnome := Target{ID: "desktop", Source: model.SourceGNOME, Mode: BackupOnly, Root: nil}
	got, err = gnome.Model()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "desktop" || got.Source != model.SourceGNOME || got.Root != nil || got.SourceVersion != 1 {
		t.Fatalf("GNOME model conversion = %#v", got)
	}
}

func TestConfigBytesContainNoAbsoluteRoot(t *testing.T) {
	paths := testPaths(t)
	root := filepath.Join(paths.Home, "dotfiles")
	c := Default()
	c.Targets = []Target{filesTarget("dots", model.RootHome, "dotfiles", model.SelectionDirectory)}
	encoded, err := encodeConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), root) || strings.Contains(string(encoded), paths.Home) {
		t.Fatalf("portable config leaked an absolute path: %s", encoded)
	}
}
