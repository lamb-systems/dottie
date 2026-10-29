package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
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
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	return platform.Paths{Home: home, ConfigHome: configHome, StateHome: stateHome, CacheHome: cacheHome, DataHome: dataHome}
}

func filesTarget(id string, base model.RootBase, path string, kind model.SelectionKind) Target {
	return Target{ID: id, Source: model.SourceFiles, Root: &Root{Base: base, Path: path, Kind: kind}}
}

func writeRawConfig(t *testing.T, paths platform.Paths, text string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(paths.AppConfigDir(), 0o700))
	require.NoError(t, os.Chmod(paths.AppConfigDir(), 0o700))
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	require.NoError(t, os.WriteFile(configPath, []byte(text), 0o600))
	require.NoError(t, os.Chmod(configPath, 0o600))
}

func TestAbsentDefaultModeResolvesToReview(t *testing.T) {
	current := Config{Version: Version, Targets: []Target{filesTarget("target", model.RootHome, "dotfiles", model.SelectionDirectory)}}
	require.NoError(t, current.Validate())
	assert.Equal(t, Review, current.Targets[0].ModeOrDefault(current.Defaults), "mode without a default")
}

func TestLoadAbsentDoesNotCreateState(t *testing.T) {
	paths := testPaths(t)
	got, err := Load(paths)
	require.NoError(t, err)
	assert.Equal(t, Version, got.Version, "Version")
	assert.Equal(t, Review, got.Defaults.Mode, "Defaults.Mode")
	assert.Empty(t, got.Targets, "Targets")
	_, err = os.Lstat(paths.AppConfigDir())
	assert.ErrorIs(t, err, os.ErrNotExist, "Load created config directory")
}

func TestLoadSymlinkedRegularConfig(t *testing.T) {
	paths := testPaths(t)
	require.NoError(t, os.Mkdir(paths.AppConfigDir(), 0o700))
	target := filepath.Join(t.TempDir(), "config.toml")
	content := []byte("config_version = 1\n[defaults]\nmode = 'backup-only'\n[[targets]]\nid = 'saved'\nsource = 'files'\n[targets.root]\nbase = 'home'\npath = 'dotfiles'\nkind = 'directory'\n")
	require.NoError(t, os.WriteFile(target, content, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(paths.AppConfigDir(), FileName)))

	got, err := Load(paths)
	require.NoError(t, err)
	assert.Equal(t, Version, got.Version, "Version")
	assert.Equal(t, BackupOnly, got.Defaults.Mode, "Defaults.Mode")
	require.Len(t, got.Targets, 1, "Targets")
	assert.Equal(t, "saved", got.Targets[0].ID, "ID")
	assert.Equal(t, model.SourceFiles, got.Targets[0].Source, "Source")
	require.NotNil(t, got.Targets[0].Root, "Root")
	assert.Equal(t, model.RootHome, got.Targets[0].Root.Base, "Root.Base")
	assert.Equal(t, "dotfiles", got.Targets[0].Root.Path, "Root.Path")
	assert.Equal(t, model.SelectionDirectory, got.Targets[0].Root.Kind, "Root.Kind")
}

func TestLoadRefusesDanglingSymlink(t *testing.T) {
	paths := testPaths(t)
	require.NoError(t, os.Mkdir(paths.AppConfigDir(), 0o700))
	configPath := filepath.Join(paths.AppConfigDir(), FileName)
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "missing.toml"), configPath))

	_, err := Load(paths)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symbolic link whose target cannot be resolved", "Load dangling symlink error")
	assert.NotContains(t, err.Error(), configPath, "error leaked the config path")
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
			require.NoError(t, os.Mkdir(paths.AppConfigDir(), 0o700))
			configPath := filepath.Join(paths.AppConfigDir(), FileName)
			require.NoError(t, test.make(configPath))

			_, err := Load(paths)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.want, "Load error")
			assert.NotContains(t, err.Error(), configPath, "error leaked the config path")
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
			require.Error(t, err)
			assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.want), "Load error")
		})
	}
}

func TestSaveLoadPermissionsAndCanonicalExcludes(t *testing.T) {
	paths := testPaths(t)
	require.NoError(t, os.Mkdir(paths.AppConfigDir(), 0o755))
	require.NoError(t, os.Chmod(paths.AppConfigDir(), 0o755))

	c := Default()
	target := filesTarget("nvim", model.RootXDGConfig, "nvim", model.SelectionDirectory)
	target.Mode = AutoApply
	target.Root.Exclude = []string{".git", ".git/**", ".git"}
	c.Targets = []Target{target, {ID: "desktop", Source: model.SourceGNOME}}
	require.NoError(t, Save(paths, c))

	assert.Len(t, c.Targets[0].Root.Exclude, 3, "Save mutated the caller's excludes")

	info, err := os.Stat(paths.AppConfigDir())
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "config dir mode")

	file := filepath.Join(paths.AppConfigDir(), FileName)
	info, err = os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "config file mode")

	loaded, err := Load(paths)
	require.NoError(t, err)
	require.Len(t, loaded.Targets, 2, "round trip target count")
	assert.Equal(t, AutoApply, loaded.Targets[0].Mode, "round trip lost overrides")
	assert.Empty(t, loaded.Targets[1].Mode, "round trip invented an override")
	assert.Equal(t, []string{".git", ".git/**"}, loaded.Targets[0].Root.Exclude, "excludes")
}

func TestSaveRefusesUnsafePaths(t *testing.T) {
	t.Run("non-directory app path", func(t *testing.T) {
		paths := testPaths(t)
		require.NoError(t, os.WriteFile(paths.AppConfigDir(), []byte("x"), 0o600))

		err := Save(paths, Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "directory", "Save error")
	})

	t.Run("symlink config file", func(t *testing.T) {
		paths := testPaths(t)
		require.NoError(t, os.Mkdir(paths.AppConfigDir(), 0o700))
		victim := filepath.Join(t.TempDir(), "victim")
		original := []byte("do not replace\n")
		require.NoError(t, os.WriteFile(victim, original, 0o600))
		configPath := filepath.Join(paths.AppConfigDir(), FileName)
		require.NoError(t, os.Symlink(victim, configPath))
		linkBefore, err := os.Readlink(configPath)
		require.NoError(t, err)

		err = Save(paths, Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configuration file is a symbolic link", "Save error")
		assert.Contains(t, err.Error(), "Dottie will not replace", "Save error")
		assert.Contains(t, err.Error(), "moving the file or removing the link", "Save error")

		linkAfter, linkErr := os.Readlink(configPath)
		require.NoError(t, linkErr)
		got, readErr := os.ReadFile(victim)
		require.NoError(t, readErr)
		assert.Equal(t, linkBefore, linkAfter, "symlink target changed")
		assert.Equal(t, original, got, "symlink target content changed")
	})
}

func TestSaveCommitPointFailures(t *testing.T) {
	for _, stage := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			paths := testPaths(t)
			old := Default()
			old.Targets = []Target{filesTarget("one", model.RootHome, "old", model.SelectionDirectory)}
			require.NoError(t, Save(paths, old))
			configPath := filepath.Join(paths.AppConfigDir(), FileName)
			oldBytes, err := os.ReadFile(configPath)
			require.NoError(t, err)

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
			require.Error(t, err, "Save succeeded with injected failure")

			if stage == "directory-sync" {
				assert.Contains(t, err.Error(), "durability uncertain", "post-commit error")
				loaded, loadErr := Load(paths)
				require.NoError(t, loadErr)
				assert.Equal(t, BackupOnly, loaded.Targets[0].Mode, "new value not visible after commit")
			} else {
				got, readErr := os.ReadFile(configPath)
				require.NoError(t, readErr)
				assert.Equal(t, oldBytes, got, "pre-commit failure changed old bytes")
				loaded, loadErr := Load(paths)
				require.NoError(t, loadErr)
				assert.Empty(t, loaded.Targets[0].Mode, "old value not preserved")
			}

			entries, err := os.ReadDir(paths.AppConfigDir())
			require.NoError(t, err)
			for _, entry := range entries {
				assert.False(t, strings.HasPrefix(entry.Name(), ".config.toml.tmp-"), "temporary file remains: %s", entry.Name())
			}
		})
	}
}

func TestExcludeValidationUsesSharedMatcherDiagnostics(t *testing.T) {
	target := filesTarget("named-target", model.RootHome, "dotfiles", model.SelectionDirectory)
	target.Root.Exclude = []string{"[a-c]x"}
	current := Default()
	current.Targets = []Target{target}
	require.NoError(t, current.Validate())

	target.Root.Exclude = []string{"valid", "{a,b}"}
	current.Targets = []Target{target}
	err := current.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `target "named-target"`)
	assert.Contains(t, err.Error(), "pattern 1")
	assert.Contains(t, err.Error(), `"{a,b}"`)
}

func TestTargetModelConversion(t *testing.T) {
	files := filesTarget("portable-id", model.RootXDGConfig, "nvim", model.SelectionDirectory)
	files.Mode = AutoApply
	files.Root.Exclude = []string{".git"}

	got, err := files.Model()
	require.NoError(t, err)
	assert.Equal(t, files.ID, got.ID, "ID")
	assert.Equal(t, model.SourceFiles, got.Source, "Source")
	assert.Equal(t, uint32(1), got.SourceVersion, "SourceVersion")
	require.NotNil(t, got.Root, "Root")
	assert.Equal(t, model.RootXDGConfig, got.Root.Base, "Root.Base")
	assert.Equal(t, "nvim", got.Root.Path, "Root.Path")
	assert.Equal(t, model.SelectionDirectory, got.Root.Kind, "Root.Kind")

	gnome := Target{ID: "desktop", Source: model.SourceGNOME, Mode: BackupOnly, Root: nil}
	got, err = gnome.Model()
	require.NoError(t, err)
	assert.Equal(t, "desktop", got.ID, "ID")
	assert.Equal(t, model.SourceGNOME, got.Source, "Source")
	assert.Nil(t, got.Root, "Root")
	assert.Equal(t, uint32(1), got.SourceVersion, "SourceVersion")
}

func TestConfigBytesContainNoAbsoluteRoot(t *testing.T) {
	paths := testPaths(t)
	root := filepath.Join(paths.Home, "dotfiles")
	c := Default()
	c.Targets = []Target{filesTarget("dots", model.RootHome, "dotfiles", model.SelectionDirectory)}

	encoded, err := encodeConfig(c)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), root, "portable config leaked the absolute root")
	assert.NotContains(t, string(encoded), paths.Home, "portable config leaked the home directory")
}
