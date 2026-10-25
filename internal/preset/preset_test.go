package preset

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/dottorblaster/dottie/internal/config"
	"github.com/dottorblaster/dottie/internal/model"
	"github.com/dottorblaster/dottie/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogCompilesSortsAndDeepCopies(t *testing.T) {
	catalog, err := Catalog()
	require.NoError(t, err)
	require.NotEmpty(t, catalog)
	ids := make([]string, len(catalog))
	for i, preset := range catalog {
		ids[i] = preset.ID
		require.NoError(t, validatePreset(preset))
	}
	assert.Equal(t, []string{"gnome", "kitty", "neovim", "sway"}, ids)

	neovim, err := Lookup("neovim")
	require.NoError(t, err)
	require.Len(t, neovim.Roots, 1)
	require.Len(t, neovim.Roots[0].Exclude, 2)
	require.NotEmpty(t, neovim.Notes)
	neovim.Roots[0].Path = "changed"
	neovim.Roots[0].Exclude[0] = "changed"
	neovim.Notes[0] = "changed"
	gnome, err := Lookup("gnome")
	require.NoError(t, err)
	require.NotEmpty(t, gnome.Categories)
	gnome.Categories[0] = "changed"

	freshNeovim, err := Lookup("neovim")
	require.NoError(t, err)
	assert.Equal(t, "nvim", freshNeovim.Roots[0].Path)
	assert.Equal(t, ".git", freshNeovim.Roots[0].Exclude[0])
	assert.NotEqual(t, "changed", freshNeovim.Notes[0])
	freshGNOME, err := Lookup("gnome")
	require.NoError(t, err)
	assert.Equal(t, "appearance", freshGNOME.Categories[0])
}

func TestNeovimIsExactlyOneDirectoryRoot(t *testing.T) {
	preset, err := Lookup("neovim")
	require.NoError(t, err)
	assert.Equal(t, model.SourceFiles, preset.Source)
	require.Len(t, preset.Roots, 1)
	assert.Equal(t, Root{Base: model.RootXDGConfig, Path: "nvim", Kind: model.SelectionDirectory, Exclude: []string{".git", ".git/**"}}, preset.Roots[0])
	assert.Empty(t, preset.Categories)
}

func TestLookupUnknownListsKnownIDsSorted(t *testing.T) {
	_, err := Lookup("missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnknownPreset)
	assert.Contains(t, err.Error(), "gnome, kitty, neovim, sway")
}

func TestCatalogRejectsDuplicateIDs(t *testing.T) {
	one := "schema_version=1\nid=\"same\"\nname=\"one\"\nsource=\"files\"\nrisk=\"executable-config\"\n[[roots]]\nbase=\"home\"\npath=\"one\"\nkind=\"directory\"\n"
	two := strings.ReplaceAll(one, "name=\"one\"", "name=\"two\"")
	_, err := readCatalog(fstest.MapFS{
		"data/one.toml": &fstest.MapFile{Data: []byte(one)},
		"data/two.toml": &fstest.MapFile{Data: []byte(two)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `preset "same" key "id"`)
}

func TestClosedSchemaAndPresetValidation(t *testing.T) {
	base := "schema_version=1\nid=\"sample\"\nname=\"Sample\"\nsource=\"files\"\nrisk=\"executable-config\"\n[[roots]]\nbase=\"home\"\npath=\"sample\"\nkind=\"directory\"\n"
	cases := []struct {
		name string
		text string
		key  string
	}{
		{name: "top level unknown key", text: strings.Replace(base, "[[roots]]", "command = \"run\"\n[[roots]]", 1), key: "command"},
		{name: "nested reload", text: strings.Replace(base, "kind=\"directory\"", "kind=\"directory\"\nreload = true", 1), key: "roots.reload"},
		{name: "nested command", text: strings.Replace(base, "kind=\"directory\"", "kind=\"directory\"\ncommand = \"run\"", 1), key: "roots.command"},
		{name: "nested follow", text: strings.Replace(base, "kind=\"directory\"", "kind=\"directory\"\nfollow = true", 1), key: "roots.follow"},
		{name: "unsupported schema", text: strings.Replace(base, "schema_version=1", "schema_version=2", 1), key: "schema_version"},
		{name: "unknown source", text: strings.Replace(base, "source=\"files\"", "source=\"other\"", 1), key: "source"},
		{name: "unknown risk", text: strings.Replace(base, "risk=\"executable-config\"", "risk=\"unknown\"", 1), key: "risk"},
		{name: "files without roots", text: strings.Split(base, "[[roots]]")[0], key: "roots"},
		{name: "GNOME with roots", text: strings.Replace(base, "source=\"files\"", "source=\"gnome\"", 1), key: "roots"},
		{name: "invalid exclude", text: strings.Replace(base, "kind=\"directory\"", "kind=\"directory\"\nexclude = [\"{a,b}\"]", 1), key: "exclude"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodePreset([]byte(test.text))
			require.Error(t, err)
			assert.Contains(t, err.Error(), `preset "sample"`)
			assert.Contains(t, err.Error(), test.key)
		})
	}
}

func TestBuildPreviewResolvesRelocatedXDGWithoutWrites(t *testing.T) {
	paths := testPaths(t)
	preset, err := Lookup("neovim")
	require.NoError(t, err)
	configPath := filepath.Join(paths.AppConfigDir(), config.FileName)
	rootPath := filepath.Join(paths.ConfigHome, "nvim")
	assertMissing(t, configPath)
	assertMissing(t, paths.AppConfigDir())
	assertMissing(t, rootPath)

	preview, err := BuildPreview(preset, paths)
	require.NoError(t, err)
	assert.Equal(t, []string{filepath.Join(paths.ConfigHome, "nvim")}, preview.ResolvedRoots)
	assert.Equal(t, []string{".git", ".git/**"}, preview.Excludes)
	assert.Equal(t, config.Review, preview.EffectiveMode)
	assert.Nil(t, preview.Unsupported)
	assertMissing(t, configPath)
	assertMissing(t, paths.AppConfigDir())
	assertMissing(t, rootPath)
}

func TestBuildPreviewLeavesExistingConfigUnchanged(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, "auto-apply")
	configPath := filepath.Join(paths.AppConfigDir(), config.FileName)
	before, err := os.ReadFile(configPath)
	require.NoError(t, err)
	preset, err := Lookup("neovim")
	require.NoError(t, err)
	preview, err := BuildPreview(preset, paths)
	require.NoError(t, err)
	assert.Equal(t, config.AutoApply, preview.EffectiveMode)
	after, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	assertMissing(t, filepath.Join(paths.ConfigHome, "nvim"))
}

func TestBuildPreviewReportsEffectiveMode(t *testing.T) {
	for _, test := range []struct {
		name string
		mode string
		want config.Mode
	}{
		{name: "auto-apply", mode: "auto-apply", want: config.AutoApply},
		{name: "review", mode: "review", want: config.Review},
		{name: "backup-only", mode: "backup-only", want: config.BackupOnly},
		{name: "empty default", want: config.Review},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := testPaths(t)
			writeConfig(t, paths, test.mode)
			preset, err := Lookup("neovim")
			require.NoError(t, err)
			preview, err := BuildPreview(preset, paths)
			require.NoError(t, err)
			assert.Equal(t, test.want, preview.EffectiveMode)
		})
	}
}

func TestMaterializeAddsNeovimWithoutMutatingInput(t *testing.T) {
	paths := testPaths(t)
	preset, err := Lookup("neovim")
	require.NoError(t, err)
	input := config.Default()
	input.Targets = []config.Target{{ID: "existing", Source: model.SourceFiles, Mode: config.AutoApply, Root: &config.Root{Base: model.RootHome, Path: "Documents", Kind: model.SelectionDirectory, Exclude: []string{"local"}}}}
	before := cloneConfig(input)

	result, err := Materialize(preset, input, paths)
	require.NoError(t, err)
	assert.Equal(t, before, input)
	require.Len(t, result.Targets, 2)
	added := result.Targets[1]
	assert.Equal(t, config.DeriveID(model.RootXDGConfig, "nvim"), added.ID)
	assert.Equal(t, model.SourceFiles, added.Source)
	assert.Empty(t, added.Mode)
	require.NotNil(t, added.Root)
	assert.Equal(t, []string{".git", ".git/**"}, added.Root.Exclude)
	preset.Roots[0].Exclude[0] = "changed"
	assert.Equal(t, []string{".git", ".git/**"}, added.Root.Exclude)
	assert.NoError(t, result.Validate())
}

func TestMaterializeIdenticalRootIsNoOpAndPreservesSelection(t *testing.T) {
	paths := testPaths(t)
	preset, err := Lookup("neovim")
	require.NoError(t, err)
	input := config.Default()
	input.Targets = []config.Target{{ID: "user-nvim", Source: model.SourceFiles, Mode: config.AutoApply, Root: &config.Root{Base: model.RootXDGConfig, Path: "nvim", Kind: model.SelectionDirectory, Exclude: []string{".git/**", ".git"}}}}
	before := cloneConfig(input)
	result, err := Materialize(preset, input, paths)
	require.NoError(t, err)
	assert.Equal(t, before, result)
	assert.Equal(t, "user-nvim", result.Targets[0].ID)
	assert.Equal(t, config.AutoApply, result.Targets[0].Mode)
	assert.Equal(t, []string{".git/**", ".git"}, result.Targets[0].Root.Exclude)
}

func TestMaterializeRejectsConflictingExcludesAndIDCollision(t *testing.T) {
	paths := testPaths(t)
	preset, err := Lookup("neovim")
	require.NoError(t, err)
	conflict := config.Default()
	conflict.Targets = []config.Target{{ID: "nvim", Source: model.SourceFiles, Root: &config.Root{Base: model.RootXDGConfig, Path: "nvim", Kind: model.SelectionDirectory, Exclude: []string{".git"}}}}
	_, err = Materialize(preset, conflict, paths)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConsentConflict)
	assert.Contains(t, err.Error(), "exclude")

	collision := config.Default()
	collision.Targets = []config.Target{{ID: config.DeriveID(model.RootXDGConfig, "nvim"), Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory}}}
	_, err = Materialize(preset, collision, paths)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id")
	assert.Contains(t, err.Error(), "roots[0]")
}

func TestMaterializeRejectsConfigAuthorityViolations(t *testing.T) {
	cases := []struct {
		name  string
		roots []Root
		setup func(*testing.T, platform.Paths)
	}{
		{name: "whole base", roots: []Root{{Base: model.RootHome, Path: ".", Kind: model.SelectionDirectory}}},
		{name: "overlap", roots: []Root{{Base: model.RootHome, Path: "parent", Kind: model.SelectionDirectory}, {Base: model.RootHome, Path: "parent/child", Kind: model.SelectionDirectory}}},
		{name: "self capture", roots: []Root{{Base: model.RootXDGConfig, Path: "dottie", Kind: model.SelectionDirectory}}},
		{name: "unsafe symlink root", roots: []Root{{Base: model.RootXDGConfig, Path: "linked", Kind: model.SelectionDirectory}}, setup: func(t *testing.T, paths platform.Paths) {
			t.Helper()
			state := paths.AppStateDir()
			require.NoError(t, os.MkdirAll(state, 0o700))
			require.NoError(t, os.Symlink(state, filepath.Join(paths.ConfigHome, "linked")))
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			paths := testPaths(t)
			if test.setup != nil {
				test.setup(t, paths)
			}
			preset := Preset{ID: "proposal", Name: "Proposal", Source: model.SourceFiles, Risk: "executable-config", Roots: test.roots}
			_, err := Materialize(preset, config.Default(), paths)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `preset "proposal"`)
			assert.Contains(t, err.Error(), "roots[")
		})
	}
}

func TestMaterializeProgressivelyValidatesMultipleRoots(t *testing.T) {
	paths := testPaths(t)
	preset := Preset{ID: "nested", Name: "Nested", Source: model.SourceFiles, Risk: "executable-config", Roots: []Root{
		{Base: model.RootHome, Path: "parent", Kind: model.SelectionDirectory},
		{Base: model.RootHome, Path: "parent/child", Kind: model.SelectionDirectory},
	}}
	_, err := Materialize(preset, config.Default(), paths)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overlaps")
	assert.Contains(t, err.Error(), "roots[1]")
}

func TestGNOMEPresetIsStructuredUnsupported(t *testing.T) {
	paths := testPaths(t)
	preset, err := Lookup("gnome")
	require.NoError(t, err)
	preview, err := BuildPreview(preset, paths)
	require.ErrorIs(t, err, ErrSourceNotCapturable)
	assert.Equal(t, preset.ID, preview.Preset.ID)
	require.NotNil(t, preview.Unsupported)
	var reason *UnsupportedReason
	require.ErrorAs(t, preview.Unsupported, &reason)
	assert.Equal(t, model.SourceGNOME, reason.Source)
	assert.Equal(t, "DOT-G01", reason.Boundary)
	_, err = Materialize(preset, config.Default(), paths)
	assert.ErrorIs(t, err, ErrSourceNotCapturable)
}

func TestHandBuiltPresetIsRevalidatedAtBothBoundaries(t *testing.T) {
	paths := testPaths(t)
	invalid := Preset{ID: "hand-built", Name: "Hand built", Source: model.SourceFiles, Risk: "executable-config", Roots: []Root{{Base: model.RootHome, Path: "../escape", Kind: model.SelectionDirectory}}}
	_, err := BuildPreview(invalid, paths)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `preset "hand-built"`)
	assert.Contains(t, err.Error(), "roots[0]")
	_, err = Materialize(invalid, config.Default(), paths)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `preset "hand-built"`)
	assert.Contains(t, err.Error(), "roots[0]")
}

func TestCustomRootDoesNotRequirePreset(t *testing.T) {
	paths := testPaths(t)
	custom := config.Target{ID: "my-custom-root", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "custom/preferences", Kind: model.SelectionDirectory}}
	c := config.Default()
	require.NoError(t, config.CheckAddition(c, paths, custom))
	c.Targets = append(c.Targets, custom)
	assert.NoError(t, c.Validate())
}

func TestDecodePresetErrorNamesPresetAndKey(t *testing.T) {
	text := "schema_version=1\nid=\"broken\"\nname=\"Broken\"\nsource=\"files\"\nrisk=\"unknown\"\n[[roots]]\nbase=\"home\"\npath=\"sample\"\nkind=\"directory\"\n"
	_, err := decodePreset([]byte(text))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `preset "broken" key "risk"`)
}

func testPaths(t *testing.T) platform.Paths {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configHome := filepath.Join(root, "relocated-config")
	stateHome := filepath.Join(root, "state")
	cacheHome := filepath.Join(root, "cache")
	dataHome := filepath.Join(root, "data")
	for _, path := range []string{home, configHome, stateHome, cacheHome, dataHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	return platform.Paths{Home: home, ConfigHome: configHome, StateHome: stateHome, CacheHome: cacheHome, DataHome: dataHome}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	assert.True(t, os.IsNotExist(err), "expected %q to be absent; got %v", path, err)
}

func writeConfig(t *testing.T, paths platform.Paths, mode string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(paths.AppConfigDir(), 0o700))
	content := "config_version = 1\n"
	if mode != "" {
		content += "\n[defaults]\nmode = " + strconv.Quote(mode) + "\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(paths.AppConfigDir(), config.FileName), []byte(content), 0o600))
}

func TestClonePresetIsDeep(t *testing.T) {
	original, err := Lookup("neovim")
	require.NoError(t, err)
	require.Len(t, original.Roots, 1)
	require.NotEmpty(t, original.Roots[0].Exclude)
	require.NotEmpty(t, original.Notes)

	cloned := clonePreset(original)
	cloned.Roots[0].Path = "changed"
	cloned.Roots[0].Exclude[0] = "changed"
	cloned.Notes[0] = "changed"

	require.Len(t, original.Roots, 1)
	require.Equal(t, "nvim", original.Roots[0].Path)
	require.Equal(t, ".git", original.Roots[0].Exclude[0])
	require.NotEqual(t, "changed", original.Notes[0])

	gnome, err := Lookup("gnome")
	require.NoError(t, err)
	require.NotEmpty(t, gnome.Categories)
	clonedGNOME := clonePreset(gnome)
	clonedGNOME.Categories[0] = "changed"
	require.NotEqual(t, "changed", gnome.Categories[0])
}
