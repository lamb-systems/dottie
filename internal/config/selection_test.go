package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/model"
)

func TestResolveSelectionNestingAndKinds(t *testing.T) {
	paths := testPaths(t)
	paths.ConfigHome = filepath.Join(paths.Home, ".config")
	require.NoError(t, os.Mkdir(paths.ConfigHome, 0o700))
	configFile := filepath.Join(paths.ConfigHome, "settings.ini")
	require.NoError(t, os.WriteFile(configFile, []byte("x"), 0o600))

	root, err := ResolveSelection(paths, configFile)
	require.NoError(t, err)
	assert.Equal(t, Root{Base: model.RootXDGConfig, Path: "settings.ini", Kind: model.SelectionFile}, root, "config selection")

	directory := filepath.Join(paths.Home, "documents")
	require.NoError(t, os.Mkdir(directory, 0o700))

	root, err = ResolveSelection(paths, directory)
	require.NoError(t, err)
	assert.Equal(t, Root{Base: model.RootHome, Path: "documents", Kind: model.SelectionDirectory}, root, "home selection")
}

func TestResolveSelectionRejectsWholeBases(t *testing.T) {
	paths := testPaths(t)
	paths.ConfigHome = filepath.Join(t.TempDir(), "relocated-config")
	paths.StateHome = filepath.Join(t.TempDir(), "relocated-state")
	paths.CacheHome = filepath.Join(t.TempDir(), "relocated-cache")
	paths.DataHome = filepath.Join(t.TempDir(), "relocated-data")
	require.NoError(t, os.Mkdir(paths.ConfigHome, 0o700))

	for _, path := range []string{paths.Home, paths.ConfigHome} {
		_, err := ResolveSelection(paths, path)
		require.Error(t, err, "ResolveSelection(%q) accepted a whole base", path)
		assert.Contains(t, err.Error(), "whole base", "ResolveSelection(%q) error", path)
	}
}

func TestResolveSelectionRejectsOutsideAndSymlinkEscape(t *testing.T) {
	paths := testPaths(t)
	outside := filepath.Join(t.TempDir(), "outside")
	require.NoError(t, os.Mkdir(outside, 0o700))

	_, err := ResolveSelection(paths, outside)
	require.Error(t, err, "outside path accepted")

	link := filepath.Join(paths.Home, "escaped")
	require.NoError(t, os.Symlink(outside, link))

	_, err = ResolveSelection(paths, link)
	require.Error(t, err, "symlink escaping portable roots accepted")
}

func TestDeriveIDGoldenVectors(t *testing.T) {
	longAtLimit := strings.Repeat("a", 123)
	longPastLimit := strings.Repeat("a", 124)
	trimAfterTruncate := strings.Repeat("a", 122) + "/more"
	tests := []struct {
		base model.RootBase
		path string
		want string
	}{
		{model.RootHome, "---", "home"},
		{model.RootHome, "caf\u00e9", "home-caf"},
		{model.RootHome, "A//B", "home-a-b"},
		{model.RootHome, longAtLimit, "home-" + longAtLimit},
		{model.RootHome, longPastLimit, "home-" + strings.Repeat("a", 123)},
		{model.RootHome, trimAfterTruncate, "home-" + strings.Repeat("a", 122)},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, DeriveID(tt.base, tt.path), "DeriveID(%q, %q)", tt.base, tt.path)
	}
}

func TestCheckAdditionIdCollisions(t *testing.T) {
	paths := testPaths(t)
	for _, pair := range [][2]string{{"A/B", "a--b"}, {strings.Repeat("a", 123) + "x", strings.Repeat("a", 123) + "y"}} {
		id := DeriveID(model.RootHome, pair[0])
		current := Default()
		current.Targets = []Target{filesTarget(id, model.RootHome, pair[0], model.SelectionDirectory)}
		added := filesTarget(DeriveID(model.RootHome, pair[1]), model.RootHome, pair[1], model.SelectionDirectory)
		require.Equal(t, id, added.ID, "fixture ids did not collide")

		err := CheckAddition(current, paths, added)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "id", "CheckAddition collision error")
		assert.Contains(t, err.Error(), pair[0], "CheckAddition collision error")
		assert.Contains(t, err.Error(), pair[1], "CheckAddition collision error")
	}
}

func TestCheckAdditionOverlapUsesPathComponents(t *testing.T) {
	paths := testPaths(t)
	current := Default()
	current.Targets = []Target{
		filesTarget("parent-prefix", model.RootHome, "dottie", model.SelectionDirectory),
		filesTarget("short", model.RootHome, "b", model.SelectionDirectory),
	}
	for _, added := range []Target{
		filesTarget("sibling-prefix", model.RootHome, "dottie-notes", model.SelectionDirectory),
		filesTarget("longer-sibling", model.RootHome, "bc", model.SelectionDirectory),
	} {
		assert.NoError(t, CheckAddition(current, paths, added), "sibling %q incorrectly overlaps", added.Root.Path)
	}

	err := CheckAddition(current, paths, filesTarget("child", model.RootHome, "dottie/child", model.SelectionDirectory))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overlaps", "child overlap error")
}

func TestCheckAdditionRejectsContainingAndNestedDottieDirectories(t *testing.T) {
	paths := testPaths(t)
	selected := filepath.Join(paths.Home, "container")
	paths.ConfigHome = filepath.Join(selected, "config")
	paths.StateHome = filepath.Join(selected, "state")
	paths.CacheHome = filepath.Join(selected, "cache")
	paths.DataHome = filepath.Join(selected, "data")
	require.NoError(t, os.MkdirAll(selected, 0o700))

	root, err := ResolveSelection(paths, selected)
	require.NoError(t, err)
	err = CheckAddition(Default(), paths, Target{ID: "container", Source: model.SourceFiles, Root: &root})
	require.Error(t, err, "containing self-capture accepted")
	assert.Contains(t, err.Error(), "Dottie", "containing self-capture error")

	inside := filepath.Join(paths.Home, "outside-config")
	require.NoError(t, os.Mkdir(inside, 0o700))
	paths.ConfigHome = inside
	child := filepath.Join(inside, "dottie", "nested")
	require.NoError(t, os.MkdirAll(child, 0o700))

	root, err = ResolveSelection(paths, child)
	require.NoError(t, err)
	err = CheckAddition(Default(), paths, Target{ID: "nested", Source: model.SourceFiles, Root: &root})
	require.Error(t, err, "nested self-capture accepted")
	assert.Contains(t, err.Error(), "Dottie", "nested self-capture error")
}

func TestCheckAdditionSelfCaptureThroughSymlinkedXDG(t *testing.T) {
	paths := testPaths(t)
	actualConfig := filepath.Join(t.TempDir(), "actual-config")
	require.NoError(t, os.Mkdir(actualConfig, 0o700))
	linkedConfig := filepath.Join(paths.Home, ".config-link")
	require.NoError(t, os.Symlink(actualConfig, linkedConfig))
	paths.ConfigHome = linkedConfig
	selected := filepath.Join(actualConfig, "dottie", "sync")
	require.NoError(t, os.MkdirAll(selected, 0o700))

	root, err := ResolveSelection(paths, selected)
	require.NoError(t, err)
	candidate := Target{ID: "self", Source: model.SourceFiles, Root: &root}
	err = CheckAddition(Default(), paths, candidate)
	require.Error(t, err, "self-capture through a symlinked XDG base accepted")
	assert.Contains(t, err.Error(), "Dottie", "self-capture error")
}

func TestCheckAdditionFailsClosedForUnavailableStoredRoot(t *testing.T) {
	paths := testPaths(t)
	broken := filepath.Join(paths.Home, "broken")
	require.NoError(t, os.Symlink(filepath.Join(paths.Home, "missing"), broken))
	current := Default()
	current.Targets = []Target{filesTarget("offline", model.RootHome, "broken/selected", model.SelectionDirectory)}
	added := filesTarget("other", model.RootHome, "new", model.SelectionDirectory)

	err := CheckAddition(current, paths, added)
	require.Error(t, err, "unavailable existing root accepted")
	assert.Contains(t, err.Error(), "stored root", "unavailable existing root error")
}

func TestCheckAdditionRejectsLocalPolicyAndKinds(t *testing.T) {
	paths := testPaths(t)
	for _, target := range []Target{
		{ID: "whole", Source: model.SourceFiles, Root: &Root{Base: model.RootHome, Path: ".", Kind: model.SelectionDirectory}},
		{ID: "mode", Source: model.SourceFiles, Mode: "always", Root: &Root{Base: model.RootHome, Path: "x", Kind: model.SelectionDirectory}},
		{ID: "exclude", Source: model.SourceFiles, Root: &Root{Base: model.RootHome, Path: "x", Kind: model.SelectionDirectory, Exclude: []string{"/absolute"}}},
	} {
		assert.Error(t, CheckAddition(Default(), paths, target), "invalid target accepted: %#v", target)
	}
}

func TestModelConversionDoesNotCarryLocalFields(t *testing.T) {
	root := &Root{Base: model.RootHome, Path: "dotfiles", Kind: model.SelectionDirectory, Exclude: []string{"secret"}}
	target := Target{ID: "same-id", Source: model.SourceFiles, Mode: AutoApply, Root: root}

	portable, err := target.Model()
	require.NoError(t, err)
	assert.Equal(t, target.ID, portable.ID, "ID")
	assert.Equal(t, model.SourceFiles, portable.Source, "Source")
	assert.Equal(t, uint32(1), portable.SourceVersion, "SourceVersion")
	require.NotNil(t, portable.Root, "Root")
	assert.Equal(t, root.Base, portable.Root.Base, "Root.Base")
	assert.Equal(t, root.Path, portable.Root.Path, "Root.Path")
	assert.Equal(t, root.Kind, portable.Root.Kind, "Root.Kind")

	gnome, err := (Target{ID: "gnome-id", Source: model.SourceGNOME, Mode: Review}).Model()
	require.NoError(t, err)
	assert.Equal(t, "gnome-id", gnome.ID, "ID")
	assert.Equal(t, model.SourceGNOME, gnome.Source, "Source")
	assert.Nil(t, gnome.Root, "Root")
	assert.Equal(t, uint32(1), gnome.SourceVersion, "SourceVersion")
}

func TestConcurrentSaveAndLoadSupplemental(t *testing.T) {
	paths := testPaths(t)
	require.NoError(t, Save(paths, Default()))

	var group sync.WaitGroup
	for writer := 0; writer < 2; writer++ {
		group.Add(1)
		go func(writer int) {
			defer group.Done()
			for i := 0; i < 8; i++ {
				value := Default()
				value.Targets = []Target{{ID: fmt.Sprintf("writer-%d-%d", writer, i), Source: model.SourceGNOME}}
				if !assert.NoError(t, Save(paths, value), "Save") {
					return
				}
			}
		}(writer)
	}
	for i := 0; i < 8; i++ {
		_, err := Load(paths)
		assert.NoError(t, err, "Load")
	}
	group.Wait()
}
