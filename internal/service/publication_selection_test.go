package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicationSelectionCapture struct {
	calls int
}

func (capture *publicationSelectionCapture) Capture(context.Context, config.Target, string) (files.Result, error) {
	capture.calls++
	return files.Result{}, nil
}

type publicationSelectionSettings struct {
	path       string
	resolveErr error
	resolveN   int
	captureN   int
	backendN   int
}

func (settings *publicationSelectionSettings) Resolve(_ context.Context, _, _, _ string) (string, error) {
	settings.resolveN++
	return settings.path, settings.resolveErr
}

func (settings *publicationSelectionSettings) Capture(context.Context, string, []SettingRef) (SettingsCapture, error) {
	settings.captureN++
	return SettingsCapture{}, nil
}

func (settings *publicationSelectionSettings) Backend() syncengine.SettingsBackend {
	settings.backendN++
	return nil
}

type publicationSelectionFixture struct {
	paths         platform.Paths
	configuration config.Config
	target        config.Target
	local         *PublicationLocalContext
	capture       *publicationSelectionCapture
}

func newPublicationSelectionFixture(t *testing.T) publicationSelectionFixture {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	paths := platform.Paths{
		Home:       home,
		ConfigHome: filepath.Join(home, ".config"),
		StateHome:  filepath.Join(home, ".state"),
		CacheHome:  filepath.Join(home, ".cache"),
		DataHome:   filepath.Join(home, ".data"),
	}
	for _, path := range []string{paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(path, 0o700))
	}
	targetPath := filepath.Join(home, "selected")
	require.NoError(t, os.Mkdir(targetPath, 0o700))
	target := config.Target{
		ID:     "selected-files",
		Source: model.SourceFiles,
		Root:   &config.Root{Base: model.RootHome, Path: "selected", Kind: model.SelectionDirectory, Exclude: []string{".cache", "*.tmp", ".cache"}},
	}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	capture := &publicationSelectionCapture{}
	local, err := NewPublicationLocalContext(paths, capture, nil)
	require.NoError(t, err)
	return publicationSelectionFixture{paths: paths, configuration: configuration, target: target, local: local, capture: capture}
}

func publicationSelectionPortable(t *testing.T, target config.Target) model.Target {
	t.Helper()
	portable, err := target.Model()
	require.NoError(t, err)
	return portable
}

func assertPublicationSelectionError(t *testing.T, err error, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublicationReconciliation)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, "selection", classified.Stage())
	assert.Equal(t, reason, classified.Reason())
}

func TestNewPublicationLocalContextRequiresExplicitBoundedPathsAndUniqueAffinity(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	other, err := NewPublicationLocalContext(fixture.paths, nil, nil)
	require.NoError(t, err)
	assert.True(t, samePublicationContext(fixture.local, fixture.local))
	assert.False(t, samePublicationContext(fixture.local, other))
	assert.NotNil(t, fixture.local.files)
	assert.Equal(t, 0, fixture.capture.calls)
	var nilCapture *publicationSelectionCapture
	var nilSettings *publicationSelectionSettings
	typedNil, err := NewPublicationLocalContext(fixture.paths, nilCapture, nilSettings)
	require.NoError(t, err)
	_, usesDefaultCapture := typedNil.files.(LocalFilesCapture)
	assert.True(t, usesDefaultCapture)
	assert.Nil(t, typedNil.settings)
	expectedPathBytes := len(fixture.paths.Home) + len(fixture.paths.ConfigHome) + len(fixture.paths.StateHome) + len(fixture.paths.CacheHome) + len(fixture.paths.DataHome)
	assert.Equal(t, expectedPathBytes, fixture.local.pathBytes)

	invalid := []platform.Paths{
		{},
		{Home: "relative", ConfigHome: fixture.paths.ConfigHome, StateHome: fixture.paths.StateHome, CacheHome: fixture.paths.CacheHome, DataHome: fixture.paths.DataHome},
		{Home: fixture.paths.Home, ConfigHome: fixture.paths.ConfigHome, StateHome: fixture.paths.StateHome, CacheHome: fixture.paths.CacheHome},
		{Home: fixture.paths.Home + "\x00", ConfigHome: fixture.paths.ConfigHome, StateHome: fixture.paths.StateHome, CacheHome: fixture.paths.CacheHome, DataHome: fixture.paths.DataHome},
		{Home: fixture.paths.Home + string([]byte{0xff}), ConfigHome: fixture.paths.ConfigHome, StateHome: fixture.paths.StateHome, CacheHome: fixture.paths.CacheHome, DataHome: fixture.paths.DataHome},
		{Home: "/" + strings.Repeat("h", model.MaxRelativePathBytes), ConfigHome: fixture.paths.ConfigHome, StateHome: fixture.paths.StateHome, CacheHome: fixture.paths.CacheHome, DataHome: fixture.paths.DataHome},
	}
	for index, paths := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			context, contextErr := NewPublicationLocalContext(paths, nil, nil)
			assert.Nil(t, context)
			assertPublicationSelectionError(t, contextErr, string(publicationSelectionReasonInput))
		})
	}
}

func TestSelectPublicationTargetCopiesExactLocalSelectionAndLeavesConfigurationUnchanged(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	fixture.target.Mode = config.BackupOnly
	fixture.configuration.Targets = make([]config.Target, 1, 4)
	fixture.configuration.Targets[0] = fixture.target
	before := cloneSelectionTestConfig(fixture.configuration)
	originalExcludes := append([]string(nil), fixture.target.Root.Exclude...)
	portable := publicationSelectionPortable(t, fixture.target)
	selection, err := selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, fixture.target.ID, portable)
	require.NoError(t, err)
	assert.True(t, samePublicationContext(selection.context, fixture.local))
	assert.Equal(t, portable, selection.portable)
	assert.Equal(t, config.BackupOnly, selection.mode)
	assert.Equal(t, fixture.target.Root.Exclude, selection.excludes)
	assert.Equal(t, before, fixture.configuration)

	fixture.configuration.Targets[0].ID = "changed-after-selection"
	fixture.configuration.Targets[0].Root.Path = "changed"
	fixture.configuration.Targets[0].Root.Exclude[0] = "changed"
	assert.Equal(t, fixture.target.ID, selection.target.ID)
	assert.Equal(t, "selected", selection.target.Root.Path)
	assert.Equal(t, []string{".cache", "*.tmp", ".cache"}, selection.excludes)
	assert.Equal(t, originalExcludes, selection.target.Root.Exclude)
}

func TestSelectPublicationTargetUsesDefaultModeAndDoesNotMutateBackingTargetSlice(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	fixture.configuration.Targets = make([]config.Target, 1, 3)
	fixture.configuration.Targets[0] = fixture.target
	before := cloneSelectionTestConfig(fixture.configuration)
	selection, err := selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	require.NoError(t, err)
	assert.Equal(t, config.Review, selection.mode)
	assert.Equal(t, before, fixture.configuration)
	assert.Equal(t, fixture.target.ID, fixture.configuration.Targets[0].ID)
}

func TestSelectPublicationTargetRejectsZeroContextAndPortableMismatches(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	zero, err := selectPublicationTarget(context.Background(), &PublicationLocalContext{}, fixture.configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, zero)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonInput))

	tests := []struct {
		name   string
		mutate func(*model.Target)
	}{
		{name: "independent id", mutate: func(target *model.Target) { target.ID = "remote-other" }},
		{name: "source", mutate: func(target *model.Target) { target.Source = model.SourceGNOME; target.Root = nil }},
		{name: "version", mutate: func(target *model.Target) { target.SourceVersion++ }},
		{name: "base", mutate: func(target *model.Target) { target.Root.Base = model.RootXDGConfig }},
		{name: "path", mutate: func(target *model.Target) { target.Root.Path = "other" }},
		{name: "kind", mutate: func(target *model.Target) { target.Root.Kind = model.SelectionFile }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := publicationSelectionPortable(t, fixture.target)
			test.mutate(&expected)
			selection, selectErr := selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, fixture.target.ID, expected)
			assert.Equal(t, publicationSelection{}, selection)
			assertPublicationSelectionError(t, selectErr, string(publicationSelectionReasonTarget))
		})
	}
	selection, err := selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, "remote-other", publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonTarget))
}

func TestSelectPublicationTargetEnforcesConfigVersionAndCountLimits(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	configuration := fixture.configuration
	configuration.Version = 1
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonConfig))

	configuration = config.Default()
	configuration.Targets = make([]config.Target, 0, publicationSelectionMaxTargets+1)
	configuration.Targets = append(configuration.Targets, fixture.target)
	for index := 0; index < publicationSelectionMaxTargets; index++ {
		id := fmt.Sprintf("target-%03d", index)
		root := fmt.Sprintf("root-%03d", index)
		require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, root), 0o700))
		configuration.Targets = append(configuration.Targets, config.Target{ID: id, Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: root, Kind: model.SelectionDirectory}})
	}
	require.NoError(t, configuration.Validate())
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))
}

func TestSelectPublicationTargetAccepts256DistinctTargets(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	configuration := config.Default()
	configuration.Targets = make([]config.Target, 0, publicationSelectionMaxTargets)
	for index := 0; index < publicationSelectionMaxTargets; index++ {
		id := fmt.Sprintf("target-%03d", index)
		root := fmt.Sprintf("root-%03d", index)
		require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, root), 0o700))
		configuration.Targets = append(configuration.Targets, config.Target{ID: id, Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: root, Kind: model.SelectionDirectory}})
	}
	require.NoError(t, configuration.Validate())
	expected, err := configuration.Targets[0].Model()
	require.NoError(t, err)
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, "target-000", expected)
	require.NoError(t, err)
	assert.Equal(t, "target-000", selection.target.ID)
}

func TestSelectPublicationTargetBoundsAllConfigStringsExcludesAndCategories(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	configuration := fixture.configuration
	configuration.Targets = make([]config.Target, publicationSelectionMaxTargets)
	for index := range configuration.Targets {
		configuration.Targets[index] = config.Target{
			ID: fmt.Sprintf("bounded-%03d", index), Source: model.SourceFiles,
			Root: &config.Root{Base: model.RootHome, Path: fmt.Sprintf("r-%03d", index), Kind: model.SelectionDirectory,
				Exclude: []string{strings.Repeat("a", publicationSelectionMaxExcludeBytes)}},
		}
	}
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))

	configuration = cloneSelectionTestConfig(fixture.configuration)
	configuration.Targets[0].Root.Exclude = make([]string, publicationSelectionMaxExcludes)
	for index := range configuration.Targets[0].Root.Exclude {
		configuration.Targets[0].Root.Exclude[index] = fmt.Sprintf("exclude-%02d", index)
	}
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	require.NoError(t, err)
	assert.Len(t, selection.excludes, publicationSelectionMaxExcludes)

	configuration = cloneSelectionTestConfig(fixture.configuration)
	configuration.Targets[0].Root.Exclude = make([]string, publicationSelectionMaxExcludes+1)
	for index := range configuration.Targets[0].Root.Exclude {
		configuration.Targets[0].Root.Exclude[index] = "x"
	}
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))

	configuration = cloneSelectionTestConfig(fixture.configuration)
	configuration.Targets[0].Root.Exclude = make([]string, publicationSelectionMaxExcludes+1)
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))

	configuration = cloneSelectionTestConfig(fixture.configuration)
	configuration.Targets = append(configuration.Targets, config.Target{
		ID: "unselected-gnome", Source: model.SourceGNOME,
		GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalApproved, Categories: make([]string, matrix.MaxKeys+1), MatrixVersion: matrix.Version, KeyDigest: strings.Repeat("0", 64)},
	})
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))

	configuration = cloneSelectionTestConfig(fixture.configuration)
	configuration.Targets[0].Root.Exclude = []string{strings.Repeat("x", publicationSelectionMaxExcludeBytes)}
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	require.NoError(t, err)
	configuration.Targets[0].Root.Exclude[0] += "x"
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))

	configuration = cloneSelectionTestConfig(fixture.configuration)
	categories := make([]string, matrix.MaxKeys)
	for index := range categories {
		categories[index] = fmt.Sprintf("category-%03d", index)
	}
	configuration.Targets = append(configuration.Targets, config.Target{
		ID: "unselected-gnome", Source: model.SourceGNOME,
		GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalApproved, Categories: categories, MatrixVersion: matrix.Version, KeyDigest: strings.Repeat("0", 64)},
	})
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	require.NoError(t, err)
	categories = append(categories, "category-256")
	configuration.Targets[1].GNOMEPolicy.Categories = categories
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))
}

func TestSelectPublicationTargetRejectsModelFieldLimitsBeforeRootUse(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{name: "target id", mutate: func(configuration *config.Config) {
			configuration.Targets[0].ID = strings.Repeat("i", model.MaxTargetIDBytes+1)
		}},
		{name: "relative path", mutate: func(configuration *config.Config) {
			configuration.Targets[0].Root.Path = strings.Repeat("p", model.MaxRelativePathBytes+1)
		}},
		{name: "invalid utf8", mutate: func(configuration *config.Config) { configuration.Targets[0].Mode = config.Mode(string([]byte{0xff})) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			configuration := cloneSelectionTestConfig(fixture.configuration)
			test.mutate(&configuration)
			selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
			assert.Equal(t, publicationSelection{}, selection)
			assert.ErrorIs(t, err, ErrPublicationReconciliation)
		})
	}
}

func TestSelectPublicationTargetExcludesOnlySelfAndPreservesOtherRootChecks(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	siblingPath := filepath.Join(fixture.paths.Home, "selected-old")
	require.NoError(t, os.Mkdir(siblingPath, 0o700))
	sibling := config.Target{ID: "sibling", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "selected-old", Kind: model.SelectionDirectory}}
	fixture.configuration.Targets = make([]config.Target, 2, 4)
	fixture.configuration.Targets[0] = fixture.target
	fixture.configuration.Targets[1] = sibling
	before := cloneSelectionTestConfig(fixture.configuration)
	selection, err := selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	require.NoError(t, err)
	assert.Equal(t, fixture.target.ID, selection.target.ID)
	assert.Equal(t, before, fixture.configuration)

	nestedPath := filepath.Join(fixture.paths.Home, "selected", "nested")
	require.NoError(t, os.Mkdir(nestedPath, 0o700))
	fixture.configuration.Targets = append(fixture.configuration.Targets, config.Target{ID: "nested", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "selected/nested", Kind: model.SelectionDirectory}})
	selection, err = selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonRoot))
}

func TestSelectPublicationTargetRejectsProtectedAliasesAndBaseEscapes(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	protected := filepath.Join(fixture.paths.ConfigHome, "dottie")
	require.NoError(t, os.Mkdir(protected, 0o700))
	alias := filepath.Join(fixture.paths.Home, "protected-alias")
	require.NoError(t, os.Symlink(protected, alias))
	target := config.Target{ID: "protected-alias", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "protected-alias", Kind: model.SelectionDirectory}}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonRoot))

	outside := t.TempDir()
	outsideRoot := filepath.Join(outside, "outside")
	require.NoError(t, os.Mkdir(outsideRoot, 0o700))
	escape := filepath.Join(fixture.paths.Home, "escape")
	require.NoError(t, os.Symlink(outsideRoot, escape))
	target = config.Target{ID: "escape", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "escape", Kind: model.SelectionDirectory}}
	configuration.Targets = []config.Target{target}
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonRoot))

	wholeBase := filepath.Join(fixture.paths.Home, "whole-base")
	require.NoError(t, os.Symlink(fixture.paths.Home, wholeBase))
	target = config.Target{ID: "whole-base", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "whole-base", Kind: model.SelectionDirectory}}
	configuration.Targets = []config.Target{target}
	selection, err = selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonRoot))
}

func TestSelectPublicationDirectoryAnchorUsesResolvedDirectoryObject(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	actual := filepath.Join(fixture.paths.Home, "actual")
	require.NoError(t, os.Mkdir(actual, 0o700))
	alias := filepath.Join(fixture.paths.Home, "stable-alias")
	require.NoError(t, os.Symlink(actual, alias))
	target := config.Target{ID: "stable-alias", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "stable-alias", Kind: model.SelectionDirectory}}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(fixture.paths, nil, nil)
	require.NoError(t, err)
	selection, err := selectPublicationTarget(context.Background(), local, configuration, target.ID, publicationSelectionPortable(t, target))
	require.NoError(t, err)
	assert.Equal(t, actual, selection.resolvedPath)
	assert.Equal(t, actual, selection.anchorPath)
	assert.Empty(t, selection.anchorName)
	current, err := os.Stat(actual)
	require.NoError(t, err)
	assert.True(t, os.SameFile(selection.anchorInfo, current))
}

func TestSelectPublicationFileAnchorIsParentAndBasenameNotFileInode(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selectedPath := filepath.Join(fixture.paths.Home, "selected.ini")
	require.NoError(t, os.WriteFile(selectedPath, []byte("old"), 0o600))
	target := config.Target{ID: "selected-file", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "selected.ini", Kind: model.SelectionFile}}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
	require.NoError(t, err)
	assert.Equal(t, selectedPath, selection.resolvedPath)
	assert.Equal(t, fixture.paths.Home, selection.anchorPath)
	assert.Equal(t, "selected.ini", selection.anchorName)
	parentInfo, err := os.Stat(fixture.paths.Home)
	require.NoError(t, err)
	assert.True(t, os.SameFile(selection.anchorInfo, parentInfo))

	oldFile, err := os.Open(selectedPath)
	require.NoError(t, err)
	defer func() { assert.NoError(t, oldFile.Close()) }()
	oldInfo, err := oldFile.Stat()
	require.NoError(t, err)
	replacement := filepath.Join(fixture.paths.Home, "replacement")
	require.NoError(t, os.WriteFile(replacement, []byte("new"), 0o600))
	replacementInfo, err := os.Stat(replacement)
	require.NoError(t, err)
	require.NoError(t, os.Rename(replacement, selectedPath))
	newInfo, err := os.Stat(selectedPath)
	require.NoError(t, err)
	assert.False(t, os.SameFile(oldInfo, newInfo))
	assert.True(t, os.SameFile(replacementInfo, newInfo))
	parentAfter, err := os.Stat(fixture.paths.Home)
	require.NoError(t, err)
	assert.True(t, os.SameFile(selection.anchorInfo, parentAfter))

	reselected, err := selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
	require.NoError(t, err)
	assert.Equal(t, selection.anchorPath, reselected.anchorPath)
	assert.Equal(t, filepath.Base(selectedPath), reselected.anchorName)
	assert.True(t, os.SameFile(selection.anchorInfo, reselected.anchorInfo))
}

func TestSelectPublicationFileAnchorResolvesContainedSymlinkedParent(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	actualParent := filepath.Join(fixture.paths.Home, "actual-parent")
	require.NoError(t, os.Mkdir(actualParent, 0o700))
	selectedName := "settings.ini"
	actualFile := filepath.Join(actualParent, selectedName)
	require.NoError(t, os.WriteFile(actualFile, []byte("synthetic"), 0o600))
	parentAlias := filepath.Join(fixture.paths.Home, "parent-alias")
	require.NoError(t, os.Symlink(actualParent, parentAlias))
	target := config.Target{ID: "aliased-parent-file", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "parent-alias/" + selectedName, Kind: model.SelectionFile}}
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
	require.NoError(t, err)
	assert.Equal(t, actualFile, selection.resolvedPath)
	assert.Equal(t, actualParent, selection.anchorPath)
	assert.Equal(t, selectedName, selection.anchorName)
	parentInfo, err := os.Stat(actualParent)
	require.NoError(t, err)
	assert.True(t, os.SameFile(selection.anchorInfo, parentInfo))
}

func TestSelectPublicationTargetRejectsMissingWrongKindAndFinalFileSymlink(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	cases := []struct {
		name string
		path string
		kind model.SelectionKind
	}{
		{name: "missing", path: "missing", kind: model.SelectionDirectory},
		{name: "wrong kind", path: "selected", kind: model.SelectionFile},
		{name: "final file symlink", path: "selected-link", kind: model.SelectionFile},
	}
	file := filepath.Join(fixture.paths.Home, "file-target")
	require.NoError(t, os.WriteFile(file, []byte("value"), 0o600))
	link := filepath.Join(fixture.paths.Home, "selected-link")
	require.NoError(t, os.Symlink(file, link))
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			target := config.Target{ID: "candidate", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: test.path, Kind: test.kind}}
			configuration := config.Default()
			configuration.Targets = []config.Target{target}
			selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, publicationSelectionPortable(t, target))
			assert.Equal(t, publicationSelection{}, selection)
			assertPublicationSelectionError(t, err, string(publicationSelectionReasonRoot))
		})
	}
}

func newApprovedPublicationGNOMETarget(t *testing.T, id string, categories []string) config.Target {
	t.Helper()
	keys, err := matrix.SelectCategories(categories)
	require.NoError(t, err)
	digest, err := matrix.KeySetDigest(keys)
	require.NoError(t, err)
	return config.Target{ID: id, Source: model.SourceGNOME, GNOMEPolicy: &config.GNOMEPolicy{
		Approval: config.GNOMEApprovalApproved, Categories: append([]string(nil), categories...), MatrixVersion: matrix.Version, KeyDigest: fmt.Sprintf("%x", digest),
	}}
}

func TestSelectPublicationGNOMEUsesOnlyResolvedApprovedRefsAndContextAffinity(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	settings := &publicationSelectionSettings{path: "/synthetic/"}
	local, err := NewPublicationLocalContext(fixture.paths, fixture.capture, settings)
	require.NoError(t, err)
	target := newApprovedPublicationGNOMETarget(t, "desktop", []string{"fonts", "clock"})
	expectedCategories := append([]string(nil), target.GNOMEPolicy.Categories...)
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	selection, err := selectPublicationTarget(context.Background(), local, configuration, target.ID, model.Target{ID: target.ID, Source: model.SourceGNOME, SourceVersion: model.SourceVersion})
	require.NoError(t, err)
	keys, err := matrix.SelectCategories(target.GNOMEPolicy.Categories)
	require.NoError(t, err)
	assert.Len(t, selection.settingRefs, len(keys))
	assert.Equal(t, len(keys), settings.resolveN)
	assert.Equal(t, 0, settings.captureN)
	assert.Equal(t, 0, settings.backendN)
	assert.Equal(t, 0, fixture.capture.calls)
	for index := 1; index < len(selection.settingRefs); index++ {
		assert.True(t, settingRefLess(selection.settingRefs[index-1], selection.settingRefs[index]))
	}
	assert.Equal(t, target.GNOMEPolicy, selection.target.GNOMEPolicy)

	secondLocal, err := NewPublicationLocalContext(fixture.paths, fixture.capture, settings)
	require.NoError(t, err)
	assert.False(t, samePublicationContext(local, secondLocal))
	expectedRefs := make([]SettingRef, 0, len(keys))
	for _, key := range keys {
		expectedRefs = append(expectedRefs, SettingRef{SchemaID: key.SchemaID, Path: "/synthetic/", Key: key.Key})
	}
	sortSettingRefs(expectedRefs)
	assert.Equal(t, expectedRefs, selection.settingRefs)
	configuration.Targets[0].GNOMEPolicy.Categories[0] = "mutated-after-selection"
	assert.Equal(t, expectedCategories, selection.target.GNOMEPolicy.Categories)
}

func TestSelectPublicationGNOMERefusesPendingStaleMissingAndInvalidPolicies(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	good := newApprovedPublicationGNOMETarget(t, "desktop", []string{"fonts"})
	cases := []struct {
		name     string
		target   config.Target
		settings SettingsPort
	}{
		{name: "pending", target: config.Target{ID: good.ID, Source: model.SourceGNOME, GNOMEPolicy: &config.GNOMEPolicy{Approval: config.GNOMEApprovalPending}}},
		{name: "stale matrix", target: func() config.Target {
			target := cloneSelectionTarget(good)
			target.GNOMEPolicy.MatrixVersion++
			return target
		}(), settings: &publicationSelectionSettings{path: "/synthetic/"}},
		{name: "stale digest", target: func() config.Target {
			target := cloneSelectionTarget(good)
			target.GNOMEPolicy.KeyDigest = strings.Repeat("0", 64)
			return target
		}(), settings: &publicationSelectionSettings{path: "/synthetic/"}},
		{name: "missing port", target: good},
		{name: "resolve error", target: good, settings: &publicationSelectionSettings{resolveErr: errors.New("synthetic resolver detail")}},
		{name: "invalid path", target: good, settings: &publicationSelectionSettings{path: "/bad"}},
		{name: "newline path", target: good, settings: &publicationSelectionSettings{path: "/synthetic/\n/"}},
		{name: "DEL path", target: good, settings: &publicationSelectionSettings{path: "/synthetic/\x7f/"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			configuration := config.Default()
			configuration.Targets = []config.Target{test.target}
			local, err := NewPublicationLocalContext(fixture.paths, fixture.capture, test.settings)
			require.NoError(t, err)
			portable := model.Target{ID: test.target.ID, Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
			selection, selectErr := selectPublicationTarget(context.Background(), local, configuration, test.target.ID, portable)
			assert.Equal(t, publicationSelection{}, selection)
			assertPublicationSelectionError(t, selectErr, string(publicationSelectionReasonSettings))
			assert.NotContains(t, selectErr.Error(), "synthetic resolver detail")
			assert.NotContains(t, selectErr.Error(), "\n")
			assert.NotContains(t, selectErr.Error(), "\x7f")
			if settings, ok := test.settings.(*publicationSelectionSettings); ok {
				assert.Equal(t, 0, settings.captureN)
				assert.Equal(t, 0, settings.backendN)
			}
		})
	}
}

func TestValidatePublicationSettingRefsRejectsDuplicateKeys(t *testing.T) {
	refs := []SettingRef{{SchemaID: "org.example.Test", Path: "/test/", Key: "value"}, {SchemaID: "org.example.Test", Path: "/test/", Key: "value"}}
	keys, err := validatePublicationSettingRefs("desktop", refs)
	assert.Nil(t, keys)
	assert.Error(t, err)
}

func TestSelectPublicationTargetRefusesWithoutLeakingLocalIdentifiers(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-selection-canary"
	configuration := fixture.configuration
	configuration.Targets[0].ID = canary
	configuration.Targets[0].Root.Path = "missing-root-canary"
	portable := model.Target{ID: canary, Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "missing-root-canary", Kind: model.SelectionDirectory}}
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, canary, portable)
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonRoot))
	assert.NotContains(t, err.Error(), canary)
	assert.NotContains(t, err.Error(), "missing-root-canary")
}

func TestSelectPublicationTargetHonorsCanceledContext(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	selection, err := selectPublicationTarget(ctx, fixture.local, fixture.configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonCanceled))
}

func cloneSelectionTestConfig(configuration config.Config) config.Config {
	out := configuration
	out.Targets = make([]config.Target, len(configuration.Targets))
	for index, target := range configuration.Targets {
		out.Targets[index] = cloneSelectionTarget(target)
	}
	return out
}

func TestPublicationSelectionContextInputsAreDetached(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	paths := fixture.paths
	local, err := NewPublicationLocalContext(paths, nil, nil)
	require.NoError(t, err)
	paths.Home = "/changed-after-construction"
	assert.Equal(t, fixture.paths.Home, local.paths.Home)
}

func TestPublicationSelectionConfigValidationHappensAfterBounds(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	configuration := fixture.configuration
	configuration.Targets[0].Root.Exclude = make([]string, publicationSelectionMaxExcludes+1)
	for index := range configuration.Targets[0].Root.Exclude {
		configuration.Targets[0].Root.Exclude[index] = "x"
	}
	configuration.Targets[0].Mode = config.Mode("invalid-but-bounded")
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))
}

func TestPublicationSelectionUsesFreshTargetSliceWhenOmittingSelf(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	fixture.configuration.Targets = make([]config.Target, 1, 5)
	fixture.configuration.Targets[0] = fixture.target
	backing := fixture.configuration.Targets[:cap(fixture.configuration.Targets)]
	backing[1] = config.Target{ID: "backing-canary", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory}}
	fixture.configuration.Targets = fixture.configuration.Targets[:1]
	before := cloneSelectionTestConfig(fixture.configuration)
	selection, err := selectPublicationTarget(context.Background(), fixture.local, fixture.configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	require.NoError(t, err)
	assert.Equal(t, fixture.target.ID, selection.target.ID)
	assert.True(t, reflect.DeepEqual(before, fixture.configuration))
	assert.Equal(t, "backing-canary", backing[1].ID)
}

func TestPublicationStringBudgetRejectsOversizeWithoutChangingUsage(t *testing.T) {
	budget := publicationStringBudget{used: publicationSelectionMaxStringBytes - 1}
	assert.False(t, budget.add(string([]byte{0xff, 0xff})))
	assert.Equal(t, publicationSelectionMaxStringBytes-1, budget.used)

	fixture := newPublicationSelectionFixture(t)
	configuration := cloneSelectionTestConfig(fixture.configuration)
	configuration.Defaults.Mode = config.Mode(strings.Repeat("x", publicationSelectionMaxStringBytes+1))
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, fixture.target.ID, publicationSelectionPortable(t, fixture.target))
	assert.Equal(t, publicationSelection{}, selection)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))
}

func TestPublicationSelectionStringBudgetExactLimitAndOneByteOver(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = nil
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	for index := 0; index < 3; index++ {
		id := fmt.Sprintf("padding-%d", index)
		root := fmt.Sprintf("padding-root-%d", index)
		require.NoError(t, os.Mkdir(filepath.Join(fixture.paths.Home, root), 0o700))
		configuration.Targets = append(configuration.Targets, config.Target{
			ID: id, Source: model.SourceFiles,
			Root: &config.Root{Base: model.RootHome, Path: root, Kind: model.SelectionDirectory},
		})
	}
	require.NoError(t, configuration.Validate())
	expected, err := target.Model()
	require.NoError(t, err)
	logicalPath := filepath.Join(fixture.paths.Home, target.Root.Path)
	derivedPaths := []string{logicalPath, logicalPath, fixture.paths.Home, fixture.paths.Home, fixture.paths.ConfigHome, logicalPath, ""}
	fixedBytes := publicationSelectionContractBytes(fixture.paths, configuration, target.ID, expected, nil, derivedPaths)
	patternBytes := publicationSelectionMaxStringBytes - fixedBytes
	const patternsPerRoot = publicationSelectionMaxExcludes
	const maxPatternChunk = publicationSelectionMaxExcludeBytes - 1
	remainingPatterns := len(configuration.Targets) * patternsPerRoot
	remainingBytes := patternBytes
	for targetIndex := range configuration.Targets {
		patterns := make([]string, patternsPerRoot)
		for patternIndex := range patterns {
			remainingPatterns--
			length := min(maxPatternChunk, remainingBytes-remainingPatterns)
			require.GreaterOrEqual(t, length, 1)
			patterns[patternIndex] = strings.Repeat("a", length)
			remainingBytes -= length
		}
		configuration.Targets[targetIndex].Root.Exclude = patterns
	}
	require.Zero(t, remainingBytes)
	require.Equal(t, publicationSelectionMaxStringBytes, publicationSelectionContractBytes(fixture.paths, configuration, target.ID, expected, nil, derivedPaths))
	require.NoError(t, configuration.Validate())
	selection, err := selectPublicationTarget(context.Background(), fixture.local, configuration, target.ID, expected)
	require.NoError(t, err)
	assert.Equal(t, target.ID, selection.target.ID)

	over := cloneSelectionTestConfig(configuration)
	lastTarget := len(over.Targets) - 1
	lastPattern := len(over.Targets[lastTarget].Root.Exclude) - 1
	over.Targets[lastTarget].Root.Exclude[lastPattern] += "a"
	require.Equal(t, publicationSelectionMaxStringBytes+1, publicationSelectionContractBytes(fixture.paths, over, target.ID, expected, nil, derivedPaths))
	require.NoError(t, over.Validate())
	rejected, err := selectPublicationTarget(context.Background(), fixture.local, over, target.ID, expected)
	assert.Equal(t, publicationSelection{}, rejected)
	assertPublicationSelectionError(t, err, string(publicationSelectionReasonBounds))

	budget := publicationStringBudget{used: publicationSelectionMaxStringBytes - 1}
	assert.False(t, budget.add("xx"))
	assert.Equal(t, publicationSelectionMaxStringBytes-1, budget.used)
}

func publicationSelectionContractBytes(paths platform.Paths, configuration config.Config, selectedID string, expected model.Target, refs []SettingRef, derivedPaths []string) int {
	total := 0
	add := func(value string) { total += len(value) }
	for _, value := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome, string(configuration.Defaults.Mode)} {
		add(value)
	}
	for _, target := range configuration.Targets {
		add(target.ID)
		add(string(target.Source))
		add(string(target.Mode))
		if target.Root != nil {
			add(string(target.Root.Base))
			add(target.Root.Path)
			add(string(target.Root.Kind))
			for _, pattern := range target.Root.Exclude {
				add(pattern)
			}
		}
		if target.GNOMEPolicy != nil {
			add(string(target.GNOMEPolicy.Approval))
			add(target.GNOMEPolicy.KeyDigest)
			for _, category := range target.GNOMEPolicy.Categories {
				add(category)
			}
		}
	}
	add(selectedID)
	add(expected.ID)
	add(string(expected.Source))
	if expected.Root != nil {
		add(string(expected.Root.Base))
		add(expected.Root.Path)
		add(string(expected.Root.Kind))
	}
	for _, ref := range refs {
		add(ref.SchemaID)
		add(ref.Path)
		add(ref.Key)
	}
	for _, value := range derivedPaths {
		add(value)
	}
	return total
}
