package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/gnome/matrix"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertPublicationProjectionError(t *testing.T, err error, reason publicationReconciliationReason) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublicationReconciliation)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, string(publicationProjectionStage), classified.Stage())
	assert.Equal(t, string(reason), classified.Reason())
}

func publicationProjectionSnapshot(selection publicationSelection, entries []model.Entry) model.Snapshot {
	return model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{selection.portable}, Entries: entries}
}

func publicationProjectionFile(targetID, path string, kind model.FileKind, content []byte) model.Entry {
	file := &model.FileEntry{Path: path, State: model.FilePresent, Kind: kind, Content: content, Mode: 0o600}
	if kind == model.FileDirectory {
		file.Content = nil
	}
	if kind == model.FileSymlink {
		file.Content = nil
		file.Mode = 0
	}
	return model.Entry{TargetID: targetID, File: file}
}

func publicationProjectionTombstone(targetID, path string) model.Entry {
	return model.Entry{TargetID: targetID, File: &model.FileEntry{Path: path, State: model.FileDeleted}}
}

func publicationProjectionPaths(entries []model.Entry) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.File.Path)
	}
	sort.Strings(paths)
	return paths
}

func TestProjectPublicationSnapshotMatchesLocalFileExclusionPolicy(t *testing.T) {
	for _, test := range []struct {
		name    string
		pattern string
		files   []string
		want    []string
	}{
		{name: "question mark", pattern: "?", files: []string{"x", "stay"}, want: []string{"stay"}},
		{name: "dot star root only", pattern: ".*", files: []string{".root", "stay", "nested/.hidden"}, want: []string{"nested", "nested/.hidden", "stay"}},
		{name: "recursive dot star", pattern: "**/.*", files: []string{".root", "stay", "nested/.hidden"}, want: []string{"nested", "stay"}},
		{name: "single star tmp", pattern: "*.tmp", files: []string{"root.tmp", "nested/deep.tmp", "keep"}, want: []string{"keep", "nested", "nested/deep.tmp"}},
		{name: "recursive tmp", pattern: "**/*.tmp", files: []string{"root.tmp", "nested/deep.tmp", "keep"}, want: []string{"keep", "nested"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicationSelectionFixture(t)
			root := filepath.Join(fixture.paths.Home, "selected")
			for _, path := range test.files {
				fullPath := filepath.Join(root, filepath.FromSlash(path))
				require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o700))
				require.NoError(t, os.WriteFile(fullPath, []byte(path), 0o600))
			}
			target := cloneSelectionTarget(fixture.target)
			target.Root.Exclude = []string{test.pattern}
			selection := publicationCaptureSelectionFor(t, fixture, target, nil)

			capture, err := capturePublicationFiles(context.Background(), selection)
			require.NoError(t, err)
			assert.True(t, capture.complete)
			capturedPaths := make([]string, 0, len(capture.observations))
			for _, observation := range capture.observations {
				capturedPaths = append(capturedPaths, observation.Identity.FilePath)
			}
			sort.Strings(capturedPaths)
			assert.Equal(t, test.want, capturedPaths)

			entries := make([]model.Entry, 0, len(test.files)*2)
			directories := make(map[string]struct{})
			for _, path := range test.files {
				parts := strings.Split(path, "/")
				for index := 1; index < len(parts); index++ {
					directories[strings.Join(parts[:index], "/")] = struct{}{}
				}
			}
			for directory := range directories {
				entries = append(entries, publicationProjectionFile(selection.portable.ID, directory, model.FileDirectory, nil))
			}
			for _, path := range test.files {
				entries = append(entries, publicationProjectionFile(selection.portable.ID, path, model.FileRegular, []byte(path)))
			}
			projected, projectErr := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, entries))
			assert.NoError(t, projectErr)
			assert.Equal(t, test.want, publicationProjectionPaths(projected.entries))
		})
	}
}

func TestProjectPublicationSnapshotPrunesExcludedAncestorsAndPreservesIncludedFileData(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{"excluded"}
	selection := publicationCaptureSelectionFor(t, fixture, target, nil)
	root := filepath.Join(fixture.paths.Home, "selected")
	require.NoError(t, os.WriteFile(filepath.Join(root, "keep"), []byte("kept"), 0o600))
	require.NoError(t, os.Symlink("keep", filepath.Join(root, "internal")))
	excludedRoot := filepath.Join(root, "excluded")
	require.NoError(t, os.Mkdir(excludedRoot, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(excludedRoot, "child"), []byte("omitted"), 0o600))
	captured, captureErr := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, captureErr)
	require.True(t, captured.complete)
	require.Len(t, captured.observations, 2)
	require.NotNil(t, captured.observations[0].Entry)
	require.NotNil(t, captured.observations[0].Entry.File)
	require.NotNil(t, captured.observations[1].Entry)
	require.NotNil(t, captured.observations[1].Entry.File)
	assert.Equal(t, []model.EntryKey{
		{TargetID: selection.portable.ID, Source: model.SourceFiles, FilePath: "internal"},
		{TargetID: selection.portable.ID, Source: model.SourceFiles, FilePath: "keep"},
	}, []model.EntryKey{captured.observations[0].Identity, captured.observations[1].Identity})
	assert.Equal(t, model.ObservationPresent, captured.observations[0].State)
	assert.Equal(t, model.FileSymlink, captured.observations[0].Entry.File.Kind)
	assert.Equal(t, "keep", captured.observations[0].Entry.File.LinkTarget)
	assert.Equal(t, model.ObservationPresent, captured.observations[1].State)
	assert.Equal(t, []byte("kept"), captured.observations[1].Entry.File.Content)

	entries := []model.Entry{
		publicationProjectionFile(selection.portable.ID, "keep", model.FileRegular, []byte("kept")),
		publicationProjectionFile(selection.portable.ID, "excluded/child", model.FileRegular, []byte("omitted")),
		publicationProjectionTombstone(selection.portable.ID, "excluded/gone"),
		publicationProjectionFile(selection.portable.ID, "internal", model.FileSymlink, nil),
		publicationProjectionTombstone(selection.portable.ID, "deleted"),
	}
	entries[3].File.LinkTarget = "keep"
	projected, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, entries))
	require.NoError(t, err)
	require.Len(t, projected.entries, 3)
	for _, entry := range projected.entries {
		require.NotNil(t, entry.File)
	}
	require.Equal(t, []string{"deleted", "internal", "keep"}, publicationProjectionPaths(projected.entries))
	assert.Equal(t, "keep", projected.entries[1].File.LinkTarget)
	assert.Equal(t, []byte("kept"), projected.entries[2].File.Content)
	assert.Empty(t, projected.untracked)

	malformedExcluded := model.Entry{TargetID: selection.portable.ID, File: &model.FileEntry{Path: "excluded/malformed", State: model.FilePresent, Kind: model.FileRegular}}
	refused, refusalErr := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, []model.Entry{malformedExcluded}))
	assert.Equal(t, publicationProjection{}, refused)
	assertPublicationProjectionError(t, refusalErr, publicationProjectionReasonSnapshot)
}

func TestProjectPublicationSnapshotAppliesSingleFileDotExcludesLikeCapture(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	parent := filepath.Join(fixture.paths.Home, "single-parent")
	require.NoError(t, os.Mkdir(parent, 0o700))
	filePath := filepath.Join(parent, "selected.ini")
	require.NoError(t, os.WriteFile(filePath, []byte("selected"), 0o600))
	for _, test := range []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "dot matching", pattern: ".*", want: false},
		{name: "dot nonmatching", pattern: "*.ini", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := config.Target{ID: "single-file", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "single-parent/selected.ini", Kind: model.SelectionFile, Exclude: []string{test.pattern}}}
			selection := publicationCaptureSelectionFor(t, fixture, target, nil)
			captured, captureErr := capturePublicationFiles(context.Background(), selection)
			require.NoError(t, captureErr)
			if test.want {
				require.Len(t, captured.observations, 1)
				require.NotNil(t, captured.observations[0].Entry)
				require.NotNil(t, captured.observations[0].Entry.File)
				assert.Equal(t, ".", captured.observations[0].Identity.FilePath)
			} else {
				assert.Empty(t, captured.observations)
			}

			entry := publicationProjectionFile(selection.portable.ID, ".", model.FileRegular, []byte("selected"))
			projected, projectErr := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, []model.Entry{entry}))
			require.NoError(t, projectErr)
			if test.want {
				require.Len(t, projected.entries, 1)
				require.NotNil(t, projected.entries[0].File)
				assert.Equal(t, []byte("selected"), projected.entries[0].File.Content)
			} else {
				assert.Empty(t, projected.entries)
			}
		})
	}
}

func TestProjectPublicationSnapshotRejectsRootAndUnsafeLinkShapes(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, nil)
	for _, test := range []struct {
		name    string
		entries []model.Entry
	}{
		{name: "directory dot", entries: []model.Entry{publicationProjectionFile(selection.portable.ID, ".", model.FileDirectory, nil)}},
		{name: "directory dot tombstone", entries: []model.Entry{publicationProjectionTombstone(selection.portable.ID, ".")}},
		{name: "included external link", entries: []model.Entry{{TargetID: selection.portable.ID, File: &model.FileEntry{Path: "link", State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: "../outside"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			projected, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, test.entries))
			assert.Equal(t, publicationProjection{}, projected)
			assertPublicationProjectionError(t, err, publicationProjectionReasonSnapshot)
		})
	}

	excludedTarget := cloneSelectionTarget(fixture.target)
	excludedTarget.Root.Exclude = []string{"link"}
	excludedSelection := publicationCaptureSelectionFor(t, fixture, excludedTarget, nil)
	external := model.Entry{TargetID: excludedSelection.portable.ID, File: &model.FileEntry{Path: "link", State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: "../outside"}}
	projected, err := projectPublicationSnapshot(excludedSelection, publicationProjectionSnapshot(excludedSelection, []model.Entry{external}))
	require.NoError(t, err)
	assert.Empty(t, projected.entries)
	assert.Empty(t, projected.untracked)

	fileTarget := config.Target{ID: "single-file", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "single.ini", Kind: model.SelectionFile}}
	require.NoError(t, os.WriteFile(filepath.Join(fixture.paths.Home, "single.ini"), []byte("selected"), 0o600))
	fileSelection := publicationCaptureSelectionFor(t, fixture, fileTarget, nil)
	badSymlink := publicationProjectionFile(fileSelection.portable.ID, ".", model.FileSymlink, nil)
	badSymlink.File.LinkTarget = "inside"
	belowRoot := publicationProjectionFile(fileSelection.portable.ID, "child", model.FileRegular, []byte("not in a single-file target"))
	for _, entry := range []model.Entry{
		publicationProjectionFile(fileSelection.portable.ID, ".", model.FileDirectory, nil),
		badSymlink,
		belowRoot,
	} {
		projected, projectErr := projectPublicationSnapshot(fileSelection, publicationProjectionSnapshot(fileSelection, []model.Entry{entry}))
		assert.Equal(t, publicationProjection{}, projected)
		assertPublicationProjectionError(t, projectErr, publicationProjectionReasonSnapshot)
	}
	tombstone := publicationProjectionTombstone(fileSelection.portable.ID, ".")
	projected, err = projectPublicationSnapshot(fileSelection, publicationProjectionSnapshot(fileSelection, []model.Entry{tombstone}))
	require.NoError(t, err)
	assert.Equal(t, []string{"."}, publicationProjectionPaths(projected.entries))
}

func TestProjectPublicationSnapshotRefusesMissingMismatchedAndMalformedDescriptors(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, nil)
	missing := model.Snapshot{Version: model.SnapshotVersion}
	projected, err := projectPublicationSnapshot(selection, missing)
	assert.Equal(t, publicationProjection{}, projected)
	assertPublicationProjectionError(t, err, publicationProjectionReasonSelection)

	mismatched := selection.portable
	mismatched.Root = &model.FileRoot{Base: model.RootHome, Path: "different", Kind: model.SelectionDirectory}
	projected, err = projectPublicationSnapshot(selection, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{mismatched}})
	assert.Equal(t, publicationProjection{}, projected)
	assertPublicationProjectionError(t, err, publicationProjectionReasonSelection)

	other := model.Target{ID: "other", Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
	entries := []model.Entry{
		publicationProjectionFile(selection.portable.ID, "keep", model.FileRegular, []byte("kept")),
		{TargetID: other.ID, File: &model.FileEntry{Path: "wrong", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("bad")}},
	}
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{selection.portable, other}, Entries: entries}
	projected, err = projectPublicationSnapshot(selection, snapshot)
	assert.Equal(t, publicationProjection{}, projected)
	assertPublicationProjectionError(t, err, publicationProjectionReasonSnapshot)

	otherFile := model.Target{ID: "other-files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory}}
	validOther := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{selection.portable, otherFile}, Entries: []model.Entry{publicationProjectionFile(selection.portable.ID, "keep", model.FileRegular, []byte("kept")), publicationProjectionFile(otherFile.ID, "foreign", model.FileRegular, []byte("ignored"))}}
	projected, err = projectPublicationSnapshot(selection, validOther)
	require.NoError(t, err)
	assert.Equal(t, []string{"keep"}, publicationProjectionPaths(projected.entries))

	duplicate := publicationProjectionSnapshot(selection, []model.Entry{publicationProjectionFile(selection.portable.ID, "same", model.FileRegular, []byte("a")), publicationProjectionFile(selection.portable.ID, "same", model.FileRegular, []byte("b"))})
	projected, err = projectPublicationSnapshot(selection, duplicate)
	assert.Equal(t, publicationProjection{}, projected)
	assertPublicationProjectionError(t, err, publicationProjectionReasonSnapshot)

	invalidTree := publicationProjectionSnapshot(selection, []model.Entry{publicationProjectionFile(selection.portable.ID, "node", model.FileRegular, []byte("a")), publicationProjectionFile(selection.portable.ID, "node/child", model.FileRegular, []byte("b"))})
	projected, err = projectPublicationSnapshot(selection, invalidTree)
	assert.Equal(t, publicationProjection{}, projected)
	assertPublicationProjectionError(t, err, publicationProjectionReasonSnapshot)
}

func TestProjectPublicationSnapshotReturnsGNOMEUntrackedBarrierAndDetachedValues(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
	refs := selection.settingRefs
	require.GreaterOrEqual(t, len(refs), 2)
	present := publicationCaptureGNOMEEntry(selection.portable.ID, refs[0], model.SettingPresent, &model.VariantValue{Type: "s", Text: "'synthetic'"})
	reset := publicationCaptureGNOMEEntry(selection.portable.ID, refs[1], model.SettingReset, nil)
	wrongPathRef := refs[0]
	wrongPathRef.Path = "/unapproved/"
	wrongPath := publicationCaptureGNOMEEntry(selection.portable.ID, wrongPathRef, model.SettingPresent, &model.VariantValue{Type: "s", Text: "'untracked'"})
	unapprovedRef := SettingRef{SchemaID: "org.example.Unapproved", Path: "/", Key: "foreign"}
	unapproved := publicationCaptureGNOMEEntry(selection.portable.ID, unapprovedRef, model.SettingPresent, &model.VariantValue{Type: "s", Text: "'untracked'"})
	snapshot := publicationProjectionSnapshot(selection, []model.Entry{unapproved, reset, wrongPath, present})
	resolveCalls := settings.resolveCalls
	captureCalls := settings.captureCalls
	backendCalls := settings.backendCalls
	projected, err := projectPublicationSnapshot(selection, snapshot)
	require.NoError(t, err)
	require.Len(t, projected.entries, 2)
	require.NotNil(t, projected.entries[0].Setting)
	require.NotNil(t, projected.entries[0].Setting.Value)
	require.NotNil(t, projected.entries[1].Setting)
	require.Equal(t, []model.Entry{present, reset}, projected.entries)
	expectedUntracked := []model.EntryKey{wrongPath.Identity(), unapproved.Identity()}
	sort.Slice(expectedUntracked, func(left, right int) bool {
		return publicationProjectionKeyLess(expectedUntracked[left], expectedUntracked[right])
	})
	assert.Equal(t, expectedUntracked, projected.untracked)
	assert.Equal(t, resolveCalls, settings.resolveCalls)
	assert.Equal(t, captureCalls, settings.captureCalls)
	assert.Equal(t, backendCalls, settings.backendCalls)

	require.Len(t, snapshot.Entries, 4)
	require.NotNil(t, snapshot.Entries[3].Setting)
	require.NotNil(t, snapshot.Entries[3].Setting.Value)
	*snapshot.Entries[3].Setting.Value = model.VariantValue{Type: "s", Text: "'changed'"}
	assert.Equal(t, "'synthetic'", projected.entries[0].Setting.Value.Text)
	require.NotNil(t, snapshot.Entries[0].Setting)
	require.NotNil(t, snapshot.Entries[0].Setting.Value)
	*snapshot.Entries[0].Setting.Value = model.VariantValue{Type: "s", Text: "'changed untracked'"}
	assert.Equal(t, expectedUntracked, projected.untracked)
}

func clonePublicationProjectionSelection(selection publicationSelection) publicationSelection {
	out := selection
	out.target = cloneSelectionTarget(selection.target)
	out.portable = cloneSelectionTargetModel(selection.portable)
	out.excludes = append([]string(nil), selection.excludes...)
	out.settingRefs = append([]SettingRef(nil), selection.settingRefs...)
	return out
}

func TestProjectPublicationSnapshotRequiresApprovedGNOMEPolicyAndMatchingRefs(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	fixture, original := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
	keys, err := matrix.SelectCategories(original.target.GNOMEPolicy.Categories)
	require.NoError(t, err)
	require.Len(t, keys, len(original.settingRefs))
	require.NotEmpty(t, keys)
	require.NotEmpty(t, original.settingRefs)
	assert.NotEqual(t, keys[0].Path, original.settingRefs[0].Path)
	entry := publicationCaptureGNOMEEntry(original.portable.ID, original.settingRefs[0], model.SettingReset, nil)
	snapshot := publicationProjectionSnapshot(original, []model.Entry{entry})

	assertUnchanged := func(t *testing.T, selection publicationSelection, target config.Target, portable model.Target, excludes []string, refs []SettingRef) {
		t.Helper()
		assert.Equal(t, target, selection.target)
		assert.Equal(t, portable, selection.portable)
		assert.Equal(t, excludes, selection.excludes)
		assert.Equal(t, refs, selection.settingRefs)
	}

	healthy := clonePublicationProjectionSelection(original)
	healthyTarget := cloneSelectionTarget(healthy.target)
	healthyPortable := cloneSelectionTargetModel(healthy.portable)
	healthyExcludes := append([]string(nil), healthy.excludes...)
	healthyRefs := append([]SettingRef(nil), healthy.settingRefs...)
	projected, err := projectPublicationSnapshot(healthy, snapshot)
	require.NoError(t, err)
	assert.Equal(t, []model.Entry{entry}, projected.entries)
	assert.Empty(t, projected.untracked)
	assertUnchanged(t, healthy, healthyTarget, healthyPortable, healthyExcludes, healthyRefs)
	assert.Zero(t, settings.resolveCalls)
	assert.Zero(t, settings.captureCalls)
	assert.Zero(t, settings.backendCalls)
	assert.Zero(t, fixture.capture.calls)

	tests := []struct {
		name   string
		mutate func(*publicationSelection)
	}{
		{name: "pending approval", mutate: func(selection *publicationSelection) {
			selection.target.GNOMEPolicy.Approval = config.GNOMEApprovalPending
		}},
		{name: "stale matrix", mutate: func(selection *publicationSelection) { selection.target.GNOMEPolicy.MatrixVersion++ }},
		{name: "invalid category", mutate: func(selection *publicationSelection) {
			selection.target.GNOMEPolicy.Categories = []string{"unknown-category"}
		}},
		{name: "category digest mismatch", mutate: func(selection *publicationSelection) {
			selection.target.GNOMEPolicy.Categories = []string{"appearance"}
		}},
		{name: "malformed digest", mutate: func(selection *publicationSelection) { selection.target.GNOMEPolicy.KeyDigest = "not-a-digest" }},
		{name: "forged retained schema key", mutate: func(selection *publicationSelection) {
			selection.settingRefs[len(selection.settingRefs)-1].Key = "zzzz-forged"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection := clonePublicationProjectionSelection(original)
			test.mutate(&selection)
			beforeTarget := cloneSelectionTarget(selection.target)
			beforePortable := cloneSelectionTargetModel(selection.portable)
			beforeExcludes := append([]string(nil), selection.excludes...)
			beforeRefs := append([]SettingRef(nil), selection.settingRefs...)
			refused, refusalErr := projectPublicationSnapshot(selection, snapshot)
			assert.Equal(t, publicationProjection{}, refused)
			assertPublicationProjectionError(t, refusalErr, publicationProjectionReasonInput)
			assertUnchanged(t, selection, beforeTarget, beforePortable, beforeExcludes, beforeRefs)
			assert.Zero(t, settings.resolveCalls)
			assert.Zero(t, settings.captureCalls)
			assert.Zero(t, settings.backendCalls)
			assert.Zero(t, fixture.capture.calls)
		})
	}
}

func TestProjectPublicationSnapshotAcceptsEmptySelectedDirectory(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, nil)
	capture, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, capture.complete)
	assert.Empty(t, capture.observations)
	projected, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, nil))
	require.NoError(t, err)
	assert.Empty(t, projected.entries)
	assert.Empty(t, projected.untracked)
}

func TestProjectPublicationSnapshotEnforcesWholeInputBoundsBeforeFiltering(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, nil)
	valid := publicationProjectionSnapshot(selection, []model.Entry{publicationProjectionFile(selection.portable.ID, "keep", model.FileRegular, []byte("ok"))})
	for _, test := range []struct {
		name     string
		snapshot model.Snapshot
	}{
		{
			name: "entry count",
			snapshot: func() model.Snapshot {
				entries := make([]model.Entry, 20001)
				for index := range entries {
					entries[index] = publicationProjectionFile(selection.portable.ID, fmt.Sprintf("f-%05d", index), model.FileRegular, []byte{})
				}
				result := valid
				result.Entries = entries
				return result
			}(),
		},
		{
			name: "target count",
			snapshot: func() model.Snapshot {
				targets := make([]model.Target, 20001)
				for index := range targets {
					targets[index] = model.Target{ID: fmt.Sprintf("other-%05d", index), Source: model.SourceGNOME, SourceVersion: model.SourceVersion}
				}
				return model.Snapshot{Version: model.SnapshotVersion, Targets: targets}
			}(),
		},
		{
			name: "path depth",
			snapshot: func() model.Snapshot {
				path := strings.Repeat("a/", 32) + "leaf"
				return publicationProjectionSnapshot(selection, []model.Entry{publicationProjectionFile(selection.portable.ID, path, model.FileRegular, []byte{})})
			}(),
		},
		{
			name: "aggregate content",
			snapshot: func() model.Snapshot {
				content := make([]byte, 8*1024*1024)
				entries := make([]model.Entry, 33)
				for index := range entries {
					entries[index] = publicationProjectionFile(selection.portable.ID, fmt.Sprintf("large-%02d", index), model.FileRegular, content)
				}
				return publicationProjectionSnapshot(selection, entries)
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			projected, err := projectPublicationSnapshot(selection, test.snapshot)
			assert.Equal(t, publicationProjection{}, projected)
			assertPublicationProjectionError(t, err, publicationProjectionReasonBounds)
		})
	}
}

func TestProjectPublicationSnapshotAcceptsMaximumFilePathDepth(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, nil)
	path := strings.Repeat("a/", 31) + "leaf"
	entry := publicationProjectionFile(selection.portable.ID, path, model.FileRegular, []byte("body"))
	projected, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, []model.Entry{entry}))
	require.NoError(t, err)
	assert.Equal(t, []model.Entry{entry}, projected.entries)
}

func TestProjectPublicationSnapshotRejectsExcludedOversizedFileBeforeFiltering(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{"large.tmp"}
	selection := publicationCaptureSelectionFor(t, fixture, target, nil)
	snapshot := publicationProjectionSnapshot(selection, []model.Entry{publicationProjectionFile(selection.portable.ID, "large.tmp", model.FileRegular, make([]byte, 8*1024*1024+1))})
	projected, err := projectPublicationSnapshot(selection, snapshot)
	assert.Equal(t, publicationProjection{}, projected)
	assertPublicationProjectionError(t, err, publicationProjectionReasonBounds)
}

func TestProjectPublicationSnapshotEnforcesGNOMEValueAndMetadataBoundsBeforeFiltering(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	_, selection := publicationCaptureGNOMESelectionFor(t, settings, "desktop")
	unapproved := SettingRef{SchemaID: "org.example.Unapproved", Path: "/", Key: "foreign"}
	tests := []struct {
		name    string
		entries []model.Entry
	}{
		{
			name:    "oversized excluded identity value",
			entries: []model.Entry{publicationCaptureGNOMEEntry(selection.portable.ID, unapproved, model.SettingPresent, &model.VariantValue{Type: "s", Text: strings.Repeat("x", model.MaxVariantTextBytes+1)})},
		},
		{
			name: "oversized malformed dual payload",
			entries: func() []model.Entry {
				entry := publicationCaptureGNOMEEntry(selection.portable.ID, unapproved, model.SettingPresent, &model.VariantValue{Type: "s", Text: strings.Repeat("x", model.MaxVariantTextBytes+1)})
				entry.File = &model.FileEntry{Path: "child", State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}}
				return []model.Entry{entry}
			}(),
		},
		{
			name: "aggregate logical metadata",
			entries: func() []model.Entry {
				value := &model.VariantValue{Type: "s", Text: strings.Repeat("x", model.MaxVariantTextBytes)}
				entries := make([]model.Entry, 257)
				for index := range entries {
					ref := SettingRef{SchemaID: "org.example.Unapproved", Path: "/", Key: fmt.Sprintf("foreign-%03d", index)}
					entries[index] = publicationCaptureGNOMEEntry(selection.portable.ID, ref, model.SettingPresent, value)
				}
				return entries
			}(),
		},
		{
			name:    "settings path depth",
			entries: []model.Entry{publicationCaptureGNOMEEntry(selection.portable.ID, SettingRef{SchemaID: "org.example.Unapproved", Path: "/" + strings.Repeat("a/", 32) + "a/", Key: "foreign"}, model.SettingReset, nil)},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projected, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, test.entries))
			assert.Equal(t, publicationProjection{}, projected)
			assertPublicationProjectionError(t, err, publicationProjectionReasonBounds)
		})
	}
}

func TestProjectPublicationSnapshotSyntheticBaseReconciliationWitnessForFileExclusions(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	root := filepath.Join(fixture.paths.Home, "selected")
	require.NoError(t, os.WriteFile(filepath.Join(root, "keep"), []byte("same"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "excluded.tmp"), []byte("local"), 0o600))
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{"*.tmp"}
	selection := publicationCaptureSelectionFor(t, fixture, target, nil)
	localCapture, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	require.True(t, localCapture.complete)
	localEntries := make([]model.Entry, 0, len(localCapture.observations))
	for _, observation := range localCapture.observations {
		if observation.State == model.ObservationPresent {
			localEntries = append(localEntries, *observation.Entry)
		}
	}

	baseEntries := []model.Entry{
		publicationProjectionFile(selection.portable.ID, "keep", model.FileRegular, []byte("same")),
		publicationProjectionFile(selection.portable.ID, "excluded.tmp", model.FileRegular, []byte("excluded")),
	}
	currentEntries := []model.Entry{
		publicationProjectionFile(selection.portable.ID, "keep", model.FileRegular, []byte("same")),
		publicationProjectionFile(selection.portable.ID, "excluded.tmp", model.FileRegular, []byte("excluded")),
	}
	binding, err := syncengine.NewTargetBinding(selection.portable)
	require.NoError(t, err)
	unprojectedPlan, err := syncengine.Reconcile(syncengine.BaseView{Entries: baseEntries, Status: syncengine.BaseKnown}, syncengine.LocalView{Entries: localEntries, Coverage: []string{selection.portable.ID}}, currentEntries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
	require.NoError(t, err)
	require.Len(t, unprojectedPlan.Decisions, 2)
	assert.Equal(t, syncengine.ActionDeleteRemote, unprojectedPlan.Decisions[0].Action)
	assert.Equal(t, syncengine.ReasonLocalChanged, unprojectedPlan.Decisions[0].Reason)
	assert.Equal(t, "excluded.tmp", unprojectedPlan.Decisions[0].Key.FilePath)

	base, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, baseEntries))
	require.NoError(t, err)
	remote, err := projectPublicationSnapshot(selection, publicationProjectionSnapshot(selection, currentEntries))
	require.NoError(t, err)
	plan, err := syncengine.Reconcile(syncengine.BaseView{Entries: base.entries, Status: syncengine.BaseKnown}, syncengine.LocalView{Entries: localEntries, Coverage: []string{selection.portable.ID}}, remote.entries, syncengine.Options{Bindings: []syncengine.TargetBinding{binding}})
	require.NoError(t, err)
	require.Len(t, plan.Decisions, 1)
	assert.Equal(t, model.EntryKey{TargetID: selection.portable.ID, Source: model.SourceFiles, FilePath: "keep"}, plan.Decisions[0].Key)
	assert.Equal(t, syncengine.ActionUnchanged, plan.Decisions[0].Action)
	assert.Equal(t, syncengine.ReasonEqual, plan.Decisions[0].Reason)
}

func TestProjectPublicationSnapshotReturnsIndependentDeterministicCopies(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, nil)
	beforeTarget := cloneSelectionTarget(selection.target)
	beforePortable := cloneSelectionTargetModel(selection.portable)
	beforeExcludes := append([]string(nil), selection.excludes...)
	beforeRefs := append([]SettingRef(nil), selection.settingRefs...)
	z := publicationProjectionFile(selection.portable.ID, "z", model.FileRegular, []byte("z"))
	a := publicationProjectionFile(selection.portable.ID, "a", model.FileRegular, []byte("a"))
	firstSnapshot := publicationProjectionSnapshot(selection, []model.Entry{z, a})
	secondSnapshot := publicationProjectionSnapshot(selection, []model.Entry{a, z})
	first, err := projectPublicationSnapshot(selection, firstSnapshot)
	require.NoError(t, err)
	second, err := projectPublicationSnapshot(selection, secondSnapshot)
	require.NoError(t, err)
	require.Len(t, first.entries, 2)
	require.Len(t, second.entries, 2)
	for _, entry := range first.entries {
		require.NotNil(t, entry.File)
	}
	require.Equal(t, []string{"a", "z"}, publicationProjectionPaths(first.entries))
	require.Equal(t, first.entries, second.entries)
	assert.Equal(t, beforeTarget, selection.target)
	assert.Equal(t, beforePortable, selection.portable)
	assert.Equal(t, beforeExcludes, selection.excludes)
	assert.Equal(t, beforeRefs, selection.settingRefs)
	require.Len(t, firstSnapshot.Entries, 2)
	require.NotNil(t, firstSnapshot.Entries[0].File)
	require.Len(t, firstSnapshot.Entries[0].File.Content, 1)
	firstSnapshot.Entries[0].File.Content[0] = 'x'
	assert.Equal(t, []byte("z"), first.entries[1].File.Content)
	assert.Equal(t, []byte("a"), first.entries[0].File.Content)
}
