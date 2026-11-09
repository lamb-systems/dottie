package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type publicationCapturePortFunc func(context.Context, config.Target, string) (files.Result, error)

func (capture publicationCapturePortFunc) Capture(ctx context.Context, target config.Target, path string) (files.Result, error) {
	return capture(ctx, target, path)
}

func publicationCaptureSelectionFor(t *testing.T, fixture publicationSelectionFixture, target config.Target, capture CapturePort) publicationSelection {
	t.Helper()
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	portable, err := target.Model()
	require.NoError(t, err)
	selection, err := selectPublicationTarget(context.Background(), local, configuration, target.ID, portable)
	require.NoError(t, err)
	return selection
}

func publicationCaptureObservation(targetID, path string, kind model.FileKind, content []byte, mode uint32) model.Observation {
	entry := model.Entry{TargetID: targetID, File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: kind, Content: content, Mode: mode}}
	if kind == model.FileDirectory {
		entry.File.Content = nil
	}
	if kind == model.FileSymlink {
		entry.File.Content = nil
		entry.File.Mode = 0
	}
	return model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
}

func publicationCaptureUnknown(targetID, path string) model.Observation {
	return model.Observation{State: model.ObservationUnknown, Identity: model.EntryKey{TargetID: targetID, Source: model.SourceFiles, FilePath: path}}
}

func assertPublicationCaptureError(t *testing.T, err error, reason string) {
	t.Helper()
	require.ErrorIs(t, err, ErrPublicationReconciliation)
	var classified interface {
		Stage() string
		Reason() string
	}
	require.ErrorAs(t, err, &classified)
	assert.Equal(t, "capture", classified.Stage())
	assert.Equal(t, reason, classified.Reason())
}

func TestCapturePublicationFilesRealDirectoryPreservesEntriesAndExclusionCoverage(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	root := filepath.Join(fixture.paths.Home, "selected")
	require.NoError(t, os.WriteFile(filepath.Join(root, "config"), []byte("body"), 0o640))
	require.NoError(t, os.WriteFile(filepath.Join(root, "empty"), []byte{}, 0o600))
	subdir := filepath.Join(root, "sub")
	require.NoError(t, os.Mkdir(subdir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "nested"), []byte("nested"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "discard.tmp"), []byte("excluded"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".cache", "child"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".cache", "child", "hidden"), []byte("hidden"), 0o600))
	require.NoError(t, os.Symlink("config", filepath.Join(root, "internal-link")))

	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{".cache", "**/*.tmp"}
	selection := publicationCaptureSelectionFor(t, fixture, target, nil)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)

	paths := make([]string, 0, len(captured.observations))
	entries := make(map[string]model.Entry, len(captured.observations))
	for _, observation := range captured.observations {
		paths = append(paths, observation.Identity.FilePath)
		require.Equal(t, model.ObservationPresent, observation.State)
		require.NotNil(t, observation.Entry)
		entries[observation.Identity.FilePath] = *observation.Entry
	}
	assert.Equal(t, []string{"config", "empty", "internal-link", "sub", "sub/nested"}, paths)
	assert.Equal(t, []byte("body"), entries["config"].File.Content)
	assert.Equal(t, uint32(0o640), entries["config"].File.Mode)
	assert.Equal(t, []byte{}, entries["empty"].File.Content)
	assert.Equal(t, uint32(0o750), entries["sub"].File.Mode)
	assert.Equal(t, model.FileSymlink, entries["internal-link"].File.Kind)
	assert.Equal(t, "config", entries["internal-link"].File.LinkTarget)
	assert.NotContains(t, paths, ".cache")
	assert.NotContains(t, paths, ".cache/child/hidden")
	assert.NotContains(t, paths, "sub/discard.tmp")
	again, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, captured.observations, again.observations)
}

func TestCapturePublicationFilesDirectoryExcludesDoNotMatchSyntheticRoot(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		wantPath []string
	}{
		{
			name:    "single character",
			pattern: "?",
			wantPath: []string{
				".hidden", ".hidden-dir", "config", "folder",
				".hidden-dir/child", "folder/.nested-hidden", "folder/config", "folder/.nested-hidden/child",
			},
		},
		{
			name:    "dot prefix",
			pattern: ".*",
			wantPath: []string{
				"config", "folder", "x", "z",
				"folder/.nested-hidden", "folder/config", "x/child",
				"folder/.nested-hidden/child",
			},
		},
		{
			name:    "recursive dot prefix",
			pattern: "**/.*",
			wantPath: []string{
				"config", "folder", "x", "z", "folder/config", "x/child",
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPublicationSelectionFixture(t)
			root := filepath.Join(fixture.paths.Home, "selected")
			require.NoError(t, os.WriteFile(filepath.Join(root, "config"), []byte("root config"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(root, "z"), []byte("single character"), 0o600))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "x"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "x", "child"), []byte("under excluded directory"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(root, ".hidden"), []byte("hidden file"), 0o600))
			require.NoError(t, os.MkdirAll(filepath.Join(root, ".hidden-dir"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(root, ".hidden-dir", "child"), []byte("hidden child"), 0o600))
			require.NoError(t, os.MkdirAll(filepath.Join(root, "folder", ".nested-hidden"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "folder", ".nested-hidden", "child"), []byte("nested hidden child"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(root, "folder", "config"), []byte("nested config"), 0o600))

			target := cloneSelectionTarget(fixture.target)
			target.Root.Exclude = []string{test.pattern}
			selection := publicationCaptureSelectionFor(t, fixture, target, nil)
			captured, err := capturePublicationFiles(context.Background(), selection)
			require.NoError(t, err)
			assert.True(t, captured.complete)
			assert.Equal(t, test.wantPath, publicationCapturePaths(captured.observations))
			assert.Contains(t, publicationCapturePaths(captured.observations), "config")
			assert.Contains(t, publicationCapturePaths(captured.observations), "folder/config")
		})
	}
}

func TestCapturePublicationFilesEmptyDirectoryAndMissingRootDiffer(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	root := filepath.Join(fixture.paths.Home, "selected")
	for _, name := range []string{"old-selected", "old-selected-2"} {
		assert.NoError(t, os.RemoveAll(filepath.Join(fixture.paths.Home, name)))
	}
	calls := 0
	capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		calls++
		return (LocalFilesCapture{}).Capture(ctx, target, path)
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)
	assert.Empty(t, captured.observations)

	old := filepath.Join(fixture.paths.Home, "old-selected")
	require.NoError(t, os.Rename(root, old))
	missing, err := capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, missing)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonRoot))
	assert.Equal(t, 1, calls, "the changed root is rejected before the capture port")
	assert.True(t, fileExists(old))
}

func TestCapturePublicationFilesSingleFileDotAndOmissionRules(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	filePath := filepath.Join(fixture.paths.Home, "single.ini")
	require.NoError(t, os.WriteFile(filePath, []byte("single"), 0o600))
	target := config.Target{ID: "single", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "single.ini", Kind: model.SelectionFile}}
	selection := publicationCaptureSelectionFor(t, fixture, target, nil)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)
	require.Len(t, captured.observations, 1)
	assert.Equal(t, ".", captured.observations[0].Identity.FilePath)
	assert.Equal(t, []byte("single"), captured.observations[0].Entry.File.Content)

	calls := 0
	omitting := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		calls++
		return files.Result{}, nil
	})
	omittedSelection := publicationCaptureSelectionFor(t, fixture, target, omitting)
	omitted, err := capturePublicationFiles(context.Background(), omittedSelection)
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.False(t, omitted.complete)
	require.Len(t, omitted.observations, 1)
	assert.Equal(t, publicationCaptureUnknown("single", "."), omitted.observations[0])

	dotCalls := 0
	var callbackPath string
	presentDot := publicationCapturePortFunc(func(_ context.Context, selected config.Target, path string) (files.Result, error) {
		dotCalls++
		callbackPath = path
		return files.Result{Observations: []model.Observation{publicationCaptureObservation(selected.ID, ".", model.FileRegular, []byte("captured dot"), 0o600)}}, nil
	})
	for _, pattern := range []string{"?", ".*", "*", "**", "**/.*"} {
		t.Run("dot-excluded-"+pattern, func(t *testing.T) {
			patterned := cloneSelectionTarget(target)
			patterned.Root.Exclude = []string{pattern}
			selection := publicationCaptureSelectionFor(t, fixture, patterned, presentDot)
			excluded, captureErr := capturePublicationFiles(context.Background(), selection)
			require.NoError(t, captureErr)
			assert.True(t, excluded.complete)
			assert.Empty(t, excluded.observations)
			assert.Zero(t, dotCalls)
			assert.Empty(t, callbackPath)
		})
	}

	nonmatching := cloneSelectionTarget(target)
	nonmatching.Root.Exclude = []string{"*.ini"}
	nonmatchingSelection := publicationCaptureSelectionFor(t, fixture, nonmatching, presentDot)
	included, err := capturePublicationFiles(context.Background(), nonmatchingSelection)
	require.NoError(t, err)
	assert.Equal(t, 1, dotCalls, "matching is against root-relative dot, never the host basename")
	assert.Equal(t, filePath, callbackPath)
	assert.True(t, included.complete)
	require.Len(t, included.observations, 1)
	assert.Equal(t, ".", included.observations[0].Identity.FilePath)
	assert.Equal(t, []byte("captured dot"), included.observations[0].Entry.File.Content)
}

func TestCapturePublicationFilesExcludedSingleFileRejectsReplacedParent(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	parent := filepath.Join(fixture.paths.Home, "single-parent")
	oldParent := filepath.Join(fixture.paths.Home, "single-parent-old")
	filePath := filepath.Join(parent, "single.ini")
	require.NoError(t, os.Mkdir(parent, 0o700))
	require.NoError(t, os.WriteFile(filePath, []byte("old selection"), 0o600))
	target := config.Target{ID: "single", Source: model.SourceFiles, Root: &config.Root{
		Base: model.RootHome, Path: "single-parent/single.ini", Kind: model.SelectionFile, Exclude: []string{"**"},
	}}
	calls := 0
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		calls++
		return files.Result{}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, target, capture)
	require.NoError(t, os.Rename(parent, oldParent))
	require.NoError(t, os.Mkdir(parent, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(parent, "single.ini"), []byte("replacement"), 0o600))

	captured, err := capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonRoot))
	assert.Zero(t, calls)
	assert.True(t, fileExists(filepath.Join(oldParent, "single.ini")))
}

func TestCapturePublicationFilesKnownSkipsBecomeUnknownWithoutDetails(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-skip-detail-canary"
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{
			{Path: "special", Reason: files.SkipSpecialFile, Detail: canary},
			{Path: "outside", Reason: files.SkipExternalLink, Detail: canary},
			{Path: "legacy", Reason: files.SkipSymlink, Detail: canary},
			{Path: "root-unknown", Reason: files.SkipSpecialFile, Detail: canary},
		}}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	result, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.False(t, result.complete)
	assert.Equal(t, []string{"legacy", "outside", "root-unknown", "special"}, publicationCapturePaths(result.observations))
	for _, observation := range result.observations {
		assert.Equal(t, model.ObservationUnknown, observation.State)
		assert.Nil(t, observation.Entry)
	}
	assert.NotContains(t, fmt.Sprint(result), canary)

	rootTarget := cloneSelectionTarget(fixture.target)
	rootTarget.Root.Exclude = []string{"**"}
	rootSkip := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{{Path: ".", Reason: files.SkipSpecialFile, Detail: canary}}}, nil
	})
	rootSelection := publicationCaptureSelectionFor(t, fixture, rootTarget, rootSkip)
	rootResult, err := capturePublicationFiles(context.Background(), rootSelection)
	require.NoError(t, err)
	assert.False(t, rootResult.complete)
	assert.Equal(t, []model.Observation{publicationCaptureUnknown(fixture.target.ID, ".")}, rootResult.observations)

	rootUnknown := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Observations: []model.Observation{publicationCaptureUnknown(fixture.target.ID, ".")}}, nil
	})
	unknownSelection := publicationCaptureSelectionFor(t, fixture, rootTarget, rootUnknown)
	unknown, err := capturePublicationFiles(context.Background(), unknownSelection)
	require.NoError(t, err)
	assert.False(t, unknown.complete)
	assert.Equal(t, []model.Observation{publicationCaptureUnknown(fixture.target.ID, ".")}, unknown.observations)
}

func TestCapturePublicationFilesKnownSkipsRejectPresentDescendants(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	reasons := []files.SkipReason{files.SkipSpecialFile, files.SkipExternalLink, files.SkipSymlink}
	for _, reason := range reasons {
		t.Run(string(reason), func(t *testing.T) {
			capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
				return files.Result{
					Observations: []model.Observation{publicationCaptureObservation(fixture.target.ID, "ancestor/child", model.FileRegular, []byte("not reachable"), 0o600)},
					Skipped:      []files.Skip{{Path: "ancestor", Reason: reason}},
				}, nil
			})
			selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
			captured, err := capturePublicationFiles(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
		})
	}

	tests := []struct {
		name   string
		result files.Result
	}{
		{
			name: "unknown observation descendant",
			result: files.Result{
				Observations: []model.Observation{publicationCaptureUnknown(fixture.target.ID, "ancestor/child")},
				Skipped:      []files.Skip{{Path: "ancestor", Reason: files.SkipExternalLink}},
			},
		},
		{
			name: "skip descendant",
			result: files.Result{Skipped: []files.Skip{
				{Path: "ancestor", Reason: files.SkipSpecialFile},
				{Path: "ancestor/child", Reason: files.SkipExternalLink},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) { return test.result, nil })
			selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
			captured, err := capturePublicationFiles(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
		})
	}
}

func TestCapturePublicationFilesMixedSiblingSkipAndPresentEntryRemainsIncomplete(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-mixed-skip-detail"
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{
			Observations: []model.Observation{publicationCaptureObservation(fixture.target.ID, "sibling", model.FileRegular, []byte("safe sibling"), 0o600)},
			Skipped:      []files.Skip{{Path: "uncertain", Reason: files.SkipExternalLink, Detail: canary}},
		}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.False(t, captured.complete)
	assert.Equal(t, []string{"sibling", "uncertain"}, publicationCapturePaths(captured.observations))
	assert.Equal(t, model.ObservationPresent, captured.observations[0].State)
	assert.Equal(t, []byte("safe sibling"), captured.observations[0].Entry.File.Content)
	assert.Equal(t, model.ObservationUnknown, captured.observations[1].State)
	assert.Nil(t, captured.observations[1].Entry)
	assert.NotContains(t, fmt.Sprint(captured), canary)
}

func TestCapturePublicationFilesEmptyIdentityPathsAreProviderInvalid(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	cases := []struct {
		name   string
		result files.Result
	}{
		{
			name: "empty observation path",
			result: files.Result{Observations: []model.Observation{
				publicationCaptureUnknown(fixture.target.ID, ""),
			}},
		},
		{
			name: "empty skip path",
			result: files.Result{Skipped: []files.Skip{
				{Path: "", Reason: files.SkipSpecialFile},
			}},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) { return test.result, nil })
			selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
			captured, err := capturePublicationFiles(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
		})
	}
}

func TestCapturePublicationFilesExclusionClaimsAreValidatedAndDetailsAreDiscarded(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-exclusion-detail-canary"
	known := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{{Path: ".cache", Reason: files.SkipExcluded, Detail: canary}}}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, known)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)
	assert.Empty(t, captured.observations)
	assert.NotContains(t, fmt.Sprint(captured), canary)

	falseClaim := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{{Path: "ordinary", Reason: files.SkipExcluded, Detail: canary}}}, nil
	})
	selection = publicationCaptureSelectionFor(t, fixture, fixture.target, falseClaim)
	captured, err = capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
	assert.NotContains(t, err.Error(), canary)

	invalidReason := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{{Path: "ordinary", Reason: files.SkipReason("future-reason"), Detail: canary}}}, nil
	})
	selection = publicationCaptureSelectionFor(t, fixture, fixture.target, invalidReason)
	captured, err = capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
}

func TestCapturePublicationFilesRejectsMalformedAndInconsistentProducerShapes(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	valid := publicationCaptureObservation(fixture.target.ID, "file", model.FileRegular, []byte("bytes"), 0o600)
	cases := []struct {
		name   string
		result files.Result
	}{
		{name: "wrong target", result: files.Result{Observations: []model.Observation{publicationCaptureObservation("other", "file", model.FileRegular, []byte("x"), 0o600)}}},
		{name: "wrong source", result: files.Result{Observations: []model.Observation{{State: model.ObservationUnknown, Identity: model.EntryKey{TargetID: fixture.target.ID, Source: model.SourceGNOME, SchemaID: "org.example.Test", SettingsPath: "/test/", SettingKey: "key"}}}}},
		{name: "identity differs from entry", result: files.Result{Observations: []model.Observation{{State: model.ObservationPresent, Identity: model.EntryKey{TargetID: fixture.target.ID, Source: model.SourceFiles, FilePath: "other"}, Entry: valid.Entry}}}},
		{name: "duplicate identity", result: files.Result{Observations: []model.Observation{valid, valid}}},
		{name: "present file ancestor", result: files.Result{Observations: []model.Observation{valid, publicationCaptureUnknown(fixture.target.ID, "file/child")}}},
		{name: "missing is not file producer output", result: files.Result{Observations: []model.Observation{{State: model.ObservationMissing, Identity: valid.Identity}}}},
		{name: "untracked is not file producer output", result: files.Result{Observations: []model.Observation{{State: model.ObservationUntracked, Identity: valid.Identity}}}},
		{name: "directory dot is not an entry", result: files.Result{Observations: []model.Observation{publicationCaptureObservation(fixture.target.ID, ".", model.FileDirectory, nil, 0o700)}}},
		{name: "empty file payload is required", result: files.Result{Observations: []model.Observation{{State: model.ObservationPresent, Identity: valid.Identity, Entry: &model.Entry{TargetID: fixture.target.ID, File: &model.FileEntry{Path: "file", State: model.FilePresent, Kind: model.FileRegular, Mode: 0o600}}}}}},
		{name: "duplicate skip and observation", result: files.Result{Observations: []model.Observation{valid}, Skipped: []files.Skip{{Path: "file", Reason: files.SkipSpecialFile}}}},
		{name: "invalid skip path", result: files.Result{Skipped: []files.Skip{{Path: "../escape", Reason: files.SkipSpecialFile}}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) { return test.result, nil })
			selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
			captured, err := capturePublicationFiles(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
		})
	}
}

func TestCapturePublicationFilesDotMatchingPatternsPreserveOrdinaryUnknownAndSkips(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{"?"}
	canary := "private-dot-matching-skip-detail"
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{
			Observations: []model.Observation{publicationCaptureUnknown(target.ID, "config")},
			Skipped:      []files.Skip{{Path: "ordinary/multichar", Reason: files.SkipSpecialFile, Detail: canary}},
		}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.False(t, captured.complete)
	assert.Equal(t, []string{"config", "ordinary/multichar"}, publicationCapturePaths(captured.observations))
	for _, observation := range captured.observations {
		assert.Equal(t, model.ObservationUnknown, observation.State)
		assert.Nil(t, observation.Entry)
	}
	assert.NotContains(t, fmt.Sprint(captured), canary)
}

func TestCapturePublicationFilesRejectsRootAndFalseExclusionClaims(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-false-exclusion-detail"
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{".*"}
	falseOrdinary := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{{Path: "config", Reason: files.SkipExcluded, Detail: canary}}}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, target, falseOrdinary)
	captured, err := capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
	assert.NotContains(t, err.Error(), canary)

	target.Root.Exclude = []string{"**"}
	falseRoot := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Skipped: []files.Skip{{Path: ".", Reason: files.SkipExcluded, Detail: canary}}}, nil
	})
	selection = publicationCaptureSelectionFor(t, fixture, target, falseRoot)
	captured, err = capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
	assert.NotContains(t, err.Error(), canary)
}

func TestCapturePublicationFilesFiltersExcludedObservationsThroughAncestors(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	target := cloneSelectionTarget(fixture.target)
	target.Root.Exclude = []string{"blocked"}
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Observations: []model.Observation{
			publicationCaptureObservation(target.ID, "blocked/nested/item", model.FileRegular, []byte("excluded"), 0o600),
		}}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)
	assert.Empty(t, captured.observations)
}

func TestCapturePublicationFilesExternalRepresentedLinkBecomesUnknown(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-external-link-target"
	observation := publicationCaptureObservation(fixture.target.ID, "link", model.FileSymlink, nil, 0)
	observation.Entry.File.LinkTarget = "../" + canary
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Observations: []model.Observation{observation}}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.False(t, captured.complete)
	require.Len(t, captured.observations, 1)
	assert.Equal(t, publicationCaptureUnknown(fixture.target.ID, "link"), captured.observations[0])
	assert.NotContains(t, fmt.Sprint(captured), canary)
}

func TestCapturePublicationFilesEnforcesProducerBoundsBeforeCopying(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	cases := []struct {
		name   string
		result files.Result
	}{
		{name: "count", result: files.Result{Observations: make([]model.Observation, files.DefaultBudget().MaxEntries+1)}},
		{name: "depth", result: files.Result{Observations: []model.Observation{publicationCaptureUnknown(fixture.target.ID, strings.Join(strings.Split(strings.Repeat("d/", 32)+"leaf", "/"), "/"))}}},
		{name: "file bytes", result: files.Result{Observations: []model.Observation{publicationCaptureObservation(fixture.target.ID, "large", model.FileRegular, make([]byte, files.DefaultBudget().MaxFileBytes+1), 0o600)}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) { return test.result, nil })
			selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
			captured, err := capturePublicationFiles(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, err, string(publicationCaptureReasonBounds))
		})
	}

	shared := make([]byte, files.DefaultBudget().MaxFileBytes)
	observations := make([]model.Observation, 33)
	for index := range observations {
		observations[index] = publicationCaptureObservation(fixture.target.ID, fmt.Sprintf("large-%02d", index), model.FileRegular, shared, 0o600)
	}
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Observations: observations}, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonBounds))
}

func TestCapturePublicationFilesBoundsCombinedCountSkipDepthAndObservationPath(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	observations := make([]model.Observation, files.DefaultBudget().MaxEntries)
	for index := range observations {
		observations[index] = publicationCaptureUnknown(fixture.target.ID, fmt.Sprintf("unknown-%05d", index))
	}
	result := files.Result{Observations: observations}
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) { return result, nil })
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	positive, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.Len(t, positive.observations, files.DefaultBudget().MaxEntries)
	assert.False(t, positive.complete)

	result.Skipped = []files.Skip{{Path: "extra-skip", Reason: files.SkipSpecialFile}}
	overLimit, err := capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, overLimit)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonBounds))

	tests := []struct {
		name   string
		result files.Result
	}{
		{
			name: "skip depth",
			result: files.Result{Skipped: []files.Skip{{
				Path: strings.Repeat("x/", 32) + "leaf", Reason: files.SkipSpecialFile,
			}}},
		},
		{
			name: "observation path length",
			result: files.Result{Observations: []model.Observation{
				publicationCaptureUnknown(fixture.target.ID, strings.Repeat("p", model.MaxRelativePathBytes+1)),
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundedCapture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) { return test.result, nil })
			boundedSelection := publicationCaptureSelectionFor(t, fixture, fixture.target, boundedCapture)
			captured, captureErr := capturePublicationFiles(context.Background(), boundedSelection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, captureErr, string(publicationCaptureReasonBounds))
		})
	}
}

func TestCapturePublicationFilesDetachesSelectionAndProducerOwnership(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	producerContent := []byte("detached")
	producer := files.Result{Observations: []model.Observation{publicationCaptureObservation(fixture.target.ID, "owned", model.FileRegular, producerContent, 0o600)}}
	calls := 0
	capture := publicationCapturePortFunc(func(_ context.Context, target config.Target, path string) (files.Result, error) {
		calls++
		assert.Equal(t, filepath.Join(fixture.paths.Home, "selected"), path)
		target.ID = "mutated"
		target.Root.Path = "mutated"
		target.Root.Exclude[0] = "mutated"
		return producer, nil
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	first, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	second, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, fixture.target.ID, selection.target.ID)
	assert.Equal(t, "selected", selection.target.Root.Path)
	assert.Equal(t, []string{".cache", "*.tmp", ".cache"}, selection.target.Root.Exclude)

	producerContent[0] = 'X'
	assert.Equal(t, []byte("detached"), first.observations[0].Entry.File.Content)
	assert.Equal(t, []byte("detached"), second.observations[0].Entry.File.Content)
	first.observations[0].Entry.File.Content[1] = 'Y'
	assert.Equal(t, []byte("detached"), second.observations[0].Entry.File.Content)
}

func TestCapturePublicationFilesRejectsObservedRootDrift(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	root := filepath.Join(fixture.paths.Home, "selected")
	oldRoot := filepath.Join(fixture.paths.Home, "selected-old")
	outside := t.TempDir()
	cases := []struct {
		name string
		port func() CapturePort
	}{
		{name: "replacement directory", port: func() CapturePort {
			return publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
				if err := os.Rename(root, oldRoot); err != nil {
					return files.Result{}, err
				}
				if err := os.Mkdir(root, 0o700); err != nil {
					return files.Result{}, err
				}
				return files.Result{}, nil
			})
		}},
		{name: "final anchor symlink", port: func() CapturePort {
			return publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
				if err := os.Rename(root, oldRoot); err != nil {
					return files.Result{}, err
				}
				if err := os.Symlink(outside, root); err != nil {
					return files.Result{}, err
				}
				return files.Result{}, nil
			})
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, os.RemoveAll(root))
			require.NoError(t, os.RemoveAll(oldRoot))
			require.NoError(t, os.Mkdir(root, 0o700))
			selection := publicationCaptureSelectionFor(t, fixture, fixture.target, test.port())
			captured, err := capturePublicationFiles(context.Background(), selection)
			assert.Equal(t, publicationCapture{}, captured)
			assertPublicationCaptureError(t, err, string(publicationCaptureReasonRoot))
			assert.True(t, fileExists(oldRoot))
		})
	}
}

func TestCapturePublicationFilesAllowsAtomicSingleFileReplacementInSameParent(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	filePath := filepath.Join(fixture.paths.Home, "single.ini")
	require.NoError(t, os.WriteFile(filePath, []byte("old"), 0o600))
	target := config.Target{ID: "single", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "single.ini", Kind: model.SelectionFile}}
	capture := publicationCapturePortFunc(func(ctx context.Context, selected config.Target, path string) (files.Result, error) {
		temporary := filepath.Join(fixture.paths.Home, "single-new")
		if err := os.WriteFile(temporary, []byte("new"), 0o640); err != nil {
			return files.Result{}, err
		}
		if err := os.Rename(temporary, path); err != nil {
			return files.Result{}, err
		}
		return (LocalFilesCapture{}).Capture(ctx, selected, path)
	})
	selection := publicationCaptureSelectionFor(t, fixture, target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)
	require.Len(t, captured.observations, 1)
	assert.Equal(t, []byte("new"), captured.observations[0].Entry.File.Content)
	assert.Equal(t, uint32(0o640), captured.observations[0].Entry.File.Mode)
}

func TestCapturePublicationFilesPreservesContainedDirectoryAliases(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	root := filepath.Join(fixture.paths.Home, "selected")
	require.NoError(t, os.WriteFile(filepath.Join(root, "value"), []byte("inside"), 0o600))
	alias := filepath.Join(fixture.paths.Home, "selected-alias")
	require.NoError(t, os.Symlink(root, alias))
	target := config.Target{ID: "aliased", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "selected-alias", Kind: model.SelectionDirectory}}
	selection := publicationCaptureSelectionFor(t, fixture, target, nil)
	captured, err := capturePublicationFiles(context.Background(), selection)
	require.NoError(t, err)
	assert.True(t, captured.complete)
	require.Len(t, captured.observations, 1)
	assert.Equal(t, "value", captured.observations[0].Identity.FilePath)
	assert.Equal(t, []byte("inside"), captured.observations[0].Entry.File.Content)
}

func TestCapturePublicationFilesClosedFailuresAndCancellation(t *testing.T) {
	fixture := newPublicationSelectionFixture(t)
	canary := "private-provider-error-canary"
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{Observations: []model.Observation{publicationCaptureObservation(fixture.target.ID, "partial", model.FileRegular, []byte("partial"), 0o600)}}, errors.New(canary)
	})
	selection := publicationCaptureSelectionFor(t, fixture, fixture.target, capture)
	captured, err := capturePublicationFiles(context.Background(), selection)
	assert.Equal(t, publicationCapture{}, captured)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonProvider))
	assert.NotContains(t, err.Error(), canary)
	assert.NotContains(t, err.Error(), fixture.paths.Home)

	calls := 0
	cancelledPort := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		calls++
		return files.Result{}, nil
	})
	selection = publicationCaptureSelectionFor(t, fixture, fixture.target, cancelledPort)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	captured, err = capturePublicationFiles(ctx, selection)
	assert.Equal(t, publicationCapture{}, captured)
	assert.ErrorIs(t, err, context.Canceled)
	assertPublicationCaptureError(t, err, string(publicationCaptureReasonCanceled))
	assert.Zero(t, calls)
}

func publicationCapturePaths(observations []model.Observation) []string {
	paths := make([]string, 0, len(observations))
	for _, observation := range observations {
		paths = append(paths, observation.Identity.FilePath)
	}
	return paths
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
