package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreviewPublicationTargetNoBaseAndEstablishedContinuity(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, nil)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
	assert.True(t, preview.Complete)
	assert.Equal(t, syncengine.PreviewStateUnchanged, publicationPreviewEntryFor(t, preview, "settings.ini").State)

	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	preview, disposition, err = PreviewPublicationTarget(context.Background(), fixture.request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.True(t, preview.Complete)
	assert.Equal(t, syncengine.PreviewReasonEqual, publicationPreviewEntryFor(t, preview, "settings.ini").Reason)

	publicationBaseAcceptSamePayloadSuccessor(t, fixture.accepted)
	successor := cloneAcceptedMaterialTestRequest(fixture.accepted.request)
	latest, present, err := fixture.accepted.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	fixture.request.ExpectedFloor = cloneServiceTestFloor(latest)
	fixture.request.SnapshotRecord = publicationBaseSuccessorRecord(t, fixture.accepted.request)
	fixture.request.Payload = bytes.Clone(successor.payload)
	preview, disposition, err = PreviewPublicationTarget(context.Background(), fixture.request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.True(t, preview.Complete)
	assert.Equal(t, syncengine.PreviewReasonEqual, publicationPreviewEntryFor(t, preview, "settings.ini").Reason)
}

func TestPreviewPublicationTargetClassifiesIndependentDisjointEditsAgainstRetainedBase(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	baseEntries := publicationPreviewFileEntries(target.ID, map[string]string{"local-only": "A", "remote-only": "A"})
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: baseEntries})
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	capturedEntries := clonePublicationProjectionEntriesForTest(baseEntries)
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		observations := make([]model.Observation, len(capturedEntries))
		for index := range capturedEntries {
			entry := clonePublicationProjectionEntry(capturedEntries[index])
			observations[index] = model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
		}
		return files.Result{Observations: observations}, nil
	})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	require.NoError(t, err)
	beforeBase := clonePublicationProjectionEntriesForTest(base.entries)

	remoteEntries := publicationPreviewFileEntries(target.ID, map[string]string{"local-only": "A", "remote-only": "B"})
	record, payload, floor := publicationPreviewAcceptSuccessor(t, accepted, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: remoteEntries})
	request.ExpectedFloor = floor
	request.SnapshotRecord = record
	request.Payload = payload
	capturedEntries = publicationPreviewFileEntries(target.ID, map[string]string{"local-only": "C", "remote-only": "A"})

	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.True(t, preview.Complete)
	localOnly := publicationPreviewEntryFor(t, preview, "local-only")
	assert.Equal(t, syncengine.ActionUpload, localOnly.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonLocalChanged, localOnly.Reason)
	remoteOnly := publicationPreviewEntryFor(t, preview, "remote-only")
	assert.Equal(t, syncengine.ActionDownload, remoteOnly.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonRemoteChanged, remoteOnly.Reason)
	assert.Equal(t, beforeBase, base.entries)
}

func TestPreviewPublicationTargetClassifiesPartialLocalStateAgainstRetainedBase(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	baseEntries := publicationPreviewFileEntries(target.ID, map[string]string{"already-remote": "A", "untouched": "A", "divergent": "A"})
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: baseEntries})
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	capturedEntries := clonePublicationProjectionEntriesForTest(baseEntries)
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		observations := make([]model.Observation, len(capturedEntries))
		for index := range capturedEntries {
			entry := clonePublicationProjectionEntry(capturedEntries[index])
			observations[index] = model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
		}
		return files.Result{Observations: observations}, nil
	})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	require.NoError(t, err)
	beforeBase := clonePublicationProjectionEntriesForTest(base.entries)

	remoteEntries := publicationPreviewFileEntries(target.ID, map[string]string{"already-remote": "B", "untouched": "B", "divergent": "B"})
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: remoteEntries}
	record, payload, floor := publicationPreviewAcceptSuccessor(t, accepted, snapshot)
	request.ExpectedFloor = floor
	request.SnapshotRecord = record
	request.Payload = payload
	capturedEntries = publicationPreviewFileEntries(target.ID, map[string]string{"already-remote": "B", "untouched": "A", "divergent": "C"})

	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.False(t, preview.Complete)
	alreadyRemote := publicationPreviewEntryFor(t, preview, "already-remote")
	assert.Equal(t, syncengine.ActionUnchanged, alreadyRemote.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonEqual, alreadyRemote.Reason)
	untouched := publicationPreviewEntryFor(t, preview, "untouched")
	assert.Equal(t, syncengine.ActionDownload, untouched.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonRemoteChanged, untouched.Reason)
	divergent := publicationPreviewEntryFor(t, preview, "divergent")
	assert.Equal(t, syncengine.ActionConflict, divergent.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonConflict, divergent.Reason)
	assert.Equal(t, beforeBase, base.entries)
}

func publicationPreviewFileEntries(targetID string, values map[string]string) []model.Entry {
	entries := make([]model.Entry, 0, len(values))
	for path, value := range values {
		entries = append(entries, model.Entry{TargetID: targetID, File: &model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileRegular, Content: []byte(value), Mode: 0o600}})
	}
	return entries
}

func TestPreviewPublicationTargetNoBaseInspectsLocalChangeWithoutEstablishing(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	filePath := filepath.Join(fixture.paths.Home, "synthetic", "settings.ini")
	require.NoError(t, os.WriteFile(filePath, []byte("local synthetic change"), 0o600))

	preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, nil)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
	assert.False(t, preview.Complete)
	entry := publicationPreviewEntryFor(t, preview, "settings.ini")
	assert.Equal(t, syncengine.ActionConflict, entry.DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonConflict, entry.Reason)
}

func TestPreviewPublicationTargetOmitsRawContentAndDoesNotRereadInputsAfterSelection(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	canary := []byte("preview-private-content-canary")
	remote := model.Entry{TargetID: target.ID, File: &model.FileEntry{Path: "secret.ini", State: model.FilePresent, Kind: model.FileRegular, Content: bytes.Clone(canary), Mode: 0o600}}
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: []model.Entry{remote}})
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "secret.ini"), canary, 0o600))
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, nil)
	require.NotEmpty(t, request.SnapshotRecord)
	require.NotEmpty(t, request.Payload)
	require.Len(t, request.Configuration.Targets, 1)
	require.NotNil(t, request.Configuration.Targets[0].Root)
	capture := publicationCapturePortFunc(func(ctx context.Context, selected config.Target, path string) (files.Result, error) {
		request.SnapshotRecord[0] ^= 0xff
		request.Payload[0] ^= 0xff
		request.Configuration.Targets[0].Root.Path = "changed-after-selection"
		return (LocalFilesCapture{}).Capture(ctx, selected, path)
	})
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request.Local = local

	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, nil)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
	assert.True(t, preview.Complete)
	encoded, err := json.Marshal(preview)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), string(canary))
}

func TestPreviewPublicationTargetRejectsMalformedBaseAndModeDrift(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	zero := &PublicationReconciliationBase{}
	preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, zero)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationPreviewStage), string(publicationPreviewReasonInput))

	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	request := fixture.request
	request.Configuration.Defaults.Mode = config.BackupOnly
	preview, disposition, err = PreviewPublicationTarget(context.Background(), request, base)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
}

func TestPreviewPublicationTargetStopsAtCurrentAndRetainedGNOMEUntrackedBarriers(t *testing.T) {
	t.Run("current projection", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		fixture := newPublicationPreviewGNOMEFixture(t, settings, true)
		settings.captureCalls = 0
		preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, nil)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		publicationBaseAssertFailure(t, err, string(publicationPreviewStage), string(publicationPreviewReasonUntracked))
		assert.Zero(t, settings.captureCalls)
	})

	t.Run("retained projection", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		fixture := newPublicationPreviewGNOMEFixture(t, settings, false)
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			require.NotEmpty(t, refs)
			return SettingsCapture{Entries: publicationBaseGNOMEEntries(targetID, refs)}, nil
		}
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		base.entries = append(base.entries, model.Entry{TargetID: fixture.target.ID, Setting: &model.SettingEntry{SchemaID: "org.example.Foreign", Path: "/synthetic/", Key: "foreign", State: model.SettingReset}})
		settings.captureCalls = 0
		preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, base)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		publicationBaseAssertFailure(t, err, string(publicationPreviewStage), string(publicationPreviewReasonUntracked))
		assert.Zero(t, settings.captureCalls)
	})
}

func TestPreviewPublicationTargetPreservesUnknownCoverageAndOutputPrivacy(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	fixture := newPublicationPreviewGNOMEFixture(t, settings, false)
	settings.capture = func(context.Context, string, []SettingRef) (SettingsCapture, error) { return SettingsCapture{}, nil }
	preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, nil)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
	assert.False(t, preview.Complete)
	assert.NotZero(t, preview.UnresolvedEntries)
	encoded, err := json.Marshal(preview)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "'synthetic'")
}

func TestPreviewPublicationTargetSnapshotsGNOMESelectionInputsBeforeFirstResolve(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	fixture := newPublicationPreviewGNOMEFixture(t, settings, false)
	refs, err := approvedSettings(context.Background(), settings, fixture.target)
	require.NoError(t, err)
	require.NotEmpty(t, refs)
	settings.capture = func(_ context.Context, targetID string, got []SettingRef) (SettingsCapture, error) {
		require.Equal(t, refs, got)
		require.NotEmpty(t, got)
		return SettingsCapture{Entries: publicationBaseGNOMEEntries(targetID, got)}, nil
	}
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	require.Len(t, base.entries, len(refs))
	require.NotNil(t, base.entries[0].Setting)
	require.NotNil(t, base.entries[0].Setting.Value)
	baseValue := base.entries[0].Setting.Value.Text
	updatedSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fixture.portable}, Entries: clonePublicationProjectionEntriesForTest(base.entries)}
	require.Len(t, updatedSnapshot.Entries, len(base.entries))
	require.NotNil(t, updatedSnapshot.Entries[0].Setting)
	require.NotNil(t, updatedSnapshot.Entries[0].Setting.Value)
	updatedSnapshot.Entries[0].Setting.Value = &model.VariantValue{Type: "s", Text: "'remote-new'"}
	successorRecord, successorPayload, successorFloor := publicationPreviewAcceptSuccessor(t, fixture.accepted, updatedSnapshot)
	fixture.request.ExpectedFloor = successorFloor
	fixture.request.SnapshotRecord = successorRecord
	fixture.request.Payload = successorPayload

	require.Len(t, base.entries, len(refs))
	require.NotNil(t, base.entries[0].Setting)
	require.NotNil(t, base.entries[0].Setting.Value)
	originalLocal := fixture.request.Local
	replacementCapture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		return files.Result{}, errors.New("replacement capture must not run")
	})
	replacementSettings := &publicationCaptureGNOMESettings{}
	replacement, err := NewPublicationLocalContext(fixture.paths, replacementCapture, replacementSettings)
	require.NoError(t, err)
	request := fixture.request
	require.Len(t, request.Configuration.Targets, 1)
	require.NotNil(t, request.Configuration.Targets[0].GNOMEPolicy)
	require.NotEmpty(t, request.Configuration.Targets[0].GNOMEPolicy.Categories)
	mutated := false
	settings.resolve = func(_ context.Context, _, _, _ string, _ int) (string, error) {
		if !mutated {
			mutated = true
			request.Configuration.Targets[0].GNOMEPolicy.Categories[0] = "appearance"
			originalLocal.settings = replacement.settings
			originalLocal.files = replacement.files
			base.entries[0].Setting.Value = &model.VariantValue{Type: "s", Text: "'callback-base-mutation'"}
		}
		return "/synthetic/", nil
	}
	settings.capture = func(_ context.Context, targetID string, got []SettingRef) (SettingsCapture, error) {
		require.NotEmpty(t, got)
		entry := publicationCaptureGNOMEEntry(targetID, got[0], model.SettingPresent, &model.VariantValue{Type: "s", Text: baseValue})
		return SettingsCapture{Entries: []model.Entry{entry}}, nil
	}
	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	require.NoError(t, err)
	assert.True(t, mutated)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.False(t, preview.Complete)
	require.Len(t, preview.Targets, 1)
	require.NotEmpty(t, preview.Targets[0].Entries)
	assert.Equal(t, syncengine.ActionDownload, preview.Targets[0].Entries[0].DecisionAction)
	assert.Equal(t, syncengine.PreviewReasonRemoteChanged, preview.Targets[0].Entries[0].Reason)
	assert.Equal(t, "'callback-base-mutation'", base.entries[0].Setting.Value.Text)
	assert.Same(t, replacementSettings, originalLocal.settings)
}

func TestPreviewPublicationTargetRechecksAcceptedFloorAfterCapture(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	request := fixture.request
	capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		captured, err := (LocalFilesCapture{}).Capture(ctx, target, path)
		if err != nil {
			return files.Result{}, err
		}
		publicationBaseAcceptSamePayloadSuccessor(t, fixture.accepted)
		return captured, nil
	})
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)
	request.Local = local
	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, nil)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationStagePosition), string(publicationReasonPosition))
}

func TestPreviewPublicationTargetBoundsThreeViewsBeforeReconcile(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	remote := publicationBaseEmptyRegularEntries(target.ID, 0, publicationBaseMaxUnionKeys)
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: remote})
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	localEntry := model.Entry{TargetID: target.ID, File: &model.FileEntry{Path: "local-disjoint", State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}, Mode: 0o600}}
	calls := 0
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		calls++
		return files.Result{Observations: []model.Observation{{State: model.ObservationPresent, Identity: localEntry.Identity(), Entry: &localEntry}}}, nil
	})
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, nil)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationPreviewStage), string(publicationPreviewReasonBounds))
	assert.Equal(t, 1, calls)
}

func TestPreviewPublicationTargetIncludesRetainedBaseInKeyUnionBound(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	baseEntries := publicationBaseEmptyRegularEntries("base", 0, 10001)
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: baseEntries})
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	capturedEntries := clonePublicationProjectionEntriesForTest(baseEntries)
	captureCalls := 0
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		captureCalls++
		observations := make([]model.Observation, len(capturedEntries))
		for index := range capturedEntries {
			entry := clonePublicationProjectionEntry(capturedEntries[index])
			observations[index] = model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
		}
		return files.Result{Observations: observations}, nil
	})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	require.NoError(t, err)
	require.Len(t, base.entries, 10001)
	beforeBase := clonePublicationProjectionEntriesForTest(base.entries)

	remoteEntries := publicationBaseEmptyRegularEntries("successor", 0, 10000)
	record, payload, floor := publicationPreviewAcceptSuccessor(t, accepted, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: remoteEntries})
	request.ExpectedFloor = floor
	request.SnapshotRecord = record
	request.Payload = payload
	capturedEntries = clonePublicationProjectionEntriesForTest(remoteEntries)

	localView := syncengine.LocalView{Entries: capturedEntries, Coverage: []string{target.ID}}
	assert.True(t, publicationBaseWithinBounds(nil, localView, remoteEntries, nil))
	assert.False(t, publicationBaseWithinBounds(base.entries, localView, remoteEntries, nil))

	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationPreviewStage), string(publicationPreviewReasonBounds))
	assert.Equal(t, 2, captureCalls)
	assert.Equal(t, beforeBase, base.entries)
}

func TestPreviewPublicationTargetReturnsZeroOnCancellation(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		fixture := newPublicationBaseTestFixture(t, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		preview, disposition, err := PreviewPublicationTarget(ctx, fixture.request, nil)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("canceled during capture", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
			captured, err := (LocalFilesCapture{}).Capture(ctx, target, path)
			if err != nil {
				return files.Result{}, err
			}
			cancel()
			return captured, nil
		})
		fixture := newPublicationBaseTestFixture(t, capture)
		preview, disposition, err := PreviewPublicationTarget(ctx, fixture.request, nil)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

type publicationPreviewGNOMEFixture struct {
	accepted acceptedMaterialTestFixture
	paths    platform.Paths
	target   config.Target
	portable model.Target
	request  PublicationReconciliationRequest
}

func newPublicationPreviewGNOMEFixture(t *testing.T, settings *publicationCaptureGNOMESettings, untracked bool) publicationPreviewGNOMEFixture {
	t.Helper()
	selectionFixture := newPublicationSelectionFixture(t)
	target := newApprovedPublicationGNOMETarget(t, "synthetic-desktop", []string{"clock"})
	portable, err := target.Model()
	require.NoError(t, err)
	refs, err := approvedSettings(context.Background(), settings, target)
	require.NoError(t, err)
	require.NotEmpty(t, refs)
	entries := publicationBaseGNOMEEntries(target.ID, refs)
	if untracked {
		entries = append(entries, model.Entry{TargetID: target.ID, Setting: &model.SettingEntry{SchemaID: "org.example.Foreign", Path: "/synthetic/", Key: "foreign", State: model.SettingReset}})
	}
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: entries})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, selectionFixture.capture, settings)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	return publicationPreviewGNOMEFixture{accepted: accepted, paths: selectionFixture.paths, target: target, portable: portable, request: request}
}

func publicationPreviewEntryFor(t *testing.T, preview syncengine.Preview, path string) syncengine.PreviewEntry {
	t.Helper()
	require.Len(t, preview.Targets, 1)
	for _, entry := range preview.Targets[0].Entries {
		if entry.Key.FilePath == path {
			return entry
		}
	}
	require.FailNow(t, "preview entry not found")
	return syncengine.PreviewEntry{}
}

func publicationPreviewAcceptSuccessor(t *testing.T, fixture acceptedMaterialTestFixture, snapshot model.Snapshot) ([]byte, []byte, publicationstate.Floor) {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	old, err := publication.DecodeSnapshot(fixture.request.snapshotRecord)
	require.NoError(t, err)
	parentCID, err := publication.RecordCID(fixture.request.snapshotRecord)
	require.NoError(t, err)
	old.PublicationSeq++
	old.Parent = bytes.Clone(parentCID)
	old.PublicationID[15]++
	old.Blob = publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))}
	record, err := publication.EncodeSnapshot(old)
	require.NoError(t, err)
	cid, err := publication.RecordCID(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(old.PublicationSeq)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: fixture.request.binding.Vault, PublicationSeq: old.PublicationSeq, SnapshotCID: cid, BlobCID: blobCID})
	require.NoError(t, err)
	observation := publicationstate.Observation{
		Origin: fixture.request.binding, SuppliedContext: fixture.request.expectedFloor.SuppliedContext, Head: head,
		Snapshots: []publicationstate.SnapshotBlock{{Key: fixture.request.expectedFloor.SnapshotKey, Raw: bytes.Clone(fixture.request.snapshotRecord)}, {Key: key, Raw: bytes.Clone(record)}},
	}
	proposal, err := fixture.store.Prepare(context.Background(), publicationstate.ModeAdvance, observation, packed.Payload)
	require.NoError(t, err)
	floor, err := fixture.store.Accept(context.Background(), publicationstate.ModeAdvance, proposal.StateToken, observation, packed.Payload, [32]byte{})
	require.NoError(t, err)
	return record, packed.Payload, floor
}
