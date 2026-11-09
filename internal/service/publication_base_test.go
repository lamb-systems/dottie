package service

import (
	"bytes"
	"context"
	"fmt"
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

type publicationBaseTestFixture struct {
	accepted acceptedMaterialTestFixture
	paths    platform.Paths
	target   config.Target
	config   config.Config
	local    *PublicationLocalContext
	request  PublicationReconciliationRequest
}

func newPublicationBaseTestFixture(t *testing.T, capture CapturePort) publicationBaseTestFixture {
	t.Helper()
	accepted := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{
		ID: "synthetic-files", Source: model.SourceFiles,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory},
	}
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.ini"), []byte("synthetic accepted publication"), 0o600))
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := PublicationReconciliationRequest{
		Store: accepted.store, Binding: accepted.request.binding,
		ExpectedFloor:  cloneServiceTestFloor(accepted.request.expectedFloor),
		SnapshotRecord: bytes.Clone(accepted.request.snapshotRecord), Payload: bytes.Clone(accepted.request.payload),
		Configuration: configuration, TargetID: target.ID, Local: local,
	}
	return publicationBaseTestFixture{accepted: accepted, paths: selectionFixture.paths, target: target, config: configuration, local: local, request: request}
}

func publicationBaseSelectCurrent(t *testing.T, request PublicationReconciliationRequest) (acceptedPublicationMaterial, publicationSelection) {
	t.Helper()
	material, err := validateAcceptedPublication(context.Background(), acceptedPublicationRequest{
		store: request.Store, binding: request.Binding, expectedFloor: request.ExpectedFloor,
		snapshotRecord: request.SnapshotRecord, payload: request.Payload,
	})
	require.NoError(t, err)
	var portable model.Target
	found := false
	for _, target := range material.snapshot.Targets {
		if target.ID == request.TargetID {
			portable = target
			found = true
			break
		}
	}
	require.True(t, found)
	selection, err := selectPublicationTarget(context.Background(), snapshotPublicationLocalContext(request.Local), request.Configuration, request.TargetID, portable)
	require.NoError(t, err)
	return material, selection
}

func publicationBaseAssertFailure(t *testing.T, err error, stage, reason string) {
	t.Helper()
	assertPublicationReconciliationError(t, err, stage, reason)
}

func TestEstablishLocalReconciliationBaseRequiresCompleteConvergenceAndDetachesInputs(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	originalRecord := bytes.Clone(fixture.request.SnapshotRecord)
	ctx := context.Background()
	beforeFloor, present, err := fixture.accepted.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	beforeHistory, err := fixture.accepted.store.History(ctx, 0, 10)
	require.NoError(t, err)

	base, err := EstablishLocalReconciliationBase(ctx, fixture.request)
	require.NoError(t, err)
	require.NotNil(t, base)
	assert.Equal(t, fixture.request.ExpectedFloor, base.position.floor)
	assert.Equal(t, fixture.request.SnapshotRecord, base.position.snapshotRecord)
	require.Len(t, base.entries, 1)
	require.NotNil(t, base.entries[0].File)
	assert.Equal(t, []byte("synthetic accepted publication"), base.entries[0].File.Content)
	assert.Equal(t, fixture.target, base.selection.target)
	assert.Same(t, fixture.local.affinity, base.selection.affinity.token)
	assert.Equal(t, fixture.paths, base.selection.paths)

	firstEntries := clonePublicationProjectionEntriesForTest(base.entries)
	second, err := EstablishLocalReconciliationBase(ctx, fixture.request)
	require.NoError(t, err)
	assert.Equal(t, firstEntries, second.entries)
	assert.Equal(t, base.position.floor, second.position.floor)
	assert.Equal(t, base.position.snapshotRecord, second.position.snapshotRecord)

	fixture.request.SnapshotRecord[0] ^= 0xff
	fixture.request.Payload[0] ^= 0xff
	fixture.request.ExpectedFloor.Head[0] ^= 0xff
	fixture.request.Configuration.Targets[0].Root.Path = "changed-after-establishment"
	assert.Equal(t, []byte("synthetic accepted publication"), base.entries[0].File.Content)
	assert.Equal(t, []byte("synthetic accepted publication"), second.entries[0].File.Content)
	assert.Equal(t, "synthetic", base.selection.target.Root.Path)
	assert.Equal(t, "synthetic", base.selection.portable.Root.Path)
	assert.Equal(t, fixture.accepted.request.expectedFloor, base.position.floor)
	assert.Equal(t, originalRecord, base.position.snapshotRecord)
	assert.Equal(t, originalRecord, second.position.snapshotRecord)
	base.position.snapshotRecord[0] ^= 0xff
	assert.Equal(t, originalRecord, second.position.snapshotRecord)

	afterFloor, present, err := fixture.accepted.store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	afterHistory, err := fixture.accepted.store.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, beforeFloor, afterFloor)
	assert.Equal(t, beforeHistory, afterHistory)
}

func TestEstablishLocalReconciliationBaseClonesRecordBeforeCaptureCallback(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	request := fixture.request
	originalRecord := bytes.Clone(request.SnapshotRecord)
	capture := publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		captured, err := (LocalFilesCapture{}).Capture(ctx, target, path)
		if err != nil {
			return files.Result{}, err
		}
		request.SnapshotRecord[0] ^= 0xff
		return captured, nil
	})
	local, err := NewPublicationLocalContext(fixture.paths, capture, nil)
	require.NoError(t, err)
	request.Local = local

	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, base)
	assert.Equal(t, originalRecord, base.position.snapshotRecord)
	assert.True(t, validPublicationBasePosition(base.position))

	eligibilityRequest := request
	eligibilityRequest.SnapshotRecord = bytes.Clone(originalRecord)
	current, selection := publicationBaseSelectCurrent(t, eligibilityRequest)
	require.NoError(t, checkBaseEligibility(context.Background(), fixture.accepted.store, base.position, base.selection, current.floor, selection))
}

func TestEstablishLocalReconciliationBaseRejectsMissingAndUnboundedRecordBeforeCapture(t *testing.T) {
	calls := 0
	capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
		calls++
		return files.Result{}, nil
	})
	fixture := newPublicationBaseTestFixture(t, capture)

	t.Run("missing target", func(t *testing.T) {
		request := fixture.request
		request.TargetID = "not-in-snapshot"
		base, err := EstablishLocalReconciliationBase(context.Background(), request)
		assert.Nil(t, base)
		publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonTarget))
		assert.Zero(t, calls)
	})

	for _, test := range []struct {
		name   string
		record []byte
	}{
		{name: "empty", record: []byte{}},
		{name: "over maximum", record: make([]byte, publication.MaxRecordBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.request
			request.SnapshotRecord = test.record
			base, err := EstablishLocalReconciliationBase(context.Background(), request)
			assert.Nil(t, base)
			publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonInput))
			assert.Zero(t, calls)
		})
	}
}

func TestEstablishLocalReconciliationBaseRefusesDivergentAndUnknownCapture(t *testing.T) {
	t.Run("divergent content", func(t *testing.T) {
		fixture := newPublicationBaseTestFixture(t, nil)
		path := filepath.Join(fixture.paths.Home, "synthetic", "settings.ini")
		require.NoError(t, os.WriteFile(path, []byte("local divergence"), 0o600))
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		assert.Nil(t, base)
		publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonConvergence))
	})

	t.Run("divergent mode", func(t *testing.T) {
		fixture := newPublicationBaseTestFixture(t, nil)
		path := filepath.Join(fixture.paths.Home, "synthetic", "settings.ini")
		require.NoError(t, os.Chmod(path, 0o640))
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		assert.Nil(t, base)
		publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonConvergence))
	})

	t.Run("unknown file observation", func(t *testing.T) {
		capture := publicationCapturePortFunc(func(_ context.Context, selected config.Target, _ string) (files.Result, error) {
			key := model.EntryKey{TargetID: selected.ID, Source: model.SourceFiles, FilePath: "settings.ini"}
			return files.Result{Observations: []model.Observation{{State: model.ObservationUnknown, Identity: key}}}, nil
		})
		fixture := newPublicationBaseTestFixture(t, capture)
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		assert.Nil(t, base)
		publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonConvergence))
	})
}

func TestEstablishLocalReconciliationBaseRefusesUntrackedGNOMEBeforeCapture(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	fixture := newPublicationSelectionFixture(t)
	target := newApprovedPublicationGNOMETarget(t, "synthetic-desktop", []string{"clock"})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	portable, err := target.Model()
	require.NoError(t, err)
	refs, err := approvedSettings(context.Background(), settings, target)
	require.NoError(t, err)
	entries := publicationBaseGNOMEEntries(target.ID, refs)
	foreign := model.Entry{TargetID: target.ID, Setting: &model.SettingEntry{SchemaID: "org.example.Foreign", Path: "/synthetic/", Key: "foreign", State: model.SettingReset}}
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: append(entries, foreign)}
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, snapshot)
	local, err := NewPublicationLocalContext(fixture.paths, nil, settings)
	require.NoError(t, err)
	settings.captureCalls = 0
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)

	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	assert.Nil(t, base)
	publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonUntracked))
	assert.Zero(t, settings.captureCalls)
	assert.Zero(t, settings.backendCalls)
}

func TestEstablishLocalReconciliationBaseRefusesOmittedGNOMEObservationAndAcceptsPresentReset(t *testing.T) {
	settings := &publicationCaptureGNOMESettings{}
	selectionFixture := newPublicationSelectionFixture(t)
	target := newApprovedPublicationGNOMETarget(t, "synthetic-desktop", []string{"clock"})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	portable, err := target.Model()
	require.NoError(t, err)
	refs, err := approvedSettings(context.Background(), settings, target)
	require.NoError(t, err)
	entries := publicationBaseGNOMEEntries(target.ID, refs)
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: entries}
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, snapshot)
	local, err := NewPublicationLocalContext(selectionFixture.paths, nil, settings)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)

	settings.capture = func(_ context.Context, _ string, got []SettingRef) (SettingsCapture, error) {
		assert.Equal(t, refs, got)
		return SettingsCapture{Entries: clonePublicationProjectionEntriesForTest(entries[:len(entries)-1])}, nil
	}
	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	assert.Nil(t, base)
	publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonConvergence))

	settings.capture = func(_ context.Context, _ string, got []SettingRef) (SettingsCapture, error) {
		assert.Equal(t, refs, got)
		return SettingsCapture{Entries: clonePublicationProjectionEntriesForTest(entries)}, nil
	}
	base, err = EstablishLocalReconciliationBase(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, base)
	assert.Equal(t, entries, base.entries)
	assert.True(t, base.selection.target.GNOMEPolicy != nil)
}

func TestEstablishLocalReconciliationBaseRechecksFloorAfterCapture(t *testing.T) {
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

	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	assert.Nil(t, base)
	publicationBaseAssertFailure(t, err, "position", "position_changed")
}

func TestCheckBaseEligibilityRequiresExactPositionAndSelection(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	material, selection := publicationBaseSelectCurrent(t, fixture.request)
	ctx := context.Background()

	require.NoError(t, checkBaseEligibility(ctx, fixture.accepted.store, base.position, base.selection, material.floor, selection))

	independent, err := NewPublicationLocalContext(fixture.paths, nil, nil)
	require.NoError(t, err)
	independentSelection, err := selectPublicationTarget(ctx, independent, fixture.config, fixture.target.ID, selection.portable)
	require.NoError(t, err)
	err = checkBaseEligibility(ctx, fixture.accepted.store, base.position, base.selection, material.floor, independentSelection)
	require.Error(t, err)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))

	for _, test := range []struct {
		name   string
		change func(*config.Config)
	}{
		{name: "mode drift", change: func(configuration *config.Config) { configuration.Targets[0].Mode = config.BackupOnly }},
		{name: "exclude drift", change: func(configuration *config.Config) { configuration.Targets[0].Root.Exclude = []string{"settings.ini"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := cloneSelectionTestConfig(fixture.config)
			test.change(&configuration)
			changed, err := selectPublicationTarget(ctx, snapshotPublicationLocalContext(fixture.local), configuration, fixture.target.ID, selection.portable)
			require.NoError(t, err)
			err = checkBaseEligibility(ctx, fixture.accepted.store, base.position, base.selection, material.floor, changed)
			require.Error(t, err)
			publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
		})
	}

	zero := publicationBasePosition{}
	err = checkBaseEligibility(ctx, fixture.accepted.store, zero, base.selection, material.floor, selection)
	require.Error(t, err)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilityInput))
}

func TestCheckBaseEligibilityAllowsReopenAndAuditedSuccessorWithHistoryMore(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	current, selection := publicationBaseSelectCurrent(t, fixture.request)

	page, err := fixture.accepted.store.History(context.Background(), base.position.floor.Revision-1, 1)
	require.NoError(t, err)
	assert.False(t, page.HasMore)
	require.NoError(t, checkBaseEligibility(context.Background(), fixture.accepted.store, base.position, base.selection, current.floor, selection))

	publicationBaseAcceptSamePayloadSuccessor(t, fixture.accepted)
	successorRequest := cloneAcceptedMaterialTestRequest(fixture.accepted.request)
	latest, present, err := fixture.accepted.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	successorRecord := publicationBaseSuccessorRecord(t, fixture.accepted.request)
	successorRequest.expectedFloor = cloneServiceTestFloor(latest)
	successorRequest.snapshotRecord = successorRecord
	current, err = validateAcceptedPublication(context.Background(), successorRequest)
	require.NoError(t, err)
	selection, err = selectPublicationTarget(context.Background(), snapshotPublicationLocalContext(fixture.local), fixture.config, fixture.target.ID, current.snapshot.Targets[0])
	require.NoError(t, err)
	page, err = fixture.accepted.store.History(context.Background(), base.position.floor.Revision-1, 1)
	require.NoError(t, err)
	assert.True(t, page.HasMore)
	require.NoError(t, checkBaseEligibility(context.Background(), fixture.accepted.store, base.position, base.selection, current.floor, selection))

	directory := fixture.accepted.directory
	binding := fixture.accepted.request.binding
	require.NoError(t, fixture.accepted.store.Close())
	reopened, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	require.NoError(t, checkBaseEligibility(context.Background(), reopened, base.position, base.selection, current.floor, selection))
}

func TestCheckBaseEligibilityRejectsRecreatedStoreAndChangedContext(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	current, selection := publicationBaseSelectCurrent(t, fixture.request)

	recreated := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	err = checkBaseEligibility(context.Background(), recreated.store, base.position, base.selection, recreated.request.expectedFloor, selection)
	require.Error(t, err)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilityLineage))

	changedLocal, err := NewPublicationLocalContext(fixture.paths, nil, nil)
	require.NoError(t, err)
	fixture.local.affinity = changedLocal.affinity
	changedSelection, err := selectPublicationTarget(context.Background(), fixture.local, fixture.config, fixture.target.ID, selection.portable)
	require.NoError(t, err)
	err = checkBaseEligibility(context.Background(), fixture.accepted.store, base.position, base.selection, current.floor, changedSelection)
	require.Error(t, err)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
}

func TestPublicationBaseBudgetBoundsDistinctKeysAcrossViewsAndFileContent(t *testing.T) {
	singleView := publicationBaseEmptyRegularEntries("single", 0, publicationBaseMaxUnionKeys+1)
	assert.True(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: singleView[:publicationBaseMaxUnionKeys]}, nil, nil))
	assert.False(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: singleView}, nil, nil))

	overlapping := publicationBaseEmptyRegularEntries("overlap", 0, publicationBaseMaxUnionKeys/2+1)
	assert.True(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: overlapping}, overlapping, nil))
	localDisjoint := publicationBaseEmptyRegularEntries("local", 0, publicationBaseMaxUnionKeys/2)
	remoteDisjoint := publicationBaseEmptyRegularEntries("remote", 0, publicationBaseMaxUnionKeys/2+1)
	assert.False(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: localDisjoint}, remoteDisjoint, nil))

	oversized := model.Entry{TargetID: "files", File: &model.FileEntry{Path: "oversized", State: model.FilePresent, Kind: model.FileRegular, Content: make([]byte, publicationBaseMaxFileBytes+1)}}
	assert.False(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: []model.Entry{oversized}}, nil, nil))

	shared := make([]byte, publicationBaseMaxFileBytes)
	repeated := make([]model.Entry, publicationBaseMaxTotalBytes/publicationBaseMaxFileBytes+1)
	for index := range repeated {
		repeated[index] = model.Entry{TargetID: "files", File: &model.FileEntry{Path: fmt.Sprintf("content-%05d", index), State: model.FilePresent, Kind: model.FileRegular, Content: shared}}
	}
	assert.False(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: repeated}, nil, nil))
	assert.True(t, publicationBaseWithinBounds(nil, syncengine.LocalView{Entries: repeated[:len(repeated)-1]}, nil, nil))
}

func TestEstablishLocalReconciliationBaseBoundsTwentyThousandEntryUnionBeforeReconcile(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	remoteEntries := publicationBaseEmptyRegularEntries("remote", 0, publicationBaseMaxUnionKeys)
	portable, err := target.Model()
	require.NoError(t, err)
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: remoteEntries}
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, snapshot)

	calls := 0
	capture := publicationCapturePortFunc(func(_ context.Context, selected config.Target, _ string) (files.Result, error) {
		calls++
		entry := model.Entry{TargetID: selected.ID, File: &model.FileEntry{Path: "local-disjoint", State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}, Mode: 0o600}}
		return files.Result{Observations: []model.Observation{{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}}}, nil
	})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)

	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	assert.Nil(t, base)
	publicationBaseAssertFailure(t, err, "base", string(publicationBaseReasonBounds))
	assert.Equal(t, 1, calls)
}

func publicationBaseEmptyRegularEntries(prefix string, start, count int) []model.Entry {
	entries := make([]model.Entry, count)
	for index := range entries {
		entries[index] = model.Entry{TargetID: "synthetic-files", File: &model.FileEntry{
			Path: fmt.Sprintf("%s-%05d", prefix, start+index), State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}, Mode: 0o600,
		}}
	}
	return entries
}

func TestPublicationBaseErrorsAreZeroSafeAndCancellationAware(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	base, err := EstablishLocalReconciliationBase(context.Background(), PublicationReconciliationRequest{})
	assert.Nil(t, base)
	publicationBaseAssertFailure(t, err, string(publicationBaseStage), string(publicationBaseReasonInput))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	base, err = EstablishLocalReconciliationBase(ctx, fixture.request)
	assert.Nil(t, base)
	assert.ErrorIs(t, err, context.Canceled)
	assert.NotContains(t, err.Error(), fixture.request.Binding.AccountDID)
	assert.NotContains(t, err.Error(), "synthetic accepted publication")
}

func TestEstablishLocalReconciliationBasePreservesCancellationDuringCapture(t *testing.T) {
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

	base, err := EstablishLocalReconciliationBase(ctx, fixture.request)
	assert.Nil(t, base)
	assert.ErrorIs(t, err, context.Canceled)
	publicationBaseAssertFailure(t, err, "capture", "canceled")
	assert.NotContains(t, err.Error(), fixture.request.Binding.AccountDID)
}

func publicationBaseRequestFor(t *testing.T, accepted acceptedMaterialTestFixture, configuration config.Config, targetID string, local *PublicationLocalContext) PublicationReconciliationRequest {
	t.Helper()
	return PublicationReconciliationRequest{
		Store: accepted.store, Binding: accepted.request.binding,
		ExpectedFloor:  cloneServiceTestFloor(accepted.request.expectedFloor),
		SnapshotRecord: bytes.Clone(accepted.request.snapshotRecord), Payload: bytes.Clone(accepted.request.payload),
		Configuration: configuration, TargetID: targetID, Local: local,
	}
}

func publicationBaseGNOMEEntries(targetID string, refs []SettingRef) []model.Entry {
	entries := make([]model.Entry, 0, len(refs))
	for index, ref := range refs {
		if index == 0 {
			entries = append(entries, publicationCaptureGNOMEEntry(targetID, ref, model.SettingPresent, &model.VariantValue{Type: "s", Text: "'synthetic'"}))
		} else {
			entries = append(entries, publicationCaptureGNOMEEntry(targetID, ref, model.SettingReset, nil))
		}
	}
	return entries
}

func newAcceptedSnapshotForPublicationBaseTest(t *testing.T, snapshot model.Snapshot) acceptedMaterialTestFixture {
	t.Helper()
	binding := publicationstate.Binding{AccountDID: "did:plc:abcdefghijklmnopqrstuvwx", Backend: publicationstate.BackendPublicRepo, Repository: "at://did:plc:abcdefghijklmnopqrstuvwx", Vault: [32]byte{0x41, 0x52, 0x63}}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: [16]byte{0x25, 0x71}, Parent: []byte{}, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))}}
	recordRaw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(recordRaw)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: 0, SnapshotCID: recordCID, BlobCID: blobCID})
	require.NoError(t, err)
	observation := publicationstate.Observation{
		Origin: binding, SuppliedContext: publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}, Head: head,
		Snapshots: []publicationstate.SnapshotBlock{{Key: "0000000000000000", Raw: bytes.Clone(recordRaw)}},
	}
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	proposal, err := store.Prepare(context.Background(), publicationstate.ModeFirstUse, observation, packed.Payload)
	require.NoError(t, err)
	floor, err := store.Accept(context.Background(), publicationstate.ModeFirstUse, proposal.StateToken, observation, packed.Payload, proposal.Confirmation)
	require.NoError(t, err)
	return acceptedMaterialTestFixture{store: store, directory: directory, request: acceptedPublicationRequest{
		store: store, binding: binding, expectedFloor: cloneServiceTestFloor(floor), snapshotRecord: bytes.Clone(recordRaw), payload: bytes.Clone(packed.Payload),
	}}
}

func publicationBaseAcceptSamePayloadSuccessor(t *testing.T, fixture acceptedMaterialTestFixture) {
	t.Helper()
	record := publicationBaseSuccessorRecord(t, fixture.request)
	cid, err := publication.RecordCID(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(1)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{SchemaVersion: publication.SchemaVersion, Vault: fixture.request.binding.Vault, PublicationSeq: 1, SnapshotCID: cid, BlobCID: bytes.Clone(fixture.request.expectedFloor.BlobCID)})
	require.NoError(t, err)
	observation := publicationstate.Observation{
		Origin: fixture.request.binding, SuppliedContext: fixture.request.expectedFloor.SuppliedContext, Head: head,
		Snapshots: []publicationstate.SnapshotBlock{{Key: fixture.request.expectedFloor.SnapshotKey, Raw: bytes.Clone(fixture.request.snapshotRecord)}, {Key: key, Raw: record}},
	}
	proposal, err := fixture.store.Prepare(context.Background(), publicationstate.ModeAdvance, observation, fixture.request.payload)
	require.NoError(t, err)
	_, err = fixture.store.Accept(context.Background(), publicationstate.ModeAdvance, proposal.StateToken, observation, fixture.request.payload, [32]byte{})
	require.NoError(t, err)
}

func publicationBaseSuccessorRecord(t *testing.T, request acceptedPublicationRequest) []byte {
	t.Helper()
	old, err := publication.DecodeSnapshot(request.snapshotRecord)
	require.NoError(t, err)
	parentCID, err := publication.RecordCID(request.snapshotRecord)
	require.NoError(t, err)
	old.PublicationSeq = request.expectedFloor.Sequence + 1
	old.Parent = bytes.Clone(parentCID)
	old.PublicationID[15]++
	raw, err := publication.EncodeSnapshot(old)
	require.NoError(t, err)
	return raw
}

func clonePublicationProjectionEntriesForTest(entries []model.Entry) []model.Entry {
	out := make([]model.Entry, len(entries))
	for index, entry := range entries {
		out[index] = clonePublicationProjectionEntry(entry)
	}
	return out
}
