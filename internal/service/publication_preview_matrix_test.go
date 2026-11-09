package service

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreviewPublicationTargetKeepsOlderBaseEligibleAfterReopen(t *testing.T) {
	fixture := newPublicationBaseTestFixture(t, nil)
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	before := publicationPreviewBaseWitnessForTest(t, base)
	assert.Equal(t, fixture.accepted.request.expectedFloor, before.floor)
	assert.Equal(t, fixture.accepted.request.snapshotRecord, before.snapshotRecord)
	oldFloor := cloneServiceTestFloor(fixture.request.ExpectedFloor)

	publicationBaseAcceptSamePayloadSuccessor(t, fixture.accepted)
	successorRecord := publicationBaseSuccessorRecord(t, fixture.accepted.request)
	currentFloor, present, err := fixture.accepted.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	fixture.request.ExpectedFloor = cloneServiceTestFloor(currentFloor)
	fixture.request.SnapshotRecord = bytes.Clone(successorRecord)
	fixture.request.Payload = bytes.Clone(fixture.accepted.request.payload)
	assert.Equal(t, oldFloor.DatabaseID, currentFloor.DatabaseID)
	assert.Equal(t, oldFloor.Generation, currentFloor.Generation)
	assert.Greater(t, currentFloor.Revision, oldFloor.Revision)

	directory := fixture.accepted.directory
	binding := fixture.request.Binding
	require.NoError(t, fixture.accepted.store.Close())
	reopened, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	fixture.request.Store = reopened
	reopenedFloor, reopenedPresent, err := reopened.Load(context.Background())
	require.NoError(t, err)
	require.True(t, reopenedPresent)
	assert.Equal(t, currentFloor, reopenedFloor)
	page, err := reopened.History(context.Background(), oldFloor.Revision-1, 1)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	assert.Equal(t, oldFloor, page.Events[0].NewFloor)
	assert.True(t, page.HasMore)

	preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.True(t, preview.Complete)
	assert.Equal(t, syncengine.PreviewReasonEqual, publicationPreviewEntryFor(t, preview, "settings.ini").Reason)
	assertPublicationPreviewBaseWitnessForTest(t, base, before)
}

func TestPreviewPublicationTargetRefusesBaseFromRecreatedMatchingStore(t *testing.T) {
	captureCalls := 0
	fixture := newPublicationBaseTestFixture(t, publicationPreviewCountingCaptureForTest(&captureCalls))
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, 1, captureCalls)
	before := publicationPreviewBaseWitnessForTest(t, base)

	recreated := newAcceptedMaterialTestFixture(t, publicationstate.BackendPublicRepo)
	require.Equal(t, fixture.request.Binding, recreated.request.binding)
	require.Equal(t, fixture.request.SnapshotRecord, recreated.request.snapshotRecord)
	require.Equal(t, fixture.request.Payload, recreated.request.payload)
	require.Equal(t, fixture.request.ExpectedFloor.Sequence, recreated.request.expectedFloor.Sequence)
	require.Equal(t, fixture.request.ExpectedFloor.Revision, recreated.request.expectedFloor.Revision)
	require.Equal(t, fixture.request.ExpectedFloor.Generation, recreated.request.expectedFloor.Generation)
	require.Equal(t, fixture.request.ExpectedFloor.RecordCID, recreated.request.expectedFloor.RecordCID)
	require.Equal(t, fixture.request.ExpectedFloor.BlobCID, recreated.request.expectedFloor.BlobCID)
	require.NotEqual(t, [32]byte{}, fixture.request.ExpectedFloor.DatabaseID)
	require.NotEqual(t, [32]byte{}, recreated.request.expectedFloor.DatabaseID)
	assert.NotEqual(t, fixture.request.ExpectedFloor.DatabaseID, recreated.request.expectedFloor.DatabaseID)

	request := fixture.request
	request.Store = recreated.store
	request.ExpectedFloor = cloneServiceTestFloor(recreated.request.expectedFloor)
	request.SnapshotRecord = bytes.Clone(recreated.request.snapshotRecord)
	request.Payload = bytes.Clone(recreated.request.payload)
	captureCalls = 0
	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	assert.Zero(t, captureCalls)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilityLineage))
	assertPublicationPreviewBaseWitnessForTest(t, base, before)

	preview, disposition, err = PreviewPublicationTarget(context.Background(), request, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, captureCalls)
	assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
	assert.True(t, preview.Complete)
}

func TestPreviewPublicationTargetDoesNotResurrectBaseAfterReplaceAwayAndBack(t *testing.T) {
	captureCalls := 0
	fixture := newPublicationBaseTestFixture(t, publicationPreviewCountingCaptureForTest(&captureCalls))
	base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
	require.NoError(t, err)
	assert.Equal(t, 1, captureCalls)
	before := publicationPreviewBaseWitnessForTest(t, base)
	assert.Equal(t, fixture.accepted.request.expectedFloor, before.floor)
	assert.Equal(t, fixture.accepted.request.snapshotRecord, before.snapshotRecord)
	originalFloor := cloneServiceTestFloor(fixture.request.ExpectedFloor)
	originalRecord := bytes.Clone(fixture.request.SnapshotRecord)
	originalPayload := bytes.Clone(fixture.request.Payload)
	portable, err := fixture.target.Model()
	require.NoError(t, err)
	branch := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: publicationPreviewFileEntries(fixture.target.ID, map[string]string{"settings.ini": "branch B"})}
	branchRecord, branchPayload := publicationPreviewGenesisMaterialForTest(t, fixture.request.Binding, branch, [16]byte{0x77, 0x71})
	branchFloor := publicationPreviewAcceptFloorReplacementForTest(t, fixture.accepted.store, fixture.request.Binding, branchRecord, branchPayload)
	assert.NotEqual(t, originalFloor.RecordCID, branchFloor.RecordCID)
	assert.Equal(t, originalFloor.DatabaseID, branchFloor.DatabaseID)
	assert.Equal(t, originalFloor.Generation+1, branchFloor.Generation)

	returnedFloor := publicationPreviewAcceptFloorReplacementForTest(t, fixture.accepted.store, fixture.request.Binding, originalRecord, originalPayload)
	assert.Equal(t, originalFloor.DatabaseID, returnedFloor.DatabaseID)
	assert.Equal(t, originalFloor.Generation+2, returnedFloor.Generation)
	assert.Equal(t, originalFloor.Binding, returnedFloor.Binding)
	assert.Equal(t, originalFloor.Sequence, returnedFloor.Sequence)
	assert.Equal(t, originalFloor.PublicationID, returnedFloor.PublicationID)
	assert.Equal(t, originalFloor.RecordCID, returnedFloor.RecordCID)
	assert.Equal(t, originalFloor.BlobCID, returnedFloor.BlobCID)
	assert.Equal(t, originalFloor.BlobSize, returnedFloor.BlobSize)
	request := fixture.request
	request.ExpectedFloor = cloneServiceTestFloor(returnedFloor)
	request.SnapshotRecord = bytes.Clone(originalRecord)
	request.Payload = bytes.Clone(originalPayload)
	captureCalls = 0
	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	assert.Zero(t, captureCalls)
	assert.Equal(t, syncengine.Preview{}, preview)
	assert.Empty(t, disposition)
	publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilityLineage))
	assertPublicationPreviewBaseWitnessForTest(t, base, before)

	preview, disposition, err = PreviewPublicationTarget(context.Background(), request, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, captureCalls)
	assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
	assert.True(t, preview.Complete)
}

type publicationPreviewBaseWitness struct {
	floor          publicationstate.Floor
	snapshotRecord []byte
	entries        []model.Entry
}

func publicationPreviewBaseWitnessForTest(t *testing.T, base *PublicationReconciliationBase) publicationPreviewBaseWitness {
	t.Helper()
	require.NotNil(t, base)
	return publicationPreviewBaseWitness{
		floor: cloneServiceTestFloor(base.position.floor), snapshotRecord: bytes.Clone(base.position.snapshotRecord),
		entries: clonePublicationProjectionEntriesForTest(base.entries),
	}
}

func assertPublicationPreviewBaseWitnessForTest(t *testing.T, base *PublicationReconciliationBase, expected publicationPreviewBaseWitness) {
	t.Helper()
	require.NotNil(t, base)
	assert.Equal(t, expected.floor, base.position.floor)
	assert.Equal(t, expected.snapshotRecord, base.position.snapshotRecord)
	assert.Equal(t, expected.entries, base.entries)
}

func publicationPreviewGenesisMaterialForTest(t *testing.T, binding publicationstate.Binding, snapshot model.Snapshot, publicationID [16]byte) ([]byte, []byte) {
	t.Helper()
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	blobCID, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	record, err := publication.EncodeSnapshot(publication.SnapshotRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationID: publicationID,
		Parent: []byte{}, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(packed.Payload))},
	})
	require.NoError(t, err)
	return record, bytes.Clone(packed.Payload)
}

func publicationPreviewAcceptFloorReplacementForTest(t *testing.T, store *publicationstate.Store, binding publicationstate.Binding, record, payload []byte) publicationstate.Floor {
	t.Helper()
	decoded, err := publication.DecodeSnapshot(record)
	require.NoError(t, err)
	cid, err := publication.RecordCID(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(decoded.PublicationSeq)
	require.NoError(t, err)
	head, err := publication.EncodeHead(publication.HeadRecord{
		SchemaVersion: publication.SchemaVersion, Vault: binding.Vault, PublicationSeq: decoded.PublicationSeq,
		SnapshotCID: cid, BlobCID: bytes.Clone(decoded.Blob.CID),
	})
	require.NoError(t, err)
	current, present, err := store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, present)
	observation := publicationstate.Observation{
		Origin: binding, SuppliedContext: current.SuppliedContext, Head: head,
		Snapshots: []publicationstate.SnapshotBlock{{Key: key, Raw: bytes.Clone(record)}},
	}
	proposal, err := store.Prepare(context.Background(), publicationstate.ModeReplaceFloor, observation, payload)
	require.NoError(t, err)
	floor, err := store.Accept(context.Background(), publicationstate.ModeReplaceFloor, proposal.StateToken, observation, payload, proposal.Confirmation)
	require.NoError(t, err)
	return floor
}

func TestPreviewPublicationTargetRequiresOriginalContextForEqualSelections(t *testing.T) {
	t.Run("files", func(t *testing.T) {
		captureCalls := 0
		fixture := newPublicationBaseTestFixture(t, publicationPreviewCountingCaptureForTest(&captureCalls))
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		assert.Equal(t, 1, captureCalls)
		before := publicationPreviewBaseWitnessForTest(t, base)
		oldMaterial, oldSelection := publicationBaseSelectCurrent(t, fixture.request)

		independent, err := NewPublicationLocalContext(fixture.paths, fixture.local.files, nil)
		require.NoError(t, err)
		request := fixture.request
		request.Local = independent
		currentMaterial, currentSelection := publicationBaseSelectCurrent(t, request)
		assert.Equal(t, oldMaterial.floor, currentMaterial.floor)
		assert.Equal(t, oldSelection.context.paths, currentSelection.context.paths)
		assert.Equal(t, oldSelection.target, currentSelection.target)
		assert.Equal(t, oldSelection.portable, currentSelection.portable)
		assert.Equal(t, oldSelection.excludes, currentSelection.excludes)
		assert.Equal(t, oldSelection.anchorPath, currentSelection.anchorPath)
		assert.Equal(t, oldSelection.anchorName, currentSelection.anchorName)
		assert.True(t, os.SameFile(oldSelection.anchorInfo, currentSelection.anchorInfo))

		captureCalls = 0
		preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
		assert.Zero(t, captureCalls)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
		assertPublicationPreviewBaseWitnessForTest(t, base, before)

		preview, disposition, err = PreviewPublicationTarget(context.Background(), request, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, captureCalls)
		assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
		assert.True(t, preview.Complete)
	})

	t.Run("GNOME refs", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		fixture := newPublicationPreviewGNOMEFixture(t, settings, false)
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			return SettingsCapture{Entries: publicationBaseGNOMEEntries(targetID, refs)}, nil
		}
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		assert.Equal(t, 1, settings.captureCalls)
		before := publicationPreviewBaseWitnessForTest(t, base)
		oldMaterial, oldSelection := publicationBaseSelectCurrent(t, fixture.request)
		settings.captureCalls = 0

		independent, err := NewPublicationLocalContext(fixture.paths, fixture.request.Local.files, settings)
		require.NoError(t, err)
		request := fixture.request
		request.Local = independent
		currentMaterial, currentSelection := publicationBaseSelectCurrent(t, request)
		assert.Equal(t, oldMaterial.floor, currentMaterial.floor)
		assert.Equal(t, oldSelection.context.paths, currentSelection.context.paths)
		assert.Equal(t, oldSelection.target, currentSelection.target)
		assert.Equal(t, oldSelection.portable, currentSelection.portable)
		assert.Equal(t, oldSelection.settingRefs, currentSelection.settingRefs)

		preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		assert.Zero(t, settings.captureCalls)
		publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
		assertPublicationPreviewBaseWitnessForTest(t, base, before)

		preview, disposition, err = PreviewPublicationTarget(context.Background(), request, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, settings.captureCalls)
		assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
		assert.True(t, preview.Complete)
	})
}

func TestPreviewPublicationTargetRefusesCurrentFileSelectionDrift(t *testing.T) {
	t.Run("exclusion drift", func(t *testing.T) {
		captureCalls := 0
		fixture := newPublicationBaseTestFixture(t, publicationPreviewCountingCaptureForTest(&captureCalls))
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		assert.Equal(t, 1, captureCalls)
		before := publicationPreviewBaseWitnessForTest(t, base)
		request := fixture.request
		request.Configuration = cloneSelectionTestConfig(fixture.request.Configuration)
		require.Len(t, request.Configuration.Targets, 1)
		require.NotNil(t, request.Configuration.Targets[0].Root)
		request.Configuration.Targets[0].Root.Exclude = []string{"settings.ini"}

		captureCalls = 0
		preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
		assert.Zero(t, captureCalls)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
		assertPublicationPreviewBaseWitnessForTest(t, base, before)

		preview, disposition, err = PreviewPublicationTarget(context.Background(), request, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, captureCalls)
		assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
		assert.True(t, preview.Complete)
	})

	t.Run("replacement directory incarnation", func(t *testing.T) {
		captureCalls := 0
		fixture := newPublicationBaseTestFixture(t, publicationPreviewCountingCaptureForTest(&captureCalls))
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		assert.Equal(t, 1, captureCalls)
		before := publicationPreviewBaseWitnessForTest(t, base)
		root := filepath.Join(fixture.paths.Home, "synthetic")
		heldRoot := filepath.Join(fixture.paths.Home, "synthetic-held")
		require.NoError(t, os.Rename(root, heldRoot))
		require.NoError(t, os.Mkdir(root, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, "settings.ini"), []byte("synthetic accepted publication"), 0o600))
		oldInfo, err := os.Stat(heldRoot)
		require.NoError(t, err)
		newInfo, err := os.Stat(root)
		require.NoError(t, err)
		assert.False(t, os.SameFile(oldInfo, newInfo))

		captureCalls = 0
		preview, disposition, err := PreviewPublicationTarget(context.Background(), fixture.request, base)
		assert.Zero(t, captureCalls)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
		assertPublicationPreviewBaseWitnessForTest(t, base, before)

		preview, disposition, err = PreviewPublicationTarget(context.Background(), fixture.request, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, captureCalls)
		assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
		assert.True(t, preview.Complete)
	})
}

func TestPreviewPublicationTargetRequiresCurrentGNOMEApprovalAndPolicy(t *testing.T) {
	t.Run("pending approval", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		fixture := newPublicationPreviewGNOMEFixture(t, settings, false)
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			return SettingsCapture{Entries: publicationBaseGNOMEEntries(targetID, refs)}, nil
		}
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		assert.Equal(t, 1, settings.captureCalls)
		before := publicationPreviewBaseWitnessForTest(t, base)
		settings.captureCalls = 0
		request := fixture.request
		request.Configuration = cloneSelectionTestConfig(fixture.request.Configuration)
		require.Len(t, request.Configuration.Targets, 1)
		request.Configuration.Targets[0].GNOMEPolicy = &config.GNOMEPolicy{Approval: config.GNOMEApprovalPending}
		require.NoError(t, request.Configuration.Validate())

		preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		assert.Zero(t, settings.captureCalls)
		publicationBaseAssertFailure(t, err, string(publicationSelectionStage), string(publicationSelectionReasonSettings))
		assertPublicationPreviewBaseWitnessForTest(t, base, before)
	})

	t.Run("approved category change with matching current material", func(t *testing.T) {
		settings := &publicationCaptureGNOMESettings{}
		fixture := newPublicationPreviewGNOMEFixture(t, settings, false)
		settings.capture = func(_ context.Context, targetID string, refs []SettingRef) (SettingsCapture, error) {
			return SettingsCapture{Entries: publicationBaseGNOMEEntries(targetID, refs)}, nil
		}
		base, err := EstablishLocalReconciliationBase(context.Background(), fixture.request)
		require.NoError(t, err)
		before := publicationPreviewBaseWitnessForTest(t, base)

		changedTarget := newApprovedPublicationGNOMETarget(t, fixture.target.ID, []string{"fonts"})
		changedRefs, err := approvedSettings(context.Background(), settings, changedTarget)
		require.NoError(t, err)
		require.NotEmpty(t, changedRefs)
		changedEntries := publicationBaseGNOMEEntries(changedTarget.ID, changedRefs)
		updatedSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{fixture.portable}, Entries: changedEntries}
		record, payload, floor := publicationPreviewAcceptSuccessor(t, fixture.accepted, updatedSnapshot)
		request := fixture.request
		request.ExpectedFloor = floor
		request.SnapshotRecord = bytes.Clone(record)
		request.Payload = bytes.Clone(payload)
		request.Configuration = cloneSelectionTestConfig(fixture.request.Configuration)
		require.Len(t, request.Configuration.Targets, 1)
		request.Configuration.Targets[0] = changedTarget
		settings.captureCalls = 0

		preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
		assert.Equal(t, syncengine.Preview{}, preview)
		assert.Empty(t, disposition)
		assert.Zero(t, settings.captureCalls)
		publicationBaseAssertFailure(t, err, string(publicationBaseEligibilityStage), string(publicationBaseEligibilitySelection))
		assertPublicationPreviewBaseWitnessForTest(t, base, before)

		preview, disposition, err = PreviewPublicationTarget(context.Background(), request, nil)
		require.NoError(t, err)
		assert.Equal(t, 1, settings.captureCalls)
		assert.Equal(t, PublicationPreviewBaseUnestablished, disposition)
		assert.True(t, preview.Complete)
	})
}

func TestPreviewPublicationTargetKeepsTombstoneDistinctFromAbsenceOnResurrection(t *testing.T) {
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	tombstone := model.Entry{TargetID: target.ID, File: &model.FileEntry{Path: "settings.ini", State: model.FileDeleted}}
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: []model.Entry{tombstone}})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, nil, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	base, err := EstablishLocalReconciliationBase(context.Background(), request)
	require.NoError(t, err)
	require.NotNil(t, base)
	require.Equal(t, []model.Entry{tombstone}, base.entries)
	before := publicationPreviewBaseWitnessForTest(t, base)

	resurrected := publicationPreviewFileEntries(target.ID, map[string]string{"settings.ini": "resurrected content"})
	record, payload, floor := publicationPreviewAcceptSuccessor(t, accepted, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: resurrected})
	request.ExpectedFloor = floor
	request.SnapshotRecord = bytes.Clone(record)
	request.Payload = bytes.Clone(payload)
	preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
	require.NoError(t, err)
	assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
	assert.False(t, preview.Complete)
	entry := publicationPreviewEntryFor(t, preview, "settings.ini")
	assert.Equal(t, syncengine.ActionConflict, entry.DecisionAction)
	assert.Equal(t, syncengine.PreviewStateConflict, entry.State)
	assert.Equal(t, syncengine.PreviewReasonConflict, entry.Reason)
	assert.Equal(t, string(syncengine.ReasonDivergence), entry.Detail)
	assertPublicationPreviewBaseWitnessForTest(t, base, before)
}

func TestPreviewPublicationTargetClassifiesFileEditAndDeletionMatrix(t *testing.T) {
	for _, test := range []struct {
		name         string
		local        func(string) files.Result
		remote       func(string) []model.Entry
		wantAction   syncengine.Action
		wantState    syncengine.PreviewState
		wantReason   syncengine.PreviewReason
		wantDetail   string
		wantComplete bool
	}{
		{
			name: "local edit versus remote deletion",
			local: func(targetID string) files.Result {
				return publicationPreviewFileResultForTest(publicationPreviewFileEntries(targetID, map[string]string{"settings.ini": "local edit"}))
			},
			remote: func(targetID string) []model.Entry {
				return []model.Entry{publicationPreviewFileTombstoneForTest(targetID, "settings.ini")}
			},
			wantAction: syncengine.ActionConflict, wantState: syncengine.PreviewStateConflict, wantReason: syncengine.PreviewReasonConflict, wantDetail: string(syncengine.ReasonDivergence),
		},
		{
			name:  "local deletion versus remote edit",
			local: func(string) files.Result { return files.Result{} },
			remote: func(targetID string) []model.Entry {
				return publicationPreviewFileEntries(targetID, map[string]string{"settings.ini": "remote edit"})
			},
			wantAction: syncengine.ActionConflict, wantState: syncengine.PreviewStateConflict, wantReason: syncengine.PreviewReasonConflict, wantDetail: string(syncengine.ReasonDivergence),
		},
		{
			name: "unchanged local versus remote deletion",
			local: func(targetID string) files.Result {
				return publicationPreviewFileResultForTest(publicationPreviewFileEntries(targetID, map[string]string{"settings.ini": "base value"}))
			},
			remote: func(targetID string) []model.Entry {
				return []model.Entry{publicationPreviewFileTombstoneForTest(targetID, "settings.ini")}
			},
			wantAction: syncengine.ActionDeleteLocal, wantReason: syncengine.PreviewReasonRemoteChanged, wantComplete: true,
		},
		{
			name:  "local deletion versus unchanged remote",
			local: func(string) files.Result { return files.Result{} },
			remote: func(targetID string) []model.Entry {
				return publicationPreviewFileEntries(targetID, map[string]string{"settings.ini": "base value"})
			},
			wantAction: syncengine.ActionDeleteRemote, wantState: syncengine.PreviewStateMissing, wantReason: syncengine.PreviewReasonMissing, wantDetail: string(syncengine.ReasonLocalChanged), wantComplete: true,
		},
		{
			name: "explicit unknown identity blocks deletion",
			local: func(targetID string) files.Result {
				key := model.EntryKey{TargetID: targetID, Source: model.SourceFiles, FilePath: "settings.ini"}
				return files.Result{Observations: []model.Observation{{State: model.ObservationUnknown, Identity: key}}}
			},
			remote: func(targetID string) []model.Entry {
				return []model.Entry{publicationPreviewFileTombstoneForTest(targetID, "settings.ini")}
			},
			wantAction: syncengine.ActionBlocked, wantState: syncengine.PreviewStateUnknown, wantReason: syncengine.PreviewReasonUnknown,
		},
		{
			name: "omitted identity under incomplete coverage blocks remote deletion",
			local: func(targetID string) files.Result {
				key := model.EntryKey{TargetID: targetID, Source: model.SourceFiles, FilePath: "other.ini"}
				return files.Result{Observations: []model.Observation{{State: model.ObservationUnknown, Identity: key}}}
			},
			remote: func(targetID string) []model.Entry {
				return publicationPreviewFileEntries(targetID, map[string]string{"settings.ini": "base value"})
			},
			wantAction: syncengine.ActionBlocked, wantState: syncengine.PreviewStateMissing, wantReason: syncengine.PreviewReasonMissing, wantDetail: string(syncengine.ReasonCoverage),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetID := "synthetic-files"
			baseEntries := publicationPreviewFileEntries(targetID, map[string]string{"settings.ini": "base value"})
			var captured files.Result
			capture := publicationCapturePortFunc(func(context.Context, config.Target, string) (files.Result, error) {
				return captured, nil
			})
			accepted, request := newPublicationPreviewFileRequestForTest(t, baseEntries, capture)
			captured = publicationPreviewFileResultForTest(baseEntries)
			base, err := EstablishLocalReconciliationBase(context.Background(), request)
			require.NoError(t, err)
			before := publicationPreviewBaseWitnessForTest(t, base)

			remoteEntries := test.remote(targetID)
			updatedSnapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{base.selection.portable}, Entries: remoteEntries}
			record, payload, floor := publicationPreviewAcceptSuccessor(t, accepted, updatedSnapshot)
			request.ExpectedFloor = floor
			request.SnapshotRecord = bytes.Clone(record)
			request.Payload = bytes.Clone(payload)
			captured = test.local(targetID)

			preview, disposition, err := PreviewPublicationTarget(context.Background(), request, base)
			require.NoError(t, err)
			assert.Equal(t, PublicationPreviewBaseEstablished, disposition)
			assert.Equal(t, test.wantComplete, preview.Complete)
			entry := publicationPreviewEntryFor(t, preview, "settings.ini")
			assert.Equal(t, test.wantAction, entry.DecisionAction)
			assert.Equal(t, test.wantState, entry.State)
			assert.Equal(t, test.wantReason, entry.Reason)
			assert.Equal(t, test.wantDetail, entry.Detail)
			assertPublicationPreviewBaseWitnessForTest(t, base, before)
		})
	}
}

func newPublicationPreviewFileRequestForTest(t *testing.T, entries []model.Entry, capture CapturePort) (acceptedMaterialTestFixture, PublicationReconciliationRequest) {
	t.Helper()
	selectionFixture := newPublicationSelectionFixture(t)
	target := config.Target{ID: "synthetic-files", Source: model.SourceFiles, Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory}}
	portable, err := target.Model()
	require.NoError(t, err)
	root := filepath.Join(selectionFixture.paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(root, 0o700))
	accepted := newAcceptedSnapshotForPublicationBaseTest(t, model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: clonePublicationProjectionEntriesForTest(entries)})
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	local, err := NewPublicationLocalContext(selectionFixture.paths, capture, nil)
	require.NoError(t, err)
	request := publicationBaseRequestFor(t, accepted, configuration, target.ID, local)
	return accepted, request
}

func publicationPreviewFileResultForTest(entries []model.Entry) files.Result {
	observations := make([]model.Observation, len(entries))
	for index, original := range entries {
		entry := clonePublicationProjectionEntry(original)
		observations[index] = model.Observation{State: model.ObservationPresent, Identity: entry.Identity(), Entry: &entry}
	}
	return files.Result{Observations: observations}
}

func publicationPreviewFileTombstoneForTest(targetID, path string) model.Entry {
	return model.Entry{TargetID: targetID, File: &model.FileEntry{Path: path, State: model.FileDeleted}}
}

func publicationPreviewCountingCaptureForTest(calls *int) CapturePort {
	return publicationCapturePortFunc(func(ctx context.Context, target config.Target, path string) (files.Result, error) {
		*calls = *calls + 1
		return (LocalFilesCapture{}).Capture(ctx, target, path)
	})
}
