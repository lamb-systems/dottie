package local_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lamb-systems/dottie/internal/config"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/publicationstate"
	"github.com/lamb-systems/dottie/internal/service"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/syncengine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationMaterialOwnedReadDrivesFreshLocalPreview(t *testing.T) {
	ctx := context.Background()
	binding := publicationReconcileBinding()
	home, storeDirectory := newPublicationMaterialHome(t, binding)
	target, configuration, portable := publicationMaterialTarget(t)
	initial := bytes.Clone(publicationReconcileInitial)
	writePublicationReconcileFile(t, filepath.Join(home.selected, "settings.ini"), initial, 0o600)

	expectedFloor, attemptID, expectedRecord, expectedPayload := finalizePublicationMaterialOwner(t, home, binding, target, portable, initial)
	reopened, err := publicationstate.Open(storeDirectory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	home.pubStore = reopened

	beforeRead := readPublicationMaterialOwnedState(t, reopened, attemptID)
	requirePublicationMaterialOwnedState(t, beforeRead, expectedFloor, attemptID, expectedRecord)
	requirePublicationMaterialFile(t, filepath.Join(home.selected, "settings.ini"), initial, 0o600)
	requirePublicationMaterialFile(t, home.sentinel, publicationReconcileSentinelA, 0o640)

	material, err := reopened.ReadAcceptedMaterial(ctx, binding, beforeRead.floor)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(beforeRead.floor, material.Floor), "reader floor must match the independently loaded current floor")
	require.True(t, bytes.Equal(expectedRecord, material.SnapshotRecord), "reader record must match the assertions-only setup oracle")
	require.True(t, bytes.Equal(expectedPayload, material.Payload), "reader payload must match the assertions-only setup oracle")
	requirePublicationMaterialFile(t, filepath.Join(home.selected, "settings.ini"), initial, 0o600)
	requirePublicationMaterialFile(t, home.sentinel, publicationReconcileSentinelA, 0o640)
	record, err := publication.DecodeSnapshot(material.SnapshotRecord)
	require.NoError(t, err)
	snapshot, err := publication.DecodePayload(material.Payload, record.Blob)
	require.NoError(t, err)
	require.Equal(t, model.SnapshotVersion, snapshot.Version)
	require.Len(t, snapshot.Targets, 1)
	require.True(t, reflect.DeepEqual(portable, snapshot.Targets[0]), "reader snapshot must contain the independently selected target")
	require.Len(t, snapshot.Entries, 1)
	require.NotNil(t, snapshot.Entries[0].File)
	require.Equal(t, model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}, snapshot.Entries[0].Identity())
	require.Equal(t, model.FileRegular, snapshot.Entries[0].File.Kind)
	require.True(t, bytes.Equal(initial, snapshot.Entries[0].File.Content), "reader snapshot must contain the independent expected file bytes")
	require.Equal(t, uint32(0o600), snapshot.Entries[0].File.Mode)

	request := service.PublicationReconciliationRequest{
		Store: reopened, Binding: binding, ExpectedFloor: beforeRead.floor,
		SnapshotRecord: bytes.Clone(material.SnapshotRecord), Payload: bytes.Clone(material.Payload),
		Configuration: configuration, TargetID: publicationReconcileTargetID,
		Local: newPublicationReconcileContext(t, home.paths),
	}

	captured := requirePublicationMaterialCapture(t, ctx, home, target, initial)
	require.Len(t, captured, 1)
	require.True(t, reflect.DeepEqual(snapshot.Entries[0], captured[0]), "actual local capture must exactly converge with the reader snapshot before base establishment")
	afterRead := readPublicationMaterialOwnedState(t, reopened, attemptID)
	require.True(t, reflect.DeepEqual(beforeRead, afterRead), "reader and capture must preserve fresh public publication and attempt state")
	requirePublicationMaterialFile(t, filepath.Join(home.selected, "settings.ini"), initial, 0o600)
	requirePublicationMaterialFile(t, home.sentinel, publicationReconcileSentinelA, 0o640)

	base, err := service.EstablishLocalReconciliationBase(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, base)
	afterEstablish := readPublicationMaterialOwnedState(t, reopened, attemptID)
	require.True(t, reflect.DeepEqual(beforeRead, afterEstablish), "base establishment must preserve fresh public publication and attempt state")
	requirePublicationMaterialFile(t, filepath.Join(home.selected, "settings.ini"), initial, 0o600)
	requirePublicationMaterialFile(t, home.sentinel, publicationReconcileSentinelA, 0o640)

	localEdit := []byte("distinct synthetic local edit\n")
	require.False(t, bytes.Equal(initial, localEdit), "the local edit must differ from the accepted base bytes")
	writePublicationReconcileFile(t, filepath.Join(home.selected, "settings.ini"), localEdit, 0o600)
	preview, disposition, err := service.PreviewPublicationTarget(ctx, request, base)
	require.NoError(t, err)
	require.Equal(t, service.PublicationPreviewBaseEstablished, disposition)
	require.True(t, preview.Complete)
	require.Zero(t, preview.UnresolvedEntries)
	require.Len(t, preview.Targets, 1)
	require.Equal(t, publicationReconcileTargetID, preview.Targets[0].ID)
	require.Len(t, preview.Targets[0].Entries, 1)
	entry := preview.Targets[0].Entries[0]
	require.True(t, entry.Key == (model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}), "preview must identify the selected synthetic file")
	require.Equal(t, syncengine.ActionUpload, entry.DecisionAction)
	require.Equal(t, syncengine.PreviewChange, entry.Action)
	require.Equal(t, syncengine.PreviewReasonLocalChanged, entry.Reason)
	require.Empty(t, entry.State)
	require.Empty(t, entry.Detail)
	require.NotNil(t, entry.Preimage)
	localDigest := sha256.Sum256(localEdit)
	require.True(t, hex.EncodeToString(localDigest[:]) == entry.Preimage.Digest, "preview preimage must match the independent synthetic edit SHA256")
	require.Equal(t, uint32(0o600), entry.Preimage.Mode)
	afterPreview := readPublicationMaterialOwnedState(t, reopened, attemptID)
	require.True(t, reflect.DeepEqual(beforeRead, afterPreview), "preview must preserve fresh public publication and attempt state")
	requirePublicationMaterialFile(t, filepath.Join(home.selected, "settings.ini"), localEdit, 0o600)
	requirePublicationMaterialFile(t, home.sentinel, publicationReconcileSentinelA, 0o640)
}

func TestPublicationMaterialPositionOnlyReadRefusesUnretainedFloor(t *testing.T) {
	ctx := context.Background()
	binding := publicationReconcileBinding()
	home, _ := newPublicationMaterialHome(t, binding)
	_, _, portable := publicationMaterialTarget(t)
	incomingBytes := []byte("synthetic position-only incoming bytes\n")
	entry := model.Entry{TargetID: publicationReconcileTargetID, File: &model.FileEntry{
		Path: "settings.ini", State: model.FilePresent, Kind: model.FileRegular,
		Content: bytes.Clone(incomingBytes), Mode: 0o600,
	}}
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: []model.Entry{entry}}
	require.NoError(t, snapshot.Validate())
	incoming := encodePublicationReconcileMaterial(t, binding, snapshot, 0, nil, [16]byte{0x25, 0xa3})
	expectedRecord := bytes.Clone(incoming.record)
	supplied := publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}}
	observation := publicationReconcileObservation(binding, supplied, incoming)
	proposal, err := home.pubStore.Prepare(ctx, publicationstate.ModeFirstUse, observation, incoming.payload)
	require.NoError(t, err)
	acceptedFloor, err := home.pubStore.Accept(ctx, publicationstate.ModeFirstUse, proposal.StateToken, observation, incoming.payload, proposal.Confirmation)
	require.NoError(t, err)
	clear(incoming.payload)
	incoming.payload = nil
	clear(incoming.record)
	incoming.record = nil
	clear(incoming.head)
	incoming.head = nil
	clear(observation.Head)
	observation.Head = nil
	for index := range observation.Snapshots {
		clear(observation.Snapshots[index].Raw)
		observation.Snapshots[index].Raw = nil
	}

	before := readPublicationMaterialPositionOnlyState(t, home.pubStore)
	require.True(t, reflect.DeepEqual(acceptedFloor, before.floor), "fresh public load must identify the accepted current floor")
	requirePublicationMaterialPositionOnlyLink(t, before, expectedRecord)
	material, err := home.pubStore.ReadAcceptedMaterial(ctx, binding, before.floor)
	require.True(t, reflect.DeepEqual(publicationstate.AcceptedMaterial{}, material), "refusal must return zero material")
	require.ErrorIs(t, err, publicationstate.ErrStorage)
	var classified *publicationstate.Error
	require.ErrorAs(t, err, &classified)
	require.Equal(t, publicationstate.ErrStorage, classified.Class())
	require.Equal(t, publicationstate.StageReadAcceptedMaterial, classified.Stage())
	require.Equal(t, publicationstate.ReasonMaterialNotRetained, classified.Reason())
	after := readPublicationMaterialPositionOnlyState(t, home.pubStore)
	require.True(t, reflect.DeepEqual(before, after), "position-only read refusal must preserve fresh public floor/history and attempt metadata")
	requirePublicationMaterialPositionOnlyLink(t, after, expectedRecord)
}

func newPublicationMaterialHome(t *testing.T, binding publicationstate.Binding) (*publicationReconcileHome, string) {
	t.Helper()
	root := canonicalPublicationReconcileTempDir(t)
	homePath := filepath.Join(root, "home")
	paths := platform.Paths{
		Home: homePath, ConfigHome: filepath.Join(homePath, ".config"),
		StateHome: filepath.Join(homePath, ".local", "state"), CacheHome: filepath.Join(homePath, ".cache"),
		DataHome: filepath.Join(homePath, ".local", "share"),
	}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o700))
	}
	selected := filepath.Join(paths.Home, "synthetic")
	require.NoError(t, os.Mkdir(selected, 0o700))
	selected, err := filepath.EvalSymlinks(selected)
	require.NoError(t, err)
	selected = filepath.Clean(selected)
	sentinel := filepath.Join(selected, "machine-only")
	writePublicationReconcileFile(t, sentinel, publicationReconcileSentinelA, 0o640)
	storeDirectory := filepath.Join(root, "publication-state")
	require.NoError(t, os.Mkdir(storeDirectory, 0o700))
	store := openPublicationMaterialStore(t, storeDirectory, binding)
	return &publicationReconcileHome{paths: paths, root: selected, selected: selected, sentinel: sentinel, pubStore: store}, storeDirectory
}

func openPublicationMaterialStore(t *testing.T, directory string, binding publicationstate.Binding) *publicationstate.Store {
	t.Helper()
	store, err := publicationstate.Open(directory, binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	return store
}

func publicationMaterialTarget(t *testing.T) (config.Target, config.Config, model.Target) {
	t.Helper()
	target := config.Target{
		ID: publicationReconcileTargetID, Source: model.SourceFiles, Mode: config.Review,
		Root: &config.Root{Base: model.RootHome, Path: "synthetic", Kind: model.SelectionDirectory, Exclude: []string{"machine-only"}},
	}
	portable, err := target.Model()
	require.NoError(t, err)
	configuration := config.Default()
	configuration.Targets = []config.Target{target}
	require.NoError(t, configuration.Validate())
	return target, configuration, portable
}

func finalizePublicationMaterialOwner(t *testing.T, home *publicationReconcileHome, binding publicationstate.Binding, target config.Target, portable model.Target, expectedBytes []byte) (publicationstate.Floor, [16]byte, []byte, []byte) {
	t.Helper()
	ctx := context.Background()
	captured := requirePublicationMaterialCapture(t, ctx, home, target, expectedBytes)
	snapshot := model.Snapshot{Version: model.SnapshotVersion, Targets: []model.Target{portable}, Entries: captured}
	require.NoError(t, snapshot.Validate())
	setup := encodePublicationReconcileMaterial(t, binding, snapshot, 0, nil, [16]byte{0x25, 0xa2})
	expectedRecord := bytes.Clone(setup.record)
	expectedPayload := bytes.Clone(setup.payload)
	candidate := publicationstate.CandidateInput{
		SnapshotKey: setup.key, SnapshotRecord: bytes.Clone(setup.record),
		HeadRecord: bytes.Clone(setup.head), Payload: bytes.Clone(setup.payload),
	}
	view := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: publicationstate.SuppliedContext{RepositoryRevision: "synthetic-revision", RepositoryDigest: []byte{1, 2, 3}},
	}
	review := publicationstate.LocalReviewContext{
		SelectionDigest: [32]byte{0x61}, SelectionRevision: 1,
		ApprovalDigest: [32]byte{0x62}, ApprovalRevision: 1,
	}
	proposal, err := home.pubStore.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	require.Equal(t, publicationstate.AttemptGenesis, proposal.Kind)
	require.Equal(t, [16]byte{0x25, 0xa2}, proposal.AttemptID)
	attempt, err := home.pubStore.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, proposal.AttemptID, attempt.ID)
	require.Equal(t, publicationstate.AttemptPrepared, attempt.Lifecycle)
	require.Equal(t, publicationstate.OutcomeNotSubmitted, attempt.Outcome)

	uploadProposal, err := home.pubStore.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchUpload, view, review)
	require.NoError(t, err)
	require.Equal(t, attempt.ID, uploadProposal.AttemptID)
	require.Equal(t, publicationstate.DispatchUpload, uploadProposal.Kind)
	upload, err := home.pubStore.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, attempt.ID, upload.AttemptID)
	require.True(t, bytes.Equal(expectedPayload, upload.Payload), "local upload reservation must match only the setup oracle")
	setupRecord, err := publication.DecodeSnapshot(expectedRecord)
	require.NoError(t, err)
	require.True(t, bytes.Equal(setupRecord.Blob.CID, upload.Blob.CID), "local upload reservation must bind the setup blob")
	afterUpload, err := home.pubStore.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	require.Equal(t, publicationstate.AttemptUploadStarted, afterUpload.Lifecycle)

	submissionProposal, err := home.pubStore.PrepareDispatch(ctx, attempt.ID, publicationstate.DispatchSubmission, view, review)
	require.NoError(t, err)
	require.Equal(t, attempt.ID, submissionProposal.AttemptID)
	require.Equal(t, publicationstate.DispatchSubmission, submissionProposal.Kind)
	submission, err := home.pubStore.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, attempt.ID, submission.AttemptID)
	require.True(t, bytes.Equal(expectedRecord, submission.SnapshotRecord), "local submission reservation must match only the setup oracle")
	require.True(t, bytes.Equal(candidate.HeadRecord, submission.HeadRecord), "local submission head must match the setup candidate")
	require.True(t, submission.SnapshotCreateOnly)
	require.True(t, submission.RequiresAtomicBatch)
	require.True(t, submission.RequiresCreateExclude)
	require.True(t, submission.HeadCreate)

	current := publicationstate.SuppliedRepositoryView{
		Origin: binding, Scope: publicationstate.ViewScopeWholeRepository,
		SuppliedContext: view.SuppliedContext, Head: bytes.Clone(candidate.HeadRecord),
		Snapshots: []publicationstate.SnapshotBlock{{Key: candidate.SnapshotKey, Raw: bytes.Clone(candidate.SnapshotRecord)}},
	}
	loaded, err := home.pubStore.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	require.Equal(t, publicationstate.AttemptMayHaveSubmitted, loaded.Lifecycle)
	resolution, err := home.pubStore.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	require.Equal(t, attempt.ID, resolution.Attempt.ID)
	require.Equal(t, publicationstate.AttemptMayHaveSubmitted, resolution.Attempt.Lifecycle)
	require.Equal(t, publicationstate.OutcomeCurrent, resolution.Outcome)
	finalized, err := home.pubStore.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	require.Equal(t, attempt.ID, finalized.Attempt.ID)
	require.Equal(t, publicationstate.AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	require.Equal(t, publicationstate.OutcomeCurrent, finalized.Attempt.Outcome)
	require.Equal(t, uint64(0), finalized.Floor.Sequence)
	require.True(t, bytes.Equal(recordCIDForPublicationMaterial(t, expectedRecord), finalized.Floor.RecordCID))
	require.NoError(t, home.pubStore.Close())

	clear(setup.payload)
	clear(setup.record)
	clear(setup.head)
	clear(candidate.Payload)
	clear(candidate.SnapshotRecord)
	clear(candidate.HeadRecord)
	clear(upload.Payload)
	clear(submission.SnapshotRecord)
	clear(submission.HeadRecord)
	clear(current.Head)
	clear(current.Snapshots[0].Raw)
	clear(resolution.Evidence)
	for index := range captured {
		if captured[index].File != nil {
			clear(captured[index].File.Content)
		}
	}
	for index := range snapshot.Entries {
		if snapshot.Entries[index].File != nil {
			clear(snapshot.Entries[index].File.Content)
		}
	}
	return finalized.Floor, attempt.ID, expectedRecord, expectedPayload
}

func requirePublicationMaterialCapture(t *testing.T, ctx context.Context, home *publicationReconcileHome, target config.Target, expectedBytes []byte) []model.Entry {
	t.Helper()
	captured, err := (service.LocalFilesCapture{}).Capture(ctx, target, home.selected)
	require.NoError(t, err)
	require.Len(t, captured.Observations, 1)
	observation := captured.Observations[0]
	require.Equal(t, model.ObservationPresent, observation.State)
	require.NotNil(t, observation.Entry)
	require.True(t, observation.Identity == (model.EntryKey{TargetID: publicationReconcileTargetID, Source: model.SourceFiles, FilePath: "settings.ini"}), "local capture must identify the selected synthetic file")
	require.True(t, observation.Entry.Identity() == observation.Identity, "present capture identity must match its entry")
	require.NotNil(t, observation.Entry.File)
	require.Equal(t, model.FileRegular, observation.Entry.File.Kind)
	require.True(t, observation.Entry.File.Path == "settings.ini")
	require.True(t, bytes.Equal(expectedBytes, observation.Entry.File.Content), "local capture must match only the independent expected file bytes")
	require.Equal(t, uint32(0o600), observation.Entry.File.Mode)
	require.Len(t, captured.Skipped, 1)
	require.Equal(t, "machine-only", captured.Skipped[0].Path)
	require.Equal(t, files.SkipExcluded, captured.Skipped[0].Reason)
	require.Equal(t, "machine-only", captured.Skipped[0].Detail)
	entry := *observation.Entry
	entry.File.Content = bytes.Clone(observation.Entry.File.Content)
	return []model.Entry{entry}
}

func readPublicationMaterialOwnedState(t *testing.T, store *publicationstate.Store, attemptID [16]byte) publicationMaterialOwnedState {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	history, err := store.History(ctx, floor.Revision-1, 1)
	require.NoError(t, err)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	attempts, err := store.AttemptHistory(ctx, [16]byte{}, 1)
	require.NoError(t, err)
	active, activePresent, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	return publicationMaterialOwnedState{floor: floor, history: history, attempt: attempt, attempts: attempts, active: active, activePresent: activePresent}
}

type publicationMaterialOwnedState struct {
	floor         publicationstate.Floor
	history       publicationstate.HistoryPage
	attempt       publicationstate.Attempt
	attempts      publicationstate.AttemptPage
	active        publicationstate.Attempt
	activePresent bool
}

func requirePublicationMaterialOwnedState(t *testing.T, state publicationMaterialOwnedState, expectedFloor publicationstate.Floor, attemptID [16]byte, expectedRecord []byte) {
	t.Helper()
	require.True(t, reflect.DeepEqual(expectedFloor, state.floor), "public load must preserve the exact finalized floor")
	require.NotZero(t, state.floor.DatabaseID)
	require.Equal(t, uint64(1), state.floor.Revision)
	require.Equal(t, uint64(1), state.floor.Generation)
	require.Equal(t, uint64(0), state.floor.Sequence)
	require.Len(t, state.history.Events, 1)
	require.False(t, state.history.HasMore)
	require.Equal(t, state.floor.Revision, state.history.NextRevision)
	require.True(t, reflect.DeepEqual(state.floor, state.history.Events[0].NewFloor), "public history must preserve the exact current event floor")
	require.Len(t, state.history.Events[0].Trace, 1)
	require.Len(t, state.history.Records, 1)
	require.True(t, state.history.Events[0].Trace[0].Key == state.floor.SnapshotKey)
	require.Equal(t, state.floor.Revision, state.history.Events[0].Revision)
	require.Equal(t, state.floor.Sequence, state.history.Events[0].Trace[0].Sequence)
	require.True(t, bytes.Equal(state.floor.RecordCID, state.history.Events[0].Trace[0].CID))
	expectedSnapshot, err := publication.DecodeSnapshot(expectedRecord)
	require.NoError(t, err)
	expectedCID, err := publication.RecordCID(expectedRecord)
	require.NoError(t, err)
	expectedKey, err := publication.SequenceKey(state.floor.Sequence)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expectedCID, state.floor.RecordCID))
	require.True(t, state.floor.SnapshotKey == expectedKey)
	require.Equal(t, expectedSnapshot.PublicationSeq, state.floor.Sequence)
	require.Equal(t, expectedSnapshot.PublicationID, state.floor.PublicationID)
	require.Equal(t, expectedSnapshot.Vault, state.floor.Binding.Vault)
	require.True(t, bytes.Equal(expectedSnapshot.Blob.CID, state.floor.BlobCID))
	require.Equal(t, expectedSnapshot.Blob.Size, state.floor.BlobSize)
	require.NoError(t, publication.VerifyHeadBinding(state.floor.Head, expectedRecord, expectedKey))
	require.True(t, bytes.Equal(expectedRecord, state.history.Records[0].Raw), "public history record must match the independent setup oracle")
	require.True(t, reflect.DeepEqual(state.history.Events[0].Trace[0], state.history.Records[0].Reference), "public history evidence must join to the accepted trace")
	require.Equal(t, attemptID, state.attempt.ID)
	require.Equal(t, publicationstate.AttemptRetiredSuccess, state.attempt.Lifecycle)
	require.Equal(t, publicationstate.OutcomeCurrent, state.attempt.Outcome)
	require.Empty(t, state.attempt.Blocked)
	require.Len(t, state.attempts.Attempts, 1)
	require.False(t, state.attempts.HasMore)
	require.Equal(t, attemptID, state.attempts.Attempts[0].ID)
	require.Equal(t, publicationstate.AttemptRetiredSuccess, state.attempts.Attempts[0].Lifecycle)
	require.Equal(t, publicationstate.OutcomeCurrent, state.attempts.Attempts[0].Outcome)
	require.False(t, state.activePresent)
	require.True(t, reflect.DeepEqual(publicationstate.Attempt{}, state.active), "finalized publication must leave no active attempt")
}

func readPublicationMaterialPositionOnlyState(t *testing.T, store *publicationstate.Store) publicationMaterialPositionOnlyState {
	t.Helper()
	ctx := context.Background()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	history, err := store.History(ctx, floor.Revision-1, 1)
	require.NoError(t, err)
	active, activePresent, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	attempts, err := store.AttemptHistory(ctx, [16]byte{}, 1)
	require.NoError(t, err)
	return publicationMaterialPositionOnlyState{floor: floor, history: history, active: active, activePresent: activePresent, attempts: attempts}
}

type publicationMaterialPositionOnlyState struct {
	floor         publicationstate.Floor
	history       publicationstate.HistoryPage
	active        publicationstate.Attempt
	activePresent bool
	attempts      publicationstate.AttemptPage
}

func requirePublicationMaterialPositionOnlyLink(t *testing.T, state publicationMaterialPositionOnlyState, expectedRecord []byte) {
	t.Helper()
	record, err := publication.DecodeSnapshot(expectedRecord)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(expectedRecord)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	require.Equal(t, uint64(0), record.PublicationSeq)
	require.Equal(t, record.PublicationID, state.floor.PublicationID)
	require.True(t, state.floor.SnapshotKey == key)
	require.True(t, bytes.Equal(recordCID, state.floor.RecordCID))
	require.Equal(t, record.Vault, state.floor.Binding.Vault)
	require.Equal(t, record.Blob.Size, state.floor.BlobSize)
	require.True(t, bytes.Equal(record.Blob.CID, state.floor.BlobCID))
	require.NoError(t, publication.VerifyHeadBinding(state.floor.Head, expectedRecord, key))
	head, err := publication.DecodeHead(state.floor.Head)
	require.NoError(t, err)
	require.Equal(t, state.floor.Sequence, head.PublicationSeq)
	require.Equal(t, state.floor.Binding.Vault, head.Vault)
	require.True(t, bytes.Equal(recordCID, head.SnapshotCID))
	require.True(t, bytes.Equal(record.Blob.CID, head.BlobCID))
	require.Len(t, state.history.Events, 1)
	require.False(t, state.history.HasMore)
	require.Equal(t, state.floor.Revision, state.history.NextRevision)
	require.True(t, reflect.DeepEqual(state.floor, state.history.Events[0].NewFloor), "public history must show the exact accepted current floor")
	require.Len(t, state.history.Events[0].Trace, 1)
	require.Len(t, state.history.Records, 1)
	require.True(t, state.history.Events[0].Trace[0].Key == key)
	require.Equal(t, uint64(0), state.history.Events[0].Trace[0].Sequence)
	require.True(t, bytes.Equal(recordCID, state.history.Events[0].Trace[0].CID))
	require.True(t, bytes.Equal(expectedRecord, state.history.Records[0].Raw), "accepted raw record must independently match the supplied fixture record")
	require.True(t, reflect.DeepEqual(state.history.Events[0].Trace[0], state.history.Records[0].Reference), "public event must link the exact record evidence")
	require.False(t, state.activePresent)
	require.Empty(t, state.attempts.Attempts)
}

func requirePublicationMaterialFile(t *testing.T, path string, expected []byte, mode os.FileMode) {
	t.Helper()
	actual, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, bytes.Equal(expected, actual), "private synthetic file must retain expected bytes")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, mode.Perm(), info.Mode().Perm())
}

func recordCIDForPublicationMaterial(t *testing.T, raw []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(raw)
	require.NoError(t, err)
	return cid
}
