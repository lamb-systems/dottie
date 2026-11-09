package publicationstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationReadAcceptedMaterialRepinSameBytesRequiresCurrentRevisionOwner(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	require.Len(t, f.blocks, 2)
	store, _ := newStore(t, f)
	defer store.Close()

	candidate := attemptCandidate(f, 0)
	attempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, candidate)
	initialFloor := finalized.Floor
	initialMaterial, err := store.ReadAcceptedMaterial(ctx, f.binding, initialFloor)
	require.NoError(t, err)
	require.Equal(t, initialFloor, initialMaterial.Floor)
	assert.Equal(t, candidate.SnapshotRecord, initialMaterial.SnapshotRecord)
	assert.Equal(t, candidate.Payload, initialMaterial.Payload)

	advanceObservation := f.observation(2)
	advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, f.payload)
	require.NoError(t, err)
	advanceFloor, err := store.Accept(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, uint64(1), advanceFloor.Sequence)
	assert.Equal(t, initialFloor.Revision+1, advanceFloor.Revision)
	assert.Equal(t, initialFloor.Generation, advanceFloor.Generation)
	assert.NotEqual(t, initialFloor.RecordCID, advanceFloor.RecordCID)

	replacementObservation := f.observation(1)
	require.Len(t, replacementObservation.Snapshots, 1)
	replacementProposal, err := store.Prepare(ctx, ModeReplaceFloor, replacementObservation, f.payload)
	require.NoError(t, err)
	require.Equal(t, ReasonRollback, replacementProposal.Reason)
	replacementFloor, err := store.Accept(ctx, ModeReplaceFloor, replacementProposal.StateToken, replacementObservation, f.payload, replacementProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), replacementFloor.Sequence)
	assert.Equal(t, initialFloor.Revision+2, replacementFloor.Revision)
	assert.Equal(t, initialFloor.Generation+1, replacementFloor.Generation)
	assert.Equal(t, initialFloor.DatabaseID, replacementFloor.DatabaseID)
	assert.Equal(t, candidate.HeadRecord, replacementFloor.Head)
	assert.Equal(t, initialFloor.Head, replacementFloor.Head)
	assert.Equal(t, initialFloor.RecordCID, replacementFloor.RecordCID)
	assert.Equal(t, initialFloor.BlobCID, replacementFloor.BlobCID)
	assert.Equal(t, initialFloor.BlobSize, replacementFloor.BlobSize)
	assert.Equal(t, candidate.SnapshotRecord, f.blocks[0].Raw)
	assert.Equal(t, candidate.SnapshotRecord, replacementObservation.Snapshots[0].Raw)
	assert.Equal(t, candidate.HeadRecord, replacementObservation.Head)
	assert.NotEqual(t, initialFloor.Revision, replacementFloor.Revision)
	assert.NotEqual(t, initialFloor.Generation, replacementFloor.Generation)

	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, replacementFloor, loadedFloor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.False(t, history.HasMore)
	require.Len(t, history.Events, 3)
	latest := history.Events[2]
	assert.Equal(t, replacementFloor, latest.NewFloor)
	var currentRecord []byte
	for _, evidence := range history.Records {
		if evidence.Reference.Key == replacementFloor.SnapshotKey && bytes.Equal(evidence.Reference.CID, replacementFloor.RecordCID) && evidence.Reference.Sequence == replacementFloor.Sequence {
			currentRecord = bytes.Clone(evidence.Raw)
		}
	}
	require.NotEmpty(t, currentRecord)
	assert.Equal(t, candidate.SnapshotRecord, currentRecord)
	var retainedRevision int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT accepted_revision FROM retained_publications WHERE attempt_id=?", attempt.ID[:]).Scan(&retainedRevision))
	assert.Equal(t, int64(initialFloor.Revision), retainedRevision)
	var currentOwnerCount int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", int64(loadedFloor.Revision)).Scan(&currentOwnerCount))
	assert.Zero(t, currentOwnerCount)

	before := readAcceptedMaterialRevisionOwnedState(t, store, attempt.ID)
	beforeRows := readAttemptLogicalRows(t, store)
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, loadedFloor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	after := readAcceptedMaterialRevisionOwnedState(t, store, attempt.ID)
	assert.Equal(t, before, after)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
	assert.Equal(t, candidate.SnapshotRecord, after.Candidate.SnapshotRecord)
	assert.Equal(t, candidate.Payload, after.Candidate.Payload)
}

func TestPublicationReadAcceptedMaterialRecreatedStoreRequiresOwnDatabaseFloor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	require.Len(t, f.blocks, 1)

	storeA, _ := newStore(t, f)
	defer storeA.Close()
	candidateA := attemptCandidate(f, 0)
	attemptA, finalizedA := acceptedMaterialRevisionFinalizeGenesis(t, storeA, f, candidateA)

	storeB, _ := newStore(t, f)
	defer storeB.Close()
	candidateB := attemptCandidate(f, 0)
	attemptB, finalizedB := acceptedMaterialRevisionFinalizeGenesis(t, storeB, f, candidateB)

	assert.Equal(t, f.binding, finalizedA.Floor.Binding)
	assert.Equal(t, f.binding, finalizedB.Floor.Binding)
	assert.Equal(t, finalizedA.Floor.Sequence, finalizedB.Floor.Sequence)
	assert.Equal(t, finalizedA.Floor.Head, finalizedB.Floor.Head)
	assert.Equal(t, finalizedA.Floor.RecordCID, finalizedB.Floor.RecordCID)
	assert.Equal(t, finalizedA.Floor.BlobCID, finalizedB.Floor.BlobCID)
	assert.Equal(t, finalizedA.Floor.BlobSize, finalizedB.Floor.BlobSize)
	assert.Equal(t, candidateA.SnapshotRecord, candidateB.SnapshotRecord)
	assert.Equal(t, candidateA.Payload, candidateB.Payload)
	assert.NotEqual(t, [32]byte{}, finalizedA.Floor.DatabaseID)
	assert.NotEqual(t, [32]byte{}, finalizedB.Floor.DatabaseID)
	assert.NotEqual(t, finalizedA.Floor.DatabaseID, finalizedB.Floor.DatabaseID)

	before := readAcceptedMaterialRevisionOwnedState(t, storeB, attemptB.ID)
	beforeRows := readAttemptLogicalRows(t, storeB)
	material, err := storeB.ReadAcceptedMaterial(ctx, f.binding, finalizedA.Floor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonStale)
	after := readAcceptedMaterialRevisionOwnedState(t, storeB, attemptB.ID)
	assert.Equal(t, before, after)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, storeB))

	loadedFloor, present, err := storeB.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, finalizedB.Floor, loadedFloor)
	beforePositive := readAcceptedMaterialRevisionOwnedState(t, storeB, attemptB.ID)
	beforePositiveRows := readAttemptLogicalRows(t, storeB)
	material, err = storeB.ReadAcceptedMaterial(ctx, f.binding, loadedFloor)
	require.NoError(t, err)
	require.Equal(t, finalizedB.Floor, material.Floor)
	assert.Equal(t, candidateB.SnapshotRecord, material.SnapshotRecord)
	assert.Equal(t, candidateB.Payload, material.Payload)
	afterPositive := readAcceptedMaterialRevisionOwnedState(t, storeB, attemptB.ID)
	assert.Equal(t, beforePositive, afterPositive)
	assert.Equal(t, beforePositiveRows, readAttemptLogicalRows(t, storeB))
	assert.Equal(t, candidateB.SnapshotRecord, afterPositive.Candidate.SnapshotRecord)
	assert.Equal(t, candidateB.Payload, afterPositive.Candidate.Payload)

	attemptAState, err := storeA.LoadAttempt(ctx, attemptA.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, attemptAState.Lifecycle)
}

func TestPublicationReadAcceptedMaterialIgnoresAbandonedCandidateBytes(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	require.Len(t, f.blocks, 1)
	store, directory := newStore(t, f)
	defer store.Close()

	candidate := attemptCandidate(f, 0)
	observation := f.observation(1)
	empty := attemptView(f, observation, true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	beforeAbandon, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidate.SnapshotRecord, beforeAbandon.SnapshotRecord)
	assert.Equal(t, candidate.HeadRecord, beforeAbandon.HeadRecord)
	assert.Equal(t, candidate.Payload, beforeAbandon.Payload)

	abandonProposal, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	abandoned, err := store.AbandonAttempt(ctx, attempt.ID, abandonProposal.StateToken, nil, abandonProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, abandoned.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, abandoned.Outcome)
	active, activePresent, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, activePresent)
	assert.Equal(t, Attempt{}, active)
	var attemptReferences int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attempt.ID[:]).Scan(&attemptReferences))
	assert.Zero(t, attemptReferences)

	catalogBeforeAccept := readAcceptedMaterialAbandonedObject(t, store, directory, candidate, attempt.ID)
	assert.Equal(t, candidate.Payload, catalogBeforeAccept.Payload)
	assert.Zero(t, catalogBeforeAccept.AttemptRefs)
	assert.Zero(t, catalogBeforeAccept.RetainedByBlob)
	candidateSnapshot, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, candidateSnapshot.Blob.CID, catalogBeforeAccept.CID)
	assert.Equal(t, int64(candidateSnapshot.Blob.Size), catalogBeforeAccept.Size)

	abandonedCandidate, err := store.ReadCandidate(ctx, attempt.ID)
	assert.Equal(t, CandidateMaterial{}, abandonedCandidate)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)

	require.Len(t, observation.Snapshots, 1)
	assert.Equal(t, candidate.SnapshotRecord, observation.Snapshots[0].Raw)
	assert.Equal(t, candidate.HeadRecord, observation.Head)
	positionProposal, err := store.Prepare(ctx, ModeFirstUse, observation, f.payload)
	require.NoError(t, err)
	acceptedFloor, err := store.Accept(ctx, ModeFirstUse, positionProposal.StateToken, observation, f.payload, positionProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), acceptedFloor.Sequence)
	assert.Equal(t, candidateSnapshot.PublicationID, acceptedFloor.PublicationID)
	candidateRecordCID, err := publication.RecordCID(candidate.SnapshotRecord)
	require.NoError(t, err)
	assert.Equal(t, candidateRecordCID, acceptedFloor.RecordCID)
	assert.Equal(t, candidate.HeadRecord, acceptedFloor.Head)
	assert.Equal(t, candidateSnapshot.Blob.CID, acceptedFloor.BlobCID)
	assert.Equal(t, candidateSnapshot.Blob.Size, acceptedFloor.BlobSize)
	assert.Equal(t, candidate.SnapshotRecord, observation.Snapshots[0].Raw)
	assert.Equal(t, candidate.HeadRecord, observation.Head)

	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, acceptedFloor, loadedFloor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.False(t, history.HasMore)
	require.Len(t, history.Events, 1)
	assert.Equal(t, loadedFloor, history.Events[0].NewFloor)
	var acceptedRecord []byte
	for _, evidence := range history.Records {
		if evidence.Reference.Key == loadedFloor.SnapshotKey && bytes.Equal(evidence.Reference.CID, loadedFloor.RecordCID) && evidence.Reference.Sequence == loadedFloor.Sequence {
			acceptedRecord = bytes.Clone(evidence.Raw)
		}
	}
	require.NotEmpty(t, acceptedRecord)
	assert.Equal(t, candidate.SnapshotRecord, acceptedRecord)

	catalogBeforeRead := readAcceptedMaterialAbandonedObject(t, store, directory, candidate, attempt.ID)
	assert.Equal(t, catalogBeforeAccept, catalogBeforeRead)
	var currentOwners int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", int64(loadedFloor.Revision)).Scan(&currentOwners))
	assert.Zero(t, currentOwners)
	before := readAcceptedMaterialRevisionAbandonedState(t, store, attempt.ID)
	beforeRows := readAttemptLogicalRows(t, store)
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, loadedFloor)
	assert.Equal(t, AcceptedMaterial{}, material)
	requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
	after := readAcceptedMaterialRevisionAbandonedState(t, store, attempt.ID)
	assert.Equal(t, before, after)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
	catalogAfterRead := readAcceptedMaterialAbandonedObject(t, store, directory, candidate, attempt.ID)
	assert.Equal(t, catalogBeforeRead, catalogAfterRead)
	assert.Equal(t, candidate.Payload, catalogAfterRead.Payload)
}

type acceptedMaterialRevisionOwnedState struct {
	Floor          Floor
	HasFloor       bool
	History        HistoryPage
	Attempt        Attempt
	AttemptHistory AttemptPage
	Candidate      CandidateMaterial
}

func readAcceptedMaterialRevisionOwnedState(t *testing.T, store *Store, attemptID [16]byte) acceptedMaterialRevisionOwnedState {
	t.Helper()
	ctx := context.Background()
	floor, hasFloor, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, hasFloor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Len(t, attemptHistory.Attempts, 1)
	require.Equal(t, attemptID, attemptHistory.Attempts[0].ID)
	candidate, err := store.ReadCandidate(ctx, attemptID)
	require.NoError(t, err)
	return acceptedMaterialRevisionOwnedState{Floor: floor, HasFloor: hasFloor, History: history, Attempt: attempt, AttemptHistory: attemptHistory, Candidate: candidate}
}

type acceptedMaterialRevisionAbandonedState struct {
	Floor          Floor
	HasFloor       bool
	History        HistoryPage
	Attempt        Attempt
	AttemptHistory AttemptPage
	Candidate      CandidateMaterial
}

func readAcceptedMaterialRevisionAbandonedState(t *testing.T, store *Store, attemptID [16]byte) acceptedMaterialRevisionAbandonedState {
	t.Helper()
	ctx := context.Background()
	floor, hasFloor, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, hasFloor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	attempt, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Len(t, attemptHistory.Attempts, 1)
	require.Equal(t, attemptID, attemptHistory.Attempts[0].ID)
	candidate, err := store.ReadCandidate(ctx, attemptID)
	assert.Equal(t, CandidateMaterial{}, candidate)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)
	return acceptedMaterialRevisionAbandonedState{Floor: floor, HasFloor: hasFloor, History: history, Attempt: attempt, AttemptHistory: attemptHistory, Candidate: candidate}
}

func acceptedMaterialRevisionFinalizeGenesis(t *testing.T, store *Store, f fixture, candidate CandidateInput) (Attempt, Finalization) {
	t.Helper()
	ctx := context.Background()
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	require.Equal(t, OutcomeCurrent, resolution.Outcome)
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	require.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	require.Equal(t, OutcomeCurrent, finalized.Attempt.Outcome)
	return attempt, finalized
}

type acceptedMaterialAbandonedObject struct {
	CID            []byte
	Size           int64
	Basename       string
	Payload        []byte
	AttemptRefs    int64
	RetainedByBlob int64
}

func readAcceptedMaterialAbandonedObject(t *testing.T, store *Store, directory string, candidate CandidateInput, attemptID [16]byte) acceptedMaterialAbandonedObject {
	t.Helper()
	ctx := context.Background()
	snapshot, err := publication.DecodeSnapshot(candidate.SnapshotRecord)
	require.NoError(t, err)
	var catalogCID []byte
	var catalogSize int64
	var basename string
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT blob_cid,size,basename FROM payload_objects WHERE blob_cid=?", snapshot.Blob.CID).Scan(&catalogCID, &catalogSize, &basename))
	assert.Equal(t, snapshot.Blob.CID, catalogCID)
	assert.Equal(t, int64(snapshot.Blob.Size), catalogSize)
	wantedBasename, err := payloadBasenameFromCID(catalogCID)
	require.NoError(t, err)
	require.True(t, validPayloadBasename(basename))
	require.Equal(t, wantedBasename, basename)
	path := filepath.Join(directory, payloadDirectoryName, basename)
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, payload)
	var attemptRefs int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attemptID[:]).Scan(&attemptRefs))
	var retainedByBlob int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE blob_cid=?", catalogCID).Scan(&retainedByBlob))
	return acceptedMaterialAbandonedObject{CID: bytes.Clone(catalogCID), Size: catalogSize, Basename: basename, Payload: bytes.Clone(payload), AttemptRefs: attemptRefs, RetainedByBlob: retainedByBlob}
}
