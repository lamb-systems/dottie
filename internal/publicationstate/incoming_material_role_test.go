package publicationstate

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptMaterialCoexistsWithPreparedAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	composition := incomingRolePrepareUnownedWithSuccessor(t, store, f)
	require.Equal(t, uint64(1), composition.accepted.Revision)
	mutationBefore := store.attemptMutationRevision
	require.NotZero(t, mutationBefore)
	durableBefore := intakeDurableMutation(t, ctx, store)
	require.NotZero(t, durableBefore)
	before := incomingRoleCaptureState(t, ctx, store.conn)
	fileBefore := incomingRolePayloadFileState(t, directory, f.payload)
	require.True(t, fileBefore.Exists)

	observation := f.observation(1)
	attach, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "same", attach.Stop)
	floor, err := store.acceptMaterial(ctx, ModeAdvance, attach.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, composition.accepted, floor)

	after := incomingRoleCaptureState(t, ctx, store.conn)
	incomingRoleRequireUnchangedExceptReferences(t, before, after)
	incomingRoleRequireSingleReference(t, before, after, floor)
	fileAfter := incomingRolePayloadFileState(t, directory, f.payload)
	assert.Equal(t, fileBefore, fileAfter)
	assert.Equal(t, mutationBefore, store.attemptMutationRevision)
	assert.Equal(t, durableBefore, intakeDurableMutation(t, ctx, store))

	attempt, err := store.LoadAttempt(ctx, composition.attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptPrepared, attempt.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, attempt.Outcome)
	assert.Empty(t, attempt.Blocked)
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", composition.attempt.ID[:]))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", composition.attempt.ID[:]))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications"))

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, composition.accepted, loaded)

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)

	candidate, err := store.ReadCandidate(ctx, composition.attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, composition.attempt.ID, candidate.AttemptID)
	assert.Equal(t, f.blocks[1].Raw, candidate.SnapshotRecord)
	assert.Equal(t, f.payload, candidate.Payload)

	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, composition.attempt.ID, active.ID)
}

func TestAcceptMaterialCoexistsWithSubmittedAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	composition := incomingRolePrepareUnownedWithSuccessor(t, store, f)
	incomingRoleSubmitAttempt(t, store, composition, f.payload)

	submitted, err := store.LoadAttempt(ctx, composition.attempt.ID)
	require.NoError(t, err)
	require.Equal(t, AttemptMayHaveSubmitted, submitted.Lifecycle)
	require.Equal(t, OutcomeUnresolved, submitted.Outcome)
	require.Empty(t, submitted.Blocked)
	witnessBefore := incomingRoleSubmissionWitness(t, ctx, store, composition.attempt.ID)
	activeBefore, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, composition.attempt.ID, activeBefore.ID)
	require.Equal(t, AttemptMayHaveSubmitted, activeBefore.Lifecycle)
	mutationBefore := store.attemptMutationRevision
	durableBefore := intakeDurableMutation(t, ctx, store)
	before := incomingRoleCaptureState(t, ctx, store.conn)
	fileBefore := incomingRolePayloadFileState(t, directory, f.payload)
	require.True(t, fileBefore.Exists)

	observation := f.observation(1)
	attach, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "same", attach.Stop)
	floor, err := store.acceptMaterial(ctx, ModeAdvance, attach.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, composition.accepted, floor)

	after := incomingRoleCaptureState(t, ctx, store.conn)
	incomingRoleRequireUnchangedExceptReferences(t, before, after)
	incomingRoleRequireSingleReference(t, before, after, floor)
	witnessAfter := incomingRoleSubmissionWitness(t, ctx, store, composition.attempt.ID)
	assert.Equal(t, witnessBefore, witnessAfter)
	fileAfter := incomingRolePayloadFileState(t, directory, f.payload)
	assert.Equal(t, fileBefore, fileAfter)
	assert.Equal(t, mutationBefore, store.attemptMutationRevision)
	assert.Equal(t, durableBefore, intakeDurableMutation(t, ctx, store))

	unchanged, err := store.LoadAttempt(ctx, composition.attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, unchanged.Lifecycle)
	assert.Equal(t, OutcomeUnresolved, unchanged.Outcome)
	assert.Empty(t, unchanged.Blocked)
	activeAfter, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, activeBefore, activeAfter)
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", composition.attempt.ID[:]))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", composition.attempt.ID[:]))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications"))

	candidate, err := store.ReadCandidate(ctx, composition.attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, composition.attempt.ID, candidate.AttemptID)
	assert.Equal(t, f.blocks[1].Raw, candidate.SnapshotRecord)
	assert.Equal(t, f.payload, candidate.Payload)

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)
}

func TestAcceptMaterialCoexistsWithAbandonedAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptGenesis, attempt.Kind)
	require.Equal(t, AttemptPrepared, attempt.Lifecycle)

	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	require.Equal(t, OutcomeNotSubmitted, retired.Outcome)
	_, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)

	mutationBefore := store.attemptMutationRevision
	durableBefore := intakeDurableMutation(t, ctx, store)
	require.NotZero(t, durableBefore)
	before := incomingRoleCaptureState(t, ctx, store.conn)
	require.Empty(t, before.records)
	require.Empty(t, before.events)
	require.Empty(t, before.activeFloor)
	require.Empty(t, before.incoming)
	require.Empty(t, before.retained)
	require.Empty(t, before.reservations)
	require.Len(t, before.attempts, 1)
	require.Len(t, before.objects, 1)
	fileBefore := incomingRolePayloadFileState(t, directory, f.payload)
	require.True(t, fileBefore.Exists)

	observation := f.observation(1)
	intake := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.acceptMaterial(ctx, ModeFirstUse, intake.StateToken, observation, f.payload, intake.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), floor.Revision)
	require.Equal(t, uint64(1), floor.Generation)

	after := incomingRoleCaptureState(t, ctx, store.conn)
	require.Equal(t, before.attempts, after.attempts)
	require.Equal(t, before.attemptEvents, after.attemptEvents)
	require.Equal(t, before.attemptEvidence, after.attemptEvidence)
	require.Equal(t, before.reservations, after.reservations)
	require.Equal(t, before.objects, after.objects)
	require.Equal(t, before.retained, after.retained)
	require.Equal(t, before.meta["attempt_mutation_revision"], after.meta["attempt_mutation_revision"])
	incomingRoleRequireSingleReference(t, before, after, floor)
	incomingRoleRequireFirstUseAcceptance(t, after, floor, f.blocks[0])
	fileAfter := incomingRolePayloadFileState(t, directory, f.payload)
	assert.Equal(t, fileBefore, fileAfter)
	assert.Equal(t, mutationBefore, store.attemptMutationRevision)
	assert.Equal(t, durableBefore, intakeDurableMutation(t, ctx, store))

	abandoned, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, abandoned.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, abandoned.Outcome)
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attempt.ID[:]))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_reservations WHERE attempt_id=?", attempt.ID[:]))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications"))

	missing, err := store.ReadCandidate(ctx, attempt.ID)
	assert.Equal(t, CandidateMaterial{}, missing)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)
}

func TestAcceptMaterialAdvancesPastRetainedPublication(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	retainedAttempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
	require.Equal(t, uint64(1), finalized.Floor.Revision)
	require.Equal(t, uint64(1), finalized.Floor.Generation)
	require.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	mutationBefore := store.attemptMutationRevision
	durableBefore := intakeDurableMutation(t, ctx, store)
	before := incomingRoleCaptureState(t, ctx, store.conn)
	require.Empty(t, before.incoming)
	require.Len(t, before.records, 1)
	require.Len(t, before.events, 1)
	require.Len(t, before.retained, 1)
	require.Len(t, before.attempts, 1)
	fileBefore := incomingRolePayloadFileState(t, directory, f.payload)
	require.True(t, fileBefore.Exists)

	observation := f.observation(2)
	advance, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "joined", advance.Stop)
	second, err := store.acceptMaterial(ctx, ModeAdvance, advance.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, uint64(2), second.Revision)

	after := incomingRoleCaptureState(t, ctx, store.conn)
	incomingRoleRequireKeptRows(t, before.records, after.records)
	incomingRoleRequireKeptRows(t, before.events, after.events)
	require.Len(t, after.records, len(before.records)+1)
	require.Len(t, after.events, len(before.events)+1)
	require.Equal(t, before.retained, after.retained)
	require.Equal(t, before.attempts, after.attempts)
	require.Equal(t, before.attemptEvents, after.attemptEvents)
	require.Equal(t, before.attemptEvidence, after.attemptEvidence)
	require.Equal(t, before.reservations, after.reservations)
	require.Equal(t, before.objects, after.objects)
	require.Equal(t, before.meta["attempt_mutation_revision"], after.meta["attempt_mutation_revision"])
	require.Equal(t, before.meta["generation"], after.meta["generation"])
	assert.NotEqual(t, before.meta["revision"], after.meta["revision"])
	require.Len(t, after.activeFloor, 1)
	current, err := decodeFloor(incomingRoleBytes(t, after.activeFloor[0], incomingRoleFloorValue))
	require.NoError(t, err)
	assert.True(t, sameAcceptedFloor(second, current))
	incomingRoleRequireSingleReference(t, before, after, second)
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=?", int64(finalized.Floor.Revision)))
	fileAfter := incomingRolePayloadFileState(t, directory, f.payload)
	assert.Equal(t, fileBefore, fileAfter)
	assert.Equal(t, mutationBefore, store.attemptMutationRevision)
	assert.Equal(t, durableBefore, intakeDurableMutation(t, ctx, store))

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, second)
	require.NoError(t, err)
	assert.Equal(t, second, material.Floor)
	assert.Equal(t, f.blocks[1].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)

	stale, err := store.ReadAcceptedMaterial(ctx, f.binding, finalized.Floor)
	assert.Equal(t, AcceptedMaterial{}, stale)
	requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonStale)

	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Len(t, history.Events, 2)
	assert.Equal(t, finalized.Floor, history.Events[0].NewFloor)
	assert.Equal(t, second, history.Events[1].NewFloor)

	retained, err := store.LoadAttempt(ctx, retainedAttempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, retained.Lifecycle)
	assert.Equal(t, OutcomeCurrent, retained.Outcome)
}

func TestAcceptMaterialKeepsFinalizedOwnerOnSamePosition(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	_, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
	require.Equal(t, uint64(1), finalized.Floor.Revision)
	mutationBefore := store.attemptMutationRevision
	durableBefore := intakeDurableMutation(t, ctx, store)
	before := incomingRoleCaptureState(t, ctx, store.conn)
	require.Empty(t, before.incoming)
	require.Len(t, before.retained, 1)
	fileBefore := incomingRolePayloadFileState(t, directory, f.payload)
	require.True(t, fileBefore.Exists)

	observation := f.observation(1)
	same, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "same", same.Stop)
	floor, err := store.acceptMaterial(ctx, ModeAdvance, same.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, finalized.Floor, floor)

	after := incomingRoleCaptureState(t, ctx, store.conn)
	require.Equal(t, before.records, after.records)
	require.Equal(t, before.events, after.events)
	require.Equal(t, before.activeFloor, after.activeFloor)
	require.Equal(t, before.meta, after.meta)
	require.Equal(t, before.attempts, after.attempts)
	require.Equal(t, before.attemptEvents, after.attemptEvents)
	require.Equal(t, before.attemptEvidence, after.attemptEvidence)
	require.Equal(t, before.reservations, after.reservations)
	require.Equal(t, before.retained, after.retained)
	require.Equal(t, before.objects, after.objects)
	assert.Empty(t, after.incoming)
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	fileAfter := incomingRolePayloadFileState(t, directory, f.payload)
	assert.Equal(t, fileBefore, fileAfter)
	assert.Equal(t, mutationBefore, store.attemptMutationRevision)
	assert.Equal(t, durableBefore, intakeDurableMutation(t, ctx, store))

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)
}

func TestAcceptMaterialCompositionPreservesRawState(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	composition := incomingRolePrepareUnownedWithSuccessor(t, store, f)

	before := incomingRoleCaptureState(t, ctx, store.conn)
	require.Empty(t, before.incoming)
	require.Len(t, before.objects, 1)
	catalog := before.objects[0]
	assert.Equal(t, composition.accepted.BlobCID, incomingRoleBytes(t, catalog, incomingRoleObjectCID))
	assert.Equal(t, payloadBasename(f.payload), incomingRoleText(t, catalog, incomingRoleObjectBasename))
	assert.Equal(t, int64(len(f.payload)), incomingRoleInt(t, catalog, incomingRoleObjectSize))
	assert.Equal(t, int64(len(f.payload)), incomingRoleInt(t, catalog, incomingRoleObjectLogicalBytes))
	fileBefore := incomingRolePayloadFileState(t, directory, f.payload)
	require.True(t, fileBefore.Exists)
	assert.Equal(t, f.payload, fileBefore.Bytes)

	observation := f.observation(1)
	attach, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	require.Equal(t, "same", attach.Stop)
	floor, err := store.acceptMaterial(ctx, ModeAdvance, attach.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, composition.accepted, floor)

	after := incomingRoleCaptureState(t, ctx, store.conn)
	incomingRoleRequireUnchangedExceptReferences(t, before, after)
	incomingRoleRequireSingleReference(t, before, after, floor)
	require.Len(t, after.objects, 1)
	assert.Equal(t, catalog, after.objects[0])
	fileAfter := incomingRolePayloadFileState(t, directory, f.payload)
	assert.Equal(t, fileBefore, fileAfter)
	assert.Equal(t, f.payload, fileAfter.Bytes)

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, composition.accepted, loaded)
}

type incomingRoleSuccessorState struct {
	accepted Floor
	attempt  Attempt
	view     SuppliedRepositoryView
	review   LocalReviewContext
}

func incomingRolePrepareUnownedWithSuccessor(t *testing.T, store *Store, f fixture) incomingRoleSuccessorState {
	t.Helper()
	ctx := context.Background()
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	accepted, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	candidate := attemptCandidate(f, 1)
	view := attemptView(f, observation, false)
	review := attemptReview()
	attemptProposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, attemptProposal.StateToken, candidate, view, review, attemptProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptSuccessor, attempt.Kind)
	require.Equal(t, AttemptPrepared, attempt.Lifecycle)
	require.Equal(t, OutcomeNotSubmitted, attempt.Outcome)
	return incomingRoleSuccessorState{accepted: accepted, attempt: attempt, view: view, review: review}
}

func incomingRoleSubmitAttempt(t *testing.T, store *Store, state incomingRoleSuccessorState, payload []byte) {
	t.Helper()
	ctx := context.Background()
	uploadProposal, err := store.PrepareDispatch(ctx, state.attempt.ID, DispatchUpload, state.view, state.review)
	require.NoError(t, err)
	upload, err := store.BeginUpload(ctx, state.attempt.ID, uploadProposal.StateToken, state.view, state.review, uploadProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, state.attempt.ID, upload.AttemptID)
	require.Equal(t, payload, upload.Payload)
	submissionProposal, err := store.PrepareDispatch(ctx, state.attempt.ID, DispatchSubmission, state.view, state.review)
	require.NoError(t, err)
	submission, err := store.BeginSubmission(ctx, state.attempt.ID, submissionProposal.StateToken, state.view, state.review, submissionProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, state.attempt.ID, submission.AttemptID)
}

func incomingRoleSubmissionWitness(t *testing.T, ctx context.Context, store *Store, id [16]byte) incomingRoleSubmissionWitnessState {
	t.Helper()
	var body []byte
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body FROM attempt_events WHERE attempt_id=? AND kind='may-have-submitted'", id[:]).Scan(&body))
	require.NotEmpty(t, body)
	var event attemptEventWire
	require.NoError(t, strictJSON(body, &event))
	assert.Equal(t, "may-have-submitted", event.Kind)
	require.NotEmpty(t, event.Evidence)
	return incomingRoleSubmissionWitnessState{body: bytes.Clone(body), evidence: bytes.Clone(event.Evidence)}
}

type incomingRoleSubmissionWitnessState struct {
	body     []byte
	evidence []byte
}

const (
	incomingRoleRecordCID = iota
	incomingRoleRecordKey
	incomingRoleRecordSequence
	incomingRoleRecordRaw
	incomingRoleRecordLogicalBytes
)

const (
	incomingRoleEventRevision = iota
	incomingRoleEventMode
	incomingRoleEventReason
	incomingRoleEventStop
	incomingRoleEventOldFloor
	incomingRoleEventNewFloor
	incomingRoleEventBody
	incomingRoleEventDigest
	incomingRoleEventLogicalBytes
)

const (
	incomingRoleReferenceRevision = iota
	incomingRoleReferenceRecordCID
	incomingRoleReferenceBlobCID
)

const (
	incomingRoleFloorSingleton = iota
	incomingRoleFloorValue
)

const (
	incomingRoleObjectCID = iota
	incomingRoleObjectSize
	incomingRoleObjectBasename
	incomingRoleObjectLogicalBytes
)

type incomingRoleRawState struct {
	records         map[string][]any
	events          map[string][]any
	activeFloor     [][]any
	meta            map[string][]byte
	attempts        [][]any
	attemptEvents   [][]any
	attemptEvidence [][]any
	reservations    [][]any
	retained        [][]any
	objects         [][]any
	incoming        [][]any
}

func incomingRoleCaptureState(t *testing.T, ctx context.Context, q queryer) incomingRoleRawState {
	t.Helper()
	return incomingRoleRawState{
		records:         incomingRoleKeyedRows(t, ctx, q, "SELECT cid,record_key,sequence,raw,logical_bytes FROM accepted_records ORDER BY cid"),
		events:          incomingRoleKeyedRows(t, ctx, q, "SELECT revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes FROM accepted_events ORDER BY revision"),
		activeFloor:     incomingRoleRows(t, ctx, q, "SELECT singleton,floor FROM active_floor"),
		meta:            incomingRoleMeta(t, ctx, q),
		attempts:        incomingRoleRows(t, ctx, q, "SELECT attempt_id,core,lifecycle,outcome,blocked,state_digest,mutation_revision,created_order,logical_bytes,terminal_evidence,retirement_evidence FROM publication_attempts ORDER BY attempt_id"),
		attemptEvents:   incomingRoleRows(t, ctx, q, "SELECT attempt_id,ordinal,kind,body,digest FROM attempt_events ORDER BY attempt_id,ordinal"),
		attemptEvidence: incomingRoleRows(t, ctx, q, "SELECT attempt_id,role,body FROM attempt_evidence ORDER BY attempt_id,role"),
		reservations:    incomingRoleRows(t, ctx, q, "SELECT attempt_id,metadata_bytes,accepted_bytes,accepted_records,accepted_events,retained_points FROM attempt_reservations ORDER BY attempt_id"),
		retained:        incomingRoleRows(t, ctx, q, "SELECT record_cid,attempt_id,sequence,blob_cid,size,accepted_revision FROM retained_publications ORDER BY record_cid"),
		objects:         incomingRoleRows(t, ctx, q, "SELECT blob_cid,size,basename,logical_bytes FROM payload_objects ORDER BY blob_cid"),
		incoming:        incomingRoleRows(t, ctx, q, "SELECT accepted_revision,record_cid,blob_cid FROM accepted_material_refs ORDER BY accepted_revision"),
	}
}

func incomingRoleRows(t *testing.T, ctx context.Context, q queryer, query string) [][]any {
	t.Helper()
	rows, err := q.QueryContext(ctx, query)
	require.NoError(t, err)
	columns, err := rows.Columns()
	require.NoError(t, err)
	result := make([][]any, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for index := range values {
			destinations[index] = &values[index]
		}
		require.NoError(t, rows.Scan(destinations...))
		result = append(result, values)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	return result
}

func incomingRoleKeyedRows(t *testing.T, ctx context.Context, q queryer, query string) map[string][]any {
	t.Helper()
	keyed := make(map[string][]any)
	for _, row := range incomingRoleRows(t, ctx, q, query) {
		keyed[incomingRoleRowKey(t, row)] = row
	}
	return keyed
}

func incomingRoleRowKey(t *testing.T, row []any) string {
	t.Helper()
	require.NotEmpty(t, row)
	switch value := row[0].(type) {
	case []byte:
		return fmt.Sprintf("bytes:%x", value)
	case int64:
		return fmt.Sprintf("int:%d", value)
	case string:
		return "text:" + value
	default:
		require.FailNowf(t, "unexpected row key column", "%T", row[0])
		return ""
	}
}

func incomingRoleMeta(t *testing.T, ctx context.Context, q queryer) map[string][]byte {
	t.Helper()
	meta := make(map[string][]byte)
	for _, row := range incomingRoleRows(t, ctx, q, "SELECT key,value FROM store_meta ORDER BY key") {
		meta[incomingRoleText(t, row, 0)] = incomingRoleBytes(t, row, 1)
	}
	return meta
}

func incomingRoleBytes(t *testing.T, row []any, index int) []byte {
	t.Helper()
	require.Greater(t, len(row), index)
	value, ok := row[index].([]byte)
	require.Truef(t, ok, "column %d holds %T, want []byte", index, row[index])
	return value
}

func incomingRoleText(t *testing.T, row []any, index int) string {
	t.Helper()
	require.Greater(t, len(row), index)
	value, ok := row[index].(string)
	require.Truef(t, ok, "column %d holds %T, want string", index, row[index])
	return value
}

func incomingRoleInt(t *testing.T, row []any, index int) int64 {
	t.Helper()
	require.Greater(t, len(row), index)
	value, ok := row[index].(int64)
	require.Truef(t, ok, "column %d holds %T, want int64", index, row[index])
	return value
}

func incomingRoleSingleRow(t *testing.T, keyed map[string][]any) []any {
	t.Helper()
	require.Len(t, keyed, 1)
	for _, row := range keyed {
		return row
	}
	return nil
}

func incomingRolePayloadFileState(t *testing.T, directory string, payload []byte) acceptedMaterialPayloadFileState {
	t.Helper()
	file, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, payloadBasename(payload)), len(payload))
	require.NoError(t, err)
	return file
}

func incomingRoleRequireUnchangedExceptReferences(t *testing.T, before, after incomingRoleRawState) {
	t.Helper()
	require.Equal(t, before.records, after.records)
	require.Equal(t, before.events, after.events)
	require.Equal(t, before.activeFloor, after.activeFloor)
	require.Equal(t, before.meta, after.meta)
	require.Equal(t, before.attempts, after.attempts)
	require.Equal(t, before.attemptEvents, after.attemptEvents)
	require.Equal(t, before.attemptEvidence, after.attemptEvidence)
	require.Equal(t, before.reservations, after.reservations)
	require.Equal(t, before.retained, after.retained)
	require.Equal(t, before.objects, after.objects)
}

func incomingRoleRequireKeptRows(t *testing.T, before, after map[string][]any) {
	t.Helper()
	for key, row := range before {
		require.Contains(t, after, key)
		require.Equal(t, row, after[key], key)
	}
}

func incomingRoleRequireSingleReference(t *testing.T, before, after incomingRoleRawState, floor Floor) {
	t.Helper()
	require.Empty(t, before.incoming)
	require.Len(t, after.incoming, 1)
	assert.Equal(t, int64(floor.Revision), incomingRoleInt(t, after.incoming[0], incomingRoleReferenceRevision))
	assert.Equal(t, floor.RecordCID, incomingRoleBytes(t, after.incoming[0], incomingRoleReferenceRecordCID))
	assert.Equal(t, floor.BlobCID, incomingRoleBytes(t, after.incoming[0], incomingRoleReferenceBlobCID))
}

func incomingRoleRequireFirstUseAcceptance(t *testing.T, state incomingRoleRawState, floor Floor, block SnapshotBlock) {
	t.Helper()
	record := incomingRoleSingleRow(t, state.records)
	assert.Equal(t, floor.RecordCID, incomingRoleBytes(t, record, incomingRoleRecordCID))
	assert.Equal(t, block.Key, incomingRoleText(t, record, incomingRoleRecordKey))
	assert.Equal(t, int64(0), incomingRoleInt(t, record, incomingRoleRecordSequence))
	assert.Equal(t, block.Raw, incomingRoleBytes(t, record, incomingRoleRecordRaw))
	assert.Equal(t, int64(len(block.Raw)+len(floor.RecordCID)+len(block.Key)+8), incomingRoleInt(t, record, incomingRoleRecordLogicalBytes))

	event := incomingRoleSingleRow(t, state.events)
	assert.Equal(t, int64(floor.Revision), incomingRoleInt(t, event, incomingRoleEventRevision))
	assert.Equal(t, string(ModeFirstUse), incomingRoleText(t, event, incomingRoleEventMode))
	assert.Empty(t, incomingRoleText(t, event, incomingRoleEventReason))
	assert.Equal(t, "first_use", incomingRoleText(t, event, incomingRoleEventStop))
	assert.Nil(t, event[incomingRoleEventOldFloor])
	accepted, err := decodeFloor(incomingRoleBytes(t, event, incomingRoleEventNewFloor))
	require.NoError(t, err)
	assert.True(t, sameAcceptedFloor(floor, accepted))
	body := incomingRoleBytes(t, event, incomingRoleEventBody)
	digest := incomingRoleBytes(t, event, incomingRoleEventDigest)
	newFloor := incomingRoleBytes(t, event, incomingRoleEventNewFloor)
	require.NotEmpty(t, body)
	require.Len(t, digest, 32)
	assert.Equal(t, int64(len(body)+len(digest)+len(newFloor)+len(string(ModeFirstUse))+len("first_use")+8), incomingRoleInt(t, event, incomingRoleEventLogicalBytes))

	require.Len(t, state.activeFloor, 1)
	assert.Equal(t, int64(1), incomingRoleInt(t, state.activeFloor[0], incomingRoleFloorSingleton))
	current, err := decodeFloor(incomingRoleBytes(t, state.activeFloor[0], incomingRoleFloorValue))
	require.NoError(t, err)
	assert.True(t, sameAcceptedFloor(floor, current))
}

func incomingRoleAcceptAttachedFirstUse(t *testing.T, store *Store, f fixture) Floor {
	t.Helper()
	ctx := context.Background()
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), floor.Revision)
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	return floor
}
