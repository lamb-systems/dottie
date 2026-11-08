package publicationstate

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptMetadataCorruptionRefusesReadback(t *testing.T) {
	for _, damage := range []string{"event-digest", "reference", "reservation"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, _ := newStore(t, f)
			defer store.Close()
			candidate := attemptCandidate(f, 0)
			view := attemptView(f, f.observation(1), true)
			review := attemptReview()
			proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
			require.NoError(t, err)
			attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
			require.NoError(t, err)
			var statement string
			switch damage {
			case "event-digest":
				statement = "UPDATE attempt_events SET digest=zeroblob(32) WHERE attempt_id=x'" + hexID(attempt.ID) + "' AND ordinal=1"
			case "reference":
				statement = "DELETE FROM attempt_payload_refs WHERE attempt_id=x'" + hexID(attempt.ID) + "'"
			case "reservation":
				statement = "UPDATE attempt_reservations SET accepted_records=-1 WHERE attempt_id=x'" + hexID(attempt.ID) + "'"
			}
			_, err = store.conn.ExecContext(ctx, statement)
			require.NoError(t, err)
			_, _, err = store.Load(ctx)
			requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
		})
	}
}

type attemptProjectionSnapshot struct {
	lifecycle          string
	outcome            string
	blocked            string
	stateDigest        []byte
	mutationRevision   int64
	terminalEvidence   []byte
	retirementEvidence []byte
}

func readAttemptProjectionSnapshot(t *testing.T, store *Store, id [16]byte) attemptProjectionSnapshot {
	t.Helper()
	var snapshot attemptProjectionSnapshot
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT lifecycle,outcome,blocked,state_digest,mutation_revision,terminal_evidence,retirement_evidence FROM publication_attempts WHERE attempt_id=?", id[:]).Scan(&snapshot.lifecycle, &snapshot.outcome, &snapshot.blocked, &snapshot.stateDigest, &snapshot.mutationRevision, &snapshot.terminalEvidence, &snapshot.retirementEvidence))
	return snapshot
}

func restoreAttemptProjectionSnapshot(t *testing.T, store *Store, id [16]byte, snapshot attemptProjectionSnapshot) {
	t.Helper()
	result, err := store.conn.ExecContext(context.Background(), "UPDATE publication_attempts SET lifecycle=?,outcome=?,blocked=?,state_digest=?,mutation_revision=?,terminal_evidence=?,retirement_evidence=? WHERE attempt_id=?", snapshot.lifecycle, snapshot.outcome, snapshot.blocked, snapshot.stateDigest, snapshot.mutationRevision, snapshot.terminalEvidence, snapshot.retirementEvidence, id[:])
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	assert.Equal(t, int64(1), affected)
}

func TestPublicationAttemptReadbackRejectsPreSubmissionProjectionWithSubmissionJournal(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, empty, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, empty, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	oldProjection := readAttemptProjectionSnapshot(t, store, attempt.ID)
	assert.Equal(t, string(AttemptUploadStarted), oldProjection.lifecycle)
	assert.Equal(t, string(OutcomeNotSubmitted), oldProjection.outcome)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	firstBatch, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, attempt.SnapshotRecordCID, firstBatch.ExpectedSnapshotCID)
	var submissionEvents int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=? AND kind='may-have-submitted'", attempt.ID[:]).Scan(&submissionEvents))
	assert.Equal(t, 1, submissionEvents)
	restoreAttemptProjectionSnapshot(t, store, attempt.ID, oldProjection)
	corruptRows := readAttemptLogicalRows(t, store)
	store.needsReadback = true
	_, _, err = store.Load(ctx)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
	assert.True(t, store.needsReadback)
	assert.Equal(t, corruptRows, readAttemptLogicalRows(t, store))
	secondBatch, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	assert.Equal(t, SubmissionMaterial{}, secondBatch)
	assert.Equal(t, corruptRows, readAttemptLogicalRows(t, store))
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
	assert.Nil(t, reopened)
}

func TestPublicationAttemptReadbackRejectsPreOutcomeProjectionWithOutcomeJournal(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	oldProjection := readAttemptProjectionSnapshot(t, store, attempt.ID)
	assert.Equal(t, string(AttemptMayHaveSubmitted), oldProjection.lifecycle)
	assert.Equal(t, string(OutcomeUnresolved), oldProjection.outcome)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	restoreAttemptProjectionSnapshot(t, store, attempt.ID, oldProjection)
	corruptRows := readAttemptLogicalRows(t, store)
	store.needsReadback = true
	_, _, err = store.Load(ctx)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
	assert.True(t, store.needsReadback)
	assert.Equal(t, corruptRows, readAttemptLogicalRows(t, store))
	require.NoError(t, store.Close())
	_, err = Open(directory, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
}

func TestPublicationAttemptJournalRejectsSubmissionBeforeUpload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	var uploadBody, submissionBody []byte
	var uploadDigest, submissionDigest []byte
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body,digest FROM attempt_events WHERE attempt_id=? AND ordinal=2", attempt.ID[:]).Scan(&uploadBody, &uploadDigest))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body,digest FROM attempt_events WHERE attempt_id=? AND ordinal=3", attempt.ID[:]).Scan(&submissionBody, &submissionDigest))
	var uploadEvent, submissionEvent attemptEventWire
	require.NoError(t, strictJSON(uploadBody, &uploadEvent))
	require.NoError(t, strictJSON(submissionBody, &submissionEvent))
	assert.Equal(t, "upload-started", uploadEvent.Kind)
	assert.Equal(t, "may-have-submitted", submissionEvent.Kind)

	uploadEvent.Kind = "may-have-submitted"
	uploadEvent.Evidence = bytes.Clone(submissionEvent.Evidence)
	misorderedUpload, err := encodeAttemptEvent(uploadEvent)
	require.NoError(t, err)
	misorderedUploadDigest := domainHash("systems.lamb.dottie.publication-attempt-event.v1", misorderedUpload)
	submissionEvent.Kind = "upload-started"
	submissionEvent.Evidence = nil
	submissionEvent.PreviousDigest = bytes.Clone(misorderedUploadDigest[:])
	misorderedSubmission, err := encodeAttemptEvent(submissionEvent)
	require.NoError(t, err)
	misorderedSubmissionDigest := domainHash("systems.lamb.dottie.publication-attempt-event.v1", misorderedSubmission)
	_, err = store.conn.ExecContext(ctx, "UPDATE attempt_events SET body=?,digest=? WHERE attempt_id=? AND ordinal=2", misorderedUpload, misorderedUploadDigest[:], attempt.ID[:])
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "UPDATE attempt_events SET body=?,digest=? WHERE attempt_id=? AND ordinal=3", misorderedSubmission, misorderedSubmissionDigest[:], attempt.ID[:])
	require.NoError(t, err)
	assertAttemptLogicalBytesExact(t, store, attempt.ID)
	corruptRows := readAttemptLogicalRows(t, store)
	_, _, err = store.Load(ctx)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
	assert.Equal(t, corruptRows, readAttemptLogicalRows(t, store))
	var attemptEvents int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=?", attempt.ID[:]).Scan(&attemptEvents))
	assert.Equal(t, 3, attemptEvents)
}

func TestPublicationAttemptJournalAcceptsRepeatedUploadAndRolledBackSubmission(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitPreparationForFaultTest(t, store, candidate, empty, review)
	var eventCount int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=?", attempt.ID[:]).Scan(&eventCount))
	assert.Equal(t, 2, eventCount)
	repeatProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, empty, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, repeatProposal.StateToken, empty, review, repeatProposal.Confirmation)
	require.NoError(t, err)
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=?", attempt.ID[:]).Scan(&eventCount))
	assert.Equal(t, 2, eventCount)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, loaded.Lifecycle)
	before := readAttemptLogicalRows(t, store)
	candidateBefore, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER fail_projection_submission AFTER INSERT ON main.attempt_events WHEN NEW.kind='may-have-submitted' BEGIN INSERT INTO attempt_commit_child(id) VALUES(105); END")
	material, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	assert.Equal(t, SubmissionMaterial{}, material)
	assert.True(t, store.needsReadback)
	_, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.False(t, store.needsReadback)
	rolledBack, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, rolledBack.Lifecycle)
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	candidateAfter, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidateBefore, candidateAfter)
	removeDeferredAttemptCommitFailure(t, store, "fail_projection_submission")
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	_, present, err = reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, loaded.Lifecycle)
	fresh, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	material, err = reopened.BeginSubmission(ctx, attempt.ID, fresh.StateToken, empty, review, fresh.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
	loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
	assert.Equal(t, OutcomeUnresolved, loaded.Outcome)
}

func TestPublicationAttemptCorruptTerminalEvidenceRefusesReadback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	_, err = store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "UPDATE attempt_evidence SET digest=zeroblob(32) WHERE attempt_id=? AND role='outcome'", attempt.ID[:])
	require.NoError(t, err)
	_, _, err = store.Load(ctx)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
}

func hexID(id [16]byte) string {
	const digits = "0123456789abcdef"
	var encoded [32]byte
	for index, value := range id {
		encoded[index*2] = digits[value>>4]
		encoded[index*2+1] = digits[value&0x0f]
	}
	return string(encoded[:])
}
