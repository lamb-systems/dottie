package publicationstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptCommitSucceededButReturnedErrorRequiresReadback(t *testing.T) {
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
	store.commitTransaction = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("commit canary")
	}
	result, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageAttempt, ReasonCommitUnknown)
	assert.Equal(t, Attempt{}, result)
	assert.True(t, store.needsReadback)
	_, err = store.PrepareDispatch(ctx, proposal.AttemptID, DispatchUpload, view, review)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Floor{}, floor)
	assert.False(t, store.needsReadback)
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, proposal.AttemptID, active.ID)
	store.commitTransaction = func(tx *sql.Tx) error { return tx.Commit() }
	dispatch, err := store.PrepareDispatch(ctx, active.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	upload, err := store.BeginUpload(ctx, active.ID, dispatch.StateToken, view, review, dispatch.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, upload.Payload)
}

func TestPublicationAttemptDeferredCommitErrorRollsBackAndAllowsSubsequentWrite(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	dispatch, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	for _, statement := range []string{
		"CREATE TEMP TABLE attempt_commit_parent(id INTEGER PRIMARY KEY)",
		"CREATE TEMP TABLE attempt_commit_child(id INTEGER REFERENCES attempt_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)",
		"CREATE TEMP TRIGGER attempt_commit_failure AFTER UPDATE ON main.publication_attempts BEGIN INSERT INTO attempt_commit_child(id) VALUES(NEW.mutation_revision); END",
	} {
		_, err := store.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
	material, err := store.BeginUpload(ctx, attempt.ID, dispatch.StateToken, view, review, dispatch.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	assert.Equal(t, UploadMaterial{}, material)
	assert.True(t, store.needsReadback)
	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Floor{}, loadedFloor)
	assert.False(t, store.needsReadback)
	attemptAfter, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptPrepared, attemptAfter.Lifecycle)
	for _, statement := range []string{"DROP TRIGGER attempt_commit_failure", "DROP TABLE attempt_commit_child", "DROP TABLE attempt_commit_parent"} {
		_, err := store.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
	freshDispatch, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	material, err = store.BeginUpload(ctx, attempt.ID, freshDispatch.StateToken, view, review, freshDispatch.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, material.Payload)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	attemptAfter, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, attemptAfter.Lifecycle)
}

func TestPublicationAttemptSubmissionCommitUnknownNeverReturnsBatchOrRetry(t *testing.T) {
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
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	store.commitTransaction = commitThenReturnError
	material, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	assert.Equal(t, SubmissionMaterial{}, material)
	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Floor{}, loadedFloor)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
	_, err = store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonTransition)
}

func TestPublicationAttemptFinalizeCommitUnknownRequiresCompleteReadback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	store.commitTransaction = commitThenReturnError
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	requireErrorMetadata(t, err, ErrStorage, StageFinalize, ReasonCommitUnknown)
	assert.Equal(t, Finalization{}, finalized)
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, uint64(0), floor.Sequence)
	retired, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, retired.Lifecycle)
	var retained int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retained))
	assert.Equal(t, 1, retained)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	floor, present, err = reopened.Load(ctx)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, uint64(0), floor.Sequence)
}

func TestPublicationAttemptAbandonCommitUnknownRequiresCompleteReadback(t *testing.T) {
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
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	store.commitTransaction = commitThenReturnError
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageAbandon, ReasonCommitUnknown)
	assert.Equal(t, Attempt{}, retired)
	_, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	retired, err = store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
	var refs int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&refs))
	assert.Equal(t, 0, refs)
}

func TestPublicationAttemptAdmissionCommitRollbackAllowsRealRetryAfterReadback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	before := readAttemptLogicalRows(t, store)
	sentinel := filepath.Join(directory, "commit-sentinel")
	sentinelBytes := []byte("unchanged admission commit sentinel")
	require.NoError(t, os.WriteFile(sentinel, sentinelBytes, 0o600))
	installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER fail_admission_commit AFTER INSERT ON main.publication_attempts BEGIN INSERT INTO attempt_commit_child(id) VALUES(101); END")
	result, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageAttempt, ReasonCommitUnknown)
	assert.Equal(t, Attempt{}, result)
	assert.True(t, store.needsReadback)
	payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
	orphan, err := os.ReadFile(payloadPath)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, orphan)
	_, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.False(t, store.needsReadback)
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	var attempts, objects, refs int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_attempts").Scan(&attempts))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects").Scan(&objects))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&refs))
	assert.Zero(t, attempts)
	assert.Zero(t, objects)
	assert.Zero(t, refs)
	sentinelAfter, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	assert.Equal(t, sentinelBytes, sentinelAfter)
	removeDeferredAttemptCommitFailure(t, store, "fail_admission_commit")
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	_, present, err = reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, before, readAttemptLogicalRows(t, reopened))
	attempt, err := reopened.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, proposal.AttemptID, attempt.ID)
	assert.Equal(t, AttemptPrepared, attempt.Lifecycle)
}

func TestPublicationAttemptSubmissionCommitRollbackAllowsFreshBoundaryAfterReadback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitPreparationForFaultTest(t, store, candidate, empty, review)
	before := readAttemptLogicalRows(t, store)
	candidateBefore, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	proposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER fail_submission_commit AFTER INSERT ON main.attempt_events WHEN NEW.kind='may-have-submitted' BEGIN INSERT INTO attempt_commit_child(id) VALUES(102); END")
	material, err := store.BeginSubmission(ctx, attempt.ID, proposal.StateToken, empty, review, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	assert.Equal(t, SubmissionMaterial{}, material)
	assert.True(t, store.needsReadback)
	_, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.False(t, store.needsReadback)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, loaded.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, loaded.Outcome)
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	candidateAfter, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidateBefore, candidateAfter)
	removeDeferredAttemptCommitFailure(t, store, "fail_submission_commit")
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
}

func TestPublicationAttemptFinalizeCommitRollbackAllowsRealRetryAfterReadback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	before := readAttemptLogicalRows(t, store)
	candidateBefore, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER fail_finalize_commit AFTER INSERT ON main.attempt_events WHEN NEW.kind='retired-success' BEGIN INSERT INTO attempt_commit_child(id) VALUES(103); END")
	result, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	requireErrorMetadata(t, err, ErrStorage, StageFinalize, ReasonCommitUnknown)
	assert.Equal(t, Finalization{}, result)
	assert.True(t, store.needsReadback)
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Floor{}, floor)
	assert.False(t, store.needsReadback)
	loaded, err = store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
	assert.Equal(t, OutcomeCurrent, loaded.Outcome)
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	candidateAfter, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidateBefore, candidateAfter)
	removeDeferredAttemptCommitFailure(t, store, "fail_finalize_commit")
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	_, present, err = reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err = reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
	require.NoError(t, err)
	result, err = reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, result.Attempt.Lifecycle)
	assert.Equal(t, uint64(0), result.Floor.Sequence)
}

func TestPublicationAttemptAbandonCommitRollbackAllowsRealRetryAfterReadback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { _ = store.Close() })
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	current := attemptView(f, f.observation(1), false)
	before := readAttemptLogicalRows(t, store)
	candidateBefore, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	proposal, err := store.PrepareAbandon(ctx, attempt.ID, &current)
	require.NoError(t, err)
	installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER fail_abandon_commit AFTER INSERT ON main.attempt_evidence WHEN NEW.role='outcome' BEGIN INSERT INTO attempt_commit_child(id) VALUES(104); END")
	result, err := store.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &current, proposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageAbandon, ReasonCommitUnknown)
	assert.Equal(t, Attempt{}, result)
	assert.True(t, store.needsReadback)
	_, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.False(t, store.needsReadback)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
	assert.Equal(t, OutcomeUnresolved, loaded.Outcome)
	assert.Equal(t, before, readAttemptLogicalRows(t, store))
	candidateAfter, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidateBefore, candidateAfter)
	removeDeferredAttemptCommitFailure(t, store, "fail_abandon_commit")
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	_, present, err = reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	fresh, err := reopened.PrepareAbandon(ctx, attempt.ID, &current)
	require.NoError(t, err)
	result, err = reopened.AbandonAttempt(ctx, attempt.ID, fresh.StateToken, &current, fresh.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, result.Lifecycle)
	assert.Equal(t, OutcomeCurrent, result.Outcome)
}

func installDeferredAttemptCommitFailure(t *testing.T, store *Store, trigger string) {
	t.Helper()
	for _, statement := range []string{
		"CREATE TEMP TABLE attempt_commit_parent(id INTEGER PRIMARY KEY)",
		"CREATE TEMP TABLE attempt_commit_child(id INTEGER REFERENCES attempt_commit_parent(id) DEFERRABLE INITIALLY DEFERRED)",
		trigger,
	} {
		_, err := store.conn.ExecContext(context.Background(), statement)
		require.NoError(t, err)
	}
}

func removeDeferredAttemptCommitFailure(t *testing.T, store *Store, triggerName string) {
	t.Helper()
	for _, statement := range []string{"DROP TRIGGER " + triggerName, "DROP TABLE attempt_commit_child", "DROP TABLE attempt_commit_parent"} {
		_, err := store.conn.ExecContext(context.Background(), statement)
		require.NoError(t, err)
	}
}

func createAndSubmitPreparationForFaultTest(t *testing.T, store *Store, candidate CandidateInput, view SuppliedRepositoryView, review LocalReviewContext) Attempt {
	t.Helper()
	ctx := context.Background()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	_, err = store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, view, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	return attempt
}

func commitThenReturnError(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	return errors.New("commit canary")
}

func TestSubmittedTerminalAbandonEvidenceWritesRollbackTogether(t *testing.T) {
	triggers := []struct {
		role string
		ddl  string
	}{
		{"outcome", "CREATE TEMP TRIGGER fail_abandon_outcome BEFORE INSERT ON main.attempt_evidence WHEN NEW.role='outcome' BEGIN SELECT RAISE(ABORT,'abandon-outcome-canary'); END"},
		{"retirement", "CREATE TEMP TRIGGER fail_abandon_retirement BEFORE INSERT ON main.attempt_evidence WHEN NEW.role='retirement' BEGIN SELECT RAISE(ABORT,'abandon-retirement-canary'); END"},
	}
	for _, fault := range triggers {
		t.Run(fault.role, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
			current := attemptView(f, f.observation(1), false)
			proposal, err := store.PrepareAbandon(ctx, attempt.ID, &current)
			require.NoError(t, err)
			before := readAttemptLogicalRows(t, store)
			_, err = store.conn.ExecContext(ctx, fault.ddl)
			require.NoError(t, err)
			result, err := store.AbandonAttempt(ctx, attempt.ID, proposal.StateToken, &current, proposal.Confirmation)
			requireErrorMetadata(t, err, ErrStorage, StageAbandon, ReasonIO)
			assert.Equal(t, Attempt{}, result)
			assert.NotContains(t, err.Error(), "-canary")
			assert.Equal(t, before, readAttemptLogicalRows(t, store))
			loaded, err := store.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
			assert.Equal(t, OutcomeUnresolved, loaded.Outcome)
			triggerName := "fail_abandon_" + fault.role
			_, err = store.conn.ExecContext(ctx, "DROP TRIGGER "+triggerName)
			require.NoError(t, err)
			require.NoError(t, store.Close())
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			fresh, err := reopened.PrepareAbandon(ctx, attempt.ID, &current)
			require.NoError(t, err)
			retired, err := reopened.AbandonAttempt(ctx, attempt.ID, fresh.StateToken, &current, fresh.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, OutcomeCurrent, retired.Outcome)
			assertOutcomeRetirementProofs(t, reopened, attempt.ID, OutcomeCurrent)
			assert.Equal(t, AttemptRetiredAbandoned, retired.Lifecycle)
		})
	}
}

func TestPublicationAttemptFinalizeStatementFailuresRollbackAllRows(t *testing.T) {
	triggers := []struct {
		name string
		ddl  string
	}{
		{"accepted-record", "CREATE TEMP TRIGGER abort_final_record BEFORE INSERT ON main.accepted_records BEGIN SELECT RAISE(ABORT,'final-record-canary'); END"},
		{"accepted-event", "CREATE TEMP TRIGGER abort_final_event BEFORE INSERT ON main.accepted_events BEGIN SELECT RAISE(ABORT,'final-event-canary'); END"},
		{"floor", "CREATE TEMP TRIGGER abort_final_floor BEFORE INSERT ON main.active_floor BEGIN SELECT RAISE(ABORT,'final-floor-canary'); END"},
		{"retained-point", "CREATE TEMP TRIGGER abort_final_retained BEFORE INSERT ON main.retained_publications BEGIN SELECT RAISE(ABORT,'final-retained-canary'); END"},
		{"attempt-state", "CREATE TEMP TRIGGER abort_final_attempt BEFORE UPDATE ON main.publication_attempts BEGIN SELECT RAISE(ABORT,'final-attempt-canary'); END"},
		{"attempt-reference", "CREATE TEMP TRIGGER abort_final_ref BEFORE DELETE ON main.attempt_payload_refs BEGIN SELECT RAISE(ABORT,'final-ref-canary'); END"},
		{"active-slot", "CREATE TEMP TRIGGER abort_final_active BEFORE DELETE ON main.active_publication_attempt BEGIN SELECT RAISE(ABORT,'final-active-canary'); END"},
		{"reservation", "CREATE TEMP TRIGGER abort_final_reservation BEFORE DELETE ON main.attempt_reservations BEGIN SELECT RAISE(ABORT,'final-reservation-canary'); END"},
		{"pending-genesis-delete", "CREATE TEMP TRIGGER abort_final_pending_genesis BEFORE DELETE ON main.pending_genesis BEGIN SELECT RAISE(ABORT,'final-pending-genesis-canary'); END"},
		{"store-meta-revision", "CREATE TEMP TRIGGER abort_final_meta_revision BEFORE UPDATE ON main.store_meta WHEN OLD.key='revision' BEGIN SELECT RAISE(ABORT,'final-meta-revision-canary'); END"},
		{"store-meta-generation", "CREATE TEMP TRIGGER abort_final_meta_generation BEFORE UPDATE ON main.store_meta WHEN OLD.key='generation' BEGIN SELECT RAISE(ABORT,'final-meta-generation-canary'); END"},
		{"store-meta-attempt-mutation", "CREATE TEMP TRIGGER abort_final_meta_attempt_mutation BEFORE UPDATE ON main.store_meta WHEN OLD.key='attempt_mutation_revision' BEGIN SELECT RAISE(ABORT,'final-meta-attempt-mutation-canary'); END"},
		{"attempt-event", "CREATE TEMP TRIGGER abort_final_retired_event BEFORE INSERT ON main.attempt_events WHEN NEW.kind='retired-success' BEGIN SELECT RAISE(ABORT,'final-retired-event-canary'); END"},
		{"outcome-evidence-upsert", "CREATE TEMP TRIGGER abort_final_outcome_evidence BEFORE UPDATE ON main.attempt_evidence WHEN NEW.role='outcome' BEGIN SELECT RAISE(ABORT,'final-outcome-evidence-canary'); END"},
	}
	for _, test := range triggers {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { _ = store.Close() })
			candidate := attemptCandidate(f, 0)
			empty := attemptView(f, f.observation(1), true)
			review := attemptReview()
			attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
			current := attemptView(f, f.observation(1), false)
			loaded, err := store.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			resolution, err := store.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
			require.NoError(t, err)
			candidateBefore, err := store.ReadCandidate(ctx, attempt.ID)
			require.NoError(t, err)
			before := readAttemptLogicalRows(t, store)
			_, err = store.conn.ExecContext(ctx, test.ddl)
			require.NoError(t, err)
			finalization, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
			expectedStage := StageFinalize
			if test.name == "accepted-record" {
				expectedStage = StageAccept
			}
			requireErrorMetadata(t, err, ErrStorage, expectedStage, ReasonIO)
			assert.Equal(t, Finalization{}, finalization)
			assert.NotContains(t, err.Error(), "final-")
			assert.Equal(t, before, readAttemptLogicalRows(t, store))
			candidateAfter, err := store.ReadCandidate(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, candidateBefore, candidateAfter)
			_, err = store.conn.ExecContext(ctx, "DROP TRIGGER abort_final_"+triggerSuffix(test.name))
			require.NoError(t, err)
			require.NoError(t, store.Close())
			reopened, err := Open(directory, f.binding)
			require.NoError(t, err)
			defer reopened.Close()
			assert.Equal(t, before, readAttemptLogicalRows(t, reopened))
			floor, present, err := reopened.Load(ctx)
			require.NoError(t, err)
			assert.False(t, present)
			assert.Equal(t, Floor{}, floor)
			loaded, err = reopened.LoadAttempt(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, AttemptMayHaveSubmitted, loaded.Lifecycle)
			candidateAfter, err = reopened.ReadCandidate(ctx, attempt.ID)
			require.NoError(t, err)
			assert.Equal(t, candidateBefore, candidateAfter)
			resolution, err = reopened.ResolveAttempt(ctx, attempt.ID, loaded.StateDigest, current)
			require.NoError(t, err)
			finalization, err = reopened.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
			require.NoError(t, err)
			assert.Equal(t, AttemptRetiredSuccess, finalization.Attempt.Lifecycle)
			assert.Equal(t, uint64(0), finalization.Floor.Sequence)
		})
	}
}

func triggerSuffix(name string) string {
	switch name {
	case "accepted-record":
		return "record"
	case "accepted-event":
		return "event"
	case "retained-point":
		return "retained"
	case "attempt-state":
		return "attempt"
	case "attempt-reference":
		return "ref"
	case "active-slot":
		return "active"
	case "reservation":
		return "reservation"
	case "pending-genesis-delete":
		return "pending_genesis"
	case "store-meta-revision":
		return "meta_revision"
	case "store-meta-generation":
		return "meta_generation"
	case "store-meta-attempt-mutation":
		return "meta_attempt_mutation"
	case "attempt-event":
		return "retired_event"
	case "outcome-evidence-upsert":
		return "outcome_evidence"
	default:
		return "floor"
	}
}

func readAttemptLogicalRows(t *testing.T, store *Store) map[string]string {
	t.Helper()
	rows := readLogicalRows(t, store.conn)
	for _, table := range []string{"publication_attempts", "active_publication_attempt", "pending_genesis", "attempt_events", "attempt_evidence", "payload_objects", "attempt_payload_refs", "retained_publications", "attempt_reservations"} {
		query, err := store.conn.QueryContext(context.Background(), "SELECT * FROM "+table+" ORDER BY 1")
		require.NoError(t, err)
		columns, err := query.Columns()
		require.NoError(t, err)
		allRows := make([][]any, 0)
		for query.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(columns))
			for index := range values {
				destinations[index] = &values[index]
			}
			require.NoError(t, query.Scan(destinations...))
			allRows = append(allRows, values)
		}
		assert.NoError(t, query.Err())
		assert.NoError(t, query.Close())
		encoded, err := json.Marshal(allRows)
		require.NoError(t, err)
		rows[table] = string(encoded)
	}
	return rows
}
