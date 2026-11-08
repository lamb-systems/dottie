package publicationstate

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptUploadCanRepeatBeforeSubmissionAfterReadbackAndRestart(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	firstProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	store.commitTransaction = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("commit canary")
	}
	first, err := store.BeginUpload(ctx, attempt.ID, firstProposal.StateToken, view, review, firstProposal.Confirmation)
	requireErrorMetadata(t, err, ErrStorage, StageDispatch, ReasonCommitUnknown)
	assert.Equal(t, UploadMaterial{}, first)
	loadedFloor, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Floor{}, loadedFloor)
	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, loaded.Lifecycle)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	_, err = reopened.BeginUpload(ctx, attempt.ID, firstProposal.StateToken, view, review, firstProposal.Confirmation)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonStale)
	freshProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	require.NoError(t, err)
	var beforeCore []byte
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT core FROM publication_attempts WHERE attempt_id=?", attempt.ID[:]).Scan(&beforeCore))
	repeated, err := reopened.BeginUpload(ctx, attempt.ID, freshProposal.StateToken, view, review, freshProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, repeated.Payload)
	var afterCore []byte
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT core FROM publication_attempts WHERE attempt_id=?", attempt.ID[:]).Scan(&afterCore))
	assert.Equal(t, beforeCore, afterCore)
	for repeat := 0; repeat < 20; repeat++ {
		repeatProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
		require.NoError(t, err)
		repeated, err := reopened.BeginUpload(ctx, attempt.ID, repeatProposal.StateToken, view, review, repeatProposal.Confirmation)
		require.NoError(t, err)
		assert.Equal(t, candidate.Payload, repeated.Payload)
	}
	var eventCount int
	require.NoError(t, reopened.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_events WHERE attempt_id=?", attempt.ID[:]).Scan(&eventCount))
	assert.Equal(t, 2, eventCount)

	submissionProposal, err := reopened.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, view, review)
	require.NoError(t, err)
	_, err = reopened.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, view, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	_, err = reopened.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonTransition)
}

func TestPublicationAttemptReviewRevisionsInvalidateAtoBtoA(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	reviewA := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, reviewA)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, reviewA, proposal.Confirmation)
	require.NoError(t, err)
	reviewB := reviewA
	reviewB.SelectionDigest[0] = 3
	reviewB.SelectionRevision = 2
	_, err = store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, reviewB)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonStale)
	reviewA.SelectionRevision = 3
	_, err = store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, reviewA)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonStale)
}
