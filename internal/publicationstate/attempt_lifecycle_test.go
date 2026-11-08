package publicationstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptDispatchResolveFinalizeAndRetain(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)

	uploadProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, empty, review)
	require.NoError(t, err)
	upload, err := store.BeginUpload(ctx, attempt.ID, uploadProposal.StateToken, empty, review, uploadProposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, upload.Payload)
	assert.Equal(t, attempt.ID, upload.AttemptID)
	started, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptUploadStarted, started.Lifecycle)

	submissionProposal, err := store.PrepareDispatch(ctx, attempt.ID, DispatchSubmission, empty, review)
	require.NoError(t, err)
	submission, err := store.BeginSubmission(ctx, attempt.ID, submissionProposal.StateToken, empty, review, submissionProposal.Confirmation)
	require.NoError(t, err)
	assert.True(t, submission.SnapshotCreateOnly)
	assert.True(t, submission.RequiresAtomicBatch)
	assert.True(t, submission.RequiresCreateExclude)
	assert.True(t, submission.HeadCreate)
	assert.Equal(t, candidate.SnapshotRecord, submission.SnapshotRecord)
	mayHaveSubmitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptMayHaveSubmitted, mayHaveSubmitted.Lifecycle)
	page, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Len(t, page.Attempts, 1)
	require.NotEmpty(t, page.Evidence)
	assert.Equal(t, "submission", page.Evidence[0].Role)

	current := attemptView(f, f.observation(1), false)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, mayHaveSubmitted.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, resolution.Outcome)
	finalized, err := store.FinalizeAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest, current)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredSuccess, finalized.Attempt.Lifecycle)
	assert.Equal(t, OutcomeCurrent, finalized.Attempt.Outcome)
	assert.Equal(t, uint64(0), finalized.Floor.Sequence)
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Attempt{}, active)
	var retained int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications").Scan(&retained))
	assert.Equal(t, 1, retained)
	var attemptRefs int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs").Scan(&attemptRefs))
	assert.Equal(t, 0, attemptRefs)
	info, err := os.Stat(filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload)))
	require.NoError(t, err)
	assert.Equal(t, int64(len(f.payload)), info.Size())
	retainedMaterial, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, candidate.Payload, retainedMaterial.Payload)
	loaded, hasFloor, err := store.Load(ctx)
	require.NoError(t, err)
	assert.True(t, hasFloor)
	assert.Equal(t, finalized.Floor, loaded)
}
