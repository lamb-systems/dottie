package publicationstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRejectAttemptRetiresARejectedSubmissionAndReleasesItsBlock(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)

	submitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	require.Equal(t, AttemptMayHaveSubmitted, submitted.Lifecycle)
	require.Equal(t, OutcomeUnresolved, submitted.Outcome)
	_, active, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, active)

	rejected, err := store.RejectAttempt(ctx, attempt.ID, submitted.StateDigest)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, rejected.Lifecycle)
	assert.Equal(t, OutcomeRejected, rejected.Outcome)
	assert.Empty(t, rejected.Blocked)
	assert.Equal(t, attempt.ID, rejected.ID)
	assert.NotEqual(t, submitted.StateDigest, rejected.StateDigest)

	_, active, err = store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.False(t, active, "the rejected attempt still blocks preparation")
	_, err = store.RejectAttempt(ctx, attempt.ID, rejected.StateDigest)
	requireErrorMetadata(t, err, ErrConsent, StageReject, ReasonTransition)

	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	loaded, err := reopened.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptRetiredAbandoned, loaded.Lifecycle)
	assert.Equal(t, OutcomeRejected, loaded.Outcome)
	assert.Equal(t, rejected.StateDigest, loaded.StateDigest)

	page, err := reopened.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Len(t, page.Attempts, 1)
	assert.Equal(t, OutcomeRejected, page.Attempts[0].Outcome)
	assert.NotEmpty(t, page.Evidence)
}

func TestRejectAttemptRefusesAStaleTokenAndAnUnsubmittedAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, empty, review)
	require.NoError(t, err)
	created, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, empty, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptPrepared, created.Lifecycle)

	stale := [32]byte{0x01}
	_, err = store.RejectAttempt(ctx, created.ID, stale)
	requireErrorMetadata(t, err, ErrConsent, StageReject, ReasonStale)
	loaded, err := store.LoadAttempt(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, AttemptPrepared, loaded.Lifecycle)
	assert.Equal(t, OutcomeNotSubmitted, loaded.Outcome)
	_, active, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	assert.True(t, active, "a stale rejection token retired the attempt")

	_, err = store.RejectAttempt(ctx, created.ID, loaded.StateDigest)
	requireErrorMetadata(t, err, ErrConsent, StageReject, ReasonTransition)
	unchanged, err := store.LoadAttempt(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, loaded.StateDigest, unchanged.StateDigest)
}

func TestRejectAttemptRefusesAnAttemptWithARecordedPublicationOutcome(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	submitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	current := attemptView(f, f.observation(1), false)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, submitted.StateDigest, current)
	require.NoError(t, err)
	require.Equal(t, OutcomeCurrent, resolution.Outcome)

	_, err = store.RejectAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest)
	requireErrorMetadata(t, err, ErrContinuity, StageReject, ReasonTransition)
	unchanged, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, OutcomeCurrent, unchanged.Outcome)
	assert.Equal(t, AttemptMayHaveSubmitted, unchanged.Lifecycle)
}

func TestAbsentAfterSubmissionStillCannotBeAbandonedOrRejected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	defer store.Close()
	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	submitted, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	resolution, err := store.ResolveAttempt(ctx, attempt.ID, submitted.StateDigest, empty)
	require.NoError(t, err)
	require.Equal(t, OutcomeAbsentUnresolved, resolution.Outcome)

	_, err = store.PrepareAbandon(ctx, attempt.ID, &empty)
	requireErrorMetadata(t, err, ErrContinuity, StageAbandon, ReasonSubmittedUnknown)

	rejected, err := store.RejectAttempt(ctx, attempt.ID, resolution.Attempt.StateDigest)
	require.NoError(t, err)
	assert.Equal(t, OutcomeRejected, rejected.Outcome)
	assert.Equal(t, AttemptRetiredAbandoned, rejected.Lifecycle)
}
