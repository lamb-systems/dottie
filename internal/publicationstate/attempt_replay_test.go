package publicationstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicationAttemptConfirmationIsDatabaseBoundAndIDsAreNeverReused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	storeA, _ := newStore(t, f)
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposalA, err := storeA.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	storeB, directoryB := newStore(t, f)
	defer storeB.Close()
	freshB, err := storeB.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	assert.NotEqual(t, proposalA.StateToken, freshB.StateToken)
	_, err = storeB.CreateAttempt(ctx, proposalA.StateToken, candidate, view, review, proposalA.Confirmation)
	requireErrorMetadata(t, err, ErrConsent, StageAttempt, ReasonStale)
	_, statErr := os.Stat(filepath.Join(directoryB, payloadDirectoryName))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	attempt, err := storeA.CreateAttempt(ctx, proposalA.StateToken, candidate, view, review, proposalA.Confirmation)
	require.NoError(t, err)
	abandon, err := storeA.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	_, err = storeA.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
	_, err = storeA.PrepareAttempt(ctx, candidate, view, review)
	requireErrorMetadata(t, err, ErrConsent, StageAttempt, ReasonStale)
	assert.NotEqual(t, [32]byte{}, storeA.databaseID)
	assert.NotEqual(t, storeA.databaseID, storeB.databaseID)
	require.NoError(t, storeA.Close())
}
