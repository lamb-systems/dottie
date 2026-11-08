package publicationstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttemptHistoryLoweredPageBytesKeepsByIDConflictReadAvailable(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	attemptLimits := DefaultAttemptLimits()
	attemptLimits.HistoryPageBytes = 2048
	store, _ := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
	defer store.Close()

	candidate := attemptCandidate(f, 0)
	empty := attemptView(f, f.observation(1), true)
	review := attemptReview()
	attempt := createAndSubmitGenesis(t, store, f, empty, candidate, review)
	conflict := competingGenesisView(t, f)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, &conflict)
	require.NoError(t, err)
	retired, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, &conflict, abandon.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, OutcomeLostFence, retired.Outcome)

	loaded, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	firstConflict, present, err := store.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, conflict.Head, firstConflict.Head)

	var roleCount int
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_evidence WHERE attempt_id=?", attempt.ID[:]).Scan(&roleCount))
	assert.Equal(t, 3, roleCount)
	attemptJSON, err := canonicalJSON(loaded)
	require.NoError(t, err)
	assert.Less(t, uint64(len(attemptJSON)), attemptLimits.HistoryPageBytes)

	var evidenceBytes int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(body)+32),0) FROM attempt_evidence WHERE attempt_id=?", attempt.ID[:]).Scan(&evidenceBytes))
	var submissionBody []byte
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT body FROM attempt_events WHERE attempt_id=? AND kind='may-have-submitted'", attempt.ID[:]).Scan(&submissionBody))
	var submissionEvent attemptEventWire
	require.NoError(t, strictJSON(submissionBody, &submissionEvent))
	aggregateEntryBytes := uint64(len(attemptJSON)) + uint64(evidenceBytes) + uint64(len(submissionEvent.Evidence)+32)
	assert.Greater(t, aggregateEntryBytes, attemptLimits.HistoryPageBytes)

	page, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	requireErrorMetadata(t, err, ErrLimit, StageHistory, ReasonCapacity)
	assert.Equal(t, AttemptPage{}, page)
	loadedAfter, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, loaded.StateDigest, loadedAfter.StateDigest)
	conflictAfter, present, err := store.ReadFirstConflict(ctx, attempt.ID)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, firstConflict.ID, conflictAfter.ID)
	assert.Equal(t, firstConflict.Evidence, conflictAfter.Evidence)
}
