package publicationstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModeMatrixAndPrepareNoWriteContract(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newStore(t, f)
	defer store.Close()
	initial := f.observation(1)
	before := readLogicalRows(t, store.conn)
	_, err := store.Prepare(ctx, ModeAdvance, initial, f.payload)
	requireErrorMetadata(t, err, ErrContinuity, StagePrepare, ReasonFirstUseRequired)
	assert.Equal(t, before, readLogicalRows(t, store.conn))
	first := prepareFirstUse(t, store, initial, f.payload)
	assert.Equal(t, before, readLogicalRows(t, store.conn))
	_, err = store.Accept(ctx, ModeFirstUse, first.StateToken, initial, f.payload, first.Confirmation)
	require.NoError(t, err)
	current, err := store.Prepare(ctx, ModeAdvance, f.observation(2), f.payload)
	require.NoError(t, err)
	before = readLogicalRows(t, store.conn)
	_, err = store.Prepare(ctx, ModeFirstUse, initial, f.payload)
	requireErrorMetadata(t, err, ErrConsent, StagePrepare, ReasonMode)
	_, err = store.Prepare(ctx, ModeReplaceFloor, f.observation(2), f.payload)
	requireErrorMetadata(t, err, ErrConsent, StagePrepare, ReasonMode)
	_, err = store.Prepare(ctx, ModeReplaceFloor, initial, f.payload)
	requireErrorMetadata(t, err, ErrConsent, StagePrepare, ReasonMode)
	_, err = store.Accept(ctx, ModeFirstUse, current.StateToken, initial, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonMode)
	_, err = store.Accept(ctx, ModeAdvance, current.StateToken, f.observation(2), f.payload, [32]byte{1})
	requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonMode)
	assert.Equal(t, before, readLogicalRows(t, store.conn))
}

func TestStaleOrdinaryAdvanceTokenCannotAcceptCurrentSuccessor(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	f.appendRecord(t, 2)
	store, _ := newStore(t, f)
	defer store.Close()
	initial := f.observation(1)
	first := prepareFirstUse(t, store, initial, f.payload)
	_, err := store.Accept(ctx, ModeFirstUse, first.StateToken, initial, f.payload, first.Confirmation)
	require.NoError(t, err)
	staleCandidate := f.observation(3)
	staleCandidate.Snapshots = staleCandidate.Snapshots[1:]
	staleProposal, err := store.Prepare(ctx, ModeAdvance, staleCandidate, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "joined", staleProposal.Stop)
	winner := f.observation(2)
	winningProposal, err := store.Prepare(ctx, ModeAdvance, winner, f.payload)
	require.NoError(t, err)
	winningFloor, err := store.Accept(ctx, ModeAdvance, winningProposal.StateToken, winner, f.payload, [32]byte{})
	require.NoError(t, err)
	before := readLogicalRows(t, store.conn)
	_, err = store.Accept(ctx, ModeAdvance, staleProposal.StateToken, staleCandidate, f.payload, [32]byte{})
	requireErrorMetadata(t, err, ErrConsent, StageAccept, ReasonStale)
	assert.Equal(t, before, readLogicalRows(t, store.conn))
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, winningFloor, loaded)
}
