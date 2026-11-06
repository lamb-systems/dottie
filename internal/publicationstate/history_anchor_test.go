package publicationstate

import (
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryPageIncludesHeldFloorRecordForReturnedJoin(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newStore(t, f)
	defer store.Close()
	initial := f.observation(1)
	proposal := prepareFirstUse(t, store, initial, f.payload)
	_, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, initial, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	candidate := f.observation(2)
	advance, err := store.Prepare(ctx, ModeAdvance, candidate, f.payload)
	require.NoError(t, err)
	_, err = store.Accept(ctx, ModeAdvance, advance.StateToken, candidate, f.payload, [32]byte{})
	require.NoError(t, err)
	page, err := store.History(ctx, 1, 1)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
	oldCID, err := publication.RecordCID(f.blocks[0].Raw)
	require.NoError(t, err)
	oldRaw := findHistoryRaw(t, page, oldCID)
	assert.Equal(t, f.blocks[0].Raw, oldRaw)
	current := findHistoryRaw(t, page, page.Events[0].Trace[0].CID)
	assert.NoError(t, publication.VerifySuccessor(oldRaw, current, page.Events[0].Trace[0].Key))
}
