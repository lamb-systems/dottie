package publicationstate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMissingAcceptedRecordRefusesLoadHistoryAndReopen(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, dir := newStore(t, f)
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "DELETE FROM accepted_records WHERE cid=?", floor.RecordCID)
	require.NoError(t, err)
	_, present, err := store.Load(ctx)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
	assert.False(t, present)
	page, err := store.History(ctx, 0, 10)
	requireErrorMetadata(t, err, ErrSchema, StageHistory, ReasonCorrupt)
	assert.Equal(t, HistoryPage{}, page)
	require.NoError(t, store.Close())
	_, err = Open(dir, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
}

func TestTamperedEventAndFloorRefuseWithoutPartialHistory(t *testing.T) {
	for _, name := range []string{"event", "missing-event", "floor"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, dir := newStore(t, f)
			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			_, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			require.NoError(t, err)
			if name == "event" {
				_, err = store.conn.ExecContext(ctx, "UPDATE accepted_events SET body=? WHERE revision=1", []byte(`{}`))
			} else if name == "missing-event" {
				_, err = store.conn.ExecContext(ctx, "DELETE FROM accepted_events WHERE revision=1")
			} else {
				_, err = store.conn.ExecContext(ctx, "UPDATE active_floor SET floor=? WHERE singleton=1", []byte(`{}`))
			}
			require.NoError(t, err)
			page, historyErr := store.History(ctx, 0, 10)
			requireErrorMetadata(t, historyErr, ErrSchema, StageHistory, ReasonCorrupt)
			assert.Equal(t, HistoryPage{}, page)
			_, present, loadErr := store.Load(ctx)
			requireErrorMetadata(t, loadErr, ErrSchema, StageLoad, ReasonCorrupt)
			assert.False(t, present)
			require.NoError(t, store.Close())
			_, openErr := Open(dir, f.binding)
			requireErrorMetadata(t, openErr, ErrSchema, StageOpen, ReasonCorrupt)
		})
	}
}
