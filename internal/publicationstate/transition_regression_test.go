package publicationstate

import (
	"bytes"
	"context"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiLinkForkReplacementHistorySurvivesReopenAndContinues(t *testing.T) {
	for _, links := range []uint64{2, 3} {
		t.Run(string(rune('0'+links))+"-links", func(t *testing.T) {
			ctx := context.Background()
			original := newFixture(t, BackendPublicRepo)
			original.appendRecord(t, 0)
			store, directory := newStore(t, original)
			initial := original.observation(1)
			first := prepareFirstUse(t, store, initial, original.payload)
			oldFloor, err := store.Accept(ctx, ModeFirstUse, first.StateToken, initial, original.payload, first.Confirmation)
			require.NoError(t, err)
			fork := newFixture(t, BackendPublicRepo)
			fork.appendRecord(t, 0)
			root, err := publication.DecodeSnapshot(fork.blocks[0].Raw)
			require.NoError(t, err)
			root.PublicationID[0] = 0x5a
			fork.blocks[0].Raw, err = publication.EncodeSnapshot(root)
			require.NoError(t, err)
			for sequence := uint64(1); sequence <= links+1; sequence++ {
				fork.appendRecord(t, sequence)
			}
			candidate := fork.observation(int(links + 1))
			proposal, err := store.Prepare(ctx, ModeReplaceFloor, candidate, fork.payload)
			require.NoError(t, err)
			assert.Equal(t, ReasonFork, proposal.Reason)
			assert.Equal(t, int(links), len(proposal.Trace))
			accepted, err := store.Accept(ctx, ModeReplaceFloor, proposal.StateToken, candidate, fork.payload, proposal.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, uint64(2), accepted.Generation)
			loaded, present, err := store.Load(ctx)
			require.NoError(t, err)
			require.True(t, present)
			assert.Equal(t, accepted, loaded)
			page, err := store.History(ctx, 0, 20)
			require.NoError(t, err)
			require.Len(t, page.Events, 2)
			require.NotNil(t, page.Events[1].OldFloor)
			assert.Equal(t, oldFloor, *page.Events[1].OldFloor)
			assert.Equal(t, candidate.SuppliedContext, page.Events[1].NewFloor.SuppliedContext)
			for index, ref := range page.Events[1].Trace {
				require.Equal(t, fork.blocks[links-uint64(index)].Key, ref.Key)
				require.Equal(t, fork.blocks[links-uint64(index)].Raw, findHistoryRaw(t, page, ref.CID))
			}
			require.NoError(t, store.Close())
			reopened, err := Open(directory, original.binding)
			require.NoError(t, err)
			defer reopened.Close()
			persisted, present, err := reopened.Load(ctx)
			require.NoError(t, err)
			require.True(t, present)
			assert.Equal(t, accepted, persisted)
			continued := fork.observation(int(links + 2))
			advance, err := reopened.Prepare(ctx, ModeAdvance, continued, fork.payload)
			require.NoError(t, err)
			assert.Equal(t, "joined", advance.Stop)
			continuedFloor, err := reopened.Accept(ctx, ModeAdvance, advance.StateToken, continued, fork.payload, [32]byte{})
			require.NoError(t, err)
			assert.Equal(t, accepted.Revision+1, continuedFloor.Revision)
		})
	}
}

func TestCachedBridgeUsesResolvedLineageLimitAcrossReopen(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence < 4; sequence++ {
		f.appendRecord(t, sequence)
	}
	limits := DefaultLimits()
	limits.SuppliedSnapshotCount = 1
	limits.MaxLineageLinks = 2
	store, directory := newStore(t, f, limits)
	initial := f.observation(1)
	first := prepareFirstUse(t, store, initial, f.payload)
	_, err := store.Accept(ctx, ModeFirstUse, first.StateToken, initial, f.payload, first.Confirmation)
	require.NoError(t, err)
	bridge := f.observation(2)
	bridge.Snapshots = bridge.Snapshots[1:]
	_, err = store.RecordObservation(ctx, bridge)
	require.NoError(t, err)
	candidate := f.observation(3)
	candidate.Snapshots = candidate.Snapshots[2:]
	proposal, err := store.Prepare(ctx, ModeAdvance, candidate, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "joined", proposal.Stop)
	require.Len(t, proposal.Trace, 2)
	floor, err := store.Accept(ctx, ModeAdvance, proposal.StateToken, candidate, f.payload, [32]byte{})
	require.NoError(t, err)
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor, loaded)
	page, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 2)
	for _, ref := range page.Events[1].Trace {
		assert.NotEmpty(t, findHistoryRaw(t, page, ref.CID))
	}
	require.NoError(t, store.Close())
	reopened, err := OpenWithLimits(directory, f.binding, limits)
	require.NoError(t, err)
	defer reopened.Close()
	persisted, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor, persisted)
	continued := f.observation(4)
	continued.Snapshots = continued.Snapshots[3:]
	advance, err := reopened.Prepare(ctx, ModeAdvance, continued, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "joined", advance.Stop)
	_, err = reopened.Accept(ctx, ModeAdvance, advance.StateToken, continued, f.payload, [32]byte{})
	require.NoError(t, err)
}

func findHistoryRaw(t *testing.T, page HistoryPage, cid []byte) []byte {
	t.Helper()
	for _, record := range page.Records {
		if bytes.Equal(record.Reference.CID, cid) {
			return record.Raw
		}
	}
	require.Fail(t, "history page omitted a referenced raw record")
	return nil
}
