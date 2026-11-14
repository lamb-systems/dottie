package publicationstate

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const incomingCommitFailureTrigger = "fail_incoming_commit"

func installIncomingCommitFailure(t *testing.T, store *Store) {
	t.Helper()
	installDeferredAttemptCommitFailure(t, store, "CREATE TEMP TRIGGER "+incomingCommitFailureTrigger+" AFTER UPDATE ON main.store_meta WHEN OLD.key='revision' BEGIN INSERT INTO attempt_commit_child(id) VALUES(201); END")
}

func removeIncomingCommitFailure(t *testing.T, store *Store) {
	t.Helper()
	removeDeferredAttemptCommitFailure(t, store, incomingCommitFailureTrigger)
}

func countIncomingCommits(t *testing.T, store *Store) *int {
	t.Helper()
	original := store.commitTransaction
	count := new(int)
	t.Cleanup(func() { store.commitTransaction = original })
	store.commitTransaction = func(tx *sql.Tx) error {
		*count++
		return original(tx)
	}
	return count
}

func TestAcceptMaterialCommitSucceededThenErrorReconcilesWithoutReopen(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	originalCommit := store.commitTransaction
	t.Cleanup(func() { store.commitTransaction = originalCommit })
	commits := 0
	store.commitTransaction = func(tx *sql.Tx) error {
		commits++
		return commitThenReturnError(tx)
	}

	floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonCommitUnknown)
	assert.Equal(t, 1, commits)
	assert.True(t, store.needsReadback)

	fenced, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, fenced)
	requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonCommitUnknown)
	assert.Equal(t, 1, commits)

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, uint64(1), loaded.Revision)
	assert.False(t, store.needsReadback)
	references := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, references, 1)
	assert.Equal(t, []any{int64(loaded.Revision), loaded.RecordCID, loaded.BlobCID}, references[0])
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, loaded)
	require.NoError(t, err)
	assert.Equal(t, loaded, material.Floor)
	assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)

	store.commitTransaction = func(tx *sql.Tx) error {
		commits++
		return tx.Commit()
	}
	advance, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "same", advance.Stop)
	rowsBefore := readAttemptLogicalRows(t, store)
	noOp, err := store.acceptMaterial(ctx, ModeAdvance, advance.StateToken, observation, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, loaded, noOp)
	assert.Equal(t, rowsBefore, readAttemptLogicalRows(t, store))
	assert.Equal(t, references, b8IncomingRows(t, ctx, store.conn))
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
}

func TestAcceptMaterialCommitFailedWithoutCommitReconcilesWithoutReopen(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	commits := countIncomingCommits(t, store)
	installIncomingCommitFailure(t, store)

	floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonCommitUnknown)
	assert.Equal(t, 1, *commits)
	assert.True(t, store.needsReadback)
	requireIncomingMaterialRowsAbsent(t, ctx, store)

	removeIncomingCommitFailure(t, store)
	probe, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, probe)
	requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonCommitUnknown)
	assert.Equal(t, 1, *commits)
	assert.True(t, store.needsReadback)
	requireIncomingMaterialRowsAbsent(t, ctx, store)

	requireIncomingMaterialLoadAbsent(t, ctx, store)
	assert.False(t, store.needsReadback)
	floor, err = store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), floor.Revision)
	assert.Equal(t, 2, *commits)
	requireIncomingMaterialPublication(t, ctx, store, f, floor)
}
