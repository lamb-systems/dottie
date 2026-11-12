package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestIncomingMaterialReaderExactCurrent(t *testing.T) {
	for _, backend := range []Backend{BackendPublicRepo, BackendSpaces} {
		t.Run(string(backend), func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, backend)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			storeClosed := false
			t.Cleanup(func() {
				if !storeClosed {
					assert.NoError(t, store.Close())
				}
			})

			floor := incomingMaterialFirstUse(t, store, f)
			name := b8CommitIncomingRef(t, ctx, store, floor, f.payload)
			require.Equal(t, payloadBasename(f.payload), name)
			state, err := store.readState(ctx, store.conn, StageLoad)
			require.NoError(t, err)
			beforeRows := readAttemptLogicalRows(t, store)
			beforeRefs := b8IncomingRows(t, ctx, store.conn)
			beforeHistory, err := store.History(ctx, 0, 10)
			require.NoError(t, err)
			beforeFile, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, name), len(f.payload))
			require.NoError(t, err)
			require.True(t, beforeFile.Exists)
			require.Equal(t, f.payload, beforeFile.Bytes)

			require.NoError(t, store.Close())
			storeClosed = true
			reopened, err := Open(directory, f.binding)
			if reopened != nil {
				t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
			}
			require.NoError(t, err)
			require.NotNil(t, reopened)
			loaded, present, err := reopened.Load(ctx)
			require.NoError(t, err)
			require.True(t, present)
			require.Equal(t, floor, loaded)
			beforeReadState, err := reopened.readState(ctx, reopened.conn, StageReadAcceptedMaterial)
			require.NoError(t, err)
			beforeReadRows := readAttemptLogicalRows(t, reopened)
			beforeReadRefs := b8IncomingRows(t, ctx, reopened.conn)
			beforeReadHistory, err := reopened.History(ctx, 0, 10)
			require.NoError(t, err)
			beforeReadFile, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, name), len(f.payload))
			require.NoError(t, err)
			require.Equal(t, beforeFile, beforeReadFile)

			material, err := reopened.ReadAcceptedMaterial(ctx, f.binding, floor)
			require.NoError(t, err)
			require.Equal(t, floor, material.Floor)
			require.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
			require.Equal(t, f.payload, material.Payload)
			material.Floor.AnchorCID[0] ^= 0xff
			material.Floor.Head[0] ^= 0xff
			material.Floor.RecordCID[0] ^= 0xff
			material.Floor.BlobCID[0] ^= 0xff
			material.SnapshotRecord[0] ^= 0xff
			material.Payload[0] ^= 0xff
			if material.Floor.SuppliedContext.Policy != nil {
				material.Floor.SuppliedContext.Policy.Identity[0] ^= 0xff
			}

			again, err := reopened.ReadAcceptedMaterial(ctx, f.binding, floor)
			require.NoError(t, err)
			require.Equal(t, floor, again.Floor)
			require.Equal(t, f.blocks[0].Raw, again.SnapshotRecord)
			require.Equal(t, f.payload, again.Payload)
			afterReadState, err := reopened.readState(ctx, reopened.conn, StageReadAcceptedMaterial)
			require.NoError(t, err)
			assert.Equal(t, state.token, afterReadState.token)
			assert.Equal(t, state.revision, afterReadState.revision)
			assert.Equal(t, state.generation, afterReadState.generation)
			assert.Equal(t, beforeReadState, afterReadState)
			assert.Equal(t, beforeReadRows, readAttemptLogicalRows(t, reopened))
			assert.Equal(t, beforeReadRefs, b8IncomingRows(t, ctx, reopened.conn))
			assert.Equal(t, beforeReadHistory, beforeHistory)
			afterHistory, err := reopened.History(ctx, 0, 10)
			require.NoError(t, err)
			assert.Equal(t, beforeReadHistory, afterHistory)
			afterFile, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, name), len(f.payload))
			require.NoError(t, err)
			assert.Equal(t, beforeReadFile, afterFile)
			assert.Equal(t, beforeRefs, beforeReadRefs)
			assert.Equal(t, beforeRows, beforeReadRows)
		})
	}
}

func TestIncomingMaterialOwnerUsesQueryer(t *testing.T) {
	t.Run("schema3 no owner", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		floor := incomingMaterialFirstUse(t, store, f)
		lease := b8AttachClosedDecoy(t, ctx, store)
		b8RequireCurrentFloor(t, ctx, store, lease.tx, floor)
		before := b8CapturePrivateOwnerState(t, ctx, store, lease.tx)
		recorder := &b8QueryRecorder{source: lease.tx}
		name, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, floor, StageAccept)
		t.Logf("B8 owner query trace no-owner: %s", b8FormatQueryTrace(recorder.calls))
		requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonMaterialNotRetained)
		require.Empty(t, name)
		require.Nil(t, record)
		require.Equal(t, publication.BlobReference{}, blob)
		require.Nil(t, ctx.Err())
		b8RequireQueryTrace(t, recorder.calls, []string{
			"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?",
			"SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=?",
		}, [][]any{{int64(floor.Revision)}, {int64(floor.Revision)}})
		require.Equal(t, -1, store.payloadFD)
		requirePayloadDirectoryAbsent(t, directory)
		assert.Equal(t, before, b8CapturePrivateOwnerState(t, ctx, store, lease.tx))
		lease.restoreRollbackClose(t)
	})

	t.Run("finalized owner", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendSpaces)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		candidate := attemptCandidate(f, 0)
		attempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, candidate)
		lease := b8AttachClosedDecoy(t, ctx, store)
		b8RequireCurrentFloor(t, ctx, store, lease.tx, finalized.Floor)
		recorder := &b8QueryRecorder{source: lease.tx}
		beforeFD := store.payloadFD
		payloadPath := filepath.Join(directory, payloadDirectoryName, payloadBasename(candidate.Payload))
		beforeFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
		require.NoError(t, err)
		require.True(t, beforeFile.Exists)
		before := b8CapturePrivateOwnerState(t, ctx, store, lease.tx)
		name, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, finalized.Floor, StageAccept)
		t.Logf("B8 owner query trace finalized: %s", b8FormatQueryTrace(recorder.calls))
		require.NoError(t, err)
		require.Equal(t, candidate.SnapshotRecord, record)
		require.Equal(t, finalized.Floor.RecordCID, mustB8RecordCID(t, record))
		require.Equal(t, finalized.Floor.BlobCID, blob.CID)
		require.Equal(t, finalized.Floor.BlobSize, blob.Size)
		require.Equal(t, payloadBasename(candidate.Payload), name)
		require.NotEmpty(t, attempt.ID)
		require.Equal(t, beforeFD, store.payloadFD)
		afterFile, fileErr := observeAcceptedMaterialPayloadFile(payloadPath, len(candidate.Payload))
		require.NoError(t, fileErr)
		require.Equal(t, beforeFile, afterFile)
		assert.Equal(t, before, b8CapturePrivateOwnerState(t, ctx, store, lease.tx))
		b8RequireQueryTrace(t, recorder.calls, []string{
			"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?",
			"SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=?",
			"FROM retained_publications rp",
			"SELECT length(core),length(state_digest)",
			"SELECT core,state_digest",
			"SELECT length(raw) FROM accepted_records WHERE cid=?",
			"SELECT record_key,sequence,cid,raw FROM accepted_records WHERE cid=?",
		}, [][]any{
			{int64(finalized.Floor.Revision)}, {int64(finalized.Floor.Revision)}, {int64(finalized.Floor.Revision)},
			{attempt.ID[:]}, {attempt.ID[:]}, {finalized.Floor.RecordCID}, {finalized.Floor.RecordCID},
		})
		require.Nil(t, ctx.Err())
		lease.restoreRollbackClose(t)
	})

	t.Run("incoming uncommitted owner", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		floor := incomingMaterialFirstUse(t, store, f)
		lease := b8AttachClosedDecoy(t, ctx, store)
		name := b8InsertIncomingRef(t, ctx, store, lease.tx, floor, f.payload)
		b8RequireCurrentFloor(t, ctx, store, lease.tx, floor)
		recorder := &b8QueryRecorder{source: lease.tx}
		beforeFD := store.payloadFD
		payloadPath := filepath.Join(directory, payloadDirectoryName, name)
		beforeFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(f.payload))
		require.NoError(t, err)
		require.True(t, beforeFile.Exists)
		before := b8CapturePrivateOwnerState(t, ctx, store, lease.tx)
		ownerName, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, floor, StageAccept)
		t.Logf("B8 owner query trace incoming: %s", b8FormatQueryTrace(recorder.calls))
		require.NoError(t, err)
		require.Equal(t, name, ownerName)
		require.Equal(t, f.blocks[0].Raw, record)
		require.Equal(t, floor.BlobCID, blob.CID)
		require.Equal(t, floor.BlobSize, blob.Size)
		require.Equal(t, beforeFD, store.payloadFD)
		afterFile, fileErr := observeAcceptedMaterialPayloadFile(payloadPath, len(f.payload))
		require.NoError(t, fileErr)
		require.Equal(t, beforeFile, afterFile)
		assert.Equal(t, before, b8CapturePrivateOwnerState(t, ctx, store, lease.tx))
		require.Equal(t, int64(1), b8Count(t, ctx, lease.tx, "SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=?", int64(floor.Revision)))
		b8RequireQueryTrace(t, recorder.calls, []string{
			"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?",
			"SELECT COUNT(*) FROM accepted_material_refs WHERE accepted_revision=?",
			"FROM accepted_material_refs WHERE accepted_revision=?",
			"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?",
			"SELECT typeof(new_floor)",
			"FROM accepted_records WHERE cid=?",
			"FROM payload_objects WHERE blob_cid=?",
			"SELECT length(raw) FROM accepted_records WHERE cid=?",
			"SELECT record_key,sequence,cid,raw FROM accepted_records WHERE cid=?",
		}, [][]any{
			{int64(floor.Revision)}, {int64(floor.Revision)}, {int64(floor.Revision)}, {int64(floor.Revision)},
			{int64(floor.Revision)}, {floor.RecordCID}, {floor.BlobCID}, {floor.RecordCID}, {floor.RecordCID},
		})
		lease.restoreRollbackClose(t)
		assertFile, err := os.Stat(filepath.Join(directory, payloadDirectoryName, name))
		require.NoError(t, err)
		require.True(t, assertFile.Mode().IsRegular())
	})
}

func TestIncomingMaterialOwnerSchema2Isolation(t *testing.T) {
	ctx := b8TestContext(t)
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newSchema2UnitStore(t, f)
	floor := incomingMaterialFirstUse(t, store, f)
	b8RequireCurrentFloor(t, ctx, store, store.conn, floor)
	recorder := &b8QueryRecorder{source: store.conn}
	name, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, floor, StageAccept)
	t.Logf("B8 owner query trace schema2: %s", b8FormatQueryTrace(recorder.calls))
	requireErrorMetadata(t, err, ErrStorage, StageAccept, ReasonMaterialNotRetained)
	require.Empty(t, name)
	require.Nil(t, record)
	require.Equal(t, publication.BlobReference{}, blob)
	b8RequireQueryTrace(t, recorder.calls, []string{
		"SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?",
	}, [][]any{{int64(floor.Revision)}})
	requirePayloadDirectoryAbsent(t, directory)
}

func TestIncomingMaterialReaderRevisionOwnership(t *testing.T) {
	t.Run("historical incoming reference does not authorize repinned current bytes", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		first, _, third := incomingMaterialHistoricalLifecycle(t, store, f)
		b8CommitIncomingRef(t, ctx, store, first, f.payload)
		require.Equal(t, first.RecordCID, third.RecordCID)
		require.Equal(t, first.BlobCID, third.BlobCID)
		require.NotEqual(t, first.Revision, third.Revision)
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, first)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonStale)
		material, err = store.ReadAcceptedMaterial(ctx, f.binding, third)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, ReasonMaterialNotRetained)
		b8CommitIncomingRef(t, ctx, store, third, f.payload)
		material, err = store.ReadAcceptedMaterial(ctx, f.binding, third)
		require.NoError(t, err)
		require.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
		require.Equal(t, f.payload, material.Payload)
		refs := b8IncomingRows(t, ctx, store.conn)
		require.Len(t, refs, 2)
		require.Equal(t, int64(first.Revision), refs[0][0])
		require.Equal(t, int64(third.Revision), refs[1][0])
	})

	t.Run("finalized historical role and incoming current role coexist", func(t *testing.T) {
		ctx := context.Background()
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		candidate := attemptCandidate(f, 0)
		attempt, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, candidate)
		advanceObservation := f.observation(2)
		advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, f.payload)
		require.NoError(t, err)
		_, err = store.Accept(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, f.payload, advanceProposal.Confirmation)
		require.NoError(t, err)
		replacementObservation := f.observation(1)
		replacementProposal, err := store.Prepare(ctx, ModeReplaceFloor, replacementObservation, f.payload)
		require.NoError(t, err)
		current, err := store.Accept(ctx, ModeReplaceFloor, replacementProposal.StateToken, replacementObservation, f.payload, replacementProposal.Confirmation)
		require.NoError(t, err)
		require.Equal(t, finalized.Floor.RecordCID, current.RecordCID)
		require.Equal(t, finalized.Floor.BlobCID, current.BlobCID)
		require.NotEqual(t, finalized.Floor.Revision, current.Revision)
		b8CommitIncomingRef(t, ctx, store, current, f.payload)
		var retainedRevision int64
		require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT accepted_revision FROM retained_publications WHERE attempt_id=?", attempt.ID[:]).Scan(&retainedRevision))
		require.Equal(t, int64(finalized.Floor.Revision), retainedRevision)
		refs := b8IncomingRows(t, ctx, store.conn)
		require.Len(t, refs, 1)
		require.Equal(t, int64(current.Revision), refs[0][0])
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, current)
		require.NoError(t, err)
		require.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
		require.Equal(t, candidate.Payload, material.Payload)
	})
}

func TestIncomingMaterialOwnerRejectsCorruptRefs(t *testing.T) {
	t.Run("overlap at exact revision", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		_, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
		healthy, err := store.ReadAcceptedMaterial(ctx, f.binding, finalized.Floor)
		require.NoError(t, err)
		require.Equal(t, f.blocks[0].Raw, healthy.SnapshotRecord)
		require.Equal(t, f.payload, healthy.Payload)
		tx := b8BeginTx(t, ctx, store)
		b8InsertIncomingRef(t, ctx, store, tx, finalized.Floor, f.payload)
		state, err := store.readState(ctx, tx, StageAccept)
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		require.Equal(t, stateSnapshot{}, state)
		recorder := &b8QueryRecorder{source: tx}
		name, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, finalized.Floor, StageAccept)
		t.Logf("B8 overlap query trace: %s", b8FormatQueryTrace(recorder.calls))
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		require.Empty(t, name)
		require.Nil(t, record)
		require.Equal(t, publication.BlobReference{}, blob)
		require.NoError(t, tx.Commit())
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, finalized.Floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	})

	t.Run("wrong existing record is refused by full state and private owner", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		_, second, current := incomingMaterialHistoricalLifecycle(t, store, f)
		b8CommitIncomingRef(t, ctx, store, current, f.payload)
		healthy, err := store.ReadAcceptedMaterial(ctx, f.binding, current)
		require.NoError(t, err)
		require.Equal(t, f.blocks[0].Raw, healthy.SnapshotRecord)
		tx := b8BeginTx(t, ctx, store)
		result, err := tx.ExecContext(ctx, "UPDATE accepted_material_refs SET record_cid=? WHERE accepted_revision=?", second.RecordCID, int64(current.Revision))
		require.NoError(t, err)
		affected, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), affected)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
		state, err := store.readState(ctx, tx, StageAccept)
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		require.Equal(t, stateSnapshot{}, state)
		recorder := &b8QueryRecorder{source: tx}
		name, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, current, StageAccept)
		t.Logf("B8 wrong-record query trace: %s", b8FormatQueryTrace(recorder.calls))
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		require.Empty(t, name)
		require.Nil(t, record)
		require.Equal(t, publication.BlobReference{}, blob)
		require.NoError(t, tx.Commit())
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, current)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	})

	t.Run("wrong existing catalog blob is refused by full state and private owner", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, _ := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		floor := incomingMaterialFirstUse(t, store, f)
		b8CommitIncomingRef(t, ctx, store, floor, f.payload)
		healthy, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
		require.NoError(t, err)
		require.Equal(t, f.blocks[0].Raw, healthy.SnapshotRecord)
		tx := b8BeginTx(t, ctx, store)
		alternate := b8BuildOtherPackedPayload(t)
		b8PersistCatalogPayload(t, ctx, store, tx, alternate.payload, alternate.blob, alternate.name)
		result, err := tx.ExecContext(ctx, "UPDATE accepted_material_refs SET blob_cid=? WHERE accepted_revision=?", alternate.blob.CID, int64(floor.Revision))
		require.NoError(t, err)
		affected, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), affected)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
		state, err := store.readState(ctx, tx, StageAccept)
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		require.Equal(t, stateSnapshot{}, state)
		recorder := &b8QueryRecorder{source: tx}
		name, record, blob, err := store.acceptedMaterialOwner(ctx, recorder, floor, StageAccept)
		t.Logf("B8 wrong-blob query trace: %s", b8FormatQueryTrace(recorder.calls))
		requireErrorMetadata(t, err, ErrSchema, StageAccept, ReasonCorrupt)
		require.Empty(t, name)
		require.Nil(t, record)
		require.Equal(t, publication.BlobReference{}, blob)
		require.NoError(t, tx.Commit())
		material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
		assert.Equal(t, AcceptedMaterial{}, material)
		requireErrorMetadata(t, err, ErrSchema, StageReadAcceptedMaterial, ReasonCorrupt)
	})

	t.Run("wrong-type cid is private and rolled back", func(t *testing.T) {
		ctx := b8TestContext(t)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		floor := incomingMaterialFirstUse(t, store, f)
		name := b8CommitIncomingRef(t, ctx, store, floor, f.payload)
		healthy, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
		require.NoError(t, err)
		require.Equal(t, f.payload, healthy.Payload)
		beforeRows := readAttemptLogicalRows(t, store)
		beforeRefs := b8IncomingRows(t, ctx, store.conn)
		beforeFile, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, name), len(f.payload))
		require.NoError(t, err)

		tx := b8BeginTx(t, ctx, store)
		var foreignKeys, deferred int64
		require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys))
		require.Equal(t, int64(1), foreignKeys)
		require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&deferred))
		require.Equal(t, int64(0), deferred)
		_, err = tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON")
		require.NoError(t, err)
		require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&deferred))
		require.Equal(t, int64(1), deferred)
		result, err := tx.ExecContext(ctx, "UPDATE accepted_material_refs SET blob_cid=? WHERE accepted_revision=?", "wrong-text-cid", int64(floor.Revision))
		require.NoError(t, err)
		affected, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), affected)
		var valueType string
		var valueLength int64
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(blob_cid),length(CAST(blob_cid AS BLOB)) FROM accepted_material_refs WHERE accepted_revision=?", int64(floor.Revision)).Scan(&valueType, &valueLength))
		require.Equal(t, "text", valueType)
		require.Equal(t, int64(len("wrong-text-cid")), valueLength)
		recorder := &b8QueryRecorder{source: tx}
		ownerName, record, blob, helperErr := store.acceptedMaterialOwner(ctx, recorder, floor, StageAccept)
		t.Logf("B8 wrong-type query trace: %s", b8FormatQueryTrace(recorder.calls))
		requireErrorMetadata(t, helperErr, ErrSchema, StageAccept, ReasonCorrupt)
		require.Empty(t, ownerName)
		require.Nil(t, record)
		require.Equal(t, publication.BlobReference{}, blob)
		require.NoError(t, tx.Rollback())
		require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys))
		require.Equal(t, int64(1), foreignKeys)
		require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&deferred))
		require.Equal(t, int64(0), deferred)
		assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
		assert.Equal(t, beforeRefs, b8IncomingRows(t, ctx, store.conn))
		afterFile, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, name), len(f.payload))
		require.NoError(t, err)
		assert.Equal(t, beforeFile, afterFile)
		assert.Equal(t, f.payload, healthy.Payload)
	})
}

func TestIncomingMaterialReaderCustodyRefusals(t *testing.T) {
	for _, fault := range []string{"missing", "wrong-bytes", "unsafe-mode", "replaced-directory"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			floor := incomingMaterialFirstUse(t, store, f)
			name := b8CommitIncomingRef(t, ctx, store, floor, f.payload)
			healthy, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
			require.NoError(t, err)
			require.Equal(t, f.payload, healthy.Payload)
			beforeRows := readAttemptLogicalRows(t, store)
			beforeRefs := b8IncomingRows(t, ctx, store.conn)
			payloadPath := filepath.Join(directory, payloadDirectoryName, name)
			healthyFile, err := observeAcceptedMaterialPayloadFile(payloadPath, len(f.payload))
			require.NoError(t, err)
			require.True(t, healthyFile.Exists)

			wantReason := ReasonMaterialMissing
			switch fault {
			case "missing":
				require.NoError(t, os.Remove(payloadPath))
			case "wrong-bytes":
				file, openErr := os.OpenFile(payloadPath, os.O_WRONLY, 0)
				require.NoError(t, openErr)
				written, writeErr := file.WriteAt([]byte{f.payload[0] ^ 0xff}, 0)
				syncErr := file.Sync()
				closeErr := file.Close()
				require.NoError(t, writeErr)
				require.Equal(t, 1, written)
				require.NoError(t, syncErr)
				require.NoError(t, closeErr)
				wantReason = ReasonMaterialCorrupt
			case "unsafe-mode":
				require.NoError(t, os.Chmod(payloadPath, 0o400))
				wantReason = ReasonMaterialUnsafe
			case "replaced-directory":
				replacement := filepath.Join(directory, "payloads-replacement")
				held := filepath.Join(directory, "payloads-held")
				require.NoError(t, os.Mkdir(replacement, 0o700))
				require.NoError(t, os.WriteFile(filepath.Join(replacement, "sentinel"), []byte("synthetic replacement"), 0o600))
				require.NoError(t, os.Rename(filepath.Join(directory, payloadDirectoryName), held))
				require.NoError(t, os.Rename(replacement, filepath.Join(directory, payloadDirectoryName)))
				wantReason = ReasonIO
			default:
				require.FailNow(t, "unexpected custody fault")
			}

			paths := []string{payloadPath}
			if fault == "replaced-directory" {
				paths = append(paths, filepath.Join(directory, "payloads-held", name), filepath.Join(directory, payloadDirectoryName, "sentinel"))
				var held, replacement unix.Stat_t
				require.NoError(t, unix.Fstat(store.payloadFD, &held))
				require.NoError(t, unix.Lstat(filepath.Join(directory, payloadDirectoryName), &replacement))
				require.True(t, held.Dev != replacement.Dev || held.Ino != replacement.Ino)
			}
			faulted := make([]acceptedMaterialPayloadFileState, len(paths))
			for index, path := range paths {
				faulted[index], err = observeAcceptedMaterialPayloadFile(path, len(f.payload))
				require.NoError(t, err)
			}
			switch fault {
			case "missing":
				require.False(t, faulted[0].Exists)
			case "wrong-bytes":
				wanted := bytes.Clone(f.payload)
				wanted[0] ^= 0xff
				require.Equal(t, wanted, faulted[0].Bytes)
			case "unsafe-mode":
				require.Equal(t, healthyFile.Inode, faulted[0].Inode)
				require.Equal(t, uint32(0o400), faulted[0].Mode&0o777)
			case "replaced-directory":
				require.False(t, faulted[0].Exists)
				require.Equal(t, healthyFile, faulted[1])
				require.Equal(t, []byte("synthetic replacement"), faulted[2].Bytes)
			}

			material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
			assert.Equal(t, AcceptedMaterial{}, material)
			requireErrorMetadata(t, err, ErrStorage, StageReadAcceptedMaterial, wantReason)
			assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
			assert.Equal(t, beforeRefs, b8IncomingRows(t, ctx, store.conn))
			for index, path := range paths {
				afterFile, fileErr := observeAcceptedMaterialPayloadFile(path, len(f.payload))
				require.NoError(t, fileErr)
				assert.Equal(t, faulted[index], afterFile, path)
			}
			require.Equal(t, f.payload, healthy.Payload)
		})
	}
}

func TestIncomingMaterialReaderDoesNotRestoreCandidateOwnership(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	candidate := attemptCandidate(f, 0)
	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	abandon, err := store.PrepareAbandon(ctx, attempt.ID, nil)
	require.NoError(t, err)
	abandoned, err := store.AbandonAttempt(ctx, attempt.ID, abandon.StateToken, nil, abandon.Confirmation)
	require.NoError(t, err)
	require.Equal(t, AttemptRetiredAbandoned, abandoned.Lifecycle)
	position := incomingMaterialFirstUse(t, store, f)
	name := b8CommitIncomingRef(t, ctx, store, position, f.payload)
	beforeRows := readAttemptLogicalRows(t, store)
	beforeRefs := b8IncomingRows(t, ctx, store.conn)
	beforeAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	beforeHistory, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, position)
	require.NoError(t, err)
	require.Equal(t, candidate.SnapshotRecord, material.SnapshotRecord)
	require.Equal(t, candidate.Payload, material.Payload)
	candidateMaterial, err := store.ReadCandidate(ctx, attempt.ID)
	assert.Equal(t, CandidateMaterial{}, candidateMaterial)
	requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, Attempt{}, active)
	var attemptRefs, retainedRefs int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attempt.ID[:]).Scan(&attemptRefs))
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", int64(position.Revision)).Scan(&retainedRefs))
	require.Zero(t, attemptRefs)
	require.Zero(t, retainedRefs)
	_, err = store.PrepareDispatch(ctx, attempt.ID, DispatchUpload, view, review)
	requireErrorMetadata(t, err, ErrConsent, StageDispatch, ReasonTransition)
	afterAttempt, err := store.LoadAttempt(ctx, attempt.ID)
	require.NoError(t, err)
	afterHistory, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, beforeAttempt, afterAttempt)
	assert.Equal(t, beforeHistory, afterHistory)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
	assert.Equal(t, beforeRefs, b8IncomingRows(t, ctx, store.conn))
	file, err := observeAcceptedMaterialPayloadFile(filepath.Join(store.directory, payloadDirectoryName, name), len(f.payload))
	require.NoError(t, err)
	require.True(t, file.Exists)
	require.Equal(t, f.payload, file.Bytes)
}

func TestIncomingMaterialReaderErrorStages(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	floor := incomingMaterialFirstUse(t, store, f)
	invalid := cloneFloor(floor)
	invalid.SnapshotKey = ""
	err := validateExpectedAcceptedFloor(invalid, f.binding, store.limits, StageAccept)
	requireErrorMetadata(t, err, ErrInvalid, StageAccept, ReasonRecordSet)
	bindingErr := validateExpectedAcceptedFloor(floor, Binding{}, store.limits, StageAccept)
	requireErrorMetadata(t, bindingErr, ErrInvalid, StageAccept, ReasonBinding)
	missingDirectory := classifyAcceptedMaterialDirectory(unix.ENOENT, StageAccept)
	requireErrorMetadata(t, missingDirectory, ErrStorage, StageAccept, ReasonMaterialMissing)
	unsafeRead := classifyAcceptedMaterialRead(errUnsafePayloadObject, StageAccept)
	requireErrorMetadata(t, unsafeRead, ErrStorage, StageAccept, ReasonMaterialUnsafe)
	corruptRead := classifyAcceptedMaterialRead(errCorruptPayloadObject, StageAccept)
	requireErrorMetadata(t, corruptRead, ErrStorage, StageAccept, ReasonMaterialCorrupt)
	ioRead := classifyAcceptedMaterialRead(errors.New("b8 read path canary"), StageAccept)
	requireErrorMetadata(t, ioRead, ErrStorage, StageAccept, ReasonIO)
	assert.NotContains(t, ioRead.Error(), "b8 read path canary")
}

func b8CommitIncomingRef(t *testing.T, ctx context.Context, store *Store, floor Floor, payload []byte) string {
	t.Helper()
	before, err := store.readState(ctx, store.conn, StageAccept)
	require.NoError(t, err)
	require.NotNil(t, before.floor)
	tx := b8BeginTx(t, ctx, store)
	name := b8InsertIncomingRef(t, ctx, store, tx, floor, payload)
	state, err := store.readState(ctx, tx, StageAccept)
	require.NoError(t, err)
	require.Equal(t, before, state)
	incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
	require.NoError(t, tx.Commit())
	return name
}

func b8BeginTx(t *testing.T, ctx context.Context, store *Store) *sql.Tx {
	t.Helper()
	tx, err := store.conn.BeginTx(ctx, nil)
	if tx != nil {
		t.Cleanup(func() {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				assert.NoError(t, err)
			}
		})
	}
	require.NoError(t, err)
	require.NotNil(t, tx)
	return tx
}

func b8InsertIncomingRef(t *testing.T, ctx context.Context, store *Store, tx *sql.Tx, floor Floor, payload []byte) string {
	t.Helper()
	blob := publication.BlobReference{CID: bytes.Clone(floor.BlobCID), Size: floor.BlobSize}
	name, err := payloadBasenameFromCID(blob.CID)
	require.NoError(t, err)
	require.Equal(t, payloadBasename(payload), name)
	b8PersistCatalogPayload(t, ctx, store, tx, payload, blob, name)
	result, err := tx.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", int64(floor.Revision), floor.RecordCID, floor.BlobCID)
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)
	return name
}

func b8PersistCatalogPayload(t *testing.T, ctx context.Context, store *Store, tx *sql.Tx, payload []byte, blob publication.BlobReference, name string) {
	t.Helper()
	canonicalName, err := payloadBasenameFromCID(blob.CID)
	require.NoError(t, err)
	require.Equal(t, canonicalName, name)
	var initialCatalogCount int64
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects WHERE blob_cid=?", blob.CID).Scan(&initialCatalogCount))
	require.LessOrEqual(t, initialCatalogCount, int64(1))
	beforePhysical, err := observeAcceptedMaterialPayloadFile(filepath.Join(store.directory, payloadDirectoryName, name), len(payload))
	require.NoError(t, err)
	newPayload := initialCatalogCount == 0 && !beforePhysical.Exists
	storedName, storedBytes, err := store.persistPayload(ctx, tx, payload, blob, name)
	require.NoError(t, err)
	require.Equal(t, name, storedName)
	if newPayload {
		require.Equal(t, payload, storedBytes)
	} else {
		require.Nil(t, storedBytes)
	}
	var catalogCount int64
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM payload_objects WHERE blob_cid=?", blob.CID).Scan(&catalogCount))
	require.LessOrEqual(t, catalogCount, int64(1))
	if catalogCount == 0 {
		result, insertErr := tx.ExecContext(ctx, "INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?)", blob.CID, int64(blob.Size), name, int64(blob.Size))
		require.NoError(t, insertErr)
		affected, rowsErr := result.RowsAffected()
		require.NoError(t, rowsErr)
		require.Equal(t, int64(1), affected)
	} else {
		var sizeType, nameType, logicalType string
		var size, logical int64
		var storedBasename string
		require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(size),size,typeof(basename),basename,typeof(logical_bytes),logical_bytes FROM payload_objects WHERE blob_cid=?", blob.CID).Scan(&sizeType, &size, &nameType, &storedBasename, &logicalType, &logical))
		require.Equal(t, "integer", sizeType)
		require.Equal(t, int64(blob.Size), size)
		require.Equal(t, "text", nameType)
		require.Equal(t, name, storedBasename)
		require.Equal(t, "integer", logicalType)
		require.Equal(t, int64(blob.Size), logical)
	}
	physical, err := observeAcceptedMaterialPayloadFile(filepath.Join(store.directory, payloadDirectoryName, name), len(payload))
	require.NoError(t, err)
	require.True(t, physical.Exists)
	require.Equal(t, payload, physical.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), physical.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), physical.UID)
	require.Equal(t, int64(len(payload)), physical.Size)
	require.Equal(t, uint64(1), physical.Nlink)
	require.GreaterOrEqual(t, store.payloadFD, 0)
	var directoryStat unix.Stat_t
	require.NoError(t, unix.Fstat(store.payloadFD, &directoryStat))
	require.Equal(t, uint32(unix.S_IFDIR|0o700), directoryStat.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint32(os.Geteuid()), directoryStat.Uid)
}

func b8IncomingRows(t *testing.T, ctx context.Context, q queryer) [][]any {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT accepted_revision,record_cid,blob_cid FROM accepted_material_refs ORDER BY accepted_revision")
	require.NoError(t, err)
	var result [][]any
	var scanErr error
	for rows.Next() {
		var revision int64
		var recordCID, blobCID []byte
		if scanErr = rows.Scan(&revision, &recordCID, &blobCID); scanErr != nil {
			break
		}
		result = append(result, []any{revision, bytes.Clone(recordCID), bytes.Clone(blobCID)})
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	return result
}

func b8Count(t *testing.T, ctx context.Context, q queryer, query string, args ...any) int64 {
	t.Helper()
	count, err := queryInt64(ctx, q, query, args...)
	require.NoError(t, err)
	return count
}

func b8TestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func b8RequireCurrentFloor(t *testing.T, ctx context.Context, store *Store, q queryer, floor Floor) {
	t.Helper()
	state, err := store.readState(ctx, q, StageAccept)
	require.NoError(t, err)
	require.NotNil(t, state.floor)
	require.Equal(t, floor, *state.floor)
}

type b8PrivateOwnerState struct {
	rows     map[string][][]any
	incoming [][]any
	metadata map[string][]byte
	state    stateSnapshot
}

func b8CapturePrivateOwnerState(t *testing.T, ctx context.Context, store *Store, q queryer) b8PrivateOwnerState {
	t.Helper()
	rows, err := sharedCustodyLogicalRows(ctx, q)
	require.NoError(t, err)
	incoming := b8IncomingRows(t, ctx, q)
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, q)
	state, err := store.readState(ctx, q, StageAccept)
	require.NoError(t, err)
	return b8PrivateOwnerState{rows: rows, incoming: incoming, metadata: metadata, state: state}
}

func mustB8RecordCID(t *testing.T, record []byte) []byte {
	t.Helper()
	cid, err := publication.RecordCID(record)
	require.NoError(t, err)
	return cid
}

type b8QueryCall struct {
	query string
	args  []any
}

type b8QueryRecorder struct {
	source queryer
	calls  []b8QueryCall
}

func (r *b8QueryRecorder) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	r.calls = append(r.calls, b8QueryCall{query: query, args: b8CloneQueryArgs(args)})
	return r.source.QueryContext(ctx, query, args...)
}

func (r *b8QueryRecorder) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	r.calls = append(r.calls, b8QueryCall{query: query, args: b8CloneQueryArgs(args)})
	return r.source.QueryRowContext(ctx, query, args...)
}

func b8CloneQueryArgs(args []any) []any {
	result := make([]any, len(args))
	for index, arg := range args {
		if value, ok := arg.([]byte); ok {
			result[index] = bytes.Clone(value)
		} else {
			result[index] = arg
		}
	}
	return result
}

func b8RequireQueryTrace(t *testing.T, calls []b8QueryCall, fragments []string, args [][]any) {
	t.Helper()
	require.Len(t, calls, len(fragments))
	require.Len(t, args, len(fragments))
	for index, fragment := range fragments {
		require.Contains(t, calls[index].query, fragment, index)
		assert.Equal(t, args[index], calls[index].args, index)
	}
}

func b8FormatQueryTrace(calls []b8QueryCall) string {
	parts := make([]string, len(calls))
	for index, call := range calls {
		parts[index] = fmt.Sprintf("%d:%s args=%#v", index+1, strings.Join(strings.Fields(call.query), " "), call.args)
	}
	return strings.Join(parts, " | ")
}

type b8QueryLease struct {
	store      *Store
	original   *sql.Conn
	tx         *sql.Tx
	decoyDB    *sql.DB
	decoyConn  *sql.Conn
	restored   bool
	rolledBack bool
	closedDB   bool
}

func b8AttachClosedDecoy(t *testing.T, ctx context.Context, store *Store) *b8QueryLease {
	t.Helper()
	lease := &b8QueryLease{store: store, original: store.conn}
	var cleanupErrors []error
	t.Cleanup(func() {
		lease.restore()
		if lease.tx != nil && !lease.rolledBack {
			lease.rolledBack = true
			if err := lease.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		if lease.decoyConn != nil {
			if err := lease.decoyConn.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		if lease.decoyDB != nil && !lease.closedDB {
			lease.closedDB = true
			if err := lease.decoyDB.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		for _, err := range cleanupErrors {
			assert.NoError(t, err)
		}
	})
	var err error
	lease.tx, err = lease.original.BeginTx(ctx, nil)
	require.NoError(t, err)
	lease.decoyDB, err = sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	lease.decoyDB.SetMaxOpenConns(1)
	lease.decoyDB.SetMaxIdleConns(1)
	lease.decoyConn, err = lease.decoyDB.Conn(ctx)
	require.NoError(t, err)
	require.NotSame(t, lease.original, lease.decoyConn)
	closeErr := lease.decoyConn.Close()
	poolErr := lease.decoyDB.Close()
	lease.closedDB = true
	require.NoError(t, closeErr)
	require.NoError(t, poolErr)
	require.ErrorIs(t, lease.decoyConn.PingContext(ctx), sql.ErrConnDone)
	require.Nil(t, ctx.Err())
	store.conn = lease.decoyConn
	return lease
}

func (l *b8QueryLease) restore() {
	if l == nil || l.restored {
		return
	}
	l.restored = true
	l.store.conn = l.original
}

func (l *b8QueryLease) restoreRollbackClose(t *testing.T) {
	t.Helper()
	l.restore()
	var cleanupErrors []error
	if l.tx != nil && !l.rolledBack {
		l.rolledBack = true
		if err := l.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if l.decoyConn != nil {
		if err := l.decoyConn.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if l.decoyDB != nil && !l.closedDB {
		l.closedDB = true
		if err := l.decoyDB.Close(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	for _, err := range cleanupErrors {
		require.NoError(t, err)
	}
}

type b8AlternatePayloadFixture struct {
	payload []byte
	blob    publication.BlobReference
	name    string
}

func b8BuildOtherPackedPayload(t *testing.T) b8AlternatePayloadFixture {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "other.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("second synthetic incoming material payload"), Mode: 0o600}}},
	}
	packed, err := vault.Pack(snapshot)
	require.NoError(t, err)
	cid, err := publication.RawPayloadCID(packed.Payload)
	require.NoError(t, err)
	blob := publication.BlobReference{CID: bytes.Clone(cid), Size: uint64(len(packed.Payload))}
	decoded, err := publication.DecodePayload(packed.Payload, blob)
	require.NoError(t, err)
	require.Len(t, decoded.Targets, 1)
	require.Len(t, decoded.Entries, 1)
	name, err := payloadBasenameFromCID(blob.CID)
	require.NoError(t, err)
	return b8AlternatePayloadFixture{payload: bytes.Clone(packed.Payload), blob: blob, name: name}
}
