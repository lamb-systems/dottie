package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const incomingMaterialExpectedSchemaStatement = "CREATE TABLE accepted_material_refs (accepted_revision INTEGER PRIMARY KEY NOT NULL REFERENCES accepted_events(revision), record_cid BLOB NOT NULL REFERENCES accepted_records(cid), blob_cid BLOB NOT NULL REFERENCES payload_objects(blob_cid))"

func incomingMaterialFirstUse(t *testing.T, store *Store, f fixture) Floor {
	t.Helper()
	ctx := context.Background()
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	require.Equal(t, ModeFirstUse, proposal.Mode)
	require.Equal(t, Reason(""), proposal.Reason)
	require.Equal(t, "first_use", proposal.Stop)
	floor, err := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), floor.Revision)
	require.Equal(t, uint64(1), floor.Generation)
	return floor
}

func incomingMaterialHistoricalLifecycle(t *testing.T, store *Store, f fixture) (Floor, Floor, Floor) {
	t.Helper()
	ctx := context.Background()
	first := incomingMaterialFirstUse(t, store, f)
	advanceObservation := f.observation(2)
	advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, f.payload)
	require.NoError(t, err)
	require.Equal(t, ModeAdvance, advanceProposal.Mode)
	require.Equal(t, Reason(""), advanceProposal.Reason)
	require.Equal(t, "joined", advanceProposal.Stop)
	second, err := store.Accept(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, f.payload, advanceProposal.Confirmation)
	require.NoError(t, err)
	replacementObservation := f.observation(1)
	replacementProposal, err := store.Prepare(ctx, ModeReplaceFloor, replacementObservation, f.payload)
	require.NoError(t, err)
	require.Equal(t, ModeReplaceFloor, replacementProposal.Mode)
	require.Equal(t, ReasonRollback, replacementProposal.Reason)
	require.Equal(t, "rollback", replacementProposal.Stop)
	third, err := store.Accept(ctx, ModeReplaceFloor, replacementProposal.StateToken, replacementObservation, f.payload, replacementProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Revision)
	require.Equal(t, uint64(2), second.Revision)
	require.Equal(t, uint64(3), third.Revision)
	require.Equal(t, uint64(1), first.Generation)
	require.Equal(t, uint64(1), second.Generation)
	require.Equal(t, uint64(2), third.Generation)
	require.Equal(t, first.RecordCID, third.RecordCID)
	require.NotEqual(t, first.RecordCID, second.RecordCID)
	require.Equal(t, first.BlobCID, second.BlobCID)
	require.Equal(t, first.BlobCID, third.BlobCID)
	incomingMaterialRequireLifecycleHistory(t, store, []Floor{first, second, third})
	return first, second, third
}

func incomingMaterialRequireLifecycleHistory(t *testing.T, store *Store, floors []Floor) {
	t.Helper()
	require.Len(t, floors, 3)
	history, err := store.History(context.Background(), 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Equal(t, uint64(3), history.NextRevision)
	require.Len(t, history.Events, 3)
	require.Len(t, history.Records, 2)
	modes := []Mode{ModeFirstUse, ModeAdvance, ModeReplaceFloor}
	reasons := []Reason{"", "", ReasonRollback}
	for index, event := range history.Events {
		require.Equal(t, uint64(index+1), event.Revision)
		require.Equal(t, modes[index], event.Mode)
		require.Equal(t, reasons[index], event.Reason)
		require.Equal(t, floors[index], event.NewFloor)
		require.NotEmpty(t, event.Stop)
	}
	for _, evidence := range history.Records {
		require.NotEmpty(t, evidence.Raw)
	}
}

func incomingMaterialCreateTable(t *testing.T, ctx context.Context, tx *sql.Tx) {
	t.Helper()
	_, err := tx.ExecContext(ctx, incomingMaterialSchemaStatement)
	require.NoError(t, err)
}

func incomingMaterialInsertCatalog(t *testing.T, ctx context.Context, tx *sql.Tx, cid []byte, size int64, name string, logical int64) {
	t.Helper()
	_, err := tx.ExecContext(ctx, "INSERT INTO payload_objects(blob_cid,size,basename,logical_bytes) VALUES(?,?,?,?)", cid, size, name, logical)
	require.NoError(t, err)
}

func incomingMaterialValidCatalog(t *testing.T, ctx context.Context, tx *sql.Tx, cid []byte, size uint64) {
	t.Helper()
	name, err := payloadBasenameFromCID(cid)
	require.NoError(t, err)
	incomingMaterialInsertCatalog(t, ctx, tx, cid, int64(size), name, int64(size))
}

func incomingMaterialInsertRef(t *testing.T, ctx context.Context, tx *sql.Tx, revision int64, recordCID any, blobCID any) {
	t.Helper()
	_, err := tx.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", revision, recordCID, blobCID)
	require.NoError(t, err)
}

func incomingMaterialTransaction(t *testing.T, store *Store, deferred bool) (*sql.Tx, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	tx, err := store.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			assert.NoError(t, err)
		}
		if deferred {
			diagnosticContext, diagnosticCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer diagnosticCancel()
			var foreignKeys, stillDeferred int64
			assert.NoError(t, store.conn.QueryRowContext(diagnosticContext, "PRAGMA foreign_keys").Scan(&foreignKeys))
			assert.Equal(t, int64(1), foreignKeys)
			assert.NoError(t, store.conn.QueryRowContext(diagnosticContext, "PRAGMA defer_foreign_keys").Scan(&stillDeferred))
			assert.Equal(t, int64(0), stillDeferred)
		}
	})
	if deferred {
		_, err = tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON")
		require.NoError(t, err)
		var enabled int64
		require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&enabled))
		require.Equal(t, int64(1), enabled)
	}
	return tx, ctx
}

func incomingMaterialRollback(t *testing.T, ctx context.Context, store *Store, tx *sql.Tx) {
	t.Helper()
	require.NoError(t, tx.Rollback())
	var foreignKeys, deferred int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys))
	assert.Equal(t, int64(1), foreignKeys)
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&deferred))
	assert.Equal(t, int64(0), deferred)
}

func incomingMaterialCount(t *testing.T, ctx context.Context, q queryer, query string, args ...any) int64 {
	t.Helper()
	count, err := queryInt64(ctx, q, query, args...)
	require.NoError(t, err)
	return count
}

func incomingMaterialRequireBoundedCounts(t *testing.T, ctx context.Context, q queryer, limit uint32) (int64, int64) {
	t.Helper()
	var eventCount, refCount int64
	require.NoError(t, q.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM accepted_events),(SELECT COUNT(*) FROM accepted_material_refs)").Scan(&eventCount, &refCount))
	require.GreaterOrEqual(t, refCount, int64(0))
	require.GreaterOrEqual(t, eventCount, refCount)
	require.LessOrEqual(t, eventCount, int64(limit))
	return eventCount, refCount
}

func incomingMaterialRequireReadState(t *testing.T, ctx context.Context, store *Store, q queryer, stage Stage) stateSnapshot {
	t.Helper()
	state, err := store.readState(ctx, q, stage)
	require.NoError(t, err)
	return state
}

func incomingMaterialRequireNoForeignKeyViolation(t *testing.T, ctx context.Context, q queryer) {
	t.Helper()
	rows, err := q.QueryContext(ctx, "PRAGMA foreign_key_check")
	require.NoError(t, err)
	present := rows.Next()
	var table, parent, rowID, foreignKeyID any
	var scanErr error
	if present {
		scanErr = rows.Scan(&table, &rowID, &parent, &foreignKeyID)
	}
	iterErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, iterErr)
	require.NoError(t, closeErr)
	require.Falsef(t, present, "unexpected foreign key violation: %v -> %v", table, parent)
}

func incomingMaterialRequireForeignKeyViolation(t *testing.T, ctx context.Context, q queryer) {
	t.Helper()
	rows, err := q.QueryContext(ctx, "PRAGMA foreign_key_check")
	require.NoError(t, err)
	present := rows.Next()
	var table, parent, rowID, foreignKeyID any
	var scanErr error
	if present {
		scanErr = rows.Scan(&table, &rowID, &parent, &foreignKeyID)
	}
	iterErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, iterErr)
	require.NoError(t, closeErr)
	require.Truef(t, present, "expected a foreign key violation")
}

func incomingMaterialRowSnapshot(t *testing.T, ctx context.Context, q queryer) [][]any {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT accepted_revision,record_cid,blob_cid FROM accepted_material_refs ORDER BY accepted_revision")
	require.NoError(t, err)
	snapshot := make([][]any, 0)
	for rows.Next() {
		values, err := scanRawValues(rows, 3)
		require.NoError(t, err)
		snapshot = append(snapshot, values)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	return snapshot
}

func incomingMaterialSecondPayloadCID(t *testing.T) ([]byte, uint64) {
	t.Helper()
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "files", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "other", Kind: model.SelectionDirectory}}},
		Entries: []model.Entry{{TargetID: "files", File: &model.FileEntry{Path: "other.lua", State: model.FilePresent, Kind: model.FileRegular, Content: []byte("second synthetic incoming material payload"), Mode: 0o600}}},
	}
	blob, err := vault.Pack(snapshot)
	require.NoError(t, err)
	_, err = vault.Unpack(blob)
	require.NoError(t, err)
	cid, err := publication.RawPayloadCID(blob.Payload)
	require.NoError(t, err)
	decoded, err := publication.DecodePayload(blob.Payload, publication.BlobReference{CID: cid, Size: uint64(len(blob.Payload))})
	require.NoError(t, err)
	require.Len(t, decoded.Targets, 1)
	require.Len(t, decoded.Entries, 1)
	require.Equal(t, "files", decoded.Targets[0].ID)
	require.Equal(t, "files", decoded.Entries[0].TargetID)
	return cid, uint64(len(blob.Payload))
}

func TestIncomingMaterialSchemaDefinitionAndSource2Isolation(t *testing.T) {
	ctx := context.Background()
	require.Equal(t, incomingMaterialExpectedSchemaStatement, incomingMaterialSchemaStatement)

	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	tx, txContext := incomingMaterialTransaction(t, store, false)
	incomingMaterialCreateTable(t, txContext, tx)
	var storedSQL any
	require.NoError(t, tx.QueryRowContext(txContext, "SELECT sql FROM sqlite_master WHERE type='table' AND name='accepted_material_refs'").Scan(&storedSQL))
	storedText, ok := storedSQL.(string)
	require.True(t, ok)
	assert.Equal(t, incomingMaterialSchemaStatement, strings.TrimSpace(storedText))

	infoRows, err := tx.QueryContext(txContext, "PRAGMA table_info(accepted_material_refs)")
	require.NoError(t, err)
	type incomingMaterialColumn struct {
		name    string
		kind    string
		notNull int64
		primary int64
	}
	columns := make(map[string]incomingMaterialColumn)
	for infoRows.Next() {
		var index, notNull, primary int64
		var name, kind string
		var defaultValue any
		require.NoError(t, infoRows.Scan(&index, &name, &kind, &notNull, &defaultValue, &primary))
		columns[name] = incomingMaterialColumn{name: name, kind: kind, notNull: notNull, primary: primary}
	}
	require.NoError(t, infoRows.Err())
	require.NoError(t, infoRows.Close())
	require.Equal(t, map[string]incomingMaterialColumn{
		"accepted_revision": {name: "accepted_revision", kind: "INTEGER", notNull: 1, primary: 1},
		"record_cid":        {name: "record_cid", kind: "BLOB", notNull: 1, primary: 0},
		"blob_cid":          {name: "blob_cid", kind: "BLOB", notNull: 1, primary: 0},
	}, columns)

	foreignRows, err := tx.QueryContext(txContext, "PRAGMA foreign_key_list(accepted_material_refs)")
	require.NoError(t, err)
	parents := make(map[string]string)
	for foreignRows.Next() {
		var id, sequence int64
		var table, from, to, onUpdate, onDelete, match string
		require.NoError(t, foreignRows.Scan(&id, &sequence, &table, &from, &to, &onUpdate, &onDelete, &match))
		assert.Equal(t, "NO ACTION", onUpdate)
		assert.Equal(t, "NO ACTION", onDelete)
		parents[from] = table
	}
	require.NoError(t, foreignRows.Err())
	require.NoError(t, foreignRows.Close())
	assert.Equal(t, map[string]string{"accepted_revision": "accepted_events", "record_cid": "accepted_records", "blob_cid": "payload_objects"}, parents)

	var auxiliaryObjects int64
	require.NoError(t, tx.QueryRowContext(txContext, "SELECT COUNT(*) FROM sqlite_master WHERE tbl_name='accepted_material_refs' AND type IN ('index','trigger')").Scan(&auxiliaryObjects))
	assert.Zero(t, auxiliaryObjects)
	incomingMaterialRollback(t, txContext, store, tx)

	var tableCount int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accepted_material_refs'").Scan(&tableCount))
	assert.Zero(t, tableCount)
	require.NoError(t, checkSchemaVersion(ctx, store.conn, 2))
	assert.Equal(t, 2, store.schemaVersion)

	floor := incomingMaterialFirstUse(t, store, f)
	requirePayloadDirectoryAbsent(t, directory)
	database := store.directory + "/publication.db"
	sourceMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
	sourceRows := incomingMaterialUpgradeFixtureTypedRows(t, ctx, store.conn)
	require.Len(t, sourceMetadata, 7)
	require.Len(t, sourceRows, 15)
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	require.NoError(t, store.Close())
	refused, err := Open(directory, f.binding)
	if refused != nil {
		t.Cleanup(func() { assert.NoError(t, refused.Close()) })
	}
	require.Nil(t, refused)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, database)
	require.NoError(t, checkSchemaVersion(ctx, readOnly, 2))
	require.Equal(t, sourceMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, readOnly))
	require.Equal(t, sourceRows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, readOnly))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, readOnly))
	closeReadOnly(t)
	options := DefaultOpenOptions()
	options.UpgradeFromAttempts = true
	migrated, err := OpenWithOptions(directory, f.binding, options)
	if migrated != nil {
		t.Cleanup(func() { assert.NoError(t, migrated.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 3, migrated.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, migrated.conn))
	require.NoError(t, checkSchema(ctx, migrated.conn))
	migratedObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, migrated.conn)
	migratedCounts := incomingMaterialUpgradeFixtureObjectCounts(t, migratedObjects)
	require.Equal(t, 16, migratedCounts.tables)
	require.Equal(t, 2, migratedCounts.namedIndexes)
	require.Equal(t, 14, migratedCounts.autoIndexes)
	require.Len(t, migratedObjects, 32)
	require.Equal(t, sourceMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, migrated.conn))
	require.Equal(t, sourceRows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, migrated.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, migrated.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, migrated.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	migratedFloor, present, err := migrated.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor, migratedFloor)
	requirePayloadDirectoryAbsent(t, directory)
	require.NoError(t, migrated.Close())
	reopened, err := Open(directory, f.binding)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	require.NotNil(t, reopened)
	require.Equal(t, 3, reopened.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, reopened.conn))
	require.NoError(t, checkSchema(ctx, reopened.conn))
	require.NoError(t, checkSchemaVersion(ctx, reopened.conn, 3))
	loaded, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, floor, loaded)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, reopened.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.Equal(t, sourceMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, reopened.conn))
	require.Equal(t, sourceRows, incomingMaterialUpgradeFixtureTypedRows(t, ctx, reopened.conn))
	requirePayloadDirectoryAbsent(t, directory)
	require.NoError(t, reopened.Close())
}

func TestIncomingMaterialRefsEmpty(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)

	emptyStore, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, emptyStore.Close()) })
	tx, txContext := incomingMaterialTransaction(t, emptyStore, false)
	var tableCount int64
	require.NoError(t, tx.QueryRowContext(txContext, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accepted_material_refs'").Scan(&tableCount))
	require.Zero(t, tableCount)
	incomingMaterialCreateTable(t, txContext, tx)
	incomingMaterialRequireReadState(t, txContext, emptyStore, tx, StageLoad)
	incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
	require.NoError(t, emptyStore.checkIncomingMaterialRefs(txContext, tx, StageLoad))
	assert.Zero(t, incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
	assert.Zero(t, incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	incomingMaterialRollback(t, txContext, emptyStore, tx)

	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	incomingMaterialFirstUse(t, store, f)
	tx, txContext = incomingMaterialTransaction(t, store, false)
	incomingMaterialCreateTable(t, txContext, tx)
	incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
	incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
	require.NoError(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad))
	assert.Equal(t, int64(1), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
	assert.Zero(t, incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	incomingMaterialRollback(t, txContext, store, tx)
}

func TestIncomingMaterialRefsHistoricalSharedMetadataOnly(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	limits := DefaultLimits()
	limits.AcceptedEventCount = 3
	store, directory := newSchema2UnitStore(t, f, limits)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	first, second, third := incomingMaterialHistoricalLifecycle(t, store, f)

	tx, txContext := incomingMaterialTransaction(t, store, false)
	incomingMaterialCreateTable(t, txContext, tx)
	incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
	for _, floor := range []Floor{first, second, third} {
		incomingMaterialInsertRef(t, txContext, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
	}
	require.Equal(t, int64(3), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
	require.Equal(t, int64(3), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.Equal(t, int64(2), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_records"))

	beforeState := incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
	incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
	beforeRows, err := sharedCustodyLogicalRows(txContext, tx)
	require.NoError(t, err)
	beforeIncoming := incomingMaterialRowSnapshot(t, txContext, tx)
	require.Len(t, beforeIncoming, 3)
	require.Equal(t, -1, store.payloadFD)
	requirePayloadDirectoryAbsent(t, directory)

	require.NoError(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad))

	afterRows, err := sharedCustodyLogicalRows(txContext, tx)
	require.NoError(t, err)
	assert.Equal(t, beforeRows, afterRows)
	afterIncoming := incomingMaterialRowSnapshot(t, txContext, tx)
	assert.Equal(t, beforeIncoming, afterIncoming)
	require.Len(t, afterIncoming, 3)
	for index, floor := range []Floor{first, second, third} {
		require.Equal(t, int64(floor.Revision), afterIncoming[index][0])
		assert.Equal(t, floor.RecordCID, afterIncoming[index][1])
		assert.Equal(t, floor.BlobCID, afterIncoming[index][2])
	}
	afterState := incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
	assert.Equal(t, beforeState.token, afterState.token)
	assert.Equal(t, beforeState.revision, afterState.revision)
	assert.Equal(t, beforeState.generation, afterState.generation)
	assert.Equal(t, 3, len(afterRows["accepted_events"]))
	require.Equal(t, -1, store.payloadFD)
	requirePayloadDirectoryAbsent(t, directory)
	incomingMaterialRollback(t, txContext, store, tx)

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, third, loaded)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	assert.Len(t, history.Events, 3)
}

func TestIncomingMaterialRefsUsesSuppliedTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, directory := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	first, second, third := incomingMaterialHistoricalLifecycle(t, store, f)

	tx, restore := beginSharedCustodyTransaction(t, ctx, store)
	_, err := store.conn.QueryContext(ctx, "SELECT 1")
	require.Error(t, err)
	require.ErrorIs(t, err, sql.ErrConnDone)
	var original int64
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT 1").Scan(&original))
	require.Equal(t, int64(1), original)

	incomingMaterialCreateTable(t, ctx, tx)
	assert.Zero(t, incomingMaterialCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.NoError(t, store.checkIncomingMaterialRefs(ctx, tx, StageOpen))

	incomingMaterialValidCatalog(t, ctx, tx, first.BlobCID, first.BlobSize)
	for _, floor := range []Floor{first, second, third} {
		incomingMaterialInsertRef(t, ctx, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
	}
	incomingMaterialRequireReadState(t, ctx, store, tx, StageOpen)
	incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
	requirePayloadDirectoryAbsent(t, directory)
	require.Equal(t, -1, store.payloadFD)
	require.NoError(t, store.checkIncomingMaterialRefs(ctx, tx, StageOpen))
	assert.Equal(t, int64(3), incomingMaterialCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))

	restore()
	incomingMaterialRollback(t, ctx, store, tx)
	require.Equal(t, -1, store.payloadFD)
	requirePayloadDirectoryAbsent(t, directory)
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, third, loaded)
}

func TestIncomingMaterialRefsRejectsShapesAndBounds(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	first := incomingMaterialFirstUse(t, store, f)

	shapes := []struct {
		name         string
		revision     int64
		recordCID    any
		blobCID      any
		recordType   string
		blobType     string
		recordLength int64
		blobLength   int64
	}{
		{name: "record cid text", revision: 1, recordCID: "not-a-cid", blobCID: first.BlobCID, recordType: "text", blobType: "blob", recordLength: 9, blobLength: int64(len(first.BlobCID))},
		{name: "record cid empty", revision: 1, recordCID: []byte{}, blobCID: first.BlobCID, recordType: "blob", blobType: "blob", recordLength: 0, blobLength: int64(len(first.BlobCID))},
		{name: "record cid 129 bytes", revision: 1, recordCID: make([]byte, 129), blobCID: first.BlobCID, recordType: "blob", blobType: "blob", recordLength: 129, blobLength: int64(len(first.BlobCID))},
		{name: "blob cid empty", revision: 1, recordCID: first.RecordCID, blobCID: []byte{}, recordType: "blob", blobType: "blob", recordLength: int64(len(first.RecordCID)), blobLength: 0},
		{name: "blob cid 129 bytes", revision: 1, recordCID: first.RecordCID, blobCID: make([]byte, 129), recordType: "blob", blobType: "blob", recordLength: int64(len(first.RecordCID)), blobLength: 129},
		{name: "revision zero", revision: 0, recordCID: first.RecordCID, blobCID: first.BlobCID, recordType: "blob", blobType: "blob", recordLength: int64(len(first.RecordCID)), blobLength: int64(len(first.BlobCID))},
		{name: "revision negative", revision: -1, recordCID: first.RecordCID, blobCID: first.BlobCID, recordType: "blob", blobType: "blob", recordLength: int64(len(first.RecordCID)), blobLength: int64(len(first.BlobCID))},
		{name: "revision above max sequence", revision: int64(publication.MaxSequence) + 1, recordCID: first.RecordCID, blobCID: first.BlobCID, recordType: "blob", blobType: "blob", recordLength: int64(len(first.RecordCID)), blobLength: int64(len(first.BlobCID))},
	}
	for _, test := range shapes {
		t.Run(test.name, func(t *testing.T) {
			tx, txContext := incomingMaterialTransaction(t, store, true)
			incomingMaterialCreateTable(t, txContext, tx)
			incomingMaterialInsertRef(t, txContext, tx, test.revision, test.recordCID, test.blobCID)
			var revisionType, recordType, blobType string
			var recordLength, blobLength int64
			require.NoError(t, tx.QueryRowContext(txContext, "SELECT typeof(accepted_revision),typeof(record_cid),length(CAST(record_cid AS BLOB)),typeof(blob_cid),length(CAST(blob_cid AS BLOB)) FROM accepted_material_refs WHERE accepted_revision=?", test.revision).Scan(&revisionType, &recordType, &recordLength, &blobType, &blobLength))
			require.Equal(t, "integer", revisionType)
			require.Equal(t, test.recordType, recordType)
			require.Equal(t, test.recordLength, recordLength)
			require.Equal(t, test.blobType, blobType)
			require.Equal(t, test.blobLength, blobLength)
			events, refs := incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
			require.Equal(t, int64(1), events)
			require.Equal(t, int64(1), refs)
			requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
		})
	}

	t.Run("configured event count exceeded", func(t *testing.T) {
		threeEvents := newFixture(t, BackendPublicRepo)
		threeEvents.appendRecord(t, 0)
		threeEvents.appendRecord(t, 1)
		limits := DefaultLimits()
		limits.AcceptedEventCount = 3
		boundedStore, _ := newSchema2UnitStore(t, threeEvents, limits)
		t.Cleanup(func() { assert.NoError(t, boundedStore.Close()) })
		incomingMaterialHistoricalLifecycle(t, boundedStore, threeEvents)
		tx, txContext := incomingMaterialTransaction(t, boundedStore, false)
		incomingMaterialCreateTable(t, txContext, tx)
		_, err := tx.ExecContext(txContext, "INSERT INTO accepted_events(revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes) SELECT ?,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes FROM accepted_events WHERE revision=1", int64(4))
		require.NoError(t, err)
		events := incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events")
		refs := incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs")
		require.Equal(t, int64(4), events)
		require.Greater(t, events, int64(limits.AcceptedEventCount))
		require.Zero(t, refs)
		requireErrorMetadata(t, boundedStore.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("ref count exceeds event count", func(t *testing.T) {
		threeEvents := newFixture(t, BackendPublicRepo)
		threeEvents.appendRecord(t, 0)
		threeEvents.appendRecord(t, 1)
		limits := DefaultLimits()
		limits.AcceptedEventCount = 3
		boundedStore, _ := newSchema2UnitStore(t, threeEvents, limits)
		t.Cleanup(func() { assert.NoError(t, boundedStore.Close()) })
		firstFloor, secondFloor, thirdFloor := incomingMaterialHistoricalLifecycle(t, boundedStore, threeEvents)
		tx, txContext := incomingMaterialTransaction(t, boundedStore, true)
		incomingMaterialCreateTable(t, txContext, tx)
		for _, floor := range []Floor{firstFloor, secondFloor, thirdFloor} {
			incomingMaterialInsertRef(t, txContext, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
		}
		incomingMaterialInsertRef(t, txContext, tx, int64(4), firstFloor.RecordCID, firstFloor.BlobCID)
		events := incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events")
		refs := incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs")
		require.Equal(t, int64(3), events)
		require.Equal(t, int64(4), refs)
		require.Greater(t, refs, events)
		requireErrorMetadata(t, boundedStore.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("integer primary key refuses non-integer values", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		_, err := tx.ExecContext(txContext, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", 1.5, first.RecordCID, first.BlobCID)
		require.Error(t, err)
		_, err = tx.ExecContext(txContext, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", "one", first.RecordCID, first.BlobCID)
		require.Error(t, err)
		require.Zero(t, incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	})

	t.Run("not null refuses null cid", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		_, err := tx.ExecContext(txContext, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", int64(1), nil, first.BlobCID)
		require.Error(t, err)
		require.Zero(t, incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	})
}

func TestIncomingMaterialRefsRejectsDanglingAndWrongJoins(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	first, second, third := incomingMaterialHistoricalLifecycle(t, store, f)

	t.Run("wrong existing record", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		for _, floor := range []Floor{first, second, third} {
			incomingMaterialInsertRef(t, txContext, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
		}
		_, err := tx.ExecContext(txContext, "UPDATE accepted_material_refs SET record_cid=? WHERE accepted_revision=1", second.RecordCID)
		require.NoError(t, err)
		incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
		incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("wrong existing blob", func(t *testing.T) {
		otherCID, otherSize := incomingMaterialSecondPayloadCID(t)
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialValidCatalog(t, txContext, tx, otherCID, otherSize)
		for _, floor := range []Floor{first, second, third} {
			incomingMaterialInsertRef(t, txContext, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
		}
		_, err := tx.ExecContext(txContext, "UPDATE accepted_material_refs SET blob_cid=? WHERE accepted_revision=1", otherCID)
		require.NoError(t, err)
		incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
		incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("missing event", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, true)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
		incomingMaterialInsertRef(t, txContext, tx, int64(second.Revision), second.RecordCID, second.BlobCID)
		_, err := tx.ExecContext(txContext, "DELETE FROM accepted_events WHERE revision=1")
		require.NoError(t, err)
		require.Equal(t, int64(2), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
		require.Equal(t, int64(2), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		incomingMaterialRequireForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("missing record", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, true)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		for _, floor := range []Floor{first, second, third} {
			incomingMaterialInsertRef(t, txContext, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
		}
		_, err := tx.ExecContext(txContext, "DELETE FROM accepted_records WHERE cid=?", first.RecordCID)
		require.NoError(t, err)
		require.Equal(t, int64(3), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_events"))
		require.Equal(t, int64(3), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		incomingMaterialRequireForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("missing catalog", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, true)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
		_, err := tx.ExecContext(txContext, "DELETE FROM payload_objects WHERE blob_cid=?", first.BlobCID)
		require.NoError(t, err)
		require.Equal(t, int64(1), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		incomingMaterialRequireForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("dangling record cid refuses at floor equality", func(t *testing.T) {
		missingCID := bytes.Repeat([]byte{0x7f}, 36)
		tx, txContext := incomingMaterialTransaction(t, store, true)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), missingCID, first.BlobCID)
		incomingMaterialRequireForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})
}

func TestIncomingMaterialRefsRejectsCatalogMetadata(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	first := incomingMaterialFirstUse(t, store, f)
	wantedName, err := payloadBasenameFromCID(first.BlobCID)
	require.NoError(t, err)
	originalSize := int64(first.BlobSize)

	t.Run("positive size with matching logical bytes", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
		_, err := tx.ExecContext(txContext, "UPDATE payload_objects SET size=size+1,logical_bytes=logical_bytes+1 WHERE blob_cid=?", first.BlobCID)
		require.NoError(t, err)
		var size, logical int64
		require.NoError(t, tx.QueryRowContext(txContext, "SELECT size,logical_bytes FROM payload_objects WHERE blob_cid=?", first.BlobCID).Scan(&size, &logical))
		require.Equal(t, originalSize+1, size)
		require.Equal(t, size, logical)
		require.LessOrEqual(t, uint64(size), publication.MaxBlobBytes)
		require.Less(t, uint64(size), store.attemptLimits.CustodyBytes)
		incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
		incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("logical bytes differ from size", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
		_, err := tx.ExecContext(txContext, "UPDATE payload_objects SET logical_bytes=logical_bytes+1 WHERE blob_cid=?", first.BlobCID)
		require.NoError(t, err)
		requireErrorMetadata(t, func() error { _, readErr := store.readState(txContext, tx, StageLoad); return readErr }(), ErrSchema, StageLoad, ReasonCorrupt)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})

	t.Run("size type and range", func(t *testing.T) {
		for index, value := range []any{"sixty", int64(0), int64(-1)} {
			t.Run(fmt.Sprintf("case-%d", index), func(t *testing.T) {
				tx, txContext := incomingMaterialTransaction(t, store, false)
				incomingMaterialCreateTable(t, txContext, tx)
				incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
				incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
				_, err := tx.ExecContext(txContext, "UPDATE payload_objects SET size=? WHERE blob_cid=?", value, first.BlobCID)
				require.NoError(t, err)
				var sizeType string
				var size any
				require.NoError(t, tx.QueryRowContext(txContext, "SELECT typeof(size),CASE WHEN typeof(size)='integer' THEN size END FROM payload_objects WHERE blob_cid=?", first.BlobCID).Scan(&sizeType, &size))
				if _, ok := value.(string); ok {
					require.Equal(t, "text", sizeType)
					require.Nil(t, size)
				} else {
					require.Equal(t, "integer", sizeType)
					require.Equal(t, value, size)
				}
				requireErrorMetadata(t, func() error { _, readErr := store.readState(txContext, tx, StageLoad); return readErr }(), ErrSchema, StageLoad, ReasonCorrupt)
				incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
				requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
			})
		}
	})

	t.Run("wrong canonical basename", func(t *testing.T) {
		for _, test := range []struct{ name, basename string }{
			{name: "alternate lowercase hex", basename: strings.Repeat("a", 64) + payloadSuffix},
			{name: "uppercase hex", basename: strings.ToUpper(wantedName)},
			{name: "short name", basename: wantedName[:len(wantedName)-1]},
		} {
			t.Run(test.name, func(t *testing.T) {
				tx, txContext := incomingMaterialTransaction(t, store, false)
				incomingMaterialCreateTable(t, txContext, tx)
				incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
				incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
				_, err := tx.ExecContext(txContext, "UPDATE payload_objects SET basename=? WHERE blob_cid=?", test.basename, first.BlobCID)
				require.NoError(t, err)
				var nameType string
				var nameLength int64
				require.NoError(t, tx.QueryRowContext(txContext, "SELECT typeof(basename),length(CAST(basename AS BLOB)) FROM payload_objects WHERE blob_cid=?", first.BlobCID).Scan(&nameType, &nameLength))
				require.Equal(t, "text", nameType)
				require.Equal(t, int64(len(test.basename)), nameLength)
				requireErrorMetadata(t, func() error { _, readErr := store.readState(txContext, tx, StageLoad); return readErr }(), ErrSchema, StageLoad, ReasonCorrupt)
				incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
				requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
			})
		}
	})

	t.Run("basename type", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
		incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
		_, err := tx.ExecContext(txContext, "UPDATE payload_objects SET basename=? WHERE blob_cid=?", []byte(wantedName), first.BlobCID)
		require.NoError(t, err)
		var nameType string
		var nameLength int64
		require.NoError(t, tx.QueryRowContext(txContext, "SELECT typeof(basename),length(CAST(basename AS BLOB)) FROM payload_objects WHERE blob_cid=?", first.BlobCID).Scan(&nameType, &nameLength))
		require.Equal(t, "blob", nameType)
		require.Equal(t, int64(len(wantedName)), nameLength)
		requireErrorMetadata(t, func() error { _, readErr := store.readState(txContext, tx, StageLoad); return readErr }(), ErrSchema, StageLoad, ReasonCorrupt)
		incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	})
}

func TestIncomingMaterialRefsRejectsDuplicateRetainedRevision(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	_, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
	first := finalized.Floor
	require.Equal(t, uint64(1), first.Revision)
	advanceObservation := f.observation(2)
	advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, f.payload)
	require.NoError(t, err)
	require.Equal(t, ModeAdvance, advanceProposal.Mode)
	require.Equal(t, Reason(""), advanceProposal.Reason)
	require.Equal(t, "joined", advanceProposal.Stop)
	second, err := store.Accept(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, f.payload, advanceProposal.Confirmation)
	require.NoError(t, err)
	replacementObservation := f.observation(1)
	replacementProposal, err := store.Prepare(ctx, ModeReplaceFloor, replacementObservation, f.payload)
	require.NoError(t, err)
	require.Equal(t, ModeReplaceFloor, replacementProposal.Mode)
	require.Equal(t, ReasonRollback, replacementProposal.Reason)
	require.Equal(t, "rollback", replacementProposal.Stop)
	third, err := store.Accept(ctx, ModeReplaceFloor, replacementProposal.StateToken, replacementObservation, f.payload, replacementProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, first.RecordCID, third.RecordCID)
	require.Equal(t, uint64(1), first.Revision)
	require.Equal(t, uint64(2), second.Revision)
	require.Equal(t, uint64(3), third.Revision)
	require.Equal(t, uint64(1), first.Generation)
	require.Equal(t, uint64(1), second.Generation)
	require.Equal(t, uint64(2), third.Generation)
	require.NotEqual(t, first.RecordCID, second.RecordCID)
	require.Equal(t, first.BlobCID, second.BlobCID)
	require.Equal(t, first.BlobCID, third.BlobCID)
	incomingMaterialRequireLifecycleHistory(t, store, []Floor{first, second, third})
	var retainedRevision int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT accepted_revision FROM retained_publications WHERE record_cid=?", first.RecordCID).Scan(&retainedRevision))
	require.Equal(t, int64(1), retainedRevision)

	tx, txContext := incomingMaterialTransaction(t, store, false)
	incomingMaterialCreateTable(t, txContext, tx)
	incomingMaterialInsertRef(t, txContext, tx, int64(second.Revision), second.RecordCID, second.BlobCID)
	incomingMaterialInsertRef(t, txContext, tx, int64(third.Revision), third.RecordCID, third.BlobCID)
	incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
	incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
	require.NoError(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad))

	incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
	require.Equal(t, int64(3), incomingMaterialCount(t, txContext, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	incomingMaterialRequireReadState(t, txContext, store, tx, StageLoad)
	incomingMaterialRequireNoForeignKeyViolation(t, txContext, tx)
	incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
	requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
	incomingMaterialRollback(t, txContext, store, tx)
}

func TestIncomingMaterialRefsChecksCanonicalMetadataAndErrors(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, _ := newSchema2UnitStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	first := incomingMaterialFirstUse(t, store, f)

	corruptions := []struct {
		name     string
		query    string
		args     []any
		column   string
		expected int64
	}{
		{name: "event floor 65537 bytes", query: "UPDATE accepted_events SET new_floor=zeroblob(65537) WHERE revision=1", column: "SELECT length(CAST(new_floor AS BLOB)) FROM accepted_events WHERE revision=1", expected: 65537},
		{name: "event digest short", query: "UPDATE accepted_events SET digest=zeroblob(31) WHERE revision=1", column: "SELECT length(CAST(digest AS BLOB)) FROM accepted_events WHERE revision=1", expected: 31},
		{name: "accepted record raw 2049 bytes", query: "UPDATE accepted_records SET raw=zeroblob(2049) WHERE cid=?", args: []any{first.RecordCID}, column: "SELECT length(CAST(raw AS BLOB)) FROM accepted_records WHERE cid=?", expected: 2049},
		{name: "accepted record key 17 bytes", query: "UPDATE accepted_records SET record_key=? WHERE cid=?", args: []any{strings.Repeat("k", 17), first.RecordCID}, column: "SELECT length(CAST(record_key AS BLOB)) FROM accepted_records WHERE cid=?", expected: 17},
		{name: "accepted record sequence negative", query: "UPDATE accepted_records SET sequence=-1 WHERE cid=?", args: []any{first.RecordCID}, column: "SELECT CASE WHEN typeof(sequence)='integer' THEN sequence END FROM accepted_records WHERE cid=?", expected: -1},
	}
	for _, corruption := range corruptions {
		t.Run(corruption.name, func(t *testing.T) {
			tx, txContext := incomingMaterialTransaction(t, store, false)
			incomingMaterialCreateTable(t, txContext, tx)
			incomingMaterialValidCatalog(t, txContext, tx, first.BlobCID, first.BlobSize)
			incomingMaterialInsertRef(t, txContext, tx, int64(first.Revision), first.RecordCID, first.BlobCID)
			_, err := tx.ExecContext(txContext, corruption.query, corruption.args...)
			require.NoError(t, err)
			var observed int64
			columnArgs := corruption.args
			if len(columnArgs) > 0 {
				columnArgs = columnArgs[len(columnArgs)-1:]
			}
			require.NoError(t, tx.QueryRowContext(txContext, corruption.column, columnArgs...).Scan(&observed))
			require.Equal(t, corruption.expected, observed)
			incomingMaterialRequireBoundedCounts(t, txContext, tx, store.limits.AcceptedEventCount)
			requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageLoad), ErrSchema, StageLoad, ReasonCorrupt)
			requireErrorMetadata(t, store.checkIncomingMaterialRefs(txContext, tx, StageOpen), ErrSchema, StageOpen, ReasonCorrupt)
		})
	}

	t.Run("canceled context", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		canceledContext, cancel := context.WithCancel(txContext)
		cancel()
		err := store.checkIncomingMaterialRefs(canceledContext, tx, StageLoad)
		require.ErrorIs(t, err, context.Canceled)
		requireErrorMetadata(t, err, ErrStorage, StageLoad, ReasonCanceled)
	})

	t.Run("deadline context", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		expiredContext, cancel := context.WithTimeout(txContext, 0)
		defer cancel()
		err := store.checkIncomingMaterialRefs(expiredContext, tx, StageLoad)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		requireErrorMetadata(t, err, ErrStorage, StageLoad, ReasonCanceled)
	})

	t.Run("nil context", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		var nilContext context.Context
		requireErrorMetadata(t, store.checkIncomingMaterialRefs(nilContext, tx, StageLoad), ErrInvalid, StageLoad, ReasonContext)
	})

	t.Run("closed store", func(t *testing.T) {
		closedStore, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, closedStore.Close()) })
		require.NoError(t, closedStore.Close())
		requireErrorMetadata(t, closedStore.checkIncomingMaterialRefs(ctx, closedStore.conn, StageOpen), ErrClosed, StageOpen, ReasonClosed)
	})

	t.Run("closed independent queryer", func(t *testing.T) {
		tx, txContext := incomingMaterialTransaction(t, store, false)
		incomingMaterialCreateTable(t, txContext, tx)
		decoyDB, err := sql.Open("sqlite", ":memory:")
		require.NoError(t, err)
		decoyDB.SetMaxOpenConns(1)
		decoyConn, err := decoyDB.Conn(txContext)
		require.NoError(t, err)
		require.NoError(t, decoyConn.Close())
		t.Cleanup(func() { assert.NoError(t, decoyDB.Close()) })
		checkErr := store.checkIncomingMaterialRefs(txContext, decoyConn, StageLoad)
		requireErrorMetadata(t, checkErr, ErrStorage, StageLoad, ReasonIO)
		assert.False(t, errors.Is(checkErr, sql.ErrConnDone))
		assert.NotContains(t, checkErr.Error(), "database is closed")
	})
}
