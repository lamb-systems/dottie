package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	v1state "github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type incomingMaterialSchemaSnapshot struct {
	rows     map[string][][]any
	incoming [][]any
	metadata map[string][]byte
	objects  map[string]incomingMaterialUpgradeFixtureObject
}

type incomingMaterialSchemaState struct {
	f          fixture
	store      *Store
	tx         *sql.Tx
	rolledBack bool
	metadata   map[string][]byte
	rows       map[string][][]any
	objects    map[string]incomingMaterialUpgradeFixtureObject
	source     incomingMaterialUpgradeSource
	view       *Store
	oldGraph   *Store
	floors     []Floor
	finalized  *Finalization
}

func TestIncomingMaterialPrivateSchema3ReadStateUsesQueryer(t *testing.T) {
	t.Run("empty incoming refs on nonempty old graph", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		s := incomingMaterialSchemaBegin(t, ctx, true)
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, s.tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		require.NotZero(t, incomingMaterialUpgradeCount(t, ctx, s.tx, "SELECT COUNT(*) FROM publication_attempts"))
		require.NotZero(t, incomingMaterialUpgradeCount(t, ctx, s.tx, "SELECT COUNT(*) FROM retained_publications"))
		eventCount, refCount := incomingMaterialRequireBoundedCounts(t, ctx, s.tx, s.view.limits.AcceptedEventCount)
		require.NotZero(t, eventCount)
		require.Zero(t, refCount)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, s.tx)
		before := incomingMaterialSchemaCapture(t, ctx, s.tx)
		incomingMaterialRequireReadState(t, ctx, s.oldGraph, s.tx, StageLoad)
		recorder := &incomingMaterialUpgradeRecorder{source: s.tx}
		incomingMaterialSchemaAttachDecoy(t, ctx, s)
		recorded, err := s.view.readState(ctx, recorder, StageLoad)
		require.NoError(t, err)
		direct := incomingMaterialRequireReadState(t, ctx, s.view, s.tx, StageLoad)
		require.Equal(t, direct, recorded)
		incomingMaterialSchemaRecordedQuery(t, recorder, "(SELECT COUNT(*) FROM accepted_events),(SELECT COUNT(*) FROM accepted_material_refs)")
		incomingMaterialSchemaRequireInt64Argument(t, recorder, "FROM accepted_material_refs ORDER BY accepted_revision LIMIT ?", int64(s.view.limits.AcceptedEventCount)+1)
		incomingMaterialSchemaDetachDecoy(t, s)
		incomingMaterialSchemaRequireNoWrites(t, ctx, s.tx, before)
		s.rollback(t)
		incomingMaterialSchemaRequireRestored(t, ctx, s)
	})

	t.Run("populated valid incoming refs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		s := incomingMaterialSchemaBegin(t, ctx, false)
		require.Len(t, s.floors, 3)
		second := s.floors[1]
		third := s.floors[2]
		require.NotEqual(t, s.floors[0].RecordCID, second.RecordCID)
		require.Equal(t, s.floors[0].RecordCID, third.RecordCID)
		reference := publication.BlobReference{CID: second.BlobCID, Size: second.BlobSize}
		require.NoError(t, publication.VerifyPayload(s.f.payload, reference))
		_, err := publication.DecodePayload(s.f.payload, reference)
		require.NoError(t, err)
		require.Equal(t, second.BlobCID, third.BlobCID)
		incomingMaterialValidCatalog(t, ctx, s.tx, second.BlobCID, second.BlobSize)
		incomingMaterialInsertRef(t, ctx, s.tx, int64(second.Revision), second.RecordCID, second.BlobCID)
		incomingMaterialInsertRef(t, ctx, s.tx, int64(third.Revision), third.RecordCID, third.BlobCID)
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, s.tx, "SELECT COUNT(*) FROM retained_publications"))
		eventCount, refCount := incomingMaterialRequireBoundedCounts(t, ctx, s.tx, s.view.limits.AcceptedEventCount)
		require.Equal(t, int64(3), eventCount)
		require.Equal(t, int64(2), refCount)
		stored := incomingMaterialSchemaIncomingRows(t, ctx, s.tx)
		require.Len(t, stored, 2)
		require.Equal(t, int64(second.Revision), stored[0][0])
		require.Equal(t, second.RecordCID, stored[0][1])
		require.Equal(t, second.BlobCID, stored[0][2])
		require.Equal(t, int64(third.Revision), stored[1][0])
		require.Equal(t, third.RecordCID, stored[1][1])
		require.Equal(t, third.BlobCID, stored[1][2])
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, s.tx)
		before := incomingMaterialSchemaCapture(t, ctx, s.tx)
		incomingMaterialRequireReadState(t, ctx, s.oldGraph, s.tx, StageLoad)
		recorder := &incomingMaterialUpgradeRecorder{source: s.tx}
		incomingMaterialSchemaAttachDecoy(t, ctx, s)
		recorded, err := s.view.readState(ctx, recorder, StageLoad)
		require.NoError(t, err)
		direct := incomingMaterialRequireReadState(t, ctx, s.view, s.tx, StageLoad)
		require.Equal(t, direct, recorded)
		incomingMaterialSchemaRecordedQuery(t, recorder, "(SELECT COUNT(*) FROM accepted_events),(SELECT COUNT(*) FROM accepted_material_refs)")
		incomingMaterialSchemaRequireInt64Argument(t, recorder, "FROM accepted_material_refs ORDER BY accepted_revision LIMIT ?", int64(s.view.limits.AcceptedEventCount)+1)
		for _, revision := range []int64{int64(second.Revision), int64(third.Revision)} {
			incomingMaterialSchemaRequireInt64Argument(t, recorder, "FROM retained_publications WHERE accepted_revision=?", revision)
			incomingMaterialSchemaRequireInt64Argument(t, recorder, "substr(CAST(new_floor AS BLOB),1,65537)", revision)
		}
		recordedRecords := incomingMaterialSchemaRecordedQuery(t, recorder, "typeof(record_key),length(CAST(record_key AS BLOB)),substr(CAST(record_key AS BLOB),1,17)")
		require.Contains(t, recordedRecords.query, "FROM accepted_records WHERE cid=?")
		incomingMaterialSchemaRequireByteArgument(t, recorder, recordedRecords.query, second.RecordCID)
		incomingMaterialSchemaRequireByteArgument(t, recorder, recordedRecords.query, third.RecordCID)
		recordedCatalog := incomingMaterialSchemaRecordedQuery(t, recorder, "typeof(basename),length(CAST(basename AS BLOB)),substr(CAST(basename AS BLOB),1,73)")
		require.Contains(t, recordedCatalog.query, "FROM payload_objects WHERE blob_cid=?")
		incomingMaterialSchemaRequireByteArgument(t, recorder, recordedCatalog.query, second.BlobCID)
		incomingMaterialSchemaDetachDecoy(t, s)
		incomingMaterialSchemaRequireNoWrites(t, ctx, s.tx, before)
		s.rollback(t)
		incomingMaterialSchemaRequireRestored(t, ctx, s)
	})
}

func TestIncomingMaterialPrivateSchema3ReadStateRejectsIncomingJoin(t *testing.T) {
	t.Run("wrong existing accepted record join", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		s := incomingMaterialSchemaBegin(t, ctx, false)
		second := s.floors[1]
		require.NotEqual(t, s.floors[0].RecordCID, second.RecordCID)
		incomingMaterialValidCatalog(t, ctx, s.tx, second.BlobCID, second.BlobSize)
		incomingMaterialInsertRef(t, ctx, s.tx, int64(second.Revision), second.RecordCID, second.BlobCID)
		incomingMaterialRequireReadState(t, ctx, s.view, s.tx, StageLoad)
		_, err := s.tx.ExecContext(ctx, "UPDATE accepted_material_refs SET record_cid=? WHERE accepted_revision=?", s.floors[0].RecordCID, int64(second.Revision))
		require.NoError(t, err)
		require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, s.tx))
		require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, s.tx))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, s.tx, "SELECT COUNT(*) FROM accepted_records WHERE cid=?", s.floors[0].RecordCID))
		eventCount, refCount := incomingMaterialRequireBoundedCounts(t, ctx, s.tx, s.view.limits.AcceptedEventCount)
		require.Equal(t, int64(3), eventCount)
		require.Equal(t, int64(1), refCount)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, s.tx)
		before := incomingMaterialSchemaCapture(t, ctx, s.tx)
		incomingMaterialRequireReadState(t, ctx, s.oldGraph, s.tx, StageLoad)
		incomingMaterialSchemaRequireStagesRejected(t, ctx, s, before)
		s.rollback(t)
		incomingMaterialSchemaRequireRestored(t, ctx, s)
	})

	t.Run("retained and incoming revision overlap", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		s := incomingMaterialSchemaBegin(t, ctx, true)
		require.NotNil(t, s.finalized)
		revision := int64(s.finalized.Floor.Revision)
		require.Equal(t, int64(1), revision)
		incomingMaterialRequireReadState(t, ctx, s.view, s.tx, StageLoad)
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, s.tx, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=?", revision))
		incomingMaterialInsertRef(t, ctx, s.tx, revision, s.finalized.Floor.RecordCID, s.finalized.Floor.BlobCID)
		require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, s.tx))
		eventCount, refCount := incomingMaterialRequireBoundedCounts(t, ctx, s.tx, s.view.limits.AcceptedEventCount)
		require.Equal(t, int64(1), eventCount)
		require.Equal(t, int64(1), refCount)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, s.tx)
		before := incomingMaterialSchemaCapture(t, ctx, s.tx)
		incomingMaterialRequireReadState(t, ctx, s.oldGraph, s.tx, StageLoad)
		incomingMaterialSchemaRequireStagesRejected(t, ctx, s, before)
		s.rollback(t)
		incomingMaterialSchemaRequireRestored(t, ctx, s)
	})
}

func incomingMaterialSchemaBegin(t *testing.T, ctx context.Context, populated bool) *incomingMaterialSchemaState {
	t.Helper()
	state := &incomingMaterialSchemaState{}
	if populated {
		populatedFixture, populatedStore, _, finalized := incomingMaterialUpgradePopulatedSource(t, ctx)
		state.f, state.store, state.finalized = populatedFixture, populatedStore, &finalized
	} else {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		f.appendRecord(t, 1)
		store, _ := newSchema2UnitStore(t, f)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		state.f, state.store = f, store
		first, second, third := incomingMaterialHistoricalLifecycle(t, store, f)
		state.floors = []Floor{first, second, third}
	}
	require.Equal(t, 2, state.store.schemaVersion)
	require.False(t, state.store.closed)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, state.store.conn))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, state.store.conn))
	source, err := readIncomingMaterialUpgradeSource(ctx, state.store.conn, 2, state.f.binding, DefaultLimits(), DefaultAttemptLimits())
	require.NoError(t, err)
	state.source = source
	state.rows, err = sharedCustodyLogicalRows(ctx, state.store.conn)
	require.NoError(t, err)
	require.Len(t, state.rows, 15)
	state.objects = incomingMaterialUpgradeFixtureObjects(t, ctx, state.store.conn)
	require.Len(t, state.objects, 31)
	state.metadata = incomingMaterialUpgradeStoredMetadata(t, ctx, state.store.conn)
	require.Len(t, state.metadata, 7)

	tx, err := state.store.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	state.tx = tx
	t.Cleanup(func() {
		if state.rolledBack {
			return
		}
		state.rolledBack = true
		assert.NoError(t, state.tx.Rollback())
	})
	var points []int
	require.NoError(t, migrateIncomingMaterialTx(ctx, tx, source, func(point int) error {
		points = append(points, point)
		return nil
	}))
	require.Equal(t, []int{13, 14, 15}, points)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, tx))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	destinationMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, tx)
	require.Len(t, destinationMetadata, 7)
	for _, key := range []string{"binding", "database_id", "generation", "limits", "revision", "attempt_limits", "attempt_mutation_revision"} {
		require.Equal(t, state.metadata[key], destinationMetadata[key], key)
	}
	require.Len(t, destinationMetadata["database_id"], 32)
	require.False(t, allZero(destinationMetadata["database_id"]))
	require.Len(t, destinationMetadata["attempt_mutation_revision"], 8)
	var databaseID [32]byte
	copy(databaseID[:], destinationMetadata["database_id"])
	state.view = &Store{binding: state.f.binding, limits: DefaultLimits(), attemptLimits: DefaultAttemptLimits(), databaseID: databaseID, schemaVersion: 3, rootFD: -1, payloadFD: -1}
	state.view.attemptMutationRevision = binary.BigEndian.Uint64(destinationMetadata["attempt_mutation_revision"])
	state.oldGraph = &Store{binding: state.f.binding, limits: DefaultLimits(), attemptLimits: DefaultAttemptLimits(), databaseID: databaseID, schemaVersion: 2}
	state.oldGraph.attemptMutationRevision = state.view.attemptMutationRevision
	return state
}

func (s *incomingMaterialSchemaState) rollback(t *testing.T) {
	t.Helper()
	if s.rolledBack {
		return
	}
	s.rolledBack = true
	require.NoError(t, s.tx.Rollback())
}

func incomingMaterialSchemaCapture(t *testing.T, ctx context.Context, q queryer) incomingMaterialSchemaSnapshot {
	t.Helper()
	rows, err := sharedCustodyLogicalRows(ctx, q)
	require.NoError(t, err)
	require.Len(t, rows, 15)
	return incomingMaterialSchemaSnapshot{
		rows:     rows,
		incoming: incomingMaterialSchemaIncomingRows(t, ctx, q),
		metadata: incomingMaterialUpgradeStoredMetadata(t, ctx, q),
		objects:  incomingMaterialUpgradeFixtureObjects(t, ctx, q),
	}
}

func incomingMaterialSchemaIncomingRows(t *testing.T, ctx context.Context, q queryer) [][]any {
	t.Helper()
	rows, err := q.QueryContext(ctx, "SELECT accepted_revision,record_cid,blob_cid FROM accepted_material_refs ORDER BY accepted_revision")
	require.NoError(t, err)
	result := make([][]any, 0, 2)
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

func incomingMaterialSchemaRequireNoWrites(t *testing.T, ctx context.Context, q queryer, before incomingMaterialSchemaSnapshot) {
	t.Helper()
	after := incomingMaterialSchemaCapture(t, ctx, q)
	require.Equal(t, before.rows, after.rows)
	require.Equal(t, before.incoming, after.incoming)
	require.Equal(t, before.metadata, after.metadata)
	require.Equal(t, before.objects, after.objects)
}

func incomingMaterialSchemaRequireStagesRejected(t *testing.T, ctx context.Context, s *incomingMaterialSchemaState, before incomingMaterialSchemaSnapshot) {
	t.Helper()
	for _, stage := range []Stage{StageLoad, StageHistory, StagePrepare} {
		recorder := &incomingMaterialUpgradeRecorder{source: s.tx}
		state, err := s.view.readState(ctx, recorder, stage)
		requireErrorMetadata(t, err, ErrSchema, stage, ReasonCorrupt)
		require.Equal(t, stateSnapshot{}, state)
		incomingMaterialSchemaRecordedQuery(t, recorder, "(SELECT COUNT(*) FROM accepted_events),(SELECT COUNT(*) FROM accepted_material_refs)")
		incomingMaterialSchemaRequireInt64Argument(t, recorder, "FROM accepted_material_refs ORDER BY accepted_revision LIMIT ?", int64(s.view.limits.AcceptedEventCount)+1)
	}
	incomingMaterialSchemaRequireNoWrites(t, ctx, s.tx, before)
}

func incomingMaterialSchemaRequireRestored(t *testing.T, ctx context.Context, s *incomingMaterialSchemaState) {
	t.Helper()
	require.Equal(t, 2, s.store.schemaVersion)
	require.False(t, s.store.closed)
	require.Equal(t, 2, incomingMaterialUpgradeUserVersion(t, ctx, s.store.conn))
	require.Zero(t, incomingMaterialUpgradeIncomingTableRows(t, ctx, s.store.conn))
	require.Equal(t, s.metadata, incomingMaterialUpgradeStoredMetadata(t, ctx, s.store.conn))
	require.Equal(t, s.objects, incomingMaterialUpgradeFixtureObjects(t, ctx, s.store.conn))
	rows, err := sharedCustodyLogicalRows(ctx, s.store.conn)
	require.NoError(t, err)
	require.Equal(t, s.rows, rows)
	restored, err := readIncomingMaterialUpgradeSource(ctx, s.store.conn, 2, s.f.binding, DefaultLimits(), DefaultAttemptLimits())
	require.NoError(t, err)
	require.Equal(t, s.source, restored)
}

func incomingMaterialSchemaAttachDecoy(t *testing.T, ctx context.Context, s *incomingMaterialSchemaState) {
	t.Helper()
	pool, err := sql.Open("sqlite", dbDSN(filepath.Join(t.TempDir(), "decoy.db"), false))
	require.NoError(t, err)
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() { assert.NoError(t, pool.Close()) })
	conn, err := pool.Conn(ctx)
	require.NoError(t, err)
	closed := false
	t.Cleanup(func() {
		if closed {
			return
		}
		closed = true
		assert.NoError(t, conn.Close())
	})
	require.NotSame(t, s.store.conn, conn)
	require.NoError(t, conn.Close())
	closed = true
	require.NoError(t, pool.Close())
	require.ErrorIs(t, conn.PingContext(ctx), sql.ErrConnDone)
	t.Cleanup(func() { s.view.conn = s.store.conn })
	s.view.conn = conn
}

func incomingMaterialSchemaDetachDecoy(t *testing.T, s *incomingMaterialSchemaState) {
	t.Helper()
	require.NotNil(t, s.view)
	s.view.conn = s.store.conn
}

func incomingMaterialSchemaRecordedQuery(t *testing.T, recorder *incomingMaterialUpgradeRecorder, fragment string) incomingMaterialUpgradeRecordedQuery {
	t.Helper()
	for _, recorded := range recorder.queries {
		if strings.Contains(recorded.query, fragment) {
			return recorded
		}
	}
	require.FailNowf(t, "missing recorded query", "%q not observed", fragment)
	return incomingMaterialUpgradeRecordedQuery{}
}

func incomingMaterialSchemaRequireInt64Argument(t *testing.T, recorder *incomingMaterialUpgradeRecorder, fragment string, wanted int64) {
	t.Helper()
	for _, recorded := range recorder.queries {
		if !strings.Contains(recorded.query, fragment) {
			continue
		}
		for _, arg := range recorded.args {
			if value, ok := arg.(int64); ok && value == wanted {
				return
			}
		}
	}
	require.FailNowf(t, "missing recorded argument", "%d not observed for %q", wanted, fragment)
}

func incomingMaterialSchemaRequireByteArgument(t *testing.T, recorder *incomingMaterialUpgradeRecorder, query string, wanted []byte) {
	t.Helper()
	for _, recorded := range recorder.queries {
		if recorded.query != query {
			continue
		}
		for _, arg := range recorded.args {
			if data, ok := arg.([]byte); ok && bytes.Equal(data, wanted) {
				return
			}
		}
	}
	require.FailNowf(t, "missing recorded argument", "%x not observed for %q", wanted, query)
}

func TestIncomingMaterialPublicSchema3Smoke(t *testing.T) {
	t.Run("absent default and ordinary reopen", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "absent")
		require.False(t, input.options.UpgradeFromPositions)
		require.False(t, input.options.UpgradeFromAttempts)
		recorder := newPublicationOpenRecorder()
		fd0 := publicationOpenFD0(t)
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 104, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireFD0(t, fd0)
		metadata := publicationOpenRequireSchema3(t, ctx, store, input)
		require.Len(t, metadata, 7)
		require.Equal(t, uint64Bytes(0), metadata["revision"])
		require.Equal(t, uint64Bytes(0), metadata["generation"])
		require.Equal(t, uint64Bytes(0), metadata["attempt_mutation_revision"])
		databaseID := metadata["database_id"]
		require.Len(t, databaseID, 32)
		require.False(t, allZero(databaseID))
		publicationOpenRequireEmptyState(t, ctx, store)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireEmptyDestination(t, destination)
		publicationOpenRequireClosedResources(t, store, input.directory)
		publicationOpenRequireFD0(t, fd0)
		reopenedFD0 := publicationOpenFD0(t)
		reopened, err := Open(input.directory, input.binding)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		require.NotNil(t, reopened)
		publicationOpenRequireFD0(t, reopenedFD0)
		require.Equal(t, 3, reopened.schemaVersion)
		require.Equal(t, databaseID, reopened.databaseID[:])
		require.Equal(t, metadata, publicationOpenRequireSchema3(t, ctx, reopened, input))
		publicationOpenRequireEmptyState(t, ctx, reopened)
		reopenedDestination := publicationOpenCaptureDestination(t, ctx, reopened)
		publicationOpenRequireEmptyDestination(t, reopenedDestination)
		require.Equal(t, destination, reopenedDestination)
		publicationOpenRequireClosedResources(t, reopened, input.directory)
		publicationOpenRequireFD0(t, reopenedFD0)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
	})

	t.Run("genuine1 neither refuses", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
		source := attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows)
		options := DefaultOpenOptions()
		require.False(t, options.UpgradeFromPositions)
		require.False(t, options.UpgradeFromAttempts)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("public schema three smoke genuine one neither canary")
		fd0 := publicationOpenFD0(t)
		store, err := OpenWithOptions(filepath.Dir(databasePath), f.binding, recorder.options(options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonUpgradeRequired)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, filepath.Dir(databasePath), true)
		require.Equal(t, source, attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows))
	})

	t.Run("genuine1 position permission alone refuses", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
		source := attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows)
		options := DefaultOpenOptions()
		options.UpgradeFromPositions = true
		require.True(t, options.UpgradeFromPositions)
		require.False(t, options.UpgradeFromAttempts)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("public schema three smoke genuine one position only canary")
		fd0 := publicationOpenFD0(t)
		store, err := OpenWithOptions(filepath.Dir(databasePath), f.binding, recorder.options(options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonUpgradeRequired)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, filepath.Dir(databasePath), true)
		require.Equal(t, source, attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows))
	})

	t.Run("genuine1 both direct upgrade and reopen", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		t.Cleanup(cancel)
		f, databasePath, companionRows := incomingMaterialUpgradeCopyV1(t)
		directory := filepath.Dir(databasePath)
		source := attemptSchemaFixtureSnapshotV1(t, ctx, f, databasePath, companionRows)
		options := DefaultOpenOptions()
		options.UpgradeFromPositions = true
		options.UpgradeFromAttempts = true
		require.True(t, options.UpgradeFromPositions)
		require.True(t, options.UpgradeFromAttempts)
		recorder := newPublicationOpenRecorder()
		fd0 := publicationOpenFD0(t)
		store, err := OpenWithOptions(directory, f.binding, recorder.options(options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, recorder.upgrade)
		require.Equal(t, 1, recorder.commits)
		require.Len(t, recorder.commitResults, 1)
		require.NoError(t, recorder.commitResults[0])
		require.Equal(t, []publicationOpenEvent{
			{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
			{stream: "migrate", point: 1}, {stream: "migrate", point: 2}, {stream: "migrate", point: 3}, {stream: "migrate", point: 4},
			{stream: "migrate", point: 5}, {stream: "migrate", point: 6}, {stream: "migrate", point: 7}, {stream: "migrate", point: 8},
			{stream: "migrate", point: 9}, {stream: "migrate", point: 10}, {stream: "migrate", point: 11}, {stream: "migrate", point: 12},
			{stream: "migrate", point: 13}, {stream: "migrate", point: 14}, {stream: "migrate", point: 15}, {stream: "migrate", point: 16},
			{stream: "commit", point: 0},
			{stream: "open", point: 1}, {stream: "open", point: 2}, {stream: "open", point: 3}, {stream: "open", point: 4},
		}, recorder.events)
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireFD0(t, fd0)
		attemptSchemaRequireCurrent3(t, ctx, store, f, source)
		publicationOpenRequireClosedResources(t, store, directory)
		publicationOpenRequireFD0(t, fd0)
		reopenedFD0 := publicationOpenFD0(t)
		reopened, err := Open(directory, f.binding)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		publicationOpenRequireFD0(t, reopenedFD0)
		attemptSchemaRequireCurrent3(t, ctx, reopened, f, source)
		publicationOpenRequireClosedResources(t, reopened, directory)
		publicationOpenRequireFD0(t, reopenedFD0)
		publicationOpenRequireFD0(t, fd0)
		require.Equal(t, source.payload, attemptSchemaCompanionPayload(t, directory))
	})

	t.Run("genuine2 pending without A refuses", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "pending-genesis")
		require.False(t, input.options.UpgradeFromPositions)
		require.False(t, input.options.UpgradeFromAttempts)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 2)
		require.Len(t, before.metadata, 7)
		require.Len(t, before.typed, 15)
		require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(before.typed))
		payload := publicationOpenCapturePayload(t, input)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("public schema three smoke pending genesis canary")
		fd0 := publicationOpenFD0(t)
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonUpgradeRequired)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
		publicationOpenRequirePayloadPreserved(t, input, payload)
	})

	t.Run("genuine2 pending A upgrade and reopen", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "pending-genesis")
		before := publicationOpenSnapshotSource(t, ctx, input.database, 2)
		payload := publicationOpenCapturePayload(t, input)
		wantedDatabaseID := []byte("\x61\xe4\x38\xc8\x7e\x51\x65\xa7\x21\x8e\x18\xa9\xaa\xad\x2c\x65\x1f\x0d\x3a\x09\x5a\xdc\x90\xac\xc5\x85\x8a\x89\x73\x52\x2c\x17")
		require.Equal(t, wantedDatabaseID, before.metadata["database_id"])
		require.Equal(t, uint64Bytes(0), before.metadata["revision"])
		require.Equal(t, uint64Bytes(0), before.metadata["generation"])
		require.Equal(t, uint64Bytes(1), before.metadata["attempt_mutation_revision"])
		attemptID := [16]byte{0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17}
		options := input.options
		options.UpgradeFromAttempts = true
		require.False(t, options.UpgradeFromPositions)
		require.True(t, options.UpgradeFromAttempts)
		recorder := newPublicationOpenRecorder()
		fd0 := publicationOpenFD0(t)
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Equal(t, []int{13, 14, 15, 16}, recorder.upgrade)
		require.Equal(t, 1, recorder.commits)
		require.Len(t, recorder.commitResults, 1)
		require.NoError(t, recorder.commitResults[0])
		require.Equal(t, []publicationOpenEvent{
			{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
			{stream: "migrate", point: 13}, {stream: "migrate", point: 14}, {stream: "migrate", point: 15}, {stream: "migrate", point: 16},
			{stream: "commit", point: 0},
			{stream: "open", point: 1}, {stream: "open", point: 2}, {stream: "open", point: 3}, {stream: "open", point: 4},
		}, recorder.events)
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireFD0(t, fd0)
		metadata := publicationOpenRequireSchema3(t, ctx, store, input)
		require.Equal(t, before.metadata, metadata)
		require.Equal(t, wantedDatabaseID, store.databaseID[:])
		publicationOpenRequirePendingState(t, ctx, store, before)
		loadedAttempt, err := store.LoadAttempt(ctx, attemptID)
		require.NoError(t, err)
		require.Equal(t, attemptID, loadedAttempt.ID)
		require.Equal(t, AttemptGenesis, loadedAttempt.Kind)
		require.Equal(t, AttemptPrepared, loadedAttempt.Lifecycle)
		require.Equal(t, OutcomeNotSubmitted, loadedAttempt.Outcome)
		activeAttempt, present, err := store.ActiveAttempt(ctx)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, attemptID, activeAttempt.ID)
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM pending_genesis"))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs"))
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_reservations"))
		accepted, err := store.ReadAcceptedMaterial(ctx, input.binding, zeroFloor())
		requireErrorMetadata(t, err, ErrContinuity, StageReadAcceptedMaterial, ReasonFirstUseRequired)
		require.Equal(t, AcceptedMaterial{}, accepted)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		require.Equal(t, before.metadata, destination.metadata)
		require.Equal(t, before.typed, destination.typed)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireClosedResources(t, store, input.directory)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		reopenedFD0 := publicationOpenFD0(t)
		reopened, err := Open(input.directory, input.binding)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		require.NotNil(t, reopened)
		publicationOpenRequireFD0(t, reopenedFD0)
		require.Equal(t, 3, reopened.schemaVersion)
		require.Equal(t, wantedDatabaseID, reopened.databaseID[:])
		require.Equal(t, before.metadata, publicationOpenRequireSchema3(t, ctx, reopened, input))
		publicationOpenRequirePendingState(t, ctx, reopened, before)
		reopenedAttempt, err := reopened.LoadAttempt(ctx, attemptID)
		require.NoError(t, err)
		require.Equal(t, attemptID, reopenedAttempt.ID)
		require.Equal(t, AttemptGenesis, reopenedAttempt.Kind)
		require.Equal(t, loadedAttempt.StateDigest, reopenedAttempt.StateDigest)
		require.Equal(t, AttemptPrepared, reopenedAttempt.Lifecycle)
		require.Equal(t, OutcomeNotSubmitted, reopenedAttempt.Outcome)
		publicationOpenRequireClosedResources(t, reopened, input.directory)
		publicationOpenRequireFD0(t, reopenedFD0)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
		publicationOpenRequirePayloadPreserved(t, input, payload)
	})

	t.Run("current3 permissions do not migrate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "absent")
		directory := input.directory
		require.NoError(t, validateBinding(input.binding))
		require.NoError(t, validateLimits(DefaultLimits()))
		require.NoError(t, checkPrivateDirectory(directory))
		setupFD0 := publicationOpenFD0(t)
		store, err := Open(directory, input.binding)
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.NotNil(t, store)
		publicationOpenRequireFD0(t, setupFD0)
		require.Equal(t, 3, store.schemaVersion)
		createdMetadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
		require.Len(t, createdMetadata, 7)
		databaseID := createdMetadata["database_id"]
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireEmptyDestination(t, destination)
		publicationOpenRequireClosedResources(t, store, directory)
		publicationOpenRequireFD0(t, setupFD0)
		options := DefaultOpenOptions()
		options.UpgradeFromPositions = true
		options.UpgradeFromAttempts = true
		recorder := newPublicationOpenRecorder()
		fd0 := publicationOpenFD0(t)
		reopened, err := OpenWithOptions(directory, input.binding, recorder.options(options))
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, reopened)
		publicationOpenRequireFD0(t, fd0)
		require.Equal(t, 3, reopened.schemaVersion)
		require.Equal(t, databaseID, reopened.databaseID[:])
		require.Equal(t, createdMetadata, incomingMaterialUpgradeStoredMetadata(t, ctx, reopened.conn))
		publicationOpenRequireSchema3(t, ctx, reopened, input)
		publicationOpenRequireEmptyState(t, ctx, reopened)
		reopenedDestination := publicationOpenCaptureDestination(t, ctx, reopened)
		publicationOpenRequireEmptyDestination(t, reopenedDestination)
		require.Equal(t, destination, reopenedDestination)
		publicationOpenRequireClosedResources(t, reopened, directory)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireFD0(t, setupFD0)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
	})
}

func TestIncomingMaterialPublicOpenFlagMatrix(t *testing.T) {
	permissions := []struct {
		name      string
		positions bool
		attempts  bool
	}{
		{name: "neither", positions: false, attempts: false},
		{name: "P-only", positions: true, attempts: false},
		{name: "A-only", positions: false, attempts: true},
		{name: "both", positions: true, attempts: true},
	}
	require.Len(t, permissions, 4)
	shapes := []struct {
		name          string
		sourceVersion int
		rowCount      int
		payloadCount  int
		success       [4]bool
	}{
		{name: "absent", sourceVersion: 0, success: [4]bool{true, true, true, true}},
		{name: "empty", sourceVersion: 0, success: [4]bool{true, true, true, true}},
		{name: "positions-v1", sourceVersion: 1, rowCount: 14, payloadCount: 1, success: [4]bool{false, false, false, true}},
		{name: "pending-genesis", sourceVersion: 2, rowCount: 14, payloadCount: 1, success: [4]bool{false, false, true, true}},
		{name: "mixed", sourceVersion: 2, rowCount: 44, payloadCount: 3, success: [4]bool{false, false, true, true}},
		{name: "current3", sourceVersion: 3, rowCount: 7, success: [4]bool{true, true, true, true}},
	}
	for _, shape := range shapes {
		for permissionIndex, permission := range permissions {
			t.Run(shape.name+" "+permission.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				t.Cleanup(cancel)
				var input publicationOpenInput
				payloads := make(map[string]incomingMaterialUpgradeFixturePayload)
				switch shape.name {
				case "absent", "empty", "positions-v1":
					input = publicationOpenInputFor(t, shape.name)
				case "pending-genesis", "mixed":
					assets := incomingMaterialUpgradeFixtureCopy(t)
					image := assets.manifest.requireImage(t, shape.name)
					require.Equal(t, 2, image.SchemaVersion)
					require.Len(t, image.Payloads, shape.payloadCount)
					binding, limits, attemptLimits := incomingMaterialUpgradeFixtureBindingOptions(t, image)
					options := DefaultOpenOptions()
					options.PositionLimits = limits
					options.AttemptLimits = attemptLimits
					directory := filepath.Join(assets.root, shape.name)
					input = publicationOpenInput{shape: shape.name, directory: directory, database: filepath.Join(directory, "publication.db"), binding: binding, options: options}
					for _, entry := range image.Payloads {
						require.True(t, strings.HasPrefix(entry.Path, shape.name+"/payloads/"))
						path := filepath.Join(assets.root, entry.Path)
						require.NotContains(t, payloads, path)
						payload := incomingMaterialUpgradeFixturePayloadState(t, path)
						require.Equal(t, entry.Length, payload.size)
						require.Equal(t, entry.SHA256, payload.sha256)
						require.Len(t, payload.bytes, int(entry.Length))
						payloads[path] = payload
					}
				case "current3":
					input = publicationOpenInputFor(t, "absent")
				default:
					require.FailNow(t, "unexpected flag-matrix input")
					return
				}
				require.NoError(t, validateBinding(input.binding))
				require.NoError(t, validateLimits(input.options.PositionLimits))
				require.NoError(t, validateAttemptLimits(input.options.AttemptLimits))
				require.Equal(t, DefaultLimits(), input.options.PositionLimits)
				require.Equal(t, DefaultAttemptLimits(), input.options.AttemptLimits)
				if shape.sourceVersion == 1 {
					require.True(t, input.options.UpgradeFromPositions)
					require.True(t, input.options.UpgradeFromAttempts)
					payloads[input.payloadPath] = publicationOpenCapturePayload(t, input)
				} else {
					require.False(t, input.options.UpgradeFromPositions)
					require.False(t, input.options.UpgradeFromAttempts)
				}
				require.Nil(t, input.options.upgradeFault)
				require.Nil(t, input.options.upgradeCommit)
				require.Nil(t, input.options.openFault)
				require.Nil(t, input.options.createdDatabaseChmod)
				require.Len(t, payloads, shape.payloadCount)
				require.NoError(t, checkPrivateDirectory(input.directory))
				directoryInfo, err := os.Lstat(input.directory)
				require.NoError(t, err)
				require.True(t, directoryInfo.IsDir())
				require.Equal(t, os.FileMode(0o700), directoryInfo.Mode().Perm())
				switch shape.name {
				case "absent", "current3":
					_, err := os.Lstat(input.database)
					require.ErrorIs(t, err, os.ErrNotExist)
				case "empty":
					info, err := os.Lstat(input.database)
					require.NoError(t, err)
					require.True(t, info.Mode().IsRegular())
					require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
					require.Zero(t, info.Size())
				}
				var before publicationOpenSourceSnapshot
				if shape.sourceVersion == 3 {
					setupFD0 := publicationOpenFD0(t)
					setup, err := Open(input.directory, input.binding)
					if setup != nil {
						t.Cleanup(func() { assert.NoError(t, setup.Close()) })
					}
					require.NoError(t, err)
					publicationOpenRequireFD0(t, setupFD0)
					publicationOpenRequireSchema3(t, ctx, setup, input)
					before = publicationOpenCaptureDestination(t, ctx, setup)
					publicationOpenRequireEmptyDestination(t, before)
					publicationOpenRequireClosedResources(t, setup, input.directory)
					publicationOpenRequireFD0(t, setupFD0)
				}
				if shape.sourceVersion != 0 {
					observed := publicationOpenSnapshotSource(t, ctx, input.database, shape.sourceVersion)
					if shape.sourceVersion == 3 {
						require.Equal(t, before, observed)
					}
					before = observed
					require.Equal(t, shape.sourceVersion, before.version)
					if shape.sourceVersion == 1 {
						require.Len(t, before.metadata, 5)
						require.Len(t, before.typed, 6)
					} else {
						require.Len(t, before.metadata, 7)
						require.Len(t, before.typed, 15)
					}
					require.Equal(t, shape.rowCount, incomingMaterialUpgradeFixtureRowTotal(before.typed))
					if shape.sourceVersion == 3 {
						require.Equal(t, int64(1), before.incomingTableCount)
					} else {
						require.Zero(t, before.incomingTableCount)
					}
					require.Zero(t, before.incomingRefCount)
					probe, err := probeSchema(input.database, input.binding, input.options.PositionLimits, input.options.AttemptLimits)
					require.NoError(t, err)
					require.True(t, probe.recognized)
					require.False(t, probe.initial)
					require.Equal(t, shape.sourceVersion, probe.version)
				}
				options := input.options
				options.UpgradeFromPositions = permission.positions
				options.UpgradeFromAttempts = permission.attempts
				require.Equal(t, permission.positions, options.UpgradeFromPositions)
				require.Equal(t, permission.attempts, options.UpgradeFromAttempts)
				recorder := newPublicationOpenRecorder()
				recorder.canary = errors.New("incoming material flag matrix unused canary")
				fd0 := publicationOpenFD0(t)
				store, err := OpenWithOptions(input.directory, input.binding, recorder.options(options))
				if store != nil {
					t.Cleanup(func() { assert.NoError(t, store.Close()) })
				}
				if !shape.success[permissionIndex] {
					state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonUpgradeRequired)
					publicationOpenRequireRefusalIdentities(t, recorder, state, false)
					publicationOpenRequireFD0(t, fd0)
					for _, event := range recorder.events {
						require.Equal(t, "open", event.stream)
					}
					publicationOpenRequireLockWitness(t, input.directory, true)
					publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
					incomingMaterialFlagMatrixRequirePayloads(t, payloads)
					return
				}
				require.NoError(t, err)
				incomingMaterialFlagMatrixRequireTrace(t, recorder, shape.name, shape.sourceVersion)
				publicationOpenRequireAcquisitionIdentities(t, recorder, store)
				publicationOpenRequireFD0(t, fd0)
				destination := incomingMaterialFlagMatrixRequireDestination(t, ctx, store, input, before)
				incomingMaterialFlagMatrixRequirePayloads(t, payloads)
				publicationOpenRequireClosedResources(t, store, input.directory)
				publicationOpenRequireFD0(t, fd0)
				incomingMaterialFlagMatrixRequirePayloads(t, payloads)
				reopenedFD0 := publicationOpenFD0(t)
				reopened, err := Open(input.directory, input.binding)
				if reopened != nil {
					t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
				}
				require.NoError(t, err)
				require.NotNil(t, reopened)
				publicationOpenRequireFD0(t, reopenedFD0)
				require.Equal(t, destination.metadata, publicationOpenRequireSchema3(t, ctx, reopened, input))
				require.Equal(t, destination.metadata["database_id"], reopened.databaseID[:])
				require.Equal(t, destination, publicationOpenCaptureDestination(t, ctx, reopened))
				publicationOpenRequireClosedResources(t, reopened, input.directory)
				publicationOpenRequireFD0(t, reopenedFD0)
				publicationOpenRequireFD0(t, fd0)
				publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
				incomingMaterialFlagMatrixRequirePayloads(t, payloads)
			})
		}
	}
}

func incomingMaterialFlagMatrixRequireTrace(t *testing.T, recorder *publicationOpenRecorder, shape string, sourceVersion int) {
	t.Helper()
	openPoints := []int{101, 102, 103, 1, 2, 3, 4}
	if shape == "absent" {
		openPoints = []int{101, 102, 103, 1, 104, 2, 3, 4}
	}
	require.Equal(t, openPoints, recorder.openPoints())
	var migrationPoints []int
	switch sourceVersion {
	case 1:
		migrationPoints = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	case 2:
		migrationPoints = []int{13, 14, 15, 16}
	default:
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		return
	}
	require.Equal(t, migrationPoints, recorder.upgrade)
	require.Equal(t, 1, recorder.commits)
	require.Len(t, recorder.commitResults, 1)
	require.NoError(t, recorder.commitResults[0])
	expected := []publicationOpenEvent{
		{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
	}
	for _, point := range migrationPoints {
		expected = append(expected, publicationOpenEvent{stream: "migrate", point: point})
	}
	expected = append(expected,
		publicationOpenEvent{stream: "commit", point: 0},
		publicationOpenEvent{stream: "open", point: 1}, publicationOpenEvent{stream: "open", point: 2},
		publicationOpenEvent{stream: "open", point: 3}, publicationOpenEvent{stream: "open", point: 4},
	)
	require.Equal(t, expected, recorder.events)
}

func incomingMaterialFlagMatrixRequireDestination(t *testing.T, ctx context.Context, store *Store, input publicationOpenInput, before publicationOpenSourceSnapshot) publicationOpenSourceSnapshot {
	t.Helper()
	publicationOpenRequireSchema3(t, ctx, store, input)
	destination := publicationOpenCaptureDestination(t, ctx, store)
	require.Len(t, destination.metadata, 7)
	require.Len(t, destination.typed, 15)
	switch before.version {
	case 0:
		publicationOpenRequireEmptyDestination(t, destination)
	case 1:
		for key, value := range before.metadata {
			require.Contains(t, destination.metadata, key)
			require.Equal(t, value, destination.metadata[key], key)
		}
		attemptLimits, err := encodeAttemptLimits(input.options.AttemptLimits)
		require.NoError(t, err)
		require.Equal(t, attemptLimits, destination.metadata["attempt_limits"])
		require.Equal(t, uint64Bytes(0), destination.metadata["attempt_mutation_revision"])
		for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
			require.Contains(t, before.typed, table)
			require.Contains(t, destination.typed, table)
			require.Equal(t, before.typed[table], destination.typed[table], table)
		}
		for _, table := range incomingMaterialUpgradeFixtureAttemptTables {
			require.Contains(t, destination.typed, table)
			require.Empty(t, destination.typed[table], table)
		}
		source := incomingMaterialUpgradeSource{version: 1, binding: input.binding, limits: input.options.PositionLimits, attemptLimits: input.options.AttemptLimits, metadata: before.metadata}
		require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, store.conn, source))
	case 2:
		require.Equal(t, before.metadata, destination.metadata)
		require.Equal(t, before.typed, destination.typed)
	case 3:
		publicationOpenRequireEmptyDestination(t, destination)
		require.Equal(t, before, destination)
	default:
		require.FailNow(t, "unexpected flag-matrix source version")
	}
	return destination
}

func incomingMaterialFlagMatrixRequirePayloads(t *testing.T, before map[string]incomingMaterialUpgradeFixturePayload) {
	t.Helper()
	for path, expected := range before {
		require.Equal(t, expected, incomingMaterialUpgradeFixturePayloadState(t, path), path)
	}
}

type incomingMaterialPublicFixtureReadback struct {
	floor           Floor
	floorPresent    bool
	history         HistoryPage
	attempts        AttemptPage
	active          Attempt
	activePresent   bool
	loaded          map[[16]byte]Attempt
	candidates      map[[16]byte]CandidateMaterial
	conflicts       map[[16]byte]FirstConflictEvidence
	conflictPresent map[[16]byte]bool
}

func TestIncomingMaterialPublicUpgradeGenuineFixtures(t *testing.T) {
	for _, test := range []struct {
		image      string
		version    int
		rowCount   int
		revision   uint64
		generation uint64
		mutation   uint64
		sequence   uint64
		databaseID string
	}{
		{image: "positions-v1", version: 1, rowCount: 14, revision: 2, generation: 1, mutation: 0, sequence: 1},
		{image: "pending-genesis", version: 2, rowCount: 14, revision: 0, generation: 0, mutation: 1, databaseID: "61e438c87e5165a7218e18a9aaad2c651f0d3a095adc90acc5858a8973522c17"},
		{image: "mixed", version: 2, rowCount: 44, revision: 2, generation: 2, mutation: 17, sequence: 0, databaseID: "96e9eaf5938c944476328415ab4c139ed8831f1fb129165ce50c5678c55de857"},
	} {
		t.Run(test.image, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, test.image)
			require.NotNil(t, c)
			require.NotNil(t, c.owner)
			require.False(t, c.owner.closed)
			require.False(t, c.owner.sqlClosed)
			require.Equal(t, test.version, c.version)
			incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, c.owner.conn, c)
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			require.Equal(t, test.rowCount, incomingMaterialUpgradeFixtureRowTotal(c.rows))
			require.Equal(t, DefaultLimits(), c.limits)
			require.Equal(t, DefaultAttemptLimits(), c.attemptLimits)
			require.Len(t, c.metadata["database_id"], 32)
			require.False(t, allZero(c.metadata["database_id"]))
			require.Equal(t, uint64Bytes(test.revision), c.metadata["revision"])
			require.Equal(t, uint64Bytes(test.generation), c.metadata["generation"])
			var databaseID [32]byte
			copy(databaseID[:], c.metadata["database_id"])
			if c.version == 1 {
				require.Len(t, c.metadata, 5)
				require.Len(t, c.rows, 6)
				require.Equal(t, int64(3072), c.payload.size)
				require.Equal(t, incomingMaterialUpgradeFixtureHashes["schema1-baseline-payload.bin"], c.payload.sha256)
			} else {
				require.Len(t, c.metadata, 7)
				require.Len(t, c.rows, 15)
				require.Equal(t, incomingMaterialUpgradeFixtureHex(t, test.databaseID), databaseID[:])
				require.Len(t, c.metadata["attempt_mutation_revision"], 8)
				require.Equal(t, test.mutation, binary.BigEndian.Uint64(c.metadata["attempt_mutation_revision"]))
				for _, table := range []string{"active_publication_attempt", "attempt_payload_refs", "attempt_reservations"} {
					require.Contains(t, c.rows, table)
					require.Len(t, c.rows[table], 1, table)
				}
				if test.image == "pending-genesis" {
					require.Len(t, c.rows["publication_attempts"], 1)
					require.Len(t, c.rows["pending_genesis"], 1)
					require.Len(t, c.rows["payload_objects"], 1)
				} else {
					require.Len(t, c.rows["publication_attempts"], 3)
					require.Len(t, c.rows["attempt_events"], 15)
					require.Len(t, c.rows["attempt_evidence"], 5)
					require.Len(t, c.rows["payload_objects"], 3)
				}
			}
			var source incomingMaterialPublicFixtureReadback
			{
				view := &Store{conn: c.owner.conn, binding: c.binding, limits: c.limits, attemptLimits: c.attemptLimits, databaseID: databaseID, schemaVersion: c.version, rootFD: -1, payloadFD: -1}
				if c.version == 2 {
					view.attemptMutationRevision = binary.BigEndian.Uint64(c.metadata["attempt_mutation_revision"])
				}
				var err error
				if c.version == 1 {
					state, stateErr := readStateForUpgrade(ctx, c.owner.conn, c.binding, c.limits)
					require.NoError(t, stateErr)
					require.NotNil(t, state.floor)
					source.floor = cloneFloor(*state.floor)
					source.floorPresent = true
				} else {
					source.floor, source.floorPresent, err = view.Load(ctx)
					require.NoError(t, err)
				}
				source.history, err = view.History(ctx, 0, 10)
				require.NoError(t, err)
			}
			require.False(t, source.history.HasMore)
			require.Equal(t, test.revision, source.history.NextRevision)
			if test.image == "pending-genesis" {
				require.False(t, source.floorPresent)
				require.Equal(t, zeroFloor(), source.floor)
				require.Empty(t, source.history.Events)
				require.Empty(t, source.history.Records)
			} else {
				require.True(t, source.floorPresent)
				require.Equal(t, databaseID, source.floor.DatabaseID)
				require.Equal(t, test.sequence, source.floor.Sequence)
				require.Equal(t, test.revision, source.floor.Revision)
				require.Equal(t, test.generation, source.floor.Generation)
				require.Len(t, source.history.Events, 2)
				require.Len(t, source.history.Records, 2)
			}
			var mixedInputs incomingMaterialUpgradeFixtureInputs
			if test.image == "mixed" {
				data, err := os.ReadFile(filepath.Join(filepath.Dir(c.directory), "mixed-inputs.json"))
				require.NoError(t, err)
				require.Len(t, data, 195211)
				require.Equal(t, "b71f799e7f61408aa189e9a230fa9e4809b10c1f692dd67d702e540cfcfc32a6", incomingMaterialUpgradeFixtureSHA256(data))
				mixedInputs = incomingMaterialUpgradeFixtureInputsData(t, data)
				incomingMaterialUpgradeFixtureRequireMixedProjections(t, ctx, c.owner.conn, mixedInputs, source.floor)
			}
			c.owner.close(t)
			require.True(t, c.owner.closed)
			require.True(t, c.owner.sqlClosed)
			require.Equal(t, -1, c.owner.rootFD)
			probe, err := probeSchema(c.databasePath, c.binding, c.limits, c.attemptLimits)
			require.NoError(t, err)
			require.True(t, probe.recognized)
			require.False(t, probe.initial)
			require.Equal(t, test.version, probe.version)
			options := DefaultOpenOptions()
			options.PositionLimits = c.limits
			options.AttemptLimits = c.attemptLimits
			options.UpgradeFromPositions = c.version == 1
			options.UpgradeFromAttempts = true
			require.Equal(t, test.version == 1, options.UpgradeFromPositions)
			require.True(t, options.UpgradeFromAttempts)
			input := publicationOpenInput{shape: c.image, directory: c.directory, database: c.databasePath, binding: c.binding, options: options}
			recorder := newPublicationOpenRecorder()
			fd0 := publicationOpenFD0(t)
			store, err := OpenWithOptions(c.directory, c.binding, recorder.options(options))
			if store != nil {
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
			}
			require.NoError(t, err)
			incomingMaterialFlagMatrixRequireTrace(t, recorder, c.image, c.version)
			publicationOpenRequireAcquisitionIdentities(t, recorder, store)
			publicationOpenRequireFD0(t, fd0)
			publicationOpenRequireSchema3(t, ctx, store, input)
			require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, store.conn))
			require.Equal(t, databaseID, store.databaseID)
			require.Equal(t, test.mutation, store.attemptMutationRevision)
			incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, store.conn, c)
			destination := publicationOpenCaptureDestination(t, ctx, store)
			require.Len(t, destination.typed, 15)
			migrated := incomingMaterialPublicFixtureReadAPIs(t, ctx, store, c, source, mixedInputs)
			if test.image == "mixed" {
				incomingMaterialUpgradeFixtureRequireMixedProjections(t, ctx, store.conn, mixedInputs, migrated.floor)
			}
			incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, store.conn, c)
			require.Equal(t, destination, publicationOpenCaptureDestination(t, ctx, store))
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			publicationOpenRequireFD0(t, fd0)
			incomingMaterialPublicFixtureClose(t, store, c.directory, c.version == 2)
			publicationOpenRequireFD0(t, fd0)
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			reopenedFD0 := publicationOpenFD0(t)
			reopened, err := Open(c.directory, c.binding)
			if reopened != nil {
				t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
			}
			require.NoError(t, err)
			publicationOpenRequireFD0(t, reopenedFD0)
			publicationOpenRequireSchema3(t, ctx, reopened, input)
			require.NoError(t, checkIncomingMaterialUpgradeSchema(ctx, reopened.conn))
			require.Equal(t, databaseID, reopened.databaseID)
			require.Equal(t, test.mutation, reopened.attemptMutationRevision)
			incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, reopened.conn, c)
			readback := incomingMaterialPublicFixtureReadAPIs(t, ctx, reopened, c, source, mixedInputs)
			require.Equal(t, migrated, readback)
			if test.image == "mixed" {
				incomingMaterialUpgradeFixtureRequireMixedProjections(t, ctx, reopened.conn, mixedInputs, readback.floor)
			}
			incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, reopened.conn, c)
			require.Equal(t, destination, publicationOpenCaptureDestination(t, ctx, reopened))
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			publicationOpenRequireFD0(t, reopenedFD0)
			incomingMaterialPublicFixtureClose(t, reopened, c.directory, c.version == 2)
			publicationOpenRequireFD0(t, reopenedFD0)
			publicationOpenRequireFD0(t, fd0)
			readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
			incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, readOnly, c)
			require.NoError(t, checkSchema(ctx, readOnly))
			closeReadOnly(t)
			publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			publicationOpenRequireFD0(t, fd0)
		})
	}
}

func incomingMaterialPublicFixtureReadAPIs(t *testing.T, ctx context.Context, store *Store, c *incomingMaterialUpgradeOutcomeCase, source incomingMaterialPublicFixtureReadback, mixedInputs incomingMaterialUpgradeFixtureInputs) incomingMaterialPublicFixtureReadback {
	t.Helper()
	incomingMaterialUpgradeOpenRequireReadAPIs(t, ctx, store, c)
	state := incomingMaterialPublicFixtureReadback{loaded: make(map[[16]byte]Attempt), candidates: make(map[[16]byte]CandidateMaterial), conflicts: make(map[[16]byte]FirstConflictEvidence), conflictPresent: make(map[[16]byte]bool)}
	var err error
	state.floor, state.floorPresent, err = store.Load(ctx)
	require.NoError(t, err)
	require.Equal(t, source.floorPresent, state.floorPresent)
	require.Equal(t, source.floor, state.floor)
	state.history, err = store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Equal(t, source.history, state.history)
	state.attempts, err = store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, state.attempts.HasMore)
	state.active, state.activePresent, err = store.ActiveAttempt(ctx)
	require.NoError(t, err)
	if c.version == 1 {
		require.Empty(t, state.attempts.Attempts)
		require.Empty(t, state.attempts.Evidence)
		require.Equal(t, [16]byte{}, state.attempts.NextID)
		require.False(t, state.activePresent)
		require.Equal(t, Attempt{}, state.active)
		return state
	}
	expected := []Attempt{
		{ID: [16]byte{0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17}, Kind: AttemptGenesis, Lifecycle: AttemptPrepared, Outcome: OutcomeNotSubmitted},
	}
	if c.image == "mixed" {
		expected = []Attempt{
			{ID: [16]byte{0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x18}, Kind: AttemptGenesis, Lifecycle: AttemptRetiredSuccess, Outcome: OutcomeCurrent},
			{ID: [16]byte{0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x19}, Kind: AttemptSuccessor, Lifecycle: AttemptRetiredAbandoned, Outcome: OutcomeLostFence, Blocked: "blocked-floor-replaced"},
			{ID: [16]byte{0x49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1e}, Kind: AttemptSuccessor, Lifecycle: AttemptMayHaveSubmitted, Outcome: OutcomeAbsentUnresolved},
		}
	}
	require.Len(t, c.rows["publication_attempts"], len(expected))
	require.Len(t, state.attempts.Attempts, len(expected))
	for index, row := range c.rows["publication_attempts"] {
		attempt, core := incomingMaterialPublicFixtureLoadAttempt(t, ctx, store, row)
		require.Equal(t, expected[index].ID, attempt.ID)
		require.Equal(t, expected[index].Kind, attempt.Kind)
		require.Equal(t, expected[index].Lifecycle, attempt.Lifecycle)
		require.Equal(t, expected[index].Outcome, attempt.Outcome)
		require.Equal(t, expected[index].Blocked, attempt.Blocked)
		require.Equal(t, attempt, state.attempts.Attempts[index])
		state.loaded[attempt.ID] = attempt
		state.candidates[attempt.ID] = incomingMaterialPublicFixtureCandidate(t, ctx, store, c, attempt, core)
		conflict, present, err := store.ReadFirstConflict(ctx, attempt.ID)
		require.NoError(t, err)
		if attempt.Lifecycle == AttemptRetiredAbandoned {
			require.True(t, present)
			pinned := mixedInputs.Results.FirstConflict
			require.Equal(t, attempt.ID[:], incomingMaterialUpgradeFixtureDigestBytes(t, pinned.AttemptID))
			id := incomingMaterialUpgradeFixtureDigestBytes(t, pinned.ID)
			require.Len(t, id, 32)
			var conflictID [32]byte
			copy(conflictID[:], id)
			require.NotEqual(t, [32]byte{}, conflictID)
			require.Equal(t, int64(1), pinned.HeadSequence)
			expectedConflict := FirstConflictEvidence{AttemptID: attempt.ID, ID: conflictID, Evidence: incomingMaterialUpgradeFixtureDigestBytes(t, pinned.Envelope), Head: incomingMaterialUpgradeFixtureDigestBytes(t, pinned.Head), HeadKey: pinned.HeadKey, HeadRecord: incomingMaterialUpgradeFixtureDigestBytes(t, pinned.HeadRecord), HeadSequence: 1}
			require.Equal(t, expectedConflict, conflict)
		} else {
			require.False(t, present)
			require.Equal(t, FirstConflictEvidence{}, conflict)
		}
		state.conflicts[attempt.ID] = conflict
		state.conflictPresent[attempt.ID] = present
	}
	lastID := expected[len(expected)-1].ID
	require.Equal(t, lastID, state.attempts.NextID)
	require.True(t, state.activePresent)
	require.Equal(t, state.loaded[lastID], state.active)
	var evidence []AttemptEvidence
	for _, row := range c.rows["attempt_evidence"] {
		require.Len(t, row, 4)
		id, ok := row[0].([]byte)
		require.True(t, ok)
		require.Len(t, id, 16)
		role, ok := row[1].(string)
		require.True(t, ok)
		body, ok := row[2].([]byte)
		require.True(t, ok)
		require.NotEmpty(t, body)
		var attemptID [16]byte
		copy(attemptID[:], id)
		evidence = append(evidence, AttemptEvidence{AttemptID: attemptID, Role: role, Evidence: bytes.Clone(body)})
	}
	for _, row := range c.rows["attempt_events"] {
		require.Len(t, row, 5)
		kind, ok := row[2].(string)
		require.True(t, ok)
		if kind != "may-have-submitted" {
			continue
		}
		id, ok := row[0].([]byte)
		require.True(t, ok)
		require.Len(t, id, 16)
		body, ok := row[3].([]byte)
		require.True(t, ok)
		var event attemptEventWire
		require.NoError(t, strictJSON(body, &event))
		require.NotEmpty(t, event.Evidence)
		var attemptID [16]byte
		copy(attemptID[:], id)
		evidence = append(evidence, AttemptEvidence{AttemptID: attemptID, Role: "submission", Evidence: bytes.Clone(event.Evidence)})
	}
	require.ElementsMatch(t, evidence, state.attempts.Evidence)
	return state
}

func incomingMaterialPublicFixtureLoadAttempt(t *testing.T, ctx context.Context, store *Store, row []any) (Attempt, attemptCoreWire) {
	t.Helper()
	require.Len(t, row, 11)
	id, ok := row[0].([]byte)
	require.True(t, ok)
	require.Len(t, id, 16)
	coreBytes, ok := row[1].([]byte)
	require.True(t, ok)
	core, err := decodeAttemptCore(coreBytes)
	require.NoError(t, err)
	require.Equal(t, id, core.AttemptID)
	require.Equal(t, store.databaseID[:], core.DatabaseID)
	lifecycle, ok := row[2].(string)
	require.True(t, ok)
	outcome, ok := row[3].(string)
	require.True(t, ok)
	blocked, ok := row[4].(string)
	require.True(t, ok)
	digest, ok := row[5].([]byte)
	require.True(t, ok)
	require.Len(t, digest, 32)
	require.False(t, allZero(digest))
	mutation, ok := row[6].(int64)
	require.True(t, ok)
	require.GreaterOrEqual(t, mutation, int64(0))
	snapshot, err := publication.DecodeSnapshot(core.SnapshotRecord)
	require.NoError(t, err)
	var capturedFloor *Floor
	if core.CapturedFloor != nil {
		floor, err := floorFromWire(*core.CapturedFloor)
		require.NoError(t, err)
		capturedFloor = &floor
	}
	var attemptID [16]byte
	copy(attemptID[:], id)
	var stateDigest [32]byte
	copy(stateDigest[:], digest)
	expected := Attempt{ID: attemptID, Kind: AttemptKind(core.Kind), Lifecycle: AttemptLifecycle(lifecycle), Outcome: AttemptOutcome(outcome), Blocked: blocked, Sequence: snapshot.PublicationSeq, SnapshotKey: core.SnapshotKey, SnapshotRecordCID: core.SnapshotCID, HeadRecordCID: core.HeadCID, BlobCID: core.BlobCID, BlobSize: core.BlobSize, CapturedFloor: capturedFloor, CapturedRevision: core.CapturedRevision, CapturedGeneration: core.CapturedGeneration, MutationRevision: uint64(mutation), StateDigest: stateDigest, Availability: AvailabilityUnchecked}
	actual, err := store.LoadAttempt(ctx, attemptID)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	return actual, core
}

func incomingMaterialPublicFixtureCandidate(t *testing.T, ctx context.Context, store *Store, c *incomingMaterialUpgradeOutcomeCase, attempt Attempt, core attemptCoreWire) CandidateMaterial {
	t.Helper()
	basename, err := payloadBasenameFromCID(core.BlobCID)
	require.NoError(t, err)
	path := c.image + "/payloads/" + basename
	require.Contains(t, c.payloads, path)
	payload := c.payloads[path]
	require.Equal(t, payload, incomingMaterialUpgradeFixturePayloadState(t, filepath.Join(filepath.Dir(c.directory), path)))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE blob_cid=?", core.BlobCID))
	candidate, err := store.ReadCandidate(ctx, attempt.ID)
	if attempt.Lifecycle == AttemptRetiredAbandoned {
		requireErrorMetadata(t, err, ErrStorage, StageCustody, ReasonCandidateMissing)
		require.Equal(t, CandidateMaterial{}, candidate)
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM attempt_payload_refs WHERE attempt_id=?", attempt.ID[:]))
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications WHERE attempt_id=?", attempt.ID[:]))
		return candidate
	}
	require.NoError(t, err)
	expected := CandidateMaterial{AttemptID: attempt.ID, SnapshotKey: core.SnapshotKey, SnapshotRecord: core.SnapshotRecord, HeadRecord: core.HeadRecord, Payload: payload.bytes, Blob: publication.BlobReference{CID: core.BlobCID, Size: core.BlobSize}}
	require.Equal(t, expected, candidate)
	require.Equal(t, uint64(3072), candidate.Blob.Size)
	require.NoError(t, publication.VerifyPayload(candidate.Payload, candidate.Blob))
	_, err = publication.DecodePayload(candidate.Payload, candidate.Blob)
	require.NoError(t, err)
	return candidate
}

func incomingMaterialPublicFixtureClose(t *testing.T, store *Store, directory string, payloadOwned bool) {
	t.Helper()
	fd0 := publicationOpenFD0(t)
	if !payloadOwned {
		publicationOpenRequireClosedResources(t, store, directory)
		publicationOpenRequireFD0(t, fd0)
		return
	}
	require.NotNil(t, store)
	require.False(t, store.closed)
	rootFD, payloadFD := store.rootFD, store.payloadFD
	conn, pool, lock := store.conn, store.db, store.lock
	require.GreaterOrEqual(t, rootFD, 0)
	require.GreaterOrEqual(t, payloadFD, 0)
	require.NotEqual(t, rootFD, payloadFD)
	require.NotNil(t, conn)
	require.NotNil(t, pool)
	require.NotNil(t, lock)
	var rootStat, payloadStat unix.Stat_t
	closeErr := store.Close()
	rootErr := unix.Fstat(rootFD, &rootStat)
	payloadErr := unix.Fstat(payloadFD, &payloadStat)
	require.NoError(t, closeErr)
	require.True(t, store.closed)
	require.ErrorIs(t, rootErr, unix.EBADF)
	require.ErrorIs(t, payloadErr, unix.EBADF)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	require.ErrorIs(t, conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := pool.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	publicationOpenRequireLockWitness(t, directory, true)
	require.NoError(t, store.Close())
	publicationOpenRequireFD0(t, fd0)
}

type incomingMaterialRuntime3Fixture struct {
	store       *Store
	input       publicationOpenInput
	floors      []Floor
	history     HistoryPage
	baseline    incomingMaterialSchemaSnapshot
	oldGraph    *Store
	retained    bool
	payloadPath string
	payload     incomingMaterialUpgradeFixturePayload
	fd0         unix.Stat_t
}

func TestIncomingMaterialSchema3ReadStateUsesQueryer(t *testing.T) {
	for _, test := range []struct {
		name     string
		retained bool
	}{
		{name: "empty incoming on nonempty old graph", retained: true},
		{name: "populated valid incoming", retained: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			s := incomingMaterialRuntime3NewFixture(t, ctx, test.retained)
			tx, err := s.store.conn.BeginTx(ctx, nil)
			if tx != nil {
				t.Cleanup(func() {
					if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
						assert.NoError(t, err)
					}
				})
			}
			require.NoError(t, err)
			refs := make([]Floor, 0, 2)
			if !test.retained {
				require.Len(t, s.floors, 3)
				refs = append(refs, s.floors[1], s.floors[2])
				incomingMaterialValidCatalog(t, ctx, tx, refs[0].BlobCID, refs[0].BlobSize)
				for _, floor := range refs {
					incomingMaterialInsertRef(t, ctx, tx, int64(floor.Revision), floor.RecordCID, floor.BlobCID)
				}
			}
			before := incomingMaterialRuntime3Snapshot(t, ctx, s, tx, len(refs))
			expectedRows := make([][]any, 0, len(refs))
			for _, floor := range refs {
				expectedRows = append(expectedRows, []any{int64(floor.Revision), floor.RecordCID, floor.BlobCID})
			}
			require.Equal(t, expectedRows, before.incoming)
			require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs JOIN retained_publications USING(accepted_revision)"))
			direct, err := s.store.readState(ctx, tx, StageLoad)
			require.NoError(t, err)
			require.NotNil(t, direct.floor)
			require.Equal(t, s.floors[len(s.floors)-1], *direct.floor)
			recorder := &incomingMaterialUpgradeRecorder{source: tx}
			restore := incomingMaterialRuntime3AttachClosedDecoy(t, ctx, s.store)
			recorded, err := s.store.readState(ctx, recorder, StageLoad)
			require.NoError(t, err)
			require.Equal(t, direct, recorded)
			require.Equal(t, 3, s.store.schemaVersion)
			require.False(t, s.store.closed)
			incomingMaterialRuntime3RequireQueries(t, recorder, s.store.limits.AcceptedEventCount, refs, true)
			restore()
			require.Equal(t, before, incomingMaterialRuntime3Snapshot(t, ctx, s, tx, len(refs)))
			require.NoError(t, tx.Rollback())
			require.Equal(t, s.baseline, incomingMaterialRuntime3Snapshot(t, ctx, s, s.store.conn, 0))
			incomingMaterialRuntime3RequireHealthy(t, ctx, s, s.store)
			publicationOpenRequireFD0(t, s.fd0)
			incomingMaterialPublicFixtureClose(t, s.store, s.input.directory, s.retained)
			publicationOpenRequireFD0(t, s.fd0)
			reopenedFD0 := publicationOpenFD0(t)
			reopened, err := Open(s.input.directory, s.input.binding)
			if reopened != nil {
				t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
			}
			require.NoError(t, err)
			publicationOpenRequireFD0(t, reopenedFD0)
			publicationOpenRequireSchema3(t, ctx, reopened, s.input)
			require.Equal(t, s.baseline, incomingMaterialRuntime3Snapshot(t, ctx, s, reopened.conn, 0))
			incomingMaterialRuntime3RequireHealthy(t, ctx, s, reopened)
			publicationOpenRequireClosedResources(t, reopened, s.input.directory)
			if s.retained {
				require.Equal(t, s.payload, incomingMaterialUpgradeFixturePayloadState(t, s.payloadPath))
			} else {
				requirePayloadDirectoryAbsent(t, s.input.directory)
			}
			publicationOpenRequireFD0(t, reopenedFD0)
			publicationOpenRequireFD0(t, s.fd0)
		})
	}
}

func TestIncomingMaterialSchema3OrdinaryReadRefusesIncomingCorruption(t *testing.T) {
	for _, test := range []struct {
		name     string
		retained bool
	}{
		{name: "wrong existing accepted-record join", retained: false},
		{name: "retained/incoming revision overlap", retained: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			s := incomingMaterialRuntime3NewFixture(t, ctx, test.retained)
			require.GreaterOrEqual(t, len(s.floors), 2)
			first, second := s.floors[0], s.floors[1]
			require.NotEqual(t, first.RecordCID, second.RecordCID)
			validTx, err := s.store.conn.BeginTx(ctx, nil)
			if validTx != nil {
				t.Cleanup(func() {
					if err := validTx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
						assert.NoError(t, err)
					}
				})
			}
			require.NoError(t, err)
			if !s.retained {
				incomingMaterialValidCatalog(t, ctx, validTx, second.BlobCID, second.BlobSize)
			}
			incomingMaterialInsertRef(t, ctx, validTx, int64(second.Revision), second.RecordCID, second.BlobCID)
			valid := incomingMaterialRuntime3Snapshot(t, ctx, s, validTx, 1)
			require.Equal(t, [][]any{{int64(second.Revision), second.RecordCID, second.BlobCID}}, valid.incoming)
			require.Zero(t, incomingMaterialUpgradeCount(t, ctx, validTx, "SELECT COUNT(*) FROM accepted_material_refs JOIN retained_publications USING(accepted_revision)"))
			require.NoError(t, validTx.Commit())
			incomingMaterialRuntime3RequireHealthy(t, ctx, s, s.store)
			require.Equal(t, valid, incomingMaterialRuntime3Snapshot(t, ctx, s, s.store.conn, 1))
			validRecorder := &incomingMaterialUpgradeRecorder{source: s.store.conn}
			validState, err := s.store.readState(ctx, validRecorder, StageLoad)
			require.NoError(t, err)
			direct, err := s.store.readState(ctx, s.store.conn, StageLoad)
			require.NoError(t, err)
			require.Equal(t, direct, validState)
			require.NotNil(t, validState.floor)
			require.Equal(t, s.floors[len(s.floors)-1], *validState.floor)
			corruptTx, err := s.store.conn.BeginTx(ctx, nil)
			if corruptTx != nil {
				t.Cleanup(func() {
					if err := corruptTx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
						assert.NoError(t, err)
					}
				})
			}
			require.NoError(t, err)
			refCount := 1
			expectedRows := [][]any{{int64(second.Revision), first.RecordCID, second.BlobCID}}
			if s.retained {
				incomingMaterialInsertRef(t, ctx, corruptTx, int64(first.Revision), first.RecordCID, first.BlobCID)
				refCount = 2
				expectedRows = [][]any{{int64(first.Revision), first.RecordCID, first.BlobCID}, {int64(second.Revision), second.RecordCID, second.BlobCID}}
			} else {
				result, err := corruptTx.ExecContext(ctx, "UPDATE accepted_material_refs SET record_cid=? WHERE accepted_revision=?", first.RecordCID, int64(second.Revision))
				require.NoError(t, err)
				affected, err := result.RowsAffected()
				require.NoError(t, err)
				require.Equal(t, int64(1), affected)
			}
			require.NoError(t, corruptTx.Commit())
			corrupt := incomingMaterialRuntime3Snapshot(t, ctx, s, s.store.conn, refCount)
			require.Equal(t, expectedRows, corrupt.incoming)
			require.Equal(t, valid.rows, corrupt.rows)
			require.Equal(t, valid.metadata, corrupt.metadata)
			require.Equal(t, valid.objects, corrupt.objects)
			if s.retained {
				require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, s.store.conn, "SELECT COUNT(*) FROM accepted_material_refs JOIN retained_publications USING(accepted_revision)"))
			} else {
				require.Zero(t, incomingMaterialUpgradeCount(t, ctx, s.store.conn, "SELECT COUNT(*) FROM accepted_material_refs JOIN retained_publications USING(accepted_revision)"))
			}
			floor, present, err := s.store.Load(ctx)
			requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
			require.Equal(t, zeroFloor(), floor)
			require.False(t, present)
			history, err := s.store.History(ctx, 0, 10)
			requireErrorMetadata(t, err, ErrSchema, StageHistory, ReasonCorrupt)
			require.Equal(t, HistoryPage{}, history)
			incomingMaterialRuntime3RequireQueries(t, validRecorder, s.store.limits.AcceptedEventCount, []Floor{second}, true)
			for _, stage := range []Stage{StageLoad, StageHistory, StagePrepare} {
				recorder := &incomingMaterialUpgradeRecorder{source: s.store.conn}
				state, err := s.store.readState(ctx, recorder, stage)
				requireErrorMetadata(t, err, ErrSchema, stage, ReasonCorrupt)
				require.Equal(t, stateSnapshot{}, state)
				incomingMaterialRuntime3RequireQueries(t, recorder, s.store.limits.AcceptedEventCount, nil, false)
			}
			require.Equal(t, corrupt, incomingMaterialRuntime3Snapshot(t, ctx, s, s.store.conn, refCount))
			publicationOpenRequireFD0(t, s.fd0)
			incomingMaterialPublicFixtureClose(t, s.store, s.input.directory, s.retained)
			publicationOpenRequireFD0(t, s.fd0)
			readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, s.input.database)
			require.Equal(t, corrupt, incomingMaterialRuntime3Snapshot(t, ctx, s, readOnly, refCount))
			closeReadOnly(t)
			probe, err := probeSchema(s.input.database, s.input.binding, s.input.options.PositionLimits, s.input.options.AttemptLimits)
			requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
			require.Equal(t, schemaProbe{}, probe)
			options := DefaultOpenOptions()
			require.False(t, options.UpgradeFromPositions)
			require.False(t, options.UpgradeFromAttempts)
			recorder := newPublicationOpenRecorder()
			recorder.canary = errors.New("runtime schema three corrupt ordinary open unused canary")
			fd0 := publicationOpenFD0(t)
			refused, err := OpenWithOptions(s.input.directory, s.input.binding, recorder.options(options))
			if refused != nil {
				t.Cleanup(func() { assert.NoError(t, refused.Close()) })
			}
			terminal := publicationOpenRequireRefused(t, refused, err, recorder, []int{101, 102}, ErrSchema, ReasonCorrupt)
			publicationOpenRequireRefusalIdentities(t, recorder, terminal, false)
			publicationOpenRequireFD0(t, fd0)
			for _, event := range recorder.events {
				require.Equal(t, "open", event.stream)
			}
			publicationOpenRequireLockWitness(t, s.input.directory, true)
			finalReadOnly, closeFinalReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, s.input.database)
			require.Equal(t, corrupt, incomingMaterialRuntime3Snapshot(t, ctx, s, finalReadOnly, refCount))
			closeFinalReadOnly(t)
			publicationOpenRequireFD0(t, fd0)
			publicationOpenRequireFD0(t, s.fd0)
		})
	}
}

func incomingMaterialRuntime3NewFixture(t *testing.T, ctx context.Context, retained bool) *incomingMaterialRuntime3Fixture {
	t.Helper()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	require.NoError(t, checkPrivateDirectory(directory))
	input := publicationOpenInput{directory: directory, database: filepath.Join(directory, "publication.db"), binding: f.binding, options: DefaultOpenOptions()}
	fd0 := publicationOpenFD0(t)
	store, err := Open(directory, f.binding)
	if store != nil {
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
	}
	require.NoError(t, err)
	require.NotNil(t, store)
	publicationOpenRequireFD0(t, fd0)
	require.GreaterOrEqual(t, store.rootFD, 0)
	require.NotNil(t, store.conn)
	require.NotNil(t, store.db)
	require.NotNil(t, store.lock)
	publicationOpenRequireSchema3(t, ctx, store, input)
	s := &incomingMaterialRuntime3Fixture{store: store, input: input, retained: retained, fd0: fd0}
	if retained {
		_, finalized := acceptedMaterialRevisionFinalizeGenesis(t, store, f, attemptCandidate(f, 0))
		require.Equal(t, uint64(1), finalized.Floor.Revision)
		observation := f.observation(2)
		proposal, err := store.Prepare(ctx, ModeAdvance, observation, f.payload)
		require.NoError(t, err)
		require.Equal(t, ModeAdvance, proposal.Mode)
		second, err := store.Accept(ctx, ModeAdvance, proposal.StateToken, observation, f.payload, proposal.Confirmation)
		require.NoError(t, err)
		require.Equal(t, uint64(2), second.Revision)
		s.floors = []Floor{finalized.Floor, second}
		require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=1"))
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications WHERE accepted_revision=2"))
		for _, table := range []string{"publication_attempts", "attempt_events", "attempt_evidence", "payload_objects"} {
			require.NotZero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM "+table), table)
		}
		require.GreaterOrEqual(t, store.payloadFD, 0)
		basename, err := payloadBasenameFromCID(finalized.Floor.BlobCID)
		require.NoError(t, err)
		s.payloadPath = filepath.Join(directory, payloadDirectoryName, basename)
		s.payload = incomingMaterialUpgradeFixturePayloadState(t, s.payloadPath)
		require.Equal(t, f.payload, s.payload.bytes)
	} else {
		first, second, third := incomingMaterialHistoricalLifecycle(t, store, f)
		s.floors = []Floor{first, second, third}
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM retained_publications"))
		require.Equal(t, -1, store.payloadFD)
		requirePayloadDirectoryAbsent(t, directory)
	}
	require.GreaterOrEqual(t, len(s.floors), 2)
	require.NotEqual(t, s.floors[0].RecordCID, s.floors[1].RecordCID)
	require.Equal(t, s.floors[0].BlobCID, s.floors[1].BlobCID)
	require.Equal(t, s.floors[0].BlobSize, s.floors[1].BlobSize)
	reference := publication.BlobReference{CID: s.floors[1].BlobCID, Size: s.floors[1].BlobSize}
	require.NoError(t, publication.VerifyPayload(f.payload, reference))
	_, err = publication.DecodePayload(f.payload, reference)
	require.NoError(t, err)
	require.Equal(t, int64(len(s.floors)), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Equal(t, int64(2), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, s.floors[len(s.floors)-1], floor)
	s.history, err = store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, s.history.HasMore)
	require.Len(t, s.history.Events, len(s.floors))
	require.Len(t, s.history.Records, 2)
	require.Equal(t, floor.Revision, s.history.NextRevision)
	s.baseline = incomingMaterialSchemaCapture(t, ctx, store.conn)
	require.Empty(t, s.baseline.incoming)
	s.oldGraph = &Store{binding: store.binding, limits: store.limits, attemptLimits: store.attemptLimits, databaseID: store.databaseID, schemaVersion: 2, attemptMutationRevision: store.attemptMutationRevision, rootFD: -1, payloadFD: -1}
	require.Equal(t, s.baseline, incomingMaterialRuntime3Snapshot(t, ctx, s, store.conn, 0))
	return s
}

func incomingMaterialRuntime3Snapshot(t *testing.T, ctx context.Context, s *incomingMaterialRuntime3Fixture, q queryer, refCount int) incomingMaterialSchemaSnapshot {
	t.Helper()
	require.Equal(t, 3, s.store.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, q))
	require.NoError(t, checkSchemaVersion(ctx, q, 3))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, q))
	events, refs := incomingMaterialRequireBoundedCounts(t, ctx, q, s.store.limits.AcceptedEventCount)
	require.Equal(t, int64(len(s.floors)), events)
	require.Equal(t, int64(refCount), refs)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, q, "SELECT COUNT(*) FROM accepted_material_refs WHERE typeof(accepted_revision)!='integer' OR typeof(record_cid)!='blob' OR typeof(blob_cid)!='blob'"))
	incomingMaterialRequireNoForeignKeyViolation(t, ctx, q)
	old, err := s.oldGraph.readState(ctx, q, StageLoad)
	require.NoError(t, err)
	require.NotNil(t, old.floor)
	require.Equal(t, s.floors[len(s.floors)-1], *old.floor)
	require.Equal(t, old.floor.Revision, old.revision)
	require.Equal(t, old.floor.Generation, old.generation)
	snapshot := incomingMaterialSchemaCapture(t, ctx, q)
	require.Len(t, snapshot.rows, 15)
	require.Len(t, snapshot.metadata, 7)
	require.Len(t, snapshot.objects, 32)
	require.Len(t, snapshot.incoming, refCount)
	require.Equal(t, s.baseline.metadata, snapshot.metadata)
	require.Equal(t, s.baseline.objects, snapshot.objects)
	for _, row := range snapshot.incoming {
		require.Len(t, row, 3)
		revision, ok := row[0].(int64)
		require.True(t, ok)
		require.GreaterOrEqual(t, revision, int64(1))
		require.LessOrEqual(t, revision, int64(len(s.floors)))
		for _, value := range row[1:] {
			cid, ok := value.([]byte)
			require.True(t, ok)
			require.NotEmpty(t, cid)
			require.LessOrEqual(t, len(cid), publication.MaxCIDBytes)
		}
	}
	if s.retained {
		require.Equal(t, s.payload, incomingMaterialUpgradeFixturePayloadState(t, s.payloadPath))
	} else {
		requirePayloadDirectoryAbsent(t, s.input.directory)
	}
	return snapshot
}

func incomingMaterialRuntime3RequireHealthy(t *testing.T, ctx context.Context, s *incomingMaterialRuntime3Fixture, store *Store) {
	t.Helper()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, s.floors[len(s.floors)-1], floor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Equal(t, s.history, history)
}

func incomingMaterialRuntime3AttachClosedDecoy(t *testing.T, ctx context.Context, store *Store) func() {
	t.Helper()
	original := store.conn
	require.NotNil(t, original)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	var pool *sql.DB
	var conn *sql.Conn
	closed := false
	t.Cleanup(func() {
		if closed {
			return
		}
		closed = true
		var connErr, poolErr error
		if conn != nil {
			connErr = conn.Close()
		}
		if pool != nil {
			poolErr = pool.Close()
		}
		assert.NoError(t, connErr)
		assert.NoError(t, poolErr)
	})
	var err error
	pool, err = sql.Open("sqlite", dbDSN(filepath.Join(directory, "closed-decoy.db"), false))
	require.NoError(t, err)
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	conn, err = pool.Conn(ctx)
	require.NoError(t, err)
	require.NotSame(t, original, conn)
	connErr := conn.Close()
	poolErr := pool.Close()
	closed = true
	require.NoError(t, connErr)
	require.NoError(t, poolErr)
	diagnosticContext, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	require.ErrorIs(t, conn.PingContext(diagnosticContext), sql.ErrConnDone)
	poolErr = pool.PingContext(diagnosticContext)
	require.NoError(t, diagnosticContext.Err())
	require.Error(t, poolErr)
	restore := func() { store.conn = original }
	t.Cleanup(restore)
	store.conn = conn
	return restore
}

func incomingMaterialRuntime3RequireQueries(t *testing.T, recorder *incomingMaterialUpgradeRecorder, limit uint32, refs []Floor, complete bool) {
	t.Helper()
	revisions := make([][]any, 0, len(refs))
	records := make([][]any, 0, len(refs))
	catalog := make([][]any, 0, len(refs))
	for _, floor := range refs {
		revisions = append(revisions, []any{int64(floor.Revision)})
		records = append(records, []any{floor.RecordCID})
		catalog = append(catalog, []any{floor.BlobCID})
	}
	checks := []struct {
		fragment string
		args     [][]any
	}{
		{fragment: "(SELECT COUNT(*) FROM accepted_events),(SELECT COUNT(*) FROM accepted_material_refs)", args: [][]any{{}}},
		{fragment: "FROM accepted_material_refs ORDER BY accepted_revision LIMIT ?", args: [][]any{{int64(limit) + 1}}},
		{fragment: "FROM retained_publications WHERE accepted_revision=?", args: revisions},
		{fragment: "substr(CAST(new_floor AS BLOB),1,65537)", args: revisions},
		{fragment: "typeof(record_key),length(CAST(record_key AS BLOB)),substr(CAST(record_key AS BLOB),1,17)", args: records},
		{fragment: "typeof(basename),length(CAST(basename AS BLOB)),substr(CAST(basename AS BLOB),1,73)", args: catalog},
	}
	for index, check := range checks {
		if !complete && index == 2 {
			break
		}
		observed := make([][]any, 0)
		for _, recorded := range recorder.queries {
			if strings.Contains(recorded.query, check.fragment) {
				observed = append(observed, recorded.args)
			}
		}
		require.Equal(t, check.args, observed, check.fragment)
	}
}

type incomingMaterialPublicRefusalFixture struct {
	input    publicationOpenInput
	kind     string
	store    *Store
	runtime3 *incomingMaterialRuntime3Fixture
}

type incomingMaterialPublicRefusalSnapshot struct {
	applicationID   int
	userVersion     int
	journalMode     string
	objects         map[string]incomingMaterialUpgradeFixtureObject
	metadata        map[string][]byte
	rows            map[string][][]any
	incomingPresent bool
	incoming        [][]any
	selectedCount   int64
	selectedRows    [][]any
}

func TestIncomingMaterialPublicOpenRefusals(t *testing.T) {
	for _, test := range []struct {
		name   string
		class  error
		reason Reason
	}{
		{name: "foreign application", class: ErrSchema, reason: ReasonSchema},
		{name: "lookalike extra object", class: ErrSchema, reason: ReasonSchema},
		{name: "active runtime state", class: ErrSchema, reason: ReasonSchema},
		{name: "future publication4", class: ErrSchema, reason: ReasonSchema},
		{name: "altered incoming DDL", class: ErrSchema, reason: ReasonSchema},
		{name: "extra incoming index", class: ErrSchema, reason: ReasonSchema},
		{name: "missing incoming table", class: ErrSchema, reason: ReasonSchema},
		{name: "missing attempt metadata key", class: ErrSchema, reason: ReasonSchema},
		{name: "valid caller binding mismatch", class: ErrInvalid, reason: ReasonBinding},
		{name: "valid caller position-limit mismatch", class: ErrInvalid, reason: ReasonLimits},
		{name: "valid caller attempt-limit mismatch", class: ErrInvalid, reason: ReasonLimits},
		{name: "zero database ID", class: ErrSchema, reason: ReasonCorrupt},
		{name: "overflowing attempt mutation", class: ErrSchema, reason: ReasonCorrupt},
		{name: "accepted audit digest corruption", class: ErrSchema, reason: ReasonCorrupt},
		{name: "incoming wrong existing record", class: ErrSchema, reason: ReasonCorrupt},
		{name: "incoming retained overlap", class: ErrSchema, reason: ReasonCorrupt},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			setupFD0 := publicationOpenFD0(t)
			s := incomingMaterialPublicRefusalNewFixture(t, ctx, test.name)
			before := incomingMaterialPublicRefusalCapture(t, ctx, s.input.database, s.kind)
			switch s.kind {
			case "foreign":
				require.Zero(t, before.applicationID)
				require.Zero(t, before.userVersion)
				require.Equal(t, "delete", before.journalMode)
				require.Equal(t, map[string]incomingMaterialUpgradeFixtureObject{"foreign_state": {kind: "table", sql: "CREATE TABLE foreign_state (value TEXT NOT NULL)"}}, before.objects)
				require.Equal(t, int64(1), before.selectedCount)
				require.Equal(t, [][]any{{"preserve"}}, before.selectedRows)
			case "runtime":
				require.Zero(t, before.applicationID)
				require.Zero(t, before.userVersion)
				require.Equal(t, "wal", before.journalMode)
				require.Contains(t, before.objects, "schema_version")
				require.Equal(t, int64(1), before.selectedCount)
				require.Equal(t, [][]any{{int64(1), int64(v1state.LatestSchemaVersion)}}, before.selectedRows)
			case "publication":
				require.Equal(t, applicationID, before.applicationID)
				require.Equal(t, 3, before.userVersion)
				require.Equal(t, "wal", before.journalMode)
				require.Len(t, before.objects, 32)
				require.Len(t, before.metadata, 7)
				require.Len(t, before.rows, 15)
				require.True(t, before.incomingPresent)
			}
			expected := incomingMaterialPublicRefusalClone(before)
			incomingMaterialPublicRefusalDamage(t, ctx, s, test.name, &expected)
			if s.store != nil {
				payloadOwned := s.runtime3 != nil && s.runtime3.retained
				incomingMaterialPublicFixtureClose(t, s.store, s.input.directory, payloadOwned)
			}
			publicationOpenRequireFD0(t, setupFD0)
			damaged := incomingMaterialPublicRefusalCapture(t, ctx, s.input.database, s.kind)
			require.Equal(t, expected, damaged)
			publicationOpenRequirePrivateFile(t, s.input.database)
			require.NoError(t, checkPrivateDirectory(s.input.directory))
			for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
				require.NoError(t, preflightFile(filepath.Join(s.input.directory, name)), name)
			}
			if s.runtime3 != nil && s.runtime3.retained {
				require.Equal(t, s.runtime3.payload, incomingMaterialUpgradeFixturePayloadState(t, s.runtime3.payloadPath))
			}
			require.NoError(t, validateBinding(s.input.binding))
			require.NoError(t, validateLimits(s.input.options.PositionLimits))
			require.NoError(t, validateAttemptLimits(s.input.options.AttemptLimits))
			options := s.input.options
			options.UpgradeFromPositions = true
			options.UpgradeFromAttempts = true
			require.True(t, options.UpgradeFromPositions)
			require.True(t, options.UpgradeFromAttempts)
			recorder := newPublicationOpenRecorder()
			recorder.canary = errors.New("public refusal table unused canary")
			fd0 := publicationOpenFD0(t)
			refused, err := OpenWithOptions(s.input.directory, s.input.binding, recorder.options(options))
			if refused != nil {
				t.Cleanup(func() { assert.NoError(t, refused.Close()) })
			}
			terminal := publicationOpenRequireRefused(t, refused, err, recorder, []int{101, 102}, test.class, test.reason)
			publicationOpenRequireRefusalIdentities(t, recorder, terminal, false)
			publicationOpenRequireFD0(t, fd0)
			for _, event := range recorder.events {
				require.Equal(t, "open", event.stream)
			}
			publicationOpenRequireLockWitness(t, s.input.directory, true)
			require.Equal(t, damaged, incomingMaterialPublicRefusalCapture(t, ctx, s.input.database, s.kind))
			publicationOpenRequirePrivateFile(t, s.input.database)
			require.NoError(t, checkPrivateDirectory(s.input.directory))
			if s.runtime3 != nil && s.runtime3.retained {
				require.Equal(t, s.runtime3.payload, incomingMaterialUpgradeFixturePayloadState(t, s.runtime3.payloadPath))
			}
			publicationOpenRequireFD0(t, fd0)
			publicationOpenRequireFD0(t, setupFD0)
		})
	}
}

func incomingMaterialPublicRefusalNewFixture(t *testing.T, ctx context.Context, name string) *incomingMaterialPublicRefusalFixture {
	t.Helper()
	s := &incomingMaterialPublicRefusalFixture{kind: "publication"}
	switch name {
	case "foreign application":
		s.kind = "foreign"
		s.input = publicationOpenInputFor(t, "empty")
		publicationOpenCreateForeignDatabase(t, ctx, s.input.database, 0, 0)
		return s
	case "active runtime state":
		s.kind = "runtime"
		s.input = incomingMaterialPublicRefusalRuntimeCopy(t)
		return s
	case "accepted audit digest corruption", "incoming wrong existing record", "incoming retained overlap":
		s.runtime3 = incomingMaterialRuntime3NewFixture(t, ctx, name == "incoming retained overlap")
		s.input, s.store = s.runtime3.input, s.runtime3.store
	default:
		s.input = publicationOpenInputFor(t, "absent")
		fd0 := publicationOpenFD0(t)
		store, err := Open(s.input.directory, s.input.binding)
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		publicationOpenRequireFD0(t, fd0)
		s.store = store
		publicationOpenRequireSchema3(t, ctx, store, s.input)
		publicationOpenRequireEmptyDestination(t, publicationOpenCaptureDestination(t, ctx, store))
	}
	require.NoError(t, validateBinding(s.input.binding))
	require.NoError(t, validateLimits(s.input.options.PositionLimits))
	require.NoError(t, validateAttemptLimits(s.input.options.AttemptLimits))
	publicationOpenRequireHealthyCurrent3Probe(t, s.input)
	if name == "incoming wrong existing record" || name == "incoming retained overlap" {
		require.GreaterOrEqual(t, len(s.runtime3.floors), 2)
		second := s.runtime3.floors[1]
		tx, err := s.store.conn.BeginTx(ctx, nil)
		if tx != nil {
			t.Cleanup(func() {
				if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
					assert.NoError(t, err)
				}
			})
		}
		require.NoError(t, err)
		if !s.runtime3.retained {
			incomingMaterialValidCatalog(t, ctx, tx, second.BlobCID, second.BlobSize)
		}
		incomingMaterialInsertRef(t, ctx, tx, int64(second.Revision), second.RecordCID, second.BlobCID)
		require.NoError(t, tx.Commit())
		incomingMaterialRuntime3RequireHealthy(t, ctx, s.runtime3, s.store)
		valid := incomingMaterialRuntime3Snapshot(t, ctx, s.runtime3, s.store.conn, 1)
		require.Equal(t, [][]any{{int64(second.Revision), second.RecordCID, second.BlobCID}}, valid.incoming)
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, s.store.conn, "SELECT COUNT(*) FROM accepted_material_refs JOIN retained_publications USING(accepted_revision)"))
		publicationOpenRequireHealthyCurrent3Probe(t, s.input)
	}
	return s
}

func incomingMaterialPublicRefusalRuntimeCopy(t *testing.T) publicationOpenInput {
	t.Helper()
	base := t.TempDir()
	paths := platform.Paths{Home: filepath.Join(base, "home"), ConfigHome: filepath.Join(base, "config"), StateHome: filepath.Join(base, "state"), CacheHome: filepath.Join(base, "cache"), DataHome: filepath.Join(base, "data")}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	fd0 := publicationOpenFD0(t)
	store, err := v1state.Open(paths)
	if store != nil {
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
	}
	require.NoError(t, err)
	require.NotNil(t, store)
	publicationOpenRequireFD0(t, fd0)
	version, err := store.SchemaVersion()
	require.NoError(t, err)
	require.Equal(t, v1state.LatestSchemaVersion, version)
	require.Equal(t, 15, version)
	require.NoError(t, store.Close())
	publicationOpenRequireFD0(t, fd0)
	data, err := os.ReadFile(filepath.Join(paths.AppStateDir(), "state.db"))
	require.NoError(t, err)
	require.NotEmpty(t, data)
	input := publicationOpenInputFor(t, "absent")
	incomingMaterialUpgradeWriteExclusive(t, input.database, data)
	copied, err := os.ReadFile(input.database)
	require.NoError(t, err)
	require.Equal(t, data, copied)
	publicationOpenRequirePrivateFile(t, input.database)
	return input
}

func incomingMaterialPublicRefusalCapture(t *testing.T, ctx context.Context, path, kind string) incomingMaterialPublicRefusalSnapshot {
	t.Helper()
	conn, closeConn := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, path)
	var snapshot incomingMaterialPublicRefusalSnapshot
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&snapshot.applicationID))
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&snapshot.userVersion))
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&snapshot.journalMode))
	snapshot.objects = incomingMaterialUpgradeFixtureObjects(t, ctx, conn)
	var countQuery, selectedQuery string
	columns := 1
	switch kind {
	case "foreign":
		countQuery = "SELECT COUNT(*) FROM foreign_state"
		selectedQuery = "SELECT value FROM foreign_state ORDER BY value LIMIT 2"
	case "runtime":
		countQuery = "SELECT COUNT(*) FROM schema_version"
		selectedQuery = "SELECT singleton,version FROM schema_version ORDER BY singleton LIMIT 2"
		columns = 2
	case "publication":
		snapshot.metadata = incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
		snapshot.rows = incomingMaterialUpgradeFixtureTypedRows(t, ctx, conn)
		require.Len(t, snapshot.rows, 15)
		_, snapshot.incomingPresent = snapshot.objects["accepted_material_refs"]
		if snapshot.incomingPresent {
			snapshot.incoming = incomingMaterialSchemaIncomingRows(t, ctx, conn)
		}
		if _, present := snapshot.objects["SQLiteX"]; present {
			countQuery = "SELECT COUNT(*) FROM SQLiteX"
			selectedQuery = "SELECT value FROM SQLiteX ORDER BY value LIMIT 2"
		}
	default:
		require.FailNow(t, "unsupported public refusal snapshot")
	}
	if selectedQuery != "" {
		snapshot.selectedCount = incomingMaterialUpgradeCount(t, ctx, conn, countQuery)
		rows, err := conn.QueryContext(ctx, selectedQuery)
		require.NoError(t, err)
		var scanErr error
		for rows.Next() {
			var values []any
			values, scanErr = scanRawValues(rows, columns)
			if scanErr != nil {
				break
			}
			snapshot.selectedRows = append(snapshot.selectedRows, values)
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		require.NoError(t, scanErr)
		require.NoError(t, rowsErr)
		require.NoError(t, closeErr)
	}
	closeConn(t)
	return snapshot
}

func incomingMaterialPublicRefusalClone(before incomingMaterialPublicRefusalSnapshot) incomingMaterialPublicRefusalSnapshot {
	cloned := before
	cloned.objects = make(map[string]incomingMaterialUpgradeFixtureObject, len(before.objects))
	for name, object := range before.objects {
		cloned.objects[name] = object
	}
	cloned.metadata = nil
	if before.metadata != nil {
		cloned.metadata = make(map[string][]byte, len(before.metadata))
		for key, value := range before.metadata {
			cloned.metadata[key] = bytes.Clone(value)
		}
	}
	cloneRows := func(rows [][]any) [][]any {
		if rows == nil {
			return nil
		}
		result := make([][]any, len(rows))
		for index, row := range rows {
			result[index] = make([]any, len(row))
			for column, value := range row {
				if data, ok := value.([]byte); ok {
					result[index][column] = bytes.Clone(data)
				} else {
					result[index][column] = value
				}
			}
		}
		return result
	}
	cloned.rows = nil
	if before.rows != nil {
		cloned.rows = make(map[string][][]any, len(before.rows))
		for table, rows := range before.rows {
			cloned.rows[table] = cloneRows(rows)
		}
	}
	cloned.incoming = cloneRows(before.incoming)
	cloned.selectedRows = cloneRows(before.selectedRows)
	return cloned
}

func incomingMaterialPublicRefusalDamage(t *testing.T, ctx context.Context, s *incomingMaterialPublicRefusalFixture, name string, expected *incomingMaterialPublicRefusalSnapshot) {
	t.Helper()
	switch name {
	case "foreign application", "active runtime state":
		return
	case "lookalike extra object":
		statement := "CREATE TABLE SQLiteX(value TEXT NOT NULL)"
		_, err := s.store.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
		result, err := s.store.conn.ExecContext(ctx, "INSERT INTO SQLiteX(value) VALUES('preserve')")
		require.NoError(t, err)
		affected, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), affected)
		expected.objects["SQLiteX"] = incomingMaterialUpgradeFixtureObject{kind: "table", sql: statement}
		expected.selectedCount = 1
		expected.selectedRows = [][]any{{"preserve"}}
	case "future publication4":
		_, err := s.store.conn.ExecContext(ctx, "PRAGMA user_version=4")
		require.NoError(t, err)
		expected.userVersion = 4
	case "altered incoming DDL":
		require.Empty(t, expected.incoming)
		_, err := s.store.conn.ExecContext(ctx, "DROP TABLE accepted_material_refs")
		require.NoError(t, err)
		statement := "CREATE TABLE accepted_material_refs (accepted_revision INTEGER PRIMARY KEY NOT NULL REFERENCES accepted_events(revision), record_cid BLOB NOT NULL REFERENCES accepted_records(cid), blob_cid BLOB NOT NULL)"
		_, err = s.store.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
		expected.objects["accepted_material_refs"] = incomingMaterialUpgradeFixtureObject{kind: "table", sql: statement}
	case "extra incoming index":
		statement := "CREATE INDEX incoming_refusal_extra ON accepted_material_refs(record_cid)"
		_, err := s.store.conn.ExecContext(ctx, statement)
		require.NoError(t, err)
		expected.objects["incoming_refusal_extra"] = incomingMaterialUpgradeFixtureObject{kind: "index", sql: statement}
	case "missing incoming table":
		require.Empty(t, expected.incoming)
		_, err := s.store.conn.ExecContext(ctx, "DROP TABLE accepted_material_refs")
		require.NoError(t, err)
		delete(expected.objects, "accepted_material_refs")
		expected.incomingPresent = false
		expected.incoming = nil
	case "missing attempt metadata key":
		incomingMaterialPublicRefusalMetadata(t, ctx, s.store.conn, expected, "attempt_limits", nil, true)
	case "valid caller binding mismatch":
		original := s.input.binding
		s.input.binding.Vault[0] ^= 1
		require.NotEqual(t, original, s.input.binding)
		require.False(t, allZero(s.input.binding.Vault[:]))
		require.NoError(t, validateBinding(s.input.binding))
	case "valid caller position-limit mismatch":
		original := s.input.options.PositionLimits
		require.Greater(t, original.HistoryPageEvents, uint32(1))
		s.input.options.PositionLimits.HistoryPageEvents--
		require.NotEqual(t, original, s.input.options.PositionLimits)
		require.NoError(t, validateLimits(s.input.options.PositionLimits))
	case "valid caller attempt-limit mismatch":
		original := s.input.options.AttemptLimits
		require.Greater(t, original.HistoryPageEntries, uint32(1))
		s.input.options.AttemptLimits.HistoryPageEntries--
		require.NotEqual(t, original, s.input.options.AttemptLimits)
		require.NoError(t, validateAttemptLimits(s.input.options.AttemptLimits))
	case "zero database ID":
		require.Len(t, expected.metadata["database_id"], 32)
		require.False(t, allZero(expected.metadata["database_id"]))
		incomingMaterialPublicRefusalMetadata(t, ctx, s.store.conn, expected, "database_id", make([]byte, 32), false)
	case "overflowing attempt mutation":
		require.Equal(t, uint64Bytes(0), expected.metadata["attempt_mutation_revision"])
		incomingMaterialPublicRefusalMetadata(t, ctx, s.store.conn, expected, "attempt_mutation_revision", uint64Bytes(uint64(1)<<63), false)
	case "accepted audit digest corruption":
		require.NotEmpty(t, expected.rows["accepted_events"])
		matches := 0
		for _, row := range expected.rows["accepted_events"] {
			require.Len(t, row, 9)
			revision, ok := row[0].(int64)
			require.True(t, ok)
			if revision != 1 {
				continue
			}
			digest, ok := row[7].([]byte)
			require.True(t, ok)
			require.Len(t, digest, 32)
			require.False(t, allZero(digest))
			row[7] = make([]byte, 32)
			matches++
		}
		require.Equal(t, 1, matches)
		result, err := s.store.conn.ExecContext(ctx, "UPDATE accepted_events SET digest=? WHERE revision=1", make([]byte, 32))
		require.NoError(t, err)
		affected, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), affected)
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, s.store.conn)
	case "incoming wrong existing record", "incoming retained overlap":
		require.NotNil(t, s.runtime3)
		require.GreaterOrEqual(t, len(s.runtime3.floors), 2)
		first, second := s.runtime3.floors[0], s.runtime3.floors[1]
		require.NotEqual(t, first.RecordCID, second.RecordCID)
		require.Equal(t, [][]any{{int64(second.Revision), second.RecordCID, second.BlobCID}}, expected.incoming)
		if name == "incoming wrong existing record" {
			result, err := s.store.conn.ExecContext(ctx, "UPDATE accepted_material_refs SET record_cid=? WHERE accepted_revision=?", first.RecordCID, int64(second.Revision))
			require.NoError(t, err)
			affected, err := result.RowsAffected()
			require.NoError(t, err)
			require.Equal(t, int64(1), affected)
			expected.incoming[0][1] = bytes.Clone(first.RecordCID)
			incomingMaterialRuntime3Snapshot(t, ctx, s.runtime3, s.store.conn, 1)
		} else {
			result, err := s.store.conn.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", int64(first.Revision), first.RecordCID, first.BlobCID)
			require.NoError(t, err)
			affected, err := result.RowsAffected()
			require.NoError(t, err)
			require.Equal(t, int64(1), affected)
			expected.incoming = append([][]any{{int64(first.Revision), bytes.Clone(first.RecordCID), bytes.Clone(first.BlobCID)}}, expected.incoming...)
			incomingMaterialRuntime3Snapshot(t, ctx, s.runtime3, s.store.conn, 2)
			require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, s.store.conn, "SELECT COUNT(*) FROM accepted_material_refs JOIN retained_publications USING(accepted_revision)"))
		}
	default:
		require.FailNow(t, "unsupported public refusal mutation")
	}
}

func incomingMaterialPublicRefusalMetadata(t *testing.T, ctx context.Context, conn *sql.Conn, expected *incomingMaterialPublicRefusalSnapshot, key string, value []byte, remove bool) {
	t.Helper()
	require.Contains(t, expected.metadata, key)
	require.Len(t, expected.metadata, 7)
	require.Len(t, expected.rows["store_meta"], 7)
	rows := make([][]any, 0, 7)
	matches := 0
	for _, row := range expected.rows["store_meta"] {
		require.Len(t, row, 2)
		storedKey, ok := row[0].(string)
		require.True(t, ok)
		if storedKey == key {
			require.Equal(t, expected.metadata[key], row[1])
			matches++
			if remove {
				continue
			}
			row[1] = bytes.Clone(value)
		}
		rows = append(rows, row)
	}
	require.Equal(t, 1, matches)
	var result sql.Result
	var err error
	switch key {
	case "attempt_limits":
		require.True(t, remove)
		result, err = conn.ExecContext(ctx, "DELETE FROM store_meta WHERE key='attempt_limits'")
	case "database_id":
		require.False(t, remove)
		result, err = conn.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='database_id'", value)
	case "attempt_mutation_revision":
		require.False(t, remove)
		result, err = conn.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='attempt_mutation_revision'", value)
	default:
		require.FailNow(t, "unsupported public refusal metadata mutation")
		return
	}
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)
	if remove {
		delete(expected.metadata, key)
	} else {
		expected.metadata[key] = bytes.Clone(value)
	}
	expected.rows["store_meta"] = rows
}

type incomingMaterialWALReceipt struct {
	Success                 string   `json:"success"`
	SchemaVersion           int      `json:"schemaVersion"`
	DatabaseID              []byte   `json:"databaseID"`
	Revision                uint64   `json:"revision"`
	Generation              uint64   `json:"generation"`
	AttemptMutationRevision uint64   `json:"attemptMutationRevision"`
	IncomingRefs            int64    `json:"incomingRefs"`
	PendingID               [16]byte `json:"pendingID"`
	UpgradeFromPositions    bool     `json:"upgradeFromPositions"`
	UpgradeFromAttempts     bool     `json:"upgradeFromAttempts"`
}

type incomingMaterialWALRawObservation struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Missing  bool   `json:"missing"`
	Regular  bool   `json:"regular"`
	Mode     uint32 `json:"mode"`
	UID      uint32 `json:"uid"`
	Nlink    uint64 `json:"nlink"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Readable bool   `json:"readable"`
	Error    string `json:"error"`
	Artifact string `json:"artifact"`
	Data     []byte `json:"-"`
}

var incomingMaterialWALRetainedStore *Store

func TestIncomingMaterialSchema3CommittedWALProbe(t *testing.T) {
	_, directorySet := os.LookupEnv("DOTTIE_P17_B7_WAL_HELPER_DIR")
	_, receiptSet := os.LookupEnv("DOTTIE_P17_B7_WAL_HELPER_RECEIPT")
	require.False(t, directorySet)
	require.False(t, receiptSet)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	assets := incomingMaterialUpgradeFixtureCopy(t)
	image := assets.manifest.requireImage(t, "pending-genesis")
	binding, limits, attemptLimits := incomingMaterialUpgradeFixtureBindingOptions(t, image)
	require.Equal(t, Binding{AccountDID: incomingMaterialUpgradeFixtureDID, Backend: BackendPublicRepo, Repository: "at://" + incomingMaterialUpgradeFixtureDID, Vault: [32]byte{9}}, binding)
	require.Equal(t, DefaultLimits(), limits)
	require.Equal(t, DefaultAttemptLimits(), attemptLimits)
	require.Len(t, image.Payloads, 1)
	options := DefaultOpenOptions()
	options.PositionLimits, options.AttemptLimits = limits, attemptLimits
	directory := filepath.Join(assets.root, "pending-genesis")
	input := publicationOpenInput{directory: directory, database: filepath.Join(directory, "publication.db"), binding: binding, options: options, payloadPath: filepath.Join(assets.root, image.Payloads[0].Path), payloadHash: image.Payloads[0].SHA256}
	incomingMaterialWALRequireContainedDirectory(t, directory, filepath.Clean(os.TempDir()))
	before := publicationOpenSnapshotSource(t, ctx, input.database, 2)
	require.Len(t, before.metadata, 7)
	require.Len(t, before.typed, 15)
	require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(before.typed))
	require.Zero(t, before.incomingTableCount)
	require.Equal(t, uint64Bytes(0), before.metadata["revision"])
	require.Equal(t, uint64Bytes(0), before.metadata["generation"])
	require.Equal(t, uint64Bytes(1), before.metadata["attempt_mutation_revision"])
	payload := publicationOpenCapturePayload(t, input)
	readOnly, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, input.database)
	sourceObjects := incomingMaterialUpgradeFixtureObjects(t, ctx, readOnly)
	require.Len(t, sourceObjects, 31)
	closeReadOnly(t)
	sourceRaw := incomingMaterialWALReadRaw(input.database, 16<<20, true)
	require.Empty(t, sourceRaw.Error)
	require.True(t, sourceRaw.Readable)
	require.Equal(t, "d2e446ca0e728ac4af1835c2d4e65c4809fb17f19ef9729f0cc305b87b45f108", sourceRaw.SHA256)
	require.GreaterOrEqual(t, len(sourceRaw.Data), 100)
	require.Equal(t, uint32(2), binary.BigEndian.Uint32(sourceRaw.Data[60:64]))
	root, durable := os.LookupEnv("DOTTIE_P17_B7_WAL_EVIDENCE_ROOT")
	var artifactDirectory string
	if durable {
		require.True(t, filepath.IsAbs(root))
		require.Equal(t, filepath.Clean(root), root)
		require.NoError(t, checkPrivateDirectory(root))
		var err error
		artifactDirectory, err = os.MkdirTemp(root, "committed-wal-")
		require.NoError(t, err)
	} else {
		root = filepath.Clean(os.TempDir())
		artifactDirectory = t.TempDir()
	}
	incomingMaterialWALRequireContainedDirectory(t, artifactDirectory, root)
	t.Logf("committed-WAL artifacts: %s (durable=%t)", artifactDirectory, durable)
	helperReceiptPath := filepath.Join(artifactDirectory, "helper-receipt.json")
	executable, err := os.Executable()
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(executable))
	executableRaw := incomingMaterialWALReadRaw(executable, 256<<20, false)
	require.Empty(t, executableRaw.Error)
	require.True(t, executableRaw.Readable)
	require.NotEmpty(t, executableRaw.Data)
	executableRaw.Data = nil
	childContext, childCancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(childCancel)
	command := exec.CommandContext(childContext, executable, "-test.run=^TestIncomingMaterialSchema3WALWriterHelper$", "-test.count=1", "-test.timeout=60s", "-test.v")
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "DOTTIE_P17_B7_WAL_HELPER_DIR=") || strings.HasPrefix(entry, "DOTTIE_P17_B7_WAL_HELPER_RECEIPT=") {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "DOTTIE_P17_B7_WAL_HELPER_DIR="+directory, "DOTTIE_P17_B7_WAL_HELPER_RECEIPT="+helperReceiptPath)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	runErr := command.Run()
	contextErr := childContext.Err()
	childCancel()
	exitCode := -1
	exited := false
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
		exited = command.ProcessState.Exited()
	}
	var writeErrors []string
	observations := make([]incomingMaterialWALRawObservation, 0, 3)
	for _, name := range []string{"publication.db", "publication.db-wal", "publication.db-shm"} {
		observation := incomingMaterialWALReadRaw(filepath.Join(directory, name), 16<<20, true)
		if observation.Readable {
			artifact := filepath.Join(artifactDirectory, "after-child-"+name)
			if err := incomingMaterialWALWriteExclusive(artifact, observation.Data); err != nil {
				writeErrors = append(writeErrors, artifact+": "+err.Error())
			} else {
				observation.Artifact = artifact
			}
		}
		observations = append(observations, observation)
	}
	receiptRaw := incomingMaterialWALReadRaw(helperReceiptPath, 16<<20, true)
	var receipt incomingMaterialWALReceipt
	var receiptErr error
	if receiptRaw.Readable {
		receiptErr = json.Unmarshal(receiptRaw.Data, &receipt)
	} else {
		receiptErr = errors.New("helper receipt is unreadable")
	}
	for _, output := range []struct {
		name string
		data []byte
	}{{name: "child.stdout", data: stdout.Bytes()}, {name: "child.stderr", data: stderr.Bytes()}} {
		path := filepath.Join(artifactDirectory, output.name)
		if err := incomingMaterialWALWriteExclusive(path, output.data); err != nil {
			writeErrors = append(writeErrors, path+": "+err.Error())
		}
	}
	runError, contextError, receiptError := "", "", ""
	if runErr != nil {
		runError = runErr.Error()
	}
	if contextErr != nil {
		contextError = contextErr.Error()
	}
	if receiptErr != nil {
		receiptError = receiptErr.Error()
	}
	invocation := map[string]any{
		"durable": durable, "artifactDirectory": artifactDirectory, "executable": executableRaw,
		"argv": command.Args, "environment": command.Env, "exited": exited, "exitCode": exitCode,
		"runError": runError, "contextError": contextError, "raw": observations,
		"helperReceipt": receiptRaw, "helperReceiptDecodeError": receiptError, "decodedReceipt": receipt,
		"stdout": "child.stdout", "stdoutSHA256": incomingMaterialUpgradeFixtureSHA256(stdout.Bytes()),
		"stderr": "child.stderr", "stderrSHA256": incomingMaterialUpgradeFixtureSHA256(stderr.Bytes()),
		"evidenceWriteErrors": writeErrors,
	}
	invocationData, invocationErr := json.MarshalIndent(invocation, "", "  ")
	if invocationErr != nil {
		writeErrors = append(writeErrors, invocationErr.Error())
	} else if err := incomingMaterialWALWriteExclusive(filepath.Join(artifactDirectory, "after-child.json"), invocationData); err != nil {
		writeErrors = append(writeErrors, err.Error())
	}
	require.Empty(t, writeErrors)
	require.NoError(t, runErr)
	require.NoError(t, contextErr)
	require.True(t, exited)
	require.Zero(t, exitCode)
	require.Empty(t, receiptRaw.Error)
	require.True(t, receiptRaw.Readable)
	require.NoError(t, receiptErr)
	expectedReceipt := incomingMaterialWALReceipt{Success: "public-a-only-upgrade-complete", SchemaVersion: 3, DatabaseID: before.metadata["database_id"], Revision: 0, Generation: 0, AttemptMutationRevision: 1, IncomingRefs: 0, PendingID: [16]byte{0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17}, UpgradeFromPositions: false, UpgradeFromAttempts: true}
	require.Equal(t, expectedReceipt, receipt)
	require.Len(t, observations, 3)
	for index, observation := range observations {
		if index == 2 && observation.Missing {
			continue
		}
		require.Empty(t, observation.Error, observation.Path)
		require.True(t, observation.Readable, observation.Path)
	}
	mainBeforeProbe := bytes.Clone(observations[0].Data)
	require.GreaterOrEqual(t, len(mainBeforeProbe), 100)
	require.Equal(t, []byte("SQLite format 3\x00"), mainBeforeProbe[:16])
	require.Equal(t, uint32(2), binary.BigEndian.Uint32(mainBeforeProbe[60:64]))
	require.Positive(t, observations[1].Size)
	require.NotEmpty(t, observations[1].Data)
	probe, probeErr := probeSchema(input.database, input.binding, input.options.PositionLimits, input.options.AttemptLimits)
	afterProbe := incomingMaterialWALReadRaw(input.database, 16<<20, true)
	var probeWriteErrors []string
	if afterProbe.Readable {
		path := filepath.Join(artifactDirectory, "after-probe-publication.db")
		if err := incomingMaterialWALWriteExclusive(path, afterProbe.Data); err != nil {
			probeWriteErrors = append(probeWriteErrors, err.Error())
		} else {
			afterProbe.Artifact = path
		}
	}
	probeError := ""
	if probeErr != nil {
		probeError = probeErr.Error()
	}
	probeData, marshalErr := json.MarshalIndent(map[string]any{"main": afterProbe, "probeError": probeError, "recognized": probe.recognized, "initial": probe.initial, "version": probe.version, "evidenceWriteErrors": probeWriteErrors}, "", "  ")
	if marshalErr != nil {
		probeWriteErrors = append(probeWriteErrors, marshalErr.Error())
	} else if err := incomingMaterialWALWriteExclusive(filepath.Join(artifactDirectory, "after-probe.json"), probeData); err != nil {
		probeWriteErrors = append(probeWriteErrors, err.Error())
	}
	require.Empty(t, probeWriteErrors)
	require.NoError(t, probeErr)
	require.True(t, probe.recognized)
	require.False(t, probe.initial)
	require.Equal(t, 3, probe.version)
	require.Empty(t, afterProbe.Error)
	require.True(t, afterProbe.Readable)
	require.Equal(t, mainBeforeProbe, afterProbe.Data)
	require.GreaterOrEqual(t, len(afterProbe.Data), 100)
	require.Equal(t, uint32(2), binary.BigEndian.Uint32(afterProbe.Data[60:64]))
	var destination publicationOpenSourceSnapshot
	ordinaryVersions := make([]int, 0, 2)
	for index := 0; index < 2; index++ {
		fd0 := publicationOpenFD0(t)
		store, err := Open(directory, binding)
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		publicationOpenRequireFD0(t, fd0)
		current, _ := incomingMaterialWALRequirePending(t, ctx, store, input)
		require.Equal(t, before.metadata, current.metadata)
		require.Equal(t, before.typed, current.typed)
		objects := incomingMaterialUpgradeFixtureObjects(t, ctx, store.conn)
		additions, autoIndexes := incomingMaterialUpgradeFixtureObjectAdditions(t, sourceObjects, objects)
		require.Equal(t, []string{"accepted_material_refs"}, additions)
		require.Zero(t, autoIndexes)
		if index == 0 {
			destination = current
		} else {
			require.Equal(t, destination, current)
		}
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireClosedResources(t, store, directory)
		publicationOpenRequireFD0(t, fd0)
		ordinaryVersions = append(ordinaryVersions, current.version)
	}
	require.Len(t, ordinaryVersions, 2)
	final := publicationOpenSnapshotSource(t, ctx, input.database, 3)
	require.Equal(t, destination, final)
	publicationOpenRequirePayloadPreserved(t, input, payload)
	summary, err := json.MarshalIndent(map[string]any{"success": "committed-wal-probe-and-ordinary-reopen-complete", "afterChild": "after-child.json", "afterProbe": "after-probe.json", "helperReceipt": "helper-receipt.json", "readonlyProbeVersion": probe.version, "ordinaryOpenCount": len(ordinaryVersions), "ordinaryOpenVersions": ordinaryVersions, "finalSchemaVersion": final.version, "databaseID": final.metadata["database_id"], "incomingTableCount": final.incomingTableCount, "incomingRefs": final.incomingRefCount, "payloadSHA256": payload.sha256}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, incomingMaterialWALWriteExclusive(filepath.Join(artifactDirectory, "summary.json"), summary))
}

func TestIncomingMaterialSchema3WALWriterHelper(t *testing.T) {
	directory, directorySet := os.LookupEnv("DOTTIE_P17_B7_WAL_HELPER_DIR")
	receiptPath, receiptSet := os.LookupEnv("DOTTIE_P17_B7_WAL_HELPER_RECEIPT")
	if !directorySet && !receiptSet {
		return
	}
	require.True(t, directorySet)
	require.True(t, receiptSet)
	incomingMaterialWALRequireContainedDirectory(t, directory, filepath.Clean(os.TempDir()))
	require.True(t, filepath.IsAbs(receiptPath))
	require.Equal(t, filepath.Clean(receiptPath), receiptPath)
	root, durable := os.LookupEnv("DOTTIE_P17_B7_WAL_EVIDENCE_ROOT")
	if durable {
		require.True(t, filepath.IsAbs(root))
		require.Equal(t, filepath.Clean(root), root)
		require.NoError(t, checkPrivateDirectory(root))
	} else {
		root = filepath.Clean(os.TempDir())
	}
	incomingMaterialWALRequireContainedDirectory(t, filepath.Dir(receiptPath), root)
	_, err := os.Lstat(receiptPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	binding := Binding{AccountDID: incomingMaterialUpgradeFixtureDID, Backend: BackendPublicRepo, Repository: "at://" + incomingMaterialUpgradeFixtureDID, Vault: [32]byte{9}}
	options := DefaultOpenOptions()
	options.UpgradeFromAttempts = true
	require.False(t, options.UpgradeFromPositions)
	require.True(t, options.UpgradeFromAttempts)
	require.Nil(t, options.openFault)
	require.Nil(t, options.upgradeFault)
	require.Nil(t, options.upgradeCommit)
	require.Nil(t, options.createdDatabaseChmod)
	require.NoError(t, validateBinding(binding))
	require.NoError(t, validateLimits(options.PositionLimits))
	require.NoError(t, validateAttemptLimits(options.AttemptLimits))
	input := publicationOpenInput{directory: directory, database: filepath.Join(directory, "publication.db"), binding: binding, options: options, payloadPath: filepath.Join(directory, "payloads", "f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea.payload"), payloadHash: "f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea"}
	main := incomingMaterialWALReadRaw(input.database, 16<<20, true)
	require.Empty(t, main.Error)
	require.True(t, main.Readable)
	require.Equal(t, "d2e446ca0e728ac4af1835c2d4e65c4809fb17f19ef9729f0cc305b87b45f108", main.SHA256)
	require.GreaterOrEqual(t, len(main.Data), 100)
	require.Equal(t, []byte("SQLite format 3\x00"), main.Data[:16])
	require.Equal(t, uint32(2), binary.BigEndian.Uint32(main.Data[60:64]))
	incomingMaterialWALRequireContainedDirectory(t, filepath.Join(directory, "payloads"), directory)
	publicationOpenRequirePrivateFile(t, input.payloadPath)
	payload := publicationOpenCapturePayload(t, input)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	fd0 := publicationOpenFD0(t)
	store, err := OpenWithOptions(directory, binding, options)
	if store != nil {
		t.Cleanup(func() {
			if incomingMaterialWALRetainedStore != store {
				assert.NoError(t, store.Close())
			}
		})
	}
	require.NoError(t, err)
	publicationOpenRequireFD0(t, fd0)
	destination, active := incomingMaterialWALRequirePending(t, ctx, store, input)
	publicationOpenRequirePayloadPreserved(t, input, payload)
	publicationOpenRequireFD0(t, fd0)
	receipt := incomingMaterialWALReceipt{Success: "public-a-only-upgrade-complete", SchemaVersion: store.schemaVersion, DatabaseID: bytes.Clone(store.databaseID[:]), Revision: binary.BigEndian.Uint64(destination.metadata["revision"]), Generation: binary.BigEndian.Uint64(destination.metadata["generation"]), AttemptMutationRevision: store.attemptMutationRevision, IncomingRefs: destination.incomingRefCount, PendingID: active.ID, UpgradeFromPositions: options.UpgradeFromPositions, UpgradeFromAttempts: options.UpgradeFromAttempts}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	require.NoError(t, err)
	require.NoError(t, incomingMaterialWALWriteExclusive(receiptPath, encoded))
	require.Nil(t, incomingMaterialWALRetainedStore)
	incomingMaterialWALRetainedStore = store
}

func incomingMaterialWALRequireContainedDirectory(t *testing.T, path, root string) {
	t.Helper()
	require.True(t, filepath.IsAbs(path))
	require.Equal(t, filepath.Clean(path), path)
	require.True(t, filepath.IsAbs(root))
	require.Equal(t, filepath.Clean(root), root)
	rootInfo, err := os.Lstat(root)
	require.NoError(t, err)
	require.True(t, rootInfo.IsDir())
	require.Zero(t, rootInfo.Mode()&os.ModeSymlink)
	relative, err := filepath.Rel(root, path)
	require.NoError(t, err)
	require.NotEqual(t, ".", relative)
	require.NotEqual(t, "..", relative)
	require.False(t, filepath.IsAbs(relative))
	require.False(t, strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
	current := root
	for _, part := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		require.NoError(t, checkPrivateDirectory(current))
	}
}

func incomingMaterialWALReadRaw(path string, limit int64, private bool) incomingMaterialWALRawObservation {
	observation := incomingMaterialWALRawObservation{Path: path}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		observation.Missing = errors.Is(err, os.ErrNotExist)
		observation.Error = "lstat: " + err.Error()
		return observation
	}
	observation.Exists = true
	observation.Regular = stat.Mode&unix.S_IFMT == unix.S_IFREG
	observation.Mode, observation.UID, observation.Nlink, observation.Size = stat.Mode, stat.Uid, stat.Nlink, stat.Size
	if !observation.Regular || (private && (stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&0o7777 != 0o600)) {
		observation.Error = "unsafe raw file type, owner, link count or permissions"
		return observation
	}
	if stat.Size < 0 || stat.Size > limit {
		observation.Error = "raw file exceeds the selected size bound"
		return observation
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		observation.Error = "open: " + err.Error()
		return observation
	}
	var opened unix.Stat_t
	readErr := unix.Fstat(fd, &opened)
	if readErr == nil && (opened.Dev != stat.Dev || opened.Ino != stat.Ino || opened.Mode != stat.Mode || opened.Uid != stat.Uid || opened.Nlink != stat.Nlink || opened.Size != stat.Size) {
		readErr = errors.New("raw file identity or properties changed before read")
	}
	var data []byte
	if readErr == nil {
		data = make([]byte, int(stat.Size))
		for offset := 0; offset < len(data); {
			count, err := unix.Read(fd, data[offset:])
			if err != nil {
				readErr = err
				break
			}
			if count <= 0 {
				readErr = errors.New("short raw file read")
				break
			}
			offset += count
		}
	}
	var after unix.Stat_t
	afterErr := unix.Fstat(fd, &after)
	if afterErr == nil && (after.Dev != stat.Dev || after.Ino != stat.Ino || after.Mode != stat.Mode || after.Uid != stat.Uid || after.Nlink != stat.Nlink || after.Size != stat.Size) {
		afterErr = errors.New("raw file identity or properties changed during read")
	}
	closeErr := unix.Close(fd)
	if readErr == nil && afterErr == nil {
		observation.Data = data
		observation.SHA256 = incomingMaterialUpgradeFixtureSHA256(data)
		observation.Readable = true
	}
	if err := errors.Join(readErr, afterErr, closeErr); err != nil {
		observation.Error = err.Error()
	}
	return observation
}

func incomingMaterialWALWriteExclusive(path string, data []byte) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	var writeErr error
	for offset := 0; offset < len(data); {
		count, err := unix.Write(fd, data[offset:])
		if err != nil {
			writeErr = err
			break
		}
		if count <= 0 {
			writeErr = errors.New("short exclusive artifact write")
			break
		}
		offset += count
	}
	syncErr := unix.Fsync(fd)
	var stat unix.Stat_t
	statErr := unix.Fstat(fd, &stat)
	if statErr == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size != int64(len(data))) {
		statErr = errors.New("exclusive artifact properties mismatch")
	}
	closeErr := unix.Close(fd)
	return errors.Join(writeErr, syncErr, statErr, closeErr)
}

func incomingMaterialWALRequirePending(t *testing.T, ctx context.Context, store *Store, input publicationOpenInput) (publicationOpenSourceSnapshot, Attempt) {
	t.Helper()
	metadata := publicationOpenRequireSchema3(t, ctx, store, input)
	require.Equal(t, incomingMaterialUpgradeFixtureHex(t, "61e438c87e5165a7218e18a9aaad2c651f0d3a095adc90acc5858a8973522c17"), store.databaseID[:])
	require.Equal(t, uint64Bytes(0), metadata["revision"])
	require.Equal(t, uint64Bytes(0), metadata["generation"])
	require.Equal(t, uint64Bytes(1), metadata["attempt_mutation_revision"])
	require.Equal(t, uint64(1), store.attemptMutationRevision)
	destination := publicationOpenCaptureDestination(t, ctx, store)
	require.Len(t, destination.typed, 15)
	require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(destination.typed))
	counts := map[string]int{"store_meta": 7, "publication_attempts": 1, "active_publication_attempt": 1, "pending_genesis": 1, "attempt_events": 1, "payload_objects": 1, "attempt_payload_refs": 1, "attempt_reservations": 1}
	for _, table := range incomingMaterialUpgradeFixtureTableNames {
		require.Contains(t, destination.typed, table)
		require.Len(t, destination.typed[table], counts[table], table)
	}
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, zeroFloor(), floor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Empty(t, history.Events)
	require.Empty(t, history.Records)
	require.False(t, history.HasMore)
	require.Zero(t, history.NextRevision)
	active, present, err := store.ActiveAttempt(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, [16]byte{0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x17}, active.ID)
	require.Equal(t, AttemptGenesis, active.Kind)
	require.Equal(t, AttemptPrepared, active.Lifecycle)
	require.Equal(t, OutcomeNotSubmitted, active.Outcome)
	require.NotEqual(t, [32]byte{}, active.StateDigest)
	loaded, err := store.LoadAttempt(ctx, active.ID)
	require.NoError(t, err)
	require.Equal(t, active, loaded)
	attempts, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Equal(t, []Attempt{active}, attempts.Attempts)
	require.Empty(t, attempts.Evidence)
	require.False(t, attempts.HasMore)
	require.Equal(t, active.ID, attempts.NextID)
	return destination, active
}
