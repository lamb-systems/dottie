package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSharedPayloadCapacityPreflightUsesTransactionWithoutDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	var root unix.Stat_t
	require.NoError(t, unix.Fstat(store.rootFD, &root))
	require.Equal(t, uint32(os.Geteuid()), root.Uid)
	require.Equal(t, uint32(unix.S_IFDIR|0o700), root.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, -1, store.payloadFD)
	requirePayloadDirectoryAbsent(t, directory)

	tx, restore := beginSharedCustodyTransaction(t, ctx, store)
	before, err := sharedCustodyLogicalRows(ctx, tx)
	require.NoError(t, err)
	require.Empty(t, before["payload_objects"])
	require.Empty(t, before["active_floor"])
	name := payloadBasename([]byte("small capacity probe"))
	err = store.checkPayloadCapacityWithQueryer(ctx, tx, name, 1, false)
	assert.NoError(t, err)
	assert.Equal(t, -1, store.payloadFD)
	assertSharedCustodyPayloadDirectoryAbsent(t, directory)
	after, snapshotErr := sharedCustodyLogicalRows(ctx, tx)
	assert.NoError(t, snapshotErr)
	if snapshotErr == nil {
		assert.True(t, reflect.DeepEqual(before, after))
	}

	restore()
	require.NoError(t, tx.Rollback())
}

func TestSharedPayloadPersistenceUsesTransactionAndPreservesReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	candidate := attemptCandidate(f, 0)
	blob := blobForCandidate(t, candidate)
	name := payloadBasename(candidate.Payload)
	require.NoError(t, publication.VerifyPayload(candidate.Payload, blob))
	_, err := publication.DecodePayload(candidate.Payload, blob)
	require.NoError(t, err)
	canonicalName, err := payloadBasenameFromCID(blob.CID)
	require.NoError(t, err)
	require.Equal(t, name, canonicalName)

	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	require.Equal(t, -1, store.payloadFD)
	requirePayloadDirectoryAbsent(t, directory)

	tx, restore := beginSharedCustodyTransaction(t, ctx, store)
	before, err := sharedCustodyLogicalRows(ctx, tx)
	require.NoError(t, err)
	require.Empty(t, before["payload_objects"])
	require.Empty(t, before["publication_attempts"])
	require.Empty(t, before["attempt_payload_refs"])
	require.Empty(t, before["retained_publications"])
	freshName, freshBytes, persistErr := store.persistPayload(ctx, tx, candidate.Payload, blob, name)
	assert.NoError(t, persistErr)
	assert.Equal(t, name, freshName)
	assert.True(t, bytes.Equal(candidate.Payload, freshBytes))
	assert.GreaterOrEqual(t, store.payloadFD, 0)
	freshDevice, freshInode := assertSharedCustodyPayloadFile(t, filepath.Join(directory, payloadDirectoryName, name), candidate.Payload)

	orphanName, orphanBytes, orphanErr := store.persistPayload(ctx, tx, candidate.Payload, blob, name)
	assert.NoError(t, orphanErr)
	assert.Equal(t, name, orphanName)
	assert.Nil(t, orphanBytes)
	orphanDevice, orphanInode := assertSharedCustodyPayloadFile(t, filepath.Join(directory, payloadDirectoryName, name), candidate.Payload)
	assert.Equal(t, freshDevice, orphanDevice)
	assert.Equal(t, freshInode, orphanInode)
	after, snapshotErr := sharedCustodyLogicalRows(ctx, tx)
	assert.NoError(t, snapshotErr)
	if snapshotErr == nil {
		assert.True(t, reflect.DeepEqual(before, after))
	}
	restore()
	require.NoError(t, tx.Rollback())
	assertNoSharedCustodyPublicPosition(t, ctx, store)

	view := attemptView(f, f.observation(1), true)
	review := attemptReview()
	proposal, err := store.PrepareAttempt(ctx, candidate, view, review)
	require.NoError(t, err)
	attempt, err := store.CreateAttempt(ctx, proposal.StateToken, candidate, view, review, proposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, proposal.AttemptID, attempt.ID)
	assertSharedCustodyPayloadFile(t, filepath.Join(directory, payloadDirectoryName, name), candidate.Payload)

	catalogTx, restoreCatalog := beginSharedCustodyTransaction(t, ctx, store)
	catalogBefore, err := sharedCustodyLogicalRows(ctx, catalogTx)
	require.NoError(t, err)
	require.Len(t, catalogBefore["payload_objects"], 1)
	require.Len(t, catalogBefore["publication_attempts"], 1)
	require.Len(t, catalogBefore["attempt_payload_refs"], 1)
	require.GreaterOrEqual(t, store.payloadFD, 0)
	capacityErr := store.checkPayloadCapacityWithQueryer(ctx, catalogTx, name, blob.Size, false)
	assert.NoError(t, capacityErr)
	catalogName, catalogBytes, catalogErr := store.persistPayload(ctx, catalogTx, candidate.Payload, blob, name)
	assert.NoError(t, catalogErr)
	assert.Equal(t, name, catalogName)
	assert.Nil(t, catalogBytes)
	catalogDevice, catalogInode := assertSharedCustodyPayloadFile(t, filepath.Join(directory, payloadDirectoryName, name), candidate.Payload)
	assert.Equal(t, freshDevice, catalogDevice)
	assert.Equal(t, freshInode, catalogInode)
	catalogAfter, catalogSnapshotErr := sharedCustodyLogicalRows(ctx, catalogTx)
	assert.NoError(t, catalogSnapshotErr)
	if catalogSnapshotErr == nil {
		assert.True(t, reflect.DeepEqual(catalogBefore, catalogAfter))
	}
	restoreCatalog()
	require.NoError(t, catalogTx.Rollback())

	loaded, err := store.ReadCandidate(ctx, attempt.ID)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(candidate.SnapshotRecord, loaded.SnapshotRecord))
	assert.True(t, bytes.Equal(candidate.HeadRecord, loaded.HeadRecord))
	assert.True(t, bytes.Equal(candidate.Payload, loaded.Payload))
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	assert.Equal(t, Floor{}, floor)
}

func TestSharedPayloadPersistenceRejectsInvalidInputBeforeFilesystem(t *testing.T) {
	for _, caseName := range []string{"size-mismatch", "unsupported-cid", "wrong-cid-name", "wrong-name", "correct-cid-malformed-packed"} {
		t.Run(caseName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			candidate := attemptCandidate(f, 0)
			payload := bytes.Clone(candidate.Payload)
			blob := blobForCandidate(t, candidate)
			name := payloadBasename(payload)
			require.NotEmpty(t, payload)
			require.Equal(t, uint64(len(payload)), blob.Size)
			require.NoError(t, publication.VerifyPayload(payload, blob))
			_, err := publication.DecodePayload(payload, blob)
			require.NoError(t, err)
			canonicalName, err := payloadBasenameFromCID(blob.CID)
			require.NoError(t, err)
			require.Equal(t, name, canonicalName)

			switch caseName {
			case "size-mismatch":
				blob.Size++
			case "unsupported-cid":
				unsupportedCID, cidErr := publication.RecordCID(candidate.SnapshotRecord)
				require.NoError(t, cidErr)
				_, nameErr := payloadBasenameFromCID(unsupportedCID)
				require.Error(t, nameErr)
				blob = publication.BlobReference{CID: unsupportedCID, Size: uint64(len(payload))}
			case "wrong-cid-name":
				otherPayload := []byte("different small synthetic blob")
				wrongCID, cidErr := publication.RawPayloadCID(otherPayload)
				require.NoError(t, cidErr)
				wrongName, nameErr := payloadBasenameFromCID(wrongCID)
				require.NoError(t, nameErr)
				require.NotEqual(t, name, wrongName)
				blob = publication.BlobReference{CID: wrongCID, Size: uint64(len(payload))}
			case "wrong-name":
				name = payloadBasename([]byte("different canonical name"))
				require.True(t, validPayloadBasename(name))
				require.NotEqual(t, payloadBasename(payload), name)
			case "correct-cid-malformed-packed":
				payload = []byte("not a packed payload")
				cid, cidErr := publication.RawPayloadCID(payload)
				require.NoError(t, cidErr)
				blob = publication.BlobReference{CID: cid, Size: uint64(len(payload))}
				name, err = payloadBasenameFromCID(cid)
				require.NoError(t, err)
				require.Equal(t, payloadBasename(payload), name)
				require.NoError(t, publication.VerifyPayload(payload, blob))
				_, decodeErr := publication.DecodePayload(payload, blob)
				require.Error(t, decodeErr)
			default:
				require.FailNow(t, "unexpected invalid-payload case")
			}

			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			require.Equal(t, -1, store.payloadFD)
			requirePayloadDirectoryAbsent(t, directory)
			before, err := sharedCustodyLogicalRows(ctx, store.conn)
			require.NoError(t, err)
			require.Empty(t, before["payload_objects"])
			require.Empty(t, before["publication_attempts"])
			require.Empty(t, before["attempt_payload_refs"])
			require.Empty(t, before["retained_publications"])
			assertNoSharedCustodyPublicPosition(t, ctx, store)

			gotName, gotBytes, persistErr := store.persistPayload(ctx, store.conn, payload, blob, name)
			assert.Equal(t, "", gotName)
			assert.Nil(t, gotBytes)
			assert.Equal(t, -1, store.payloadFD)
			assertSharedCustodyPayloadDirectoryAbsent(t, directory)
			after, snapshotErr := sharedCustodyLogicalRows(ctx, store.conn)
			assert.NoError(t, snapshotErr)
			if snapshotErr == nil {
				assert.True(t, reflect.DeepEqual(before, after))
			}
			assertNoSharedCustodyPublicPosition(t, ctx, store)
			assert.ErrorIs(t, persistErr, errInvalidPayloadInput)
		})
	}
}

func beginSharedCustodyTransaction(t *testing.T, ctx context.Context, store *Store) (*sql.Tx, func()) {
	t.Helper()
	original := store.conn
	var tx *sql.Tx
	var decoyDB *sql.DB
	restore := func() { store.conn = original }
	t.Cleanup(func() {
		restore()
		if tx != nil {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				assert.NoError(t, err)
			}
		}
		if decoyDB != nil {
			assert.NoError(t, decoyDB.Close())
		}
	})

	var err error
	tx, err = original.BeginTx(ctx, nil)
	require.NoError(t, err)
	decoyDB, err = sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	decoyDB.SetMaxOpenConns(1)
	decoyConn, err := decoyDB.Conn(ctx)
	require.NoError(t, err)
	require.NoError(t, decoyConn.Close())
	store.conn = decoyConn
	return tx, restore
}

func sharedCustodyLogicalRows(ctx context.Context, q queryer) (map[string][][]any, error) {
	tables := []struct {
		name    string
		orderBy string
	}{
		{"store_meta", "key"},
		{"cache_records", "cid"},
		{"cache_observations", "observation_id"},
		{"accepted_records", "cid"},
		{"accepted_events", "revision"},
		{"active_floor", "singleton"},
		{"publication_attempts", "attempt_id"},
		{"active_publication_attempt", "singleton"},
		{"pending_genesis", "singleton"},
		{"attempt_events", "attempt_id,ordinal"},
		{"attempt_evidence", "attempt_id,role"},
		{"payload_objects", "blob_cid"},
		{"attempt_payload_refs", "attempt_id"},
		{"retained_publications", "record_cid"},
		{"attempt_reservations", "attempt_id"},
	}
	result := make(map[string][][]any, len(tables))
	for _, table := range tables {
		rows, err := q.QueryContext(ctx, "SELECT * FROM "+table.name+" ORDER BY "+table.orderBy)
		if err != nil {
			return nil, err
		}
		columns, err := rows.Columns()
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		tableRows := make([][]any, 0)
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(values))
			for index := range values {
				destinations[index] = &values[index]
			}
			if err := rows.Scan(destinations...); err != nil {
				_ = rows.Close()
				return nil, err
			}
			tableRows = append(tableRows, values)
		}
		rowsErr := rows.Err()
		closeErr := rows.Close()
		if rowsErr != nil {
			return nil, rowsErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		result[table.name] = tableRows
	}
	return result, nil
}

func requirePayloadDirectoryAbsent(t *testing.T, directory string) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(directory, payloadDirectoryName))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func assertSharedCustodyPayloadDirectoryAbsent(t *testing.T, directory string) {
	t.Helper()
	_, err := os.Lstat(filepath.Join(directory, payloadDirectoryName))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func assertSharedCustodyPayloadFile(t *testing.T, path string, expected []byte) (uint64, uint64) {
	t.Helper()
	actual, err := observeAcceptedMaterialPayloadFile(path, len(expected))
	require.NoError(t, err)
	require.True(t, actual.Exists)
	assert.True(t, bytes.Equal(expected, actual.Bytes))
	assert.Equal(t, uint32(unix.S_IFREG|0o600), actual.Mode&uint32(unix.S_IFMT|0o777))
	assert.Equal(t, uint32(os.Geteuid()), actual.UID)
	assert.Equal(t, uint64(1), actual.Nlink)
	assert.Equal(t, int64(len(expected)), actual.Size)
	return actual.Device, actual.Inode
}

func assertNoSharedCustodyPublicPosition(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	floor, present, err := store.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, Floor{}, floor)
	assert.False(t, present)
	history, err := store.History(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Empty(t, history.Events)
	assert.False(t, history.HasMore)
}
