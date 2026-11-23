package publicationstate

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lamb-systems/dottie/internal/publication"
)

const largeFileSetEntryCount = int(publication.MaxSnapshotEntries)

func largeFileSetPaths() []string {
	paths := make([]string, 0, largeFileSetEntryCount)
	for index := range largeFileSetEntryCount {
		paths = append(paths, fmt.Sprintf("d%02d.conf", index))
	}
	return paths
}

func oversizedFloorFileSetPaths() []string {
	paths := make([]string, 0, largeFileSetEntryCount)
	for index := range largeFileSetEntryCount {
		paths = append(paths, fmt.Sprintf("%03d-%s.lua", index, strings.Repeat("x", 1010)))
	}
	return paths
}

func newLargeFileSetFixture(t *testing.T) fileSetAttemptFixture {
	t.Helper()
	return newFileSetAttemptFixture(t, largeFileSetPaths())
}

func largeFileSetRecord(t *testing.T, f fileSetAttemptFixture) validatedRecord {
	t.Helper()
	record, err := publication.DecodeSnapshot(f.raw)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(f.raw)
	require.NoError(t, err)
	return validatedRecord{
		ref: RecordReference{Key: f.key, CID: recordCID, Sequence: record.PublicationSeq},
		raw: bytes.Clone(f.raw),
	}
}

func insertStoredRecord(t *testing.T, store *Store, table string, record validatedRecord) {
	t.Helper()
	_, err := store.conn.ExecContext(
		context.Background(),
		"INSERT INTO "+table+"(cid,record_key,sequence,raw,logical_bytes) VALUES(?,?,?,?,?)",
		record.ref.CID,
		record.ref.Key,
		int64(record.ref.Sequence),
		record.raw,
		int64(recordLogicalBytes(record)),
	)
	require.NoError(t, err)
}

func seedFileSetAcceptedPosition(t *testing.T, store *Store, f fileSetAttemptFixture) (Floor, []byte) {
	t.Helper()
	ctx := context.Background()
	record, err := publication.DecodeSnapshot(f.raw)
	require.NoError(t, err)
	recordCID, err := publication.RecordCID(f.raw)
	require.NoError(t, err)
	suppliedContext := SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}}
	setDigest := makeSetDigest([]SnapshotBlock{{Key: f.key, Raw: f.raw}})
	observationDigest, err := makeObservationDigest(store.binding, suppliedContext, f.head, setDigest)
	require.NoError(t, err)
	reference := RecordReference{Key: f.key, CID: recordCID, Sequence: record.PublicationSeq}
	floor := Floor{
		DatabaseID:        store.databaseID,
		Revision:          1,
		Generation:        1,
		Provenance:        ProvenanceFirst,
		AnchorCID:         bytes.Clone(recordCID),
		Binding:           store.binding,
		SuppliedContext:   suppliedContext,
		Head:              bytes.Clone(f.head),
		SnapshotKey:       f.key,
		Sequence:          record.PublicationSeq,
		PublicationID:     record.PublicationID,
		RecordCID:         bytes.Clone(recordCID),
		ObservationDigest: observationDigest,
		FileSet:           fileSetPayloadOf(record),
	}
	body, err := makeEventBody(
		ModeFirstUse,
		"",
		nil,
		floor,
		[]RecordReference{reference},
		"first_use",
		observationDigest,
		setDigest,
	)
	require.NoError(t, err)
	eventDigest := domainHash("systems.lamb.dottie.local-publication-event.v1", body)
	floor.AcceptedEventDigest = eventDigest
	encodedFloor, err := encodeFloor(floor)
	require.NoError(t, err)
	stored := validatedRecord{ref: reference, raw: bytes.Clone(f.raw)}
	_, err = store.conn.ExecContext(
		ctx,
		"INSERT INTO accepted_records(cid,record_key,sequence,raw,logical_bytes) VALUES(?,?,?,?,?)",
		reference.CID,
		reference.Key,
		int64(reference.Sequence),
		stored.raw,
		int64(recordLogicalBytes(stored)),
	)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(
		ctx,
		"INSERT INTO accepted_events(revision,mode,reason,stop,old_floor,new_floor,body,digest,logical_bytes) VALUES(1,?,?,?,NULL,?,?,?,?)",
		string(ModeFirstUse),
		"",
		"first_use",
		encodedFloor,
		body,
		eventDigest[:],
		int64(eventLogicalBytes(body, eventDigest[:], nil, encodedFloor, string(ModeFirstUse), "", "first_use")),
	)
	require.NoError(t, err)
	_, err = store.conn.ExecContext(ctx, "INSERT INTO active_floor(singleton,floor) VALUES(1,?)", encodedFloor)
	require.NoError(t, err)
	for _, key := range []string{"revision", "generation"} {
		_, err = store.conn.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key=?", uint64Bytes(1), key)
		require.NoError(t, err)
	}
	expected, err := decodeFloor(encodedFloor)
	require.NoError(t, err)
	return expected, encodedFloor
}

func TestFileSetAcceptedPositionLoadsAfterStoreReopen(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)
	record, err := publication.DecodeSnapshot(f.raw)
	require.NoError(t, err)
	require.Len(t, record.Entries, largeFileSetEntryCount)

	store, directory := newStore(t, fixture{t: t, binding: f.binding})
	expected, encodedFloor := seedFileSetAcceptedPosition(t, store, f)
	require.LessOrEqual(t, len(encodedFloor), 65536)

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, expected, loaded)
	require.NoError(t, store.Close())

	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	loaded, present, err = reopened.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, expected, loaded)
	state, err := reopened.readState(ctx, reopened.conn, StageLoad)
	require.NoError(t, err)
	require.NotNil(t, state.floor)
	assert.Equal(t, expected, *state.floor)
}

func TestFileSetAcceptedPositionRefusesOversizedFloor(t *testing.T) {
	ctx := context.Background()
	f := newFileSetAttemptFixture(t, oversizedFloorFileSetPaths())
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)

	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	_, encodedFloor := seedFileSetAcceptedPosition(t, store, f)
	require.Greater(t, len(encodedFloor), 65536)

	_, _, err := store.Load(ctx)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
}

func TestLargeFileSetRecordReadsThroughQueryAndVerify(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	record := largeFileSetRecord(t, f)
	require.Greater(t, len(record.raw), publication.MaxRecordBytes)

	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	insertStoredRecord(t, store, "accepted_records", record)
	insertStoredRecord(t, store, "cache_records", record)

	for _, table := range []string{"accepted_records", "cache_records"} {
		stored, err := store.queryRecord(ctx, store.conn, table, record.ref.CID, StageLoad)
		require.NoError(t, err, table)
		verified, err := store.verifyStoredRecord(stored, StageLoad)
		require.NoError(t, err, table)
		assert.Equal(t, record.ref, verified.ref, table)
		assert.Equal(t, record.raw, verified.raw, table)
	}
}

func TestStoredRecordAboveFileSetCeilingIsRefusedBeforeFetch(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	record := largeFileSetRecord(t, f)

	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	oversized := record
	oversized.raw = make([]byte, publication.MaxFileSetRecordBytes+1)
	insertStoredRecord(t, store, "accepted_records", oversized)

	_, err := store.queryRecord(ctx, store.conn, "accepted_records", record.ref.CID, StageLoad)
	requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
}

func oversizedPackedShapedRecord(t *testing.T) []byte {
	t.Helper()
	cast, err := publication.RawPayloadCID([]byte("synthetic packed payload"))
	require.NoError(t, err)
	blobCID, err := cid.Cast(cast)
	require.NoError(t, err)
	encoded, err := atdata.MarshalCBOR(map[string]any{
		"$type":          publication.SnapshotNSID,
		"schemaVersion":  publication.SchemaVersion,
		"vault":          make([]byte, 32),
		"publicationId":  make([]byte, 16),
		"publicationSeq": int64(0),
		"parent":         []byte{},
		"blob": atdata.Blob{
			Ref:      atdata.CIDLink(blobCID),
			MimeType: strings.Repeat("a", publication.MaxRecordBytes),
			Size:     1,
		},
	})
	require.NoError(t, err)
	return encoded
}

func TestPackedShapedRecordAbovePackedLimitIsRefused(t *testing.T) {
	ctx := context.Background()
	raw := oversizedPackedShapedRecord(t)
	require.Greater(t, len(raw), publication.MaxRecordBytes)
	require.LessOrEqual(t, len(raw), publication.MaxFileSetRecordBytes)

	_, err := publication.DecodeSnapshot(raw)
	require.Error(t, err)
	var violation *publication.ViolationError
	require.ErrorAs(t, err, &violation)
	assert.Equal(t, "record", violation.Field())
	assert.Equal(t, "size_limit", violation.Reason())

	f := newLargeFileSetFixture(t)
	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	packedCID, err := publication.RawPayloadCID(raw)
	require.NoError(t, err)
	key, err := publication.SequenceKey(0)
	require.NoError(t, err)
	packed := validatedRecord{ref: RecordReference{Key: key, CID: packedCID}, raw: raw}
	insertStoredRecord(t, store, "accepted_records", packed)
	insertStoredRecord(t, store, "cache_records", packed)

	for _, table := range []string{"accepted_records", "cache_records"} {
		stored, err := store.queryRecord(ctx, store.conn, table, packed.ref.CID, StageLoad)
		require.NoError(t, err, table)
		_, err = store.verifyStoredRecord(stored, StageLoad)
		requireErrorMetadata(t, err, ErrSchema, StageLoad, ReasonCorrupt)
	}

	_, err = validateSuppliedRepositoryView(
		SuppliedRepositoryView{
			Origin:          f.binding,
			Scope:           ViewScopeWholeRepository,
			SuppliedContext: SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
			Head:            f.head,
			Snapshots:       []SnapshotBlock{{Key: key, Raw: raw}},
		},
		f.binding,
		DefaultLimits(),
		false,
	)
	requireErrorMetadata(t, err, ErrInvalid, StageInput, ReasonRecordSet)
}

func TestVerifyAcceptedRecordsAuditsLargeFileSetReference(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	record := largeFileSetRecord(t, f)
	require.Greater(t, len(record.raw), publication.MaxRecordBytes)

	store, _ := newStore(t, fixture{t: t, binding: f.binding})
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	insertStoredRecord(t, store, "accepted_records", record)

	require.NoError(
		t,
		store.verifyAcceptedRecords(
			ctx,
			store.conn,
			map[string]bool{string(record.ref.CID): true},
			StageLoad,
		),
	)
	requireErrorMetadata(
		t,
		store.verifyAcceptedRecords(ctx, store.conn, map[string]bool{}, StageLoad),
		ErrSchema,
		StageLoad,
		ReasonCorrupt,
	)
}

func TestSuppliedViewAcceptsLargeFileSetBlock(t *testing.T) {
	f := newLargeFileSetFixture(t)
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)
	view, err := validateSuppliedRepositoryView(
		SuppliedRepositoryView{
			Origin:          f.binding,
			Scope:           ViewScopeWholeRepository,
			SuppliedContext: SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
			Head:            f.head,
			Snapshots:       []SnapshotBlock{{Key: f.key, Raw: f.raw}},
		},
		f.binding,
		DefaultLimits(),
		false,
	)
	require.NoError(t, err)
	require.Len(t, view.blocks, 1)
	assert.Equal(t, f.raw, view.blocks[0].raw)
	assert.Equal(t, f.key, view.blocks[0].ref.Key)
}

func TestLargeFileSetRecordReusesAcrossCapacityAndInsert(t *testing.T) {
	ctx := context.Background()
	f := newLargeFileSetFixture(t)
	record := largeFileSetRecord(t, f)
	require.Greater(t, len(record.raw), publication.MaxRecordBytes)
	logical := recordLogicalBytes(record)

	limits := DefaultLimits()
	limits.AcceptedRecordCount = 1
	limits.AcceptedEventCount = 1
	limits.AcceptedLogicalBytes = logical

	exact, _ := newStore(t, fixture{t: t, binding: f.binding}, limits)
	t.Cleanup(func() { assert.NoError(t, exact.Close()) })
	exactTx, err := exact.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = exactTx.Rollback() })
	require.NoError(
		t,
		exact.checkAcceptedCapacityWithReservation(ctx, exactTx, []validatedRecord{record}, 0, nil, StageAccept),
	)
	require.NoError(t, insertAcceptedRecord(ctx, exactTx, record))
	require.NoError(t, insertAcceptedRecord(ctx, exactTx, record))
	require.NoError(
		t,
		exact.checkAcceptedCapacityWithReservation(ctx, exactTx, []validatedRecord{record}, 0, nil, StageAccept),
	)
	require.NoError(t, exactTx.Commit())
	var count, storedBytes int64
	require.NoError(
		t,
		exact.conn.QueryRowContext(
			ctx,
			"SELECT COUNT(*),COALESCE(SUM(logical_bytes),0) FROM accepted_records",
		).Scan(&count, &storedBytes),
	)
	assert.Equal(t, int64(1), count)
	assert.Equal(t, int64(logical), storedBytes)

	limits.AcceptedLogicalBytes = logical - 1
	over, _ := newStore(t, fixture{t: t, binding: f.binding}, limits)
	t.Cleanup(func() { assert.NoError(t, over.Close()) })
	overTx, err := over.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = overTx.Rollback() })
	requireErrorMetadata(
		t,
		over.checkAcceptedCapacityWithReservation(ctx, overTx, []validatedRecord{record}, 0, nil, StageAccept),
		ErrLimit,
		StageAccept,
		ReasonCapacity,
	)
	require.NoError(t, insertAcceptedRecord(ctx, overTx, record))
	requireErrorMetadata(
		t,
		over.checkAcceptedCapacityWithReservation(ctx, overTx, []validatedRecord{record}, 0, nil, StageAccept),
		ErrLimit,
		StageAccept,
		ReasonCapacity,
	)
}

func TestObservationRefusesLargeFileSetWithTypedPayloadFormError(t *testing.T) {
	f := newLargeFileSetFixture(t)
	require.Greater(t, len(f.raw), publication.MaxRecordBytes)
	_, err := validateObservation(
		Observation{
			Origin:          f.binding,
			SuppliedContext: SuppliedContext{RepositoryRevision: "revision-1", RepositoryDigest: []byte{1, 2, 3}},
			Head:            f.head,
			Snapshots:       []SnapshotBlock{{Key: f.key, Raw: f.raw}},
		},
		f.binding,
		DefaultLimits(),
	)
	requireErrorMetadata(t, err, ErrUnsupported, StageInput, ReasonPayloadForm)
}
