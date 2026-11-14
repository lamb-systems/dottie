package publicationstate

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func incomingCapacityAppendDistinctRecord(t *testing.T, f *fixture, sequence uint64, content []byte) []byte {
	t.Helper()
	require.Equal(t, uint64(len(f.blocks)), sequence)
	var parent []byte
	if sequence > 0 {
		cid, err := publication.RecordCID(f.blocks[sequence-1].Raw)
		require.NoError(t, err)
		parent = cid
	}
	payload := packFixtureContent(t, f.payload, content)
	blobCID, err := publication.RawPayloadCID(payload)
	require.NoError(t, err)
	record := publication.SnapshotRecord{SchemaVersion: publication.SchemaVersion, Vault: f.binding.Vault, PublicationSeq: sequence, Parent: parent, Blob: publication.BlobReference{CID: blobCID, Size: uint64(len(payload))}}
	binary.BigEndian.PutUint64(record.PublicationID[8:], sequence+1)
	raw, err := publication.EncodeSnapshot(record)
	require.NoError(t, err)
	key, err := publication.SequenceKey(sequence)
	require.NoError(t, err)
	f.blocks = append(f.blocks, SnapshotBlock{Key: key, Raw: raw})
	return payload
}

func TestAcceptMaterialObjectCapacityAdmitsExactBoundary(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	payloadA := incomingCapacityAppendDistinctRecord(t, &f, 0, []byte("synthetic object boundary payload alpha"))
	payloadB := incomingCapacityAppendDistinctRecord(t, &f, 1, []byte("synthetic object boundary payload beta"))
	require.NotEqual(t, payloadA, payloadB)
	nameA := payloadBasename(payloadA)
	nameB := payloadBasename(payloadB)
	require.NotEqual(t, nameA, nameB)
	sizeA := uint64(len(payloadA))
	sizeB := uint64(len(payloadB))
	require.Positive(t, sizeA)
	require.Positive(t, sizeB)

	attemptLimits := DefaultAttemptLimits()
	attemptLimits.ManagedObjects = 2
	require.Equal(t, uint32(2), attemptLimits.ManagedObjects)
	require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeA+sizeB)
	store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)

	firstObservation := f.observation(1)
	firstProposal := prepareFirstUse(t, store, firstObservation, payloadA)
	first, err := store.acceptMaterial(ctx, ModeFirstUse, firstProposal.StateToken, firstObservation, payloadA, firstProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Revision)
	inventory, total, err := store.inventoryPayloads()
	require.NoError(t, err)
	assert.Equal(t, map[string]uint64{nameA: sizeA}, inventory)
	assert.Equal(t, sizeA, total)

	advanceObservation := f.observation(2)
	advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, payloadB)
	require.NoError(t, err)
	require.Equal(t, "joined", advanceProposal.Stop)
	second, err := store.acceptMaterial(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, payloadB, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, first.Revision+1, second.Revision)
	assert.Equal(t, first.Generation, second.Generation)

	inventory, total, err = store.inventoryPayloads()
	require.NoError(t, err)
	assert.Equal(t, attemptLimits.ManagedObjects, uint32(len(inventory)))
	assert.Equal(t, map[string]uint64{nameA: sizeA, nameB: sizeB}, inventory)
	assert.Equal(t, sizeA+sizeB, total)

	names := readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, attemptLimits.ManagedObjects)
	wantNames := []string{nameA, nameB}
	sort.Strings(wantNames)
	assert.Equal(t, wantNames, names)
	for _, payload := range [][]byte{payloadA, payloadB} {
		file, err := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, payloadBasename(payload)), len(payload))
		require.NoError(t, err)
		require.True(t, file.Exists)
		assert.Equal(t, payload, file.Bytes)
		assert.Equal(t, uint32(unix.S_IFREG|0o600), file.Mode&uint32(unix.S_IFMT|0o777))
		assert.Equal(t, uint32(os.Geteuid()), file.UID)
		assert.Equal(t, uint64(1), file.Nlink)
	}

	assert.Equal(t, int64(len(inventory)), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	assert.Equal(t, int64(total), b8Count(t, ctx, store.conn, "SELECT COALESCE(SUM(size),0) FROM payload_objects"))
	for name, size := range inventory {
		assert.Equal(t, int64(size), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", name))
	}

	references := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, references, 2)
	assert.Equal(t, []any{int64(first.Revision), first.RecordCID, first.BlobCID}, references[0])
	assert.Equal(t, []any{int64(second.Revision), second.RecordCID, second.BlobCID}, references[1])
	assert.NotEqual(t, references[0][2], references[1][2])
	require.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, second, loaded)
}

func TestAcceptMaterialObjectCapacityRefusalPreservesState(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	payloadA := incomingCapacityAppendDistinctRecord(t, &f, 0, []byte("synthetic object refusal payload alpha"))
	payloadB := incomingCapacityAppendDistinctRecord(t, &f, 1, []byte("synthetic object refusal payload beta"))
	require.NotEqual(t, payloadA, payloadB)
	nameA := payloadBasename(payloadA)
	nameB := payloadBasename(payloadB)
	require.NotEqual(t, nameA, nameB)
	sizeA := uint64(len(payloadA))
	sizeB := uint64(len(payloadB))
	require.Positive(t, sizeA)
	require.Positive(t, sizeB)

	attemptLimits := DefaultAttemptLimits()
	attemptLimits.ManagedObjects = 1
	require.Equal(t, uint32(1), attemptLimits.ManagedObjects)
	require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeA)
	require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeB)
	require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeA+sizeB)
	store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	payloadPathA := filepath.Join(payloadDirectory, nameA)

	firstObservation := f.observation(1)
	firstProposal := prepareFirstUse(t, store, firstObservation, payloadA)
	first, err := store.acceptMaterial(ctx, ModeFirstUse, firstProposal.StateToken, firstObservation, payloadA, firstProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Revision)

	beforeFile, err := observeAcceptedMaterialPayloadFile(payloadPathA, len(payloadA))
	require.NoError(t, err)
	require.True(t, beforeFile.Exists)
	require.Equal(t, payloadA, beforeFile.Bytes)
	beforeRows := readLogicalRows(t, store.conn)
	beforeReferences := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, beforeReferences, 1)
	beforeInventory, beforeTotal, err := store.inventoryPayloads()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{nameA: sizeA}, beforeInventory)
	require.Equal(t, sizeA, beforeTotal)
	beforeLoaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, first, beforeLoaded)

	advanceObservation := f.observation(2)
	require.NotEqual(t, firstObservation.Head, advanceObservation.Head)
	advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, payloadB)
	require.NoError(t, err)
	require.Equal(t, "joined", advanceProposal.Stop)
	floor, err := store.acceptMaterial(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, payloadB, [32]byte{})
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrLimit, stageAcceptMaterial, ReasonCapacity)

	afterFile, err := observeAcceptedMaterialPayloadFile(payloadPathA, len(payloadA))
	require.NoError(t, err)
	assert.Equal(t, beforeFile, afterFile)
	absentB, err := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameB), len(payloadB))
	require.NoError(t, err)
	assert.False(t, absentB.Exists)
	assert.Equal(t, []string{nameA}, readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, attemptLimits.ManagedObjects))

	assert.Equal(t, beforeRows, readLogicalRows(t, store.conn))
	assert.Equal(t, beforeReferences, b8IncomingRows(t, ctx, store.conn))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", nameB))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Equal(t, int64(sizeA), b8Count(t, ctx, store.conn, "SELECT COALESCE(SUM(size),0) FROM payload_objects"))
	require.Equal(t, int64(sizeA), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", nameA))
	afterInventory, afterTotal, err := store.inventoryPayloads()
	require.NoError(t, err)
	assert.Equal(t, beforeInventory, afterInventory)
	assert.Equal(t, beforeTotal, afterTotal)

	afterLoaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, first, afterLoaded)
}

func TestAcceptMaterialAggregateByteCapacityBoundary(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	payloadA := incomingCapacityAppendDistinctRecord(t, &f, 0, []byte("synthetic aggregate boundary payload alpha"))
	payloadB := incomingCapacityAppendDistinctRecord(t, &f, 1, []byte("synthetic aggregate boundary payload beta"))
	require.NotEqual(t, payloadA, payloadB)
	nameA := payloadBasename(payloadA)
	nameB := payloadBasename(payloadB)
	require.NotEqual(t, nameA, nameB)
	sizeA := uint64(len(payloadA))
	sizeB := uint64(len(payloadB))
	require.Positive(t, sizeA)
	require.Positive(t, sizeB)
	aggregateBytes := sizeA + sizeB
	require.Greater(t, aggregateBytes, sizeA)
	require.Greater(t, aggregateBytes, sizeB)
	require.LessOrEqual(t, aggregateBytes, DefaultAttemptLimits().CustodyBytes)

	t.Run("aggregate equal to bound admitted", func(t *testing.T) {
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.CustodyBytes = aggregateBytes
		require.Greater(t, attemptLimits.ManagedObjects, uint32(2))
		require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeA)
		require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeB)
		store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		payloadDirectory := filepath.Join(directory, payloadDirectoryName)

		firstObservation := f.observation(1)
		firstProposal := prepareFirstUse(t, store, firstObservation, payloadA)
		first, err := store.acceptMaterial(ctx, ModeFirstUse, firstProposal.StateToken, firstObservation, payloadA, firstProposal.Confirmation)
		require.NoError(t, err)
		inventory, total, err := store.inventoryPayloads()
		require.NoError(t, err)
		assert.Equal(t, map[string]uint64{nameA: sizeA}, inventory)
		assert.Equal(t, sizeA, total)

		advanceObservation := f.observation(2)
		advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, payloadB)
		require.NoError(t, err)
		require.Equal(t, "joined", advanceProposal.Stop)
		second, err := store.acceptMaterial(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, payloadB, [32]byte{})
		require.NoError(t, err)
		assert.Equal(t, first.Revision+1, second.Revision)
		assert.Equal(t, first.Generation, second.Generation)

		inventory, total, err = store.inventoryPayloads()
		require.NoError(t, err)
		assert.Equal(t, map[string]uint64{nameA: sizeA, nameB: sizeB}, inventory)
		assert.Equal(t, attemptLimits.CustodyBytes, total)
		assert.Equal(t, aggregateBytes, total)
		assert.Equal(t, int64(len(inventory)), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		assert.Equal(t, int64(total), b8Count(t, ctx, store.conn, "SELECT COALESCE(SUM(size),0) FROM payload_objects"))
		for name, size := range inventory {
			assert.Equal(t, int64(size), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", name))
		}

		names := readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, attemptLimits.ManagedObjects)
		wantNames := []string{nameA, nameB}
		sort.Strings(wantNames)
		assert.Equal(t, wantNames, names)
		references := b8IncomingRows(t, ctx, store.conn)
		require.Len(t, references, 2)
		assert.Equal(t, []any{int64(first.Revision), first.RecordCID, first.BlobCID}, references[0])
		assert.Equal(t, []any{int64(second.Revision), second.RecordCID, second.BlobCID}, references[1])

		loaded, present, err := store.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		assert.Equal(t, second, loaded)
	})

	t.Run("aggregate one byte over refused", func(t *testing.T) {
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.CustodyBytes = aggregateBytes - 1
		require.Equal(t, sizeA+sizeB-1, attemptLimits.CustodyBytes)
		require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeA)
		require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeB)
		require.Greater(t, attemptLimits.ManagedObjects, uint32(2))
		store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
		t.Cleanup(func() { assert.NoError(t, store.Close()) })
		payloadDirectory := filepath.Join(directory, payloadDirectoryName)

		firstObservation := f.observation(1)
		firstProposal := prepareFirstUse(t, store, firstObservation, payloadA)
		first, err := store.acceptMaterial(ctx, ModeFirstUse, firstProposal.StateToken, firstObservation, payloadA, firstProposal.Confirmation)
		require.NoError(t, err)
		require.Equal(t, uint64(1), first.Revision)
		inventory, total, err := store.inventoryPayloads()
		require.NoError(t, err)
		assert.Equal(t, map[string]uint64{nameA: sizeA}, inventory)
		assert.Equal(t, sizeA, total)

		advanceObservation := f.observation(2)
		advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, payloadB)
		require.NoError(t, err)
		require.Equal(t, "joined", advanceProposal.Stop)
		floor, err := store.acceptMaterial(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, payloadB, [32]byte{})
		assert.Equal(t, Floor{}, floor)
		requireErrorMetadata(t, err, ErrLimit, stageAcceptMaterial, ReasonCapacity)

		afterInventory, afterTotal, err := store.inventoryPayloads()
		require.NoError(t, err)
		assert.Equal(t, map[string]uint64{nameA: sizeA}, afterInventory)
		assert.Equal(t, sizeA, afterTotal)
		assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
		assert.Equal(t, int64(sizeA), b8Count(t, ctx, store.conn, "SELECT COALESCE(SUM(size),0) FROM payload_objects"))
		assert.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", nameB))
		assert.Equal(t, []string{nameA}, readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, attemptLimits.ManagedObjects))
		absentB, err := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameB), len(payloadB))
		require.NoError(t, err)
		assert.False(t, absentB.Exists)
		references := b8IncomingRows(t, ctx, store.conn)
		require.Len(t, references, 1)
		assert.Equal(t, []any{int64(first.Revision), first.RecordCID, first.BlobCID}, references[0])
		assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
		assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))

		loaded, present, err := store.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		assert.Equal(t, first, loaded)
	})
}

func TestAcceptMaterialCataloguedReuseNotChargedTwice(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	for sequence := uint64(0); sequence < 3; sequence++ {
		f.appendRecord(t, sequence)
	}
	require.Len(t, f.blocks, 3)
	payload := f.payload
	name := payloadBasename(payload)
	size := uint64(len(payload))
	require.Positive(t, size)

	attemptLimits := DefaultAttemptLimits()
	attemptLimits.ManagedObjects = 1
	attemptLimits.CustodyBytes = size
	require.Equal(t, uint32(1), attemptLimits.ManagedObjects)
	require.Equal(t, size, attemptLimits.CustodyBytes)
	store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)

	firstObservation := f.observation(1)
	firstProposal := prepareFirstUse(t, store, firstObservation, payload)
	first, err := store.acceptMaterial(ctx, ModeFirstUse, firstProposal.StateToken, firstObservation, payload, firstProposal.Confirmation)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Revision)
	previous := first
	middle := first
	for sequence := 1; sequence < 3; sequence++ {
		advanceObservation := f.observation(sequence + 1)
		advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, payload)
		require.NoError(t, err)
		require.Equal(t, "joined", advanceProposal.Stop)
		floor, err := store.acceptMaterial(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, payload, [32]byte{})
		require.NoError(t, err)
		assert.Equal(t, previous.Revision+1, floor.Revision)
		assert.Equal(t, previous.Generation, floor.Generation)
		middle = previous
		previous = floor
	}

	inventory, total, err := store.inventoryPayloads()
	require.NoError(t, err)
	assert.Equal(t, attemptLimits.ManagedObjects, uint32(len(inventory)))
	assert.Equal(t, map[string]uint64{name: size}, inventory)
	assert.Equal(t, size, total)
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	assert.Equal(t, int64(size), b8Count(t, ctx, store.conn, "SELECT COALESCE(SUM(size),0) FROM payload_objects"))
	assert.Equal(t, int64(size), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", name))
	assert.Equal(t, []string{name}, readAcceptedMaterialCapacityDirectoryNames(t, payloadDirectory, attemptLimits.ManagedObjects))
	file, err := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, name), len(payload))
	require.NoError(t, err)
	require.True(t, file.Exists)
	assert.Equal(t, payload, file.Bytes)
	assert.Equal(t, int64(size), file.Size)

	references := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, references, 3)
	assert.Equal(t, []any{int64(first.Revision), first.RecordCID, first.BlobCID}, references[0])
	assert.Equal(t, []any{int64(middle.Revision), middle.RecordCID, middle.BlobCID}, references[1])
	assert.Equal(t, []any{int64(previous.Revision), previous.RecordCID, previous.BlobCID}, references[2])
	assert.Equal(t, first.BlobCID, references[2][2])
	require.Equal(t, int64(3), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))

	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, previous, loaded)
}
