package publicationstate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func incomingCustodyPlaceOrphan(t *testing.T, directory string, payload []byte) string {
	t.Helper()
	payloadDirectory := filepath.Join(directory, payloadDirectoryName)
	require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
	name := payloadBasename(payload)
	require.NoError(t, os.WriteFile(filepath.Join(payloadDirectory, name), payload, 0o600))
	return name
}

func TestAcceptMaterialRefusesUnsafePayloadObject(t *testing.T) {
	for _, damage := range []string{"mode", "fifo", "hardlink"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			name := incomingCustodyPlaceOrphan(t, directory, f.payload)
			path := filepath.Join(directory, payloadDirectoryName, name)
			placed, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
			require.NoError(t, err)
			require.True(t, placed.Exists)
			require.Equal(t, f.payload, placed.Bytes)
			var wantType uint32
			var wantMode uint32
			var wantLinks uint64
			secondLink := ""
			switch damage {
			case "mode":
				require.NoError(t, os.Chmod(path, 0o644))
				wantType, wantMode, wantLinks = unix.S_IFREG, 0o644, 1
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, syscall.Mkfifo(path, 0o600))
				wantType, wantMode, wantLinks = unix.S_IFIFO, 0o600, 1
			case "hardlink":
				secondLink = filepath.Join(t.TempDir(), "second-link")
				require.NoError(t, os.Link(path, secondLink))
				wantType, wantMode, wantLinks = unix.S_IFREG, 0o600, 2
			default:
				require.FailNow(t, "unexpected damage case")
			}

			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			floor, err := store.AcceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrLimit, StageAcceptMaterial, ReasonCapacity)

			var damaged unix.Stat_t
			require.NoError(t, unix.Lstat(path, &damaged))
			assert.Equal(t, wantType, damaged.Mode&unix.S_IFMT)
			assert.Equal(t, wantMode, damaged.Mode&0o777)
			assert.Equal(t, wantLinks, uint64(damaged.Nlink))
			entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, name, entries[0].Name())
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
			loaded, present, err := store.Load(ctx)
			require.NoError(t, err)
			assert.Equal(t, Floor{}, loaded)
			assert.False(t, present)

			switch damage {
			case "mode":
				require.NoError(t, os.Chmod(path, 0o600))
			case "fifo":
				require.NoError(t, os.Remove(path))
			case "hardlink":
				require.NoError(t, os.Remove(secondLink))
			}
		})
	}
}

func TestAcceptMaterialRefusesUnsafePayloadDirectory(t *testing.T) {
	for _, damage := range []string{"mode", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			payloadDirectory := filepath.Join(directory, payloadDirectoryName)
			target := ""
			switch damage {
			case "mode":
				require.NoError(t, os.Mkdir(payloadDirectory, 0o700))
				require.NoError(t, os.Chmod(payloadDirectory, 0o755))
			case "symlink":
				target = t.TempDir()
				require.NoError(t, os.Chmod(target, 0o700))
				require.NoError(t, os.Symlink(target, payloadDirectory))
			default:
				require.FailNow(t, "unexpected damage case")
			}

			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			floor, err := store.AcceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrLimit, StageAcceptMaterial, ReasonCapacity)

			var damaged unix.Stat_t
			require.NoError(t, unix.Lstat(payloadDirectory, &damaged))
			switch damage {
			case "mode":
				assert.Equal(t, uint32(unix.S_IFDIR), damaged.Mode&unix.S_IFMT)
				assert.Equal(t, uint32(0o755), damaged.Mode&0o777)
				entries, readErr := os.ReadDir(payloadDirectory)
				require.NoError(t, readErr)
				assert.Empty(t, entries)
				require.NoError(t, os.Chmod(payloadDirectory, 0o700))
			case "symlink":
				assert.Equal(t, uint32(unix.S_IFLNK), damaged.Mode&unix.S_IFMT)
				link, readErr := os.Readlink(payloadDirectory)
				require.NoError(t, readErr)
				assert.Equal(t, target, link)
				entries, readErr := os.ReadDir(target)
				require.NoError(t, readErr)
				assert.Empty(t, entries)
				require.NoError(t, os.Remove(payloadDirectory))
			}
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
			require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
			loaded, present, err := store.Load(ctx)
			require.NoError(t, err)
			assert.Equal(t, Floor{}, loaded)
			assert.False(t, present)
		})
	}
}

func TestAcceptMaterialAdoptsCompleteUncataloguedPayload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	name := incomingCustodyPlaceOrphan(t, directory, f.payload)
	path := filepath.Join(directory, payloadDirectoryName, name)
	placed, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
	require.NoError(t, err)
	require.True(t, placed.Exists)
	require.Equal(t, f.payload, placed.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), placed.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint64(1), placed.Nlink)
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))

	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.AcceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), floor.Revision)

	adopted, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
	require.NoError(t, err)
	require.True(t, adopted.Exists)
	assert.Equal(t, placed.Device, adopted.Device)
	assert.Equal(t, placed.Inode, adopted.Inode)
	assert.Equal(t, placed.Bytes, adopted.Bytes)
	assert.Equal(t, uint32(unix.S_IFREG|0o600), adopted.Mode&uint32(unix.S_IFMT|0o777))
	assert.Equal(t, uint64(1), adopted.Nlink)
	assert.Equal(t, int64(len(f.payload)), adopted.Size)
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, name, entries[0].Name())

	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", name))
	assert.Equal(t, int64(len(f.payload)), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", name))
	references := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, references, 1)
	assert.Equal(t, []any{int64(floor.Revision), floor.RecordCID, floor.BlobCID}, references[0])

	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	assert.Equal(t, floor, material.Floor)
	assert.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	assert.Equal(t, f.payload, material.Payload)
}

func TestAcceptMaterialRefusesCorruptAdoptedPayload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	require.NotEmpty(t, f.payload)
	name := incomingCustodyPlaceOrphan(t, directory, f.payload)
	path := filepath.Join(directory, payloadDirectoryName, name)
	corrupt := bytes.Clone(f.payload)
	corrupt[0] ^= 0xff
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	written, writeErr := file.WriteAt(corrupt[:1], 0)
	syncErr := file.Sync()
	closeErr := file.Close()
	require.NoError(t, writeErr)
	require.Equal(t, 1, written)
	require.NoError(t, syncErr)
	require.NoError(t, closeErr)

	damaged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
	require.NoError(t, err)
	require.True(t, damaged.Exists)
	require.Equal(t, corrupt, damaged.Bytes)
	require.Equal(t, int64(len(f.payload)), damaged.Size)
	inventory, total, err := store.inventoryPayloads()
	require.NoError(t, err)
	require.Equal(t, map[string]uint64{name: uint64(len(f.payload))}, inventory)
	require.Equal(t, uint64(len(f.payload)), total)

	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	floor, err := store.AcceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonMaterialCorrupt)

	unchanged, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
	require.NoError(t, err)
	require.True(t, unchanged.Exists)
	assert.Equal(t, damaged, unchanged)
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, Floor{}, loaded)
	assert.False(t, present)
}

func TestAcceptMaterialRefusesMissingCataloguedPayload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
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

	name := payloadBasename(candidate.Payload)
	path := filepath.Join(directory, payloadDirectoryName, name)
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", name))
	require.NoError(t, os.Remove(path))
	_, statErr := os.Lstat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	beforeRows := readAttemptLogicalRows(t, store)
	beforeReferences := b8IncomingRows(t, ctx, store.conn)
	require.Empty(t, beforeReferences)

	observation := f.observation(1)
	firstUse := prepareFirstUse(t, store, observation, candidate.Payload)
	floor, err := store.AcceptMaterial(ctx, ModeFirstUse, firstUse.StateToken, observation, candidate.Payload, firstUse.Confirmation)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonMaterialMissing)

	_, statErr = os.Lstat(path)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
	assert.Equal(t, beforeReferences, b8IncomingRows(t, ctx, store.conn))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", name))
	assert.Equal(t, int64(len(candidate.Payload)), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", name))
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, Floor{}, loaded)
	assert.False(t, present)
}

func TestAcceptMaterialSyncsBeforeReferenceCommit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	incomingCustodyPlaceOrphan(t, directory, f.payload)
	expectedBlobCID := blobForCandidate(t, attemptCandidate(f, 0)).CID
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)

	var root unix.Stat_t
	require.NoError(t, unix.Fstat(store.rootFD, &root))
	var syncOrder []string
	originalSync := store.custodyOps.sync
	store.custodyOps.sync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		kind := ""
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			kind = "file"
		case unix.S_IFDIR:
			if stat.Dev == root.Dev && stat.Ino == root.Ino {
				kind = "root"
			} else {
				if store.payloadFD < 0 {
					return errors.New("unexpected sync directory")
				}
				var payload unix.Stat_t
				if err := unix.Fstat(store.payloadFD, &payload); err != nil {
					return err
				}
				if stat.Dev != payload.Dev || stat.Ino != payload.Ino {
					return errors.New("unexpected sync directory")
				}
				kind = "payload-directory"
			}
		default:
			return errors.New("unexpected sync object")
		}
		syncOrder = append(syncOrder, kind)
		return originalSync(fd)
	}
	wantPreCommitSyncs := []string{"root", "file", "payload-directory", "root", "root"}
	var preCommitReference []any
	preCommitReferences := 0
	commitSeen := false
	store.commitTransaction = func(tx *sql.Tx) error {
		orderOK := assert.Equal(t, wantPreCommitSyncs, syncOrder, "preflight, ownership and withTx root fsyncs must precede the incoming reference commit")
		var revision int64
		var recordCID, blobCID []byte
		scanErr := tx.QueryRowContext(ctx, "SELECT accepted_revision,record_cid,blob_cid FROM accepted_material_refs").Scan(&revision, &recordCID, &blobCID)
		refsOK := assert.NoError(t, scanErr, "incoming reference must be visible through the transaction before commit")
		if refsOK {
			refsOK = assert.Equal(t, int64(1), revision, "incoming reference revision must be the accepted revision before commit") &&
				assert.Equal(t, expectedBlobCID, blobCID, "incoming reference must name the accepted blob before commit")
			preCommitReference = []any{revision, recordCID, blobCID}
		}
		countErr := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM accepted_material_refs").Scan(&preCommitReferences)
		refsOK = refsOK && assert.NoError(t, countErr)
		if !orderOK || !refsOK {
			rollbackErr := tx.Rollback()
			assert.NoError(t, rollbackErr)
			return errors.New("incoming custody pre-commit assertion failed")
		}
		commitSeen = true
		return tx.Commit()
	}
	floor, err := store.AcceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	assert.True(t, commitSeen)
	assert.Equal(t, wantPreCommitSyncs, syncOrder)
	assert.Equal(t, 1, preCommitReferences)
	require.NotNil(t, preCommitReference)
	assert.Equal(t, int64(floor.Revision), preCommitReference[0])
	assert.Equal(t, floor.RecordCID, preCommitReference[1])
	assert.Equal(t, floor.BlobCID, preCommitReference[2])
	references := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, references, 1)
	assert.Equal(t, []any{int64(floor.Revision), floor.RecordCID, floor.BlobCID}, references[0])
}

func TestAcceptMaterialSyncFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	name := incomingCustodyPlaceOrphan(t, directory, f.payload)
	path := filepath.Join(directory, payloadDirectoryName, name)
	placed, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
	require.NoError(t, err)
	require.True(t, placed.Exists)
	require.Equal(t, f.payload, placed.Bytes)
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	beforeRows := readAttemptLogicalRows(t, store)

	var root unix.Stat_t
	require.NoError(t, unix.Fstat(store.rootFD, &root))
	var syncOrder []string
	payloadDirectorySynced := false
	originalSync := store.custodyOps.sync
	store.custodyOps.sync = func(fd int) error {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			syncOrder = append(syncOrder, "file")
			return originalSync(fd)
		case unix.S_IFDIR:
			if stat.Dev == root.Dev && stat.Ino == root.Ino {
				syncOrder = append(syncOrder, "root")
				if payloadDirectorySynced {
					return unix.EIO
				}
				return originalSync(fd)
			}
			if store.payloadFD < 0 {
				return errors.New("unexpected sync directory")
			}
			var payload unix.Stat_t
			if err := unix.Fstat(store.payloadFD, &payload); err != nil {
				return err
			}
			if stat.Dev != payload.Dev || stat.Ino != payload.Ino {
				return errors.New("unexpected sync directory")
			}
			syncOrder = append(syncOrder, "payload-directory")
			if err := originalSync(fd); err != nil {
				return err
			}
			payloadDirectorySynced = true
			return nil
		default:
			return errors.New("unexpected sync object")
		}
	}
	floor, err := store.AcceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrStorage, StageAcceptMaterial, ReasonIO)
	assert.Equal(t, []string{"root", "file", "payload-directory", "root"}, syncOrder)
	assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))

	after, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
	require.NoError(t, err)
	require.True(t, after.Exists)
	assert.Equal(t, placed, after)
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	assert.Equal(t, Floor{}, loaded)
	assert.False(t, present)
}

func TestAcceptMaterialChargesCataloguedMissingPayload(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	payloadA := incomingCapacityAppendDistinctRecord(t, &f, 0, []byte("synthetic catalogued missing payload alpha"))
	payloadB := incomingCapacityAppendDistinctRecord(t, &f, 1, []byte("synthetic catalogued missing payload beta"))
	require.NotEqual(t, payloadA, payloadB)
	nameA := payloadBasename(payloadA)
	nameB := payloadBasename(payloadB)
	require.NotEqual(t, nameA, nameB)
	sizeA := uint64(len(payloadA))
	sizeB := uint64(len(payloadB))
	require.Positive(t, sizeA)
	require.Positive(t, sizeB)

	for _, scenario := range []struct {
		name         string
		custodyBytes uint64
		refuse       bool
	}{
		{"completed union one byte over refused", sizeA + sizeB - 1, true},
		{"completed union exact bytes admitted", sizeA + sizeB, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			attemptLimits := DefaultAttemptLimits()
			attemptLimits.CustodyBytes = scenario.custodyBytes
			require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeA)
			require.GreaterOrEqual(t, attemptLimits.CustodyBytes, sizeB)
			require.GreaterOrEqual(t, attemptLimits.ManagedObjects, uint32(2))
			store, directory := openAttemptStoreWithAttemptLimits(t, f, DefaultLimits(), attemptLimits)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			payloadDirectory := filepath.Join(directory, payloadDirectoryName)

			firstObservation := f.observation(1)
			firstProposal := prepareFirstUse(t, store, firstObservation, payloadA)
			first, err := store.AcceptMaterial(ctx, ModeFirstUse, firstProposal.StateToken, firstObservation, payloadA, firstProposal.Confirmation)
			require.NoError(t, err)
			require.Equal(t, uint64(1), first.Revision)
			fileA, err := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameA), len(payloadA))
			require.NoError(t, err)
			require.True(t, fileA.Exists)
			require.Equal(t, payloadA, fileA.Bytes)
			require.NoError(t, os.Remove(filepath.Join(payloadDirectory, nameA)))
			absentA, err := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameA), len(payloadA))
			require.NoError(t, err)
			require.False(t, absentA.Exists)
			require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
			require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", nameA))
			require.Equal(t, int64(sizeA), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", nameA))
			beforeRows := readAttemptLogicalRows(t, store)
			beforeReferences := b8IncomingRows(t, ctx, store.conn)
			require.Len(t, beforeReferences, 1)

			advanceObservation := f.observation(2)
			advanceProposal, err := store.Prepare(ctx, ModeAdvance, advanceObservation, payloadB)
			require.NoError(t, err)
			require.Equal(t, "joined", advanceProposal.Stop)
			floor, err := store.AcceptMaterial(ctx, ModeAdvance, advanceProposal.StateToken, advanceObservation, payloadB, [32]byte{})
			if scenario.refuse {
				assert.Equal(t, Floor{}, floor)
				requireErrorMetadata(t, err, ErrLimit, StageAcceptMaterial, ReasonCapacity)
				assert.Equal(t, beforeRows, readAttemptLogicalRows(t, store))
				assert.Equal(t, beforeReferences, b8IncomingRows(t, ctx, store.conn))
				require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
				assert.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", nameA))
				assert.Equal(t, int64(sizeA), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", nameA))
				assert.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects WHERE basename=?", nameB))
				afterA, readErr := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameA), len(payloadA))
				require.NoError(t, readErr)
				assert.False(t, afterA.Exists)
				absentB, readErr := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameB), len(payloadB))
				require.NoError(t, readErr)
				assert.False(t, absentB.Exists)
				entries, readErr := os.ReadDir(payloadDirectory)
				require.NoError(t, readErr)
				assert.Empty(t, entries)
				loaded, present, loadErr := store.Load(ctx)
				require.NoError(t, loadErr)
				require.True(t, present)
				assert.Equal(t, first, loaded)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, first.Revision+1, floor.Revision)
			assert.Equal(t, first.Generation, floor.Generation)
			require.Equal(t, int64(2), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
			assert.Equal(t, int64(sizeA+sizeB), b8Count(t, ctx, store.conn, "SELECT COALESCE(SUM(size),0) FROM payload_objects"))
			assert.Equal(t, int64(sizeB), b8Count(t, ctx, store.conn, "SELECT size FROM payload_objects WHERE basename=?", nameB))
			fileB, readErr := observeAcceptedMaterialPayloadFile(filepath.Join(payloadDirectory, nameB), len(payloadB))
			require.NoError(t, readErr)
			require.True(t, fileB.Exists)
			assert.Equal(t, payloadB, fileB.Bytes)
			entries, readErr := os.ReadDir(payloadDirectory)
			require.NoError(t, readErr)
			require.Len(t, entries, 1)
			assert.Equal(t, nameB, entries[0].Name())
			references := b8IncomingRows(t, ctx, store.conn)
			require.Len(t, references, 2)
			assert.Equal(t, []any{int64(first.Revision), first.RecordCID, first.BlobCID}, references[0])
			assert.Equal(t, []any{int64(floor.Revision), floor.RecordCID, floor.BlobCID}, references[1])
			loaded, present, loadErr := store.Load(ctx)
			require.NoError(t, loadErr)
			require.True(t, present)
			assert.Equal(t, floor, loaded)
		})
	}
}
