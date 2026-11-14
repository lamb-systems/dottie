package publicationstate

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	custodySyncFileKind             = "file"
	custodySyncPayloadDirectoryKind = "payload-directory"
	custodySyncRootKind             = "root"
)

type custodySyncFault struct {
	kind                 string
	ordinal              int
	requireLink          bool
	requireNamedFileSync bool
}

type custodySyncObserver struct {
	ops             custodyOperations
	fault           custodySyncFault
	trace           []string
	linked          bool
	namedFileSynced bool
	armed           bool
	matched         int
	fired           int
}

func (o *custodySyncObserver) restore(store *Store) {
	store.custodyOps = o.ops
}

func (o *custodySyncObserver) preconditionMet() bool {
	if o.fault.requireLink && !o.linked {
		return false
	}
	if o.fault.requireNamedFileSync && !o.namedFileSynced {
		return false
	}
	return true
}

func installCustodySyncObserver(t *testing.T, store *Store, fault custodySyncFault) *custodySyncObserver {
	t.Helper()
	if fault.kind != "" && fault.ordinal == 0 {
		fault.ordinal = 1
	}
	observer := &custodySyncObserver{ops: store.custodyOps, fault: fault}
	t.Cleanup(func() { observer.restore(store) })
	originalLink := observer.ops.link
	store.custodyOps.link = func(fileFD, directoryFD int, name string) error {
		if err := originalLink(fileFD, directoryFD, name); err != nil {
			return err
		}
		observer.linked = true
		return nil
	}
	originalSync := observer.ops.sync
	store.custodyOps.sync = func(fd int) error {
		kind, nlink, err := classifyCustodySyncTarget(store, fd)
		if err != nil {
			return err
		}
		observer.trace = append(observer.trace, kind)
		if observer.fault.kind != "" && !observer.armed && observer.preconditionMet() {
			observer.armed = true
		}
		if observer.armed && kind == observer.fault.kind {
			observer.matched++
			if observer.matched == observer.fault.ordinal {
				observer.fired++
				return unix.EIO
			}
		}
		if err := originalSync(fd); err != nil {
			return err
		}
		if kind == custodySyncFileKind && nlink == 1 {
			observer.namedFileSynced = true
		}
		return nil
	}
	return observer
}

func classifyCustodySyncTarget(store *Store, fd int) (string, uint64, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return "", 0, err
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return custodySyncFileKind, uint64(stat.Nlink), nil
	case unix.S_IFDIR:
		var root unix.Stat_t
		if err := unix.Fstat(store.rootFD, &root); err != nil {
			return "", 0, err
		}
		if stat.Dev == root.Dev && stat.Ino == root.Ino {
			return custodySyncRootKind, uint64(stat.Nlink), nil
		}
		if store.payloadFD >= 0 {
			var payload unix.Stat_t
			if err := unix.Fstat(store.payloadFD, &payload); err != nil {
				return "", 0, err
			}
			if stat.Dev == payload.Dev && stat.Ino == payload.Ino {
				return custodySyncPayloadDirectoryKind, uint64(stat.Nlink), nil
			}
		}
		return "", 0, errors.New("unexpected custody sync directory")
	default:
		return "", 0, errors.New("unexpected custody sync object")
	}
}

func requireIncomingMaterialRowsAbsent(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_records"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Zero(t, b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
}

func requireIncomingMaterialOrphan(t *testing.T, directory string, payload []byte) acceptedMaterialPayloadFileState {
	t.Helper()
	path := filepath.Join(directory, payloadDirectoryName, payloadBasename(payload))
	orphan, err := observeAcceptedMaterialPayloadFile(path, len(payload))
	require.NoError(t, err)
	require.True(t, orphan.Exists)
	require.Equal(t, payload, orphan.Bytes)
	require.Equal(t, uint32(unix.S_IFREG|0o600), orphan.Mode&uint32(unix.S_IFMT|0o777))
	require.Equal(t, uint64(1), orphan.Nlink)
	require.Equal(t, int64(len(payload)), orphan.Size)
	entries, err := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, payloadBasename(payload), entries[0].Name())
	return orphan
}

func requireIncomingMaterialLoadAbsent(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, Floor{}, loaded)
}

func requireIncomingMaterialPublication(t *testing.T, ctx context.Context, store *Store, f fixture, floor Floor) {
	t.Helper()
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_events"))
	require.Equal(t, int64(1), b8Count(t, ctx, store.conn, "SELECT COUNT(*) FROM payload_objects"))
	references := b8IncomingRows(t, ctx, store.conn)
	require.Len(t, references, 1)
	require.Equal(t, []any{int64(floor.Revision), floor.RecordCID, floor.BlobCID}, references[0])
	material, err := store.ReadAcceptedMaterial(ctx, f.binding, floor)
	require.NoError(t, err)
	require.Equal(t, floor, material.Floor)
	require.Equal(t, f.blocks[0].Raw, material.SnapshotRecord)
	require.Equal(t, f.payload, material.Payload)
}

func TestAcceptMaterialPrelinkFaultsLeaveNoNamedPayload(t *testing.T) {
	for _, fault := range []string{"temp-open", "write", "link"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			original := store.custodyOps
			t.Cleanup(func() { store.custodyOps = original })
			seam := 0
			switch fault {
			case "temp-open":
				store.custodyOps.openTemp = func(int, uint32) (int, error) {
					seam++
					return -1, unix.EIO
				}
			case "write":
				store.custodyOps.openTemp = func(directoryFD int, mode uint32) (int, error) {
					seam++
					return original.openTemp(directoryFD, mode)
				}
				store.custodyOps.write = func(int, []byte) (int, error) { return 0, unix.EIO }
			case "link":
				store.custodyOps.openTemp = func(directoryFD int, mode uint32) (int, error) {
					seam++
					return original.openTemp(directoryFD, mode)
				}
				store.custodyOps.link = func(int, int, string) error { return unix.EIO }
			default:
				require.FailNow(t, "unexpected fault case")
			}

			floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonIO)
			assert.Equal(t, 1, seam)
			assert.False(t, store.needsReadback)
			_, statErr := os.Lstat(filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload)))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
			entries, readErr := os.ReadDir(filepath.Join(directory, payloadDirectoryName))
			require.NoError(t, readErr)
			assert.Empty(t, entries)
			requireIncomingMaterialRowsAbsent(t, ctx, store)
			requireIncomingMaterialLoadAbsent(t, ctx, store)
		})
	}
}

func TestAcceptMaterialPostlinkFaultsLeaveReusableOrphan(t *testing.T) {
	cases := []struct {
		name  string
		adopt bool
		fault custodySyncFault
		trace []string
	}{
		{
			"write-directory-fsync",
			false,
			custodySyncFault{kind: custodySyncPayloadDirectoryKind, requireLink: true},
			[]string{custodySyncRootKind, custodySyncFileKind, custodySyncPayloadDirectoryKind},
		},
		{
			"write-root-fsync",
			false,
			custodySyncFault{kind: custodySyncRootKind, requireLink: true},
			[]string{custodySyncRootKind, custodySyncFileKind, custodySyncPayloadDirectoryKind, custodySyncRootKind},
		},
		{
			"ownership-directory-fsync",
			true,
			custodySyncFault{kind: custodySyncPayloadDirectoryKind, requireNamedFileSync: true},
			[]string{custodySyncRootKind, custodySyncFileKind, custodySyncPayloadDirectoryKind},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			path := filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload))
			var placed acceptedMaterialPayloadFileState
			if test.adopt {
				incomingCustodyPlaceOrphan(t, directory, f.payload)
				var err error
				placed, err = observeAcceptedMaterialPayloadFile(path, len(f.payload))
				require.NoError(t, err)
				require.True(t, placed.Exists)
				require.Equal(t, f.payload, placed.Bytes)
				require.Equal(t, uint64(1), placed.Nlink)
			}
			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			observer := installCustodySyncObserver(t, store, test.fault)

			floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonIO)
			assert.Equal(t, 1, observer.fired)
			assert.Equal(t, test.trace, observer.trace)
			assert.False(t, store.needsReadback)

			orphan := requireIncomingMaterialOrphan(t, directory, f.payload)
			if test.adopt {
				assert.Equal(t, placed.Device, orphan.Device)
				assert.Equal(t, placed.Inode, orphan.Inode)
			}
			requireIncomingMaterialRowsAbsent(t, ctx, store)
			requireIncomingMaterialLoadAbsent(t, ctx, store)

			observer.restore(store)
			floor, err = store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, uint64(1), floor.Revision)
			adopted, err := observeAcceptedMaterialPayloadFile(path, len(f.payload))
			require.NoError(t, err)
			require.True(t, adopted.Exists)
			assert.Equal(t, orphan.Device, adopted.Device)
			assert.Equal(t, orphan.Inode, adopted.Inode)
			assert.Equal(t, orphan.Bytes, adopted.Bytes)
			assert.Equal(t, uint64(1), adopted.Nlink)
			requireIncomingMaterialPublication(t, ctx, store, f, floor)
		})
	}
}

func requireIncomingMaterialTempTrigger(t *testing.T, ctx context.Context, store *Store, name string, want int64) {
	t.Helper()
	var count any
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_temp_master WHERE type='trigger' AND name=?", name).Scan(&count))
	got, ok := rawInt64(count)
	require.True(t, ok)
	require.Equal(t, want, got)
}

func TestAcceptMaterialSQLPhaseFaultRollsBackAtomicPublication(t *testing.T) {
	cases := []struct {
		name    string
		trigger string
		ddl     string
	}{
		{
			"catalogue-insert",
			"abort_incoming_catalogue",
			"CREATE TEMP TRIGGER abort_incoming_catalogue BEFORE INSERT ON main.payload_objects BEGIN SELECT RAISE(ABORT,'incoming-catalogue-canary'); END",
		},
		{
			"reference-insert",
			"abort_incoming_reference",
			"CREATE TEMP TRIGGER abort_incoming_reference BEFORE INSERT ON main.accepted_material_refs BEGIN SELECT RAISE(ABORT,'incoming-reference-canary'); END",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, BackendPublicRepo)
			f.appendRecord(t, 0)
			store, directory := newStore(t, f)
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
			observation := f.observation(1)
			proposal := prepareFirstUse(t, store, observation, f.payload)
			requireIncomingMaterialTempTrigger(t, ctx, store, test.trigger, 0)
			_, err := store.conn.ExecContext(ctx, test.ddl)
			require.NoError(t, err)
			requireIncomingMaterialTempTrigger(t, ctx, store, test.trigger, 1)

			floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			assert.Equal(t, Floor{}, floor)
			requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonIO)
			assert.NotContains(t, err.Error(), "-canary")
			assert.False(t, store.needsReadback)
			requireIncomingMaterialOrphan(t, directory, f.payload)
			requireIncomingMaterialRowsAbsent(t, ctx, store)
			requireIncomingMaterialLoadAbsent(t, ctx, store)

			_, err = store.conn.ExecContext(ctx, "DROP TRIGGER "+test.trigger)
			require.NoError(t, err)
			requireIncomingMaterialTempTrigger(t, ctx, store, test.trigger, 0)
			floor, err = store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
			require.NoError(t, err)
			assert.Equal(t, uint64(1), floor.Revision)
			requireIncomingMaterialPublication(t, ctx, store, f, floor)
		})
	}
}

func TestAcceptMaterialFinalRootSyncFailureIsDefiniteRollback(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	observation := f.observation(1)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	commits := 0
	originalCommit := store.commitTransaction
	store.commitTransaction = func(tx *sql.Tx) error {
		commits++
		return originalCommit(tx)
	}
	t.Cleanup(func() { store.commitTransaction = originalCommit })
	observer := installCustodySyncObserver(t, store, custodySyncFault{kind: custodySyncRootKind, requireNamedFileSync: true, ordinal: 2})

	floor, err := store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	assert.Equal(t, Floor{}, floor)
	requireErrorMetadata(t, err, ErrStorage, stageAcceptMaterial, ReasonIO)
	assert.Equal(t, 1, observer.fired)
	assert.Equal(t, []string{
		custodySyncRootKind,
		custodySyncFileKind,
		custodySyncPayloadDirectoryKind,
		custodySyncRootKind,
		custodySyncFileKind,
		custodySyncPayloadDirectoryKind,
		custodySyncRootKind,
		custodySyncRootKind,
	}, observer.trace)
	assert.Equal(t, 0, commits)
	assert.False(t, store.needsReadback)
	orphan := requireIncomingMaterialOrphan(t, directory, f.payload)
	requireIncomingMaterialRowsAbsent(t, ctx, store)
	requireIncomingMaterialLoadAbsent(t, ctx, store)

	observer.restore(store)
	retry := installCustodySyncObserver(t, store, custodySyncFault{})
	floor, err = store.acceptMaterial(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), floor.Revision)
	assert.Equal(t, 0, retry.fired)
	assert.Equal(t, []string{
		custodySyncFileKind,
		custodySyncPayloadDirectoryKind,
		custodySyncRootKind,
		custodySyncRootKind,
	}, retry.trace)
	assert.Equal(t, 1, commits)
	adopted, err := observeAcceptedMaterialPayloadFile(filepath.Join(directory, payloadDirectoryName, payloadBasename(f.payload)), len(f.payload))
	require.NoError(t, err)
	require.True(t, adopted.Exists)
	assert.Equal(t, orphan.Device, adopted.Device)
	assert.Equal(t, orphan.Inode, adopted.Inode)
	assert.Equal(t, orphan.Bytes, adopted.Bytes)
	requireIncomingMaterialPublication(t, ctx, store, f, floor)
}
