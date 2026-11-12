package publicationstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/publication"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	sqliteDriver "modernc.org/sqlite"
	sqliteLib "modernc.org/sqlite/lib"
)

type publicationOpenEvent struct {
	stream string
	point  int
}

type publicationOpenHolderState struct {
	holder    *Store
	rootFD    int
	payloadFD int
	lock      *platform.Lock
	db        *sql.DB
	conn      *sql.Conn
}

type publicationOpenRecorder struct {
	events        []publicationOpenEvent
	states        map[int]publicationOpenHolderState
	upgrade       []int
	commits       int
	commitResults []error
	canary        error
	failAt        int
	mutate        func(int)
}

func newPublicationOpenRecorder() *publicationOpenRecorder {
	return &publicationOpenRecorder{states: make(map[int]publicationOpenHolderState)}
}

func (r *publicationOpenRecorder) openFault(point int, holder *Store) error {
	r.events = append(r.events, publicationOpenEvent{stream: "open", point: point})
	r.states[point] = publicationOpenHolderState{holder: holder, rootFD: holder.rootFD, payloadFD: holder.payloadFD, lock: holder.lock, db: holder.db, conn: holder.conn}
	if r.mutate != nil {
		r.mutate(point)
	}
	if r.failAt != 0 && point == r.failAt {
		return r.canary
	}
	return nil
}

func (r *publicationOpenRecorder) upgradeFault(point int) error {
	r.events = append(r.events, publicationOpenEvent{stream: "migrate", point: point})
	r.upgrade = append(r.upgrade, point)
	return nil
}

func (r *publicationOpenRecorder) commit(tx *sql.Tx) error {
	r.commits++
	err := tx.Commit()
	r.commitResults = append(r.commitResults, err)
	r.events = append(r.events, publicationOpenEvent{stream: "commit", point: 0})
	return err
}

func (r *publicationOpenRecorder) options(base OpenOptions) OpenOptions {
	base.openFault = r.openFault
	base.upgradeFault = r.upgradeFault
	base.upgradeCommit = r.commit
	return base
}

func (r *publicationOpenRecorder) openPoints() []int {
	points := make([]int, 0, len(r.events))
	for _, event := range r.events {
		if event.stream == "open" {
			points = append(points, event.point)
		}
	}
	return points
}

type publicationOpenInput struct {
	shape       string
	directory   string
	database    string
	binding     Binding
	options     OpenOptions
	payloadPath string
	payloadHash string
}

func publicationOpenInputFor(t *testing.T, shape string) publicationOpenInput {
	t.Helper()
	switch shape {
	case "absent":
		f := newFixture(t, BackendPublicRepo)
		directory := t.TempDir()
		require.NoError(t, os.Chmod(directory, 0o700))
		return publicationOpenInput{shape: shape, directory: directory, database: filepath.Join(directory, "publication.db"), binding: f.binding, options: DefaultOpenOptions()}
	case "empty":
		f := newFixture(t, BackendPublicRepo)
		directory := t.TempDir()
		require.NoError(t, os.Chmod(directory, 0o700))
		database := filepath.Join(directory, "publication.db")
		require.NoError(t, os.WriteFile(database, nil, 0o600))
		return publicationOpenInput{shape: shape, directory: directory, database: database, binding: f.binding, options: DefaultOpenOptions()}
	case "pending-genesis":
		assets := incomingMaterialUpgradeFixtureCopy(t)
		image := assets.manifest.requireImage(t, "pending-genesis")
		binding, limits, attemptLimits := incomingMaterialUpgradeFixtureBindingOptions(t, image)
		options := DefaultOpenOptions()
		options.PositionLimits = limits
		options.AttemptLimits = attemptLimits
		directory := filepath.Join(assets.root, "pending-genesis")
		payloadName := "f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea.payload"
		return publicationOpenInput{shape: shape, directory: directory, database: filepath.Join(directory, "publication.db"), binding: binding, options: options, payloadPath: filepath.Join(directory, "payloads", payloadName), payloadHash: "f947699472cc0bb633cf07c9123d6e0c768d498a1853cf83afd43428803f3eea"}
	case "positions-v1":
		f, database, _ := incomingMaterialUpgradeCopyV1(t)
		options := DefaultOpenOptions()
		options.UpgradeFromPositions = true
		options.UpgradeFromAttempts = true
		directory := filepath.Dir(database)
		payloadName := "schema1-baseline-payload.bin"
		return publicationOpenInput{shape: shape, directory: directory, database: database, binding: f.binding, options: options, payloadPath: filepath.Join(directory, payloadName), payloadHash: incomingMaterialUpgradeFixtureHashes[payloadName]}
	default:
		require.FailNowf(t, "unsupported open shape", "%q", shape)
		return publicationOpenInput{}
	}
}

type publicationOpenSourceSnapshot struct {
	version            int
	typed              map[string][][]any
	metadata           map[string][]byte
	incomingTableCount int64
	incomingRefCount   int64
}

func publicationOpenSnapshotSource(t *testing.T, ctx context.Context, databasePath string, version int) publicationOpenSourceSnapshot {
	t.Helper()
	conn, closeConn := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	require.Equal(t, version, incomingMaterialUpgradeUserVersion(t, ctx, conn))
	require.NoError(t, checkSchemaVersion(ctx, conn, version))
	var typed map[string][][]any
	if version == 1 {
		typed = incomingMaterialUpgradeV1Rows(t, ctx, conn)
		require.Len(t, typed, 6)
	} else {
		typed = incomingMaterialUpgradeFixtureTypedRows(t, ctx, conn)
		require.Len(t, typed, 15)
	}
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, conn)
	incomingTableCount := incomingMaterialUpgradeIncomingTableRows(t, ctx, conn)
	var incomingRefCount int64
	if version == 3 {
		require.Equal(t, int64(1), incomingTableCount)
		incomingRefCount = incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM accepted_material_refs")
		require.Zero(t, incomingRefCount)
	} else {
		require.Zero(t, incomingTableCount)
	}
	closeConn(t)
	return publicationOpenSourceSnapshot{version: version, typed: typed, metadata: metadata, incomingTableCount: incomingTableCount, incomingRefCount: incomingRefCount}
}

func publicationOpenRequireSourcePreserved(t *testing.T, ctx context.Context, databasePath string, before publicationOpenSourceSnapshot) {
	t.Helper()
	after := publicationOpenSnapshotSource(t, ctx, databasePath, before.version)
	require.Equal(t, before, after)
}

func publicationOpenFD0(t *testing.T) unix.Stat_t {
	t.Helper()
	var stat unix.Stat_t
	require.NoError(t, unix.Fstat(0, &stat))
	return stat
}

func publicationOpenRequireFD0(t *testing.T, before unix.Stat_t) {
	t.Helper()
	after := publicationOpenFD0(t)
	require.Equal(t, before.Dev, after.Dev)
	require.Equal(t, before.Ino, after.Ino)
	require.Equal(t, before.Rdev, after.Rdev)
	require.Equal(t, before.Mode, after.Mode)
}

func publicationOpenRequireSchema3(t *testing.T, ctx context.Context, store *Store, input publicationOpenInput) map[string][]byte {
	t.Helper()
	require.NotNil(t, store)
	require.False(t, store.closed)
	require.Equal(t, 3, store.schemaVersion)
	require.Equal(t, input.binding, store.binding)
	require.Equal(t, input.options.PositionLimits, store.limits)
	require.Equal(t, input.options.AttemptLimits, store.attemptLimits)
	require.Equal(t, -1, store.payloadFD)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
	require.NoError(t, checkSchema(ctx, store.conn))
	objects := incomingMaterialUpgradeFixtureObjects(t, ctx, store.conn)
	counts := incomingMaterialUpgradeFixtureObjectCounts(t, objects)
	require.Equal(t, 16, counts.tables)
	require.Equal(t, 2, counts.namedIndexes)
	require.Equal(t, 14, counts.autoIndexes)
	require.Len(t, objects, 32)
	require.Equal(t, incomingMaterialSchemaStatement, objects["accepted_material_refs"].sql)
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
	require.Len(t, metadata, 7)
	require.Equal(t, metadata["database_id"], store.databaseID[:])
	require.False(t, allZero(store.databaseID[:]))
	return metadata
}

func publicationOpenRequireEmptyState(t *testing.T, ctx context.Context, store *Store) {
	t.Helper()
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, zeroFloor(), floor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Empty(t, history.Events)
	require.Empty(t, history.Records)
	attempts, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Empty(t, attempts.Attempts)
	for _, table := range incomingMaterialUpgradeFixtureAttemptTables {
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM "+table), table)
	}
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
}

func publicationOpenRequirePendingState(t *testing.T, ctx context.Context, store *Store, before publicationOpenSourceSnapshot) {
	t.Helper()
	rows := incomingMaterialUpgradeFixtureTypedRows(t, ctx, store.conn)
	require.Equal(t, before.typed, rows)
	require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(rows))
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, zeroFloor(), floor)
	attempts, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.Len(t, attempts.Attempts, 1)
	require.Equal(t, AttemptGenesis, attempts.Attempts[0].Kind)
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM pending_genesis"))
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM active_publication_attempt"))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
}

func publicationOpenRequireV1Upgraded(t *testing.T, ctx context.Context, store *Store, before publicationOpenSourceSnapshot) {
	t.Helper()
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
	require.Len(t, metadata, 7)
	for _, key := range []string{"binding", "database_id", "generation", "limits", "revision"} {
		require.Equal(t, before.metadata[key], metadata[key], key)
	}
	wanted, err := encodeAttemptLimits(DefaultAttemptLimits())
	require.NoError(t, err)
	require.Equal(t, wanted, metadata["attempt_limits"])
	require.Equal(t, uint64Bytes(0), metadata["attempt_mutation_revision"])
	rows := incomingMaterialUpgradeV1Rows(t, ctx, store.conn)
	for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
		require.Equal(t, before.typed[table], rows[table], table)
	}
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, uint64(1), floor.Sequence)
	require.Equal(t, uint64(2), floor.Revision)
	require.Equal(t, uint64(1), floor.Generation)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, history.Events, 2)
	require.Equal(t, uint64(2), history.NextRevision)
}

func publicationOpenRequireReleased(t *testing.T, ctx context.Context, store *Store, input publicationOpenInput) {
	t.Helper()
	rootFD := store.rootFD
	conn := store.conn
	pool := store.db
	require.NoError(t, store.Close())
	var stat unix.Stat_t
	require.ErrorIs(t, unix.Fstat(rootFD, &stat), unix.EBADF)
	require.ErrorIs(t, conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := pool.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	lockPath := filepath.Join(input.directory, "publication.db.lock")
	info, err := os.Lstat(lockPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	lock, err := platform.LockFile(lockPath)
	if lock != nil {
		t.Cleanup(func() { assert.NoError(t, lock.Close()) })
	}
	require.NoError(t, err)
	require.NoError(t, lock.Close())
	options := DefaultOpenOptions()
	options.PositionLimits = input.options.PositionLimits
	options.AttemptLimits = input.options.AttemptLimits
	reopened, err := OpenWithOptions(input.directory, input.binding, options)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 3, reopened.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, reopened.conn))
	require.NoError(t, checkSchema(ctx, reopened.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, reopened.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	require.NoError(t, reopened.Close())
}

func publicationOpenCurrent3PendingInput(t *testing.T) publicationOpenInput {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	input := publicationOpenInputFor(t, "pending-genesis")
	require.False(t, input.options.UpgradeFromPositions)
	require.False(t, input.options.UpgradeFromAttempts)
	payload := publicationOpenCapturePayload(t, input)
	before := publicationOpenSnapshotSource(t, ctx, input.database, 2)
	require.Len(t, before.metadata, 7)
	require.Len(t, before.typed, 15)
	require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(before.typed))
	setupOptions := input.options
	setupOptions.UpgradeFromAttempts = true
	setup := newPublicationOpenRecorder()
	fd0 := publicationOpenFD0(t)
	migrated, err := OpenWithOptions(input.directory, input.binding, setup.options(setupOptions))
	if migrated != nil {
		t.Cleanup(func() { assert.NoError(t, migrated.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, setup.openPoints())
	require.Equal(t, []int{13, 14, 15, 16}, setup.upgrade)
	require.Equal(t, 1, setup.commits)
	require.Len(t, setup.commitResults, 1)
	require.NoError(t, setup.commitResults[0])
	require.Equal(t, []publicationOpenEvent{
		{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
		{stream: "migrate", point: 13}, {stream: "migrate", point: 14}, {stream: "migrate", point: 15}, {stream: "migrate", point: 16},
		{stream: "commit", point: 0},
		{stream: "open", point: 1}, {stream: "open", point: 2}, {stream: "open", point: 3}, {stream: "open", point: 4},
	}, setup.events)
	publicationOpenRequireAcquisitionIdentities(t, setup, migrated)
	publicationOpenRequireFD0(t, fd0)
	metadata := publicationOpenRequireSchema3(t, ctx, migrated, input)
	require.Equal(t, before.metadata, metadata)
	publicationOpenRequirePendingState(t, ctx, migrated, before)
	publicationOpenRequirePayloadPreserved(t, input, payload)
	publicationOpenRequireFD0(t, fd0)
	publicationOpenRequireClosedResources(t, migrated, input.directory)
	publicationOpenRequireFD0(t, fd0)
	current := publicationOpenSnapshotSource(t, ctx, input.database, 3)
	require.Equal(t, before.metadata, current.metadata)
	require.Equal(t, before.typed, current.typed)
	publicationOpenRequirePayloadPreserved(t, input, payload)
	require.False(t, input.options.UpgradeFromPositions)
	require.False(t, input.options.UpgradeFromAttempts)
	require.Nil(t, input.options.upgradeFault)
	require.Nil(t, input.options.upgradeCommit)
	require.Nil(t, input.options.openFault)
	require.Nil(t, input.options.createdDatabaseChmod)
	return input
}

func publicationOpenRequireRefused(t *testing.T, store *Store, err error, recorder *publicationOpenRecorder, expected []int, class error, reason Reason) publicationOpenHolderState {
	t.Helper()
	require.Nil(t, store)
	requireErrorMetadata(t, err, class, StageOpen, reason)
	require.Equal(t, expected, recorder.openPoints())
	require.Empty(t, recorder.upgrade)
	require.Zero(t, recorder.commits)
	require.Empty(t, recorder.commitResults)
	for _, event := range recorder.events {
		require.NotEqual(t, "commit", event.stream)
	}
	require.NotErrorIs(t, err, recorder.canary)
	require.NotContains(t, err.Error(), recorder.canary.Error())
	require.NotContains(t, fmt.Sprintf("%+v", err), recorder.canary.Error())
	last := expected[len(expected)-1]
	state, present := recorder.states[last]
	require.True(t, present)
	require.NotNil(t, state.holder)
	require.True(t, state.holder.closed)
	require.Equal(t, -1, state.payloadFD)
	var stat unix.Stat_t
	require.ErrorIs(t, unix.Fstat(state.rootFD, &stat), unix.EBADF)
	return state
}

func publicationOpenRequireStageResources(t *testing.T, ctx context.Context, state publicationOpenHolderState, point int) {
	t.Helper()
	switch point {
	case openRootAcquiredFault:
		require.Nil(t, state.lock)
		require.Nil(t, state.db)
		require.Nil(t, state.conn)
	case openLockAcquiredFault:
		require.NotNil(t, state.lock)
		require.Nil(t, state.db)
		require.Nil(t, state.conn)
	case openConnectionAcquiredFault:
		require.NotNil(t, state.lock)
		require.NotNil(t, state.db)
		require.NotNil(t, state.conn)
		require.ErrorIs(t, state.conn.PingContext(ctx), sql.ErrConnDone)
		poolErr := state.db.PingContext(ctx)
		require.NoError(t, ctx.Err())
		require.Error(t, poolErr)
	default:
		require.FailNowf(t, "unsupported acquisition point", "%d", point)
	}
}

func publicationOpenRequireAcquisitionIdentities(t *testing.T, recorder *publicationOpenRecorder, store *Store) {
	t.Helper()
	require.NotNil(t, store)
	require.False(t, store.closed)
	require.GreaterOrEqual(t, store.rootFD, 0)
	require.Equal(t, -1, store.payloadFD)
	rootState, present := recorder.states[openRootAcquiredFault]
	require.True(t, present)
	require.NotNil(t, rootState.holder)
	require.Same(t, rootState.holder, store)
	require.GreaterOrEqual(t, rootState.rootFD, 0)
	require.Equal(t, -1, rootState.payloadFD)
	require.Nil(t, rootState.lock)
	require.Nil(t, rootState.db)
	require.Nil(t, rootState.conn)
	lockState, present := recorder.states[openLockAcquiredFault]
	require.True(t, present)
	require.NotNil(t, lockState.holder)
	require.Same(t, rootState.holder, lockState.holder)
	require.Equal(t, rootState.rootFD, lockState.rootFD)
	require.Equal(t, -1, lockState.payloadFD)
	require.NotNil(t, lockState.lock)
	require.Nil(t, lockState.db)
	require.Nil(t, lockState.conn)
	connState, present := recorder.states[openConnectionAcquiredFault]
	require.True(t, present)
	require.NotNil(t, connState.holder)
	require.Same(t, rootState.holder, connState.holder)
	require.Equal(t, rootState.rootFD, connState.rootFD)
	require.Equal(t, -1, connState.payloadFD)
	require.Same(t, lockState.lock, connState.lock)
	require.NotNil(t, connState.db)
	require.NotNil(t, connState.conn)
	for point, state := range recorder.states {
		switch point {
		case openRootAcquiredFault, openLockAcquiredFault, openConnectionAcquiredFault:
			continue
		}
		require.NotNil(t, state.holder, point)
		require.Same(t, rootState.holder, state.holder, point)
		require.Equal(t, rootState.rootFD, state.rootFD, point)
		require.Equal(t, -1, state.payloadFD, point)
		require.Same(t, lockState.lock, state.lock, point)
		require.Same(t, connState.db, state.db, point)
		require.Same(t, connState.conn, state.conn, point)
	}
	require.Equal(t, rootState.rootFD, store.rootFD)
	require.Same(t, lockState.lock, store.lock)
	require.Same(t, connState.db, store.db)
	require.Same(t, connState.conn, store.conn)
}

func publicationOpenCapturePayload(t *testing.T, input publicationOpenInput) incomingMaterialUpgradeFixturePayload {
	t.Helper()
	require.NotEmpty(t, input.payloadPath)
	state := incomingMaterialUpgradeFixturePayloadState(t, input.payloadPath)
	require.Equal(t, int64(3072), state.size)
	require.Equal(t, input.payloadHash, state.sha256)
	require.Len(t, state.bytes, 3072)
	return state
}

func publicationOpenRequirePayloadPreserved(t *testing.T, input publicationOpenInput, before incomingMaterialUpgradeFixturePayload) {
	t.Helper()
	require.NotEmpty(t, input.payloadPath)
	after := incomingMaterialUpgradeFixturePayloadState(t, input.payloadPath)
	require.Equal(t, before, after)
}

func publicationOpenRequireLockWitness(t *testing.T, directory string, acquired bool) {
	t.Helper()
	if !acquired {
		return
	}
	lockPath := filepath.Join(directory, "publication.db.lock")
	info, err := os.Lstat(lockPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	lock, err := platform.LockFile(lockPath)
	if lock != nil {
		t.Cleanup(func() { assert.NoError(t, lock.Close()) })
	}
	require.NoError(t, err)
	require.NoError(t, lock.Close())
}

func publicationOpenRequireUninitialized(t *testing.T, ctx context.Context, databasePath string) {
	t.Helper()
	info, err := os.Lstat(databasePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	conn, closeConn := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	var version int
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version))
	require.Zero(t, version)
	var objects int64
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master").Scan(&objects))
	require.Zero(t, objects)
	closeConn(t)
}

func TestPublicationOpenResourceAcquisition(t *testing.T) {
	t.Run("absent database", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "absent")
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
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
		require.Equal(t, 8, len(recorder.states))
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireEmptyState(t, ctx, store)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireReleased(t, ctx, store, input)
	})

	t.Run("pre-existing empty file", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "empty")
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireEmptyState(t, ctx, store)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireReleased(t, ctx, store, input)
	})

	t.Run("existing current3 pending genesis", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenCurrent3PendingInput(t)
		payload := publicationOpenCapturePayload(t, input)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		metadata := publicationOpenRequireSchema3(t, ctx, store, input)
		require.Equal(t, before.metadata, metadata)
		publicationOpenRequirePendingState(t, ctx, store, before)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
	})

	t.Run("genuine schema one position upgrade", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "positions-v1")
		payload := publicationOpenCapturePayload(t, input)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 1)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, recorder.upgrade)
		require.Equal(t, 1, recorder.commits)
		require.Len(t, recorder.commitResults, 1)
		require.NoError(t, recorder.commitResults[0])
		expectedEvents := make([]publicationOpenEvent, 0, 24)
		for _, point := range []int{101, 102, 103} {
			expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "open", point: point})
		}
		for point := 1; point <= 16; point++ {
			expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "migrate", point: point})
		}
		expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "commit", point: 0})
		for _, point := range []int{1, 2, 3, 4} {
			expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "open", point: point})
		}
		require.Equal(t, expectedEvents, recorder.events)
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireV1Upgraded(t, ctx, store, before)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequirePayloadPreserved(t, input, payload)
	})

	for _, shape := range []string{"absent", "empty", "pending-genesis", "positions-v1"} {
		for _, point := range []int{openRootAcquiredFault, openLockAcquiredFault, openConnectionAcquiredFault} {
			t.Run(fmt.Sprintf("%s fault %d", shape, point), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				t.Cleanup(cancel)
				input := publicationOpenInputFor(t, shape)
				if shape == "pending-genesis" {
					input.options.UpgradeFromAttempts = true
				}
				var before publicationOpenSourceSnapshot
				var payload incomingMaterialUpgradeFixturePayload
				if shape == "pending-genesis" {
					payload = publicationOpenCapturePayload(t, input)
					before = publicationOpenSnapshotSource(t, ctx, input.database, 2)
				}
				if shape == "positions-v1" {
					payload = publicationOpenCapturePayload(t, input)
					before = publicationOpenSnapshotSource(t, ctx, input.database, 1)
				}
				fd0 := publicationOpenFD0(t)
				recorder := newPublicationOpenRecorder()
				recorder.canary = errors.New("injected open acquisition canary")
				recorder.failAt = point
				store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
				if store != nil {
					t.Cleanup(func() { assert.NoError(t, store.Close()) })
				}
				expected := []int{101, 102, 103}
				expected = expected[:expectedPointIndex(point)]
				state := publicationOpenRequireRefused(t, store, err, recorder, expected, ErrStorage, ReasonIO)
				publicationOpenRequireStageResources(t, ctx, state, point)
				publicationOpenRequireLockWitness(t, input.directory, point != openRootAcquiredFault)
				publicationOpenRequireFD0(t, fd0)
				switch shape {
				case "absent":
					if point == openConnectionAcquiredFault {
						publicationOpenRequireUninitialized(t, ctx, input.database)
					} else {
						_, statErr := os.Lstat(input.database)
						require.ErrorIs(t, statErr, os.ErrNotExist)
					}
				case "empty":
					publicationOpenRequireUninitialized(t, ctx, input.database)
				case "pending-genesis", "positions-v1":
					publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
					publicationOpenRequirePayloadPreserved(t, input, payload)
				}
			})
		}
	}
}

func expectedPointIndex(point int) int {
	switch point {
	case openRootAcquiredFault:
		return 1
	case openLockAcquiredFault:
		return 2
	default:
		return 3
	}
}

func TestPublicationOpenEarlySecurityOwnership(t *testing.T) {
	for _, unsafe := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		t.Run("unsafe existing "+unsafe, func(t *testing.T) {
			f := newFixture(t, BackendPublicRepo)
			directory := t.TempDir()
			require.NoError(t, os.Chmod(directory, 0o700))
			target := filepath.Join(directory, unsafe)
			require.NoError(t, os.WriteFile(target, []byte("unsafe"), 0o640))
			require.NoError(t, os.Chmod(target, 0o640))
			before, err := os.Lstat(target)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), before.Mode().Perm())
			require.Equal(t, int64(6), before.Size())
			fd0 := publicationOpenFD0(t)
			recorder := newPublicationOpenRecorder()
			recorder.canary = errors.New("injected early security canary")
			store, err := OpenWithOptions(directory, f.binding, recorder.options(DefaultOpenOptions()))
			if store != nil {
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
			}
			state := publicationOpenRequireRefused(t, store, err, recorder, []int{101}, ErrInvalid, ReasonBinding)
			require.Nil(t, state.lock)
			require.Nil(t, state.db)
			require.Nil(t, state.conn)
			publicationOpenRequireFD0(t, fd0)
			after, err := os.Lstat(target)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), after.Mode().Perm())
			require.Equal(t, before.Size(), after.Size())
		})
	}

	t.Run("live lock contention", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		owner, directory := newStore(t, f)
		t.Cleanup(func() { assert.NoError(t, owner.Close()) })
		require.Equal(t, 3, owner.schemaVersion)
		expectedFloor := incomingMaterialFirstUse(t, owner, f)
		floor, present, err := owner.Load(ctx)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, expectedFloor, floor)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("injected contention canary")
		second, err := OpenWithOptions(directory, f.binding, recorder.options(DefaultOpenOptions()))
		if second != nil {
			t.Cleanup(func() { assert.NoError(t, second.Close()) })
		}
		state := publicationOpenRequireRefused(t, second, err, recorder, []int{101}, ErrLocked, ReasonLocked)
		require.Nil(t, state.lock)
		require.Nil(t, state.db)
		require.Nil(t, state.conn)
		require.NotEqual(t, owner.rootFD, state.rootFD)
		publicationOpenRequireFD0(t, fd0)
		heldPath := filepath.Join(directory, "publication.db.lock")
		heldMode, err := os.Lstat(heldPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), heldMode.Mode().Perm())
		probe, probeErr := platform.LockFile(heldPath)
		if probe != nil {
			t.Cleanup(func() { assert.NoError(t, probe.Close()) })
		}
		require.Nil(t, probe)
		require.True(t, errors.Is(probeErr, syscall.EWOULDBLOCK) || errors.Is(probeErr, syscall.EAGAIN))
		floorAfter, presentAfter, err := owner.Load(ctx)
		require.NoError(t, err)
		require.True(t, presentAfter)
		require.Equal(t, floor, floorAfter)
		var rootStat unix.Stat_t
		require.NoError(t, unix.Fstat(owner.rootFD, &rootStat))
		require.Equal(t, uint32(unix.S_IFDIR), rootStat.Mode&unix.S_IFMT)
		require.NoError(t, owner.Close())
		reopened, err := Open(directory, f.binding)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, 3, reopened.schemaVersion)
		require.NoError(t, reopened.Close())
	})

	t.Run("second preflight lock mode", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		seed, directory := newStore(t, f)
		require.Equal(t, 3, seed.schemaVersion)
		require.NoError(t, seed.Close())
		database := filepath.Join(directory, "publication.db")
		before := publicationOpenSnapshotSource(t, ctx, database, 3)
		lockPath := filepath.Join(directory, "publication.db.lock")
		initial, err := os.Lstat(lockPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), initial.Mode().Perm())
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("injected second preflight canary")
		recorder.mutate = func(point int) {
			if point == openLockAcquiredFault {
				require.NoError(t, os.Chmod(lockPath, 0o640))
			}
		}
		store, err := OpenWithOptions(directory, f.binding, recorder.options(DefaultOpenOptions()))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrInvalid, ReasonBinding)
		require.NotNil(t, state.lock)
		require.Nil(t, state.db)
		require.Nil(t, state.conn)
		publicationOpenRequireFD0(t, fd0)
		unsafeMode, err := os.Lstat(lockPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o640), unsafeMode.Mode().Perm())
		plain, err := OpenWithOptions(directory, f.binding, DefaultOpenOptions())
		if plain != nil {
			t.Cleanup(func() { assert.NoError(t, plain.Close()) })
		}
		require.Nil(t, plain)
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
		stillUnsafe, err := os.Lstat(lockPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o640), stillUnsafe.Mode().Perm())
		publicationOpenRequireSourcePreserved(t, ctx, database, before)
		lock, err := platform.LockFile(lockPath)
		if lock != nil {
			t.Cleanup(func() { assert.NoError(t, lock.Close()) })
		}
		require.NoError(t, err)
		require.NoError(t, lock.Close())
		normalized, err := os.Lstat(lockPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), normalized.Mode().Perm())
		reopened, err := OpenWithOptions(directory, f.binding, DefaultOpenOptions())
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, 3, reopened.schemaVersion)
		require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, reopened.conn))
		require.NoError(t, checkSchema(ctx, reopened.conn))
		require.NoError(t, reopened.Close())
		publicationOpenRequireSourcePreserved(t, ctx, database, before)
	})
}

type publicationOpenForeignSnapshot struct {
	applicationID int
	userVersion   int
	journalMode   string
	objects       map[string]string
	definitions   map[string]string
	rows          int64
	value         string
}

func publicationOpenSnapshotForeign(t *testing.T, ctx context.Context, databasePath string) publicationOpenForeignSnapshot {
	t.Helper()
	conn, closeConn := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	var applicationID, userVersion int
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID))
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion))
	var journalMode string
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode))
	objects := make(map[string]string, 1)
	definitions := make(map[string]string, 1)
	rows, err := conn.QueryContext(ctx, "SELECT name,type,IFNULL(sql,'') FROM sqlite_master ORDER BY name")
	require.NoError(t, err)
	var scanErr error
	for rows.Next() {
		var name, kind, definition string
		if scanErr = rows.Scan(&name, &kind, &definition); scanErr != nil {
			break
		}
		objects[name] = kind
		definitions[name] = definition
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	var count int64
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM foreign_state").Scan(&count))
	var value string
	require.NoError(t, conn.QueryRowContext(ctx, "SELECT value FROM foreign_state").Scan(&value))
	closeConn(t)
	return publicationOpenForeignSnapshot{applicationID: applicationID, userVersion: userVersion, journalMode: journalMode, objects: objects, definitions: definitions, rows: count, value: value}
}

func publicationOpenCreateForeignDatabase(t *testing.T, ctx context.Context, databasePath string, applicationIDValue, userVersionValue int) {
	t.Helper()
	require.NoError(t, os.WriteFile(databasePath, nil, 0o600))
	conn, closeStore := incomingMaterialUpgradeFixtureOpenStore(t, ctx, databasePath)
	_, err := conn.ExecContext(ctx, "CREATE TABLE foreign_state (value TEXT NOT NULL)")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "INSERT INTO foreign_state(value) VALUES('preserve')")
	require.NoError(t, err)
	var mode string
	require.NoError(t, conn.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode))
	require.Equal(t, "delete", mode)
	_, err = conn.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d", applicationIDValue))
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", userVersionValue))
	require.NoError(t, err)
	closeStore(t)
}

func publicationOpenRequireRefusalIdentities(t *testing.T, recorder *publicationOpenRecorder, terminal publicationOpenHolderState, acquiredConn bool) {
	t.Helper()
	first, present := recorder.states[openRootAcquiredFault]
	require.True(t, present)
	require.NotNil(t, first.holder)
	require.Same(t, first.holder, terminal.holder)
	require.GreaterOrEqual(t, first.rootFD, 0)
	require.Equal(t, first.rootFD, terminal.rootFD)
	require.Equal(t, -1, first.payloadFD)
	require.Nil(t, first.lock)
	require.Nil(t, first.db)
	require.Nil(t, first.conn)
	require.Equal(t, -1, terminal.payloadFD)
	second, present := recorder.states[openLockAcquiredFault]
	require.True(t, present)
	require.NotNil(t, second.holder)
	require.Same(t, first.holder, second.holder)
	require.Equal(t, first.rootFD, second.rootFD)
	require.Equal(t, -1, second.payloadFD)
	require.NotNil(t, second.lock)
	require.Nil(t, second.db)
	require.Nil(t, second.conn)
	require.Same(t, second.lock, terminal.lock)
	if !acquiredConn {
		require.Nil(t, terminal.db)
		require.Nil(t, terminal.conn)
		return
	}
	third, present := recorder.states[openConnectionAcquiredFault]
	require.True(t, present)
	require.NotNil(t, third.holder)
	require.Same(t, first.holder, third.holder)
	require.Equal(t, first.rootFD, third.rootFD)
	require.Equal(t, -1, third.payloadFD)
	require.Same(t, second.lock, third.lock)
	require.NotNil(t, third.db)
	require.NotNil(t, third.conn)
	require.Same(t, third.db, terminal.db)
	require.Same(t, third.conn, terminal.conn)
	for point, state := range recorder.states {
		switch point {
		case openRootAcquiredFault, openLockAcquiredFault, openConnectionAcquiredFault:
			continue
		}
		require.NotNil(t, state.holder, point)
		require.Same(t, first.holder, state.holder, point)
		require.Equal(t, first.rootFD, state.rootFD, point)
		require.Equal(t, -1, state.payloadFD, point)
		require.Same(t, second.lock, state.lock, point)
		require.Same(t, third.db, state.db, point)
		require.Same(t, third.conn, state.conn, point)
	}
}

func publicationOpenRequireHealthyCurrent3Probe(t *testing.T, input publicationOpenInput) {
	t.Helper()
	probe, err := probeSchema(input.database, input.binding, input.options.PositionLimits, input.options.AttemptLimits)
	require.NoError(t, err)
	require.True(t, probe.recognized)
	require.False(t, probe.initial)
	require.Equal(t, 3, probe.version)
}

func publicationOpenRequireHealthyReopen(t *testing.T, ctx context.Context, input publicationOpenInput, before publicationOpenSourceSnapshot, payload incomingMaterialUpgradeFixturePayload) {
	t.Helper()
	reopened, err := Open(input.directory, input.binding)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	require.Equal(t, 3, reopened.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, reopened.conn))
	require.NoError(t, checkSchema(ctx, reopened.conn))
	require.Equal(t, before.metadata, incomingMaterialUpgradeStoredMetadata(t, ctx, reopened.conn))
	require.Equal(t, before.typed, incomingMaterialUpgradeFixtureTypedRows(t, ctx, reopened.conn))
	require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, reopened.conn))
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, reopened.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
	floor, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, zeroFloor(), floor)
	require.NoError(t, reopened.Close())
	publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
	publicationOpenRequirePayloadPreserved(t, input, payload)
}

func publicationOpenCorruptDatabaseID(t *testing.T, ctx context.Context, databasePath string) {
	t.Helper()
	conn, closeStore := incomingMaterialUpgradeFixtureOpenStore(t, ctx, databasePath)
	result, err := conn.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key='database_id'", make([]byte, 32))
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)
	closeStore(t)
}

func TestIncomingMaterialPublicOpenNaturalRefusalOwnership(t *testing.T) {
	t.Run("foreign empty application", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "empty")
		publicationOpenCreateForeignDatabase(t, ctx, input.database, 0, 0)
		before := publicationOpenSnapshotForeign(t, ctx, input.database)
		require.Zero(t, before.applicationID)
		require.Zero(t, before.userVersion)
		require.Equal(t, "delete", before.journalMode)
		require.Len(t, before.objects, 1)
		require.Equal(t, "table", before.objects["foreign_state"])
		require.Equal(t, "CREATE TABLE foreign_state (value TEXT NOT NULL)", before.definitions["foreign_state"])
		require.Equal(t, int64(1), before.rows)
		require.Equal(t, "preserve", before.value)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("natural foreign application canary")
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonSchema)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		require.Equal(t, before, publicationOpenSnapshotForeign(t, ctx, input.database))
	})

	t.Run("unrecognized own application", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "empty")
		publicationOpenCreateForeignDatabase(t, ctx, input.database, applicationID, 2)
		before := publicationOpenSnapshotForeign(t, ctx, input.database)
		require.Equal(t, applicationID, before.applicationID)
		require.Equal(t, 2, before.userVersion)
		require.Equal(t, "delete", before.journalMode)
		require.Len(t, before.objects, 1)
		require.Equal(t, "table", before.objects["foreign_state"])
		require.Equal(t, "CREATE TABLE foreign_state (value TEXT NOT NULL)", before.definitions["foreign_state"])
		require.Equal(t, int64(1), before.rows)
		require.Equal(t, "preserve", before.value)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("natural unrecognized catalog canary")
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonSchema)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		require.Equal(t, before, publicationOpenSnapshotForeign(t, ctx, input.database))
	})

	t.Run("genuine schema one without any permission upgrade", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "positions-v1")
		input.options.UpgradeFromPositions = false
		input.options.UpgradeFromAttempts = false
		require.False(t, input.options.UpgradeFromPositions)
		require.False(t, input.options.UpgradeFromAttempts)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 1)
		payload := publicationOpenCapturePayload(t, input)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("natural upgrade requirement canary")
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
		plain, err := Open(input.directory, input.binding)
		if plain != nil {
			t.Cleanup(func() { assert.NoError(t, plain.Close()) })
		}
		require.Nil(t, plain)
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
		publicationOpenRequirePayloadPreserved(t, input, payload)
	})
}

func TestPublicationOpenWithoutMigrationErrors(t *testing.T) {
	t.Run("wrong valid binding", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenCurrent3PendingInput(t)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		payload := publicationOpenCapturePayload(t, input)
		publicationOpenRequireHealthyCurrent3Probe(t, input)
		binding := input.binding
		binding.Vault[0] ^= 1
		require.NoError(t, validateBinding(binding))
		require.NotEqual(t, input.binding, binding)
		require.NotZero(t, binding.Vault[0])
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("wrong valid binding canary")
		store, err := OpenWithOptions(input.directory, binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrInvalid, ReasonBinding)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireHealthyReopen(t, ctx, input, before, payload)
	})

	t.Run("wrong valid position limits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenCurrent3PendingInput(t)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		payload := publicationOpenCapturePayload(t, input)
		publicationOpenRequireHealthyCurrent3Probe(t, input)
		limits := input.options.PositionLimits
		require.Greater(t, limits.HistoryPageEvents, uint32(1))
		limits.HistoryPageEvents--
		require.NoError(t, validateLimits(limits))
		require.NotEqual(t, input.options.PositionLimits, limits)
		options := input.options
		options.PositionLimits = limits
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("wrong valid position limits canary")
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrInvalid, ReasonLimits)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireHealthyReopen(t, ctx, input, before, payload)
	})

	t.Run("wrong valid attempt limits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenCurrent3PendingInput(t)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		payload := publicationOpenCapturePayload(t, input)
		publicationOpenRequireHealthyCurrent3Probe(t, input)
		attemptLimits := input.options.AttemptLimits
		require.Greater(t, attemptLimits.HistoryPageEntries, uint32(1))
		attemptLimits.HistoryPageEntries--
		require.NoError(t, validateAttemptLimits(attemptLimits))
		require.NotEqual(t, input.options.AttemptLimits, attemptLimits)
		options := input.options
		options.AttemptLimits = attemptLimits
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("wrong valid attempt limits canary")
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrInvalid, ReasonLimits)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireHealthyReopen(t, ctx, input, before, payload)
	})

	t.Run("stored zero database id", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenCurrent3PendingInput(t)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		payload := publicationOpenCapturePayload(t, input)
		publicationOpenRequireHealthyCurrent3Probe(t, input)
		require.Len(t, before.metadata, 7)
		require.Len(t, before.typed, 15)
		require.Len(t, before.typed["store_meta"], 7)
		require.Len(t, before.metadata["database_id"], 32)
		require.False(t, allZero(before.metadata["database_id"]))
		publicationOpenCorruptDatabaseID(t, ctx, input.database)
		corrupt := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		require.Len(t, corrupt.metadata, 7)
		require.Len(t, corrupt.typed, len(before.typed))
		require.Len(t, corrupt.typed["store_meta"], 7)
		require.Len(t, corrupt.metadata["database_id"], 32)
		require.True(t, allZero(corrupt.metadata["database_id"]))
		require.NotEqual(t, before.metadata["database_id"], corrupt.metadata["database_id"])
		for key, value := range before.metadata {
			if key == "database_id" {
				continue
			}
			require.Equal(t, value, corrupt.metadata[key], key)
		}
		for table, rows := range before.typed {
			if table == "store_meta" {
				continue
			}
			require.Equal(t, rows, corrupt.typed[table], table)
		}
		require.Equal(t, before.version, corrupt.version)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("stored zero database id canary")
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102}, ErrSchema, ReasonCorrupt)
		publicationOpenRequireRefusalIdentities(t, recorder, state, false)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		require.Equal(t, corrupt, publicationOpenSnapshotSource(t, ctx, input.database, 3))
		publicationOpenRequirePayloadPreserved(t, input, payload)
		plain, err := Open(input.directory, input.binding)
		if plain != nil {
			t.Cleanup(func() { assert.NoError(t, plain.Close()) })
		}
		require.Nil(t, plain)
		requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonCorrupt)
		require.Equal(t, corrupt, publicationOpenSnapshotSource(t, ctx, input.database, 3))
	})

	for _, permissions := range []bool{false, true} {
		for _, point := range []int{1, 2, 3, 4} {
			name := fmt.Sprintf("final window fault %d", point)
			if permissions {
				name += " with upgrade permissions"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				t.Cleanup(cancel)
				input := publicationOpenCurrent3PendingInput(t)
				input.options.UpgradeFromPositions = permissions
				input.options.UpgradeFromAttempts = permissions
				require.Equal(t, permissions, input.options.UpgradeFromPositions)
				require.Equal(t, permissions, input.options.UpgradeFromAttempts)
				before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
				payload := publicationOpenCapturePayload(t, input)
				publicationOpenRequireHealthyCurrent3Probe(t, input)
				fd0 := publicationOpenFD0(t)
				recorder := newPublicationOpenRecorder()
				recorder.canary = errors.New("injected final window canary")
				recorder.failAt = point
				store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
				if store != nil {
					t.Cleanup(func() { assert.NoError(t, store.Close()) })
				}
				expected := []int{101, 102, 103}
				for reached := 1; reached <= point; reached++ {
					expected = append(expected, reached)
				}
				state := publicationOpenRequireRefused(t, store, err, recorder, expected, ErrStorage, ReasonIO)
				publicationOpenRequireRefusalIdentities(t, recorder, state, true)
				diagnosticCtx, diagnosticCancel := context.WithTimeout(context.Background(), 60*time.Second)
				t.Cleanup(diagnosticCancel)
				publicationOpenRequireStageResources(t, diagnosticCtx, state, openConnectionAcquiredFault)
				publicationOpenRequireFD0(t, fd0)
				publicationOpenRequireLockWitness(t, input.directory, true)
				publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
				publicationOpenRequirePayloadPreserved(t, input, payload)
				publicationOpenRequireHealthyReopen(t, ctx, input, before, payload)
			})
		}
	}
}

func publicationOpenCaptureDestination(t *testing.T, ctx context.Context, store *Store) publicationOpenSourceSnapshot {
	t.Helper()
	require.NotNil(t, store)
	require.False(t, store.closed)
	require.Equal(t, 3, store.schemaVersion)
	require.Equal(t, 3, incomingMaterialUpgradeUserVersion(t, ctx, store.conn))
	require.NoError(t, checkSchema(ctx, store.conn))
	incomingTableCount := incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn)
	require.Equal(t, int64(1), incomingTableCount)
	incomingRefCount := incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs")
	require.Zero(t, incomingRefCount)
	return publicationOpenSourceSnapshot{version: 3, typed: incomingMaterialUpgradeFixtureTypedRows(t, ctx, store.conn), metadata: incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn), incomingTableCount: incomingTableCount, incomingRefCount: incomingRefCount}
}

func publicationOpenRequireEmptyDestination(t *testing.T, destination publicationOpenSourceSnapshot) {
	t.Helper()
	require.Equal(t, 3, destination.version)
	require.Len(t, destination.metadata, 7)
	require.Len(t, destination.metadata["database_id"], 32)
	require.False(t, allZero(destination.metadata["database_id"]))
	for _, key := range []string{"revision", "generation", "attempt_mutation_revision"} {
		require.Equal(t, uint64Bytes(0), destination.metadata[key], key)
	}
	require.Equal(t, int64(1), destination.incomingTableCount)
	require.Zero(t, destination.incomingRefCount)
	require.Len(t, destination.typed, 15)
	for _, table := range incomingMaterialUpgradeFixtureTableNames {
		require.Contains(t, destination.typed, table)
		if table == "store_meta" {
			require.Len(t, destination.typed[table], 7)
			continue
		}
		require.Empty(t, destination.typed[table], table)
	}
}

func publicationOpenRequireDestinationPreserved(t *testing.T, ctx context.Context, input publicationOpenInput, destination publicationOpenSourceSnapshot) {
	t.Helper()
	after := publicationOpenSnapshotSource(t, ctx, input.database, 3)
	require.Equal(t, destination, after)
	require.Equal(t, destination.metadata["database_id"], after.metadata["database_id"])
}

func publicationOpenRequirePrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err, path)
	require.True(t, info.Mode().IsRegular(), path)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), path)
	var stat unix.Stat_t
	require.NoError(t, unix.Lstat(path, &stat))
	require.Equal(t, uint32(os.Getuid()), stat.Uid, path)
	require.Equal(t, uint64(1), stat.Nlink, path)
}

func publicationOpenRequirePrivateFiles(t *testing.T, directory string) {
	t.Helper()
	publicationOpenRequirePrivateFile(t, filepath.Join(directory, "publication.db"))
	publicationOpenRequirePrivateFile(t, filepath.Join(directory, "publication.db.lock"))
	for _, name := range []string{"publication.db-wal", "publication.db-shm"} {
		path := filepath.Join(directory, name)
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoError(t, err, name)
		publicationOpenRequirePrivateFile(t, path)
	}
}

func TestPublicationNewStoreCreationSecurity(t *testing.T) {
	t.Run("new database default chmod restores private mode", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "absent")
		_, err := os.Lstat(input.database)
		require.ErrorIs(t, err, os.ErrNotExist)
		require.Nil(t, input.options.createdDatabaseChmod)
		fd0 := publicationOpenFD0(t)
		mutations := 0
		var driftedMode os.FileMode
		var observedMode os.FileMode
		recorder := newPublicationOpenRecorder()
		recorder.mutate = func(point int) {
			switch point {
			case openCreatedDatabaseChmodFault:
				mutations++
				info, statErr := os.Lstat(input.database)
				require.NoError(t, statErr)
				require.True(t, info.Mode().IsRegular())
				require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
				require.NoError(t, os.Chmod(input.database, 0o640))
				drifted, statErr := os.Lstat(input.database)
				require.NoError(t, statErr)
				require.Equal(t, os.FileMode(0o640), drifted.Mode().Perm())
				driftedMode = drifted.Mode().Perm()
			case incomingMaterialOpenSidecarsFault:
				observed, statErr := os.Lstat(input.database)
				require.NoError(t, statErr)
				observedMode = observed.Mode().Perm()
			}
		}
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, 1, mutations)
		require.Equal(t, os.FileMode(0o640), driftedMode)
		require.Equal(t, os.FileMode(0o600), observedMode)
		require.Equal(t, []int{101, 102, 103, 1, 104, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireEmptyState(t, ctx, store)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireEmptyDestination(t, destination)
		require.Len(t, destination.metadata, 7)
		require.Len(t, destination.typed, 15)
		require.Len(t, destination.typed["store_meta"], 7)
		require.False(t, allZero(destination.metadata["database_id"]))
		require.Equal(t, uint64Bytes(0), destination.metadata["revision"])
		require.Equal(t, uint64Bytes(0), destination.metadata["generation"])
		require.Equal(t, uint64Bytes(0), destination.metadata["attempt_mutation_revision"])
		require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, store.conn))
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM accepted_material_refs"))
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequirePrivateFiles(t, input.directory)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
	})

	t.Run("new database injected chmod operation error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "absent")
		_, err := os.Lstat(input.database)
		require.ErrorIs(t, err, os.ErrNotExist)
		canary := errors.New("injected chmod operation canary")
		calls := 0
		var callPath string
		var callMode os.FileMode
		input.options.createdDatabaseChmod = func(path string) error {
			calls++
			callPath = path
			info, statErr := os.Lstat(path)
			require.NoError(t, statErr)
			require.True(t, info.Mode().IsRegular())
			callMode = info.Mode().Perm()
			return canary
		}
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = canary
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101, 102, 103, 1, 104}, ErrStorage, ReasonIO)
		require.Equal(t, 1, calls)
		require.Equal(t, input.database, callPath)
		require.Equal(t, os.FileMode(0o600), callMode)
		publicationOpenRequireRefusalIdentities(t, recorder, state, true)
		diagnosticCtx, diagnosticCancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(diagnosticCancel)
		publicationOpenRequireStageResources(t, diagnosticCtx, state, openConnectionAcquiredFault)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequireLockWitness(t, input.directory, true)
		holder := recorder.states[openCreatedDatabaseChmodFault].holder
		require.NotNil(t, holder)
		after := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		publicationOpenRequireEmptyDestination(t, after)
		require.Len(t, after.metadata, 7)
		require.Len(t, after.typed, 15)
		require.Len(t, after.typed["store_meta"], 7)
		require.False(t, allZero(after.metadata["database_id"]))
		require.Equal(t, holder.databaseID[:], after.metadata["database_id"])
		require.Equal(t, uint64Bytes(0), after.metadata["revision"])
		require.Equal(t, uint64Bytes(0), after.metadata["generation"])
		require.Equal(t, uint64Bytes(0), after.metadata["attempt_mutation_revision"])
		for _, table := range []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
			require.Empty(t, after.typed[table], table)
		}
		publicationOpenRequirePrivateFile(t, input.database)
		reopened, err := Open(input.directory, input.binding)
		if reopened != nil {
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
		}
		require.NoError(t, err)
		require.Equal(t, 3, reopened.schemaVersion)
		require.Equal(t, after.metadata, incomingMaterialUpgradeStoredMetadata(t, ctx, reopened.conn))
		require.Equal(t, after.typed, incomingMaterialUpgradeFixtureTypedRows(t, ctx, reopened.conn))
		require.NoError(t, reopened.Close())
		require.Equal(t, after, publicationOpenSnapshotSource(t, ctx, input.database, 3))
	})

	t.Run("pre-existing empty file ignores chmod override", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "empty")
		info, err := os.Lstat(input.database)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		require.Equal(t, int64(0), info.Size())
		calls := 0
		input.options.createdDatabaseChmod = func(string) error {
			calls++
			return errors.New("unused empty override canary")
		}
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Zero(t, calls)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireEmptyState(t, ctx, store)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireEmptyDestination(t, destination)
		require.Len(t, destination.metadata, 7)
		require.False(t, allZero(destination.metadata["database_id"]))
		require.Equal(t, uint64Bytes(0), destination.metadata["revision"])
		require.Equal(t, uint64Bytes(0), destination.metadata["generation"])
		require.Equal(t, uint64Bytes(0), destination.metadata["attempt_mutation_revision"])
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequirePrivateFiles(t, input.directory)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
	})

	t.Run("existing current3 ignores chmod override", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenCurrent3PendingInput(t)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 3)
		payload := publicationOpenCapturePayload(t, input)
		publicationOpenRequireHealthyCurrent3Probe(t, input)
		calls := 0
		input.options.createdDatabaseChmod = func(string) error {
			calls++
			return errors.New("unused current override canary")
		}
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Zero(t, calls)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Empty(t, recorder.upgrade)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		for _, event := range recorder.events {
			require.Equal(t, "open", event.stream)
		}
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		require.Equal(t, before.metadata, publicationOpenRequireSchema3(t, ctx, store, input))
		publicationOpenRequirePendingState(t, ctx, store, before)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequirePrivateFiles(t, input.directory)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireSourcePreserved(t, ctx, input.database, before)
	})

	t.Run("genuine schema one upgrade ignores chmod override", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "positions-v1")
		require.True(t, input.options.UpgradeFromPositions)
		require.True(t, input.options.UpgradeFromAttempts)
		before := publicationOpenSnapshotSource(t, ctx, input.database, 1)
		payload := publicationOpenCapturePayload(t, input)
		calls := 0
		input.options.createdDatabaseChmod = func(string) error {
			calls++
			return errors.New("unused upgrade override canary")
		}
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		require.NoError(t, err)
		require.Zero(t, calls)
		require.Equal(t, []int{101, 102, 103, 1, 2, 3, 4}, recorder.openPoints())
		require.Equal(t, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, recorder.upgrade)
		require.Equal(t, 1, recorder.commits)
		require.Len(t, recorder.commitResults, 1)
		require.NoError(t, recorder.commitResults[0])
		expectedEvents := make([]publicationOpenEvent, 0, 24)
		for _, point := range []int{101, 102, 103} {
			expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "open", point: point})
		}
		for point := 1; point <= 16; point++ {
			expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "migrate", point: point})
		}
		expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "commit", point: 0})
		for _, point := range []int{1, 2, 3, 4} {
			expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "open", point: point})
		}
		require.Equal(t, expectedEvents, recorder.events)
		publicationOpenRequireAcquisitionIdentities(t, recorder, store)
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireV1Upgraded(t, ctx, store, before)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequirePrivateFiles(t, input.directory)
		publicationOpenRequirePayloadPreserved(t, input, payload)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
		publicationOpenRequirePayloadPreserved(t, input, payload)
	})

	t.Run("unsafe pre-existing database refuses without chmod", func(t *testing.T) {
		input := publicationOpenInputFor(t, "empty")
		require.NoError(t, os.Chmod(input.database, 0o640))
		original, err := os.ReadFile(input.database)
		require.NoError(t, err)
		info, err := os.Lstat(input.database)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
		require.Equal(t, int64(len(original)), info.Size())
		calls := 0
		input.options.createdDatabaseChmod = func(string) error {
			calls++
			return errors.New("unused unsafe override canary")
		}
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
		recorder.canary = errors.New("unsafe preflight canary")
		store, err := OpenWithOptions(input.directory, input.binding, recorder.options(input.options))
		if store != nil {
			t.Cleanup(func() { assert.NoError(t, store.Close()) })
		}
		state := publicationOpenRequireRefused(t, store, err, recorder, []int{101}, ErrInvalid, ReasonBinding)
		require.Zero(t, calls)
		require.Nil(t, state.lock)
		require.Nil(t, state.db)
		require.Nil(t, state.conn)
		require.Equal(t, -1, state.payloadFD)
		require.NotNil(t, state.holder)
		require.GreaterOrEqual(t, state.rootFD, 0)
		publicationOpenRequireFD0(t, fd0)
		_, err = os.Lstat(filepath.Join(input.directory, "publication.db.lock"))
		require.ErrorIs(t, err, os.ErrNotExist)
		after, err := os.ReadFile(input.database)
		require.NoError(t, err)
		require.Equal(t, original, after)
		afterInfo, err := os.Lstat(input.database)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o640), afterInfo.Mode().Perm())
		require.Equal(t, int64(len(original)), afterInfo.Size())
	})

	t.Run("absent sidecars allowed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		t.Cleanup(cancel)
		input := publicationOpenInputFor(t, "absent")
		wal := filepath.Join(input.directory, "publication.db-wal")
		shm := filepath.Join(input.directory, "publication.db-shm")
		_, err := os.Lstat(wal)
		require.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Lstat(shm)
		require.ErrorIs(t, err, os.ErrNotExist)
		require.NoError(t, secureCreatedSidecars(input.directory))
		_, err = os.Lstat(wal)
		require.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Lstat(shm)
		require.ErrorIs(t, err, os.ErrNotExist)
		_, err = os.Lstat(input.database)
		require.ErrorIs(t, err, os.ErrNotExist)
		fd0 := publicationOpenFD0(t)
		recorder := newPublicationOpenRecorder()
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
		publicationOpenRequireSchema3(t, ctx, store, input)
		publicationOpenRequireEmptyState(t, ctx, store)
		destination := publicationOpenCaptureDestination(t, ctx, store)
		publicationOpenRequireEmptyDestination(t, destination)
		require.Len(t, destination.metadata, 7)
		require.False(t, allZero(destination.metadata["database_id"]))
		require.Equal(t, uint64Bytes(0), destination.metadata["revision"])
		require.Equal(t, uint64Bytes(0), destination.metadata["generation"])
		require.Equal(t, uint64Bytes(0), destination.metadata["attempt_mutation_revision"])
		publicationOpenRequireFD0(t, fd0)
		publicationOpenRequirePrivateFiles(t, input.directory)
		publicationOpenRequireReleased(t, ctx, store, input)
		publicationOpenRequireDestinationPreserved(t, ctx, input, destination)
	})
}

func publicationOpenRequireClosedResources(t *testing.T, store *Store, directory string) {
	t.Helper()
	require.NotNil(t, store)
	require.False(t, store.closed)
	rootFD := store.rootFD
	conn := store.conn
	pool := store.db
	lock := store.lock
	require.GreaterOrEqual(t, rootFD, 0)
	require.NotNil(t, conn)
	require.NotNil(t, pool)
	require.NotNil(t, lock)
	require.Equal(t, -1, store.payloadFD)
	var stat unix.Stat_t
	closeErr := store.Close()
	rootErr := unix.Fstat(rootFD, &stat)
	require.NoError(t, closeErr)
	require.True(t, store.closed)
	require.ErrorIs(t, rootErr, unix.EBADF)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	require.ErrorIs(t, conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := pool.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	publicationOpenRequireLockWitness(t, directory, true)
	require.NoError(t, store.Close())
}

func TestIncomingMaterialPublicUpgradeCommitOutcomes(t *testing.T) {
	for _, image := range []string{"positions-v1", "pending-genesis", "mixed"} {
		for _, outcome := range []struct {
			name         string
			rollback     bool
			returnCanary bool
			returnsStore bool
			committed    bool
		}{
			{name: "actual Commit success", returnsStore: true, committed: true},
			{name: "actual Commit success then canary error", returnCanary: true, committed: true},
			{name: "actual Rollback then actual Commit", rollback: true},
		} {
			t.Run(image+" "+outcome.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				t.Cleanup(cancel)
				c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
				require.NotNil(t, c)
				require.NotNil(t, c.owner)
				incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, c.owner.conn, c)
				incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
				require.Equal(t, DefaultLimits(), c.limits)
				require.Equal(t, DefaultAttemptLimits(), c.attemptLimits)
				if image == "positions-v1" {
					require.Equal(t, 1, c.version)
					require.Len(t, c.metadata, 5)
					require.Len(t, c.rows, 6)
				} else {
					require.Equal(t, 2, c.version)
					require.Len(t, c.metadata, 7)
					require.Len(t, c.rows, 15)
				}
				if image == "mixed" {
					require.Equal(t, 44, incomingMaterialUpgradeFixtureRowTotal(c.rows))
				} else {
					require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(c.rows))
				}
				c.owner.close(t)
				require.True(t, c.owner.closed)
				require.True(t, c.owner.sqlClosed)
				require.Equal(t, -1, c.owner.rootFD)
				probe, err := probeSchema(c.databasePath, c.binding, c.limits, c.attemptLimits)
				require.NoError(t, err)
				require.True(t, probe.recognized)
				require.False(t, probe.initial)
				require.Equal(t, c.version, probe.version)
				before := incomingMaterialPublicCommitReadback(t, ctx, c, false)
				migrationPoints := []int{13, 14, 15, 16}
				if c.version == 1 {
					migrationPoints = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				}
				preCommitEvents := []publicationOpenEvent{
					{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
				}
				for _, point := range migrationPoints {
					preCommitEvents = append(preCommitEvents, publicationOpenEvent{stream: "migrate", point: point})
				}
				base := DefaultOpenOptions()
				base.PositionLimits, base.AttemptLimits = c.limits, c.attemptLimits
				base.UpgradeFromPositions = c.version == 1
				base.UpgradeFromAttempts = true
				require.Equal(t, image == "positions-v1", base.UpgradeFromPositions)
				require.True(t, base.UpgradeFromAttempts)
				input := publicationOpenInput{directory: c.directory, database: c.databasePath, binding: c.binding, options: base}
				recorder := newPublicationOpenRecorder()
				canary := errors.New("actual public upgrade Commit succeeded before this selected canary")
				recorder.canary = canary
				options := recorder.options(base)
				hookCalls, explicitRollbackCalls := 0, 0
				var explicitRollbackResults []error
				options.upgradeCommit = func(tx *sql.Tx) error {
					hookCalls++
					require.Equal(t, 1, hookCalls)
					require.Equal(t, []int{101, 102, 103}, recorder.openPoints())
					require.Equal(t, migrationPoints, recorder.upgrade)
					require.Equal(t, preCommitEvents, recorder.events)
					require.Zero(t, recorder.commits)
					require.Empty(t, recorder.commitResults)
					require.NoError(t, checkSchemaVersion(ctx, tx, 3))
					if outcome.rollback {
						explicitRollbackCalls++
						rollbackErr := tx.Rollback()
						explicitRollbackResults = append(explicitRollbackResults, rollbackErr)
						require.NoError(t, rollbackErr)
					}
					commitErr := recorder.commit(tx)
					if outcome.rollback {
						require.ErrorIs(t, commitErr, sql.ErrTxDone)
						return commitErr
					}
					require.NoError(t, commitErr)
					if outcome.returnCanary {
						return canary
					}
					return commitErr
				}
				fd0 := publicationOpenFD0(t)
				store, err := OpenWithOptions(c.directory, c.binding, options)
				if store != nil {
					t.Cleanup(func() { assert.NoError(t, store.Close()) })
				}
				var transferred publicationOpenSourceSnapshot
				if outcome.returnsStore {
					require.NoError(t, err)
					incomingMaterialFlagMatrixRequireTrace(t, recorder, image, c.version)
					publicationOpenRequireAcquisitionIdentities(t, recorder, store)
					publicationOpenRequireFD0(t, fd0)
					publicationOpenRequireSchema3(t, ctx, store, input)
					incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, store.conn, c)
					transferred = publicationOpenCaptureDestination(t, ctx, store)
					incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
					publicationOpenRequireClosedResources(t, store, c.directory)
					publicationOpenRequireFD0(t, fd0)
				} else {
					incomingMaterialPublicCommitRequireFailed(t, store, err, recorder, migrationPoints, canary, c.directory, fd0)
				}
				require.Equal(t, 1, hookCalls)
				require.Equal(t, 1, recorder.commits)
				require.Len(t, recorder.commitResults, 1)
				if outcome.rollback {
					require.Equal(t, 1, explicitRollbackCalls)
					require.Len(t, explicitRollbackResults, 1)
					require.NoError(t, explicitRollbackResults[0])
					require.ErrorIs(t, recorder.commitResults[0], sql.ErrTxDone)
				} else {
					require.Zero(t, explicitRollbackCalls)
					require.Empty(t, explicitRollbackResults)
					require.NoError(t, recorder.commitResults[0])
				}
				durable := incomingMaterialPublicCommitReadback(t, ctx, c, outcome.committed)
				if outcome.committed {
					if outcome.returnsStore {
						require.Equal(t, transferred, durable)
					}
					reopenedFD0 := publicationOpenFD0(t)
					reopened, err := Open(c.directory, c.binding)
					if reopened != nil {
						t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
					}
					require.NoError(t, err)
					publicationOpenRequireFD0(t, reopenedFD0)
					publicationOpenRequireSchema3(t, ctx, reopened, input)
					incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, reopened.conn, c)
					require.Equal(t, durable, publicationOpenCaptureDestination(t, ctx, reopened))
					incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
					publicationOpenRequireClosedResources(t, reopened, c.directory)
					publicationOpenRequireFD0(t, reopenedFD0)
					require.Equal(t, durable, incomingMaterialPublicCommitReadback(t, ctx, c, true))
				} else {
					require.Equal(t, before, durable)
					reopenFD0 := publicationOpenFD0(t)
					refused, err := Open(c.directory, c.binding)
					if refused != nil {
						t.Cleanup(func() { assert.NoError(t, refused.Close()) })
					}
					require.Nil(t, refused)
					requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
					publicationOpenRequireFD0(t, reopenFD0)
					publicationOpenRequireLockWitness(t, c.directory, true)
					require.Equal(t, before, incomingMaterialPublicCommitReadback(t, ctx, c, false))
					publicationOpenRequireFD0(t, reopenFD0)
				}
				publicationOpenRequireFD0(t, fd0)
			})
		}
	}
}

func incomingMaterialPublicCommitRequireFailed(t *testing.T, store *Store, err error, recorder *publicationOpenRecorder, migrationPoints []int, canary error, directory string, fd0 unix.Stat_t) {
	t.Helper()
	state, present := recorder.states[openConnectionAcquiredFault]
	require.True(t, present)
	require.GreaterOrEqual(t, state.rootFD, 0)
	var stat unix.Stat_t
	rootErr := unix.Fstat(state.rootFD, &stat)
	require.Nil(t, store)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
	require.NotNil(t, state.holder)
	require.True(t, state.holder.closed)
	require.Equal(t, -1, state.payloadFD)
	require.Equal(t, -1, state.holder.payloadFD)
	require.ErrorIs(t, rootErr, unix.EBADF)
	require.Equal(t, []int{101, 102, 103}, recorder.openPoints())
	require.Len(t, recorder.states, 3)
	require.Equal(t, migrationPoints, recorder.upgrade)
	require.Equal(t, 1, recorder.commits)
	require.Len(t, recorder.commitResults, 1)
	expected := []publicationOpenEvent{
		{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
	}
	for _, point := range migrationPoints {
		expected = append(expected, publicationOpenEvent{stream: "migrate", point: point})
	}
	expected = append(expected, publicationOpenEvent{stream: "commit", point: 0})
	require.Equal(t, expected, recorder.events)
	publicationOpenRequireRefusalIdentities(t, recorder, state, true)
	require.Equal(t, state.rootFD, state.holder.rootFD)
	require.Same(t, state.lock, state.holder.lock)
	require.Same(t, state.db, state.holder.db)
	require.Same(t, state.conn, state.holder.conn)
	unwrapped := errors.Unwrap(err)
	require.Same(t, ErrStorage, unwrapped)
	require.Nil(t, errors.Unwrap(unwrapped))
	for _, raw := range []error{canary, sql.ErrTxDone} {
		require.NotErrorIs(t, err, raw)
		require.NotErrorIs(t, unwrapped, raw)
		require.NotContains(t, err.Error(), raw.Error())
		require.NotContains(t, fmt.Sprintf("%+v", err), raw.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	require.ErrorIs(t, state.conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := state.db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	publicationOpenRequireFD0(t, fd0)
	publicationOpenRequireLockWitness(t, directory, true)
	publicationOpenRequireFD0(t, fd0)
}

func incomingMaterialPublicCommitReadback(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase, committed bool) publicationOpenSourceSnapshot {
	t.Helper()
	conn, closeConn := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, c.databasePath)
	version := c.version
	if committed {
		version = 3
		incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, conn, c)
	} else {
		incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, conn, c)
	}
	require.NoError(t, checkSchemaVersion(ctx, conn, version))
	snapshot := publicationOpenSourceSnapshot{version: incomingMaterialUpgradeUserVersion(t, ctx, conn), metadata: incomingMaterialUpgradeStoredMetadata(t, ctx, conn), incomingTableCount: incomingMaterialUpgradeIncomingTableRows(t, ctx, conn)}
	if version == 1 {
		snapshot.typed = incomingMaterialUpgradeV1Rows(t, ctx, conn)
		require.Len(t, snapshot.typed, 6)
	} else {
		snapshot.typed = incomingMaterialUpgradeFixtureTypedRows(t, ctx, conn)
		require.Len(t, snapshot.typed, 15)
	}
	if committed {
		require.Equal(t, int64(1), snapshot.incomingTableCount)
		snapshot.incomingRefCount = incomingMaterialUpgradeCount(t, ctx, conn, "SELECT COUNT(*) FROM accepted_material_refs")
		require.Zero(t, snapshot.incomingRefCount)
	} else {
		require.Zero(t, snapshot.incomingTableCount)
	}
	closeConn(t)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	return snapshot
}

func TestIncomingMaterialPublicUpgradeSQLiteCommitFailure(t *testing.T) {
	for _, image := range []string{"positions-v1", "pending-genesis", "mixed"} {
		t.Run(image, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
			require.NotNil(t, c)
			require.NotNil(t, c.owner)
			incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, c.owner.conn, c)
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			if image == "positions-v1" {
				require.Equal(t, 1, c.version)
				require.Len(t, c.metadata, 5)
				require.Len(t, c.rows, 6)
			} else {
				require.Equal(t, 2, c.version)
				require.Len(t, c.metadata, 7)
				require.Len(t, c.rows, 15)
			}
			if image == "mixed" {
				require.Equal(t, 44, incomingMaterialUpgradeFixtureRowTotal(c.rows))
			} else {
				require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(c.rows))
			}
			c.owner.close(t)
			require.True(t, c.owner.closed)
			require.True(t, c.owner.sqlClosed)
			require.Equal(t, -1, c.owner.rootFD)
			before := incomingMaterialPublicCommitReadback(t, ctx, c, false)
			probe, err := probeSchema(c.databasePath, c.binding, c.limits, c.attemptLimits)
			require.NoError(t, err)
			require.True(t, probe.recognized)
			require.False(t, probe.initial)
			require.Equal(t, c.version, probe.version)
			migrationPoints := []int{13, 14, 15, 16}
			if c.version == 1 {
				migrationPoints = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			}
			preCommitEvents := []publicationOpenEvent{
				{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
			}
			for _, point := range migrationPoints {
				preCommitEvents = append(preCommitEvents, publicationOpenEvent{stream: "migrate", point: point})
			}
			base := DefaultOpenOptions()
			base.PositionLimits, base.AttemptLimits = c.limits, c.attemptLimits
			base.UpgradeFromPositions = c.version == 1
			base.UpgradeFromAttempts = true
			require.Equal(t, image == "positions-v1", base.UpgradeFromPositions)
			require.True(t, base.UpgradeFromAttempts)
			recorder := newPublicationOpenRecorder()
			options := recorder.options(base)
			hookCalls := 0
			var actualCommitErr error
			options.upgradeCommit = func(tx *sql.Tx) error {
				hookCalls++
				require.Equal(t, 1, hookCalls)
				require.NotNil(t, tx)
				require.Equal(t, []int{101, 102, 103}, recorder.openPoints())
				require.Equal(t, migrationPoints, recorder.upgrade)
				require.Equal(t, preCommitEvents, recorder.events)
				require.Zero(t, recorder.commits)
				require.Empty(t, recorder.commitResults)
				require.NoError(t, checkSchemaVersion(ctx, tx, 3))
				require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, c.source))
				require.Equal(t, int64(1), incomingMaterialUpgradeIncomingTableRows(t, ctx, tx))
				require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
				incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
				revision := incomingMaterialPublicSQLiteInsertDanglingRef(t, ctx, tx, c.binding)
				incomingMaterialPublicSQLiteRequireForeignKeys(t, ctx, tx, revision)
				actualCommitErr = recorder.commit(tx)
				require.Error(t, actualCommitErr)
				require.NotErrorIs(t, actualCommitErr, sql.ErrTxDone)
				var sqliteError *sqliteDriver.Error
				require.ErrorAs(t, actualCommitErr, &sqliteError)
				require.NotNil(t, sqliteError)
				require.Equal(t, sqliteLib.SQLITE_CONSTRAINT_FOREIGNKEY, sqliteError.Code())
				return actualCommitErr
			}
			fd0 := publicationOpenFD0(t)
			store, err := OpenWithOptions(c.directory, c.binding, options)
			if store != nil {
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
			}
			require.NotNil(t, actualCommitErr)
			incomingMaterialPublicCommitRequireFailed(t, store, err, recorder, migrationPoints, actualCommitErr, c.directory, fd0)
			require.Equal(t, 1, hookCalls)
			require.Equal(t, 1, recorder.commits)
			require.Len(t, recorder.commitResults, 1)
			require.Same(t, actualCommitErr, recorder.commitResults[0])
			require.NotErrorIs(t, recorder.commitResults[0], sql.ErrTxDone)
			var sqliteError *sqliteDriver.Error
			require.ErrorAs(t, recorder.commitResults[0], &sqliteError)
			require.NotNil(t, sqliteError)
			require.Equal(t, sqliteLib.SQLITE_CONSTRAINT_FOREIGNKEY, sqliteError.Code())
			require.Equal(t, before, incomingMaterialPublicCommitReadback(t, ctx, c, false))
			reopenFD0 := publicationOpenFD0(t)
			refused, err := Open(c.directory, c.binding)
			if refused != nil {
				t.Cleanup(func() { assert.NoError(t, refused.Close()) })
			}
			require.Nil(t, refused)
			requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
			publicationOpenRequireFD0(t, reopenFD0)
			publicationOpenRequireLockWitness(t, c.directory, true)
			require.Equal(t, before, incomingMaterialPublicCommitReadback(t, ctx, c, false))
			publicationOpenRequireFD0(t, reopenFD0)
			publicationOpenRequireFD0(t, fd0)
		})
	}
}

func incomingMaterialPublicSQLiteInsertDanglingRef(t *testing.T, ctx context.Context, tx *sql.Tx, binding Binding) int64 {
	t.Helper()
	var foreignKeys, deferred int64
	require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys))
	require.Equal(t, int64(1), foreignKeys)
	require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&deferred))
	require.Zero(t, deferred)
	_, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys=ON")
	require.NoError(t, err)
	require.NoError(t, tx.QueryRowContext(ctx, "PRAGMA defer_foreign_keys").Scan(&deferred))
	require.Equal(t, int64(1), deferred)
	revision := int64(publication.MaxSequence)
	require.Equal(t, int64(9007199254740991), revision)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_events WHERE revision=?", revision))
	f := newFixture(t, BackendPublicRepo)
	for _, sequence := range []uint64{0, 1, 2, 3} {
		f.appendRecord(t, sequence)
	}
	require.Len(t, f.blocks, 4)
	snapshot, err := publication.DecodeSnapshot(f.blocks[3].Raw)
	require.NoError(t, err)
	require.Equal(t, uint64(3), snapshot.PublicationSeq)
	require.Equal(t, binding.Vault, snapshot.Vault)
	recordCID, err := publication.RecordCID(f.blocks[3].Raw)
	require.NoError(t, err)
	require.NotEmpty(t, recordCID)
	require.LessOrEqual(t, len(recordCID), publication.MaxCIDBytes)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_records WHERE cid=?", recordCID))
	blobCID, size := incomingMaterialSecondPayloadCID(t)
	require.NotEmpty(t, blobCID)
	require.LessOrEqual(t, len(blobCID), publication.MaxCIDBytes)
	require.Positive(t, size)
	require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM payload_objects WHERE blob_cid=?", blobCID))
	result, err := tx.ExecContext(ctx, "INSERT INTO accepted_material_refs(accepted_revision,record_cid,blob_cid) VALUES(?,?,?)", revision, recordCID, blobCID)
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)
	require.Equal(t, int64(1), incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
	var revisionType, recordType, blobType string
	var storedRevision int64
	var storedRecord, storedBlob []byte
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT typeof(accepted_revision),accepted_revision,typeof(record_cid),record_cid,typeof(blob_cid),blob_cid FROM accepted_material_refs").Scan(&revisionType, &storedRevision, &recordType, &storedRecord, &blobType, &storedBlob))
	require.Equal(t, "integer", revisionType)
	require.Equal(t, revision, storedRevision)
	require.Equal(t, "blob", recordType)
	require.Equal(t, recordCID, storedRecord)
	require.Equal(t, "blob", blobType)
	require.Equal(t, blobCID, storedBlob)
	return revision
}

func incomingMaterialPublicSQLiteRequireForeignKeys(t *testing.T, ctx context.Context, tx *sql.Tx, revision int64) {
	t.Helper()
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	require.NoError(t, err)
	violations := make([][]any, 0, 3)
	var scanErr error
	for rows.Next() {
		var values []any
		values, scanErr = scanRawValues(rows, 4)
		if scanErr != nil {
			break
		}
		violations = append(violations, values)
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	require.NoError(t, scanErr)
	require.NoError(t, rowsErr)
	require.NoError(t, closeErr)
	require.Len(t, violations, 3)
	parents := make([]string, 0, 3)
	foreignKeys := make(map[int64]bool, 3)
	for _, row := range violations {
		require.Len(t, row, 4)
		table, ok := row[0].(string)
		require.True(t, ok)
		require.Equal(t, "accepted_material_refs", table)
		rowID, ok := row[1].(int64)
		require.True(t, ok)
		require.Equal(t, revision, rowID)
		parent, ok := row[2].(string)
		require.True(t, ok)
		parents = append(parents, parent)
		foreignKey, ok := row[3].(int64)
		require.True(t, ok)
		require.GreaterOrEqual(t, foreignKey, int64(0))
		require.NotContains(t, foreignKeys, foreignKey)
		foreignKeys[foreignKey] = true
	}
	require.ElementsMatch(t, []string{"accepted_events", "accepted_records", "payload_objects"}, parents)
}

func TestIncomingMaterialPublicUpgradeRollbackOwnership(t *testing.T) {
	for _, image := range []string{"pending-genesis", "mixed"} {
		for _, failAt := range []int{13, 14, 15, 16} {
			t.Run(fmt.Sprintf("%s fail at %d", image, failAt), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				t.Cleanup(cancel)
				c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
				require.NotNil(t, c)
				require.NotNil(t, c.owner)
				require.Equal(t, 2, c.version)
				require.Len(t, c.metadata, 7)
				require.Len(t, c.rows, 15)
				if image == "mixed" {
					require.Equal(t, 44, incomingMaterialUpgradeFixtureRowTotal(c.rows))
				} else {
					require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(c.rows))
				}
				incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, c.owner.conn, c)
				incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
				c.owner.close(t)
				require.True(t, c.owner.closed)
				require.True(t, c.owner.sqlClosed)
				require.Equal(t, -1, c.owner.rootFD)
				before := incomingMaterialPublicCommitReadback(t, ctx, c, false)
				probe, err := probeSchema(c.databasePath, c.binding, c.limits, c.attemptLimits)
				require.NoError(t, err)
				require.True(t, probe.recognized)
				require.False(t, probe.initial)
				require.Equal(t, 2, probe.version)
				expectedReached := make([]int, 0, failAt-12)
				for point := 13; point <= failAt; point++ {
					expectedReached = append(expectedReached, point)
				}
				base := DefaultOpenOptions()
				base.PositionLimits, base.AttemptLimits = c.limits, c.attemptLimits
				base.UpgradeFromAttempts = true
				require.False(t, base.UpgradeFromPositions)
				require.True(t, base.UpgradeFromAttempts)
				recorder := newPublicationOpenRecorder()
				canary := fmt.Errorf("public source2 rollback fault %s at %d", image, failAt)
				recorder.canary = canary
				options := recorder.options(base)
				options.upgradeFault = func(point int) error {
					require.NoError(t, recorder.upgradeFault(point))
					if point == failAt {
						return canary
					}
					return nil
				}
				fd0 := publicationOpenFD0(t)
				store, err := OpenWithOptions(c.directory, c.binding, options)
				if store != nil {
					t.Cleanup(func() { assert.NoError(t, store.Close()) })
				}
				incomingMaterialPublicRollbackRequireFailed(t, store, err, recorder, expectedReached, canary, c.directory, fd0)
				require.Equal(t, before, incomingMaterialPublicCommitReadback(t, ctx, c, false))
				reopenFD0 := publicationOpenFD0(t)
				refused, err := Open(c.directory, c.binding)
				if refused != nil {
					t.Cleanup(func() { assert.NoError(t, refused.Close()) })
				}
				require.Nil(t, refused)
				requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonUpgradeRequired)
				publicationOpenRequireFD0(t, reopenFD0)
				publicationOpenRequireLockWitness(t, c.directory, true)
				require.Equal(t, before, incomingMaterialPublicCommitReadback(t, ctx, c, false))
				publicationOpenRequireFD0(t, reopenFD0)
				publicationOpenRequireFD0(t, fd0)
			})
		}
	}
}

func incomingMaterialPublicRollbackRequireFailed(t *testing.T, store *Store, err error, recorder *publicationOpenRecorder, expectedReached []int, canary error, directory string, fd0 unix.Stat_t) {
	t.Helper()
	state, present := recorder.states[openConnectionAcquiredFault]
	require.True(t, present)
	require.GreaterOrEqual(t, state.rootFD, 0)
	var stat unix.Stat_t
	rootErr := unix.Fstat(state.rootFD, &stat)
	require.Nil(t, store)
	requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonIO)
	require.NotNil(t, state.holder)
	require.True(t, state.holder.closed)
	require.Equal(t, -1, state.payloadFD)
	require.Equal(t, -1, state.holder.payloadFD)
	require.ErrorIs(t, rootErr, unix.EBADF)
	require.Equal(t, []int{101, 102, 103}, recorder.openPoints())
	require.Len(t, recorder.states, 3)
	require.NotEmpty(t, expectedReached)
	require.Equal(t, expectedReached, recorder.upgrade)
	require.Zero(t, recorder.commits)
	require.Empty(t, recorder.commitResults)
	expectedEvents := []publicationOpenEvent{
		{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103},
	}
	for _, point := range expectedReached {
		expectedEvents = append(expectedEvents, publicationOpenEvent{stream: "migrate", point: point})
	}
	require.Equal(t, expectedEvents, recorder.events)
	publicationOpenRequireRefusalIdentities(t, recorder, state, true)
	require.Equal(t, state.rootFD, state.holder.rootFD)
	require.Same(t, state.lock, state.holder.lock)
	require.Same(t, state.db, state.holder.db)
	require.Same(t, state.conn, state.holder.conn)
	unwrapped := errors.Unwrap(err)
	require.Same(t, ErrStorage, unwrapped)
	require.Nil(t, errors.Unwrap(unwrapped))
	require.NotErrorIs(t, err, canary)
	require.NotErrorIs(t, unwrapped, canary)
	require.NotContains(t, err.Error(), canary.Error())
	require.NotContains(t, fmt.Sprintf("%+v", err), canary.Error())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	require.ErrorIs(t, state.conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := state.db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	publicationOpenRequireFD0(t, fd0)
	publicationOpenRequireLockWitness(t, directory, true)
	publicationOpenRequireFD0(t, fd0)
}

func TestIncomingMaterialPublicUpgradeDestinationPostguards(t *testing.T) {
	for _, test := range []struct {
		name   string
		class  error
		reason Reason
	}{
		{name: "extra named index", class: ErrSchema, reason: ReasonSchema},
		{name: "altered canonical binding", class: ErrInvalid, reason: ReasonBinding},
		{name: "changed valid canonical attempt limits", class: ErrInvalid, reason: ReasonLimits},
		{name: "zero database ID", class: ErrSchema, reason: ReasonCorrupt},
		{name: "mutation overflow", class: ErrSchema, reason: ReasonCorrupt},
		{name: "accepted-event digest corruption", class: ErrSchema, reason: ReasonCorrupt},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialPublicCompletionPrepare(t, ctx, "mixed")
			require.Len(t, c.rows["payload_objects"], 3)
			recorder := newPublicationOpenRecorder()
			options := incomingMaterialPublicCompletionOptions(t, ctx, c, recorder)
			var expected incomingMaterialPublicRefusalSnapshot
			mutations := 0
			recorder.mutate = func(point int) {
				if point != incomingMaterialOpenDestinationFault {
					return
				}
				mutations++
				require.Equal(t, 1, mutations)
				incomingMaterialPublicCompletionTrace(t, recorder, c.version, 1)
				holder := recorder.states[point].holder
				require.NotNil(t, holder)
				incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, holder.conn, c)
				incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
				before := incomingMaterialPublicPostguardCapture(t, ctx, holder.conn)
				require.Equal(t, applicationID, before.applicationID)
				require.Equal(t, 3, before.userVersion)
				require.Equal(t, "wal", before.journalMode)
				require.Len(t, before.objects, 32)
				require.Equal(t, c.metadata, before.metadata)
				require.Equal(t, c.rows, before.rows)
				require.True(t, before.incomingPresent)
				require.Empty(t, before.incoming)
				expected = incomingMaterialPublicRefusalClone(before)
				incomingMaterialPublicPostguardDamage(t, ctx, holder.conn, c, test.name, &expected)
				require.NotEqual(t, before, expected)
				require.Equal(t, expected, incomingMaterialPublicPostguardCapture(t, ctx, holder.conn))
				require.Equal(t, before.metadata, c.source.metadata)
			}
			fd0 := publicationOpenFD0(t)
			store, err := OpenWithOptions(c.directory, c.binding, options)
			if store != nil {
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
			}
			incomingMaterialPublicCompletionRequireResources(t, store, recorder, c, 1, 0o600, fd0)
			publicationOpenRequireLockWitness(t, c.directory, true)
			requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
			require.Same(t, ErrStorage, errors.Unwrap(err))
			require.Nil(t, errors.Unwrap(errors.Unwrap(err)))
			require.Equal(t, 1, mutations)
			require.Equal(t, expected, incomingMaterialPublicRefusalCapture(t, ctx, c.databasePath, "publication"))
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			ordinary := newPublicationOpenRecorder()
			ordinary.canary = errors.New("unused corrupted postguard reopen canary")
			refused, reopenErr := OpenWithOptions(c.directory, c.binding, ordinary.options(DefaultOpenOptions()))
			if refused != nil {
				t.Cleanup(func() { assert.NoError(t, refused.Close()) })
			}
			state := publicationOpenRequireRefused(t, refused, reopenErr, ordinary, []int{101, 102}, test.class, test.reason)
			publicationOpenRequireRefusalIdentities(t, ordinary, state, false)
			publicationOpenRequireFD0(t, fd0)
			publicationOpenRequireLockWitness(t, c.directory, true)
			require.Equal(t, expected, incomingMaterialPublicRefusalCapture(t, ctx, c.databasePath, "publication"))
			incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
			publicationOpenRequireFD0(t, fd0)
		})
	}
}

func incomingMaterialPublicPostguardCapture(t *testing.T, ctx context.Context, q queryer) incomingMaterialPublicRefusalSnapshot {
	t.Helper()
	var snapshot incomingMaterialPublicRefusalSnapshot
	require.NoError(t, q.QueryRowContext(ctx, "PRAGMA application_id").Scan(&snapshot.applicationID))
	require.NoError(t, q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&snapshot.userVersion))
	require.NoError(t, q.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&snapshot.journalMode))
	snapshot.objects = incomingMaterialUpgradeFixtureObjects(t, ctx, q)
	snapshot.metadata = incomingMaterialUpgradeStoredMetadata(t, ctx, q)
	snapshot.rows = incomingMaterialUpgradeFixtureTypedRows(t, ctx, q)
	_, snapshot.incomingPresent = snapshot.objects["accepted_material_refs"]
	if snapshot.incomingPresent {
		snapshot.incoming = incomingMaterialSchemaIncomingRows(t, ctx, q)
	}
	return snapshot
}

func incomingMaterialPublicPostguardDamage(t *testing.T, ctx context.Context, conn *sql.Conn, c *incomingMaterialUpgradeOutcomeCase, name string, expected *incomingMaterialPublicRefusalSnapshot) {
	t.Helper()
	var key string
	var value []byte
	switch name {
	case "extra named index":
		statement := "CREATE INDEX incoming_postguard_extra ON accepted_material_refs(record_cid)"
		require.NotContains(t, expected.objects, "incoming_postguard_extra")
		_, err := conn.ExecContext(ctx, statement)
		require.NoError(t, err)
		expected.objects["incoming_postguard_extra"] = incomingMaterialUpgradeFixtureObject{kind: "index", sql: statement}
		return
	case "altered canonical binding":
		binding := c.binding
		binding.Vault[0] ^= 1
		require.NoError(t, validateBinding(binding))
		require.NotEqual(t, c.binding, binding)
		encoded, err := encodeBinding(binding)
		require.NoError(t, err)
		key, value = "binding", encoded
	case "changed valid canonical attempt limits":
		limits := c.attemptLimits
		require.Greater(t, limits.HistoryPageEntries, uint32(1))
		limits.HistoryPageEntries--
		require.NoError(t, validateAttemptLimits(limits))
		require.NotEqual(t, c.attemptLimits, limits)
		encoded, err := encodeAttemptLimits(limits)
		require.NoError(t, err)
		key, value = "attempt_limits", encoded
	case "zero database ID":
		require.Len(t, expected.metadata["database_id"], 32)
		require.False(t, allZero(expected.metadata["database_id"]))
		key, value = "database_id", make([]byte, 32)
	case "mutation overflow":
		require.Equal(t, uint64Bytes(17), expected.metadata["attempt_mutation_revision"])
		key, value = "attempt_mutation_revision", uint64Bytes(uint64(1)<<63)
		require.Len(t, value, 8)
	case "accepted-event digest corruption":
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
		result, err := conn.ExecContext(ctx, "UPDATE accepted_events SET digest=? WHERE revision=1", make([]byte, 32))
		require.NoError(t, err)
		affected, err := result.RowsAffected()
		require.NoError(t, err)
		require.Equal(t, int64(1), affected)
		return
	default:
		require.FailNow(t, "unsupported public postguard mutation")
		return
	}
	require.Contains(t, expected.metadata, key)
	require.Len(t, expected.metadata, 7)
	require.Len(t, expected.rows["store_meta"], 7)
	require.NotEmpty(t, value)
	require.NotEqual(t, expected.metadata[key], value)
	matches := 0
	for _, row := range expected.rows["store_meta"] {
		require.Len(t, row, 2)
		storedKey, ok := row[0].(string)
		require.True(t, ok)
		if storedKey == key {
			require.Equal(t, expected.metadata[key], row[1])
			row[1] = append([]byte(nil), value...)
			matches++
		}
	}
	require.Equal(t, 1, matches)
	result, err := conn.ExecContext(ctx, "UPDATE store_meta SET value=? WHERE key=?", value, key)
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), affected)
	expected.metadata[key] = append([]byte(nil), value...)
}

func incomingMaterialPublicCompletionPrepare(t *testing.T, ctx context.Context, image string) *incomingMaterialUpgradeOutcomeCase {
	t.Helper()
	c := incomingMaterialUpgradeOutcomePrepare(t, ctx, image)
	require.NotNil(t, c)
	require.NotNil(t, c.owner)
	require.Equal(t, DefaultLimits(), c.limits)
	require.Equal(t, DefaultAttemptLimits(), c.attemptLimits)
	if image == "positions-v1" {
		require.Equal(t, 1, c.version)
		require.Len(t, c.metadata, 5)
		require.Len(t, c.rows, 6)
	} else {
		require.Equal(t, 2, c.version)
		require.Len(t, c.metadata, 7)
		require.Len(t, c.rows, 15)
	}
	if image == "mixed" {
		require.Equal(t, 44, incomingMaterialUpgradeFixtureRowTotal(c.rows))
	} else {
		require.Equal(t, 14, incomingMaterialUpgradeFixtureRowTotal(c.rows))
	}
	incomingMaterialUpgradeOutcomeRequireRestored(t, ctx, c.owner.conn, c)
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	c.owner.close(t)
	require.True(t, c.owner.closed)
	require.True(t, c.owner.sqlClosed)
	require.Equal(t, -1, c.owner.rootFD)
	incomingMaterialPublicCommitReadback(t, ctx, c, false)
	probe, err := probeSchema(c.databasePath, c.binding, c.limits, c.attemptLimits)
	require.NoError(t, err)
	require.True(t, probe.recognized)
	require.False(t, probe.initial)
	require.Equal(t, c.version, probe.version)
	return c
}

func incomingMaterialPublicCompletionOptions(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase, recorder *publicationOpenRecorder) OpenOptions {
	t.Helper()
	base := DefaultOpenOptions()
	base.PositionLimits, base.AttemptLimits = c.limits, c.attemptLimits
	base.UpgradeFromPositions = c.version == 1
	base.UpgradeFromAttempts = true
	require.Equal(t, c.image == "positions-v1", base.UpgradeFromPositions)
	require.True(t, base.UpgradeFromAttempts)
	options := recorder.options(base)
	options.upgradeCommit = func(tx *sql.Tx) error {
		require.NotNil(t, tx)
		require.Zero(t, recorder.commits)
		require.Empty(t, recorder.commitResults)
		require.Equal(t, []int{101, 102, 103}, recorder.openPoints())
		start := 13
		if c.version == 1 {
			start = 1
		}
		points := make([]int, 0, 17-start)
		events := []publicationOpenEvent{{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103}}
		for point := start; point <= 16; point++ {
			points = append(points, point)
			events = append(events, publicationOpenEvent{stream: "migrate", point: point})
		}
		require.Equal(t, points, recorder.upgrade)
		require.Equal(t, events, recorder.events)
		require.NoError(t, checkSchemaVersion(ctx, tx, 3))
		require.NoError(t, checkIncomingMaterialUpgradeDestination(ctx, tx, c.source))
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, tx, "SELECT COUNT(*) FROM accepted_material_refs"))
		incomingMaterialRequireNoForeignKeyViolation(t, ctx, tx)
		err := recorder.commit(tx)
		require.NoError(t, err)
		incomingMaterialPublicCompletionTrace(t, recorder, c.version, 0)
		return err
	}
	return options
}

func incomingMaterialPublicCompletionTrace(t *testing.T, recorder *publicationOpenRecorder, version, finalPoint int) {
	t.Helper()
	require.Contains(t, []int{1, 2}, version)
	require.GreaterOrEqual(t, finalPoint, 0)
	require.LessOrEqual(t, finalPoint, 4)
	start := 13
	if version == 1 {
		start = 1
	}
	points := make([]int, 0, 17-start)
	events := []publicationOpenEvent{{stream: "open", point: 101}, {stream: "open", point: 102}, {stream: "open", point: 103}}
	for point := start; point <= 16; point++ {
		points = append(points, point)
		events = append(events, publicationOpenEvent{stream: "migrate", point: point})
	}
	events = append(events, publicationOpenEvent{stream: "commit", point: 0})
	openPoints := []int{101, 102, 103}
	for point := 1; point <= finalPoint; point++ {
		openPoints = append(openPoints, point)
		events = append(events, publicationOpenEvent{stream: "open", point: point})
	}
	require.Equal(t, points, recorder.upgrade)
	require.Equal(t, openPoints, recorder.openPoints())
	require.Len(t, recorder.states, len(openPoints))
	require.Equal(t, events, recorder.events)
	require.Equal(t, 1, recorder.commits)
	require.Len(t, recorder.commitResults, 1)
	require.NoError(t, recorder.commitResults[0])
}

func incomingMaterialPublicCompletionRequireResources(t *testing.T, store *Store, recorder *publicationOpenRecorder, c *incomingMaterialUpgradeOutcomeCase, point int, lockMode os.FileMode, fd0 unix.Stat_t) {
	t.Helper()
	state, present := recorder.states[openConnectionAcquiredFault]
	require.True(t, present)
	require.GreaterOrEqual(t, state.rootFD, 0)
	var stat unix.Stat_t
	rootErr := unix.Fstat(state.rootFD, &stat)
	require.Nil(t, store)
	require.ErrorIs(t, rootErr, unix.EBADF)
	require.NotNil(t, state.holder)
	require.True(t, state.holder.closed)
	require.Equal(t, -1, state.payloadFD)
	require.Equal(t, -1, state.holder.payloadFD)
	incomingMaterialPublicCompletionTrace(t, recorder, c.version, point)
	publicationOpenRequireRefusalIdentities(t, recorder, state, true)
	require.Equal(t, state.rootFD, state.holder.rootFD)
	require.Same(t, state.lock, state.holder.lock)
	require.Same(t, state.db, state.holder.db)
	require.Same(t, state.conn, state.holder.conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	require.ErrorIs(t, state.conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := state.db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	publicationOpenRequireFD0(t, fd0)
	info, err := os.Lstat(filepath.Join(c.directory, "publication.db.lock"))
	require.NoError(t, err)
	require.Equal(t, lockMode, info.Mode().Perm())
}

func incomingMaterialPublicCompletionReadback(t *testing.T, ctx context.Context, c *incomingMaterialUpgradeOutcomeCase, fd0 unix.Stat_t) {
	t.Helper()
	durable := incomingMaterialPublicCommitReadback(t, ctx, c, true)
	reopened, err := Open(c.directory, c.binding)
	if reopened != nil {
		t.Cleanup(func() { assert.NoError(t, reopened.Close()) })
	}
	require.NoError(t, err)
	require.NotNil(t, reopened)
	require.Equal(t, 3, reopened.schemaVersion)
	incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, reopened.conn, c)
	require.Equal(t, durable, publicationOpenCaptureDestination(t, ctx, reopened))
	incomingMaterialUpgradeOutcomeRequirePayloads(t, c)
	publicationOpenRequireClosedResources(t, reopened, c.directory)
	publicationOpenRequireFD0(t, fd0)
	require.Equal(t, durable, incomingMaterialPublicCommitReadback(t, ctx, c, true))
	publicationOpenRequireFD0(t, fd0)
}

func TestIncomingMaterialPublicUpgradeCompletionIntervals(t *testing.T) {
	for _, image := range []string{"positions-v1", "pending-genesis", "mixed"} {
		for _, point := range []int{1, 2, 3, 4} {
			t.Run(fmt.Sprintf("%s final %d", image, point), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				t.Cleanup(cancel)
				c := incomingMaterialPublicCompletionPrepare(t, ctx, image)
				recorder := newPublicationOpenRecorder()
				recorder.canary = errors.New("public committed completion interval canary")
				recorder.failAt = point
				options := incomingMaterialPublicCompletionOptions(t, ctx, c, recorder)
				recorder.mutate = func(reached int) {
					if reached == incomingMaterialOpenDestinationFault {
						incomingMaterialPublicCompletionTrace(t, recorder, c.version, 1)
						incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, recorder.states[reached].holder.conn, c)
					}
					if reached >= 2 && reached <= 4 {
						require.Equal(t, 3, recorder.states[reached].holder.schemaVersion)
					}
				}
				fd0 := publicationOpenFD0(t)
				store, err := OpenWithOptions(c.directory, c.binding, options)
				if store != nil {
					t.Cleanup(func() { assert.NoError(t, store.Close()) })
				}
				incomingMaterialPublicCompletionRequireResources(t, store, recorder, c, point, 0o600, fd0)
				publicationOpenRequireLockWitness(t, c.directory, true)
				requireErrorMetadata(t, err, ErrStorage, StageOpen, ReasonCommitUnknown)
				require.Same(t, ErrStorage, errors.Unwrap(err))
				require.Nil(t, errors.Unwrap(errors.Unwrap(err)))
				require.NotErrorIs(t, err, recorder.canary)
				require.NotContains(t, err.Error(), recorder.canary.Error())
				require.NotContains(t, fmt.Sprintf("%+v", err), recorder.canary.Error())
				incomingMaterialPublicCompletionReadback(t, ctx, c, fd0)
			})
		}
	}
}

func TestIncomingMaterialPublicUpgradeFinalPreflight(t *testing.T) {
	for _, image := range []string{"positions-v1", "pending-genesis", "mixed"} {
		t.Run(image, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			t.Cleanup(cancel)
			c := incomingMaterialPublicCompletionPrepare(t, ctx, image)
			recorder := newPublicationOpenRecorder()
			options := incomingMaterialPublicCompletionOptions(t, ctx, c, recorder)
			lockPath := filepath.Join(c.directory, "publication.db.lock")
			mutations := 0
			recorder.mutate = func(point int) {
				if point != incomingMaterialOpenPreflightFault {
					return
				}
				mutations++
				require.Equal(t, 1, mutations)
				incomingMaterialPublicCompletionTrace(t, recorder, c.version, 4)
				holder := recorder.states[point].holder
				require.NotNil(t, holder)
				require.Equal(t, 3, holder.schemaVersion)
				incomingMaterialUpgradeOutcomeRequireCommitted(t, ctx, holder.conn, c)
				for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
					require.NoError(t, preflightFile(filepath.Join(c.directory, name)), name)
				}
				publicationOpenRequirePrivateFile(t, lockPath)
				require.NoError(t, os.Chmod(lockPath, 0o640))
				mode, statErr := os.Lstat(lockPath)
				require.NoError(t, statErr)
				require.Equal(t, os.FileMode(0o640), mode.Mode().Perm())
			}
			fd0 := publicationOpenFD0(t)
			store, upgradeErr := OpenWithOptions(c.directory, c.binding, options)
			if store != nil {
				t.Cleanup(func() { assert.NoError(t, store.Close()) })
			}
			incomingMaterialPublicCompletionRequireResources(t, store, recorder, c, 4, 0o640, fd0)
			require.Equal(t, 1, mutations)
			ordinary := newPublicationOpenRecorder()
			ordinary.canary = errors.New("unused unsafe lock reopen canary")
			refused, err := OpenWithOptions(c.directory, c.binding, ordinary.options(DefaultOpenOptions()))
			if refused != nil {
				t.Cleanup(func() { assert.NoError(t, refused.Close()) })
			}
			state := publicationOpenRequireRefused(t, refused, err, ordinary, []int{101}, ErrInvalid, ReasonBinding)
			require.Nil(t, state.lock)
			require.Nil(t, state.db)
			require.Nil(t, state.conn)
			stillUnsafe, err := os.Lstat(lockPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o640), stillUnsafe.Mode().Perm())
			publicationOpenRequireFD0(t, fd0)
			require.NoError(t, os.Chmod(lockPath, 0o600))
			publicationOpenRequireLockWitness(t, c.directory, true)
			publicationOpenRequireFD0(t, fd0)
			requireErrorMetadata(t, upgradeErr, ErrStorage, StageOpen, ReasonCommitUnknown)
			require.Same(t, ErrStorage, errors.Unwrap(upgradeErr))
			require.Nil(t, errors.Unwrap(errors.Unwrap(upgradeErr)))
			incomingMaterialPublicCompletionReadback(t, ctx, c, fd0)
		})
	}
}
