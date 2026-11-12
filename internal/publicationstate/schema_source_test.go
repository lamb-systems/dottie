package publicationstate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func newSchema2UnitStore(t *testing.T, f fixture, limits ...Limits) (*Store, string) {
	t.Helper()
	require.LessOrEqual(t, len(limits), 1)
	positionLimits := DefaultLimits()
	if len(limits) == 1 {
		positionLimits = limits[0]
	}
	return newSchema2UnitStoreWithLimits(t, f, positionLimits, DefaultAttemptLimits())
}

func newSchema2UnitStoreWithLimits(t *testing.T, f fixture, limits Limits, attemptLimits AttemptLimits) (*Store, string) {
	t.Helper()
	require.NoError(t, validateBinding(f.binding))
	require.NoError(t, validateLimits(limits))
	require.NoError(t, validateAttemptLimits(attemptLimits))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	require.NoError(t, checkPrivateDirectory(directory))
	store := &Store{
		directory:         directory,
		binding:           f.binding,
		limits:            limits,
		attemptLimits:     attemptLimits,
		rootFD:            -1,
		payloadFD:         -1,
		schemaVersion:     2,
		custodyOps:        defaultCustodyOperations(),
		commitTransaction: func(tx *sql.Tx) error { return tx.Commit() },
	}
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	rootFD, err := openStoreRoot(directory)
	require.NoError(t, err)
	store.rootFD = rootFD
	lock, err := platform.LockFile(filepath.Join(directory, "publication.db.lock"))
	require.NoError(t, err)
	store.lock = lock
	databasePath := filepath.Join(directory, "publication.db")
	created, err := createDatabaseFile(databasePath)
	require.NoError(t, err)
	require.True(t, created)
	require.NoError(t, unix.Fsync(store.rootFD))
	db, err := sql.Open("sqlite", dbDSN(databasePath, false))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store.db = db
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	store.conn = conn
	require.NoError(t, configureConnection(ctx, conn))
	inventory, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	require.Len(t, inventory.statements, 17)
	require.Len(t, inventory.objects, 17)
	require.Len(t, inventory.metadataKeys, 7)
	require.Equal(t, expectedSchemaV2Objects(), inventory.objects)
	require.Equal(t, expectedSchemaV2MetadataKeys(), inventory.metadataKeys)
	bindingBytes, err := encodeBinding(f.binding)
	require.NoError(t, err)
	limitsBytes, err := encodeLimits(limits)
	require.NoError(t, err)
	attemptLimitsBytes, err := encodeAttemptLimits(attemptLimits)
	require.NoError(t, err)
	var databaseID [32]byte
	for allZero(databaseID[:]) {
		_, err = rand.Read(databaseID[:])
		require.NoError(t, err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			assert.NoError(t, err)
		}
	})
	for _, statement := range inventory.statements {
		_, execErr := tx.ExecContext(ctx, statement)
		require.NoError(t, execErr)
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO store_meta(key,value) VALUES ('database_id',?),('revision',?),('generation',?),('binding',?),('limits',?),('attempt_limits',?),('attempt_mutation_revision',?)", databaseID[:], uint64Bytes(0), uint64Bytes(0), bindingBytes, limitsBytes, attemptLimitsBytes, uint64Bytes(0))
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "PRAGMA application_id=1146376242")
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "PRAGMA user_version=2")
	require.NoError(t, err)
	require.NoError(t, checkSchemaVersion(ctx, tx, 2))
	require.NoError(t, compareMetadata(ctx, tx, f.binding, limits))
	require.NoError(t, checkAttemptMetadata(ctx, tx, attemptLimits))
	snapshot, err := readIncomingMaterialUpgradeSource(ctx, tx, 2, f.binding, limits, attemptLimits)
	require.NoError(t, err)
	require.Equal(t, 2, snapshot.version)
	require.Equal(t, bindingBytes, snapshot.metadata["binding"])
	require.Equal(t, limitsBytes, snapshot.metadata["limits"])
	require.Equal(t, attemptLimitsBytes, snapshot.metadata["attempt_limits"])
	require.Equal(t, databaseID[:], snapshot.metadata["database_id"])
	require.Equal(t, uint64Bytes(0), snapshot.metadata["revision"])
	require.Equal(t, uint64Bytes(0), snapshot.metadata["generation"])
	require.Equal(t, uint64Bytes(0), snapshot.metadata["attempt_mutation_revision"])
	var incomingObjects int64
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name='accepted_material_refs'").Scan(&incomingObjects))
	require.Zero(t, incomingObjects)
	require.NoError(t, unix.Fsync(store.rootFD))
	require.NoError(t, tx.Commit())
	store.databaseID = databaseID
	store.attemptMutationRevision = 0
	store.schemaVersion = 2
	require.NoError(t, secureCreatedSidecars(directory))
	require.NoError(t, unix.Fsync(store.rootFD))
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		require.NoError(t, preflightFile(filepath.Join(directory, name)), name)
	}
	require.NoError(t, checkSchemaVersion(ctx, store.conn, 2))
	persisted, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, limits, attemptLimits)
	require.NoError(t, err)
	require.Equal(t, snapshot, persisted)
	require.Equal(t, -1, store.payloadFD)
	_, err = os.Lstat(filepath.Join(directory, payloadDirectoryName))
	require.ErrorIs(t, err, os.ErrNotExist)
	return store, directory
}

func TestSchema2UnitStoreSourceSetup(t *testing.T) {
	t.Run("default limits", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		store, directory := newSchema2UnitStore(t, f)
		incomingMaterialUpgradeAssertSchema2UnitSource(t, store, directory, f, DefaultLimits(), DefaultAttemptLimits())
	})
	t.Run("lowered position limits", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		limits := DefaultLimits()
		limits.AcceptedEventCount = 3
		require.NoError(t, validateLimits(limits))
		store, directory := newSchema2UnitStore(t, f, limits)
		incomingMaterialUpgradeAssertSchema2UnitSource(t, store, directory, f, limits, DefaultAttemptLimits())
	})
	t.Run("lowered attempt limits", func(t *testing.T) {
		f := newFixture(t, BackendPublicRepo)
		f.appendRecord(t, 0)
		attemptLimits := DefaultAttemptLimits()
		attemptLimits.HistoricalAttempts = 1000
		require.NoError(t, validateAttemptLimits(attemptLimits))
		store, directory := newSchema2UnitStoreWithLimits(t, f, DefaultLimits(), attemptLimits)
		incomingMaterialUpgradeAssertSchema2UnitSource(t, store, directory, f, DefaultLimits(), attemptLimits)
	})
}

func incomingMaterialUpgradeAssertSchema2UnitSource(t *testing.T, store *Store, directory string, f fixture, limits Limits, attemptLimits AttemptLimits) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	require.NotNil(t, store)
	require.False(t, store.closed)
	require.Equal(t, 2, store.schemaVersion)
	require.Equal(t, f.binding, store.binding)
	require.Equal(t, limits, store.limits)
	require.Equal(t, attemptLimits, store.attemptLimits)
	require.Equal(t, -1, store.payloadFD)
	require.GreaterOrEqual(t, store.rootFD, 0)
	require.NotNil(t, store.conn)
	require.NotNil(t, store.db)
	require.NotNil(t, store.lock)
	require.Equal(t, directory, store.directory)
	require.NoError(t, checkPrivateDirectory(directory))
	var rootStat unix.Stat_t
	require.NoError(t, unix.Fstat(store.rootFD, &rootStat))
	require.Equal(t, uint32(unix.S_IFDIR), rootStat.Mode&unix.S_IFMT)
	require.Equal(t, uint32(0o700), rootStat.Mode&0o777)
	require.Equal(t, uint32(os.Geteuid()), rootStat.Uid)
	for _, name := range []string{"publication.db.lock", "publication.db", "publication.db-wal", "publication.db-shm"} {
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		require.NoError(t, err, name)
		require.True(t, info.Mode().IsRegular(), name)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
		var stat unix.Stat_t
		require.NoError(t, unix.Lstat(path, &stat))
		require.Equal(t, uint64(1), stat.Nlink, name)
		require.Equal(t, uint32(os.Geteuid()), stat.Uid, name)
	}
	_, err := os.Lstat(filepath.Join(directory, payloadDirectoryName))
	require.ErrorIs(t, err, os.ErrNotExist)
	var userVersion, appID int
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion))
	require.Equal(t, 2, userVersion)
	require.NoError(t, store.conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID))
	require.Equal(t, applicationID, appID)
	objects, definitions, err := readSchemaObjects(ctx, store.conn)
	require.NoError(t, err)
	require.Equal(t, expectedSchemaV2Objects(), objects)
	inventory, err := schemaInventoryForVersion(2)
	require.NoError(t, err)
	require.Len(t, inventory.statements, 17)
	for _, statement := range inventory.statements {
		name := statementTableName(statement)
		require.Contains(t, definitions, name)
		require.Equal(t, statement, strings.TrimSpace(definitions[name]))
	}
	keys, err := readMetadataKeys(ctx, store.conn)
	require.NoError(t, err)
	require.Equal(t, expectedSchemaV2MetadataKeys(), keys)
	metadata := incomingMaterialUpgradeStoredMetadata(t, ctx, store.conn)
	require.Len(t, metadata, 7)
	bindingBytes, err := encodeBinding(f.binding)
	require.NoError(t, err)
	require.Equal(t, bindingBytes, metadata["binding"])
	limitsBytes, err := encodeLimits(limits)
	require.NoError(t, err)
	require.Equal(t, limitsBytes, metadata["limits"])
	attemptLimitsBytes, err := encodeAttemptLimits(attemptLimits)
	require.NoError(t, err)
	require.Equal(t, attemptLimitsBytes, metadata["attempt_limits"])
	require.Len(t, metadata["database_id"], 32)
	require.False(t, allZero(metadata["database_id"]))
	require.Equal(t, metadata["database_id"], store.databaseID[:])
	require.Equal(t, uint64Bytes(0), metadata["revision"])
	require.Equal(t, uint64Bytes(0), metadata["generation"])
	require.Equal(t, uint64Bytes(0), metadata["attempt_mutation_revision"])
	require.Equal(t, uint64(0), store.attemptMutationRevision)
	snapshot, err := readIncomingMaterialUpgradeSource(ctx, store.conn, 2, f.binding, limits, attemptLimits)
	require.NoError(t, err)
	require.Equal(t, 2, snapshot.version)
	require.Equal(t, f.binding, snapshot.binding)
	require.Equal(t, limits, snapshot.limits)
	require.Equal(t, attemptLimits, snapshot.attemptLimits)
	require.Equal(t, metadata, snapshot.metadata)
	var incomingObjects int64
	require.NoError(t, store.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE name='accepted_material_refs'").Scan(&incomingObjects))
	require.Zero(t, incomingObjects)
	require.Equal(t, int64(7), incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM store_meta"))
	emptyTables := []string{"cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor", "publication_attempts", "active_publication_attempt", "pending_genesis", "attempt_events", "attempt_evidence", "payload_objects", "attempt_payload_refs", "retained_publications", "attempt_reservations"}
	for _, table := range emptyTables {
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, store.conn, "SELECT COUNT(*) FROM "+table), table)
	}
	floor, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.False(t, present)
	require.Equal(t, zeroFloor(), floor)
	history, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.False(t, history.HasMore)
	require.Empty(t, history.Events)
	require.Empty(t, history.Records)
	attemptHistory, err := store.AttemptHistory(ctx, [16]byte{}, 10)
	require.NoError(t, err)
	require.False(t, attemptHistory.HasMore)
	require.Empty(t, attemptHistory.Attempts)
	rootFD := store.rootFD
	conn := store.conn
	db := store.db
	require.NoError(t, store.Close())
	var closedStat unix.Stat_t
	require.ErrorIs(t, unix.Fstat(rootFD, &closedStat), unix.EBADF)
	require.ErrorIs(t, conn.PingContext(ctx), sql.ErrConnDone)
	poolErr := db.PingContext(ctx)
	require.NoError(t, ctx.Err())
	require.Error(t, poolErr)
	databasePath := filepath.Join(directory, "publication.db")
	readOnlyConn, closeReadOnly := incomingMaterialUpgradeFixtureOpenReadOnly(t, ctx, databasePath)
	var persistedVersion int
	require.NoError(t, readOnlyConn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&persistedVersion))
	require.Equal(t, 2, persistedVersion)
	persisted, err := readIncomingMaterialUpgradeSource(ctx, readOnlyConn, 2, f.binding, limits, attemptLimits)
	require.NoError(t, err)
	require.Equal(t, snapshot, persisted)
	require.Equal(t, uint64Bytes(0), persisted.metadata["revision"])
	require.Equal(t, uint64Bytes(0), persisted.metadata["generation"])
	require.Equal(t, uint64Bytes(0), persisted.metadata["attempt_mutation_revision"])
	for _, table := range emptyTables {
		require.Zero(t, incomingMaterialUpgradeCount(t, ctx, readOnlyConn, "SELECT COUNT(*) FROM "+table), table)
	}
	closeReadOnly(t)
}
