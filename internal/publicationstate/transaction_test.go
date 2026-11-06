package publicationstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptRollbackLeavesAllRowsUnchangedAndRedactsSQLCanary(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	store, directory := newStore(t, f)
	defer store.Close()
	observation := f.observation(1)
	_, err := store.RecordObservation(ctx, observation)
	require.NoError(t, err)
	proposal := prepareFirstUse(t, store, observation, f.payload)
	before := readLogicalRows(t, store.conn)
	_, err = store.conn.ExecContext(ctx, "CREATE TRIGGER abort_publication_event BEFORE INSERT ON accepted_events BEGIN SELECT RAISE(ABORT,'raw-canary-publication-event'); END")
	require.NoError(t, err)
	result, acceptErr := store.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.ErrorIs(t, acceptErr, ErrStorage)
	assert.Equal(t, Floor{}, result)
	assert.NotContains(t, acceptErr.Error(), "raw-canary-publication-event")
	for current := error(acceptErr); current != nil; current = errors.Unwrap(current) {
		assert.NotContains(t, current.Error(), "raw-canary-publication-event")
	}
	assert.Nil(t, errors.Unwrap(errors.Unwrap(acceptErr)))
	after := readLogicalRows(t, store.conn)
	assert.Equal(t, before, after)
	_, err = store.conn.ExecContext(ctx, "DROP TRIGGER abort_publication_event")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	reopened, err := Open(directory, f.binding)
	require.NoError(t, err)
	defer reopened.Close()
	floor, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	assert.Equal(t, Floor{}, floor)
	_, err = reopened.Accept(ctx, ModeFirstUse, proposal.StateToken, observation, f.payload, proposal.Confirmation)
	require.NoError(t, err)
}

func TestAcceptedEventCapacityIsTerminalButReadsAndNoOpsRemainAvailable(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, BackendPublicRepo)
	f.appendRecord(t, 0)
	f.appendRecord(t, 1)
	limits := DefaultLimits()
	limits.AcceptedEventCount = 1
	store, _ := newStore(t, f, limits)
	defer store.Close()
	firstObs := f.observation(1)
	first := prepareFirstUse(t, store, firstObs, f.payload)
	floor, err := store.Accept(ctx, ModeFirstUse, first.StateToken, firstObs, f.payload, first.Confirmation)
	require.NoError(t, err)
	advanceObs := f.observation(2)
	advance, err := store.Prepare(ctx, ModeAdvance, advanceObs, f.payload)
	require.NoError(t, err)
	refused, err := store.Accept(ctx, ModeAdvance, advance.StateToken, advanceObs, f.payload, [32]byte{})
	require.ErrorIs(t, err, ErrLimit)
	assert.Equal(t, Floor{}, refused)
	loaded, present, err := store.Load(ctx)
	require.NoError(t, err)
	require.True(t, present)
	assert.Equal(t, floor, loaded)
	noOp, err := store.Prepare(ctx, ModeAdvance, firstObs, f.payload)
	require.NoError(t, err)
	assert.Equal(t, "same", noOp.Stop)
	accepted, err := store.Accept(ctx, ModeAdvance, noOp.StateToken, firstObs, f.payload, [32]byte{})
	require.NoError(t, err)
	assert.Equal(t, floor, accepted)
	page, err := store.History(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, page.Events, 1)
}

var walCrashDB *sql.DB

func TestOpenWALCrashWriterHelper(t *testing.T) {
	directory := os.Getenv("PUBLICATION_STATE_WAL_CRASH_DIR")
	if directory == "" {
		return
	}
	path := filepath.Join(directory, "publication.db")
	db, err := sql.Open("sqlite", dbDSN(path, false))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode))
	_, err = db.Exec("PRAGMA wal_autocheckpoint=0")
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE crash_wal(value TEXT NOT NULL)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO crash_wal(value) VALUES('committed-in-wal')")
	require.NoError(t, err)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			require.NoError(t, os.Chmod(path+suffix, 0o600))
		}
	}
	walCrashDB = db
}

func TestOpenReadOnlyProbeSeesCommittedCrashWALWithoutMainMutation(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	command := exec.Command(os.Args[0], "-test.run=^TestOpenWALCrashWriterHelper$", "-test.count=1")
	command.Env = append(os.Environ(), "PUBLICATION_STATE_WAL_CRASH_DIR="+dir)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	path := filepath.Join(dir, "publication.db")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	walInfo, err := os.Stat(path + "-wal")
	require.NoError(t, err)
	require.NotZero(t, walInfo.Size())
	_, err = Open(dir, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, before, after)
	ro, err := sql.Open("sqlite", dbDSN(path, true))
	require.NoError(t, err)
	defer ro.Close()
	var value string
	require.NoError(t, ro.QueryRow("SELECT value FROM crash_wal").Scan(&value))
	assert.Equal(t, "committed-in-wal", value)
	var mode string
	require.NoError(t, ro.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode)
}

func TestOpenProbesForeignDatabaseReadOnlyAndAcceptsEmptyWAL(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	foreignDir := t.TempDir()
	require.NoError(t, os.Chmod(foreignDir, 0o700))
	foreignPath := filepath.Join(foreignDir, "publication.db")
	db, err := sql.Open("sqlite", dbDSN(foreignPath, false))
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE foreign_rows(value TEXT NOT NULL)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO foreign_rows(value) VALUES('preserve-me')")
	require.NoError(t, err)
	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode=DELETE").Scan(&mode))
	assert.Equal(t, "delete", mode)
	require.NoError(t, db.Close())
	require.NoError(t, os.Chmod(foreignPath, 0o600))
	_, err = Open(foreignDir, f.binding)
	require.ErrorIs(t, err, ErrSchema)
	check, err := sql.Open("sqlite", dbDSN(foreignPath, false))
	require.NoError(t, err)
	var value string
	require.NoError(t, check.QueryRow("SELECT value FROM foreign_rows").Scan(&value))
	assert.Equal(t, "preserve-me", value)
	require.NoError(t, check.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "delete", mode)
	require.NoError(t, check.Close())

	walDir := t.TempDir()
	require.NoError(t, os.Chmod(walDir, 0o700))
	walPath := filepath.Join(walDir, "publication.db")
	walDB, err := sql.Open("sqlite", dbDSN(walPath, false))
	require.NoError(t, err)
	walDB.SetMaxOpenConns(1)
	require.NoError(t, walDB.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode))
	assert.Equal(t, "wal", mode)
	_, err = walDB.Exec("PRAGMA wal_autocheckpoint=0")
	require.NoError(t, err)
	_, err = walDB.Exec("CREATE TABLE committed_wal(value TEXT NOT NULL)")
	require.NoError(t, err)
	_, err = walDB.Exec("INSERT INTO committed_wal(value) VALUES('wal-preserve')")
	require.NoError(t, err)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if _, statErr := os.Lstat(walPath + suffix); statErr == nil {
			require.NoError(t, os.Chmod(walPath+suffix, 0o600))
		}
	}
	_, err = Open(walDir, f.binding)
	require.ErrorIs(t, err, ErrSchema)
	var walValue string
	require.NoError(t, walDB.QueryRow("SELECT value FROM committed_wal").Scan(&walValue))
	assert.Equal(t, "wal-preserve", walValue)
	require.NoError(t, walDB.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "wal", mode)
	require.NoError(t, walDB.Close())

	emptyDir := t.TempDir()
	require.NoError(t, os.Chmod(emptyDir, 0o700))
	emptyPath := filepath.Join(emptyDir, "publication.db")
	empty, err := sql.Open("sqlite", dbDSN(emptyPath, false))
	require.NoError(t, err)
	require.NoError(t, empty.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode))
	assert.Equal(t, "wal", mode)
	require.NoError(t, empty.Close())
	require.NoError(t, os.Chmod(emptyPath, 0o600))
	store, err := Open(emptyDir, f.binding)
	require.NoError(t, err)
	_, present, err := store.Load(context.Background())
	require.NoError(t, err)
	assert.False(t, present)
	require.NoError(t, store.Close())
}

func TestOpenCrossProcessLockContentionRefuses(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	defer store.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestStoreLockSubprocess$", "-test.count=1")
	command.Env = append(os.Environ(), "PUBLICATION_STATE_LOCK_HELPER="+directory)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
}

func TestStoreLockSubprocess(t *testing.T) {
	directory := os.Getenv("PUBLICATION_STATE_LOCK_HELPER")
	if directory == "" {
		return
	}
	f := newFixture(t, BackendPublicRepo)
	_, err := Open(directory, f.binding)
	require.ErrorIs(t, err, ErrLocked)
}

func TestOpenLockContentionRefusesWithoutWaiting(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	store, directory := newStore(t, f)
	defer store.Close()
	_, err := Open(directory, f.binding)
	require.ErrorIs(t, err, ErrLocked)
}

func readLogicalRows(t *testing.T, conn *sql.Conn) map[string]string {
	t.Helper()
	rowsByTable := map[string]string{}
	for _, table := range []string{"store_meta", "cache_records", "cache_observations", "accepted_records", "accepted_events", "active_floor"} {
		rows, err := conn.QueryContext(context.Background(), "SELECT * FROM "+table+" ORDER BY 1")
		require.NoError(t, err)
		columns, err := rows.Columns()
		require.NoError(t, err)
		allRows := make([][]any, 0)
		for rows.Next() {
			values := make([]any, len(columns))
			destinations := make([]any, len(columns))
			for index := range values {
				destinations[index] = &values[index]
			}
			require.NoError(t, rows.Scan(destinations...))
			allRows = append(allRows, values)
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
		encoded, err := json.Marshal(allRows)
		require.NoError(t, err)
		rowsByTable[table] = string(encoded)
	}
	return rowsByTable
}
