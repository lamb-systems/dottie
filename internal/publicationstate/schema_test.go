package publicationstate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/lamb-systems/dottie/internal/platform"
	v1state "github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenRejectsSQLitePrefixLookalikeAsForeignSchema(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	path := filepath.Join(dir, "publication.db")
	db, err := sql.Open("sqlite", dbDSN(path, false))
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE sqliteX(value TEXT NOT NULL)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO sqliteX(value) VALUES('preserve')")
	require.NoError(t, err)
	var mode string
	require.NoError(t, db.QueryRow("PRAGMA journal_mode=DELETE").Scan(&mode))
	require.NoError(t, db.Close())
	require.NoError(t, os.Chmod(path, 0o600))
	_, err = Open(dir, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
	check, err := sql.Open("sqlite", dbDSN(path, false))
	require.NoError(t, err)
	var value string
	require.NoError(t, check.QueryRow("SELECT value FROM sqliteX").Scan(&value))
	assert.Equal(t, "preserve", value)
	require.NoError(t, check.QueryRow("PRAGMA journal_mode").Scan(&mode))
	assert.Equal(t, "delete", mode)
	require.NoError(t, check.Close())
}

func TestOpenRejectsLookalikeObjectInRecognizedSchema(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	store, dir := newStore(t, f)
	_, err := store.conn.ExecContext(context.Background(), "CREATE TABLE SQLiteX(value TEXT)")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	_, err = Open(dir, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
}

func TestOpenRefusesSyntheticV1SchemaWithoutAdoption(t *testing.T) {
	base := t.TempDir()
	paths := platform.Paths{Home: filepath.Join(base, "home"), ConfigHome: filepath.Join(base, "config"), StateHome: filepath.Join(base, "state"), CacheHome: filepath.Join(base, "cache"), DataHome: filepath.Join(base, "data")}
	for _, directory := range []string{paths.Home, paths.ConfigHome, paths.StateHome, paths.CacheHome, paths.DataHome} {
		require.NoError(t, os.MkdirAll(directory, 0o700))
	}
	v1, err := v1state.Open(paths)
	require.NoError(t, err)
	version, err := v1.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, v1state.LatestSchemaVersion, version)
	statePath := filepath.Join(paths.AppStateDir(), "state.db")
	require.NoError(t, v1.Close())
	v1Bytes, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.NotEmpty(t, v1Bytes)

	f := newFixture(t, BackendPublicRepo)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	publicationPath := filepath.Join(dir, "publication.db")
	require.NoError(t, os.WriteFile(publicationPath, v1Bytes, 0o600))
	require.NoError(t, os.Chmod(publicationPath, 0o600))
	_, err = Open(dir, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
	check, err := sql.Open("sqlite", dbDSN(publicationPath, true))
	require.NoError(t, err)
	var copiedVersion int
	require.NoError(t, check.QueryRow("SELECT version FROM schema_version WHERE singleton=1").Scan(&copiedVersion))
	assert.Equal(t, v1state.LatestSchemaVersion, copiedVersion)
	require.NoError(t, check.Close())
}

func TestOpenRefusesNewerSyntheticSchema(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	path := filepath.Join(dir, "publication.db")
	db, err := sql.Open("sqlite", dbDSN(path, false))
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE future_state(value TEXT)")
	require.NoError(t, err)
	_, err = db.Exec("PRAGMA application_id=1146376242")
	require.NoError(t, err)
	_, err = db.Exec("PRAGMA user_version=2")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	require.NoError(t, os.Chmod(path, 0o600))
	_, err = Open(dir, f.binding)
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonSchema)
}

func TestOpenRejectsWrongBindingBeforeReadWriteOpen(t *testing.T) {
	f := newFixture(t, BackendSpaces)
	store, dir := newStore(t, f)
	require.NoError(t, store.Close())
	wrong := f.binding
	wrong.Repository = "at://" + testDID + "/systems.lamb.dottie.vaultSnapshotV2/other-record"
	_, err := Open(dir, wrong)
	requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
}

func TestOpenRejectsSymlinkFIFOAndHardlinkWithoutRepair(t *testing.T) {
	f := newFixture(t, BackendPublicRepo)
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o700))
		target := filepath.Join(dir, "target")
		require.NoError(t, os.WriteFile(target, []byte("safe-target"), 0o600))
		path := filepath.Join(dir, "publication.db")
		require.NoError(t, os.Symlink(target, path))
		_, err := Open(dir, f.binding)
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
		data, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, []byte("safe-target"), data)
		info, err := os.Stat(target)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})
	t.Run("fifo", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o700))
		require.NoError(t, syscall.Mkfifo(filepath.Join(dir, "publication.db"), 0o600))
		_, err := Open(dir, f.binding)
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
	})
	t.Run("hardlink", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o700))
		target := filepath.Join(dir, "target")
		require.NoError(t, os.WriteFile(target, []byte("hardlink-target"), 0o600))
		path := filepath.Join(dir, "publication.db")
		require.NoError(t, os.Link(target, path))
		_, err := Open(dir, f.binding)
		requireErrorMetadata(t, err, ErrInvalid, StageOpen, ReasonBinding)
		data, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, []byte("hardlink-target"), data)
	})
}
