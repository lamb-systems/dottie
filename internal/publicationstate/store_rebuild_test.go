package publicationstate

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var legacyPositionsImages = []string{
	filepath.Join("testdata", "positions-v1", "schema1-baseline.db"),
	filepath.Join("testdata", "positions-v2", "schema2-mixed.db"),
	filepath.Join("testdata", "positions-v2", "schema2-pending-genesis.db"),
	filepath.Join("testdata", "positions-v3", "schema3-empty.db"),
	filepath.Join("testdata", "positions-v3", "schema3-upgraded.db"),
}

func legacyPositionsDirectory(t *testing.T) string {
	t.Helper()
	return legacyPositionsDirectoryOf(t, legacyPositionsImages[0])
}

func legacyPositionsDirectoryOf(t *testing.T, source string) string {
	t.Helper()
	raw, err := os.ReadFile(source)
	require.NoError(t, err)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "publication.db"), raw, 0o600))
	return directory
}

func legacyPositionsBinding() Binding {
	return Binding{
		AccountDID: "did:plc:abcdefghijklmnopqrstuvwx",
		Backend:    BackendPublicRepo,
		Repository: "at://did:plc:abcdefghijklmnopqrstuvwx",
		Vault:      [32]byte{0x09},
	}
}

func TestOpenRefusesALegacyPositionsStoreAsRebuildRequired(t *testing.T) {
	for _, image := range legacyPositionsImages {
		t.Run(filepath.Base(image), func(t *testing.T) {
			requireLegacyStoreRefused(t, image)
		})
	}
}

func TestInspectRefusesALegacyPositionsStoreAsRebuildRequired(t *testing.T) {
	for _, image := range legacyPositionsImages {
		t.Run(filepath.Base(image), func(t *testing.T) {
			requireLegacyInspectionRefused(t, image)
		})
	}
}

func requireLegacyStoreRefused(t *testing.T, image string) {
	t.Helper()
	directory := legacyPositionsDirectoryOf(t, image)
	before, err := os.ReadFile(filepath.Join(directory, "publication.db"))
	require.NoError(t, err)

	_, err = Open(directory, legacyPositionsBinding())
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonRebuildRequired)
	assert.True(t, IsRebuildRequired(err))

	after, err := os.ReadFile(filepath.Join(directory, "publication.db"))
	require.NoError(t, err)
	assert.Equal(t, before, after, "the refused legacy store was modified")
	if info, statErr := os.Lstat(filepath.Join(directory, "publication.db-wal")); statErr == nil {
		assert.Zero(t, info.Size(), "the refused legacy store left a write-ahead log with content")
	}
}

func requireLegacyInspectionRefused(t *testing.T, image string) {
	t.Helper()
	directory := legacyPositionsDirectoryOf(t, image)
	before, err := os.ReadFile(filepath.Join(directory, "publication.db"))
	require.NoError(t, err)

	_, err = Inspect(context.Background(), directory, legacyPositionsBinding())
	requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonRebuildRequired)

	after, err := os.ReadFile(filepath.Join(directory, "publication.db"))
	require.NoError(t, err)
	assert.Equal(t, before, after, "inspection modified the refused legacy store")
}

func TestInspectKeepsAForeignDatabaseDistinctFromARebuild(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	databasePath := filepath.Join(directory, "publication.db")
	db, err := sql.Open("sqlite", dbDSN(databasePath, false))
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(), "CREATE TABLE unrelated (value TEXT)")
	require.NoError(t, err)
	var mode string
	require.NoError(t, db.QueryRowContext(context.Background(), "PRAGMA journal_mode=DELETE").Scan(&mode))
	require.NoError(t, db.Close())
	require.NoError(t, os.Chmod(databasePath, 0o600))

	_, err = Inspect(context.Background(), directory, legacyPositionsBinding())
	requireErrorMetadata(t, err, ErrSchema, StageInspect, ReasonSchema)
	assert.False(t, IsRebuildRequired(err), "a foreign database was reported as a legacy store")
}

func TestARefusedLegacyStoreKeepsItsLiveJournalAndBackups(t *testing.T) {
	directory := legacyPositionsDirectory(t)
	raw, err := os.ReadFile(filepath.Join("testdata", "journals-v2", "schema2-pending.db"))
	require.NoError(t, err)
	journalPath := filepath.Join(directory, journalDatabaseName)
	require.NoError(t, os.WriteFile(journalPath, raw, 0o600))
	backups := journalBackupCount(t, journalPath)
	require.Equal(t, int64(1), backups, "the fixture does not carry a preimage")

	_, err = Open(directory, legacyPositionsBinding())
	requireErrorMetadata(t, err, ErrSchema, StageOpen, ReasonRebuildRequired)

	live, err := LiveJournalRows(directory)
	require.NoError(t, err)
	assert.Equal(t, int64(1), live, "the refused legacy store discarded a live journal row")
	assert.Equal(t, backups, journalBackupCount(t, journalPath), "the refused store discarded a preimage")

	after, err := os.ReadFile(journalPath)
	require.NoError(t, err)
	assert.Equal(t, raw, after, "the refused store modified the journal")
}

func journalBackupCount(t *testing.T, path string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", dbDSN(path, true))
	require.NoError(t, err)
	defer func() { assert.NoError(t, db.Close()) }()
	count, err := queryInt64(context.Background(), db, "SELECT count(*) FROM backups")
	require.NoError(t, err)
	return count
}
