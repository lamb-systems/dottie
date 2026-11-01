package state

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrationFiveAddsStageToExistingJournal(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	identity := fileIdentity("prefs.toml")
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	_, err := store.AppendJournal(context.Background(), JournalEntry{
		ID: "existing-journal", Operation: "replace", State: "pending", Identity: identity,
		Preimage: preimage, Postimage: postimage, CreatedAt: 1,
	}, []byte("before"))
	require.NoError(t, err)
	require.NoError(t, store.Close())

	dbPath := filepath.Join(paths.AppStateDir(), "state.db")
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	for _, column := range []string{"root_path", "destination_path", "root_device", "root_inode", "stage"} {
		_, err = raw.Exec("ALTER TABLE apply_journal DROP COLUMN " + column)
		require.NoError(t, err)
	}
	_, err = raw.Exec("UPDATE schema_version SET version = 4 WHERE singleton = 1")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	migrated, err := Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { _ = migrated.Close() })
	version, err := migrated.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, LatestSchemaVersion, version)
	entries, err := migrated.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "pending", entries[0].State)
	assert.Empty(t, entries[0].Stage)
	payload, err := migrated.Payload(entries[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("before"), payload)
}

func TestJournalTransitionsAndBackupPruning(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	identity := fileIdentity("prefs.toml")
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	entry, err := store.AppendJournal(context.Background(), JournalEntry{
		ID: "apply-1", Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1,
	}, []byte("before"))
	require.NoError(t, err)
	require.Equal(t, "pending", entry.State)
	assert.Error(t, store.TransitionJournalEntry(context.Background(), entry.ID, "pending", "applied", JournalStageWrite))
	assert.Error(t, store.TransitionJournalEntry(context.Background(), entry.ID, "pending", "failed", JournalStageVerified))
	require.NoError(t, store.TransitionJournalEntry(context.Background(), entry.ID, "pending", "applied", JournalStageVerified))
	assert.Error(t, store.PruneJournalBackup(context.Background(), entry.ID, time.Unix(1, 0).Add(JournalBackupRetention-time.Second)))
	require.NoError(t, store.PruneJournalBackup(context.Background(), entry.ID, time.Unix(1, 0).Add(JournalBackupRetention)))
	entries, err := store.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "applied", entries[0].State)
	assert.Equal(t, JournalStageVerified, entries[0].Stage)
	assert.Empty(t, entries[0].BackupRef)
	_, err = store.Payload(entry.BackupRef)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.ErrorIs(t, store.TransitionJournalEntry(context.Background(), entry.ID, "pending", "failed", JournalStageWrite), ErrInvalidJournalTransition)
}

func TestJournalPruningPreservesSharedBackupPayload(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	identity := fileIdentity("prefs.toml")
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	for _, id := range []string{"shared-one", "shared-two"} {
		_, err := store.AppendJournal(context.Background(), JournalEntry{
			ID: id, Operation: "replace", State: "pending", Stage: JournalStagePending,
			Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1,
		}, []byte("before"))
		require.NoError(t, err)
	}
	entries := journalEntriesForTest(t, store)
	require.Len(t, entries, 2)
	usage, err := store.JournalBackupUsage(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(len("before")), usage.Bytes)
	require.Len(t, usage.Holders, 1)
	assert.Len(t, usage.Holders[0].Entries, 2)
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "shared-one", "pending", "applied", JournalStageVerified))
	require.NoError(t, store.PruneJournalBackup(context.Background(), "shared-one", time.Unix(1, 0).Add(JournalBackupRetention)))
	payload, err := store.Payload(entries[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("before"), payload)
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "shared-two", "pending", "applied", JournalStageVerified))
	require.NoError(t, store.PruneJournalBackup(context.Background(), "shared-two", time.Unix(1, 0).Add(JournalBackupRetention)))
	_, err = store.Payload(entries[1].BackupRef)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func journalEntriesForTest(t *testing.T, store *Store) []JournalEntry {
	t.Helper()
	entries, err := store.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	return entries
}

func TestJournalExpiryPrunesOnlyVerifiedAppliedAndRolledBackMaterial(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	identity := fileIdentity("prefs.toml")
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	for _, id := range []string{"expired-applied", "expired-failed", "expired-indeterminate"} {
		_, err := store.AppendJournal(context.Background(), JournalEntry{
			ID: id, Operation: "replace", State: "pending", Stage: JournalStagePending,
			Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1,
		}, []byte("before"))
		require.NoError(t, err)
	}
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "expired-applied", "pending", "applied", JournalStageVerified))
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "expired-failed", "pending", "failed", JournalStageRename))
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "expired-indeterminate", "pending", "indeterminate", JournalStageIndeterminate))
	now := time.Unix(1, 0).Add(JournalBackupRetention + 24*time.Hour)
	pruned, err := store.PruneExpiredJournalBackups(context.Background(), now)
	require.NoError(t, err)
	assert.Equal(t, []string{"expired-applied"}, pruned)
	entries, err := store.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, entry := range entries {
		switch entry.ID {
		case "expired-applied":
			assert.Empty(t, entry.BackupRef)
		case "expired-failed", "expired-indeterminate":
			assert.NotEmpty(t, entry.BackupRef)
			payload, err := store.Payload(entry.BackupRef)
			require.NoError(t, err)
			assert.Equal(t, []byte("before"), payload)
		}
	}
}

func TestJournalFailedTransitionKeepsBackupForRecovery(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	identity := fileIdentity("prefs.toml")
	preimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte("after"))
	entry, err := store.AppendJournal(context.Background(), JournalEntry{
		ID: "apply-failed", Operation: "replace", State: "pending", Stage: JournalStagePending,
		Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1,
	}, []byte("before"))
	require.NoError(t, err)
	require.NoError(t, store.TransitionJournalEntry(context.Background(), entry.ID, "pending", "failed", JournalStageRename))
	entries, err := store.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "failed", entries[0].State)
	assert.Equal(t, JournalStageRename, entries[0].Stage)
	payload, err := store.Payload(entries[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("before"), payload)
	assert.Error(t, store.PruneJournalBackup(context.Background(), entry.ID, time.Unix(1, 0).Add(JournalBackupRetention)))
	assert.Error(t, store.TransitionJournalEntry(context.Background(), entry.ID, "failed", "applied", JournalStageVerified))
}
