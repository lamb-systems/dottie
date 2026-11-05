package state

import (
	"context"
	"database/sql"
	"net/url"
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
	for _, column := range []string{"root_path", "destination_path", "root_device", "root_inode", "stage", "vault", "epoch", "snapshot_cid", "policy_digest", "control_cid", "retention_binding_version"} {
		_, err = raw.Exec("ALTER TABLE apply_journal DROP COLUMN " + column)
		require.NoError(t, err)
	}
	_, err = raw.Exec("ALTER TABLE vault_publication_observations DROP COLUMN control_cid")
	require.NoError(t, err)
	_, err = raw.Exec("DROP TABLE vault_epoch_first_seen")
	require.NoError(t, err)
	for _, table := range []string{"authenticated_position_history_certificates", "authenticated_position_history", "vault_selections", "authenticated_position_certificates", "authenticated_position_evidence", "retention_recovery_material", "retention_declaration_history_points", "retention_declaration_history", "retention_recovery_points", "retention_declarations"} {
		_, err = raw.Exec("DROP TABLE " + table)
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

func TestJournalTransitionsAndUnboundBackupPreservation(t *testing.T) {
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
	assert.Equal(t, entry.BackupRef, entries[0].BackupRef, "a version-1 journal row without a point binding is ineligible")
	payload, err := store.Payload(entry.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("before"), payload)
	assert.ErrorIs(t, store.TransitionJournalEntry(context.Background(), entry.ID, "pending", "failed", JournalStageWrite), ErrInvalidJournalTransition)
}

func TestJournalPruningRedactsSettingValuesAndProtectsUnresolvedRows(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	descriptor := TargetDescriptor{ID: "settings", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1}
	require.NoError(t, store.PutTarget(context.Background(), descriptor))
	identity := model.EntryKey{TargetID: "settings", Source: model.SourceGNOME, SchemaID: "org.example.Settings", SettingsPath: "/", SettingKey: "enabled"}
	preimage := NewSettingFingerprint(model.SettingPresent, "b", "true")
	postimage := NewSettingFingerprint(model.SettingReset, "", "")
	backup := []byte("b\x00true")
	backupReference, _ := payloadReference(backup)
	for _, id := range []string{"eligible-setting", "protected-setting"} {
		_, err := store.AppendJournal(context.Background(), JournalEntry{
			ID: id, Operation: "setting-set", State: "pending", Stage: JournalStagePending,
			Identity: identity, Preimage: preimage, Postimage: postimage, CreatedAt: 1,
		}, backup)
		require.NoError(t, err)
	}
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "eligible-setting", "pending", "applied", JournalStageVerified))
	require.NoError(t, store.TransitionJournalEntry(context.Background(), "protected-setting", "pending", "failed", JournalStageSettingSet))
	now := time.Unix(1, 0).Add(JournalBackupRetention)
	require.NoError(t, store.PruneJournalBackup(context.Background(), "eligible-setting", now))

	entries, err := store.JournalEntries(context.Background(), "settings")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, entry := range entries {
		switch entry.ID {
		case "eligible-setting":
			assert.Equal(t, backupReference, entry.BackupRef)
			assert.Equal(t, "b", entry.Preimage.ValueType)
			assert.Equal(t, "true", entry.Preimage.ValueText)
			assert.Empty(t, entry.Postimage.ValueType)
			assert.Empty(t, entry.Postimage.ValueText)
			payload, err := store.Payload(entry.BackupRef)
			require.NoError(t, err)
			assert.Equal(t, backup, payload)
		case "protected-setting":
			assert.NotEmpty(t, entry.BackupRef)
			assert.Equal(t, "b", entry.Preimage.ValueType)
			assert.Equal(t, "true", entry.Preimage.ValueText)
			assert.Empty(t, entry.Postimage.ValueType)
			assert.Empty(t, entry.Postimage.ValueText)
			payload, err := store.Payload(entry.BackupRef)
			require.NoError(t, err)
			assert.Equal(t, backup, payload)
		}
	}
}

func TestJournalEntriesUseRowIDInsertionOrder(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	for _, item := range []struct {
		id   string
		path string
	}{
		{id: "z-inserted-first", path: "first.toml"},
		{id: "a-inserted-second", path: "second.toml"},
	} {
		before := []byte(item.id + "-before")
		_, err := store.AppendJournal(context.Background(), JournalEntry{
			ID: item.id, Operation: "replace", State: "pending", Stage: JournalStagePending,
			Identity:  fileIdentity(item.path),
			Preimage:  NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", before),
			Postimage: NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", []byte(item.id+"-after")),
			CreatedAt: 17,
		}, before)
		require.NoError(t, err)
	}
	want := []string{"z-inserted-first", "a-inserted-second"}
	for name, lookup := range map[string]func() ([]JournalEntry, error){
		"target":  func() ([]JournalEntry, error) { return store.JournalEntries(context.Background(), "target") },
		"all":     func() ([]JournalEntry, error) { return store.JournalEntriesAll(context.Background()) },
		"pending": func() ([]JournalEntry, error) { return store.PendingJournalEntries(context.Background()) },
	} {
		t.Run(name, func(t *testing.T) {
			entries, err := lookup()
			require.NoError(t, err)
			require.Len(t, entries, 2)
			assert.Equal(t, want, []string{entries[0].ID, entries[1].ID})
		})
	}
}

func TestSettingJournalStagesAreValidFailureAndJournalStages(t *testing.T) {
	stages := []string{JournalStageSettingSet, JournalStageSettingReset, JournalStageSettingReadBack}
	for _, stage := range stages {
		assert.True(t, validJournalFailureStage(stage))
		assert.True(t, validJournalStage(stage))
	}
	assert.False(t, validJournalFailureStage("unknown-setting-stage"))
	assert.False(t, validJournalStage("unknown-setting-stage"))
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
	payload, err = store.Payload(entries[1].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("before"), payload)
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
	assert.Empty(t, pruned, "automatic pruning preserves backups without an authenticated point binding")
	entries, err := store.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, entry := range entries {
		switch entry.ID {
		case "expired-applied", "expired-failed", "expired-indeterminate":
			assert.NotEmpty(t, entry.BackupRef)
			payload, err := store.Payload(entry.BackupRef)
			require.NoError(t, err)
			assert.Equal(t, []byte("before"), payload)
		}
	}
}

func TestJournalExpiryPreservesBackupRegisteredToRetainedRecoveryPoint(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	ctx := context.Background()
	vaultID := [32]byte{54}
	entry := appendRetentionJournal(t, store, "retained-recovery-backup", 10)
	body := []byte("retained recovery snapshot body")
	point := testRetentionPoint(t, vaultID, 2, body, [32]byte{7})
	declaration := testRetentionDeclaration(t, vaultID, point, 2, 1_700_000_000)
	_, err := store.PutRetentionDeclaration(ctx, declaration)
	require.NoError(t, err)
	bodyRef := storeUnreferencedPayload(t, store, body)
	require.NoError(t, store.SetRetentionRecoveryPointMaterial(ctx, vaultID, declaration.DeviceID, point, []string{bodyRef}, []string{entry.BackupRef}))

	pruned, err := store.PruneExpiredJournalBackups(ctx, time.Unix(10, 0).Add(JournalBackupRetention))
	require.NoError(t, err)
	assert.Empty(t, pruned, "a retained recovery backup must not be reported as pruned")

	entries, err := store.JournalEntries(ctx, "target")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, entry.BackupRef, entries[0].BackupRef, "a retained recovery backup must stay attached to its journal entry")
	payload, err := store.Payload(entry.BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("retained-recovery-backup-before"), payload)
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
