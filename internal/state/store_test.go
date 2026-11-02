package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"testing/fstest"

	"github.com/ipfs/go-cid"
	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPaths(t *testing.T) platform.Paths {
	t.Helper()
	root := t.TempDir()
	return platform.Paths{
		Home:      filepath.Join(root, "home"),
		StateHome: filepath.Join(root, "state"),
		CacheHome: filepath.Join(root, "cache"),
	}
}

func testDescriptor() TargetDescriptor {
	return TargetDescriptor{ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion, LogicalBase: model.RootHome, LogicalPath: "prefs", Kind: model.SelectionDirectory, Mode: "review", CreatedAt: 101}
}

func fileIdentity(path string) model.EntryKey {
	return model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: path}
}

func openTestStore(t *testing.T, paths platform.Paths) *Store {
	t.Helper()
	store, err := Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestFreshOpenPermissionsSchemaAndPragmas(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	_, err := store.PutAppliedBase(context.Background(), BaseRecord{Identity: fileIdentity("prefs.toml"), Fingerprint: NewFingerprint("present", model.FileRegular, 0o600, "", "", "", []byte("base")), RecordedAt: 123}, []byte("base"))
	require.NoError(t, err)

	stateDir := paths.AppStateDir()
	for path, mode := range map[string]os.FileMode{
		stateDir:                                 0o700,
		filepath.Join(stateDir, "state.db"):      0o600,
		filepath.Join(stateDir, "state.db-wal"):  0o600,
		filepath.Join(stateDir, "state.db-shm"):  0o600,
		filepath.Join(stateDir, "state.db.lock"): 0o600,
	} {
		info, err := os.Lstat(path)
		require.NoError(t, err, path)
		assert.Equal(t, mode, info.Mode().Perm(), path)
	}

	version, err := store.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, LatestSchemaVersion, version)

	rows, err := store.conn.QueryContext(context.Background(), "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
	require.NoError(t, err)
	tables := map[string]bool{}
	for rows.Next() {
		var table string
		require.NoError(t, rows.Scan(&table))
		tables[table] = true
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	for _, table := range []string{"schema_version", "targets", "applied_base", "outbound_intent", "conflicts", "checkpoints", "apply_journal", "transition_attempts", "vault_checkpoints", "vault_publication_observations"} {
		assert.True(t, tables[table], "missing table %s", table)
	}

	var journal string
	var synchronous, foreignKeys, busyTimeout int
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journal))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "PRAGMA synchronous").Scan(&synchronous))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&foreignKeys))
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&busyTimeout))
	assert.Equal(t, "wal", strings.ToLower(journal))
	assert.Equal(t, 2, synchronous)
	assert.Equal(t, 1, foreignKeys)
	assert.Equal(t, 5000, busyTimeout)
}

func TestVaultCheckpointRoundTripsControlBytesAndRejectsBackwardUpdate(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	checkpoint := VaultCheckpoint{
		Vault: [32]byte{1}, Anchor: [32]byte{2}, SnapshotCID: []byte("cid-snapshot-2"),
		Epoch: 2, PolicyDigest: [32]byte{3}, RecordedAt: 123,
	}
	checkpoint.ControlBytes = testVaultControlBytes(checkpoint.Vault, checkpoint.Epoch, checkpoint.PolicyDigest, checkpoint.SnapshotCID)
	checkpoint.ControlCID = testRawCID(t, checkpoint.ControlBytes)
	require.NoError(t, store.PutVaultCheckpoint(context.Background(), checkpoint))
	stored, err := store.VaultCheckpoint(context.Background(), checkpoint.Vault)
	require.NoError(t, err)
	require.Equal(t, checkpoint, stored)

	backwards := checkpoint
	backwards.Epoch = 1
	backwards.ControlBytes = testVaultControlBytes(backwards.Vault, backwards.Epoch, backwards.PolicyDigest, backwards.SnapshotCID)
	backwards.ControlCID = testRawCID(t, backwards.ControlBytes)
	backwards.RecordedAt = 124
	assert.ErrorIs(t, store.PutVaultCheckpoint(context.Background(), backwards), ErrCheckpointBackwards)
	stored, err = store.VaultCheckpoint(context.Background(), checkpoint.Vault)
	require.NoError(t, err)
	assert.Equal(t, checkpoint, stored, "backwards write leaves the held checkpoint unchanged")
	require.NoError(t, store.Close())
	reopened, err := Open(paths)
	require.NoError(t, err)
	defer reopened.Close()
	stored, err = reopened.VaultCheckpoint(context.Background(), checkpoint.Vault)
	require.NoError(t, err)
	assert.Equal(t, checkpoint, stored, "checkpoint control bytes survive restart")
}

func TestVaultEpochFirstSeenIsInsertOnlyAndDurable(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	vaultID := [32]byte{17}
	const epoch = 5
	require.NoError(t, store.RecordVaultEpochFirstSeen(context.Background(), vaultID, epoch, 1_700_000_000))
	require.NoError(t, store.RecordVaultEpochFirstSeen(context.Background(), vaultID, epoch, 1_700_100_000))
	require.NoError(t, store.RecordVaultEpochFirstSeen(context.Background(), vaultID, epoch+1, 1_700_200_000))
	firstSeenAt, found, err := store.VaultEpochFirstSeen(context.Background(), vaultID, epoch)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_000_000), firstSeenAt)
	newEpochAt, found, err := store.VaultEpochFirstSeen(context.Background(), vaultID, epoch+1)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_200_000), newEpochAt)
	missingAt, found, err := store.VaultEpochFirstSeen(context.Background(), vaultID, epoch+2)
	require.NoError(t, err)
	assert.False(t, found)
	assert.Zero(t, missingAt)
	require.NoError(t, store.Close())

	reopened, err := Open(paths)
	require.NoError(t, err)
	defer reopened.Close()
	firstSeenAt, found, err = reopened.VaultEpochFirstSeen(context.Background(), vaultID, epoch)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(1_700_000_000), firstSeenAt)
}

func TestVaultPublicationObservationIsDurableAndMonotonicWithinEpoch(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	first := VaultPublicationObservation{Vault: [32]byte{8}, Epoch: 2, PublicationCount: 3, HeadCID: []byte("head-3"), ControlCID: []byte("control-2")}
	require.NoError(t, store.RecordVaultPublicationObservation(context.Background(), first))
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(context.Background(), VaultPublicationObservation{Vault: first.Vault, Epoch: 2, PublicationCount: 2, HeadCID: []byte("head-2"), ControlCID: first.ControlCID}), ErrVaultPublicationBackwards)
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(context.Background(), VaultPublicationObservation{Vault: first.Vault, Epoch: 2, PublicationCount: 3, HeadCID: []byte("different-head"), ControlCID: first.ControlCID}), ErrVaultPublicationConflict)
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(context.Background(), VaultPublicationObservation{Vault: first.Vault, Epoch: 2, PublicationCount: 5, HeadCID: []byte("head-5"), ControlCID: first.ControlCID}), ErrVaultPublicationGap)
	require.NoError(t, store.RecordVaultPublicationObservation(context.Background(), VaultPublicationObservation{Vault: first.Vault, Epoch: 2, PublicationCount: 4, HeadCID: []byte("head-4"), ControlCID: first.ControlCID, PrevControlCID: first.ControlCID, PrevHeadCID: first.HeadCID}))
	thirdEpoch := VaultPublicationObservation{Vault: first.Vault, Epoch: 3, PublicationCount: 0, HeadCID: []byte("epoch-3-head"), ControlCID: []byte("control-3"), PrevControlCID: []byte("wrong-control")}
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(context.Background(), thirdEpoch), ErrVaultPublicationControlAncestry)
	thirdEpoch.PrevControlCID = []byte("control-2")
	require.NoError(t, store.RecordVaultPublicationObservation(context.Background(), thirdEpoch))
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(context.Background(), VaultPublicationObservation{Vault: first.Vault, Epoch: 2, PublicationCount: 5, HeadCID: []byte("old-epoch-head"), ControlCID: first.ControlCID}), ErrVaultPublicationBackwards)
	require.NoError(t, store.Close())
	reopened, err := Open(paths)
	require.NoError(t, err)
	defer reopened.Close()
	var epoch, count int64
	var headCID, controlCID []byte
	require.NoError(t, reopened.conn.QueryRowContext(context.Background(), "SELECT epoch, publication_count, head_cid, control_cid FROM vault_publication_observations WHERE vault = ?", first.Vault[:]).Scan(&epoch, &count, &headCID, &controlCID))
	assert.Equal(t, int64(3), epoch)
	assert.Equal(t, int64(0), count)
	assert.Equal(t, []byte("epoch-3-head"), headCID)
	assert.Equal(t, []byte("control-3"), controlCID)
}

func TestVaultPublicationObservationAcceptsFirstIdempotentAndMidEpochRead(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	defer store.Close()
	ctx := context.Background()
	vaultID := [32]byte{9}
	first := VaultPublicationObservation{Vault: vaultID, Epoch: 1, PublicationCount: 1, HeadCID: []byte("head-1"), ControlCID: []byte("control-1")}
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, first))
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, first))

	next := VaultPublicationObservation{
		Vault: vaultID, Epoch: 1, PublicationCount: 2, HeadCID: []byte("head-2"), ControlCID: first.ControlCID,
		PrevHeadCID: first.HeadCID, ParentCID: first.HeadCID, EnforceParent: true,
	}
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, next))

	midEpoch := VaultPublicationObservation{Vault: vaultID, Epoch: 2, PublicationCount: 7, HeadCID: []byte("epoch-2-head-7"), ControlCID: []byte("control-2"), PrevControlCID: next.ControlCID}
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, midEpoch))
}

func TestMigrationSevenBackfillsUnknownObservedControl(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	first := VaultPublicationObservation{Vault: [32]byte{12}, Epoch: 4, PublicationCount: 2, HeadCID: []byte("head-4"), ControlCID: []byte("control-4")}
	require.NoError(t, store.RecordVaultPublicationObservation(context.Background(), first))
	require.NoError(t, store.Close())

	dbPath := filepath.Join(paths.AppStateDir(), "state.db")
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	_, err = raw.Exec("ALTER TABLE vault_publication_observations DROP COLUMN control_cid; DROP TABLE vault_epoch_first_seen; UPDATE schema_version SET version = 6 WHERE singleton = 1")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	migrated, err := Open(paths)
	require.NoError(t, err)
	defer migrated.Close()
	advanced := VaultPublicationObservation{
		Vault: first.Vault, Epoch: 5, PublicationCount: 0, HeadCID: []byte("head-5"),
		ControlCID: []byte("control-5"), PrevControlCID: first.ControlCID,
	}
	assert.ErrorIs(t, migrated.RecordVaultPublicationObservation(context.Background(), advanced), ErrVaultPublicationControlAncestry)
	require.NoError(t, migrated.RecordVaultPublicationObservation(context.Background(), first), "a same-epoch observation refreshes the backfilled unknown control")
	advanced.PrevControlCID = first.ControlCID
	require.NoError(t, migrated.RecordVaultPublicationObservation(context.Background(), advanced))
}

func TestVaultPublicationObservationAllowsFirstHigherEpochWithoutControlFloor(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	defer store.Close()
	first := VaultPublicationObservation{
		Vault: [32]byte{11}, Epoch: 9, PublicationCount: 6, HeadCID: []byte("head-9"),
		ControlCID: []byte("control-9"), PrevControlCID: []byte("unobserved-control-8"),
	}
	require.NoError(t, store.RecordVaultPublicationObservation(context.Background(), first))
}

func TestVaultPublicationObservationRejectsAncestryMismatch(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	defer store.Close()
	ctx := context.Background()
	first := VaultPublicationObservation{Vault: [32]byte{10}, Epoch: 3, PublicationCount: 4, HeadCID: []byte("head-4"), ControlCID: []byte("control-3")}
	require.NoError(t, store.RecordVaultPublicationObservation(ctx, first))

	wrongPrevHead := VaultPublicationObservation{
		Vault: first.Vault, Epoch: 3, PublicationCount: 5, HeadCID: []byte("head-5"), ControlCID: first.ControlCID,
		PrevHeadCID: []byte("other-head"), ParentCID: first.HeadCID, EnforceParent: true,
	}
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(ctx, wrongPrevHead), ErrPublicationAncestry)

	wrongParent := VaultPublicationObservation{
		Vault: first.Vault, Epoch: 3, PublicationCount: 5, HeadCID: []byte("head-5"), ControlCID: first.ControlCID,
		PrevHeadCID: first.HeadCID, ParentCID: []byte("other-head"), EnforceParent: true,
	}
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(ctx, wrongParent), ErrPublicationAncestry)

	sameHead := VaultPublicationObservation{
		Vault: first.Vault, Epoch: 3, PublicationCount: 5, HeadCID: first.HeadCID, ControlCID: first.ControlCID, PrevHeadCID: first.HeadCID,
	}
	assert.ErrorIs(t, store.RecordVaultPublicationObservation(ctx, sameHead), ErrVaultPublicationConflict)
}

func testVaultControlBytes(vault [32]byte, epoch uint64, digest [32]byte, snapshotCID []byte) []byte {
	encoded := []byte{0x44, 0x54, 0x45, 1, 3}
	encoded = append(encoded, vault[:]...)
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	encoded = append(encoded, epochBytes[:]...)
	encoded = append(encoded, digest[:]...)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(snapshotCID)))
	encoded = append(encoded, length[:]...)
	encoded = append(encoded, snapshotCID...)
	return append(encoded, make([]byte, 80)...)
}

func testRawCID(t *testing.T, encoded []byte) []byte {
	t.Helper()
	digest, err := multihash.Sum(encoded, multihash.SHA2_256, -1)
	require.NoError(t, err)
	return cid.NewCidV1(cid.Raw, digest).Bytes()
}

func TestTransitionAttemptSurvivesStoreRestart(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	attempt := TransitionAttempt{
		ID: "transition-attempt-1", MarkerCollection: "systems.lamb.dottie.vaultSnapshot", MarkerRKey: "snapshot-one",
		ExpectedRecordCID: "bafyrecord", CandidateBlobCID: "bafyblob", EpochSeq: 4,
		PolicyDigest: strings.Repeat("a", 64), Outcome: TransitionAttemptPrepared, Evidence: `{"headRecordCid":"bafyhead"}`, CreatedAt: 123,
	}
	require.NoError(t, store.BeginTransitionAttempt(context.Background(), attempt))
	require.NoError(t, store.Close())

	reopened, err := Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := reopened.TransitionAttempt(context.Background(), attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, attempt, got)
	attempts, err := reopened.TransitionAttempts(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []TransitionAttempt{attempt}, attempts)
	require.NoError(t, reopened.UpdateTransitionAttempt(context.Background(), attempt.ID, TransitionAttemptStaged, `{"stage":true}`))
	require.NoError(t, reopened.UpdateTransitionAttempt(context.Background(), attempt.ID, TransitionAttemptSubmitted, `{"submitted":true}`))
	require.NoError(t, reopened.UpdateTransitionAttempt(context.Background(), attempt.ID, TransitionAttemptCommitted, `{"verified":true}`))
	got, err = reopened.TransitionAttempt(context.Background(), attempt.ID)
	require.NoError(t, err)
	assert.Equal(t, TransitionAttemptCommitted, got.Outcome)
	assert.Equal(t, `{"verified":true}`, got.Evidence)
	require.Error(t, reopened.UpdateTransitionAttempt(context.Background(), attempt.ID, TransitionAttemptNotLanded, `{"verified":false}`))
}

func TestRestartPreservesRecordsAndPayloadsAfterCacheDeletion(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	basePayload := []byte("immutable base bytes")
	base, err := store.PutAppliedBase(context.Background(), BaseRecord{
		Identity: fileIdentity("prefs.toml"), Fingerprint: NewFingerprint("present", model.FileRegular, 0o600, "", "", "", basePayload), RecordedAt: 10,
	}, basePayload)
	require.NoError(t, err)
	gnomeDescriptor := TargetDescriptor{ID: "gnome-target", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 10}
	require.NoError(t, store.PutTarget(context.Background(), gnomeDescriptor))
	settingIdentity := model.EntryKey{TargetID: "gnome-target", Source: model.SourceGNOME, SchemaID: "org.example", SettingsPath: "/", SettingKey: "enabled"}
	settingPayload := []byte("true")
	settingBase, err := store.PutAppliedBase(context.Background(), BaseRecord{Identity: settingIdentity, Fingerprint: NewFingerprint("present", "", 0, "", "b", "true", settingPayload), RecordedAt: 10}, settingPayload)
	require.NoError(t, err)
	intent, err := store.AppendIntent(context.Background(), Intent{ID: "intent-1", Identity: fileIdentity("pending.toml"), State: "pending", Attempts: 2, CreatedAt: 11}, []byte("intent bytes"))
	require.NoError(t, err)
	conflict, err := store.RecordConflict(context.Background(), Conflict{ID: "conflict-1", Identity: fileIdentity("conflicted.toml"), State: "unresolved", CreatedAt: 12}, []byte("local bytes"), []byte("remote bytes"))
	require.NoError(t, err)
	require.NoError(t, store.AppendCheckpoint(context.Background(), Checkpoint{ID: "checkpoint-1", Counter: 9, CID: "bafy-test", RecordedAt: 13}))
	preimage := NewFingerprint("present", model.FileRegular, 0o600, "", "", "", []byte("before"))
	postimage := NewFingerprint("present", model.FileRegular, 0o640, "", "", "", []byte("after"))
	journal, err := store.AppendJournal(context.Background(), JournalEntry{ID: "journal-1", Operation: "replace", State: "prepared", Identity: fileIdentity("journal.toml"), Preimage: preimage, Postimage: postimage, CreatedAt: 14}, []byte("before"))
	require.NoError(t, err)
	cacheFile := filepath.Join(paths.AppCacheDir(), "discardable")
	require.NoError(t, os.MkdirAll(filepath.Dir(cacheFile), 0o700))
	require.NoError(t, os.WriteFile(cacheFile, []byte("cache"), 0o600))
	require.NoError(t, store.Close())
	require.NoError(t, os.RemoveAll(paths.AppCacheDir()))

	reopened, err := Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	bases, err := reopened.AppliedBase(context.Background(), "target")
	require.NoError(t, err)
	require.Equal(t, []BaseRecord{base}, bases)
	payload, err := reopened.Payload(bases[0].PayloadRef)
	require.NoError(t, err)
	assert.Equal(t, basePayload, payload)
	settingBases, err := reopened.AppliedBase(context.Background(), "gnome-target")
	require.NoError(t, err)
	require.Equal(t, []BaseRecord{settingBase}, settingBases)
	assert.Equal(t, "b", settingBases[0].Fingerprint.ValueType)
	assert.Equal(t, "true", settingBases[0].Fingerprint.ValueText)
	payload, err = reopened.Payload(settingBases[0].PayloadRef)
	require.NoError(t, err)
	assert.Equal(t, settingPayload, payload)
	intents, err := reopened.Intents(context.Background(), "target")
	require.NoError(t, err)
	require.Equal(t, []Intent{intent}, intents)
	payload, err = reopened.Payload(intents[0].PayloadRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("intent bytes"), payload)
	conflicts, err := reopened.Conflicts(context.Background(), "target")
	require.NoError(t, err)
	require.Equal(t, []Conflict{conflict}, conflicts)
	payload, err = reopened.Payload(conflicts[0].LocalPayloadRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("local bytes"), payload)
	payload, err = reopened.Payload(conflicts[0].RemotePayloadRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("remote bytes"), payload)
	checkpoints, err := reopened.Checkpoints(context.Background())
	require.NoError(t, err)
	require.Equal(t, []Checkpoint{{ID: "checkpoint-1", Counter: 9, CID: "bafy-test", RecordedAt: 13}}, checkpoints)
	journalEntries, err := reopened.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	require.Equal(t, []JournalEntry{journal}, journalEntries)
	payload, err = reopened.Payload(journalEntries[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("before"), payload)
}

func TestFailedMigrationIsAtomicAndGoodRetrySucceeds(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	_, err := store.PutAppliedBase(context.Background(), BaseRecord{Identity: fileIdentity("safe.toml"), Fingerprint: NewFingerprint("present", model.FileRegular, 0o600, "", "", "", []byte("safe")), RecordedAt: 10}, []byte("safe"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	dbPath := filepath.Join(paths.AppStateDir(), "state.db")
	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	_, err = raw.Exec("DROP TABLE transition_attempts; UPDATE schema_version SET version = 1 WHERE singleton = 1")
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	broken := fstest.MapFS{
		"migrations/0001_initial.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
		"migrations/0002_probe.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE migration_probe(value TEXT); INSERT INTO migration_probe VALUES ('partial'); INVALID SQL;")},
	}
	_, err = openWithMigrations(paths, broken)
	require.Error(t, err)
	prior, err := openWithMigrations(paths, fstest.MapFS{"migrations/0001_initial.sql": &fstest.MapFile{Data: []byte("SELECT 1;")}})
	require.NoError(t, err)
	version, err := prior.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, 1, version)
	bases, err := prior.AppliedBase(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, bases, 1)
	assert.Equal(t, "safe", string(mustPayload(t, prior, bases[0].PayloadRef)))
	require.NoError(t, prior.Close())

	good := fstest.MapFS{
		"migrations/0001_initial.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
		"migrations/0002_probe.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE migration_probe(value TEXT);")},
	}
	reopened, err := openWithMigrations(paths, good)
	require.NoError(t, err)
	defer reopened.Close()
	version, err = reopened.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, 2, version)
	bases, err = reopened.AppliedBase(context.Background(), "target")
	require.NoError(t, err)
	require.Len(t, bases, 1)
	assert.Equal(t, "safe", string(mustPayload(t, reopened, bases[0].PayloadRef)))
	var rows int
	require.NoError(t, reopened.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='migration_probe'").Scan(&rows))
	assert.Equal(t, 1, rows)
}

func TestNewerSchemaIsRefusedWithoutChangingDatabase(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	require.NoError(t, store.PutTarget(context.Background(), testDescriptor()))
	require.NoError(t, store.Close())
	dbPath := filepath.Join(paths.AppStateDir(), "state.db")
	dsn := (&url.URL{Scheme: "file", Path: dbPath}).String()
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	_, err = db.Exec("UPDATE schema_version SET version = 99 WHERE singleton = 1")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	before, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	beforeDigest := sha256.Sum256(before)

	_, err = Open(paths)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnsupportedSchema)
	assert.Contains(t, err.Error(), "supports version 8")
	after, err := os.ReadFile(dbPath)
	require.NoError(t, err)
	afterDigest := sha256.Sum256(after)
	assert.Equal(t, hex.EncodeToString(beforeDigest[:]), hex.EncodeToString(afterDigest[:]))
}

func TestTargetBindingChangeIsRejected(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	descriptor := testDescriptor()
	require.NoError(t, store.PutTarget(context.Background(), descriptor))
	changed := descriptor
	changed.LogicalPath = "other-prefs"
	err := store.PutTarget(context.Background(), changed)
	require.ErrorIs(t, err, ErrTargetBindingChanged)
	var stored string
	require.NoError(t, store.conn.QueryRowContext(context.Background(), "SELECT logical_path FROM targets WHERE target_id = ?", descriptor.ID).Scan(&stored))
	assert.Equal(t, descriptor.LogicalPath, stored)
}

func TestExistingDatabaseModeCorrectedAndNonRegularPathRefused(t *testing.T) {
	paths := testPaths(t)
	stateDir := paths.AppStateDir()
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	dbPath := filepath.Join(stateDir, "state.db")
	require.NoError(t, os.WriteFile(dbPath, nil, 0o644))
	require.NoError(t, os.Chmod(dbPath, 0o644))
	store, err := Open(paths)
	require.NoError(t, err)
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.NoError(t, store.Close())

	directoryPaths := testPaths(t)
	require.NoError(t, os.MkdirAll(filepath.Join(directoryPaths.AppStateDir(), "state.db"), 0o700))
	_, err = Open(directoryPaths)
	require.Error(t, err)
}

func TestSymlinkedDatabasePathIsRefused(t *testing.T) {
	paths := testPaths(t)
	stateDir := paths.AppStateDir()
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	victim := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(victim, []byte("untouched"), 0o600))
	require.NoError(t, os.Symlink(victim, filepath.Join(stateDir, "state.db")))
	_, err := Open(paths)
	require.Error(t, err)
	data, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "untouched", string(data))
}

func TestNoSecretColumns(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	rows, err := store.conn.QueryContext(context.Background(), "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var table string
		require.NoError(t, rows.Scan(&table))
		tables = append(tables, table)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	for _, table := range tables {
		rows, err := store.conn.QueryContext(context.Background(), "PRAGMA table_info('"+table+"')")
		require.NoError(t, err)
		for rows.Next() {
			var cid, notNull, primary int
			var name, kind string
			var defaultValue any
			require.NoError(t, rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary))
			lower := strings.ToLower(name)
			for _, forbidden := range []string{"credential", "token", "password", "secret", "api_key", "access_key", "private_key", "encryption_key"} {
				assert.NotContains(t, lower, forbidden, "%s.%s", table, name)
			}
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
	}
}

func TestCGODisabledOpen(t *testing.T) {
	store := openTestStore(t, testPaths(t))
	version, err := store.SchemaVersion()
	require.NoError(t, err)
	assert.Equal(t, LatestSchemaVersion, version)
}

func TestStateLockHelperProcess(t *testing.T) {
	stateHome := os.Getenv("DOTTIE_STATE_HELPER_HOME")
	if stateHome == "" {
		return
	}
	paths := platform.Paths{StateHome: stateHome}
	store, err := Open(paths)
	expectLocked := os.Getenv("DOTTIE_STATE_HELPER_EXPECT") == "locked"
	if expectLocked {
		require.ErrorIs(t, err, ErrStateLocked, "expected locked state, got store=%v err=%v", store, err)
		return
	}
	require.NoError(t, err, "expected lock to be available: %v", err)
	require.NoError(t, store.Close())
}

func TestCrossProcessLockAndReacquire(t *testing.T) {
	paths := testPaths(t)
	store := openTestStore(t, paths)
	runLockHelper := func(expected string) {
		t.Helper()
		command := exec.Command(os.Args[0], "-test.run=^TestStateLockHelperProcess$")
		command.Env = append(os.Environ(), "DOTTIE_STATE_HELPER_HOME="+paths.StateHome, "DOTTIE_STATE_HELPER_EXPECT="+expected)
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
	}
	runLockHelper("locked")
	require.NoError(t, store.Close())
	runLockHelper("available")
}

func mustPayload(t *testing.T, store *Store, reference string) []byte {
	t.Helper()
	payload, err := store.Payload(reference)
	require.NoError(t, err)
	return payload
}

func TestNewerSchemaRefusedBeforeJournalModeChange(t *testing.T) {
	paths := testPaths(t)
	require.NoError(t, os.MkdirAll(paths.AppStateDir(), 0o700))
	dbPath := filepath.Join(paths.AppStateDir(), "state.db")

	raw, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	_, err = raw.Exec("CREATE TABLE schema_version (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL)")
	require.NoError(t, err)
	_, err = raw.Exec("INSERT INTO schema_version (singleton, version) VALUES (1, 9999)")
	require.NoError(t, err)
	var mode string
	require.NoError(t, raw.QueryRow("PRAGMA journal_mode=delete").Scan(&mode))
	require.Equal(t, "delete", mode)
	require.NoError(t, raw.Close())

	store, err := Open(paths)
	require.ErrorIs(t, err, ErrUnsupportedSchema)
	require.Nil(t, store)

	check, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	require.NoError(t, check.QueryRow("PRAGMA journal_mode").Scan(&mode))
	require.Equal(t, "delete", mode, "refusing a newer schema must not convert the journal mode")
	require.NoError(t, check.Close())
}
