package publicationstate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const journalTestDirectory = "/home/synthetic/config"

func newJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	journal, err := OpenJournal(directory)
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	return journal, directory
}

func journalTestVault() [32]byte {
	var vault [32]byte
	vault[0] = 1
	return vault
}

func journalTestIntent(preimage, postimage []byte, seenFloorRevision uint64) JournalIntent {
	intent := JournalIntent{
		Vault:             journalTestVault(),
		Operation:         "apply",
		DestinationDir:    journalTestDirectory,
		DestinationPath:   "init.lua",
		Anchor:            journalTestAnchor(),
		Postimage:         ObservedJournalFile(postimage),
		SeenFloorRevision: seenFloorRevision,
	}
	if preimage != nil {
		observed := ObservedJournalFile(preimage)
		intent.Preimage = &observed
		intent.PreimageBytes = append([]byte(nil), preimage...)
	}
	return intent
}

func journalTestAnchor() JournalAnchor {
	return JournalAnchor{Path: journalTestDirectory, Device: 42, Inode: 7}
}

func journalTestPath(name string) string {
	return filepath.Join(journalTestDirectory, name)
}

func journalTestDeleteIntent(preimage []byte, seenFloorRevision uint64) JournalIntent {
	intent := journalTestIntent(preimage, nil, seenFloorRevision)
	intent.Operation = "delete"
	intent.Postimage = ObservedFile{}
	return intent
}

func journalStoredPostimage(t *testing.T, journal *Journal, entry int64) (any, any) {
	t.Helper()
	var digestValue, sizeValue any
	require.NoError(t, journal.conn.QueryRowContext(context.Background(), "SELECT postimage_digest,postimage_size FROM journal WHERE entry=?", entry).Scan(&digestValue, &sizeValue))
	return digestValue, sizeValue
}

func requireJournalError(t *testing.T, err error, class error, stage Stage, reason Reason) {
	t.Helper()
	require.Error(t, err)
	require.ErrorIs(t, err, class)
	var stateError *Error
	require.ErrorAs(t, err, &stateError)
	assert.Equal(t, stage, stateError.Stage())
	assert.Equal(t, reason, stateError.Reason())
}

func journalStoredState(t *testing.T, journal *Journal, entry int64) (JournalState, JournalStage) {
	t.Helper()
	var stateValue, stageValue any
	require.NoError(t, journal.conn.QueryRowContext(context.Background(), "SELECT state,stage FROM journal WHERE entry=?", entry).Scan(&stateValue, &stageValue))
	state, stateOK := rawText(stateValue)
	require.True(t, stateOK)
	stage, stageOK := rawText(stageValue)
	require.True(t, stageOK)
	return JournalState(state), JournalStage(stage)
}

func journalStoredCount(t *testing.T, journal *Journal, table string) int64 {
	t.Helper()
	var value any
	require.NoError(t, journal.conn.QueryRowContext(context.Background(), "SELECT count(*) FROM "+table).Scan(&value))
	count, ok := rawInt64(value)
	require.True(t, ok)
	return count
}

func TestJournalOpenRefusesUnsafeForeignAndFutureStores(t *testing.T) {
	ctx := context.Background()

	relative, err := OpenJournal("relative/path")
	requireJournalError(t, err, ErrInvalid, StageJournalOpen, ReasonBinding)
	assert.Nil(t, relative)

	if _, err := OpenJournal(filepath.Join(t.TempDir(), "absent")); err != nil {
		requireJournalError(t, err, ErrInvalid, StageJournalOpen, ReasonBinding)
	} else {
		require.Fail(t, "an absent directory must be refused")
	}

	openDirectory := t.TempDir()
	require.NoError(t, os.Chmod(openDirectory, 0o755))
	if _, err := OpenJournal(openDirectory); err != nil {
		requireJournalError(t, err, ErrInvalid, StageJournalOpen, ReasonBinding)
	} else {
		require.Fail(t, "a group-readable directory must be refused")
	}

	journal, directory := newJournal(t)
	databasePath := filepath.Join(directory, journalDatabaseName)
	_, err = journal.BeginJournal(ctx, journalTestIntent(nil, []byte("postimage"), 0))
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	require.NoError(t, os.Chmod(databasePath, 0o644))
	_, err = OpenJournal(directory)
	requireJournalError(t, err, ErrInvalid, StageJournalOpen, ReasonBinding)
	info, statErr := os.Stat(databasePath)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	require.NoError(t, os.Chmod(databasePath, 0o600))

	linkedPath := filepath.Join(directory, "journal.link")
	require.NoError(t, os.Link(databasePath, linkedPath))
	_, err = OpenJournal(directory)
	requireJournalError(t, err, ErrInvalid, StageJournalOpen, ReasonBinding)
	require.NoError(t, os.Remove(linkedPath))

	require.NoError(t, os.Remove(databasePath))
	require.NoError(t, os.Symlink(filepath.Join(t.TempDir(), "target"), databasePath))
	_, err = OpenJournal(directory)
	requireJournalError(t, err, ErrInvalid, StageJournalOpen, ReasonBinding)
	require.NoError(t, os.Remove(databasePath))

	require.NoError(t, os.WriteFile(databasePath, []byte("not a database at all"), 0o600))
	_, err = OpenJournal(directory)
	require.ErrorIs(t, err, ErrStorage)
	require.NoError(t, os.Remove(databasePath))

	foreignDirectory := t.TempDir()
	require.NoError(t, os.Chmod(foreignDirectory, 0o700))
	foreignPath := filepath.Join(foreignDirectory, journalDatabaseName)
	require.NoError(t, os.WriteFile(foreignPath, nil, 0o600))
	foreign, err := sql.Open("sqlite", dbDSN(foreignPath, false))
	require.NoError(t, err)
	_, err = foreign.ExecContext(ctx, "CREATE TABLE unrelated (id INTEGER PRIMARY KEY NOT NULL)")
	require.NoError(t, err)
	require.NoError(t, foreign.Close())
	_, err = OpenJournal(foreignDirectory)
	requireJournalError(t, err, ErrSchema, StageJournalOpen, ReasonSchema)

	futureDirectory := t.TempDir()
	require.NoError(t, os.Chmod(futureDirectory, 0o700))
	future, err := OpenJournal(futureDirectory)
	require.NoError(t, err)
	require.NoError(t, future.Close())
	futurePath := filepath.Join(futureDirectory, journalDatabaseName)
	rewrite, err := sql.Open("sqlite", dbDSN(futurePath, false))
	require.NoError(t, err)
	_, err = rewrite.ExecContext(ctx, "PRAGMA user_version=2")
	require.NoError(t, err)
	require.NoError(t, rewrite.Close())
	_, err = OpenJournal(futureDirectory)
	requireJournalError(t, err, ErrSchema, StageJournalOpen, ReasonSchema)
	info, statErr = os.Stat(futurePath)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	held, heldDirectory := newJournal(t)
	_, err = OpenJournal(heldDirectory)
	requireJournalError(t, err, ErrLocked, StageJournalOpen, ReasonLocked)
	require.NoError(t, held.Close())
	reopened, err := OpenJournal(heldDirectory)
	require.NoError(t, err)
	assert.Equal(t, heldDirectory, reopened.directory)
	require.NoError(t, reopened.Close())
}

func TestJournalSchemaAndFileModes(t *testing.T) {
	ctx := context.Background()
	journal, directory := newJournal(t)
	_, err := journal.BeginJournal(ctx, journalTestIntent(nil, []byte("postimage"), 0))
	require.NoError(t, err)

	var applicationIDValue, versionValue any
	require.NoError(t, journal.conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationIDValue))
	require.NoError(t, journal.conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&versionValue))
	application, applicationOK := rawInt64(applicationIDValue)
	require.True(t, applicationOK)
	version, versionOK := rawInt64(versionValue)
	require.True(t, versionOK)
	assert.Equal(t, int64(journalApplicationID), application)
	assert.Equal(t, int64(1), version)

	objects, err := queryJournalObjects(ctx, journal)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"backups": "table", "journal": "table", "journal_live": "index"}, objects)

	for name, mode := range map[string]os.FileMode{journalDatabaseName: 0o600, journalLockName: 0o600} {
		info, statErr := os.Lstat(filepath.Join(directory, name))
		require.NoError(t, statErr)
		assert.Equal(t, mode, info.Mode().Perm(), name)
		assert.True(t, info.Mode().IsRegular(), name)
	}
	for _, name := range []string{journalWalName, journalShmName} {
		info, statErr := os.Lstat(filepath.Join(directory, name))
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func queryJournalObjects(ctx context.Context, journal *Journal) (map[string]string, error) {
	rows, err := journal.conn.QueryContext(ctx, "SELECT name,type FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	objects := map[string]string{}
	for rows.Next() {
		var name, kind string
		if err := rows.Scan(&name, &kind); err != nil {
			return nil, err
		}
		objects[name] = kind
	}
	return objects, rows.Err()
}

func TestJournalBackupRoundTripAndBounds(t *testing.T) {
	ctx := context.Background()
	journal, directory := newJournal(t)

	absent, err := journal.BeginJournal(ctx, journalTestIntent(nil, []byte("created"), 3))
	require.NoError(t, err)
	assert.Nil(t, absent.Preimage)
	assert.Nil(t, absent.BackupDigest)
	var digestValue, sizeValue any
	require.NoError(t, journal.conn.QueryRowContext(ctx, "SELECT preimage_digest,preimage_size FROM journal WHERE entry=?", absent.Entry).Scan(&digestValue, &sizeValue))
	assert.Nil(t, digestValue)
	assert.Nil(t, sizeValue)

	preimage := []byte("original file bytes\n")
	present, err := journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("replacement"), 4))
	require.NoError(t, err)
	require.NotNil(t, present.Preimage)
	require.NotNil(t, present.BackupDigest)
	assert.Equal(t, sha256.Sum256(preimage), *present.BackupDigest)
	assert.Equal(t, uint64(len(preimage)), present.Preimage.Size)
	stored, err := journal.BackupBytes(ctx, *present.BackupDigest)
	require.NoError(t, err)
	assert.Equal(t, preimage, stored)

	missing, err := journal.BackupBytes(ctx, [32]byte{9})
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonJournalBackup)
	assert.Nil(t, missing)

	shared, err := journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("second replacement"), 4))
	require.NoError(t, err)
	require.NotNil(t, shared.BackupDigest)
	assert.Equal(t, *present.BackupDigest, *shared.BackupDigest)
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "backups"))

	oversized := make([]byte, journalMaxBackupBytes+1)
	_, err = journal.BeginJournal(ctx, journalTestIntent(oversized, []byte("replacement"), 5))
	requireJournalError(t, err, ErrLimit, StageJournal, ReasonCapacity)
	assert.Equal(t, int64(3), journalStoredCount(t, journal, "journal"))
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "backups"))

	_, err = journal.conn.ExecContext(ctx, "INSERT INTO backups(digest,size,data) VALUES (?,?,?)", []byte("01234567890123456789012345678901"), journalMaxTotalBytes+1, []byte{0})
	require.NoError(t, err)
	small := []byte("abc")
	_, err = journal.BeginJournal(ctx, journalTestIntent(small, []byte("replacement"), 6))
	requireJournalError(t, err, ErrLimit, StageJournal, ReasonCapacity)
	assert.Equal(t, int64(3), journalStoredCount(t, journal, "journal"))

	corruptDigest := sha256.Sum256([]byte("expected bytes"))
	_, err = journal.conn.ExecContext(ctx, "INSERT INTO backups(digest,size,data) VALUES (?,?,?)", corruptDigest[:], len("other bytes"), []byte("other bytes"))
	require.NoError(t, err)
	corrupt, err := journal.BackupBytes(ctx, corruptDigest)
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)
	assert.Nil(t, corrupt)

	require.NoError(t, journal.CompleteJournal(ctx, present, ObservedJournalFile([]byte("replacement"))))
	require.NoError(t, journal.BeginRollback(ctx, present))
	require.NoError(t, journal.CompleteRollback(ctx, present, ObservedJournalFile(preimage)))
	state, stage := journalStoredState(t, journal, present.Entry)
	assert.Equal(t, JournalStateRolledBack, state)
	assert.Equal(t, JournalStageRollbackComplete, stage)

	require.NoError(t, journal.Close())
	reopened, err := OpenJournal(directory)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	retained, err := reopened.BackupBytes(ctx, *present.BackupDigest)
	require.NoError(t, err)
	assert.Equal(t, preimage, retained)
	assert.Equal(t, int64(3), journalStoredCount(t, reopened, "backups"))
}

func TestJournalTransitionsAcceptOnlyExactEdges(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("preimage")
	postimage := []byte("postimage")

	entry, err := journal.BeginJournal(ctx, journalTestIntent(preimage, postimage, 2))
	require.NoError(t, err)
	state, stage := journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStatePending, state)
	assert.Equal(t, JournalStageApplyPending, stage)

	requireJournalError(t, journal.CompleteJournal(ctx, entry, ObservedJournalFile([]byte("neither"))), ErrInvalid, StageJournal, ReasonJournalObservation)
	state, stage = journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStatePending, state)
	assert.Equal(t, JournalStageApplyPending, stage)

	requireJournalError(t, journal.CompleteRollback(ctx, entry, ObservedJournalFile(preimage)), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.BeginRollback(ctx, entry), ErrInvalid, StageJournal, ReasonTransition)
	_, err = journal.ResolveIndeterminate(ctx, entry, ObservedJournalFile(postimage))
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonTransition)

	require.NoError(t, journal.CompleteJournal(ctx, entry, ObservedJournalFile(postimage)))
	state, stage = journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageApplyComplete, stage)

	requireJournalError(t, journal.CompleteJournal(ctx, entry, ObservedJournalFile(postimage)), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.MarkIndeterminate(ctx, entry), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.CompleteRollback(ctx, entry, ObservedJournalFile(preimage)), ErrInvalid, StageJournal, ReasonTransition)

	require.NoError(t, journal.BeginRollback(ctx, entry))
	state, stage = journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageRollbackPending, stage)

	requireJournalError(t, journal.BeginRollback(ctx, entry), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.CompleteJournal(ctx, entry, ObservedJournalFile(postimage)), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.CompleteRollback(ctx, entry, ObservedJournalFile(postimage)), ErrInvalid, StageJournal, ReasonJournalObservation)
	state, stage = journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageRollbackPending, stage)

	require.NoError(t, journal.CompleteRollback(ctx, entry, ObservedJournalFile(preimage)))
	state, stage = journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStateRolledBack, state)
	assert.Equal(t, JournalStageRollbackComplete, stage)
	requireJournalError(t, journal.CompleteRollback(ctx, entry, ObservedJournalFile(preimage)), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.BeginRollback(ctx, entry), ErrInvalid, StageJournal, ReasonTransition)

	missing := entry
	missing.Entry = 4242
	requireJournalError(t, journal.CompleteJournal(ctx, missing, ObservedJournalFile(postimage)), ErrInvalid, StageJournal, ReasonJournalEntry)
	requireJournalError(t, journal.MarkIndeterminate(ctx, missing), ErrInvalid, StageJournal, ReasonTransition)
	requireJournalError(t, journal.BeginRollback(ctx, missing), ErrInvalid, StageJournal, ReasonTransition)

	requireJournalError(t, journal.CompleteJournal(ctx, entry, ObservedFile{Digest: sha256.Sum256(postimage)}), ErrInvalid, StageJournal, ReasonJournalObservation)
	requireJournalError(t, journal.CompleteJournal(ctx, entry, ObservedFile{Present: true}), ErrInvalid, StageJournal, ReasonJournalObservation)

	absent, err := journal.BeginJournal(ctx, journalTestIntent(nil, postimage, 2))
	require.NoError(t, err)
	requireJournalError(t, journal.CompleteRollback(ctx, absent, ObservedFile{}), ErrInvalid, StageJournal, ReasonTransition)
	require.NoError(t, journal.CompleteJournal(ctx, absent, ObservedJournalFile(postimage)))
	require.NoError(t, journal.BeginRollback(ctx, absent))
	requireJournalError(t, journal.CompleteRollback(ctx, absent, ObservedJournalFile(postimage)), ErrInvalid, StageJournal, ReasonJournalObservation)
	require.NoError(t, journal.CompleteRollback(ctx, absent, ObservedFile{}))
	state, stage = journalStoredState(t, journal, absent.Entry)
	assert.Equal(t, JournalStateRolledBack, state)
	assert.Equal(t, JournalStageRollbackComplete, stage)

	restored, err := journal.BeginJournal(ctx, journalTestIntent(preimage, postimage, 2))
	require.NoError(t, err)
	requireJournalError(t, journal.CompleteRollback(ctx, restored, ObservedFile{}), ErrInvalid, StageJournal, ReasonTransition)
	require.NoError(t, journal.CompleteJournal(ctx, restored, ObservedJournalFile(postimage)))
	require.NoError(t, journal.BeginRollback(ctx, restored))
	requireJournalError(t, journal.CompleteRollback(ctx, restored, ObservedFile{}), ErrInvalid, StageJournal, ReasonJournalObservation)
	state, stage = journalStoredState(t, journal, restored.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageRollbackPending, stage)
}

func TestJournalIndeterminateResolution(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("preimage")
	postimage := []byte("postimage")

	decided, err := journal.BeginJournal(ctx, journalTestIntent(preimage, postimage, 7))
	require.NoError(t, err)
	require.NoError(t, journal.CompleteJournal(ctx, decided, ObservedJournalFile(postimage)))
	requireJournalError(t, journal.MarkIndeterminate(ctx, decided), ErrInvalid, StageJournal, ReasonTransition)

	applied, err := journal.BeginJournal(ctx, journalTestIntent(preimage, postimage, 7))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, applied))
	state, stage := journalStoredState(t, journal, applied.Entry)
	assert.Equal(t, JournalStateIndeterminate, state)
	assert.Equal(t, JournalStageIndeterminate, stage)
	requireJournalError(t, journal.MarkIndeterminate(ctx, applied), ErrInvalid, StageJournal, ReasonTransition)
	resolved, err := journal.ResolveIndeterminate(ctx, applied, ObservedJournalFile(postimage))
	require.NoError(t, err)
	assert.Equal(t, JournalStateApplied, resolved)
	state, stage = journalStoredState(t, journal, applied.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageApplyComplete, stage)
	_, err = journal.ResolveIndeterminate(ctx, applied, ObservedJournalFile(postimage))
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonTransition)

	failed, err := journal.BeginJournal(ctx, journalTestIntent(preimage, postimage, 8))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, failed))
	resolved, err = journal.ResolveIndeterminate(ctx, failed, ObservedJournalFile(preimage))
	require.NoError(t, err)
	assert.Equal(t, JournalStateFailed, resolved)
	state, stage = journalStoredState(t, journal, failed.Entry)
	assert.Equal(t, JournalStateFailed, state)
	assert.Equal(t, JournalStageApplyFailed, stage)

	absent, err := journal.BeginJournal(ctx, journalTestIntent(nil, postimage, 9))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, absent))
	resolved, err = journal.ResolveIndeterminate(ctx, absent, ObservedFile{})
	require.NoError(t, err)
	assert.Equal(t, JournalStateFailed, resolved)

	undecidable, err := journal.BeginJournal(ctx, journalTestIntent(preimage, postimage, 10))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, undecidable))
	resolved, err = journal.ResolveIndeterminate(ctx, undecidable, ObservedJournalFile([]byte("user edit")))
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonJournalObservation)
	assert.Equal(t, JournalState(""), resolved)
	state, stage = journalStoredState(t, journal, undecidable.Entry)
	assert.Equal(t, JournalStateIndeterminate, state)
	assert.Equal(t, JournalStageIndeterminate, stage)
	var blocked *JournalBlockedError
	err = journal.CheckAdmission(ctx, 1000)
	require.Error(t, err)
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, undecidable.Entry, blocked.Entry)
	assert.Equal(t, JournalStateIndeterminate, blocked.State)
}

func TestJournalAdmissionBlocksLiveAndFutureRows(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	require.NoError(t, journal.CheckAdmission(ctx, 0))

	first, err := journal.BeginJournal(ctx, journalTestIntent([]byte("preimage"), []byte("postimage"), 5))
	require.NoError(t, err)
	second, err := journal.BeginJournal(ctx, journalTestIntent(nil, []byte("created"), 5))
	require.NoError(t, err)

	err = journal.CheckAdmission(ctx, 100)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrContinuity)
	var blocked *JournalBlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, first.Entry, blocked.Entry)
	assert.Equal(t, JournalStatePending, blocked.State)
	assert.Equal(t, JournalStageApplyPending, blocked.Stage)
	assert.Equal(t, uint64(100), blocked.FloorRevision)

	require.NoError(t, journal.CompleteJournal(ctx, first, ObservedJournalFile([]byte("postimage"))))
	require.NoError(t, journal.CompleteJournal(ctx, second, ObservedJournalFile([]byte("created"))))

	require.NoError(t, journal.CheckAdmission(ctx, 5))
	requireJournalError(t, journal.CheckAdmission(ctx, 4), ErrContinuity, StageJournal, ReasonJournalBlocked)
	require.ErrorIs(t, journal.CheckAdmission(ctx, 4), ErrContinuity)
	blocked = nil
	err = journal.CheckAdmission(ctx, 4)
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, first.Entry, blocked.Entry)
	assert.Equal(t, JournalStateApplied, blocked.State)
	assert.Equal(t, JournalStageApplyComplete, blocked.Stage)
	assert.Equal(t, uint64(5), blocked.SeenFloorRevision)
	assert.Equal(t, uint64(4), blocked.FloorRevision)
	require.NoError(t, journal.CheckAdmission(ctx, 1000))

	require.NoError(t, journal.BeginRollback(ctx, second))
	requireJournalError(t, journal.CheckAdmission(ctx, 1000), ErrContinuity, StageJournal, ReasonJournalBlocked)
	blocked = nil
	require.ErrorAs(t, journal.CheckAdmission(ctx, 1000), &blocked)
	assert.Equal(t, second.Entry, blocked.Entry)
	assert.Equal(t, JournalStageRollbackPending, blocked.Stage)
	require.NoError(t, journal.CompleteRollback(ctx, second, ObservedFile{}))
	require.NoError(t, journal.CheckAdmission(ctx, 5))

	failed, err := journal.BeginJournal(ctx, journalTestIntent([]byte("preimage"), []byte("postimage"), 6))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, failed))
	requireJournalError(t, journal.CheckAdmission(ctx, 1000), ErrContinuity, StageJournal, ReasonJournalBlocked)
	_, err = journal.ResolveIndeterminate(ctx, failed, ObservedJournalFile([]byte("preimage")))
	require.NoError(t, err)
	require.NoError(t, journal.CheckAdmission(ctx, 5))

	blocking, err := journal.BeginJournal(ctx, journalTestIntent(nil, []byte("created"), 0))
	require.NoError(t, err)
	err = journal.CheckAdmission(ctx, 1000)
	blocked = nil
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, blocking.Entry, blocked.Entry)
}

func TestJournalResolveInterruptedResolvesAndReports(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("preimage")
	postimage := []byte("postimage")
	observed := map[string]ObservedFile{}
	unobservable := ""

	begin := func(name string, pre []byte, seen uint64) JournalEntry {
		intent := journalTestIntent(pre, postimage, seen)
		intent.DestinationPath = name
		entry, err := journal.BeginJournal(ctx, intent)
		require.NoError(t, err)
		return entry
	}

	completed := begin("completed.lua", preimage, 1)
	observed[journalTestPath("completed.lua")] = ObservedJournalFile(postimage)

	reverted := begin("reverted.lua", preimage, 1)
	observed[journalTestPath("reverted.lua")] = ObservedJournalFile(preimage)

	undecided := begin("undecided.lua", preimage, 1)
	observed[journalTestPath("undecided.lua")] = ObservedJournalFile([]byte("user edit"))

	indeterminate := begin("indeterminate.lua", preimage, 1)
	require.NoError(t, journal.MarkIndeterminate(ctx, indeterminate))
	observed[journalTestPath("indeterminate.lua")] = ObservedJournalFile(postimage)

	rolling := begin("rolling.lua", preimage, 1)
	require.NoError(t, journal.CompleteJournal(ctx, rolling, ObservedJournalFile(postimage)))
	require.NoError(t, journal.BeginRollback(ctx, rolling))
	observed[journalTestPath("rolling.lua")] = ObservedJournalFile(preimage)

	unobserved := begin("unobserved.lua", preimage, 1)
	unobservable = journalTestPath("unobserved.lua")

	absent := begin("absent.lua", nil, 1)
	observed[journalTestPath("absent.lua")] = ObservedFile{}

	observe := func(entry JournalEntry) (ObservedFile, error) {
		if entry.Path() == unobservable {
			return ObservedFile{}, errors.New("observation unavailable")
		}
		value, ok := observed[entry.Path()]
		if !ok {
			return ObservedFile{}, errors.New("unexpected path")
		}
		return value, nil
	}

	resolutions, err := journal.ResolveInterrupted(ctx, observe)
	require.NoError(t, err)
	byEntry := map[int64]JournalOutcome{}
	for _, resolution := range resolutions {
		byEntry[resolution.Entry] = resolution.Outcome
	}
	assert.Equal(t, map[int64]JournalOutcome{
		completed.Entry:     JournalOutcomeApplied,
		reverted.Entry:      JournalOutcomeFailed,
		undecided.Entry:     JournalOutcomeIndeterminate,
		indeterminate.Entry: JournalOutcomeApplied,
		rolling.Entry:       JournalOutcomeRolledBack,
		unobserved.Entry:    JournalOutcomeUnobserved,
		absent.Entry:        JournalOutcomeFailed,
	}, byEntry)

	expected := map[int64]struct {
		state JournalState
		stage JournalStage
	}{
		completed.Entry:     {state: JournalStateApplied, stage: JournalStageApplyComplete},
		reverted.Entry:      {state: JournalStateFailed, stage: JournalStageApplyFailed},
		undecided.Entry:     {state: JournalStateIndeterminate, stage: JournalStageIndeterminate},
		indeterminate.Entry: {state: JournalStateApplied, stage: JournalStageApplyComplete},
		rolling.Entry:       {state: JournalStateRolledBack, stage: JournalStageRollbackComplete},
		unobserved.Entry:    {state: JournalStatePending, stage: JournalStageApplyPending},
		absent.Entry:        {state: JournalStateFailed, stage: JournalStageApplyFailed},
	}
	for entry, want := range expected {
		state, stage := journalStoredState(t, journal, entry)
		assert.Equal(t, want.state, state, "entry %d", entry)
		assert.Equal(t, want.stage, stage, "entry %d", entry)
	}

	err = journal.CheckAdmission(ctx, 1000)
	var blocked *JournalBlockedError
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, undecided.Entry, blocked.Entry)

	repeated, err := journal.ResolveInterrupted(ctx, observe)
	require.NoError(t, err)
	againByEntry := map[int64]JournalOutcome{}
	for _, resolution := range repeated {
		againByEntry[resolution.Entry] = resolution.Outcome
	}
	assert.Equal(t, map[int64]JournalOutcome{
		undecided.Entry:  JournalOutcomeIndeterminate,
		unobserved.Entry: JournalOutcomeUnobserved,
	}, againByEntry)
	state, stage := journalStoredState(t, journal, undecided.Entry)
	assert.Equal(t, JournalStateIndeterminate, state)
	assert.Equal(t, JournalStageIndeterminate, stage)

	_, err = journal.ResolveInterrupted(ctx, nil)
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonBinding)

	canceledContext, cancel := context.WithCancel(ctx)
	cancel()
	_, err = journal.ResolveInterrupted(canceledContext, observe)
	requireJournalError(t, err, ErrStorage, StageJournal, ReasonCanceled)
}

func TestJournalDeleteIntentBeginsWithoutAPostimage(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("preimage")

	entry, err := journal.BeginJournal(ctx, journalTestDeleteIntent(preimage, 4))
	require.NoError(t, err)
	assert.False(t, entry.Postimage.Present)
	assert.Equal(t, uint64(0), entry.Postimage.Size)
	require.NotNil(t, entry.Preimage)
	assert.Equal(t, journalTestVault(), entry.Vault)
	state, stage := journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStatePending, state)
	assert.Equal(t, JournalStageApplyPending, stage)
	digestValue, sizeValue := journalStoredPostimage(t, journal, entry.Entry)
	assert.Nil(t, digestValue)
	assert.Nil(t, sizeValue)
	require.NotNil(t, entry.BackupDigest)
	retained, err := journal.BackupBytes(ctx, *entry.BackupDigest)
	require.NoError(t, err)
	assert.Equal(t, preimage, retained)
}

func TestJournalDeleteCompletionRequiresObservedAbsence(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("preimage")

	applied, err := journal.BeginJournal(ctx, journalTestDeleteIntent(preimage, 4))
	require.NoError(t, err)
	requireJournalError(t, journal.CompleteJournal(ctx, applied, ObservedJournalFile(preimage)), ErrInvalid, StageJournal, ReasonJournalObservation)
	state, stage := journalStoredState(t, journal, applied.Entry)
	assert.Equal(t, JournalStatePending, state)
	assert.Equal(t, JournalStageApplyPending, stage)

	require.NoError(t, journal.CompleteJournal(ctx, applied, ObservedFile{}))
	state, stage = journalStoredState(t, journal, applied.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageApplyComplete, stage)
	requireJournalError(t, journal.CompleteJournal(ctx, applied, ObservedFile{}), ErrInvalid, StageJournal, ReasonTransition)

	resolved, err := journal.BeginJournal(ctx, journalTestDeleteIntent(preimage, 4))
	require.NoError(t, err)
	resolutions, err := journal.ResolveInterrupted(ctx, func(JournalEntry) (ObservedFile, error) { return ObservedFile{}, nil })
	require.NoError(t, err)
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalResolution{Entry: resolved.Entry, Outcome: JournalOutcomeApplied}, resolutions[0])
	state, stage = journalStoredState(t, journal, resolved.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageApplyComplete, stage)
}

func TestJournalDeleteResolutionLeavesUndecidableRowsIndeterminate(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("preimage")

	entry, err := journal.BeginJournal(ctx, journalTestDeleteIntent(preimage, 4))
	require.NoError(t, err)
	resolutions, err := journal.ResolveInterrupted(ctx, func(JournalEntry) (ObservedFile, error) {
		return ObservedJournalFile([]byte("user edit")), nil
	})
	require.NoError(t, err)
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalOutcomeIndeterminate, resolutions[0].Outcome)
	state, stage := journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStateIndeterminate, state)
	assert.Equal(t, JournalStageIndeterminate, stage)

	var blocked *JournalBlockedError
	err = journal.CheckAdmission(ctx, 100)
	require.ErrorAs(t, err, &blocked)
	assert.Equal(t, entry.Entry, blocked.Entry)
	assert.Equal(t, JournalStateIndeterminate, blocked.State)

	resolutions, err = journal.ResolveInterrupted(ctx, func(JournalEntry) (ObservedFile, error) { return ObservedFile{}, nil })
	require.NoError(t, err)
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalOutcomeApplied, resolutions[0].Outcome)
	state, stage = journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStateApplied, state)
	assert.Equal(t, JournalStageApplyComplete, stage)
}

func TestJournalEntryBoundRefusesBeforeWriting(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	tx, err := journal.conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	statement, err := tx.PrepareContext(ctx, "INSERT INTO journal(entry,vault,operation,stage,state,destination_dir,destination_path,anchor_path,anchor_device,anchor_inode,preimage_digest,preimage_size,postimage_digest,postimage_size,backup_digest,seen_floor_revision,created,updated) VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	require.NoError(t, err)
	vault := journalTestVault()
	digest := sha256.Sum256([]byte("postimage"))
	for index := 0; index < journalMaxEntries; index++ {
		_, err = statement.ExecContext(ctx, vault[:], "apply", string(JournalStageApplyPending), string(JournalStatePending), []byte(journalTestDirectory), "file.lua", []byte(journalTestDirectory), 42, 7, nil, nil, digest[:], 8, nil, 0, 1, 1)
		require.NoError(t, err)
	}
	require.NoError(t, statement.Close())
	require.NoError(t, tx.Commit())
	require.Equal(t, int64(journalMaxEntries), journalStoredCount(t, journal, "journal"))

	_, err = journal.BeginJournal(ctx, journalTestIntent([]byte("preimage"), []byte("postimage"), 1))
	requireJournalError(t, err, ErrLimit, StageJournal, ReasonCapacity)
	assert.Equal(t, int64(journalMaxEntries), journalStoredCount(t, journal, "journal"))
	assert.Equal(t, int64(0), journalStoredCount(t, journal, "backups"))
}

func TestJournalLeavesPositionStoreUntouched(t *testing.T) {
	ctx := context.Background()
	fixture := newFixture(t, BackendPublicRepo)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	store, err := Open(directory, fixture.binding)
	require.NoError(t, err)
	require.Equal(t, 3, store.schemaVersion)
	require.NoError(t, store.Close())

	before := journalPositionStoreBytes(t, directory)
	require.NotEmpty(t, before)
	assert.Contains(t, before, "publication.db")

	journal, err := OpenJournal(directory)
	require.NoError(t, err)
	preimage := []byte("original")
	entry, err := journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("replacement"), 1))
	require.NoError(t, err)
	_, err = journal.BackupBytes(ctx, *entry.BackupDigest)
	require.NoError(t, err)
	require.NoError(t, journal.CompleteJournal(ctx, entry, ObservedJournalFile([]byte("replacement"))))
	require.NoError(t, journal.BeginRollback(ctx, entry))
	require.NoError(t, journal.CompleteRollback(ctx, entry, ObservedJournalFile(preimage)))
	second, err := journal.BeginJournal(ctx, journalTestIntent(nil, []byte("replacement"), 1))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, second))
	_, err = journal.ResolveIndeterminate(ctx, second, ObservedJournalFile([]byte("replacement")))
	require.NoError(t, err)
	require.NoError(t, journal.CheckAdmission(ctx, 1))
	_, err = journal.ResolveInterrupted(ctx, func(JournalEntry) (ObservedFile, error) { return ObservedFile{}, nil })
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	after := journalPositionStoreBytes(t, directory)
	assert.Equal(t, before, after)
	for _, name := range []string{journalDatabaseName, journalLockName} {
		info, statErr := os.Lstat(filepath.Join(directory, name))
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		stat, ok := info.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		assert.Equal(t, uint32(os.Geteuid()), stat.Uid)
	}

	reopened, err := Open(directory, fixture.binding)
	require.NoError(t, err)
	assert.Equal(t, 3, reopened.schemaVersion)
	_, present, err := reopened.Load(ctx)
	require.NoError(t, err)
	assert.False(t, present)
	require.NoError(t, reopened.Close())
}

func journalPositionStoreBytes(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	files := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || journalFile(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		require.NoError(t, err)
		info, err := entry.Info()
		require.NoError(t, err)
		files[entry.Name()] = string(data) + "|" + info.Mode().String()
	}
	return files
}

func journalFile(name string) bool {
	return name == journalDatabaseName || name == journalLockName || name == journalWalName || name == journalShmName || name == journalLeaseName
}

func TestJournalBeginRefusesReusingCorruptBackup(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("original file bytes\n")
	digest := sha256.Sum256(preimage)
	entry, err := journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("replacement"), 4))
	require.NoError(t, err)
	require.Equal(t, digest, *entry.BackupDigest)

	var sizeValue, dataValue any
	truncated := preimage[:len(preimage)-4]
	_, err = journal.conn.ExecContext(ctx, "UPDATE backups SET data=? WHERE digest=?", truncated, digest[:])
	require.NoError(t, err)
	_, err = journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("second replacement"), 4))
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "journal"))
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "backups"))
	require.NoError(t, journal.conn.QueryRowContext(ctx, "SELECT size,data FROM backups WHERE digest=?", digest[:]).Scan(&sizeValue, &dataValue))
	assert.Equal(t, int64(len(preimage)), sizeValue)
	assert.Equal(t, truncated, dataValue)

	corrupt := append([]byte(nil), preimage...)
	corrupt[0] ^= 0xff
	_, err = journal.conn.ExecContext(ctx, "UPDATE backups SET data=? WHERE digest=?", corrupt, digest[:])
	require.NoError(t, err)
	_, err = journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("third replacement"), 4))
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "journal"))
	require.NoError(t, journal.conn.QueryRowContext(ctx, "SELECT size,data FROM backups WHERE digest=?", digest[:]).Scan(&sizeValue, &dataValue))
	assert.Equal(t, int64(len(preimage)), sizeValue)
	assert.Equal(t, corrupt, dataValue)
}

func TestJournalBackupReuseAcceptsVerifiedBytes(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	preimage := []byte("original file bytes\n")
	first, err := journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("replacement"), 4))
	require.NoError(t, err)
	second, err := journal.BeginJournal(ctx, journalTestIntent(preimage, []byte("second replacement"), 4))
	require.NoError(t, err)
	require.NotNil(t, second.BackupDigest)
	assert.Equal(t, *first.BackupDigest, *second.BackupDigest)
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "backups"))
	retained, err := journal.BackupBytes(ctx, *second.BackupDigest)
	require.NoError(t, err)
	assert.Equal(t, preimage, retained)
}

func journalInsertRawEntry(t *testing.T, ctx context.Context, journal *Journal, postimageDigest, postimageSize any) int64 {
	t.Helper()
	vault := journalTestVault()
	result, err := journal.conn.ExecContext(ctx, "INSERT INTO journal(entry,vault,operation,stage,state,destination_dir,destination_path,anchor_path,anchor_device,anchor_inode,preimage_digest,preimage_size,postimage_digest,postimage_size,backup_digest,seen_floor_revision,created,updated) VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		vault[:], "apply", string(JournalStageApplyPending), string(JournalStatePending),
		[]byte(journalTestDirectory), "init.lua", []byte(journalTestDirectory), 42, 7,
		nil, nil, postimageDigest, postimageSize, nil, 0, 1, 1)
	require.NoError(t, err)
	id, err := result.LastInsertId()
	require.NoError(t, err)
	return id
}

func journalReadRawEntry(journal *Journal, entry int64) (JournalEntry, error) {
	var read JournalEntry
	err := journal.withTx(context.Background(), StageJournal, func(tx *sql.Tx) error {
		var readErr error
		read, readErr = readJournalEntry(context.Background(), tx, entry)
		return readErr
	})
	return read, err
}

func TestJournalEntryScanRequiresNullForAbsence(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	empty := sha256.Sum256(nil)

	_, err := journalReadRawEntry(journal, journalInsertRawEntry(t, ctx, journal, []byte{}, nil))
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)

	present := journalInsertRawEntry(t, ctx, journal, empty[:], int64(0))
	read, err := journalReadRawEntry(journal, present)
	require.NoError(t, err)
	assert.True(t, read.Postimage.Present)
	assert.Equal(t, empty, read.Postimage.Digest)
	assert.Equal(t, uint64(0), read.Postimage.Size)

	_, err = journalReadRawEntry(journal, journalInsertRawEntry(t, ctx, journal, empty[:], nil))
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)

	_, err = journalReadRawEntry(journal, journalInsertRawEntry(t, ctx, journal, empty[:31], int64(0)))
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)

	orphanSize := journalInsertRawEntry(t, ctx, journal, nil, int64(0))
	_, err = journalReadRawEntry(journal, orphanSize)
	requireJournalError(t, err, ErrSchema, StageJournal, ReasonCorrupt)
}

func TestJournalPersistsAnchorIdentity(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	entry, err := journal.BeginJournal(ctx, journalTestIntent([]byte("preimage"), []byte("postimage"), 3))
	require.NoError(t, err)
	assert.Equal(t, journalTestAnchor(), entry.Anchor)

	var pathValue, deviceValue, inodeValue any
	require.NoError(t, journal.conn.QueryRowContext(ctx, "SELECT anchor_path,anchor_device,anchor_inode FROM journal WHERE entry=?", entry.Entry).Scan(&pathValue, &deviceValue, &inodeValue))
	assert.Equal(t, []byte(journalTestDirectory), pathValue)
	assert.Equal(t, int64(42), deviceValue)
	assert.Equal(t, int64(7), inodeValue)

	missing := journalTestIntent([]byte("preimage"), []byte("postimage"), 3)
	missing.Anchor = JournalAnchor{}
	_, err = journal.BeginJournal(ctx, missing)
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonBinding)

	noInode := journalTestIntent([]byte("preimage"), []byte("postimage"), 3)
	noInode.Anchor.Inode = 0
	_, err = journal.BeginJournal(ctx, noInode)
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonBinding)

	relative := journalTestIntent([]byte("preimage"), []byte("postimage"), 3)
	relative.Anchor.Path = "relative/anchor"
	_, err = journal.BeginJournal(ctx, relative)
	requireJournalError(t, err, ErrInvalid, StageJournal, ReasonBinding)
	assert.Equal(t, int64(1), journalStoredCount(t, journal, "journal"))
}

func TestJournalResolveInterruptedGivesTheObserverTheRecordedAnchor(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	entry, err := journal.BeginJournal(ctx, journalTestDeleteIntent([]byte("preimage"), 4))
	require.NoError(t, err)

	seen := make([]JournalAnchor, 0, 1)
	resolutions, err := journal.ResolveInterrupted(ctx, func(row JournalEntry) (ObservedFile, error) {
		seen = append(seen, row.Anchor)
		return ObservedFile{}, errors.New("anchor unavailable")
	})
	require.NoError(t, err)
	require.Len(t, seen, 1)
	assert.Equal(t, journalTestAnchor(), seen[0])
	require.Len(t, resolutions, 1)
	assert.Equal(t, JournalResolution{Entry: entry.Entry, Outcome: JournalOutcomeUnobserved}, resolutions[0])
	state, stage := journalStoredState(t, journal, entry.Entry)
	assert.Equal(t, JournalStatePending, state)
	assert.Equal(t, JournalStageApplyPending, stage)
	requireJournalError(t, journal.CheckAdmission(ctx, 100), ErrContinuity, StageJournal, ReasonJournalBlocked)
}

func TestJournalApplyLeaseIsExclusiveAndRefusesImmediately(t *testing.T) {
	ctx := context.Background()
	journal, directory := newJournal(t)
	lease, err := journal.AcquireApplyLease(ctx)
	require.NoError(t, err)
	info, err := os.Lstat(filepath.Join(directory, journalLeaseName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	_, err = journal.AcquireApplyLease(ctx)
	requireJournalError(t, err, ErrLocked, StageJournal, ReasonLocked)

	require.NoError(t, lease.Close())
	require.NoError(t, lease.Close())
	reacquired, err := journal.AcquireApplyLease(ctx)
	require.NoError(t, err)

	canceledContext, cancel := context.WithCancel(ctx)
	cancel()
	_, err = journal.AcquireApplyLease(canceledContext)
	requireJournalError(t, err, ErrStorage, StageJournal, ReasonCanceled)
	require.NoError(t, reacquired.Close())

	require.NoError(t, journal.Close())
	_, err = journal.AcquireApplyLease(ctx)
	requireJournalError(t, err, ErrClosed, StageJournal, ReasonClosed)
}

func TestJournalEntryCountReadsWithoutMutating(t *testing.T) {
	ctx := context.Background()
	journal, _ := newJournal(t)
	count, err := journal.EntryCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	first, err := journal.BeginJournal(ctx, journalTestIntent([]byte("preimage"), []byte("postimage"), 3))
	require.NoError(t, err)
	require.NoError(t, journal.MarkIndeterminate(ctx, first))
	count, err = journal.EntryCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	state, stage := journalStoredState(t, journal, first.Entry)
	assert.Equal(t, JournalStateIndeterminate, state)
	assert.Equal(t, JournalStageIndeterminate, stage)
}
