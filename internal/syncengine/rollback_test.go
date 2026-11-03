package syncengine

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/lamb-systems/dottie/internal/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func appendPendingTestEntry(t *testing.T, store *state.Store, root, key string, preimage, postimage []byte, createdAt int64) state.JournalEntry {
	t.Helper()
	info, err := os.Stat(root)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	identity := model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: key}
	pre := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", preimage)
	post := state.NewFingerprint(string(model.FilePresent), model.FileRegular, 0o600, "", "", "", postimage)
	entry, err := store.AppendJournal(context.Background(), state.JournalEntry{
		ID: "journal-" + key, Operation: "replace", State: "pending", Stage: state.JournalStagePending,
		Identity: identity, RootPath: root, DestinationPath: key, RootDevice: int64(stat.Dev), RootInode: int64(stat.Ino),
		Preimage: pre, Postimage: post, CreatedAt: createdAt,
	}, preimage)
	require.NoError(t, err)
	return entry
}

func TestApplyRequiresRecoveryOfPendingRows(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
	appendPendingTestEntry(t, store, root, "file", []byte("old"), []byte("pending"), 100)
	newEntry, postimage := applyEntry("new", PreviewCreate, []byte("new file"), 0o600, nil, 0)
	err := Apply(context.Background(), store, applyRequest(root, []PreviewEntry{newEntry}, []Postimage{postimage}))
	assert.ErrorIs(t, err, ErrRecoveryRequired)
	_, err = os.Stat(filepath.Join(root, "new"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestRecoverInterruptedClassifiesPendingEntriesAndIsIdempotent(t *testing.T) {
	for _, test := range []struct {
		name          string
		actual        []byte
		outcome       string
		resolvedState string
	}{
		{name: "preimage", actual: []byte("old"), outcome: "failed", resolvedState: "failed"},
		{name: "postimage", actual: []byte("new"), outcome: "indeterminate", resolvedState: "indeterminate"},
		{name: "unrecognised", actual: []byte("user edit"), outcome: "indeterminate", resolvedState: "indeterminate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := applyTestStore(t)
			root := t.TempDir()
			writeApplyFile(t, filepath.Join(root, "file"), test.actual, 0o600)
			appendPendingTestEntry(t, store, root, "file", []byte("old"), []byte("new"), 100)
			now := func() time.Time { return time.Unix(100, 0) }
			report, err := RecoverInterrupted(context.Background(), store, nil, now)
			require.NoError(t, err)
			require.Len(t, report.Entries, 1)
			assert.Equal(t, test.outcome, report.Entries[0].Outcome)
			rows := journalEntriesFor(t, store)
			require.Len(t, rows, 1)
			assert.Equal(t, test.resolvedState, rows[0].State)
			assert.NotEmpty(t, rows[0].BackupRef)
			assert.Equal(t, test.actual, readApplyFile(t, filepath.Join(root, "file")))
			report, err = RecoverInterrupted(context.Background(), store, nil, now)
			require.NoError(t, err)
			assert.Empty(t, report.Entries)
		})
	}
}

func TestRecoverInterruptedLeavesDestinationWhenRootIdentityChanges(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
	appendPendingTestEntry(t, store, root, "file", []byte("old"), []byte("new"), 100)
	moved := root + "-moved"
	require.NoError(t, os.Rename(root, moved))
	require.NoError(t, os.Mkdir(root, 0o700))
	writeApplyFile(t, filepath.Join(root, "file"), []byte("replacement root"), 0o600)
	report, err := RecoverInterrupted(context.Background(), store, nil, func() time.Time { return time.Unix(100, 0) })
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
	assert.Equal(t, []byte("replacement root"), readApplyFile(t, filepath.Join(root, "file")))
	assert.Equal(t, "old", string(readApplyFile(t, filepath.Join(moved, "file"))))
}

func TestRecoverInterruptedLeavesEditMadeAfterCrashUntouched(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeApplyFile(t, path, []byte("old"), 0o600)
	entry, postimage := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
	request := applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})
	request.FileSystem = &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: "crash-before-readback"}
	assert.Panics(t, func() { _ = Apply(context.Background(), store, request) })
	writeApplyFile(t, path, []byte("user edit"), 0o600)
	report, err := RecoverInterrupted(context.Background(), store, nil, request.Now)
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
	assert.Equal(t, []byte("user edit"), readApplyFile(t, path))
}

func TestRecoverInterruptedAfterReadbackBeforeJournalUpdate(t *testing.T) {
	base := t.TempDir()
	paths := platform.Paths{Home: filepath.Join(base, "home"), StateHome: filepath.Join(base, "state")}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: model.RootHome, LogicalPath: "prefs", Kind: model.SelectionDirectory, Mode: "review", CreatedAt: 1,
	}))
	dbPath := filepath.Join(paths.AppStateDir(), "state.db")
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	_, err = db.Exec("CREATE TRIGGER simulated_crash BEFORE UPDATE OF state ON apply_journal WHEN NEW.state = 'applied' BEGIN SELECT RAISE(ABORT, 'simulated crash'); END")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeApplyFile(t, path, []byte("old"), 0o600)
	entry, postimage := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
	request := applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})
	err = Apply(context.Background(), store, request)
	require.Error(t, err)
	assert.Equal(t, []byte("new"), readApplyFile(t, path))
	rows := journalEntriesFor(t, store)
	require.Len(t, rows, 1)
	assert.Equal(t, "pending", rows[0].State)
	db, err = sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
	require.NoError(t, err)
	_, err = db.Exec("DROP TRIGGER simulated_crash")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	report, err := RecoverInterrupted(context.Background(), store, nil, request.Now)
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
}

func TestRollbackAppliedReportsEachEntryAndSkipsNewerEdits(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	entries := make([]PreviewEntry, 0, 5)
	content := make([]Postimage, 0, 5)
	for index := 0; index < 5; index++ {
		name := string(rune('a' + index))
		before := []byte("old-" + name)
		after := []byte("new-" + name)
		writeApplyFile(t, filepath.Join(root, name), before, 0o600)
		entry, postimage := applyEntry(name, PreviewChange, after, 0o600, before, 0o600)
		entries = append(entries, entry)
		content = append(content, postimage)
	}
	require.NoError(t, Apply(context.Background(), store, applyRequest(root, entries, content)))
	writeApplyFile(t, filepath.Join(root, "a"), []byte("newer-a"), 0o600)
	writeApplyFile(t, filepath.Join(root, "c"), []byte("newer-c"), 0o600)
	report, err := RollbackApplied(context.Background(), store, nil, func() time.Time { return time.Unix(100, 0) })
	require.NoError(t, err)
	require.Len(t, report.Entries, 5)
	outcomes := map[string]int{}
	for _, result := range report.Entries {
		outcomes[result.Outcome]++
	}
	assert.Equal(t, 3, outcomes["rolled-back"])
	assert.Equal(t, 2, outcomes["skipped-newer-edit"])
	for _, name := range []string{"b", "d", "e"} {
		assert.Equal(t, []byte("old-"+name), readApplyFile(t, filepath.Join(root, name)))
	}
	assert.Equal(t, []byte("newer-a"), readApplyFile(t, filepath.Join(root, "a")))
	assert.Equal(t, []byte("newer-c"), readApplyFile(t, filepath.Join(root, "c")))
	journal := journalEntriesFor(t, store)
	states := map[string]string{}
	for _, entry := range journal {
		states[entry.Identity.FilePath] = entry.State
	}
	assert.Equal(t, "rolled-back", states["b"])
	assert.Equal(t, "applied", states["a"])
	assert.Equal(t, state.JournalStageRollbackSkipped, journalStateFor(t, journal, "a").Stage)
}

func journalStateFor(t *testing.T, entries []state.JournalEntry, path string) state.JournalEntry {
	t.Helper()
	for _, entry := range entries {
		if entry.Identity.FilePath == path {
			return entry
		}
	}
	require.FailNow(t, "journal entry not found", "%s", path)
	return state.JournalEntry{}
}

func TestRollbackSkippedNewerEditBlocksOlderSameDestinationHistory(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeApplyFile(t, path, []byte("A"), 0o600)
	firstEntry, firstPostimage := applyEntry("file", PreviewChange, []byte("B"), 0o600, []byte("A"), 0o600)
	firstRequest := applyRequest(root, []PreviewEntry{firstEntry}, []Postimage{firstPostimage})
	firstRequest.Now = func() time.Time { return time.Unix(100, 0) }
	require.NoError(t, Apply(context.Background(), store, firstRequest))
	secondEntry, secondPostimage := applyEntry("file", PreviewChange, []byte("C"), 0o600, []byte("B"), 0o600)
	secondRequest := applyRequest(root, []PreviewEntry{secondEntry}, []Postimage{secondPostimage})
	secondRequest.Now = func() time.Time { return time.Unix(200, 0) }
	require.NoError(t, Apply(context.Background(), store, secondRequest))
	writeApplyFile(t, path, []byte("B"), 0o600)

	now := func() time.Time { return time.Unix(300, 0) }
	report, err := RollbackApplied(context.Background(), store, nil, now)
	require.NoError(t, err)
	require.Len(t, report.Entries, 2)
	assert.Equal(t, "skipped-newer-edit", report.Entries[0].Outcome)
	assert.Equal(t, "skipped-newer-edit", report.Entries[1].Outcome)
	assert.Equal(t, []byte("B"), readApplyFile(t, path))
	rows := journalEntriesFor(t, store)
	require.Len(t, rows, 2)
	skippedRecorded := false
	for _, row := range rows {
		if row.Stage == state.JournalStageRollbackSkipped {
			skippedRecorded = true
		}
		assert.Equal(t, "applied", row.State, "skipped and blocked rollback history must stay applied")
	}
	assert.True(t, skippedRecorded, "newest skipped rollback outcome must be durable")

	report, err = RollbackApplied(context.Background(), store, nil, now)
	require.NoError(t, err)
	require.Len(t, report.Entries, 2)
	assert.Equal(t, []byte("B"), readApplyFile(t, path), "durable skipped outcome must not become a later restore")
}

func TestRollbackUnresolvedRestoreRetainsBackupPastRetention(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	path := filepath.Join(root, "file")
	writeApplyFile(t, path, []byte("old"), 0o600)
	entry, postimage := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
	require.NoError(t, Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})))
	request := applyRequest(root, nil, nil)
	request.FileSystem = &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: "rename"}
	report, err := RollbackApplied(context.Background(), store, request.FileSystem, request.Now)
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
	journal := journalEntriesFor(t, store)
	require.Len(t, journal, 1)
	assert.Equal(t, state.JournalStageRollbackIndeterminate, journal[0].Stage)
	backupRef := journal[0].BackupRef

	late := func() time.Time { return time.Unix(100, 0).Add(state.JournalBackupRetention + time.Hour) }
	report, err = RollbackApplied(context.Background(), store, nil, late)
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), readApplyFile(t, path))
	journal = journalEntriesFor(t, store)
	assert.Equal(t, backupRef, journal[0].BackupRef, "unresolved rollback backup must not expire")
	backup, err := store.Payload(backupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("old"), backup)
}

func TestRollbackUsesResolvedDirectoryForSingleFileTarget(t *testing.T) {
	store := applyTestStore(t)
	root := filepath.Join(t.TempDir(), "selected-file")
	writeApplyFile(t, root, []byte("old"), 0o600)
	entry, postimage := applyEntry(".", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
	require.NoError(t, Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})))
	journal := journalEntriesFor(t, store)
	require.Len(t, journal, 1)
	assert.Equal(t, filepath.Dir(root), journal[0].RootPath)
	assert.Equal(t, filepath.Base(root), journal[0].DestinationPath)
	report, err := RollbackApplied(context.Background(), store, nil, func() time.Time { return time.Unix(100, 0) })
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "rolled-back", report.Entries[0].Outcome)
	assert.Equal(t, []byte("old"), readApplyFile(t, root))
}

func TestRollbackRestoresDeletedFileAndRemovesCreatedFile(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		path := filepath.Join(root, "file")
		writeApplyFile(t, path, []byte("old"), 0o640)
		digest := sha256.Sum256([]byte("old"))
		entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "file"}, Action: PreviewDelete, DecisionAction: ActionDeleteLocal, Preimage: &PreviewPreimage{Digest: fmtDigest(digest[:]), Mode: 0o640}}
		require.NoError(t, Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, nil)))
		_, err := os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist)
		report, err := RollbackApplied(context.Background(), store, nil, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "rolled-back", report.Entries[0].Outcome)
		assert.Equal(t, []byte("old"), readApplyFile(t, path))
	})

	t.Run("create", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		entry, postimage := applyEntry("file", PreviewCreate, []byte("created"), 0o600, nil, 0)
		require.NoError(t, Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})))
		path := filepath.Join(root, "file")
		assert.Equal(t, []byte("created"), readApplyFile(t, path))
		report, err := RollbackApplied(context.Background(), store, nil, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "rolled-back", report.Entries[0].Outcome)
		_, err = os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestRollbackMaterialCapMatchesSnapshotDefault(t *testing.T) {
	assert.Equal(t, vault.DefaultLimits().MaxTotalBytes, MaxRollbackMaterialBytes)
}

func TestRollbackMaterialLimitNamesExistingHolders(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	writeApplyFile(t, filepath.Join(root, "file"), []byte("held"), 0o600)
	appendPendingTestEntry(t, store, root, "file", []byte("held"), []byte("post"), 100)
	err := checkJournalBackupCapacityLimit(context.Background(), store, []byte("next"), 6)
	var limitError *RollbackMaterialLimitError
	require.ErrorAs(t, err, &limitError)
	assert.Equal(t, int64(4), limitError.CurrentBytes)
	assert.Equal(t, int64(4), limitError.RequestedBytes)
	assert.Equal(t, int64(6), limitError.LimitBytes)
	assert.Equal(t, []string{"journal-file"}, limitError.Entries)
}

func TestRecoverInterruptedSettingsClassifications(t *testing.T) {
	for _, test := range []struct {
		name       string
		current    SettingValue
		locked     bool
		readError  bool
		nilBackend bool
		want       string
	}{
		{name: "preimage", current: SettingValue{Present: true, Type: "s", Text: "before"}, want: "failed"},
		{name: "postimage", current: SettingValue{Present: true, Type: "s", Text: "after"}, want: "indeterminate"},
		{name: "neither", current: SettingValue{Present: true, Type: "s", Text: "other"}, want: "indeterminate"},
		{name: "locked", current: SettingValue{Present: true, Type: "s", Text: "before"}, locked: true, want: "indeterminate"},
		{name: "read error", current: SettingValue{Present: true, Type: "s", Text: "before"}, readError: true, want: "indeterminate"},
		{name: "nil backend", current: SettingValue{Present: true, Type: "s", Text: "before"}, nilBackend: true, want: "indeterminate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := applyTestStore(t)
			key := settingTestKey("settings")
			appendSettingJournal(t, store, "pending-setting", key, model.SettingPresent, "s", "before", model.SettingPresent, "s", "after", "pending", 100)
			backend := newFakeSettingsBackend()
			backend.values[key] = test.current
			backend.locked = test.locked
			if test.readError {
				backend.observeErrors[1] = errors.New("read failed")
			}
			var selected SettingsBackend = backend
			if test.nilBackend {
				selected = nil
			}
			report, err := RecoverInterruptedWithSettings(context.Background(), store, nil, selected, func() time.Time { return time.Unix(100, 0) })
			require.NoError(t, err)
			require.Len(t, report.Entries, 1)
			assert.Equal(t, test.want, report.Entries[0].Outcome)
			assert.Equal(t, key, report.Entries[0].Key)
			assert.Zero(t, backend.writeCount)
			rows, err := store.JournalEntries(context.Background(), key.TargetID)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			assert.Equal(t, test.want, rows[0].State)
		})
	}
}

func TestInterruptedMixedApplyRecoversPendingSettingAfterAppliedFile(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
	fileEntry, filePost := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
	key := settingTestKey("settings")
	backend := newFakeSettingsBackend()
	backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
	before := backend.values[key]
	settingEntry := settingTestEntry(key, &before)
	postimage := settingTestPostimage(key, model.SettingPresent, "s", "after")
	backend.beforeSet = func() { panic("interrupted before setting write") }
	request := ApplyRequest{
		Preview: Preview{Targets: []PreviewTarget{
			{ID: "target", Entries: []PreviewEntry{fileEntry}},
			{ID: "settings", Entries: []PreviewEntry{settingEntry}},
		}, Complete: true},
		Roots: map[string]string{"target": root}, ModePolicy: ModePolicy{Default: 0o600}, Content: []Postimage{filePost},
		Settings: backend, SettingPostimages: []SettingPostimage{postimage}, Now: func() time.Time { return time.Unix(100, 0) },
	}
	assert.Panics(t, func() { _ = Apply(context.Background(), store, request) })
	assert.Equal(t, []byte("new"), readApplyFile(t, filepath.Join(root, "file")))
	report, err := RecoverInterruptedWithSettings(context.Background(), store, nil, backend, request.Now)
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, key, report.Entries[0].Key)
	assert.Equal(t, "failed", report.Entries[0].Outcome)
	assert.Equal(t, SettingValue{Present: true, Type: "s", Text: "before", Writable: true}, mustObserveSetting(t, backend, key))
}

func TestRollbackSettingsPresentResetAndSameTimestampReverseOrder(t *testing.T) {
	for _, test := range []struct {
		name       string
		before     SettingValue
		postState  model.SettingState
		postType   string
		postText   string
		wantAbsent bool
	}{
		{name: "present to reset", before: SettingValue{Present: true, Type: "s", Text: "before"}, postState: model.SettingReset, wantAbsent: true},
		{name: "reset to present", before: SettingValue{}, postState: model.SettingPresent, postType: "s", postText: "after"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := applyTestStore(t)
			key := settingTestKey("settings")
			backend := newFakeSettingsBackend()
			backend.values[key] = test.before
			before := test.before
			entry := settingTestEntry(key, &before)
			postimage := settingTestPostimage(key, test.postState, test.postType, test.postText)
			require.NoError(t, Apply(context.Background(), store, settingApplyRequest(key, entry, []SettingPostimage{postimage}, backend)))
			report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
			require.NoError(t, err)
			require.Len(t, report.Entries, 1)
			assert.Equal(t, "rolled-back", report.Entries[0].Outcome)
			assert.Equal(t, key, report.Entries[0].Key)
			current := mustObserveSetting(t, backend, key)
			assert.Equal(t, test.before.Present, current.Present)
			if test.before.Present {
				assert.Equal(t, test.before.Type, current.Type)
				assert.Equal(t, test.before.Text, current.Text)
			} else {
				assert.False(t, current.Present)
			}
		})
	}

	store := applyTestStore(t)
	key := settingTestKey("settings")
	backend := newFakeSettingsBackend()
	backend.values[key] = SettingValue{Present: true, Type: "s", Text: "A"}
	for _, transition := range []struct{ before, after string }{{"A", "B"}, {"B", "C"}} {
		before := SettingValue{Present: true, Type: "s", Text: transition.before}
		entry := settingTestEntry(key, &before)
		postimage := settingTestPostimage(key, model.SettingPresent, "s", transition.after)
		require.NoError(t, Apply(context.Background(), store, settingApplyRequest(key, entry, []SettingPostimage{postimage}, backend)))
	}
	report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
	require.NoError(t, err)
	require.Len(t, report.Entries, 2)
	assert.Equal(t, []string{"rolled-back", "rolled-back"}, []string{report.Entries[0].Outcome, report.Entries[1].Outcome})
	assert.Equal(t, "A", mustObserveSetting(t, backend, key).Text)
}

func TestRollbackSettingsAliasBlockingNilBackendAndRecheck(t *testing.T) {
	t.Run("alias blocking", func(t *testing.T) {
		store := applyTestStore(t)
		key := settingTestKey("settings")
		alias := settingTestKey("settings-alias")
		appendSettingJournal(t, store, "older-setting", key, model.SettingPresent, "s", "A", model.SettingPresent, "s", "B", "applied", 100)
		appendSettingJournal(t, store, "newer-alias", alias, model.SettingPresent, "s", "B", model.SettingPresent, "s", "C", "applied", 100)
		backend := newFakeSettingsBackend()
		backend.values[alias] = SettingValue{Present: true, Type: "s", Text: "B"}
		report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 2)
		assert.Equal(t, "skipped-newer-edit", report.Entries[0].Outcome)
		assert.Equal(t, "skipped-newer-edit", report.Entries[1].Outcome)
		assert.Zero(t, backend.writeCount)
	})

	t.Run("nil backend", func(t *testing.T) {
		store := applyTestStore(t)
		key := settingTestKey("settings")
		appendSettingJournal(t, store, "setting-no-backend", key, model.SettingPresent, "s", "before", model.SettingPresent, "s", "after", "applied", 100)
		report, err := RollbackAppliedWithSettings(context.Background(), store, nil, nil, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
	})

	t.Run("postimage changes after rollback intent", func(t *testing.T) {
		store := applyTestStore(t)
		key := settingTestKey("settings")
		backend := newFakeSettingsBackend()
		backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
		before := backend.values[key]
		entry := settingTestEntry(key, &before)
		postimage := settingTestPostimage(key, model.SettingPresent, "s", "after")
		require.NoError(t, Apply(context.Background(), store, settingApplyRequest(key, entry, []SettingPostimage{postimage}, backend)))
		backend.observeCalls = 0
		backend.writeCount = 0
		backend.observeHook = func(call int, observedKey model.EntryKey) {
			if call == 2 {
				backend.setNative(observedKey, SettingValue{Present: true, Type: "s", Text: "user edit"})
			}
		}
		report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "skipped-newer-edit", report.Entries[0].Outcome)
		assert.Equal(t, "user edit", mustObserveSetting(t, backend, key).Text)
		assert.Zero(t, backend.writeCount)
	})
}

func TestRollbackBlocksOlderSettingBehindNewerIndeterminateHistory(t *testing.T) {
	store := applyTestStore(t)
	key := settingTestKey("settings")
	appendSettingJournal(t, store, "older-setting", key, model.SettingPresent, "s", "A", model.SettingPresent, "s", "B", "applied", 100)
	newer := appendSettingJournal(t, store, "newer-indeterminate", key, model.SettingPresent, "s", "C", model.SettingPresent, "s", "B", "", 101)
	require.NoError(t, store.TransitionJournalEntry(context.Background(), newer.ID, "pending", "indeterminate", state.JournalStageIndeterminate))
	backend := newFakeSettingsBackend()
	backend.values[key] = SettingValue{Present: true, Type: "s", Text: "B"}
	report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "skipped-newer-edit", report.Entries[0].Outcome)
	assert.Equal(t, "B", mustObserveSetting(t, backend, key).Text)
	assert.Zero(t, backend.writeCount)
}

func TestRollbackSettingPersistsIntentBeforeMutationAndRejectsIntentFailure(t *testing.T) {
	t.Run("intent before mutation", func(t *testing.T) {
		store := applyTestStore(t)
		key := settingTestKey("settings")
		backend := newFakeSettingsBackend()
		backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
		before := backend.values[key]
		entry := settingTestEntry(key, &before)
		postimage := settingTestPostimage(key, model.SettingPresent, "s", "after")
		require.NoError(t, Apply(context.Background(), store, settingApplyRequest(key, entry, []SettingPostimage{postimage}, backend)))
		backend.beforeSet = func() {
			rows, err := store.JournalEntries(context.Background(), key.TargetID)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			assert.Equal(t, state.JournalStageRollbackPending, rows[0].Stage)
		}
		report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "rolled-back", report.Entries[0].Outcome)
	})

	t.Run("intent write failure", func(t *testing.T) {
		base := t.TempDir()
		paths := platform.Paths{Home: filepath.Join(base, "home"), StateHome: filepath.Join(base, "state")}
		store, err := state.Open(paths)
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })
		key := settingTestKey("settings")
		require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{ID: key.TargetID, Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1}))
		appendSettingJournal(t, store, "intent-failure", key, model.SettingPresent, "s", "before", model.SettingPresent, "s", "after", "applied", 100)
		dbPath := filepath.Join(paths.AppStateDir(), "state.db")
		db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: dbPath}).String())
		require.NoError(t, err)
		_, err = db.Exec("CREATE TRIGGER reject_rollback_intent BEFORE UPDATE OF stage ON apply_journal WHEN NEW.stage = 'rollback-pending' BEGIN SELECT RAISE(ABORT, 'intent rejected'); END")
		require.NoError(t, err)
		require.NoError(t, db.Close())
		backend := newFakeSettingsBackend()
		backend.values[key] = SettingValue{Present: true, Type: "s", Text: "after"}
		report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
		assert.Zero(t, backend.writeCount)
		assert.Equal(t, "after", mustObserveSetting(t, backend, key).Text)

		report, err = RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
		assert.Zero(t, backend.writeCount)
	})
}
