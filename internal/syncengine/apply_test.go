package syncengine

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lamb-systems/dottie/internal/model"
	"github.com/lamb-systems/dottie/internal/platform"
	"github.com/lamb-systems/dottie/internal/source/files"
	"github.com/lamb-systems/dottie/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func applyTestStore(t *testing.T) *state.Store {
	t.Helper()
	base := t.TempDir()
	paths := platform.Paths{Home: filepath.Join(base, "home"), StateHome: filepath.Join(base, "state")}
	store, err := state.Open(paths)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: "target", Version: 1, Source: model.SourceFiles, SourceVersion: model.SourceVersion,
		LogicalBase: model.RootHome, LogicalPath: "prefs", Kind: model.SelectionDirectory, Mode: "review", CreatedAt: 1,
	}))
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: "settings", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1,
	}))
	require.NoError(t, store.PutTarget(context.Background(), state.TargetDescriptor{
		ID: "settings-alias", Version: 1, Source: model.SourceGNOME, SourceVersion: model.SourceVersion, Mode: "review", CreatedAt: 1,
	}))
	return store
}

func applyEntry(path string, action PreviewAction, data []byte, mode os.FileMode, before []byte, beforeMode os.FileMode) (PreviewEntry, Postimage) {
	decisionAction := ActionDownload
	if action == PreviewDelete {
		decisionAction = ActionDeleteLocal
	}
	entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: path}, Action: action, DecisionAction: decisionAction}
	if before != nil {
		digest := sha256.Sum256(before)
		entry.Preimage = &PreviewPreimage{Digest: fmtDigest(digest[:]), Mode: uint32(beforeMode.Perm())}
	}
	digest := sha256.Sum256(data)
	return entry, Postimage{TargetID: "target", Key: path, Data: data, Digest: digest[:], Mode: mode}
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return fmtDigest(digest[:])
}

func fmtDigest(digest []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(digest)*2)
	for index, value := range digest {
		encoded[index*2] = digits[value>>4]
		encoded[index*2+1] = digits[value&15]
	}
	return string(encoded)
}

func applyRequest(root string, entries []PreviewEntry, content []Postimage) ApplyRequest {
	return ApplyRequest{
		Preview: Preview{Targets: []PreviewTarget{{ID: "target", Entries: entries}}, Complete: true},
		Roots:   map[string]string{"target": root}, ModePolicy: ModePolicy{Default: 0o600}, Content: content, Now: func() time.Time { return time.Unix(100, 0) },
	}
}

func writeApplyFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, mode))
	require.NoError(t, os.Chmod(path, mode))
}

func journalEntriesFor(t *testing.T, store *state.Store) []state.JournalEntry {
	t.Helper()
	entries, err := store.JournalEntries(context.Background(), "target")
	require.NoError(t, err)
	return entries
}

func TestApplyRefusesChangedDigestOrModeBeforeWriting(t *testing.T) {
	for _, test := range []struct {
		name        string
		previewData []byte
		previewMode os.FileMode
		actualData  []byte
		actualMode  os.FileMode
	}{
		{name: "digest", previewData: []byte("preview"), previewMode: 0o600, actualData: []byte("changed"), actualMode: 0o600},
		{name: "mode", previewData: []byte("same"), previewMode: 0o640, actualData: []byte("same"), actualMode: 0o600},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := applyTestStore(t)
			root := t.TempDir()
			path := filepath.Join(root, "file")
			writeApplyFile(t, path, test.actualData, test.actualMode)
			entry, postimage := applyEntry("file", PreviewChange, []byte("wanted"), 0o600, test.previewData, test.previewMode)
			err := Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage}))
			assert.ErrorIs(t, err, ErrPreconditionChanged)
			actual, readErr := os.ReadFile(path)
			require.NoError(t, readErr)
			assert.Equal(t, test.actualData, actual)
			assert.Empty(t, journalEntriesFor(t, store))
		})
	}
}

func TestApplyStopsAfterFailingEntryAndPreservesUnpreviewedFiles(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	writeApplyFile(t, filepath.Join(root, "a"), []byte("old-a"), 0o600)
	writeApplyFile(t, filepath.Join(root, "b"), []byte("old-b"), 0o600)
	writeApplyFile(t, filepath.Join(root, "unpreviewed"), []byte("keep"), 0o600)
	a, postA := applyEntry("a", PreviewChange, []byte("new-a"), 0o600, []byte("old-a"), 0o600)
	b, postB := applyEntry("b", PreviewChange, []byte("new-b"), 0o600, []byte("old-b"), 0o600)
	filesystem := &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: "rename", destination: "a"}
	request := applyRequest(root, []PreviewEntry{a, b}, []Postimage{postA, postB})
	request.FileSystem = filesystem
	err := Apply(context.Background(), store, request)
	require.Error(t, err)
	assert.Equal(t, []byte("old-a"), readApplyFile(t, filepath.Join(root, "a")))
	assert.Equal(t, []byte("old-b"), readApplyFile(t, filepath.Join(root, "b")))
	assert.Equal(t, []byte("keep"), readApplyFile(t, filepath.Join(root, "unpreviewed")))
	entries := journalEntriesFor(t, store)
	require.Len(t, entries, 1)
	assert.Equal(t, "failed", entries[0].State)
	assert.Equal(t, state.JournalStageRename, entries[0].Stage)
	backup, err := store.Payload(entries[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("old-a"), backup)
}

func TestApplyLeavesPendingJournalAcrossCrashBoundaries(t *testing.T) {
	t.Run("journal before write", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
		entry, postimage := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
		request := applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})
		request.FileSystem = &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: "crash-before-write"}
		assert.Panics(t, func() { _ = Apply(context.Background(), store, request) })
		assert.Equal(t, []byte("old"), readApplyFile(t, filepath.Join(root, "file")))
		entries := journalEntriesFor(t, store)
		require.Len(t, entries, 1)
		assert.Equal(t, "pending", entries[0].State)
		assert.Equal(t, state.JournalStagePending, entries[0].Stage)
		report, err := RecoverInterrupted(context.Background(), store, nil, request.Now)
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "failed", report.Entries[0].Outcome)
		assert.Equal(t, []byte("old"), readApplyFile(t, filepath.Join(root, "file")))
		report, err = RecoverInterrupted(context.Background(), store, nil, request.Now)
		require.NoError(t, err)
		assert.Empty(t, report.Entries)
	})

	t.Run("mid-write", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
		entry, postimage := applyEntry("file", PreviewChange, []byte("new data"), 0o600, []byte("old"), 0o600)
		request := applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})
		request.FileSystem = &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: "crash-mid-write"}
		assert.Panics(t, func() { _ = Apply(context.Background(), store, request) })
		assert.Equal(t, []byte("old"), readApplyFile(t, filepath.Join(root, "file")))
		entries := journalEntriesFor(t, store)
		require.Len(t, entries, 1)
		assert.Equal(t, "pending", entries[0].State)
		report, err := RecoverInterrupted(context.Background(), store, nil, request.Now)
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "failed", report.Entries[0].Outcome)
	})

	t.Run("write before readback", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
		entry, postimage := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
		request := applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})
		request.FileSystem = &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: "crash-before-readback"}
		assert.Panics(t, func() { _ = Apply(context.Background(), store, request) })
		assert.Equal(t, []byte("new"), readApplyFile(t, filepath.Join(root, "file")))
		entries := journalEntriesFor(t, store)
		require.Len(t, entries, 1)
		assert.Equal(t, "pending", entries[0].State)
		backup, err := store.Payload(entries[0].BackupRef)
		require.NoError(t, err)
		assert.Equal(t, []byte("old"), backup)
		report, err := RecoverInterrupted(context.Background(), store, nil, request.Now)
		require.NoError(t, err)
		require.Len(t, report.Entries, 1)
		assert.Equal(t, "indeterminate", report.Entries[0].Outcome)
		entries = journalEntriesFor(t, store)
		assert.Equal(t, "indeterminate", entries[0].State)
		assert.NotEmpty(t, entries[0].BackupRef)
		report, err = RecoverInterrupted(context.Background(), store, nil, request.Now)
		require.NoError(t, err)
		assert.Empty(t, report.Entries)
	})
}

func TestApplyFaultsKeepDestinationWholeAndJournalRecoverable(t *testing.T) {
	for _, fault := range []string{"partial-write", "disk-full", "permission-denied", "rename", "sync-directory"} {
		t.Run(fault, func(t *testing.T) {
			store := applyTestStore(t)
			root := t.TempDir()
			path := filepath.Join(root, "file")
			writeApplyFile(t, path, []byte("original"), 0o600)
			entry, postimage := applyEntry("file", PreviewChange, []byte("replacement"), 0o600, []byte("original"), 0o600)
			request := applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage})
			request.FileSystem = &faultApplyFS{base: files.DefaultApplyFileSystem(), fault: fault}
			err := Apply(context.Background(), store, request)
			require.Error(t, err)
			expectedData := []byte("original")
			if fault == "sync-directory" {
				expectedData = []byte("replacement")
			}
			assert.Equal(t, expectedData, readApplyFile(t, path))
			entries := journalEntriesFor(t, store)
			require.Len(t, entries, 1)
			expectedState := "failed"
			if fault == "sync-directory" {
				expectedState = "indeterminate"
			}
			assert.Equal(t, expectedState, entries[0].State)
			assert.NotEmpty(t, entries[0].Stage)
			backup, err := store.Payload(entries[0].BackupRef)
			require.NoError(t, err)
			assert.Equal(t, []byte("original"), backup)
		})
	}
}

func TestApplyRefusesDirectoriesRootDeletionAndCapturedMode(t *testing.T) {
	t.Run("directory delete", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		directory := filepath.Join(root, "dir")
		require.NoError(t, os.Mkdir(directory, 0o700))
		emptyDigest := sha256.Sum256(nil)
		entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "dir"}, Action: PreviewDelete, DecisionAction: ActionDeleteLocal, Preimage: &PreviewPreimage{Digest: fmtDigest(emptyDigest[:]), Mode: 0}}
		err := Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, nil))
		require.Error(t, err)
		info, statErr := os.Stat(directory)
		require.NoError(t, statErr)
		assert.True(t, info.IsDir())
		assert.Empty(t, journalEntriesFor(t, store))
	})

	t.Run("root delete", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		emptyDigest := sha256.Sum256(nil)
		entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "."}, Action: PreviewDelete, DecisionAction: ActionDeleteLocal, Preimage: &PreviewPreimage{Digest: fmtDigest(emptyDigest[:]), Mode: 0}}
		err := Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, nil))
		require.Error(t, err)
		assert.Empty(t, journalEntriesFor(t, store))
	})

	t.Run("captured mode mismatch", func(t *testing.T) {
		store := applyTestStore(t)
		root := t.TempDir()
		entry, postimage := applyEntry("new", PreviewCreate, []byte("data"), 0o644, nil, 0)
		err := Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage}))
		require.Error(t, err)
		assert.Empty(t, journalEntriesFor(t, store))
		_, statErr := os.Stat(filepath.Join(root, "new"))
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	})
}

func TestApplyDeletesOnlyPreviewedFileAndNeverDirectory(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	path := filepath.Join(root, "remove")
	writeApplyFile(t, path, []byte("remove"), 0o600)
	writeApplyFile(t, filepath.Join(root, "unpreviewed"), []byte("keep"), 0o600)
	entry := PreviewEntry{
		Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "remove"}, Action: PreviewDelete, DecisionAction: ActionDeleteLocal,
		Preimage: &PreviewPreimage{Digest: digestHex([]byte("remove")), Mode: 0o600},
	}
	err := Apply(context.Background(), store, applyRequest(root, []PreviewEntry{entry}, nil))
	require.NoError(t, err)
	_, err = os.Stat(path)
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Equal(t, []byte("keep"), readApplyFile(t, filepath.Join(root, "unpreviewed")))
	info, err := os.Stat(root)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	journal := journalEntriesFor(t, store)
	require.Len(t, journal, 1)
	assert.Equal(t, "applied", journal[0].State)
	assert.NotEmpty(t, journal[0].BackupRef)
	backup, err := store.Payload(journal[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("remove"), backup)
}

func TestApplyRequiresExactPostimageSetAndRejectsSettings(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	entry, postimage := applyEntry("file", PreviewCreate, []byte("data"), 0o600, nil, 0)
	request := applyRequest(root, []PreviewEntry{entry}, nil)
	assert.Error(t, Apply(context.Background(), store, request))
	request = applyRequest(root, []PreviewEntry{entry}, []Postimage{postimage, {TargetID: "target", Key: "extra"}})
	assert.Error(t, Apply(context.Background(), store, request))
	setting := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceGNOME, SchemaID: "org.example", SettingsPath: "/", SettingKey: "enabled"}, Action: PreviewChange, DecisionAction: ActionDownload}
	assert.Error(t, Apply(context.Background(), store, applyRequest(root, []PreviewEntry{setting}, nil)))
	assert.Empty(t, journalEntriesFor(t, store))
}

func readApplyFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

type faultApplyFS struct {
	base        files.ApplyFileSystem
	fault       string
	destination string
	destReads   int
	entryLstats int
}

type faultApplyRoot struct {
	base files.ApplyRoot
	fs   *faultApplyFS
}

type faultApplyFile struct {
	files.ApplyFile
	fs        *faultApplyFS
	directory bool
}

func (f *faultApplyFS) Lstat(path string) (os.FileInfo, error) {
	return f.base.Lstat(path)
}

func (f *faultApplyFS) OpenRoot(path string) (files.ApplyRoot, error) {
	root, err := f.base.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &faultApplyRoot{base: root, fs: f}, nil
}

func (r *faultApplyRoot) Lstat(name string) (os.FileInfo, error) {
	if r.fs.fault == "crash-before-write" && name == "file" {
		r.fs.entryLstats++
		if r.fs.entryLstats == 5 {
			panic("crash before filesystem act")
		}
	}
	return r.base.Lstat(name)
}

func (r *faultApplyRoot) OpenFile(name string, flag int, mode os.FileMode) (files.ApplyFile, error) {
	if strings.Contains(filepath.Base(name), ".dottie-") {
		switch r.fs.fault {
		case "permission-denied":
			return nil, syscall.EACCES
		}
		file, err := r.base.OpenFile(name, flag, mode)
		if err != nil {
			return nil, err
		}
		return &faultApplyFile{ApplyFile: file, fs: r.fs}, nil
	}
	if r.fs.fault == "crash-before-readback" && name == "file" && flag&os.O_WRONLY == 0 {
		r.fs.destReads++
		if r.fs.destReads == 5 {
			panic("crash before read-back")
		}
	}
	if r.fs.fault == "sync-directory" && flag&syscall.O_DIRECTORY != 0 {
		file, err := r.base.OpenFile(name, flag, mode)
		if err != nil {
			return nil, err
		}
		return &faultApplyFile{ApplyFile: file, fs: r.fs, directory: true}, nil
	}
	return r.base.OpenFile(name, flag, mode)
}

func (r *faultApplyRoot) Rename(oldName, newName string) error {
	if r.fs.fault == "rename" && (r.fs.destination == "" || filepath.Base(newName) == r.fs.destination) {
		return syscall.EXDEV
	}
	return r.base.Rename(oldName, newName)
}

func (r *faultApplyRoot) Remove(name string) error { return r.base.Remove(name) }
func (r *faultApplyRoot) Close() error             { return r.base.Close() }

func (f *faultApplyFile) Write(data []byte) (int, error) {
	switch f.fs.fault {
	case "crash-mid-write":
		panic("crash during temporary-file write")
	case "partial-write":
		count := len(data) / 2
		if count == 0 {
			count = 1
		}
		if count > len(data) {
			count = len(data)
		}
		_, err := f.ApplyFile.Write(data[:count])
		if err != nil {
			return 0, err
		}
		return count, io.ErrShortWrite
	case "disk-full":
		count := len(data) / 2
		if count > 0 {
			_, _ = f.ApplyFile.Write(data[:count])
		}
		return count, syscall.ENOSPC
	}
	return f.ApplyFile.Write(data)
}

func (f *faultApplyFile) Sync() error {
	if f.fs.fault == "sync-directory" && f.directory {
		return syscall.EIO
	}
	return f.ApplyFile.Sync()
}

type fakeSettingsBackend struct {
	values            map[model.EntryKey]SettingValue
	locked            bool
	observeErrors     map[int]error
	canonicalizeError error
	setError          error
	resetError        error
	observeCalls      int
	writeCount        int
	canonicalize      func(string, string) (string, string)
	observeHook       func(int, model.EntryKey)
	beforeSet         func()
}

func newFakeSettingsBackend() *fakeSettingsBackend {
	return &fakeSettingsBackend{values: make(map[model.EntryKey]SettingValue), observeErrors: make(map[int]error)}
}

func (b *fakeSettingsBackend) Observe(ctx context.Context, key model.EntryKey) (SettingValue, error) {
	if err := ctx.Err(); err != nil {
		return SettingValue{}, err
	}
	b.observeCalls++
	if b.observeHook != nil {
		b.observeHook(b.observeCalls, key)
	}
	if err := b.observeErrors[b.observeCalls]; err != nil {
		return SettingValue{}, err
	}
	value, exists := b.values[key]
	if !exists {
		for candidate, candidateValue := range b.values {
			if candidate.SchemaID == key.SchemaID && candidate.SettingsPath == key.SettingsPath && candidate.SettingKey == key.SettingKey {
				value = candidateValue
				exists = true
				break
			}
		}
	}
	value.Writable = !b.locked
	if !exists {
		return SettingValue{Writable: !b.locked}, nil
	}
	return value, nil
}

func (b *fakeSettingsBackend) Canonicalize(ctx context.Context, key model.EntryKey, valueType, text string) (SettingValue, error) {
	if err := ctx.Err(); err != nil {
		return SettingValue{}, err
	}
	if b.canonicalizeError != nil {
		return SettingValue{}, b.canonicalizeError
	}
	if b.canonicalize != nil {
		valueType, text = b.canonicalize(valueType, text)
	}
	return SettingValue{Present: true, Type: valueType, Text: text, Writable: !b.locked}, nil
}

func (b *fakeSettingsBackend) Set(ctx context.Context, key model.EntryKey, valueType, text string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.beforeSet != nil {
		b.beforeSet()
	}
	if b.setError != nil {
		return b.setError
	}
	if b.locked {
		return errors.New("setting is locked")
	}
	b.setNative(key, SettingValue{Present: true, Type: valueType, Text: text})
	b.writeCount++
	return nil
}

func (b *fakeSettingsBackend) Reset(ctx context.Context, key model.EntryKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.resetError != nil {
		return b.resetError
	}
	if b.locked {
		return errors.New("setting is locked")
	}
	b.setNative(key, SettingValue{})
	b.writeCount++
	return nil
}

func (b *fakeSettingsBackend) setNative(key model.EntryKey, value SettingValue) {
	found := false
	for candidate := range b.values {
		if candidate.SchemaID == key.SchemaID && candidate.SettingsPath == key.SettingsPath && candidate.SettingKey == key.SettingKey {
			b.values[candidate] = value
			found = true
		}
	}
	if !found {
		b.values[key] = value
	}
}

func settingTestKey(targetID string) model.EntryKey {
	return model.EntryKey{TargetID: targetID, Source: model.SourceGNOME, SchemaID: "org.example.Settings", SettingsPath: "/", SettingKey: "enabled"}
}

func settingTestEntry(key model.EntryKey, before *SettingValue) PreviewEntry {
	entry := PreviewEntry{Key: key, Action: PreviewCreate, DecisionAction: ActionDownload, State: PreviewStateMissing}
	if before != nil {
		entry.Action = PreviewChange
		entry.State = ""
		payload := []byte{}
		if before.Present {
			payload = []byte(before.Type + "\x00" + before.Text)
		}
		digest := sha256.Sum256(payload)
		entry.Preimage = &PreviewPreimage{Digest: fmtDigest(digest[:])}
	}
	return entry
}

func settingTestPostimage(key model.EntryKey, state model.SettingState, valueType, text string) SettingPostimage {
	postimage := SettingPostimage{TargetID: key.TargetID, SchemaID: key.SchemaID, SettingsPath: key.SettingsPath, SettingKey: key.SettingKey, State: state}
	if state == model.SettingPresent {
		postimage.Value = &model.VariantValue{Type: valueType, Text: text}
	}
	return postimage
}

func settingApplyRequest(key model.EntryKey, entry PreviewEntry, postimages []SettingPostimage, backend SettingsBackend) ApplyRequest {
	return ApplyRequest{
		Preview:  Preview{Targets: []PreviewTarget{{ID: key.TargetID, Entries: []PreviewEntry{entry}}}, Complete: true},
		Settings: backend, SettingPostimages: postimages, Now: func() time.Time { return time.Unix(100, 0) },
	}
}

func appendSettingJournal(t *testing.T, store *state.Store, id string, key model.EntryKey, preState model.SettingState, preType, preText string, postState model.SettingState, postType, postText string, stateName string, createdAt int64) state.JournalEntry {
	t.Helper()
	preimage := state.NewSettingFingerprint(preState, preType, preText)
	postimage := state.NewSettingFingerprint(postState, postType, postText)
	backup := []byte{}
	if preState == model.SettingPresent {
		backup = []byte(preType + "\x00" + preText)
	}
	operation := "setting-set"
	if postState == model.SettingReset {
		operation = "setting-reset"
	}
	entry, err := store.AppendJournal(context.Background(), state.JournalEntry{
		ID: id, Operation: operation, State: "pending", Stage: state.JournalStagePending,
		Identity: key, Preimage: preimage, Postimage: postimage, CreatedAt: createdAt,
	}, backup)
	require.NoError(t, err)
	if stateName == "applied" {
		require.NoError(t, store.TransitionJournalEntry(context.Background(), id, "pending", "applied", state.JournalStageVerified))
	}
	return entry
}

func TestApplyCancellationAfterCompletedEntryReportsPrefix(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	first, firstPost := applyEntry("first.txt", PreviewCreate, []byte("first"), 0o600, nil, 0)
	second, secondPost := applyEntry("second.txt", PreviewCreate, []byte("second"), 0o600, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	previous := applyBetweenOperations
	applyBetweenOperations = func(applied int) {
		if applied == 1 {
			cancel()
		}
	}
	t.Cleanup(func() { applyBetweenOperations = previous })
	err := Apply(ctx, store, applyRequest(root, []PreviewEntry{first, second}, []Postimage{firstPost, secondPost}))
	var partial *PartialApplyError
	require.ErrorAs(t, err, &partial)
	assert.ErrorIs(t, err, context.Canceled)
	require.Len(t, partial.Applied, 1)
	assert.Equal(t, "first.txt", partial.Applied[0].FilePath)
	assert.Equal(t, "second.txt", partial.Failed.Key.FilePath)
}

func TestApplyMixedCancellationReportsAppliedPrefix(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	fileEntry, filePost := applyEntry("file.txt", PreviewCreate, []byte("data"), 0o600, nil, 0)
	settingKey := settingTestKey("settings")
	backend := newFakeSettingsBackend()
	backend.values[settingKey] = SettingValue{Present: true, Type: "s", Text: "before"}
	before := backend.values[settingKey]
	settingEntry := settingTestEntry(settingKey, &before)
	postimage := settingTestPostimage(settingKey, model.SettingPresent, "s", "after")
	backend.observeErrors[1] = context.Canceled
	request := ApplyRequest{
		Preview: Preview{Targets: []PreviewTarget{
			{ID: "target", Entries: []PreviewEntry{fileEntry}},
			{ID: "settings", Entries: []PreviewEntry{settingEntry}},
		}, Complete: true},
		Roots: map[string]string{"target": root}, ModePolicy: ModePolicy{Default: 0o600}, Content: []Postimage{filePost},
		Settings: backend, SettingPostimages: []SettingPostimage{postimage}, Now: func() time.Time { return time.Unix(100, 0) },
	}
	err := Apply(context.Background(), store, request)
	var partial *PartialApplyError
	require.ErrorAs(t, err, &partial)
	assert.ErrorIs(t, err, context.Canceled)
	require.Len(t, partial.Applied, 1)
	assert.Equal(t, "target", partial.Applied[0].TargetID)
	assert.Equal(t, settingKey, partial.Failed.Key)
	assert.Equal(t, []byte("data"), readApplyFile(t, filepath.Join(root, "file.txt")))
}

func TestApplySettingsPresentResetAndRollbackInputs(t *testing.T) {
	for _, test := range []struct {
		name       string
		before     SettingValue
		postState  model.SettingState
		postType   string
		postText   string
		wantAbsent bool
	}{
		{name: "present", before: SettingValue{Present: true, Type: "s", Text: "before"}, postState: model.SettingPresent, postType: "b", postText: "true"},
		{name: "reset", before: SettingValue{Present: true, Type: "b", Text: "true"}, postState: model.SettingReset, wantAbsent: true},
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
			current, err := backend.Observe(context.Background(), key)
			require.NoError(t, err)
			assert.Equal(t, !test.wantAbsent, current.Present)
			if !test.wantAbsent {
				assert.Equal(t, test.postType, current.Type)
				assert.Equal(t, test.postText, current.Text)
			}
			rows, err := store.JournalEntries(context.Background(), key.TargetID)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			assert.Equal(t, key, rows[0].Identity)
			assert.Equal(t, "applied", rows[0].State)
			if test.before.Present {
				assert.Equal(t, state.NewSettingFingerprint(model.SettingPresent, test.before.Type, test.before.Text), rows[0].Preimage)
			} else {
				assert.Equal(t, state.NewSettingFingerprint(model.SettingReset, "", ""), rows[0].Preimage)
			}
			assert.Equal(t, state.NewSettingFingerprint(test.postState, test.postType, test.postText), rows[0].Postimage)
			assert.NotEmpty(t, rows[0].BackupRef)
			backup, err := store.Payload(rows[0].BackupRef)
			require.NoError(t, err)
			assert.Equal(t, []byte(test.before.Type+"\x00"+test.before.Text), backup)
		})
	}
}

func TestApplySettingsPreconditionsAndValidationDoNotWrite(t *testing.T) {
	for _, test := range []struct {
		name    string
		setup   func(*fakeSettingsBackend)
		wantErr error
	}{
		{name: "precondition", setup: func(backend *fakeSettingsBackend) {
			backend.values[settingTestKey("settings")] = SettingValue{Present: true, Type: "s", Text: "changed"}
		}, wantErr: ErrPreconditionChanged},
		{name: "post-journal precondition", setup: func(backend *fakeSettingsBackend) {
			backend.observeHook = func(call int, key model.EntryKey) {
				if call == 2 {
					backend.setNative(key, SettingValue{Present: true, Type: "s", Text: "changed"})
				}
			}
		}},
		{name: "locked", setup: func(backend *fakeSettingsBackend) { backend.locked = true }},
		{name: "missing schema or key", setup: func(backend *fakeSettingsBackend) { backend.observeErrors[1] = errors.New("key missing") }},
		{name: "wrong type", setup: func(backend *fakeSettingsBackend) { backend.canonicalizeError = errors.New("type mismatch") }},
		{name: "set failure", setup: func(backend *fakeSettingsBackend) { backend.setError = errors.New("write failed") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := applyTestStore(t)
			key := settingTestKey("settings")
			backend := newFakeSettingsBackend()
			backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
			test.setup(backend)
			before := SettingValue{Present: true, Type: "s", Text: "before"}
			entry := settingTestEntry(key, &before)
			postimage := settingTestPostimage(key, model.SettingPresent, "b", "true")
			err := Apply(context.Background(), store, settingApplyRequest(key, entry, []SettingPostimage{postimage}, backend))
			if test.wantErr != nil {
				assert.ErrorIs(t, err, test.wantErr)
			} else {
				assert.Error(t, err)
			}
			assert.Zero(t, backend.writeCount)
			rows, readErr := store.JournalEntries(context.Background(), key.TargetID)
			require.NoError(t, readErr)
			if test.name == "set failure" {
				require.Len(t, rows, 1)
				assert.Equal(t, "failed", rows[0].State)
			} else if test.name == "post-journal precondition" {
				require.Len(t, rows, 1)
				assert.Equal(t, "indeterminate", rows[0].State)
			} else {
				assert.Empty(t, rows)
			}
		})
	}
}

func TestApplySettingsRequiresExactPostimages(t *testing.T) {
	store := applyTestStore(t)
	key := settingTestKey("settings")
	backend := newFakeSettingsBackend()
	backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
	before := backend.values[key]
	entry := settingTestEntry(key, &before)
	postimage := settingTestPostimage(key, model.SettingPresent, "b", "true")
	request := settingApplyRequest(key, entry, nil, backend)
	assert.Error(t, Apply(context.Background(), store, request))
	request.SettingPostimages = []SettingPostimage{postimage, postimage}
	assert.Error(t, Apply(context.Background(), store, request))
	request.SettingPostimages = []SettingPostimage{postimage, settingTestPostimage(settingTestKey("settings-alias"), model.SettingReset, "", "")}
	assert.Error(t, Apply(context.Background(), store, request))
	request.SettingPostimages = []SettingPostimage{postimage}
	request.Settings = nil
	assert.Error(t, Apply(context.Background(), store, request))
	entry.Action = PreviewDelete
	entry.DecisionAction = ActionDeleteLocal
	request = settingApplyRequest(key, entry, []SettingPostimage{settingTestPostimage(key, model.SettingReset, "", "")}, backend)
	assert.Error(t, Apply(context.Background(), store, request))
	assert.Zero(t, backend.writeCount)
	rows, err := store.JournalEntries(context.Background(), key.TargetID)
	require.NoError(t, err)
	assert.Empty(t, rows)
}

func TestApplySettingsCanonicalReadbackAndRollbackPrunesBackup(t *testing.T) {
	store := applyTestStore(t)
	key := settingTestKey("settings")
	backend := newFakeSettingsBackend()
	backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
	backend.canonicalize = func(valueType, text string) (string, string) { return valueType, strings.TrimSpace(text) }
	before := backend.values[key]
	entry := settingTestEntry(key, &before)
	postimage := settingTestPostimage(key, model.SettingPresent, "s", " after ")
	require.NoError(t, Apply(context.Background(), store, settingApplyRequest(key, entry, []SettingPostimage{postimage}, backend)))
	assert.Equal(t, "after", mustObserveSetting(t, backend, key).Text)
	rows, err := store.JournalEntries(context.Background(), key.TargetID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "after", rows[0].Postimage.ValueText)
	backup, err := store.Payload(rows[0].BackupRef)
	require.NoError(t, err)
	assert.Equal(t, []byte("s\x00before"), backup)
	report, err := RollbackAppliedWithSettings(context.Background(), store, nil, backend, func() time.Time { return time.Unix(100, 0) })
	require.NoError(t, err)
	require.Len(t, report.Entries, 1)
	assert.Equal(t, "rolled-back", report.Entries[0].Outcome)
	assert.Equal(t, "before", mustObserveSetting(t, backend, key).Text)
	rows, err = store.JournalEntries(context.Background(), key.TargetID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Empty(t, rows[0].BackupRef)
	assert.Empty(t, rows[0].Preimage.ValueType)
	assert.Empty(t, rows[0].Preimage.ValueText)
	assert.Empty(t, rows[0].Postimage.ValueType)
	assert.Empty(t, rows[0].Postimage.ValueText)
}

func TestApplySettingsCanonicalizesAndReportsMixedPartialFailure(t *testing.T) {
	store := applyTestStore(t)
	root := t.TempDir()
	writeApplyFile(t, filepath.Join(root, "file"), []byte("old"), 0o600)
	fileEntry, filePost := applyEntry("file", PreviewChange, []byte("new"), 0o600, []byte("old"), 0o600)
	key := settingTestKey("settings")
	backend := newFakeSettingsBackend()
	backend.values[key] = SettingValue{Present: true, Type: "s", Text: "before"}
	backend.canonicalize = func(valueType, text string) (string, string) { return valueType, strings.TrimSpace(text) }
	backend.setError = errors.New("backend refused write")
	before := backend.values[key]
	settingEntry := settingTestEntry(key, &before)
	postimage := settingTestPostimage(key, model.SettingPresent, "s", " after ")
	request := ApplyRequest{
		Preview: Preview{Targets: []PreviewTarget{
			{ID: "target", Entries: []PreviewEntry{fileEntry}},
			{ID: "settings", Entries: []PreviewEntry{settingEntry}},
		}, Complete: true},
		Roots: map[string]string{"target": root}, ModePolicy: ModePolicy{Default: 0o600}, Content: []Postimage{filePost},
		Settings: backend, SettingPostimages: []SettingPostimage{postimage}, Now: func() time.Time { return time.Unix(100, 0) },
	}
	err := Apply(context.Background(), store, request)
	var partial *PartialApplyError
	require.ErrorAs(t, err, &partial)
	assert.Len(t, partial.Applied, 1)
	assert.Equal(t, fileEntry.Key, partial.Applied[0].Key)
	assert.Equal(t, settingEntry.Key, partial.Failed.Key)
	assert.Equal(t, "failed", partial.Failed.Outcome)
	assert.ErrorIs(t, err, backend.setError)
	assert.Equal(t, []byte("new"), readApplyFile(t, filepath.Join(root, "file")))
	rows, err := store.JournalEntries(context.Background(), "settings")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "after", rows[0].Postimage.ValueText)
	assert.Equal(t, SettingValue{Present: true, Type: "s", Text: "before", Writable: true}, mustObserveSetting(t, backend, key))
}

func mustObserveSetting(t *testing.T, backend SettingsBackend, key model.EntryKey) SettingValue {
	t.Helper()
	value, err := backend.Observe(context.Background(), key)
	require.NoError(t, err)
	return value
}
