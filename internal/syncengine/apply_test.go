package syncengine

import (
	"context"
	"crypto/sha256"
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
	return store
}

func applyEntry(path string, action PreviewAction, data []byte, mode os.FileMode, before []byte, beforeMode os.FileMode) (PreviewEntry, Postimage) {
	entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: path}, Action: action}
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
		assert.Equal(t, "applied", report.Entries[0].Outcome)
		entries = journalEntriesFor(t, store)
		assert.Equal(t, "applied", entries[0].State)
		assert.NotEmpty(t, entries[0].BackupRef)
		report, err = RecoverInterrupted(context.Background(), store, nil, request.Now)
		require.NoError(t, err)
		assert.Empty(t, report.Entries)
	})
}

func TestApplyFaultsKeepDestinationWholeAndJournalRecoverable(t *testing.T) {
	for _, fault := range []string{"partial-write", "disk-full", "permission-denied", "rename"} {
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
			assert.Equal(t, []byte("original"), readApplyFile(t, path))
			entries := journalEntriesFor(t, store)
			require.Len(t, entries, 1)
			assert.Equal(t, "failed", entries[0].State)
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
		entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "dir"}, Action: PreviewDelete, Preimage: &PreviewPreimage{Digest: fmtDigest(emptyDigest[:]), Mode: 0}}
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
		entry := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "."}, Action: PreviewDelete, Preimage: &PreviewPreimage{Digest: fmtDigest(emptyDigest[:]), Mode: 0}}
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
		Key: model.EntryKey{TargetID: "target", Source: model.SourceFiles, FilePath: "remove"}, Action: PreviewDelete,
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
	setting := PreviewEntry{Key: model.EntryKey{TargetID: "target", Source: model.SourceGNOME, SchemaID: "org.example", SettingsPath: "/", SettingKey: "enabled"}, Action: PreviewChange}
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
	fs *faultApplyFS
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
		if r.fs.destReads == 4 {
			panic("crash before read-back")
		}
	}
	if r.fs.fault == "sync-directory" && strings.HasSuffix(name, "root") {
		file, err := r.base.OpenFile(name, flag, mode)
		if err != nil {
			return nil, err
		}
		return &faultApplyFile{ApplyFile: file, fs: r.fs}, nil
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
	if f.fs.fault == "sync-directory" {
		return syscall.EIO
	}
	return f.ApplyFile.Sync()
}
