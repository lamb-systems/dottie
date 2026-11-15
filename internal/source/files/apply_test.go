package files

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObserveReplaceAndDeleteRegularFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o640))
	require.NoError(t, os.Chmod(path, 0o640))
	filesystem := DefaultApplyFileSystem()
	observed, err := ObserveFile(filesystem, root, "file")
	require.NoError(t, err)
	require.True(t, observed.Exists)
	assert.Equal(t, []byte("before"), observed.Data)
	digest := sha256.Sum256([]byte("before"))
	assert.Equal(t, hex.EncodeToString(digest[:]), observed.Digest)
	assert.Equal(t, uint32(0o640), observed.Mode)

	require.NoError(t, ReplaceFile(filesystem, root, "file", []byte("after"), 0o600, ExpectedPreimage{Exists: true, Digest: hex.EncodeToString(digest[:]), Mode: 0o640}))
	observed, err = ObserveFile(filesystem, root, "file")
	require.NoError(t, err)
	assert.Equal(t, []byte("after"), observed.Data)
	assert.Equal(t, uint32(0o600), observed.Mode)
	require.NoError(t, DeleteFile(filesystem, root, "file", ExpectedPreimage{Exists: true, Digest: applyDigestHex([]byte("after")), Mode: 0o600}))
	observed, err = ObserveFile(filesystem, root, "file")
	require.NoError(t, err)
	assert.False(t, observed.Exists)
	info, err := os.Stat(root)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestApplyFilesystemRefusesDirectoriesLinksAndRootDeletes(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "directory")
	require.NoError(t, os.Mkdir(directory, 0o700))
	filesystem := DefaultApplyFileSystem()
	err := DeleteFile(filesystem, root, "directory", ExpectedPreimage{})
	var precondition *PreconditionError
	require.ErrorAs(t, err, &precondition)
	info, err := os.Stat(directory)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Error(t, ReplaceFile(filesystem, root, ".", []byte("root"), 0o600, ExpectedPreimage{}))
	assert.Error(t, DeleteFile(filesystem, root, ".", ExpectedPreimage{}))
	assert.Error(t, ReplaceFile(filesystem, root, "../escape", []byte("escape"), 0o600, ExpectedPreimage{}))

	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0o700))
	write := filepath.Join(real, "file")
	require.NoError(t, os.WriteFile(write, []byte("keep"), 0o600))
	require.NoError(t, os.Symlink(real, filepath.Join(root, "link")))
	err = ReplaceFile(filesystem, root, "link/file", []byte("outside"), 0o600, ExpectedPreimage{})
	var unsupported *UnsupportedPathError
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, []byte("keep"), readFileForApplyTest(t, write))
}

func TestApplyFilesystemSupportsSingleFileSelectionRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o600))
	require.NoError(t, ReplaceFile(DefaultApplyFileSystem(), path, ".", []byte("after"), 0o600, ExpectedPreimage{Exists: true, Digest: applyDigestHex([]byte("before")), Mode: 0o600}))
	assert.Equal(t, []byte("after"), readFileForApplyTest(t, path))
}

func TestObserveFileBoundedStopsReadingAtTheLimit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	require.NoError(t, os.Truncate(path, 4096))
	counter := &countingApplyFileSystem{ApplyFileSystem: DefaultApplyFileSystem()}

	_, err := ObserveFileBounded(counter, root, "file", 1024)
	var oversized *ObservationLimitError
	require.ErrorAs(t, err, &oversized)
	assert.Equal(t, "file", oversized.Path)
	assert.Equal(t, int64(1024), oversized.Limit)
	assert.Equal(t, int64(1025), counter.read)

	counter.read = 0
	observed, err := ObserveFileBounded(counter, root, "file", 4096)
	require.NoError(t, err)
	require.True(t, observed.Exists)
	assert.Equal(t, 4096, len(observed.Data))
	assert.Equal(t, int64(4096), counter.read)

	counter.read = 0
	observed, err = ObserveFile(counter, root, "file")
	require.NoError(t, err)
	assert.Equal(t, 4096, len(observed.Data))
	assert.Equal(t, int64(4096), counter.read)
}

func TestObserveFileBoundedRefusesGrowthDuringTheRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	require.NoError(t, os.Truncate(path, 4096))
	counter := &countingApplyFileSystem{ApplyFileSystem: DefaultApplyFileSystem(), growth: 1 << 16}

	_, err := ObserveFileBounded(counter, root, "file", 4096)
	var oversized *ObservationLimitError
	require.ErrorAs(t, err, &oversized)
	assert.Equal(t, int64(4096), oversized.Limit)
	assert.Equal(t, int64(4097), counter.read)
}

type countingApplyFileSystem struct {
	ApplyFileSystem
	growth    int
	read      int64
	requested int
}

type countingApplyRoot struct {
	ApplyRoot
	filesystem *countingApplyFileSystem
}

type countingApplyFile struct {
	ApplyFile
	growth     int
	filesystem *countingApplyFileSystem
}

func (f *countingApplyFileSystem) OpenRoot(path string) (ApplyRoot, error) {
	root, err := f.ApplyFileSystem.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &countingApplyRoot{ApplyRoot: root, filesystem: f}, nil
}

func (r *countingApplyRoot) OpenFile(name string, flag int, mode os.FileMode) (ApplyFile, error) {
	file, err := r.ApplyRoot.OpenFile(name, flag, mode)
	if err != nil {
		return nil, err
	}
	return &countingApplyFile{ApplyFile: file, growth: r.filesystem.growth, filesystem: r.filesystem}, nil
}

func (f *countingApplyFile) Read(buffer []byte) (int, error) {
	if len(buffer) > f.filesystem.requested {
		f.filesystem.requested = len(buffer)
	}
	read, err := f.ApplyFile.Read(buffer)
	f.filesystem.read += int64(read)
	if !errors.Is(err, io.EOF) {
		return read, err
	}
	if f.growth == 0 {
		return read, err
	}
	extra := f.growth
	if extra > len(buffer) {
		extra = len(buffer)
	}
	for index := 0; index < extra; index++ {
		buffer[index] = 'g'
	}
	f.growth -= extra
	f.filesystem.read += int64(extra)
	return extra, nil
}

func applyDigestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func readFileForApplyTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func TestReplaceFileRechecksExpectedPreimageAfterSync(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o600))
	filesystem := &preimageRaceFS{base: DefaultApplyFileSystem(), path: path, when: "sync", replacement: []byte("editor save")}
	err := ReplaceFile(filesystem, root, "file", []byte("dottie bytes"), 0o600, ExpectedPreimage{Exists: true, Digest: applyDigestHex([]byte("before")), Mode: 0o600})
	var precondition *PreconditionError
	require.ErrorAs(t, err, &precondition)
	assert.Equal(t, []byte("editor save"), readFileForApplyTest(t, path))
	entries, readErr := os.ReadDir(root)
	require.NoError(t, readErr)
	assert.Equal(t, []string{"file"}, []string{entries[0].Name()}, "failed precondition must clean up the staged file")
}

func TestDeleteFileRechecksExpectedPreimageBeforeRemove(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o600))
	filesystem := &preimageRaceFS{base: DefaultApplyFileSystem(), path: path, when: "lstat", replacement: []byte("editor save")}
	err := DeleteFile(filesystem, root, "file", ExpectedPreimage{Exists: true, Digest: applyDigestHex([]byte("before")), Mode: 0o600})
	var precondition *PreconditionError
	require.ErrorAs(t, err, &precondition)
	assert.Equal(t, []byte("editor save"), readFileForApplyTest(t, path))
}

func TestReplaceFileReadsAStatedPreimageSizeExactly(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	before := []byte("before")
	after := []byte("after")
	require.NoError(t, os.WriteFile(path, before, 0o600))
	counter := &countingApplyFileSystem{ApplyFileSystem: DefaultApplyFileSystem()}
	expected := ExpectedPreimage{Exists: true, Digest: applyDigestHex(before), Mode: 0o600, Size: uint64(len(before))}
	require.NoError(t, ReplaceFile(counter, root, "file", after, 0o600, expected))
	assert.Equal(t, after, readFileForApplyTest(t, path))
	assert.Equal(t, int64(len(before)), counter.read)
	assert.Equal(t, len(before)+1, counter.requested, "the read request is the stated size plus one probe byte")
}

func TestReplaceFileWithoutAStatedSizeReadsTheWholePreimage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	before := []byte("before")
	require.NoError(t, os.WriteFile(path, before, 0o600))
	counter := &countingApplyFileSystem{ApplyFileSystem: DefaultApplyFileSystem()}
	expected := ExpectedPreimage{Exists: true, Digest: applyDigestHex(before), Mode: 0o600}
	require.NoError(t, ReplaceFile(counter, root, "file", []byte("after"), 0o600, expected))
	assert.Equal(t, []byte("after"), readFileForApplyTest(t, path))
	assert.Equal(t, int64(len(before)), counter.read)
	assert.Greater(t, counter.requested, len(before)+1)
}

func TestReplaceFileRefusesAPreimageThatGrewBeyondTheStatedSize(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	before := []byte("before")
	current := []byte("before and then an editor appends more")
	require.NoError(t, os.WriteFile(path, current, 0o600))
	counter := &countingApplyFileSystem{ApplyFileSystem: DefaultApplyFileSystem()}
	expected := ExpectedPreimage{Exists: true, Digest: applyDigestHex(before), Mode: 0o600, Size: uint64(len(before))}
	err := ReplaceFile(counter, root, "file", []byte("after"), 0o600, expected)
	var precondition *PreconditionError
	require.ErrorAs(t, err, &precondition)
	assert.Equal(t, expected, precondition.Expected)
	var oversized *ObservationLimitError
	assert.NotErrorAs(t, err, &oversized)
	assert.Equal(t, int64(len(before)+1), counter.read)
	assert.Equal(t, len(before)+1, counter.requested)
	assert.Equal(t, current, readFileForApplyTest(t, path))
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "file", entries[0].Name())
}

func TestDeleteFileRefusesAPresentPreimageWithinOneStatedByte(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	current := []byte("unexpected content")
	require.NoError(t, os.WriteFile(path, current, 0o600))
	counter := &countingApplyFileSystem{ApplyFileSystem: DefaultApplyFileSystem()}
	err := DeleteFile(counter, root, "file", ExpectedPreimage{})
	var precondition *PreconditionError
	require.ErrorAs(t, err, &precondition)
	var oversized *ObservationLimitError
	assert.NotErrorAs(t, err, &oversized)
	assert.Equal(t, int64(2), counter.read, "one content byte plus one probe byte")
	assert.Equal(t, 2, counter.requested, "one content byte plus one probe byte")
	assert.Equal(t, current, readFileForApplyTest(t, path))
}

func TestApplyFilesystemDoesNotFallbackAfterRenameError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o600))
	filesystem := &renameFailureFS{base: DefaultApplyFileSystem()}
	err := ReplaceFile(filesystem, root, "file", []byte("after"), 0o600, ExpectedPreimage{Exists: true, Digest: applyDigestHex([]byte("before")), Mode: 0o600})
	require.Error(t, err)
	var applyError *ApplyError
	require.ErrorAs(t, err, &applyError)
	assert.Equal(t, ApplyStageRename, applyError.Stage)
	assert.ErrorIs(t, err, syscallEXDEV)
	assert.Equal(t, []byte("before"), readFileForApplyTest(t, path))
}

type preimageRaceFS struct {
	base        ApplyFileSystem
	path        string
	when        string
	replacement []byte
	mutated     bool
}

type preimageRaceRoot struct {
	ApplyRoot
	fs *preimageRaceFS
}

type preimageRaceFile struct {
	ApplyFile
	fs *preimageRaceFS
}

func (f *preimageRaceFS) Lstat(path string) (os.FileInfo, error) {
	return f.base.Lstat(path)
}

func (f *preimageRaceFS) OpenRoot(path string) (ApplyRoot, error) {
	root, err := f.base.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return &preimageRaceRoot{ApplyRoot: root, fs: f}, nil
}

func (r *preimageRaceRoot) Lstat(name string) (os.FileInfo, error) {
	if r.fs.when == "lstat" && name == "file" && !r.fs.mutated {
		if err := r.fs.replace(); err != nil {
			return nil, err
		}
	}
	return r.ApplyRoot.Lstat(name)
}

func (r *preimageRaceRoot) OpenFile(name string, flag int, mode os.FileMode) (ApplyFile, error) {
	file, err := r.ApplyRoot.OpenFile(name, flag, mode)
	if err != nil {
		return nil, err
	}
	if r.fs.when == "sync" && name != "file" {
		return &preimageRaceFile{ApplyFile: file, fs: r.fs}, nil
	}
	return file, nil
}

func (f *preimageRaceFile) Sync() error {
	if err := f.ApplyFile.Sync(); err != nil {
		return err
	}
	return f.fs.replace()
}

func (f *preimageRaceFS) replace() error {
	if f.mutated {
		return nil
	}
	if err := os.WriteFile(f.path, f.replacement, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(f.path, 0o600); err != nil {
		return err
	}
	f.mutated = true
	return nil
}

type renameFailureFS struct {
	base ApplyFileSystem
}

type renameFailureRoot struct {
	ApplyRoot
}

var syscallEXDEV = syscall.EXDEV

func (f *renameFailureFS) Lstat(path string) (os.FileInfo, error) {
	return f.base.Lstat(path)
}

func (f *renameFailureFS) OpenRoot(path string) (ApplyRoot, error) {
	root, err := f.base.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	return renameFailureRoot{ApplyRoot: root}, nil
}

func (r renameFailureRoot) Rename(oldName, newName string) error {
	return syscallEXDEV
}
