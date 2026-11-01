package files

import (
	"crypto/sha256"
	"encoding/hex"
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

	require.NoError(t, ReplaceFile(filesystem, root, "file", []byte("after"), 0o600))
	observed, err = ObserveFile(filesystem, root, "file")
	require.NoError(t, err)
	assert.Equal(t, []byte("after"), observed.Data)
	assert.Equal(t, uint32(0o600), observed.Mode)
	require.NoError(t, DeleteFile(filesystem, root, "file"))
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
	err := DeleteFile(filesystem, root, "directory")
	var unsupported *UnsupportedPathError
	require.ErrorAs(t, err, &unsupported)
	info, err := os.Stat(directory)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Error(t, ReplaceFile(filesystem, root, ".", []byte("root"), 0o600))
	assert.Error(t, DeleteFile(filesystem, root, "."))
	assert.Error(t, ReplaceFile(filesystem, root, "../escape", []byte("escape"), 0o600))

	real := filepath.Join(root, "real")
	require.NoError(t, os.Mkdir(real, 0o700))
	write := filepath.Join(real, "file")
	require.NoError(t, os.WriteFile(write, []byte("keep"), 0o600))
	require.NoError(t, os.Symlink(real, filepath.Join(root, "link")))
	err = ReplaceFile(filesystem, root, "link/file", []byte("outside"), 0o600)
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, []byte("keep"), readFileForApplyTest(t, write))
}

func TestApplyFilesystemSupportsSingleFileSelectionRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "selected")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o600))
	require.NoError(t, ReplaceFile(DefaultApplyFileSystem(), path, ".", []byte("after"), 0o600))
	assert.Equal(t, []byte("after"), readFileForApplyTest(t, path))
}

func readFileForApplyTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func TestApplyFilesystemDoesNotFallbackAfterRenameError(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(path, []byte("before"), 0o600))
	filesystem := &renameFailureFS{base: DefaultApplyFileSystem()}
	err := ReplaceFile(filesystem, root, "file", []byte("after"), 0o600)
	require.Error(t, err)
	var applyError *ApplyError
	require.ErrorAs(t, err, &applyError)
	assert.Equal(t, ApplyStageRename, applyError.Stage)
	assert.ErrorIs(t, err, syscallEXDEV)
	assert.Equal(t, []byte("before"), readFileForApplyTest(t, path))
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
