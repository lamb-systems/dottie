package files

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dottorblaster/dottie/internal/model"
)

func captureRoot(path string, kind model.SelectionKind) Root {
	return Root{TargetID: "neovim", Path: path, Kind: kind, Budget: DefaultBudget()}
}

func restoreFaults(t *testing.T) {
	t.Helper()
	oldStat := statPath
	oldList := listDirectory
	oldRead := readFile
	oldOpen := openEntry
	oldReadLink := readLink
	t.Cleanup(func() {
		statPath = oldStat
		listDirectory = oldList
		readFile = oldRead
		openEntry = oldOpen
		readLink = oldReadLink
	})
}

func TestCaptureFixtureRoundTripAndInstallability(t *testing.T) {
	root := copyNeovimFixture(t)
	makeDirectory(t, filepath.Join(root, "empty"), 0o711)
	makeDirectory(t, filepath.Join(root, "empty", "nested"), 0o750)
	makeDirectory(t, filepath.Join(root, "bin"), 0o755)
	executable := filepath.Join(root, "bin", "launch")
	writeFile(t, executable, []byte("#!/bin/sh\nexit 0\n"), 0o755)

	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	require.Empty(t, result.Skipped)
	require.NotEmpty(t, result.Observations)

	entries := make([]model.Entry, 0, len(result.Observations))
	for _, observation := range result.Observations {
		require.NoError(t, observation.Validate())
		require.Equal(t, model.ObservationPresent, observation.State)
		require.NotNil(t, observation.Entry)
		entries = append(entries, *observation.Entry)
	}
	for _, entry := range entries {
		require.NotEqual(t, ".", entry.File.Path)
	}
	snapshot := model.Snapshot{
		Version: model.SnapshotVersion,
		Targets: []model.Target{{ID: "neovim", Source: model.SourceFiles, SourceVersion: model.SourceVersion, Root: &model.FileRoot{Base: model.RootHome, Path: "config/nvim", Kind: model.SelectionDirectory}}},
		Entries: entries,
	}
	require.NoError(t, snapshot.Validate())

	captured := make(map[string]model.FileEntry, len(entries))
	for _, entry := range entries {
		captured[entry.File.Path] = *entry.File
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		capturedEntry, ok := captured[relative]
		require.True(t, ok, "captured path %q", relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		assert.Equal(t, uint32(info.Mode().Perm()&0o777), capturedEntry.Mode, "mode for %q", relative)
		if info.IsDir() {
			assert.Equal(t, model.FileDirectory, capturedEntry.Kind, "kind for %q", relative)
			assert.Nil(t, capturedEntry.Content, "directory content for %q", relative)
			return nil
		}
		assert.Equal(t, model.FileRegular, capturedEntry.Kind, "kind for %q", relative)
		want, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		assert.Equal(t, want, capturedEntry.Content, "bytes for %q", relative)
		return nil
	})
	require.NoError(t, err)
	empty, ok := captured["empty.lua"]
	require.True(t, ok)
	require.NotNil(t, empty.Content)
	assert.Empty(t, empty.Content)
	assert.Equal(t, uint32(0o711), captured["empty"].Mode)
	assert.Equal(t, uint32(0o750), captured["empty/nested"].Mode)
	assert.Equal(t, uint32(0o755), captured["bin/launch"].Mode)
}

func TestCaptureDeterminism(t *testing.T) {
	root := copyNeovimFixture(t)
	makeDirectory(t, filepath.Join(root, "empty"), 0o700)
	makeDirectory(t, filepath.Join(root, "empty", "nested"), 0o700)
	first, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	second, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	assert.Equal(t, first, second)
	paths := make([]string, 0, len(first.Observations))
	for _, observation := range first.Observations {
		paths = append(paths, observation.Identity.FilePath)
	}
	assert.True(t, sort.SliceIsSorted(paths, func(i, j int) bool { return pathLess(paths[i], paths[j]) }))
}

func TestCaptureRepresentsInternalLinksAndSkipsExternalAndSpecialFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	inside := filepath.Join(root, "inside")
	makeDirectory(t, inside, 0o700)
	writeFile(t, filepath.Join(inside, "child.txt"), []byte("inside"), 0o600)
	outsideFile := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, outsideFile, []byte("outside"), 0o600)
	require.NoError(t, os.Symlink("inside", filepath.Join(root, "inside-link")))
	require.NoError(t, os.Symlink("missing-target", filepath.Join(root, "dangling-link")))
	require.NoError(t, os.Symlink("../outside.txt", filepath.Join(root, "escaping-link")))
	require.NoError(t, os.Symlink(outsideFile, filepath.Join(root, "absolute-link")))
	require.NoError(t, syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600))

	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	skips := make(map[string]Skip, len(result.Skipped))
	for _, skipped := range result.Skipped {
		skips[skipped.Path] = skipped
	}
	assert.Equal(t, Skip{Path: "absolute-link", Reason: SkipExternalLink, Detail: outsideFile}, skips["absolute-link"])
	assert.Equal(t, Skip{Path: "escaping-link", Reason: SkipExternalLink, Detail: "../outside.txt"}, skips["escaping-link"])
	assert.Equal(t, Skip{Path: "pipe", Reason: SkipSpecialFile}, skips["pipe"])
	assert.Len(t, skips, 3)

	entries := make(map[string]model.FileEntry)
	for _, observation := range result.Observations {
		require.NoError(t, observation.Validate())
		if observation.Entry != nil && observation.Entry.File != nil {
			entries[observation.Identity.FilePath] = *observation.Entry.File
		}
	}
	assert.Equal(t, "inside", entries["inside-link"].LinkTarget)
	assert.Equal(t, model.FileSymlink, entries["inside-link"].Kind)
	assert.Equal(t, "missing-target", entries["dangling-link"].LinkTarget)
	assert.Equal(t, model.FileDirectory, entries["inside"].Kind)
	assert.Equal(t, model.FileRegular, entries["inside/child.txt"].Kind)
	for _, path := range []string{"inside-link/child.txt", "escaping-link", "absolute-link", "pipe"} {
		assert.NotContains(t, entries, path)
	}
}

func TestCaptureUnknownForMissingAndInjectedReadFailures(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		result, err := Capture(captureRoot(filepath.Join(t.TempDir(), "missing"), model.SelectionDirectory))
		require.NoError(t, err)
		assertUnknownPaths(t, result, ".")
	})

	t.Run("vanished subtree", func(t *testing.T) {
		restoreFaults(t)
		root := filepath.Join(t.TempDir(), "root")
		makeDirectory(t, root, 0o700)
		gone := filepath.Join(root, "gone")
		makeDirectory(t, gone, 0o700)
		writeFile(t, filepath.Join(gone, "file"), []byte("data"), 0o600)
		oldStat := statPath
		statPath = func(root *os.Root, name string) (os.FileInfo, error) {
			if name == "gone" {
				return nil, os.ErrNotExist
			}
			return oldStat(root, name)
		}
		result, err := Capture(captureRoot(root, model.SelectionDirectory))
		require.NoError(t, err)
		assertUnknownPaths(t, result, "gone")
		assertNoPresentPath(t, result, "gone")
		assertNoPresentPath(t, result, "gone/file")
	})

	t.Run("unreadable subtree", func(t *testing.T) {
		restoreFaults(t)
		root := filepath.Join(t.TempDir(), "root")
		makeDirectory(t, root, 0o700)
		blocked := filepath.Join(root, "blocked")
		makeDirectory(t, blocked, 0o700)
		writeFile(t, filepath.Join(blocked, "file"), []byte("data"), 0o600)
		oldList := listDirectory
		listDirectory = func(root *os.Root, name string, inspected os.FileInfo) ([]os.DirEntry, error) {
			if name == "blocked" {
				return nil, syscall.EACCES
			}
			return oldList(root, name, inspected)
		}
		result, err := Capture(captureRoot(root, model.SelectionDirectory))
		require.NoError(t, err)
		assertUnknownPaths(t, result, "blocked")
		assertNoPresentPath(t, result, "blocked")
		assertNoPresentPath(t, result, "blocked/file")
	})

	t.Run("unreadable file", func(t *testing.T) {
		restoreFaults(t)
		root := filepath.Join(t.TempDir(), "root")
		makeDirectory(t, root, 0o700)
		file := filepath.Join(root, "secret")
		writeFile(t, file, []byte("data"), 0o600)
		readFile = func(*os.Root, string, *os.File, int64) ([]byte, error) {
			return nil, syscall.EIO
		}
		result, err := Capture(captureRoot(root, model.SelectionDirectory))
		require.NoError(t, err)
		assertUnknownPaths(t, result, "secret")
		assertNoPresentPath(t, result, "secret")
	})
}

func TestCaptureUnstableReadRetriesOnceThenUnknown(t *testing.T) {
	restoreFaults(t)
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	file := filepath.Join(root, "changing")
	writeFile(t, file, []byte("data"), 0o600)
	attempts := 0
	originalRead := readFile
	readFile = func(root *os.Root, name string, opened *os.File, limit int64) ([]byte, error) {
		attempts++
		content, err := originalRead(root, name, opened, limit)
		if err != nil {
			return content, err
		}
		changed, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return nil, err
		}
		_, writeErr := changed.Write([]byte{'x'})
		closeErr := changed.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		return content, closeErr
	}
	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	assert.Equal(t, 2, attempts)
	assertUnknownPaths(t, result, "changing")
	assertNoPresentPath(t, result, "changing")
}

func TestCaptureSingleFileSwapBetweenInspectAndOpenIsUnknown(t *testing.T) {
	for _, replacement := range []string{"symlink", "fifo"} {
		t.Run(replacement, func(t *testing.T) {
			restoreFaults(t)
			selected := filepath.Join(t.TempDir(), "selected")
			writeFile(t, selected, []byte("original"), 0o600)
			outside := filepath.Join(filepath.Dir(selected), "inside-target")
			writeFile(t, outside, []byte("must not be returned"), 0o600)
			oldStat := statPath
			replaced := false
			statPath = func(root *os.Root, name string) (os.FileInfo, error) {
				info, err := oldStat(root, name)
				if err == nil && name == "selected" && !replaced {
					replaced = true
					backup := selected + ".original"
					if renameErr := os.Rename(selected, backup); renameErr != nil {
						return nil, renameErr
					}
					if replacement == "symlink" {
						err = os.Symlink("inside-target", selected)
					} else {
						err = syscall.Mkfifo(selected, 0o600)
					}
					if err != nil {
						return nil, err
					}
				}
				return info, err
			}
			readAttempts := 0
			readFile = func(*os.Root, string, *os.File, int64) ([]byte, error) {
				readAttempts++
				return nil, errors.New("read seam should not run for a replaced file")
			}

			result, err := Capture(captureRoot(selected, model.SelectionFile))
			require.NoError(t, err)
			assert.True(t, replaced)
			assert.Equal(t, 0, readAttempts)
			assertUnknownPaths(t, result, ".")
			assertNoPresentPath(t, result, ".")
		})
	}
}

func TestCaptureBudgetsReturnTypedErrorsWithoutPartialResults(t *testing.T) {
	assert.Equal(t, Budget{MaxEntries: 20000, MaxDepth: 32, MaxFileBytes: 8 * 1024 * 1024, MaxTotalBytes: 256 * 1024 * 1024}, DefaultBudget())
	t.Run("entry count", func(t *testing.T) {
		root := makeBudgetTree(t)
		budget := DefaultBudget()
		budget.MaxEntries = 1
		assertBudgetFailure(t, root, budget, "MaxEntries", "a/child", 2)
	})
	t.Run("depth", func(t *testing.T) {
		root := makeBudgetTree(t)
		budget := DefaultBudget()
		budget.MaxDepth = 1
		assertBudgetFailure(t, root, budget, "MaxDepth", "a/child", 2)
	})
	t.Run("file bytes", func(t *testing.T) {
		root := makeBudgetTree(t)
		budget := DefaultBudget()
		budget.MaxFileBytes = 3
		assertBudgetFailure(t, root, budget, "MaxFileBytes", "a/child", 4)
	})
	t.Run("total bytes", func(t *testing.T) {
		root := makeBudgetTree(t)
		budget := DefaultBudget()
		budget.MaxTotalBytes = 6
		assertBudgetFailure(t, root, budget, "MaxTotalBytes", "b", 7)
	})
}

func TestCaptureSingleFileUsesRootIdentity(t *testing.T) {
	file := filepath.Join(t.TempDir(), "selected")
	writeFile(t, file, []byte("selected bytes"), 0o640)
	result, err := Capture(captureRoot(file, model.SelectionFile))
	require.NoError(t, err)
	require.Empty(t, result.Skipped)
	require.Len(t, result.Observations, 1)
	observation := result.Observations[0]
	require.NoError(t, observation.Validate())
	assert.Equal(t, ".", observation.Identity.FilePath)
	require.NotNil(t, observation.Entry)
	assert.Equal(t, []byte("selected bytes"), observation.Entry.File.Content)
	assert.Equal(t, uint32(0o640), observation.Entry.File.Mode)
}

func TestCaptureSingleFileInternalSymlinkIsRepresented(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	writeFile(t, target, []byte("target bytes"), 0o600)
	selected := filepath.Join(parent, "selected")
	require.NoError(t, os.Symlink("target", selected))
	result, err := Capture(captureRoot(selected, model.SelectionFile))
	require.NoError(t, err)
	assert.Empty(t, result.Skipped)
	require.Len(t, result.Observations, 1)
	require.NotNil(t, result.Observations[0].Entry)
	assert.Equal(t, model.FileSymlink, result.Observations[0].Entry.File.Kind)
	assert.Equal(t, "target", result.Observations[0].Entry.File.LinkTarget)
}

func TestCaptureSingleFileInvalidParentIsUnknown(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	writeFile(t, parent, []byte("blocking path"), 0o600)
	selected := filepath.Join(parent, "selected")
	result, err := Capture(captureRoot(selected, model.SelectionFile))
	require.NoError(t, err)
	assertUnknownPaths(t, result, ".")
}

func TestCaptureRejectsInvalidRootAndBudget(t *testing.T) {
	base := captureRoot("relative", model.SelectionDirectory)
	_, err := Capture(base)
	assert.Error(t, err)
	base = captureRoot(filepath.Join(t.TempDir(), "unused"), model.SelectionDirectory)
	base.Budget.MaxEntries = 0
	_, err = Capture(base)
	assert.Error(t, err)
}

func TestCraftedPathsAreRejectedByTheModel(t *testing.T) {
	for _, path := range []string{"../x", "/abs", "a//b"} {
		entry := model.FileEntry{Path: path, State: model.FilePresent, Kind: model.FileRegular, Content: []byte{}}
		assert.Error(t, entry.Validate(), "crafted path %q was accepted", path)
	}
}

func assertUnknownPaths(t *testing.T, result Result, paths ...string) {
	t.Helper()
	got := make([]string, 0)
	for _, observation := range result.Observations {
		require.NoError(t, observation.Validate())
		require.NotEqual(t, model.ObservationMissing, observation.State)
		if observation.State == model.ObservationUnknown {
			got = append(got, observation.Identity.FilePath)
		}
	}
	assert.ElementsMatch(t, paths, got)
}

func assertNoPresentPath(t *testing.T, result Result, path string) {
	t.Helper()
	for _, observation := range result.Observations {
		if observation.Identity.FilePath == path {
			assert.NotEqual(t, model.ObservationPresent, observation.State, "path %q was present", path)
		}
	}
}

func makeBudgetTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	makeDirectory(t, filepath.Join(root, "a"), 0o700)
	writeFile(t, filepath.Join(root, "a", "child"), []byte("four"), 0o600)
	writeFile(t, filepath.Join(root, "b"), []byte("two"), 0o600)
	return root
}

func assertBudgetFailure(t *testing.T, path string, budget Budget, limit, wantPath string, observed int64) {
	t.Helper()
	root := captureRoot(path, model.SelectionDirectory)
	root.Budget = budget
	result, err := Capture(root)
	require.Error(t, err)
	var budgetErr *BudgetError
	require.ErrorAs(t, err, &budgetErr)
	assert.Equal(t, limit, budgetErr.Limit)
	assert.Equal(t, wantPath, budgetErr.Path)
	assert.Equal(t, observed, budgetErr.Observed)
	assert.Empty(t, result.Observations)
	assert.Empty(t, result.Skipped)
}

func copyNeovimFixture(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	source := filepath.Join(filepath.Dir(sourceFile), "..", "..", "..", "tests", "testdata", "neovim")
	destination := filepath.Join(t.TempDir(), "neovim")
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			return os.Chmod(target, 0o700)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, content, entry.Type().Perm()|0o600); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.Chmod(target, info.Mode().Perm())
	})
	require.NoError(t, err)
	return destination
}

func makeDirectory(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		require.NoError(t, err)
	}
	require.NoError(t, os.Chmod(path, mode))
}

func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, content, mode))
	require.NoError(t, os.Chmod(path, mode))
}
