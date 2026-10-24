package files

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dottorblaster/dottie/internal/model"
)

func TestCaptureRepresentsInternalSiblingAndLoopLinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	makeDirectory(t, filepath.Join(root, "sub"), 0o700)
	writeFile(t, filepath.Join(root, "sibling"), []byte("safe"), 0o600)
	require.NoError(t, os.Symlink("../sibling", filepath.Join(root, "sub", "sibling-link")))
	require.NoError(t, os.Symlink("self", filepath.Join(root, "self")))
	require.NoError(t, os.Symlink("loop-b", filepath.Join(root, "loop-a")))
	require.NoError(t, os.Symlink("loop-a", filepath.Join(root, "loop-b")))

	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	assert.Empty(t, result.Skipped)
	entries := make(map[string]model.FileEntry)
	for _, observation := range result.Observations {
		require.NoError(t, observation.Validate())
		if observation.Entry != nil && observation.Entry.File != nil {
			entries[observation.Identity.FilePath] = *observation.Entry.File
		}
	}
	for path, target := range map[string]string{
		"sub/sibling-link": "../sibling",
		"self":             "self",
		"loop-a":           "loop-b",
		"loop-b":           "loop-a",
	} {
		assert.Equal(t, model.FileSymlink, entries[path].Kind, "kind for %q", path)
		assert.Equal(t, target, entries[path].LinkTarget, "target for %q", path)
		assert.Nil(t, entries[path].Content, "content for %q", path)
		assert.Zero(t, entries[path].Mode, "mode for %q", path)
	}
	for _, path := range []string{"self/child", "loop-a/child", "loop-b/child", "sub/sibling-link/child"} {
		assert.NotContains(t, entries, path)
	}
}

func TestExternalLinkApprovalNeverOpensTargets(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	makeDirectory(t, root, 0o700)
	outside := filepath.Join(parent, "outside")
	makeDirectory(t, outside, 0o700)
	outsideFile := filepath.Join(outside, "secret")
	writeFile(t, outsideFile, []byte("must not be read"), 0o600)
	require.NoError(t, os.Symlink("../outside/secret", filepath.Join(root, "relative-link")))
	require.NoError(t, os.Symlink(outsideFile, filepath.Join(root, "absolute-link")))

	rootSelection := captureRoot(root, model.SelectionDirectory)
	readNames := make([]string, 0)
	openNames := make([]string, 0)
	originalReadLink := readLink
	originalOpen := openEntry
	readLink = func(handle *os.Root, name string) (string, error) {
		readNames = append(readNames, name)
		return originalReadLink(handle, name)
	}
	openEntry = func(handle *os.Root, name string) (*os.File, error) {
		openNames = append(openNames, name)
		return nil, syscall.EPERM
	}
	t.Cleanup(func() {
		readLink = originalReadLink
		openEntry = originalOpen
	})

	result, err := Capture(rootSelection)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"absolute-link", "relative-link"}, readNames)
	assert.Empty(t, openNames)
	assert.ElementsMatch(t, []Skip{
		{Path: "absolute-link", Reason: SkipExternalLink, Detail: outsideFile},
		{Path: "relative-link", Reason: SkipExternalLink, Detail: "../outside/secret"},
	}, result.Skipped)

	rootSelection.AllowExternal = []string{"relative-link", "absolute-link"}
	readNames = nil
	openNames = nil
	result, err = Capture(rootSelection)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"absolute-link", "relative-link"}, readNames)
	assert.Empty(t, openNames)
	assert.Equal(t, []Skip{{Path: "absolute-link", Reason: SkipExternalLink, Detail: outsideFile}}, result.Skipped)
	entries := make(map[string]model.FileEntry)
	for _, observation := range result.Observations {
		if observation.Entry != nil && observation.Entry.File != nil {
			entries[observation.Identity.FilePath] = *observation.Entry.File
		}
	}
	assert.Equal(t, "../outside/secret", entries["relative-link"].LinkTarget)
	assert.Equal(t, model.FileSymlink, entries["relative-link"].Kind)
	assert.NotContains(t, entries, "absolute-link")

	rootSelection.AllowExternal = []string{"absolute-link"}
	result, err = Capture(rootSelection)
	require.NoError(t, err)
	assert.Contains(t, result.Skipped, Skip{Path: "absolute-link", Reason: SkipExternalLink, Detail: outsideFile})
}

func TestCaptureInspectReadlinkSwapBecomesUnknown(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	makeDirectory(t, root, 0o700)
	outside := filepath.Join(parent, "outside")
	writeFile(t, outside, []byte("do not open"), 0o600)
	linkPath := filepath.Join(root, "link")
	require.NoError(t, os.Symlink("inside", linkPath))
	readAttempts := 0
	openAttempts := 0
	originalReadLink := readLink
	originalOpen := openEntry
	readLink = func(handle *os.Root, name string) (string, error) {
		readAttempts++
		require.Equal(t, "link", name)
		require.NoError(t, os.Rename(linkPath, linkPath+".original"))
		require.NoError(t, os.Symlink(outside, linkPath))
		return originalReadLink(handle, name)
	}
	openEntry = func(handle *os.Root, name string) (*os.File, error) {
		openAttempts++
		return nil, syscall.EPERM
	}
	t.Cleanup(func() {
		readLink = originalReadLink
		openEntry = originalOpen
	})

	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	assert.Equal(t, 1, readAttempts)
	assert.Zero(t, openAttempts)
	assertUnknownPaths(t, result, "link")
	assertNoPresentPath(t, result, "link")
}

func TestCaptureSpecialFilesAreSkippedWithoutOpening(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	pipe := filepath.Join(root, "pipe")
	require.NoError(t, syscall.Mkfifo(pipe, 0o600))
	socket := filepath.Join(root, "socket")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, listener.Close())
	for _, name := range []string{"block", "character"} {
		writeFile(t, filepath.Join(root, name), []byte("synthetic"), 0o600)
	}
	restoreFaults(t)
	originalStat := statPath
	statPath = func(handle *os.Root, name string) (os.FileInfo, error) {
		info, err := originalStat(handle, name)
		if err != nil {
			return nil, err
		}
		switch name {
		case "block":
			return typedFileInfo{FileInfo: info, mode: os.ModeDevice}, nil
		case "character":
			return typedFileInfo{FileInfo: info, mode: os.ModeDevice | os.ModeCharDevice}, nil
		default:
			return info, nil
		}
	}
	opened := make([]string, 0)
	originalOpen := openEntry
	openEntry = func(handle *os.Root, name string) (*os.File, error) {
		opened = append(opened, name)
		return nil, syscall.EPERM
	}
	t.Cleanup(func() { openEntry = originalOpen })

	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	assert.Empty(t, opened)
	assert.ElementsMatch(t, []Skip{
		{Path: "block", Reason: SkipSpecialFile},
		{Path: "character", Reason: SkipSpecialFile},
		{Path: "pipe", Reason: SkipSpecialFile},
		{Path: "socket", Reason: SkipSpecialFile},
	}, result.Skipped)
}

type typedFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info typedFileInfo) Mode() os.FileMode {
	return info.mode
}

func TestCaptureExcludesUseFirstMatchAndPruneDirectories(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	makeDirectory(t, filepath.Join(root, "dir"), 0o700)
	makeDirectory(t, filepath.Join(root, "dir", "nested"), 0o700)
	writeFile(t, filepath.Join(root, "dir", "nested", "hidden.txt"), []byte("hidden"), 0o600)
	writeFile(t, filepath.Join(root, "dir", "keep.txt"), []byte("keep"), 0o600)
	writeFile(t, filepath.Join(root, "other.txt"), []byte("other"), 0o600)
	rootSelection := captureRoot(root, model.SelectionDirectory)
	rootSelection.Exclude = []string{"dir", "dir/**", "dir/keep.txt"}
	listedDir := false
	originalList := listDirectory
	listDirectory = func(handle *os.Root, name string, inspected os.FileInfo) ([]os.DirEntry, error) {
		if name == "dir" {
			listedDir = true
		}
		return originalList(handle, name, inspected)
	}
	t.Cleanup(func() { listDirectory = originalList })

	result, err := Capture(rootSelection)
	require.NoError(t, err)
	assert.False(t, listedDir)
	assert.Equal(t, []Skip{{Path: "dir", Reason: SkipExcluded, Detail: "dir"}}, result.Skipped)
	assertNoPresentPath(t, result, "dir")
	assertNoPresentPath(t, result, "dir/nested")
	assertNoPresentPath(t, result, "dir/nested/hidden.txt")
	assertNoPresentPath(t, result, "dir/keep.txt")
	assertPresentPath(t, result, "other.txt")
}

func TestCaptureExcludesOnlyMatchingFileInsideIncludedDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	makeDirectory(t, filepath.Join(root, "dir"), 0o700)
	writeFile(t, filepath.Join(root, "dir", "skip.txt"), []byte("skip"), 0o600)
	writeFile(t, filepath.Join(root, "dir", "keep.txt"), []byte("keep"), 0o600)
	selection := captureRoot(root, model.SelectionDirectory)
	selection.Exclude = []string{"dir/skip.txt"}
	result, err := Capture(selection)
	require.NoError(t, err)
	assert.Equal(t, []Skip{{Path: "dir/skip.txt", Reason: SkipExcluded, Detail: "dir/skip.txt"}}, result.Skipped)
	assertPresentPath(t, result, "dir")
	assertPresentPath(t, result, "dir/keep.txt")
	assertNoPresentPath(t, result, "dir/skip.txt")
}

func TestCaptureRetainsHiddenLuaAndPluginFilesWithoutExcludes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	makeDirectory(t, root, 0o700)
	makeDirectory(t, filepath.Join(root, "plugin"), 0o700)
	writeFile(t, filepath.Join(root, ".hidden"), []byte("hidden"), 0o600)
	writeFile(t, filepath.Join(root, "init.lua"), []byte("init"), 0o600)
	writeFile(t, filepath.Join(root, "plugin", "init.lua"), []byte("plugin"), 0o600)
	result, err := Capture(captureRoot(root, model.SelectionDirectory))
	require.NoError(t, err)
	assert.Empty(t, result.Skipped)
	for _, path := range []string{".hidden", "init.lua", "plugin", "plugin/init.lua"} {
		assertPresentPath(t, result, path)
	}
}

func TestSafeDetailEscapesControlsAndBoundsUTF8(t *testing.T) {
	got := safeDetail("target\x00\n\x7f-é")
	assert.Equal(t, "target\\u0000\\u000a\\u007f-é", got)
	assert.True(t, utf8.ValidString(got))
	assert.False(t, strings.ContainsAny(got, "\x00\n\x7f"))
	assert.LessOrEqual(t, len(safeDetail(strings.Repeat("é", 4097))), 4096)
	assert.True(t, utf8.ValidString(safeDetail(strings.Repeat("é", 4097))))
}

func assertPresentPath(t *testing.T, result Result, path string) {
	t.Helper()
	for _, observation := range result.Observations {
		if observation.Identity.FilePath == path {
			assert.Equal(t, model.ObservationPresent, observation.State)
			return
		}
	}
	assert.Fail(t, "present path was not observed", "%s", path)
}
