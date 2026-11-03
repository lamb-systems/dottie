package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionLockPathUsesRuntimeDirectoryWithoutStateHome(t *testing.T) {
	runtimeDir := t.TempDir()
	stateDir := t.TempDir()
	env := func(name string) string {
		switch name {
		case "XDG_RUNTIME_DIR":
			return runtimeDir
		case "XDG_STATE_HOME":
			return stateDir
		default:
			return ""
		}
	}
	want := filepath.Join(runtimeDir, "dottie-session-"+strconv.Itoa(os.Getuid())+".lock")
	assert.Equal(t, want, SessionLockPath(env))
	assert.NotContains(t, SessionLockPath(env), stateDir)
}

func TestSessionLockPathRejectsInvalidRuntimeDirectory(t *testing.T) {
	env := func(name string) string {
		if name == "XDG_RUNTIME_DIR" {
			return "relative-runtime"
		}
		return ""
	}
	path := SessionLockPath(env)
	uid := strconv.Itoa(os.Getuid())
	runtimeDir := filepath.Join("/run/user", uid)
	if info, err := os.Stat(runtimeDir); err == nil && info.IsDir() {
		assert.Equal(t, filepath.Join(runtimeDir, "dottie-session-"+uid+".lock"), path)
	} else {
		assert.Equal(t, filepath.Join(os.TempDir(), "dottie-session-"+uid+".lock"), path)
	}
}

func TestLockFileIsPrivateNonBlockingAndRejectsSymlinks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "session.lock")
	first, err := LockFile(path)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	second, err := LockFile(path)
	assert.Nil(t, second)
	assert.True(t, errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN))
	require.NoError(t, first.Close())
	second, err = LockFile(path)
	require.NoError(t, err)
	require.NoError(t, second.Close())

	target := filepath.Join(directory, "target")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))
	link := filepath.Join(directory, "link")
	require.NoError(t, os.Symlink(target, link))
	linkedLock, err := LockFile(link)
	assert.Nil(t, linkedLock)
	assert.Error(t, err)
}
