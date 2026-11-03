package platform

import (
	"os"
	"path/filepath"
	"strconv"
)

func SessionLockPath(env func(string) string) string {
	uid := os.Getuid()
	if env != nil {
		if runtimeDir := env("XDG_RUNTIME_DIR"); filepath.IsAbs(runtimeDir) && existingDirectory(runtimeDir) {
			return filepath.Join(runtimeDir, "dottie-session-"+strconv.Itoa(uid)+".lock")
		}
	}
	userRuntime := filepath.Join("/run/user", strconv.Itoa(uid))
	if existingDirectory(userRuntime) {
		return filepath.Join(userRuntime, "dottie-session-"+strconv.Itoa(uid)+".lock")
	}
	return filepath.Join(os.TempDir(), "dottie-session-"+strconv.Itoa(uid)+".lock")
}

func existingDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
