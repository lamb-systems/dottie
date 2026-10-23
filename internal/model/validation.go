package model

import (
	"strings"
	"unicode/utf8"
)

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func validRelativePath(path string, allowRoot bool) bool {
	if !validText(path, MaxRelativePathBytes) || strings.ContainsRune(path, '\\') || strings.HasPrefix(path, "/") || hasDrivePrefix(path) {
		return false
	}
	if path == "." {
		return allowRoot
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validGSettingsPath(path string) bool {
	if !validText(path, MaxRelativePathBytes) || !strings.HasPrefix(path, "/") || !strings.HasSuffix(path, "/") {
		return false
	}
	if path == "/" {
		return true
	}
	return !strings.Contains(path, "//")
}

func validRelativeLink(path string) bool {
	if !validText(path, MaxSymlinkTargetBytes) || strings.HasPrefix(path, "/") || strings.ContainsRune(path, '\\') || hasDrivePrefix(path) {
		return false
	}
	return true
}

func hasDrivePrefix(path string) bool {
	return len(path) >= 2 && ((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1] == ':'
}
