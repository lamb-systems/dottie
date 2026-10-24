package files

import (
	"errors"
	"strings"
	"unicode/utf8"
)

var errInvalidRelativePath = errors.New("invalid root-relative path")

func JoinRelative(parent, name string) (string, error) {
	if !validRelativePath(parent, true) || !validRelativeName(name) {
		return "", errInvalidRelativePath
	}
	joined := name
	if parent != "." {
		joined = parent + "/" + name
	}
	if len(joined) > 4096 {
		return "", errInvalidRelativePath
	}
	return joined, nil
}

func IsWithin(root, candidate string) bool {
	if !validRelativePath(root, true) || !validRelativePath(candidate, true) {
		return false
	}
	if root == "." || root == candidate {
		return true
	}
	return strings.HasPrefix(candidate, root+"/")
}

func LexicalResolve(linkDir, target string) (string, bool) {
	if !validRelativePath(linkDir, true) || !validLinkTextPath(target) {
		return "", true
	}
	segments := Segments(linkDir)
	for _, segment := range strings.Split(target, "/") {
		switch segment {
		case ".":
		case "..":
			if len(segments) == 0 {
				return "", true
			}
			segments = segments[:len(segments)-1]
		default:
			segments = append(segments, segment)
		}
	}
	resolved := "."
	if len(segments) > 0 {
		resolved = strings.Join(segments, "/")
	}
	if len(resolved) > 4096 {
		return "", true
	}
	return resolved, false
}

func Segments(rel string) []string {
	if rel == "." || !validRelativePath(rel, false) {
		return nil
	}
	return strings.Split(rel, "/")
}

func validRelativePath(rel string, allowRoot bool) bool {
	if rel == "." {
		return allowRoot
	}
	if rel == "" || len(rel) > 4096 || !utf8.ValidString(rel) || strings.ContainsRune(rel, 0) || strings.ContainsRune(rel, '\\') || strings.HasPrefix(rel, "/") || hasDrivePrefix(rel) {
		return false
	}
	for _, segment := range strings.Split(rel, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validRelativeName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsRune(name, '/') && validRelativePath(name, false)
}

func hasDrivePrefix(value string) bool {
	return len(value) >= 2 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1] == ':'
}

func validLinkTextPath(target string) bool {
	if target == "" || len(target) > 4096 || !utf8.ValidString(target) || strings.ContainsRune(target, 0) || strings.ContainsRune(target, '\\') || strings.HasPrefix(target, "/") || hasDrivePrefix(target) {
		return false
	}
	for _, segment := range strings.Split(target, "/") {
		if segment == "" {
			return false
		}
	}
	return true
}
