package files

import (
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/dottorblaster/dottie/internal/model"
)

var readLink = func(root *os.Root, name string) (string, error) {
	return root.Readlink(name)
}

func (s *captureState) captureLink(name, relative, linkDir string, inspected os.FileInfo) error {
	target, err := readLink(s.handle, name)
	if err != nil {
		return s.addUnknown(relative)
	}
	after, err := statPath(s.handle, name)
	if err != nil || after.Mode()&os.ModeSymlink == 0 || !sameIdentity(inspected, after) {
		return s.addUnknown(relative)
	}
	if strings.HasPrefix(target, "/") {
		return s.skipLink(relative, target)
	}
	_, escapes := LexicalResolve(linkDir, target)
	if escapes {
		if _, approved := s.allowExternal[relative]; !approved {
			return s.skipLink(relative, target)
		}
	}
	entry := model.FileEntry{Path: relative, State: model.FilePresent, Kind: model.FileSymlink, LinkTarget: target}
	if err := entry.Validate(); err != nil {
		return s.addUnknown(relative)
	}
	return s.addPresent(relative, entry)
}

func (s *captureState) skipLink(relative, target string) error {
	s.result.Skipped = append(s.result.Skipped, Skip{Path: relative, Reason: SkipExternalLink, Detail: safeDetail(target)})
	return nil
}

func safeDetail(value string) string {
	var result strings.Builder
	result.Grow(min(len(value), 4096))
	for _, character := range value {
		piece := string(character)
		if unicode.IsControl(character) {
			if character <= 0xffff {
				piece = fmt.Sprintf("\\u%04x", character)
			} else {
				piece = fmt.Sprintf("\\U%08x", character)
			}
		}
		if result.Len()+len(piece) > 4096 {
			break
		}
		result.WriteString(piece)
	}
	return result.String()
}
