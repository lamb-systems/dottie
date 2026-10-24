package ignore

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"
)

const (
	maxPatterns       = 64
	maxPatternBytes   = 4096
	maxRecursiveParts = 16
)

type Matcher struct {
	patterns []string
}

func Compile(patterns []string) (Matcher, error) {
	compiled := make([]string, 0, min(len(patterns), maxPatterns))
	for index, pattern := range patterns {
		if index == maxPatterns {
			return Matcher{}, fmt.Errorf("exclude pattern %d %q: pattern count exceeds maximum %d", index, pattern, maxPatterns)
		}
		if err := validatePattern(pattern); err != nil {
			return Matcher{}, fmt.Errorf("exclude pattern %d %q: %w", index, pattern, err)
		}
		compiled = append(compiled, pattern)
	}
	return Matcher{patterns: compiled}, nil
}

func (m Matcher) Exclude(rel string) (string, bool) {
	for _, pattern := range m.patterns {
		matched, err := doublestar.Match(pattern, rel)
		if err == nil && matched {
			return pattern, true
		}
	}
	return "", false
}

func validatePattern(pattern string) error {
	switch {
	case pattern == "":
		return fmt.Errorf("pattern is empty")
	case len(pattern) > maxPatternBytes:
		return fmt.Errorf("pattern exceeds %d bytes", maxPatternBytes)
	case !utf8.ValidString(pattern):
		return fmt.Errorf("pattern is not valid UTF-8")
	case strings.IndexByte(pattern, 0) >= 0:
		return fmt.Errorf("pattern contains NUL")
	case strings.HasPrefix(pattern, "/"):
		return fmt.Errorf("pattern must be root-relative")
	case strings.ContainsRune(pattern, '\\'):
		return fmt.Errorf("backslashes are not permitted")
	case strings.ContainsAny(pattern, "{}!"):
		return fmt.Errorf("braces and negation are not permitted")
	case pattern == ".":
		return fmt.Errorf("pattern cannot select the root")
	case strings.HasSuffix(pattern, "/"):
		return fmt.Errorf("pattern cannot end with /")
	case strings.Contains(pattern, "//"):
		return fmt.Errorf("pattern cannot contain //")
	}

	recursive := 0
	for _, segment := range strings.Split(pattern, "/") {
		if segment == ".." {
			return fmt.Errorf("parent path segments are not permitted")
		}
		if strings.Contains(segment, "**") {
			if segment != "**" {
				return fmt.Errorf("** must be a complete path segment")
			}
			recursive++
		}
	}
	if recursive > maxRecursiveParts {
		return fmt.Errorf("pattern contains more than %d ** segments", maxRecursiveParts)
	}
	if !doublestar.ValidatePattern(pattern) {
		return fmt.Errorf("pattern is not valid doublestar syntax")
	}
	return nil
}
