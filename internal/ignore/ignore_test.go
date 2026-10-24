package ignore

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileGoldenDialectVectors(t *testing.T) {
	tests := []struct {
		pattern string
		matches []string
		not     []string
	}{
		{pattern: "*.log", matches: []string{"a.log"}, not: []string{"dir/a.log", "a.log.bak"}},
		{pattern: "**/*.log", matches: []string{"a.log", "dir/a.log", "a/b/a.log"}, not: []string{"a.log.bak"}},
		{pattern: "a/**", matches: []string{"a", "a/x", "a/b/c"}, not: []string{"ab", "b/a"}},
		{pattern: "a/**/b", matches: []string{"a/b", "a/x/b", "a/x/y/b"}, not: []string{"a/x/bb", "b"}},
		{pattern: "**", matches: []string{"a", "a/b", "a/b/c"}},
		{pattern: "?", matches: []string{"a"}, not: []string{"ab", "a/b"}},
		{pattern: "[a-c]x", matches: []string{"ax", "cx"}, not: []string{"dx", "Ax"}},
	}
	for _, test := range tests {
		t.Run(test.pattern, func(t *testing.T) {
			matcher, err := Compile([]string{test.pattern})
			require.NoError(t, err)
			for _, rel := range test.matches {
				got, excluded := matcher.Exclude(rel)
				assert.True(t, excluded, "%q should match %q", test.pattern, rel)
				assert.Equal(t, test.pattern, got)
			}
			for _, rel := range test.not {
				_, excluded := matcher.Exclude(rel)
				assert.False(t, excluded, "%q should not match %q", test.pattern, rel)
			}
		})
	}
}

func TestCompileRejectsRestrictedSyntaxWithIndexAndText(t *testing.T) {
	for _, pattern := range []string{"", ".", "a/", "a//b", "{a,b}", "!x", `\x`, "/abs", "../x", "a/../x", "a**b"} {
		t.Run(pattern, func(t *testing.T) {
			_, err := Compile([]string{"valid", pattern, "also-valid"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "pattern 1")
			assert.Contains(t, err.Error(), strconv.Quote(pattern))
		})
	}
}

func TestCompileEnforcesPatternCaps(t *testing.T) {
	tooManyPatterns := make([]string, 65)
	for index := range tooManyPatterns {
		tooManyPatterns[index] = "pattern"
	}
	_, err := Compile(tooManyPatterns)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern 64")
	assert.Contains(t, err.Error(), `"pattern"`)
	assert.Contains(t, err.Error(), "maximum 64")

	_, err = Compile([]string{strings.Repeat("a", 4097)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern 0")
	assert.Contains(t, err.Error(), "exceeds 4096 bytes")

	parts := make([]string, 17)
	for index := range parts {
		parts[index] = "**"
	}
	tooManyRecursiveSegments := strings.Join(parts, "/")
	_, err = Compile([]string{tooManyRecursiveSegments})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than 16 ** segments")
}

func TestCompileAdversarialMaximumPatternSet(t *testing.T) {
	maximumLength := strings.Repeat("a", 4096)
	patterns := []string{maximumLength}
	for index := 0; index < 15; index++ {
		patterns = append(patterns, strings.Join([]string{"**", "**", "**", "**", "**", "**", "**", "**", "**", "**", "**", "**", "**", "**", "**", "**"}, "/"))
	}
	matcher, err := Compile(patterns)
	require.NoError(t, err)
	matched, excluded := matcher.Exclude(maximumLength)
	assert.True(t, excluded)
	assert.Equal(t, maximumLength, matched)
	matched, excluded = matcher.Exclude("one/two/three/four/five/six/seven/eight/nine/ten/eleven/twelve/thirteen/fourteen/fifteen/sixteen")
	assert.True(t, excluded)
	assert.NotEmpty(t, matched)
}

func TestCompileEmptyAndDuplicatePatternsKeepOrder(t *testing.T) {
	matcher, err := Compile(nil)
	require.NoError(t, err)
	_, excluded := matcher.Exclude("anything")
	assert.False(t, excluded)

	matcher, err = Compile([]string{"*.txt", "*.txt"})
	require.NoError(t, err)
	pattern, excluded := matcher.Exclude("file.txt")
	assert.True(t, excluded)
	assert.Equal(t, "*.txt", pattern)
}
